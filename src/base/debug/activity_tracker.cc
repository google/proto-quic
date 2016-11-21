// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/debug/activity_tracker.h"

#include <algorithm>

#include "base/debug/stack_trace.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/memory_mapped_file.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_macros.h"
#include "base/pending_task.h"
#include "base/process/process.h"
#include "base/process/process_handle.h"
#include "base/stl_util.h"
#include "base/strings/string_util.h"
#include "base/threading/platform_thread.h"

namespace base {
namespace debug {

namespace {

// A number that identifies the memory as having been initialized. It's
// arbitrary but happens to be the first 4 bytes of SHA1(ThreadActivityTracker).
// A version number is added on so that major structure changes won't try to
// read an older version (since the cookie won't match).
const uint32_t kHeaderCookie = 0xC0029B24UL + 2;  // v2

// The minimum depth a stack should support.
const int kMinStackDepth = 2;

// The amount of memory set aside for holding arbitrary user data (key/value
// pairs) globally or associated with ActivityData entries.
const size_t kUserDataSize = 1024;    // bytes
const size_t kGlobalDataSize = 1024;  // bytes
const size_t kMaxUserDataNameLength =
    static_cast<size_t>(std::numeric_limits<uint8_t>::max());

union ThreadRef {
  int64_t as_id;
#if defined(OS_WIN)
  // On Windows, the handle itself is often a pseudo-handle with a common
  // value meaning "this thread" and so the thread-id is used. The former
  // can be converted to a thread-id with a system call.
  PlatformThreadId as_tid;
#elif defined(OS_POSIX)
  // On Posix, the handle is always a unique identifier so no conversion
  // needs to be done. However, it's value is officially opaque so there
  // is no one correct way to convert it to a numerical identifier.
  PlatformThreadHandle::Handle as_handle;
#endif
};

// Determines the next aligned index.
size_t RoundUpToAlignment(size_t index, size_t alignment) {
  return (index + (alignment - 1)) & (0 - alignment);
}

}  // namespace


// It doesn't matter what is contained in this (though it will be all zeros)
// as only the address of it is important.
const ActivityData kNullActivityData = {};

ActivityData ActivityData::ForThread(const PlatformThreadHandle& handle) {
  ThreadRef thread_ref;
  thread_ref.as_id = 0;  // Zero the union in case other is smaller.
#if defined(OS_WIN)
  thread_ref.as_tid = ::GetThreadId(handle.platform_handle());
#elif defined(OS_POSIX)
  thread_ref.as_handle = handle.platform_handle();
#endif
  return ForThread(thread_ref.as_id);
}

ActivityTrackerMemoryAllocator::ActivityTrackerMemoryAllocator(
    PersistentMemoryAllocator* allocator,
    uint32_t object_type,
    uint32_t object_free_type,
    size_t object_size,
    size_t cache_size,
    bool make_iterable)
    : allocator_(allocator),
      object_type_(object_type),
      object_free_type_(object_free_type),
      object_size_(object_size),
      cache_size_(cache_size),
      make_iterable_(make_iterable),
      iterator_(allocator),
      cache_values_(new Reference[cache_size]),
      cache_used_(0) {
  DCHECK(allocator);
}

ActivityTrackerMemoryAllocator::~ActivityTrackerMemoryAllocator() {}

ActivityTrackerMemoryAllocator::Reference
ActivityTrackerMemoryAllocator::GetObjectReference() {
  // First see if there is a cached value that can be returned. This is much
  // faster than searching the memory system for free blocks.
  while (cache_used_ > 0) {
    Reference cached = cache_values_[--cache_used_];
    // Change the type of the cached object to the proper type and return it.
    // If the type-change fails that means another thread has taken this from
    // under us (via the search below) so ignore it and keep trying.
    if (allocator_->ChangeType(cached, object_type_, object_free_type_))
      return cached;
  }

  // Fetch the next "free" object from persistent memory. Rather than restart
  // the iterator at the head each time and likely waste time going again
  // through objects that aren't relevant, the iterator continues from where
  // it last left off and is only reset when the end is reached. If the
  // returned reference matches |last|, then it has wrapped without finding
  // anything.
  const Reference last = iterator_.GetLast();
  while (true) {
    uint32_t type;
    Reference found = iterator_.GetNext(&type);
    if (found && type == object_free_type_) {
      // Found a free object. Change it to the proper type and return it. If
      // the type-change fails that means another thread has taken this from
      // under us so ignore it and keep trying.
      if (allocator_->ChangeType(found, object_type_, object_free_type_))
        return found;
    }
    if (found == last) {
      // Wrapped. No desired object was found.
      break;
    }
    if (!found) {
      // Reached end; start over at the beginning.
      iterator_.Reset();
    }
  }

  // No free block was found so instead allocate a new one.
  Reference allocated = allocator_->Allocate(object_size_, object_type_);
  if (allocated && make_iterable_)
    allocator_->MakeIterable(allocated);
  return allocated;
}

void ActivityTrackerMemoryAllocator::ReleaseObjectReference(Reference ref) {
  // Zero the memory so that it is ready for immediate use if needed later.
  char* mem_base = allocator_->GetAsObject<char>(ref, object_type_);
  DCHECK(mem_base);
  memset(mem_base, 0, object_size_);

  // Mark object as free.
  bool success = allocator_->ChangeType(ref, object_free_type_, object_type_);
  DCHECK(success);

  // Add this reference to our "free" cache if there is space. If not, the type
  // has still been changed to indicate that it is free so this (or another)
  // thread can find it, albeit more slowly, using the iteration method above.
  if (cache_used_ < cache_size_)
    cache_values_[cache_used_++] = ref;
}

// static
void Activity::FillFrom(Activity* activity,
                        const void* program_counter,
                        const void* origin,
                        Type type,
                        const ActivityData& data) {
  activity->time_internal = base::TimeTicks::Now().ToInternalValue();
  activity->calling_address = reinterpret_cast<uintptr_t>(program_counter);
  activity->origin_address = reinterpret_cast<uintptr_t>(origin);
  activity->activity_type = type;
  activity->data = data;

#if defined(SYZYASAN)
  // Create a stacktrace from the current location and get the addresses.
  StackTrace stack_trace;
  size_t stack_depth;
  const void* const* stack_addrs = stack_trace.Addresses(&stack_depth);
  // Copy the stack addresses, ignoring the first one (here).
  size_t i;
  for (i = 1; i < stack_depth && i < kActivityCallStackSize; ++i) {
    activity->call_stack[i - 1] = reinterpret_cast<uintptr_t>(stack_addrs[i]);
  }
  activity->call_stack[i - 1] = 0;
#else
  activity->call_stack[0] = 0;
#endif
}

ActivitySnapshot::ActivitySnapshot() {}
ActivitySnapshot::~ActivitySnapshot() {}

ActivityUserData::ValueInfo::ValueInfo() {}
ActivityUserData::ValueInfo::ValueInfo(ValueInfo&&) = default;
ActivityUserData::ValueInfo::~ValueInfo() {}

ActivityUserData::ActivityUserData(void* memory, size_t size)
    : memory_(static_cast<char*>(memory)), available_(size) {}

ActivityUserData::~ActivityUserData() {}

void ActivityUserData::Set(StringPiece name,
                           ValueType type,
                           const void* memory,
                           size_t size) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_GE(std::numeric_limits<uint8_t>::max(), name.length());
  size = std::min(std::numeric_limits<uint16_t>::max() - (kMemoryAlignment - 1),
                  size);

  // It's possible that no user data is being stored.
  if (!memory_)
    return;

  // The storage of a name is limited so use that limit during lookup.
  if (name.length() > kMaxUserDataNameLength)
    name.set(name.data(), kMaxUserDataNameLength);

  ValueInfo* info;
  auto existing = values_.find(name);
  if (existing != values_.end()) {
    info = &existing->second;
  } else {
    // The name size is limited to what can be held in a single byte but
    // because there are not alignment constraints on strings, it's set tight
    // against the header. Its extent (the reserved space, even if it's not
    // all used) is calculated so that, when pressed against the header, the
    // following field will be aligned properly.
    size_t name_size = name.length();
    size_t name_extent =
        RoundUpToAlignment(sizeof(Header) + name_size, kMemoryAlignment) -
        sizeof(Header);
    size_t value_extent = RoundUpToAlignment(size, kMemoryAlignment);

    // The "basic size" is the minimum size of the record. It's possible that
    // lengthy values will get truncated but there must be at least some bytes
    // available.
    size_t basic_size = sizeof(Header) + name_extent + kMemoryAlignment;
    if (basic_size > available_)
      return;  // No space to store even the smallest value.

    // The "full size" is the size for storing the entire value, truncated
    // to the amount of available memory.
    size_t full_size =
        std::min(sizeof(Header) + name_extent + value_extent, available_);
    size = std::min(full_size - sizeof(Header) - name_extent, size);

    // Allocate a chunk of memory.
    Header* header = reinterpret_cast<Header*>(memory_);
    memory_ += full_size;
    available_ -= full_size;

    // Datafill the header and name records. Memory must be zeroed. The |type|
    // is written last, atomically, to release all the other values.
    DCHECK_EQ(END_OF_VALUES, header->type.load(std::memory_order_relaxed));
    DCHECK_EQ(0, header->value_size.load(std::memory_order_relaxed));
    header->name_size = static_cast<uint8_t>(name_size);
    header->record_size = full_size;
    char* name_memory = reinterpret_cast<char*>(header) + sizeof(Header);
    void* value_memory =
        reinterpret_cast<char*>(header) + sizeof(Header) + name_extent;
    memcpy(name_memory, name.data(), name_size);
    header->type.store(type, std::memory_order_release);

    // Create an entry in |values_| so that this field can be found and changed
    // later on without having to allocate new entries.
    StringPiece persistent_name(name_memory, name_size);
    auto inserted =
        values_.insert(std::make_pair(persistent_name, ValueInfo()));
    DCHECK(inserted.second);  // True if inserted, false if existed.
    info = &inserted.first->second;
    info->name = persistent_name;
    info->memory = value_memory;
    info->size_ptr = &header->value_size;
    info->extent = full_size - sizeof(Header) - name_extent;
    info->type = type;
  }

  // Copy the value data to storage. The |size| is written last, atomically, to
  // release the copied data. Until then, a parallel reader will just ignore
  // records with a zero size.
  DCHECK_EQ(type, info->type);
  size = std::min(size, info->extent);
  info->size_ptr->store(0, std::memory_order_seq_cst);
  memcpy(info->memory, memory, size);
  info->size_ptr->store(size, std::memory_order_release);
}

void ActivityUserData::SetReference(StringPiece name,
                                    ValueType type,
                                    const void* memory,
                                    size_t size) {
  ReferenceRecord rec;
  rec.address = reinterpret_cast<uintptr_t>(memory);
  rec.size = size;
  Set(name, type, &rec, sizeof(rec));
}

// This information is kept for every thread that is tracked. It is filled
// the very first time the thread is seen. All fields must be of exact sizes
// so there is no issue moving between 32 and 64-bit builds.
struct ThreadActivityTracker::Header {
  // This unique number indicates a valid initialization of the memory.
  std::atomic<uint32_t> cookie;
  uint32_t reserved;  // pad out to 64 bits

  // The process-id and thread-id (thread_ref.as_id) to which this data belongs.
  // These identifiers are not guaranteed to mean anything but are unique, in
  // combination, among all active trackers. It would be nice to always have
  // the process_id be a 64-bit value but the necessity of having it atomic
  // (for the memory barriers it provides) limits it to the natural word size
  // of the machine.
#ifdef ARCH_CPU_64_BITS
  std::atomic<int64_t> process_id;
#else
  std::atomic<int32_t> process_id;
  int32_t process_id_padding;
#endif
  ThreadRef thread_ref;

  // The start-time and start-ticks when the data was created. Each activity
  // record has a |time_internal| value that can be converted to a "wall time"
  // with these two values.
  int64_t start_time;
  int64_t start_ticks;

  // The number of Activity slots in the data.
  uint32_t stack_slots;

  // The current depth of the stack. This may be greater than the number of
  // slots. If the depth exceeds the number of slots, the newest entries
  // won't be recorded.
  std::atomic<uint32_t> current_depth;

  // A memory location used to indicate if changes have been made to the stack
  // that would invalidate an in-progress read of its contents. The active
  // tracker will zero the value whenever something gets popped from the
  // stack. A monitoring tracker can write a non-zero value here, copy the
  // stack contents, and read the value to know, if it is still non-zero, that
  // the contents didn't change while being copied. This can handle concurrent
  // snapshot operations only if each snapshot writes a different bit (which
  // is not the current implementation so no parallel snapshots allowed).
  std::atomic<uint32_t> stack_unchanged;

  // The name of the thread (up to a maximum length). Dynamic-length names
  // are not practical since the memory has to come from the same persistent
  // allocator that holds this structure and to which this object has no
  // reference.
  char thread_name[32];
};

ThreadActivityTracker::ScopedActivity::ScopedActivity(
    ThreadActivityTracker* tracker,
    const void* program_counter,
    const void* origin,
    Activity::Type type,
    const ActivityData& data)
    : tracker_(tracker) {
  if (tracker_)
    activity_id_ = tracker_->PushActivity(program_counter, origin, type, data);
}

ThreadActivityTracker::ScopedActivity::~ScopedActivity() {
  if (tracker_)
    tracker_->PopActivity(activity_id_);
}

void ThreadActivityTracker::ScopedActivity::ChangeTypeAndData(
    Activity::Type type,
    const ActivityData& data) {
  if (tracker_)
    tracker_->ChangeActivity(activity_id_, type, data);
}

ActivityUserData& ThreadActivityTracker::ScopedActivity::user_data() {
  if (!user_data_) {
    if (tracker_)
      user_data_ = tracker_->GetUserData(activity_id_);
    else
      user_data_ = MakeUnique<ActivityUserData>(nullptr, 0);
  }
  return *user_data_;
}

ThreadActivityTracker::ThreadActivityTracker(void* base, size_t size)
    : header_(static_cast<Header*>(base)),
      stack_(reinterpret_cast<Activity*>(reinterpret_cast<char*>(base) +
                                         sizeof(Header))),
      stack_slots_(
          static_cast<uint32_t>((size - sizeof(Header)) / sizeof(Activity))) {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Verify the parameters but fail gracefully if they're not valid so that
  // production code based on external inputs will not crash.  IsValid() will
  // return false in this case.
  if (!base ||
      // Ensure there is enough space for the header and at least a few records.
      size < sizeof(Header) + kMinStackDepth * sizeof(Activity) ||
      // Ensure that the |stack_slots_| calculation didn't overflow.
      (size - sizeof(Header)) / sizeof(Activity) >
          std::numeric_limits<uint32_t>::max()) {
    NOTREACHED();
    return;
  }

  // Ensure that the thread reference doesn't exceed the size of the ID number.
  // This won't compile at the global scope because Header is a private struct.
  static_assert(
      sizeof(header_->thread_ref) == sizeof(header_->thread_ref.as_id),
      "PlatformThreadHandle::Handle is too big to hold in 64-bit ID");

  // Ensure that the alignment of Activity.data is properly aligned to a
  // 64-bit boundary so there are no interoperability-issues across cpu
  // architectures.
  static_assert(offsetof(Activity, data) % sizeof(uint64_t) == 0,
                "ActivityData.data is not 64-bit aligned");

  // Provided memory should either be completely initialized or all zeros.
  if (header_->cookie.load(std::memory_order_relaxed) == 0) {
    // This is a new file. Double-check other fields and then initialize.
    DCHECK_EQ(0, header_->process_id.load(std::memory_order_relaxed));
    DCHECK_EQ(0, header_->thread_ref.as_id);
    DCHECK_EQ(0, header_->start_time);
    DCHECK_EQ(0, header_->start_ticks);
    DCHECK_EQ(0U, header_->stack_slots);
    DCHECK_EQ(0U, header_->current_depth.load(std::memory_order_relaxed));
    DCHECK_EQ(0U, header_->stack_unchanged.load(std::memory_order_relaxed));
    DCHECK_EQ(0, stack_[0].time_internal);
    DCHECK_EQ(0U, stack_[0].origin_address);
    DCHECK_EQ(0U, stack_[0].call_stack[0]);
    DCHECK_EQ(0U, stack_[0].data.task.sequence_id);

#if defined(OS_WIN)
    header_->thread_ref.as_tid = PlatformThread::CurrentId();
#elif defined(OS_POSIX)
    header_->thread_ref.as_handle =
        PlatformThread::CurrentHandle().platform_handle();
#endif
    header_->process_id.store(GetCurrentProcId(), std::memory_order_relaxed);

    header_->start_time = base::Time::Now().ToInternalValue();
    header_->start_ticks = base::TimeTicks::Now().ToInternalValue();
    header_->stack_slots = stack_slots_;
    strlcpy(header_->thread_name, PlatformThread::GetName(),
            sizeof(header_->thread_name));

    // This is done last so as to guarantee that everything above is "released"
    // by the time this value gets written.
    header_->cookie.store(kHeaderCookie, std::memory_order_release);

    valid_ = true;
    DCHECK(IsValid());
  } else {
    // This is a file with existing data. Perform basic consistency checks.
    valid_ = true;
    valid_ = IsValid();
  }
}

ThreadActivityTracker::~ThreadActivityTracker() {}

ThreadActivityTracker::ActivityId ThreadActivityTracker::PushActivity(
    const void* program_counter,
    const void* origin,
    Activity::Type type,
    const ActivityData& data) {
  // A thread-checker creates a lock to check the thread-id which means
  // re-entry into this code if lock acquisitions are being tracked.
  DCHECK(type == Activity::ACT_LOCK_ACQUIRE ||
         thread_checker_.CalledOnValidThread());

  // Get the current depth of the stack. No access to other memory guarded
  // by this variable is done here so a "relaxed" load is acceptable.
  uint32_t depth = header_->current_depth.load(std::memory_order_relaxed);

  // Handle the case where the stack depth has exceeded the storage capacity.
  // Extra entries will be lost leaving only the base of the stack.
  if (depth >= stack_slots_) {
    // Since no other threads modify the data, no compare/exchange is needed.
    // Since no other memory is being modified, a "relaxed" store is acceptable.
    header_->current_depth.store(depth + 1, std::memory_order_relaxed);
    return depth;
  }

  // Get a pointer to the next activity and load it. No atomicity is required
  // here because the memory is known only to this thread. It will be made
  // known to other threads once the depth is incremented.
  Activity::FillFrom(&stack_[depth], program_counter, origin, type, data);

  // Save the incremented depth. Because this guards |activity| memory filled
  // above that may be read by another thread once the recorded depth changes,
  // a "release" store is required.
  header_->current_depth.store(depth + 1, std::memory_order_release);

  // The current depth is used as the activity ID because it simply identifies
  // an entry. Once an entry is pop'd, it's okay to reuse the ID.
  return depth;
}

void ThreadActivityTracker::ChangeActivity(ActivityId id,
                                           Activity::Type type,
                                           const ActivityData& data) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(type != Activity::ACT_NULL || &data != &kNullActivityData);
  DCHECK_LT(id, header_->current_depth.load(std::memory_order_acquire));

  // Update the information if it is being recorded (i.e. within slot limit).
  if (id < stack_slots_) {
    Activity* activity = &stack_[id];

    if (type != Activity::ACT_NULL) {
      DCHECK_EQ(activity->activity_type & Activity::ACT_CATEGORY_MASK,
                type & Activity::ACT_CATEGORY_MASK);
      activity->activity_type = type;
    }

    if (&data != &kNullActivityData)
      activity->data = data;
  }
}

void ThreadActivityTracker::PopActivity(ActivityId id) {
  // Do an atomic decrement of the depth. No changes to stack entries guarded
  // by this variable are done here so a "relaxed" operation is acceptable.
  // |depth| will receive the value BEFORE it was modified which means the
  // return value must also be decremented. The slot will be "free" after
  // this call but since only a single thread can access this object, the
  // data will remain valid until this method returns or calls outside.
  uint32_t depth =
      header_->current_depth.fetch_sub(1, std::memory_order_relaxed) - 1;

  // Validate that everything is running correctly.
  DCHECK_EQ(id, depth);

  // A thread-checker creates a lock to check the thread-id which means
  // re-entry into this code if lock acquisitions are being tracked.
  DCHECK(stack_[depth].activity_type == Activity::ACT_LOCK_ACQUIRE ||
         thread_checker_.CalledOnValidThread());

  // Check if there was any user-data memory. It isn't free'd until later
  // because the call to release it can push something on the stack.
  PersistentMemoryAllocator::Reference user_data = stack_[depth].user_data;
  stack_[depth].user_data = 0;

  // The stack has shrunk meaning that some other thread trying to copy the
  // contents for reporting purposes could get bad data. That thread would
  // have written a non-zero value into |stack_unchanged|; clearing it here
  // will let that thread detect that something did change. This needs to
  // happen after the atomic |depth| operation above so a "release" store
  // is required.
  header_->stack_unchanged.store(0, std::memory_order_release);

  // Release resources located above. All stack processing is done so it's
  // safe if some outside code does another push.
  if (user_data)
    GlobalActivityTracker::Get()->ReleaseUserDataMemory(&user_data);
}

std::unique_ptr<ActivityUserData> ThreadActivityTracker::GetUserData(
    ActivityId id) {
  // User-data is only stored for activities actually held in the stack.
  if (id < stack_slots_) {
    void* memory =
        GlobalActivityTracker::Get()->GetUserDataMemory(&stack_[id].user_data);
    if (memory)
      return MakeUnique<ActivityUserData>(memory, kUserDataSize);
  }

  // Return a dummy object that will still accept (but ignore) Set() calls.
  return MakeUnique<ActivityUserData>(nullptr, 0);
}

bool ThreadActivityTracker::IsValid() const {
  if (header_->cookie.load(std::memory_order_acquire) != kHeaderCookie ||
      header_->process_id.load(std::memory_order_relaxed) == 0 ||
      header_->thread_ref.as_id == 0 ||
      header_->start_time == 0 ||
      header_->start_ticks == 0 ||
      header_->stack_slots != stack_slots_ ||
      header_->thread_name[sizeof(header_->thread_name) - 1] != '\0') {
    return false;
  }

  return valid_;
}

bool ThreadActivityTracker::Snapshot(ActivitySnapshot* output_snapshot) const {
  DCHECK(output_snapshot);

  // There is no "called on valid thread" check for this method as it can be
  // called from other threads or even other processes. It is also the reason
  // why atomic operations must be used in certain places above.

  // It's possible for the data to change while reading it in such a way that it
  // invalidates the read. Make several attempts but don't try forever.
  const int kMaxAttempts = 10;
  uint32_t depth;

  // Stop here if the data isn't valid.
  if (!IsValid())
    return false;

  // Allocate the maximum size for the stack so it doesn't have to be done
  // during the time-sensitive snapshot operation. It is shrunk once the
  // actual size is known.
  output_snapshot->activity_stack.reserve(stack_slots_);

  for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
    // Remember the process and thread IDs to ensure they aren't replaced
    // during the snapshot operation. Use "acquire" to ensure that all the
    // non-atomic fields of the structure are valid (at least at the current
    // moment in time).
    const int64_t starting_process_id =
        header_->process_id.load(std::memory_order_acquire);
    const int64_t starting_thread_id = header_->thread_ref.as_id;

    // Write a non-zero value to |stack_unchanged| so it's possible to detect
    // at the end that nothing has changed since copying the data began. A
    // "cst" operation is required to ensure it occurs before everything else.
    // Using "cst" memory ordering is relatively expensive but this is only
    // done during analysis so doesn't directly affect the worker threads.
    header_->stack_unchanged.store(1, std::memory_order_seq_cst);

    // Fetching the current depth also "acquires" the contents of the stack.
    depth = header_->current_depth.load(std::memory_order_acquire);
    uint32_t count = std::min(depth, stack_slots_);
    output_snapshot->activity_stack.resize(count);
    if (count > 0) {
      // Copy the existing contents. Memcpy is used for speed.
      memcpy(&output_snapshot->activity_stack[0], stack_,
             count * sizeof(Activity));
    }

    // Retry if something changed during the copy. A "cst" operation ensures
    // it must happen after all the above operations.
    if (!header_->stack_unchanged.load(std::memory_order_seq_cst))
      continue;

    // Stack copied. Record it's full depth.
    output_snapshot->activity_stack_depth = depth;

    // TODO(bcwhite): Snapshot other things here.

    // Get the general thread information. Loading of "process_id" is guaranteed
    // to be last so that it's possible to detect below if any content has
    // changed while reading it. It's technically possible for a thread to end,
    // have its data cleared, a new thread get created with the same IDs, and
    // it perform an action which starts tracking all in the time since the
    // ID reads above but the chance is so unlikely that it's not worth the
    // effort and complexity of protecting against it (perhaps with an
    // "unchanged" field like is done for the stack).
    output_snapshot->thread_name =
        std::string(header_->thread_name, sizeof(header_->thread_name) - 1);
    output_snapshot->thread_id = header_->thread_ref.as_id;
    output_snapshot->process_id =
        header_->process_id.load(std::memory_order_seq_cst);

    // All characters of the thread-name buffer were copied so as to not break
    // if the trailing NUL were missing. Now limit the length if the actual
    // name is shorter.
    output_snapshot->thread_name.resize(
        strlen(output_snapshot->thread_name.c_str()));

    // If the process or thread ID has changed then the tracker has exited and
    // the memory reused by a new one. Try again.
    if (output_snapshot->process_id != starting_process_id ||
        output_snapshot->thread_id != starting_thread_id) {
      continue;
    }

    // Only successful if the data is still valid once everything is done since
    // it's possible for the thread to end somewhere in the middle and all its
    // values become garbage.
    if (!IsValid())
      return false;

    // Change all the timestamps in the activities from "ticks" to "wall" time.
    const Time start_time = Time::FromInternalValue(header_->start_time);
    const int64_t start_ticks = header_->start_ticks;
    for (Activity& activity : output_snapshot->activity_stack) {
      activity.time_internal =
          (start_time +
           TimeDelta::FromInternalValue(activity.time_internal - start_ticks))
              .ToInternalValue();
    }

    // Success!
    return true;
  }

  // Too many attempts.
  return false;
}

// static
size_t ThreadActivityTracker::SizeForStackDepth(int stack_depth) {
  return static_cast<size_t>(stack_depth) * sizeof(Activity) + sizeof(Header);
}


GlobalActivityTracker* GlobalActivityTracker::g_tracker_ = nullptr;

GlobalActivityTracker::ManagedActivityTracker::ManagedActivityTracker(
    PersistentMemoryAllocator::Reference mem_reference,
    void* base,
    size_t size)
    : ThreadActivityTracker(base, size),
      mem_reference_(mem_reference),
      mem_base_(base) {}

GlobalActivityTracker::ManagedActivityTracker::~ManagedActivityTracker() {
  // The global |g_tracker_| must point to the owner of this class since all
  // objects of this type must be destructed before |g_tracker_| can be changed
  // (something that only occurs in tests).
  DCHECK(g_tracker_);
  g_tracker_->ReturnTrackerMemory(this);
}

void GlobalActivityTracker::CreateWithAllocator(
    std::unique_ptr<PersistentMemoryAllocator> allocator,
    int stack_depth) {
  // There's no need to do anything with the result. It is self-managing.
  GlobalActivityTracker* global_tracker =
      new GlobalActivityTracker(std::move(allocator), stack_depth);
  // Create a tracker for this thread since it is known.
  global_tracker->CreateTrackerForCurrentThread();
}

#if !defined(OS_NACL)
// static
void GlobalActivityTracker::CreateWithFile(const FilePath& file_path,
                                           size_t size,
                                           uint64_t id,
                                           StringPiece name,
                                           int stack_depth) {
  DCHECK(!file_path.empty());
  DCHECK_GE(static_cast<uint64_t>(std::numeric_limits<int64_t>::max()), size);

  // Create and map the file into memory and make it globally available.
  std::unique_ptr<MemoryMappedFile> mapped_file(new MemoryMappedFile());
  bool success =
      mapped_file->Initialize(File(file_path,
                                   File::FLAG_CREATE_ALWAYS | File::FLAG_READ |
                                   File::FLAG_WRITE | File::FLAG_SHARE_DELETE),
                              {0, static_cast<int64_t>(size)},
                              MemoryMappedFile::READ_WRITE_EXTEND);
  DCHECK(success);
  CreateWithAllocator(MakeUnique<FilePersistentMemoryAllocator>(
                          std::move(mapped_file), size, id, name, false),
                      stack_depth);
}
#endif  // !defined(OS_NACL)

// static
void GlobalActivityTracker::CreateWithLocalMemory(size_t size,
                                                  uint64_t id,
                                                  StringPiece name,
                                                  int stack_depth) {
  CreateWithAllocator(
      MakeUnique<LocalPersistentMemoryAllocator>(size, id, name), stack_depth);
}

ThreadActivityTracker* GlobalActivityTracker::CreateTrackerForCurrentThread() {
  DCHECK(!this_thread_tracker_.Get());

  PersistentMemoryAllocator::Reference mem_reference;

  {
    base::AutoLock autolock(thread_tracker_allocator_lock_);
    mem_reference = thread_tracker_allocator_.GetObjectReference();
  }

  if (!mem_reference) {
    // Failure. This shouldn't happen. But be graceful if it does, probably
    // because the underlying allocator wasn't given enough memory to satisfy
    // to all possible requests.
    NOTREACHED();
    // Report the thread-count at which the allocator was full so that the
    // failure can be seen and underlying memory resized appropriately.
    UMA_HISTOGRAM_COUNTS_1000(
        "ActivityTracker.ThreadTrackers.MemLimitTrackerCount",
        thread_tracker_count_.load(std::memory_order_relaxed));
    // Return null, just as if tracking wasn't enabled.
    return nullptr;
  }

  // Convert the memory block found above into an actual memory address.
  DCHECK(mem_reference);
  void* mem_base =
      allocator_->GetAsObject<char>(mem_reference, kTypeIdActivityTracker);
  DCHECK(mem_base);
  DCHECK_LE(stack_memory_size_, allocator_->GetAllocSize(mem_reference));

  // Create a tracker with the acquired memory and set it as the tracker
  // for this particular thread in thread-local-storage.
  ManagedActivityTracker* tracker =
      new ManagedActivityTracker(mem_reference, mem_base, stack_memory_size_);
  DCHECK(tracker->IsValid());
  this_thread_tracker_.Set(tracker);
  int old_count = thread_tracker_count_.fetch_add(1, std::memory_order_relaxed);

  UMA_HISTOGRAM_ENUMERATION("ActivityTracker.ThreadTrackers.Count",
                            old_count + 1, kMaxThreadCount);
  return tracker;
}

void GlobalActivityTracker::ReleaseTrackerForCurrentThreadForTesting() {
  ThreadActivityTracker* tracker =
      reinterpret_cast<ThreadActivityTracker*>(this_thread_tracker_.Get());
  if (tracker)
    delete tracker;
}

void* GlobalActivityTracker::GetUserDataMemory(
    PersistentMemoryAllocator::Reference* reference) {
  if (!*reference) {
    base::AutoLock autolock(user_data_allocator_lock_);
    *reference = user_data_allocator_.GetObjectReference();
    if (!*reference)
      return nullptr;
  }

  void* memory =
      allocator_->GetAsObject<char>(*reference, kTypeIdUserDataRecord);
  DCHECK(memory);
  return memory;
}

void GlobalActivityTracker::ReleaseUserDataMemory(
    PersistentMemoryAllocator::Reference* reference) {
  DCHECK(*reference);
  base::AutoLock autolock(user_data_allocator_lock_);
  user_data_allocator_.ReleaseObjectReference(*reference);
  *reference = PersistentMemoryAllocator::kReferenceNull;
}

GlobalActivityTracker::GlobalActivityTracker(
    std::unique_ptr<PersistentMemoryAllocator> allocator,
    int stack_depth)
    : allocator_(std::move(allocator)),
      stack_memory_size_(ThreadActivityTracker::SizeForStackDepth(stack_depth)),
      this_thread_tracker_(&OnTLSDestroy),
      thread_tracker_count_(0),
      thread_tracker_allocator_(allocator_.get(),
                                kTypeIdActivityTracker,
                                kTypeIdActivityTrackerFree,
                                stack_memory_size_,
                                kCachedThreadMemories,
                                /*make_iterable=*/true),
      user_data_allocator_(allocator_.get(),
                           kTypeIdUserDataRecord,
                           kTypeIdUserDataRecordFree,
                           kUserDataSize,
                           kCachedUserDataMemories,
                           /*make_iterable=*/false),
      user_data_(
          allocator_->GetAsObject<char>(
              allocator_->Allocate(kGlobalDataSize, kTypeIdGlobalDataRecord),
              kTypeIdGlobalDataRecord),
          kGlobalDataSize) {
  // Ensure the passed memory is valid and empty (iterator finds nothing).
  uint32_t type;
  DCHECK(!PersistentMemoryAllocator::Iterator(allocator_.get()).GetNext(&type));

  // Ensure that there is no other global object and then make this one such.
  DCHECK(!g_tracker_);
  g_tracker_ = this;
}

GlobalActivityTracker::~GlobalActivityTracker() {
  DCHECK_EQ(g_tracker_, this);
  DCHECK_EQ(0, thread_tracker_count_.load(std::memory_order_relaxed));
  g_tracker_ = nullptr;
}

void GlobalActivityTracker::ReturnTrackerMemory(
    ManagedActivityTracker* tracker) {
  PersistentMemoryAllocator::Reference mem_reference = tracker->mem_reference_;
  void* mem_base = tracker->mem_base_;
  DCHECK(mem_reference);
  DCHECK(mem_base);

  // Remove the destructed tracker from the set of known ones.
  DCHECK_LE(1, thread_tracker_count_.load(std::memory_order_relaxed));
  thread_tracker_count_.fetch_sub(1, std::memory_order_relaxed);

  // Release this memory for re-use at a later time.
  base::AutoLock autolock(thread_tracker_allocator_lock_);
  thread_tracker_allocator_.ReleaseObjectReference(mem_reference);
}

// static
void GlobalActivityTracker::OnTLSDestroy(void* value) {
  delete reinterpret_cast<ManagedActivityTracker*>(value);
}

ScopedActivity::ScopedActivity(const void* program_counter,
                               uint8_t action,
                               uint32_t id,
                               int32_t info)
    : GlobalActivityTracker::ScopedThreadActivity(
          program_counter,
          nullptr,
          static_cast<Activity::Type>(Activity::ACT_GENERIC | action),
          ActivityData::ForGeneric(id, info),
          /*lock_allowed=*/true),
      id_(id) {
  // The action must not affect the category bits of the activity type.
  DCHECK_EQ(0, action & Activity::ACT_CATEGORY_MASK);
}

void ScopedActivity::ChangeAction(uint8_t action) {
  DCHECK_EQ(0, action & Activity::ACT_CATEGORY_MASK);
  ChangeTypeAndData(static_cast<Activity::Type>(Activity::ACT_GENERIC | action),
                    kNullActivityData);
}

void ScopedActivity::ChangeInfo(int32_t info) {
  ChangeTypeAndData(Activity::ACT_NULL, ActivityData::ForGeneric(id_, info));
}

void ScopedActivity::ChangeActionAndInfo(uint8_t action, int32_t info) {
  DCHECK_EQ(0, action & Activity::ACT_CATEGORY_MASK);
  ChangeTypeAndData(static_cast<Activity::Type>(Activity::ACT_GENERIC | action),
                    ActivityData::ForGeneric(id_, info));
}

ScopedTaskRunActivity::ScopedTaskRunActivity(
    const void* program_counter,
    const base::PendingTask& task)
    : GlobalActivityTracker::ScopedThreadActivity(
          program_counter,
          task.posted_from.program_counter(),
          Activity::ACT_TASK_RUN,
          ActivityData::ForTask(task.sequence_num),
          /*lock_allowed=*/true) {}

ScopedLockAcquireActivity::ScopedLockAcquireActivity(
    const void* program_counter,
    const base::internal::LockImpl* lock)
    : GlobalActivityTracker::ScopedThreadActivity(
          program_counter,
          nullptr,
          Activity::ACT_LOCK_ACQUIRE,
          ActivityData::ForLock(lock),
          /*lock_allowed=*/false) {}

ScopedEventWaitActivity::ScopedEventWaitActivity(
    const void* program_counter,
    const base::WaitableEvent* event)
    : GlobalActivityTracker::ScopedThreadActivity(
          program_counter,
          nullptr,
          Activity::ACT_EVENT_WAIT,
          ActivityData::ForEvent(event),
          /*lock_allowed=*/true) {}

ScopedThreadJoinActivity::ScopedThreadJoinActivity(
    const void* program_counter,
    const base::PlatformThreadHandle* thread)
    : GlobalActivityTracker::ScopedThreadActivity(
          program_counter,
          nullptr,
          Activity::ACT_THREAD_JOIN,
          ActivityData::ForThread(*thread),
          /*lock_allowed=*/true) {}

#if !defined(OS_NACL) && !defined(OS_IOS)
ScopedProcessWaitActivity::ScopedProcessWaitActivity(
    const void* program_counter,
    const base::Process* process)
    : GlobalActivityTracker::ScopedThreadActivity(
          program_counter,
          nullptr,
          Activity::ACT_PROCESS_WAIT,
          ActivityData::ForProcess(process->Pid()),
          /*lock_allowed=*/true) {}
#endif

}  // namespace debug
}  // namespace base
