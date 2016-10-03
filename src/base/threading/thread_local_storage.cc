// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/threading/thread_local_storage.h"

#include "base/atomicops.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/synchronization/lock.h"
#include "build/build_config.h"

using base::internal::PlatformThreadLocalStorage;

namespace {
// In order to make TLS destructors work, we need to keep around a function
// pointer to the destructor for each slot. We keep this array of pointers in a
// global (static) array.
// We use the single OS-level TLS slot (giving us one pointer per thread) to
// hold a pointer to a per-thread array (table) of slots that we allocate to
// Chromium consumers.

// g_native_tls_key is the one native TLS that we use. It stores our table.
base::subtle::Atomic32 g_native_tls_key =
    PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES;

// The maximum number of slots in our thread local storage stack.
constexpr int kThreadLocalStorageSize = 256;
constexpr int kInvalidSlotValue = -1;

enum TlsStatus {
  FREE,
  IN_USE,
};

struct TlsMetadata {
  TlsStatus status;
  base::ThreadLocalStorage::TLSDestructorFunc destructor;
};

// This LazyInstance isn't needed until after we've constructed the per-thread
// TLS vector, so it's safe to use.
base::LazyInstance<base::Lock>::Leaky g_tls_metadata_lock;
TlsMetadata g_tls_metadata[kThreadLocalStorageSize];
size_t g_last_assigned_slot = 0;

// The maximum number of times to try to clear slots by calling destructors.
// Use pthread naming convention for clarity.
constexpr int kMaxDestructorIterations = kThreadLocalStorageSize;

// This function is called to initialize our entire Chromium TLS system.
// It may be called very early, and we need to complete most all of the setup
// (initialization) before calling *any* memory allocator functions, which may
// recursively depend on this initialization.
// As a result, we use Atomics, and avoid anything (like a singleton) that might
// require memory allocations.
void** ConstructTlsVector() {
  PlatformThreadLocalStorage::TLSKey key =
      base::subtle::NoBarrier_Load(&g_native_tls_key);
  if (key == PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES) {
    CHECK(PlatformThreadLocalStorage::AllocTLS(&key));

    // The TLS_KEY_OUT_OF_INDEXES is used to find out whether the key is set or
    // not in NoBarrier_CompareAndSwap, but Posix doesn't have invalid key, we
    // define an almost impossible value be it.
    // If we really get TLS_KEY_OUT_OF_INDEXES as value of key, just alloc
    // another TLS slot.
    if (key == PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES) {
      PlatformThreadLocalStorage::TLSKey tmp = key;
      CHECK(PlatformThreadLocalStorage::AllocTLS(&key) &&
            key != PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES);
      PlatformThreadLocalStorage::FreeTLS(tmp);
    }
    // Atomically test-and-set the tls_key. If the key is
    // TLS_KEY_OUT_OF_INDEXES, go ahead and set it. Otherwise, do nothing, as
    // another thread already did our dirty work.
    if (PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES !=
        static_cast<PlatformThreadLocalStorage::TLSKey>(
            base::subtle::NoBarrier_CompareAndSwap(
                &g_native_tls_key,
                PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES, key))) {
      // We've been shortcut. Another thread replaced g_native_tls_key first so
      // we need to destroy our index and use the one the other thread got
      // first.
      PlatformThreadLocalStorage::FreeTLS(key);
      key = base::subtle::NoBarrier_Load(&g_native_tls_key);
    }
  }
  CHECK(!PlatformThreadLocalStorage::GetTLSValue(key));

  // Some allocators, such as TCMalloc, make use of thread local storage. As a
  // result, any attempt to call new (or malloc) will lazily cause such a system
  // to initialize, which will include registering for a TLS key. If we are not
  // careful here, then that request to create a key will call new back, and
  // we'll have an infinite loop. We avoid that as follows: Use a stack
  // allocated vector, so that we don't have dependence on our allocator until
  // our service is in place. (i.e., don't even call new until after we're
  // setup)
  void* stack_allocated_tls_data[kThreadLocalStorageSize];
  memset(stack_allocated_tls_data, 0, sizeof(stack_allocated_tls_data));
  // Ensure that any rentrant calls change the temp version.
  PlatformThreadLocalStorage::SetTLSValue(key, stack_allocated_tls_data);

  // Allocate an array to store our data.
  void** tls_data = new void*[kThreadLocalStorageSize];
  memcpy(tls_data, stack_allocated_tls_data, sizeof(stack_allocated_tls_data));
  PlatformThreadLocalStorage::SetTLSValue(key, tls_data);
  return tls_data;
}

void OnThreadExitInternal(void* value) {
  DCHECK(value);
  void** tls_data = static_cast<void**>(value);
  // Some allocators, such as TCMalloc, use TLS. As a result, when a thread
  // terminates, one of the destructor calls we make may be to shut down an
  // allocator. We have to be careful that after we've shutdown all of the known
  // destructors (perchance including an allocator), that we don't call the
  // allocator and cause it to resurrect itself (with no possibly destructor
  // call to follow). We handle this problem as follows: Switch to using a stack
  // allocated vector, so that we don't have dependence on our allocator after
  // we have called all g_tls_metadata destructors. (i.e., don't even call
  // delete[] after we're done with destructors.)
  void* stack_allocated_tls_data[kThreadLocalStorageSize];
  memcpy(stack_allocated_tls_data, tls_data, sizeof(stack_allocated_tls_data));
  // Ensure that any re-entrant calls change the temp version.
  PlatformThreadLocalStorage::TLSKey key =
      base::subtle::NoBarrier_Load(&g_native_tls_key);
  PlatformThreadLocalStorage::SetTLSValue(key, stack_allocated_tls_data);
  delete[] tls_data;  // Our last dependence on an allocator.

  // Snapshot the TLS Metadata so we don't have to lock on every access.
  TlsMetadata tls_metadata[kThreadLocalStorageSize];
  {
    base::AutoLock auto_lock(g_tls_metadata_lock.Get());
    memcpy(tls_metadata, g_tls_metadata, sizeof(g_tls_metadata));
  }

  int remaining_attempts = kMaxDestructorIterations;
  bool need_to_scan_destructors = true;
  while (need_to_scan_destructors) {
    need_to_scan_destructors = false;
    // Try to destroy the first-created-slot (which is slot 1) in our last
    // destructor call. That user was able to function, and define a slot with
    // no other services running, so perhaps it is a basic service (like an
    // allocator) and should also be destroyed last. If we get the order wrong,
    // then we'll iterate several more times, so it is really not that critical
    // (but it might help).
    for (int slot = 0; slot < kThreadLocalStorageSize ; ++slot) {
      void* tls_value = stack_allocated_tls_data[slot];
      if (!tls_value || tls_metadata[slot].status == TlsStatus::FREE)
        continue;

      base::ThreadLocalStorage::TLSDestructorFunc destructor =
          tls_metadata[slot].destructor;
      if (!destructor)
        continue;
      stack_allocated_tls_data[slot] = nullptr;  // pre-clear the slot.
      destructor(tls_value);
      // Any destructor might have called a different service, which then set a
      // different slot to a non-null value. Hence we need to check the whole
      // vector again. This is a pthread standard.
      need_to_scan_destructors = true;
    }
    if (--remaining_attempts <= 0) {
      NOTREACHED();  // Destructors might not have been called.
      break;
    }
  }

  // Remove our stack allocated vector.
  PlatformThreadLocalStorage::SetTLSValue(key, nullptr);
}

}  // namespace

namespace base {

namespace internal {

#if defined(OS_WIN)
void PlatformThreadLocalStorage::OnThreadExit() {
  PlatformThreadLocalStorage::TLSKey key =
      base::subtle::NoBarrier_Load(&g_native_tls_key);
  if (key == PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES)
    return;
  void *tls_data = GetTLSValue(key);
  // Maybe we have never initialized TLS for this thread.
  if (!tls_data)
    return;
  OnThreadExitInternal(tls_data);
}
#elif defined(OS_POSIX)
void PlatformThreadLocalStorage::OnThreadExit(void* value) {
  OnThreadExitInternal(value);
}
#endif  // defined(OS_WIN)

}  // namespace internal

void ThreadLocalStorage::StaticSlot::Initialize(TLSDestructorFunc destructor) {
  PlatformThreadLocalStorage::TLSKey key =
      base::subtle::NoBarrier_Load(&g_native_tls_key);
  if (key == PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES ||
      !PlatformThreadLocalStorage::GetTLSValue(key)) {
    ConstructTlsVector();
  }

  // Grab a new slot.
  slot_ = kInvalidSlotValue;
  {
    base::AutoLock auto_lock(g_tls_metadata_lock.Get());
    for (int i = 0; i < kThreadLocalStorageSize; ++i) {
      // Tracking the last assigned slot is an attempt to find the next
      // available slot within one iteration. Under normal usage, slots remain
      // in use for the lifetime of the process (otherwise before we reclaimed
      // slots, we would have run out of slots). This makes it highly likely the
      // next slot is going to be a free slot.
      size_t slot_candidate =
          (g_last_assigned_slot + 1 + i) % kThreadLocalStorageSize;
      if (g_tls_metadata[slot_candidate].status == TlsStatus::FREE) {
        g_tls_metadata[slot_candidate].status = TlsStatus::IN_USE;
        g_tls_metadata[slot_candidate].destructor = destructor;
        g_last_assigned_slot = slot_candidate;
        slot_ = slot_candidate;
        break;
      }
    }
  }
  CHECK_NE(slot_, kInvalidSlotValue);
  CHECK_LT(slot_, kThreadLocalStorageSize);

  // Setup our destructor.
  base::subtle::Release_Store(&initialized_, 1);
}

void ThreadLocalStorage::StaticSlot::Free() {
  DCHECK_NE(slot_, kInvalidSlotValue);
  DCHECK_LT(slot_, kThreadLocalStorageSize);
  {
    base::AutoLock auto_lock(g_tls_metadata_lock.Get());
    g_tls_metadata[slot_].status = TlsStatus::FREE;
    g_tls_metadata[slot_].destructor = nullptr;
  }
  slot_ = kInvalidSlotValue;
  base::subtle::Release_Store(&initialized_, 0);
}

void* ThreadLocalStorage::StaticSlot::Get() const {
  void** tls_data = static_cast<void**>(
      PlatformThreadLocalStorage::GetTLSValue(
          base::subtle::NoBarrier_Load(&g_native_tls_key)));
  if (!tls_data)
    tls_data = ConstructTlsVector();
  DCHECK_NE(slot_, kInvalidSlotValue);
  DCHECK_LT(slot_, kThreadLocalStorageSize);
  return tls_data[slot_];
}

void ThreadLocalStorage::StaticSlot::Set(void* value) {
  void** tls_data = static_cast<void**>(
      PlatformThreadLocalStorage::GetTLSValue(
          base::subtle::NoBarrier_Load(&g_native_tls_key)));
  if (!tls_data)
    tls_data = ConstructTlsVector();
  DCHECK_NE(slot_, kInvalidSlotValue);
  DCHECK_LT(slot_, kThreadLocalStorageSize);
  tls_data[slot_] = value;
}

ThreadLocalStorage::Slot::Slot(TLSDestructorFunc destructor) {
  tls_slot_.Initialize(destructor);
}

ThreadLocalStorage::Slot::~Slot() {
  tls_slot_.Free();
}

void* ThreadLocalStorage::Slot::Get() const {
  return tls_slot_.Get();
}

void ThreadLocalStorage::Slot::Set(void* value) {
  tls_slot_.Set(value);
}

}  // namespace base
