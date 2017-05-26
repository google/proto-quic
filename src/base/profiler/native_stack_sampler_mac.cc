// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/profiler/native_stack_sampler.h"

#include <dlfcn.h>
#include <libkern/OSByteOrder.h>
#include <libunwind.h>
#include <mach-o/compact_unwind_encoding.h>
#include <mach-o/swap.h>
#include <mach/kern_return.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/syslimits.h>

#include <algorithm>
#include <map>
#include <memory>

#include "base/logging.h"
#include "base/mac/mach_logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string_number_conversions.h"

namespace base {

namespace {

// Stack walking --------------------------------------------------------------

// Fills |state| with |target_thread|'s context.
//
// Note that this is called while a thread is suspended. Make very very sure
// that no shared resources (e.g. memory allocators) are used for the duration
// of this function.
bool GetThreadState(thread_act_t target_thread, x86_thread_state64_t* state) {
  mach_msg_type_number_t count =
      static_cast<mach_msg_type_number_t>(x86_THREAD_STATE64_COUNT);
  return thread_get_state(target_thread, x86_THREAD_STATE64,
                          reinterpret_cast<thread_state_t>(state),
                          &count) == KERN_SUCCESS;
}

// If the value at |pointer| points to the original stack, rewrites it to point
// to the corresponding location in the copied stack.
//
// Note that this is called while a thread is suspended. Make very very sure
// that no shared resources (e.g. memory allocators) are used for the duration
// of this function.
uintptr_t RewritePointerIfInOriginalStack(
    const uintptr_t* original_stack_bottom,
    const uintptr_t* original_stack_top,
    uintptr_t* stack_copy_bottom,
    uintptr_t pointer) {
  uintptr_t original_stack_bottom_int =
      reinterpret_cast<uintptr_t>(original_stack_bottom);
  uintptr_t original_stack_top_int =
      reinterpret_cast<uintptr_t>(original_stack_top);
  uintptr_t stack_copy_bottom_int =
      reinterpret_cast<uintptr_t>(stack_copy_bottom);

  if ((pointer < original_stack_bottom_int) ||
      (pointer >= original_stack_top_int)) {
    return pointer;
  }

  return stack_copy_bottom_int + (pointer - original_stack_bottom_int);
}

// Copies the stack to a buffer while rewriting possible pointers to locations
// within the stack to point to the corresponding locations in the copy. This is
// necessary to handle stack frames with dynamic stack allocation, where a
// pointer to the beginning of the dynamic allocation area is stored on the
// stack and/or in a non-volatile register.
//
// Eager rewriting of anything that looks like a pointer to the stack, as done
// in this function, does not adversely affect the stack unwinding. The only
// other values on the stack the unwinding depends on are return addresses,
// which should not point within the stack memory. The rewriting is guaranteed
// to catch all pointers because the stacks are guaranteed by the ABI to be
// sizeof(void*) aligned.
//
// Note that this is called while a thread is suspended. Make very very sure
// that no shared resources (e.g. memory allocators) are used for the duration
// of this function.
void CopyStackAndRewritePointers(uintptr_t* stack_copy_bottom,
                                 const uintptr_t* original_stack_bottom,
                                 const uintptr_t* original_stack_top,
                                 x86_thread_state64_t* thread_state)
    NO_SANITIZE("address") {
  size_t count = original_stack_top - original_stack_bottom;
  for (size_t pos = 0; pos < count; ++pos) {
    stack_copy_bottom[pos] = RewritePointerIfInOriginalStack(
        original_stack_bottom, original_stack_top, stack_copy_bottom,
        original_stack_bottom[pos]);
  }

  uint64_t* rewrite_registers[] = {&thread_state->__rbx, &thread_state->__rbp,
                                   &thread_state->__rsp, &thread_state->__r12,
                                   &thread_state->__r13, &thread_state->__r14,
                                   &thread_state->__r15};
  for (auto* reg : rewrite_registers) {
    *reg = RewritePointerIfInOriginalStack(
        original_stack_bottom, original_stack_top, stack_copy_bottom, *reg);
  }
}

// Walks the stack represented by |unwind_context|, calling back to the provided
// lambda for each frame. Returns false if an error occurred, otherwise returns
// true.
template <typename StackFrameCallback>
bool WalkStackFromContext(unw_context_t* unwind_context,
                          uintptr_t stack_top,
                          size_t* frame_count,
                          const StackFrameCallback& callback) {
  unw_cursor_t unwind_cursor;
  unw_init_local(&unwind_cursor, unwind_context);

  int step_result;
  unw_word_t ip;
  do {
    ++(*frame_count);
    unw_get_reg(&unwind_cursor, UNW_REG_IP, &ip);

    callback(static_cast<uintptr_t>(ip));

    // If this stack frame has a frame pointer, stepping the cursor will involve
    // indexing memory access off of that pointer. In that case, sanity-check
    // the frame pointer register to ensure it's within bounds.
    unw_proc_info_t proc_info;
    unw_get_proc_info(&unwind_cursor, &proc_info);
    if ((proc_info.format & UNWIND_X86_64_MODE_MASK) ==
        UNWIND_X86_64_MODE_RBP_FRAME) {
      unw_word_t rsp, rbp;
      unw_get_reg(&unwind_cursor, UNW_X86_64_RSP, &rsp);
      unw_get_reg(&unwind_cursor, UNW_X86_64_RBP, &rbp);
      if (rbp < rsp || rbp > stack_top)
        return false;
    }

    step_result = unw_step(&unwind_cursor);
  } while (step_result > 0);

  if (step_result != 0)
    return false;

  return true;
}

const char* LibSystemKernelName() {
  static char path[PATH_MAX];
  static char* name = nullptr;
  if (name)
    return name;

  Dl_info info;
  dladdr(reinterpret_cast<void*>(_exit), &info);
  strlcpy(path, info.dli_fname, PATH_MAX);
  name = path;

#if !defined(ADDRESS_SANITIZER)
  DCHECK_EQ(std::string(name),
            std::string("/usr/lib/system/libsystem_kernel.dylib"));
#endif
  return name;
}

// Walks the stack represented by |thread_state|, calling back to the provided
// lambda for each frame.
template <typename StackFrameCallback>
void WalkStack(const x86_thread_state64_t& thread_state,
               uintptr_t stack_top,
               const StackFrameCallback& callback) {
  size_t frame_count = 0;
  // This uses libunwind to walk the stack. libunwind is designed to be used for
  // a thread to walk its own stack. This creates two problems.

  // Problem 1: There is no official way to create a unw_context other than to
  // create it from the current state of the current thread's stack. To get
  // around this, forge a context. A unw_context is just a copy of the 16 main
  // registers followed by the instruction pointer, nothing more.
  // Coincidentally, the first 17 items of the x86_thread_state64_t type are
  // exactly those registers in exactly the same order, so just bulk copy them
  // over.
  unw_context_t unwind_context;
  memcpy(&unwind_context, &thread_state, sizeof(uintptr_t) * 17);
  bool result =
      WalkStackFromContext(&unwind_context, stack_top, &frame_count, callback);

  if (!result)
    return;

  if (frame_count == 1) {
    // Problem 2: Because libunwind is designed to be triggered by user code on
    // their own thread, if it hits a library that has no unwind info for the
    // function that is being executed, it just stops. This isn't a problem in
    // the normal case, but in this case, it's quite possible that the stack
    // being walked is stopped in a function that bridges to the kernel and thus
    // is missing the unwind info.

    // For now, just unwind the single case where the thread is stopped in a
    // function in libsystem_kernel.
    uint64_t& rsp = unwind_context.data[7];
    uint64_t& rip = unwind_context.data[16];
    Dl_info info;
    if (dladdr(reinterpret_cast<void*>(rip), &info) != 0 &&
      strcmp(info.dli_fname, LibSystemKernelName()) == 0) {
      rip = *reinterpret_cast<uint64_t*>(rsp);
      rsp += 8;
      WalkStackFromContext(&unwind_context, stack_top, &frame_count, callback);
    }
  }
}

// Module identifiers ---------------------------------------------------------

// Returns the unique build ID for a module loaded at |module_addr|. Returns the
// empty string if the function fails to get the build ID.
//
// Build IDs are created by the concatenation of the module's GUID (Windows) /
// UUID (Mac) and an "age" field that indicates how many times that GUID/UUID
// has been reused. In Windows binaries, the "age" field is present in the
// module header, but on the Mac, UUIDs are never reused and so the "age" value
// appended to the UUID is always 0.
std::string GetUniqueId(const void* module_addr) {
  const mach_header_64* mach_header =
      reinterpret_cast<const mach_header_64*>(module_addr);
  DCHECK_EQ(MH_MAGIC_64, mach_header->magic);

  size_t offset = sizeof(mach_header_64);
  size_t offset_limit = sizeof(mach_header_64) + mach_header->sizeofcmds;
  for (uint32_t i = 0; (i < mach_header->ncmds) &&
                       (offset + sizeof(load_command) < offset_limit);
       ++i) {
    const load_command* current_cmd = reinterpret_cast<const load_command*>(
        reinterpret_cast<const uint8_t*>(mach_header) + offset);

    if (offset + current_cmd->cmdsize > offset_limit) {
      // This command runs off the end of the command list. This is malformed.
      return std::string();
    }

    if (current_cmd->cmd == LC_UUID) {
      if (current_cmd->cmdsize < sizeof(uuid_command)) {
        // This "UUID command" is too small. This is malformed.
        return std::string();
      }

      const uuid_command* uuid_cmd =
          reinterpret_cast<const uuid_command*>(current_cmd);
      static_assert(sizeof(uuid_cmd->uuid) == sizeof(uuid_t),
                    "UUID field of UUID command should be 16 bytes.");
      // The ID is comprised of the UUID concatenated with the Mac's "age" value
      // which is always 0.
      return HexEncode(&uuid_cmd->uuid, sizeof(uuid_cmd->uuid)) + "0";
    }
    offset += current_cmd->cmdsize;
  }
  return std::string();
}

// Gets the index for the Module containing |instruction_pointer| in
// |modules|, adding it if it's not already present. Returns
// StackSamplingProfiler::Frame::kUnknownModuleIndex if no Module can be
// determined for |module|.
size_t GetModuleIndex(const uintptr_t instruction_pointer,
                      std::vector<StackSamplingProfiler::Module>* modules,
                      std::map<const void*, size_t>* profile_module_index) {
  Dl_info inf;
  if (!dladdr(reinterpret_cast<const void*>(instruction_pointer), &inf))
    return StackSamplingProfiler::Frame::kUnknownModuleIndex;

  auto module_index = profile_module_index->find(inf.dli_fbase);
  if (module_index == profile_module_index->end()) {
    StackSamplingProfiler::Module module(
        reinterpret_cast<uintptr_t>(inf.dli_fbase), GetUniqueId(inf.dli_fbase),
        base::FilePath(inf.dli_fname));
    modules->push_back(module);
    module_index =
        profile_module_index
            ->insert(std::make_pair(inf.dli_fbase, modules->size() - 1))
            .first;
  }
  return module_index->second;
}

// ScopedSuspendThread --------------------------------------------------------

// Suspends a thread for the lifetime of the object.
class ScopedSuspendThread {
 public:
  explicit ScopedSuspendThread(mach_port_t thread_port)
      : thread_port_(thread_suspend(thread_port) == KERN_SUCCESS
                         ? thread_port
                         : MACH_PORT_NULL) {}

  ~ScopedSuspendThread() {
    if (!was_successful())
      return;

    kern_return_t kr = thread_resume(thread_port_);
    MACH_CHECK(kr == KERN_SUCCESS, kr) << "thread_resume";
  }

  bool was_successful() const { return thread_port_ != MACH_PORT_NULL; }

 private:
  mach_port_t thread_port_;

  DISALLOW_COPY_AND_ASSIGN(ScopedSuspendThread);
};

// NativeStackSamplerMac ------------------------------------------------------

class NativeStackSamplerMac : public NativeStackSampler {
 public:
  NativeStackSamplerMac(mach_port_t thread_port,
                        AnnotateCallback annotator,
                        NativeStackSamplerTestDelegate* test_delegate);
  ~NativeStackSamplerMac() override;

  // StackSamplingProfiler::NativeStackSampler:
  void ProfileRecordingStarting(
      std::vector<StackSamplingProfiler::Module>* modules) override;
  void RecordStackSample(StackBuffer* stack_buffer,
                         StackSamplingProfiler::Sample* sample) override;
  void ProfileRecordingStopped(StackBuffer* stack_buffer) override;

 private:
  // Suspends the thread with |thread_port_|, copies its stack and resumes the
  // thread, then records the stack frames and associated modules into |sample|.
  void SuspendThreadAndRecordStack(StackBuffer* stack_buffer,
                                   StackSamplingProfiler::Sample* sample);

  // Weak reference: Mach port for thread being profiled.
  mach_port_t thread_port_;

  const AnnotateCallback annotator_;

  NativeStackSamplerTestDelegate* const test_delegate_;

  // The stack base address corresponding to |thread_handle_|.
  const void* const thread_stack_base_address_;

  // Weak. Points to the modules associated with the profile being recorded
  // between ProfileRecordingStarting() and ProfileRecordingStopped().
  std::vector<StackSamplingProfiler::Module>* current_modules_ = nullptr;

  // Maps a module's base address to the corresponding Module's index within
  // current_modules_.
  std::map<const void*, size_t> profile_module_index_;

  DISALLOW_COPY_AND_ASSIGN(NativeStackSamplerMac);
};

NativeStackSamplerMac::NativeStackSamplerMac(
    mach_port_t thread_port,
    AnnotateCallback annotator,
    NativeStackSamplerTestDelegate* test_delegate)
    : thread_port_(thread_port),
      annotator_(annotator),
      test_delegate_(test_delegate),
      thread_stack_base_address_(
          pthread_get_stackaddr_np(pthread_from_mach_thread_np(thread_port))) {
  DCHECK(annotator_);

  // This class suspends threads, and those threads might be suspended in dyld.
  // Therefore, for all the system functions that might be linked in dynamically
  // that are used while threads are suspended, make calls to them to make sure
  // that they are linked up.
  x86_thread_state64_t thread_state;
  GetThreadState(thread_port_, &thread_state);
}

NativeStackSamplerMac::~NativeStackSamplerMac() {}

void NativeStackSamplerMac::ProfileRecordingStarting(
    std::vector<StackSamplingProfiler::Module>* modules) {
  current_modules_ = modules;
  profile_module_index_.clear();
}

void NativeStackSamplerMac::RecordStackSample(
    StackBuffer* stack_buffer,
    StackSamplingProfiler::Sample* sample) {
  DCHECK(current_modules_);

  SuspendThreadAndRecordStack(stack_buffer, sample);
}

void NativeStackSamplerMac::ProfileRecordingStopped(StackBuffer* stack_buffer) {
  current_modules_ = nullptr;
}

void NativeStackSamplerMac::SuspendThreadAndRecordStack(
    StackBuffer* stack_buffer,
    StackSamplingProfiler::Sample* sample) {
  x86_thread_state64_t thread_state;

  // Copy the stack.

  uintptr_t new_stack_top = 0;
  {
    // IMPORTANT NOTE: Do not do ANYTHING in this in this scope that might
    // allocate memory, including indirectly via use of DCHECK/CHECK or other
    // logging statements. Otherwise this code can deadlock on heap locks in the
    // default heap acquired by the target thread before it was suspended.
    ScopedSuspendThread suspend_thread(thread_port_);
    if (!suspend_thread.was_successful())
      return;

    if (!GetThreadState(thread_port_, &thread_state))
      return;
    uintptr_t stack_top =
        reinterpret_cast<uintptr_t>(thread_stack_base_address_);
    uintptr_t stack_bottom = thread_state.__rsp;
    if (stack_bottom >= stack_top)
      return;
    uintptr_t stack_size = stack_top - stack_bottom;

    if (stack_size > stack_buffer->size())
      return;

    (*annotator_)(sample);

    CopyStackAndRewritePointers(
        reinterpret_cast<uintptr_t*>(stack_buffer->buffer()),
        reinterpret_cast<uintptr_t*>(stack_bottom),
        reinterpret_cast<uintptr_t*>(stack_top), &thread_state);

    new_stack_top =
        reinterpret_cast<uintptr_t>(stack_buffer->buffer()) + stack_size;
  }  // ScopedSuspendThread

  if (test_delegate_)
    test_delegate_->OnPreStackWalk();

  // Walk the stack and record it.

  // Reserve enough memory for most stacks, to avoid repeated allocations.
  // Approximately 99.9% of recorded stacks are 128 frames or fewer.
  sample->frames.reserve(128);

  auto* current_modules = current_modules_;
  auto* profile_module_index = &profile_module_index_;
  WalkStack(
      thread_state, new_stack_top,
      [sample, current_modules, profile_module_index](uintptr_t frame_ip) {
        sample->frames.push_back(StackSamplingProfiler::Frame(
            frame_ip,
            GetModuleIndex(frame_ip, current_modules, profile_module_index)));
      });
}

}  // namespace

std::unique_ptr<NativeStackSampler> NativeStackSampler::Create(
    PlatformThreadId thread_id,
    AnnotateCallback annotator,
    NativeStackSamplerTestDelegate* test_delegate) {
  return base::MakeUnique<NativeStackSamplerMac>(thread_id, annotator,
                                                 test_delegate);
}

size_t NativeStackSampler::GetStackBufferSize() {
  // In platform_thread_mac's GetDefaultThreadStackSize(), RLIMIT_STACK is used
  // for all stacks, not just the main thread's, so it is good for use here.
  struct rlimit stack_rlimit;
  if (getrlimit(RLIMIT_STACK, &stack_rlimit) == 0 &&
      stack_rlimit.rlim_cur != RLIM_INFINITY) {
    return stack_rlimit.rlim_cur;
  }

  // If getrlimit somehow fails, return the default macOS main thread stack size
  // of 8 MB (DFLSSIZ in <i386/vmparam.h>) with extra wiggle room.
  return 12 * 1024 * 1024;
}

}  // namespace base
