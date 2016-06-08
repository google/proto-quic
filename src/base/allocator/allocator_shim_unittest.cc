// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/allocator/allocator_shim.h"

#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <memory>
#include <new>
#include <vector>

#include "base/atomicops.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread_local.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

// Some new Android NDKs (64 bit) does not expose (p)valloc anymore. These
// functions are implemented at the shim-layer level.
#if defined(OS_ANDROID)
extern "C" {
void* valloc(size_t size);
void* pvalloc(size_t size);
}
#endif

namespace base {
namespace allocator {
namespace {

using testing::MockFunction;
using testing::_;

class AllocatorShimTest : public testing::Test {
 public:
  static const size_t kMaxSizeTracked = 8192;
  AllocatorShimTest() : testing::Test() {}

  static size_t Hash(const void* ptr) {
    return reinterpret_cast<uintptr_t>(ptr) % kMaxSizeTracked;
  }

  static void* MockAlloc(const AllocatorDispatch* self, size_t size) {
    if (instance_ && size < kMaxSizeTracked)
      ++(instance_->allocs_intercepted_by_size[size]);
    return self->next->alloc_function(self->next, size);
  }

  static void* MockAllocZeroInit(const AllocatorDispatch* self,
                                 size_t n,
                                 size_t size) {
    const size_t real_size = n * size;
    if (instance_ && real_size < kMaxSizeTracked)
      ++(instance_->zero_allocs_intercepted_by_size[real_size]);
    return self->next->alloc_zero_initialized_function(self->next, n, size);
  }

  static void* MockAllocAligned(const AllocatorDispatch* self,
                                size_t alignment,
                                size_t size) {
    if (instance_) {
      if (size < kMaxSizeTracked)
        ++(instance_->aligned_allocs_intercepted_by_size[size]);
      if (alignment < kMaxSizeTracked)
        ++(instance_->aligned_allocs_intercepted_by_alignment[alignment]);
    }
    return self->next->alloc_aligned_function(self->next, alignment, size);
  }

  static void* MockRealloc(const AllocatorDispatch* self,
                           void* address,
                           size_t size) {
    if (instance_) {
      // Address 0x420 is a special sentinel for the NewHandlerConcurrency test.
      // The first time (but only the first one) it is hit it fails, causing the
      // invocation of the std::new_handler.
      if (address == reinterpret_cast<void*>(0x420)) {
        if (!instance_->did_fail_realloc_0x420_once->Get()) {
          instance_->did_fail_realloc_0x420_once->Set(true);
          return nullptr;
        } else {
          return reinterpret_cast<void*>(0x420ul);
        }
      }

      if (size < kMaxSizeTracked)
        ++(instance_->reallocs_intercepted_by_size[size]);
      ++instance_->reallocs_intercepted_by_addr[Hash(address)];
    }
    return self->next->realloc_function(self->next, address, size);
  }

  static void MockFree(const AllocatorDispatch* self, void* address) {
    if (instance_) {
      ++instance_->frees_intercepted_by_addr[Hash(address)];
    }
    self->next->free_function(self->next, address);
  }

  static void NewHandler() {
    if (!instance_)
      return;
    subtle::Barrier_AtomicIncrement(&instance_->num_new_handler_calls, 1);
  }

  int32_t GetNumberOfNewHandlerCalls() {
    return subtle::Acquire_Load(&instance_->num_new_handler_calls);
  }

  void SetUp() override {
    const size_t array_size = kMaxSizeTracked * sizeof(size_t);
    memset(&allocs_intercepted_by_size, 0, array_size);
    memset(&zero_allocs_intercepted_by_size, 0, array_size);
    memset(&aligned_allocs_intercepted_by_size, 0, array_size);
    memset(&aligned_allocs_intercepted_by_alignment, 0, array_size);
    memset(&reallocs_intercepted_by_size, 0, array_size);
    memset(&frees_intercepted_by_addr, 0, array_size);
    did_fail_realloc_0x420_once.reset(new ThreadLocalBoolean());
    subtle::Release_Store(&num_new_handler_calls, 0);
    instance_ = this;
  }

  void TearDown() override { instance_ = nullptr; }

 protected:
  size_t allocs_intercepted_by_size[kMaxSizeTracked];
  size_t zero_allocs_intercepted_by_size[kMaxSizeTracked];
  size_t aligned_allocs_intercepted_by_size[kMaxSizeTracked];
  size_t aligned_allocs_intercepted_by_alignment[kMaxSizeTracked];
  size_t reallocs_intercepted_by_size[kMaxSizeTracked];
  size_t reallocs_intercepted_by_addr[kMaxSizeTracked];
  size_t frees_intercepted_by_addr[kMaxSizeTracked];
  std::unique_ptr<ThreadLocalBoolean> did_fail_realloc_0x420_once;
  subtle::Atomic32 num_new_handler_calls;

 private:
  static AllocatorShimTest* instance_;
};

struct TestStruct1 {
  uint32_t ignored;
  uint8_t ignored_2;
};

struct TestStruct2 {
  uint64_t ignored;
  uint8_t ignored_3;
};

class ThreadDelegateForNewHandlerTest : public PlatformThread::Delegate {
 public:
  ThreadDelegateForNewHandlerTest(WaitableEvent* event) : event_(event) {}

  void ThreadMain() override {
    event_->Wait();
    void* res = realloc(reinterpret_cast<void*>(0x420ul), 1);
    EXPECT_EQ(reinterpret_cast<void*>(0x420ul), res);
  }

 private:
  WaitableEvent* event_;
};

AllocatorShimTest* AllocatorShimTest::instance_ = nullptr;

AllocatorDispatch g_mock_dispatch = {
    &AllocatorShimTest::MockAlloc,         /* alloc_function */
    &AllocatorShimTest::MockAllocZeroInit, /* alloc_zero_initialized_function */
    &AllocatorShimTest::MockAllocAligned,  /* alloc_aligned_function */
    &AllocatorShimTest::MockRealloc,       /* realloc_function */
    &AllocatorShimTest::MockFree,          /* free_function */
    nullptr,                               /* next */
};

TEST_F(AllocatorShimTest, InterceptLibcSymbols) {
  const size_t kPageSize = sysconf(_SC_PAGESIZE);
  InsertAllocatorDispatch(&g_mock_dispatch);

  void* alloc_ptr = malloc(19);
  ASSERT_NE(nullptr, alloc_ptr);
  ASSERT_GE(allocs_intercepted_by_size[19], 1u);

  void* zero_alloc_ptr = calloc(2, 23);
  ASSERT_NE(nullptr, zero_alloc_ptr);
  ASSERT_GE(zero_allocs_intercepted_by_size[2 * 23], 1u);

  void* memalign_ptr = memalign(128, 53);
  ASSERT_NE(nullptr, memalign_ptr);
  ASSERT_EQ(0u, reinterpret_cast<uintptr_t>(memalign_ptr) % 128);
  ASSERT_GE(aligned_allocs_intercepted_by_alignment[128], 1u);
  ASSERT_GE(aligned_allocs_intercepted_by_size[53], 1u);

  void* posix_memalign_ptr = nullptr;
  int res = posix_memalign(&posix_memalign_ptr, 256, 59);
  ASSERT_EQ(0, res);
  ASSERT_NE(nullptr, posix_memalign_ptr);
  ASSERT_EQ(0u, reinterpret_cast<uintptr_t>(posix_memalign_ptr) % 256);
  ASSERT_GE(aligned_allocs_intercepted_by_alignment[256], 1u);
  ASSERT_GE(aligned_allocs_intercepted_by_size[59], 1u);

  void* valloc_ptr = valloc(61);
  ASSERT_NE(nullptr, valloc_ptr);
  ASSERT_EQ(0u, reinterpret_cast<uintptr_t>(valloc_ptr) % kPageSize);
  ASSERT_GE(aligned_allocs_intercepted_by_alignment[kPageSize], 1u);
  ASSERT_GE(aligned_allocs_intercepted_by_size[61], 1u);

  void* pvalloc_ptr = pvalloc(67);
  ASSERT_NE(nullptr, pvalloc_ptr);
  ASSERT_EQ(0u, reinterpret_cast<uintptr_t>(pvalloc_ptr) % kPageSize);
  ASSERT_GE(aligned_allocs_intercepted_by_alignment[kPageSize], 1u);
  // pvalloc rounds the size up to the next page.
  ASSERT_GE(aligned_allocs_intercepted_by_size[kPageSize], 1u);

  char* realloc_ptr = static_cast<char*>(realloc(nullptr, 71));
  ASSERT_NE(nullptr, realloc_ptr);
  ASSERT_GE(reallocs_intercepted_by_size[71], 1u);
  ASSERT_GE(reallocs_intercepted_by_addr[Hash(nullptr)], 1u);
  strcpy(realloc_ptr, "foobar");
  realloc_ptr = static_cast<char*>(realloc(realloc_ptr, 73));
  ASSERT_GE(reallocs_intercepted_by_size[73], 1u);
  ASSERT_GE(reallocs_intercepted_by_addr[Hash(realloc_ptr)], 1u);
  ASSERT_EQ(0, strcmp(realloc_ptr, "foobar"));

  free(alloc_ptr);
  ASSERT_GE(frees_intercepted_by_addr[Hash(alloc_ptr)], 1u);

  free(zero_alloc_ptr);
  ASSERT_GE(frees_intercepted_by_addr[Hash(zero_alloc_ptr)], 1u);

  free(memalign_ptr);
  ASSERT_GE(frees_intercepted_by_addr[Hash(memalign_ptr)], 1u);

  free(posix_memalign_ptr);
  ASSERT_GE(frees_intercepted_by_addr[Hash(posix_memalign_ptr)], 1u);

  free(valloc_ptr);
  ASSERT_GE(frees_intercepted_by_addr[Hash(valloc_ptr)], 1u);

  free(pvalloc_ptr);
  ASSERT_GE(frees_intercepted_by_addr[Hash(pvalloc_ptr)], 1u);

  free(realloc_ptr);
  ASSERT_GE(frees_intercepted_by_addr[Hash(realloc_ptr)], 1u);

  RemoveAllocatorDispatchForTesting(&g_mock_dispatch);

  void* non_hooked_ptr = malloc(4095);
  ASSERT_NE(nullptr, non_hooked_ptr);
  ASSERT_EQ(0u, allocs_intercepted_by_size[4095]);
  free(non_hooked_ptr);
}

TEST_F(AllocatorShimTest, InterceptCppSymbols) {
  InsertAllocatorDispatch(&g_mock_dispatch);

  TestStruct1* new_ptr = new TestStruct1;
  ASSERT_NE(nullptr, new_ptr);
  ASSERT_GE(allocs_intercepted_by_size[sizeof(TestStruct1)], 1u);

  TestStruct1* new_array_ptr = new TestStruct1[3];
  ASSERT_NE(nullptr, new_array_ptr);
  ASSERT_GE(allocs_intercepted_by_size[sizeof(TestStruct1) * 3], 1u);

  TestStruct2* new_nt_ptr = new (std::nothrow) TestStruct2;
  ASSERT_NE(nullptr, new_nt_ptr);
  ASSERT_GE(allocs_intercepted_by_size[sizeof(TestStruct2)], 1u);

  TestStruct2* new_array_nt_ptr = new TestStruct2[3];
  ASSERT_NE(nullptr, new_array_nt_ptr);
  ASSERT_GE(allocs_intercepted_by_size[sizeof(TestStruct2) * 3], 1u);

  delete new_ptr;
  ASSERT_GE(frees_intercepted_by_addr[Hash(new_ptr)], 1u);

  delete[] new_array_ptr;
  ASSERT_GE(frees_intercepted_by_addr[Hash(new_array_ptr)], 1u);

  delete new_nt_ptr;
  ASSERT_GE(frees_intercepted_by_addr[Hash(new_nt_ptr)], 1u);

  delete[] new_array_nt_ptr;
  ASSERT_GE(frees_intercepted_by_addr[Hash(new_array_nt_ptr)], 1u);

  RemoveAllocatorDispatchForTesting(&g_mock_dispatch);
}

// This test exercises the case of concurrent OOM failure, which would end up
// invoking std::new_handler concurrently. This is to cover the CallNewHandler()
// paths of allocator_shim.cc and smoke-test its thread safey.
// The test creates kNumThreads threads. Each of them does just a
// realloc(0x420).
// The shim intercepts such realloc and makes it fail only once on each thread.
// We expect to see excactly kNumThreads invocations of the new_handler.
TEST_F(AllocatorShimTest, NewHandlerConcurrency) {
  const int kNumThreads = 32;
  PlatformThreadHandle threads[kNumThreads];

  // The WaitableEvent here is used to attempt to trigger all the threads at
  // the same time, after they have been initialized.
  WaitableEvent event(WaitableEvent::ResetPolicy::MANUAL,
                      WaitableEvent::InitialState::NOT_SIGNALED);

  ThreadDelegateForNewHandlerTest mock_thread_main(&event);

  for (int i = 0; i < kNumThreads; ++i)
    PlatformThread::Create(0, &mock_thread_main, &threads[i]);

  std::set_new_handler(&AllocatorShimTest::NewHandler);
  SetCallNewHandlerOnMallocFailure(true);  // It's going to fail on realloc().
  InsertAllocatorDispatch(&g_mock_dispatch);
  event.Signal();
  for (int i = 0; i < kNumThreads; ++i)
    PlatformThread::Join(threads[i]);
  RemoveAllocatorDispatchForTesting(&g_mock_dispatch);
  ASSERT_EQ(kNumThreads, GetNumberOfNewHandlerCalls());
}

}  // namespace
}  // namespace allocator
}  // namespace base
