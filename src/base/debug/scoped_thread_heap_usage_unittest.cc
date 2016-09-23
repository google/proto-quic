// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/debug/scoped_thread_heap_usage.h"

#include <map>

#include "base/allocator/allocator_shim.h"
#include "base/allocator/features.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace debug {

namespace {

class TestingScopedThreadHeapUsage : public ScopedThreadHeapUsage {
 public:
  using ScopedThreadHeapUsage::DisableHeapTrackingForTesting;
  using ScopedThreadHeapUsage::GetDispatchForTesting;
};

// A fixture class that allows testing the AllocatorDispatch associated with
// the ScopedThreadHeapUsage class in isolation against a mocked underlying
// heap implementation.
class ScopedThreadHeapUsageTest : public testing::Test {
 public:
  using AllocatorDispatch = base::allocator::AllocatorDispatch;

  static const size_t kAllocationPadding;
  enum SizeFunctionKind {
    EXACT_SIZE_FUNCTION,
    PADDING_SIZE_FUNCTION,
    ZERO_SIZE_FUNCTION,
  };

  ScopedThreadHeapUsageTest() : size_function_kind_(EXACT_SIZE_FUNCTION) {
    EXPECT_EQ(nullptr, g_self);
    g_self = this;
  }

  ~ScopedThreadHeapUsageTest() override {
    EXPECT_EQ(this, g_self);
    g_self = nullptr;
  }

  void set_size_function_kind(SizeFunctionKind kind) {
    size_function_kind_ = kind;
  }

  void SetUp() override {
    ScopedThreadHeapUsage::Initialize();

    dispatch_under_test_ =
        TestingScopedThreadHeapUsage::GetDispatchForTesting();
    ASSERT_EQ(nullptr, dispatch_under_test_->next);

    dispatch_under_test_->next = &g_mock_dispatch;
  }

  void TearDown() override {
    ASSERT_EQ(&g_mock_dispatch, dispatch_under_test_->next);

    dispatch_under_test_->next = nullptr;
  }

  void* MockMalloc(size_t size) {
    return dispatch_under_test_->alloc_function(dispatch_under_test_, size);
  }

  void* MockCalloc(size_t n, size_t size) {
    return dispatch_under_test_->alloc_zero_initialized_function(
        dispatch_under_test_, n, size);
  }

  void* MockAllocAligned(size_t alignment, size_t size) {
    return dispatch_under_test_->alloc_aligned_function(dispatch_under_test_,
                                                        alignment, size);
  }

  void* MockRealloc(void* address, size_t size) {
    return dispatch_under_test_->realloc_function(dispatch_under_test_, address,
                                                  size);
  }

  void MockFree(void* address) {
    dispatch_under_test_->free_function(dispatch_under_test_, address);
  }

  size_t MockGetSizeEstimate(void* address) {
    return dispatch_under_test_->get_size_estimate_function(
        dispatch_under_test_, address);
  }

 private:
  void RecordAlloc(void* address, size_t size) {
    if (address != nullptr)
      allocation_size_map_[address] = size;
  }

  void DeleteAlloc(void* address) {
    if (address != nullptr)
      EXPECT_EQ(1U, allocation_size_map_.erase(address));
  }

  size_t GetSizeEstimate(void* address) {
    auto it = allocation_size_map_.find(address);
    if (it == allocation_size_map_.end())
      return 0;

    size_t ret = it->second;
    switch (size_function_kind_) {
      case EXACT_SIZE_FUNCTION:
        break;
      case PADDING_SIZE_FUNCTION:
        ret += kAllocationPadding;
        break;
      case ZERO_SIZE_FUNCTION:
        ret = 0;
        break;
    }

    return ret;
  }

  static void* OnAllocFn(const AllocatorDispatch* self, size_t size) {
    EXPECT_EQ(&g_mock_dispatch, self);

    void* ret = malloc(size);
    g_self->RecordAlloc(ret, size);
    return ret;
  }

  static void* OnAllocZeroInitializedFn(const AllocatorDispatch* self,
                                        size_t n,
                                        size_t size) {
    EXPECT_EQ(&g_mock_dispatch, self);

    void* ret = calloc(n, size);
    g_self->RecordAlloc(ret, n * size);
    return ret;
  }

  static void* OnAllocAlignedFn(const AllocatorDispatch* self,
                                size_t alignment,
                                size_t size) {
    EXPECT_EQ(&g_mock_dispatch, self);

    // This is a cheat as it doesn't return aligned allocations. This has the
    // advantage of working for all platforms for this test.
    void* ret = malloc(size);
    g_self->RecordAlloc(ret, size);
    return ret;
  }

  static void* OnReallocFn(const AllocatorDispatch* self,
                           void* address,
                           size_t size) {
    EXPECT_EQ(&g_mock_dispatch, self);

    g_self->DeleteAlloc(address);
    void* ret = realloc(address, size);
    g_self->RecordAlloc(ret, size);
    return ret;
  }

  static void OnFreeFn(const AllocatorDispatch* self, void* address) {
    EXPECT_EQ(&g_mock_dispatch, self);

    g_self->DeleteAlloc(address);
    free(address);
  }

  static size_t OnGetSizeEstimateFn(const AllocatorDispatch* self,
                                    void* address) {
    EXPECT_EQ(&g_mock_dispatch, self);

    return g_self->GetSizeEstimate(address);
  }

  using AllocationSizeMap = std::map<void*, size_t>;

  SizeFunctionKind size_function_kind_;
  AllocationSizeMap allocation_size_map_;
  AllocatorDispatch* dispatch_under_test_;

  static base::allocator::AllocatorDispatch g_mock_dispatch;
  static ScopedThreadHeapUsageTest* g_self;
};

const size_t ScopedThreadHeapUsageTest::kAllocationPadding = 23;

ScopedThreadHeapUsageTest* ScopedThreadHeapUsageTest::g_self = nullptr;

base::allocator::AllocatorDispatch ScopedThreadHeapUsageTest::g_mock_dispatch =
    {
        &ScopedThreadHeapUsageTest::OnAllocFn,  // alloc_function
        &ScopedThreadHeapUsageTest::
            OnAllocZeroInitializedFn,  // alloc_zero_initialized_function
        &ScopedThreadHeapUsageTest::OnAllocAlignedFn,  // alloc_aligned_function
        &ScopedThreadHeapUsageTest::OnReallocFn,       // realloc_function
        &ScopedThreadHeapUsageTest::OnFreeFn,          // free_function
        &ScopedThreadHeapUsageTest::
            OnGetSizeEstimateFn,  // get_size_estimate_function
        nullptr,                  // next
};

}  // namespace

TEST_F(ScopedThreadHeapUsageTest, SimpleUsageWithExactSizeFunction) {
  set_size_function_kind(EXACT_SIZE_FUNCTION);

  ScopedThreadHeapUsage scoped_usage;

  ScopedThreadHeapUsage::ThreadAllocatorUsage u1 =
      ScopedThreadHeapUsage::CurrentUsage();

  EXPECT_EQ(0U, u1.alloc_ops);
  EXPECT_EQ(0U, u1.alloc_bytes);
  EXPECT_EQ(0U, u1.alloc_overhead_bytes);
  EXPECT_EQ(0U, u1.free_ops);
  EXPECT_EQ(0U, u1.free_bytes);
  EXPECT_EQ(0U, u1.max_allocated_bytes);

  const size_t kAllocSize = 1029U;
  void* ptr = MockMalloc(kAllocSize);
  MockFree(ptr);

  ScopedThreadHeapUsage::ThreadAllocatorUsage u2 =
      ScopedThreadHeapUsage::CurrentUsage();

  EXPECT_EQ(1U, u2.alloc_ops);
  EXPECT_EQ(kAllocSize, u2.alloc_bytes);
  EXPECT_EQ(0U, u2.alloc_overhead_bytes);
  EXPECT_EQ(1U, u2.free_ops);
  EXPECT_EQ(kAllocSize, u2.free_bytes);
  EXPECT_EQ(kAllocSize, u2.max_allocated_bytes);
}

TEST_F(ScopedThreadHeapUsageTest, SimpleUsageWithPaddingSizeFunction) {
  set_size_function_kind(PADDING_SIZE_FUNCTION);

  ScopedThreadHeapUsage scoped_usage;

  ScopedThreadHeapUsage::ThreadAllocatorUsage u1 =
      ScopedThreadHeapUsage::CurrentUsage();

  EXPECT_EQ(0U, u1.alloc_ops);
  EXPECT_EQ(0U, u1.alloc_bytes);
  EXPECT_EQ(0U, u1.alloc_overhead_bytes);
  EXPECT_EQ(0U, u1.free_ops);
  EXPECT_EQ(0U, u1.free_bytes);
  EXPECT_EQ(0U, u1.max_allocated_bytes);

  const size_t kAllocSize = 1029U;
  void* ptr = MockMalloc(kAllocSize);
  MockFree(ptr);

  ScopedThreadHeapUsage::ThreadAllocatorUsage u2 =
      ScopedThreadHeapUsage::CurrentUsage();

  EXPECT_EQ(1U, u2.alloc_ops);
  EXPECT_EQ(kAllocSize + kAllocationPadding, u2.alloc_bytes);
  EXPECT_EQ(kAllocationPadding, u2.alloc_overhead_bytes);
  EXPECT_EQ(1U, u2.free_ops);
  EXPECT_EQ(kAllocSize + kAllocationPadding, u2.free_bytes);
  EXPECT_EQ(kAllocSize + kAllocationPadding, u2.max_allocated_bytes);
}

TEST_F(ScopedThreadHeapUsageTest, SimpleUsageWithZeroSizeFunction) {
  set_size_function_kind(ZERO_SIZE_FUNCTION);

  ScopedThreadHeapUsage scoped_usage;

  ScopedThreadHeapUsage::ThreadAllocatorUsage u1 =
      ScopedThreadHeapUsage::CurrentUsage();
  EXPECT_EQ(0U, u1.alloc_ops);
  EXPECT_EQ(0U, u1.alloc_bytes);
  EXPECT_EQ(0U, u1.alloc_overhead_bytes);
  EXPECT_EQ(0U, u1.free_ops);
  EXPECT_EQ(0U, u1.free_bytes);
  EXPECT_EQ(0U, u1.max_allocated_bytes);

  const size_t kAllocSize = 1029U;
  void* ptr = MockMalloc(kAllocSize);
  MockFree(ptr);

  ScopedThreadHeapUsage::ThreadAllocatorUsage u2 =
      ScopedThreadHeapUsage::CurrentUsage();

  // With a get-size function that returns zero, there's no way to get the size
  // of an allocation that's being freed, hence the shim can't tally freed bytes
  // nor the high-watermark allocated bytes.
  EXPECT_EQ(1U, u2.alloc_ops);
  EXPECT_EQ(kAllocSize, u2.alloc_bytes);
  EXPECT_EQ(0U, u2.alloc_overhead_bytes);
  EXPECT_EQ(1U, u2.free_ops);
  EXPECT_EQ(0U, u2.free_bytes);
  EXPECT_EQ(0U, u2.max_allocated_bytes);
}

TEST_F(ScopedThreadHeapUsageTest, ReallocCorrectlyTallied) {
  const size_t kAllocSize = 237U;

  {
    ScopedThreadHeapUsage scoped_usage;

    // Reallocating nullptr should count as a single alloc.
    void* ptr = MockRealloc(nullptr, kAllocSize);
    ScopedThreadHeapUsage::ThreadAllocatorUsage usage =
        ScopedThreadHeapUsage::CurrentUsage();
    EXPECT_EQ(1U, usage.alloc_ops);
    EXPECT_EQ(kAllocSize, usage.alloc_bytes);
    EXPECT_EQ(0U, usage.alloc_overhead_bytes);
    EXPECT_EQ(0U, usage.free_ops);
    EXPECT_EQ(0U, usage.free_bytes);
    EXPECT_EQ(kAllocSize, usage.max_allocated_bytes);

    // Reallocating a valid pointer to a zero size should count as a single
    // free.
    ptr = MockRealloc(ptr, 0U);

    usage = ScopedThreadHeapUsage::CurrentUsage();
    EXPECT_EQ(1U, usage.alloc_ops);
    EXPECT_EQ(kAllocSize, usage.alloc_bytes);
    EXPECT_EQ(0U, usage.alloc_overhead_bytes);
    EXPECT_EQ(1U, usage.free_ops);
    EXPECT_EQ(kAllocSize, usage.free_bytes);
    EXPECT_EQ(kAllocSize, usage.max_allocated_bytes);

    // Realloc to zero size may or may not return a nullptr - make sure to
    // free the zero-size alloc in the latter case.
    if (ptr != nullptr)
      MockFree(ptr);
  }

  {
    ScopedThreadHeapUsage scoped_usage;

    void* ptr = MockMalloc(kAllocSize);
    ScopedThreadHeapUsage::ThreadAllocatorUsage usage =
        ScopedThreadHeapUsage::CurrentUsage();
    EXPECT_EQ(1U, usage.alloc_ops);

    // Now try reallocating a valid pointer to a larger size, this should count
    // as one free and one alloc.
    const size_t kLargerAllocSize = kAllocSize + 928U;
    ptr = MockRealloc(ptr, kLargerAllocSize);

    usage = ScopedThreadHeapUsage::CurrentUsage();
    EXPECT_EQ(2U, usage.alloc_ops);
    EXPECT_EQ(kAllocSize + kLargerAllocSize, usage.alloc_bytes);
    EXPECT_EQ(0U, usage.alloc_overhead_bytes);
    EXPECT_EQ(1U, usage.free_ops);
    EXPECT_EQ(kAllocSize, usage.free_bytes);
    EXPECT_EQ(kLargerAllocSize, usage.max_allocated_bytes);

    MockFree(ptr);
  }
}

TEST_F(ScopedThreadHeapUsageTest, NestedMaxWorks) {
  ScopedThreadHeapUsage outer_scoped_usage;

  const size_t kOuterAllocSize = 1029U;
  void* ptr = MockMalloc(kOuterAllocSize);
  MockFree(ptr);

  EXPECT_EQ(kOuterAllocSize,
            ScopedThreadHeapUsage::CurrentUsage().max_allocated_bytes);

  {
    ScopedThreadHeapUsage inner_scoped_usage;

    const size_t kInnerAllocSize = 673U;
    ptr = MockMalloc(kInnerAllocSize);
    MockFree(ptr);

    EXPECT_EQ(kInnerAllocSize,
              ScopedThreadHeapUsage::CurrentUsage().max_allocated_bytes);
  }

  // The greater, outer allocation size should have been restored.
  EXPECT_EQ(kOuterAllocSize,
            ScopedThreadHeapUsage::CurrentUsage().max_allocated_bytes);

  const size_t kLargerInnerAllocSize = kOuterAllocSize + 673U;
  {
    ScopedThreadHeapUsage inner_scoped_usage;

    ptr = MockMalloc(kLargerInnerAllocSize);
    MockFree(ptr);

    EXPECT_EQ(kLargerInnerAllocSize,
              ScopedThreadHeapUsage::CurrentUsage().max_allocated_bytes);
  }

  // The greater, inner allocation size should have been preserved.
  EXPECT_EQ(kLargerInnerAllocSize,
            ScopedThreadHeapUsage::CurrentUsage().max_allocated_bytes);

  // Now try the case with an outstanding net alloc size when entering the
  // inner scope.
  void* outer_ptr = MockMalloc(kOuterAllocSize);
  EXPECT_EQ(kLargerInnerAllocSize,
            ScopedThreadHeapUsage::CurrentUsage().max_allocated_bytes);
  {
    ScopedThreadHeapUsage inner_scoped_usage;

    ptr = MockMalloc(kLargerInnerAllocSize);
    MockFree(ptr);

    EXPECT_EQ(kLargerInnerAllocSize,
              ScopedThreadHeapUsage::CurrentUsage().max_allocated_bytes);
  }

  // While the inner scope saw only the inner net outstanding allocation size,
  // the outer scope saw both outstanding at the same time.
  EXPECT_EQ(kOuterAllocSize + kLargerInnerAllocSize,
            ScopedThreadHeapUsage::CurrentUsage().max_allocated_bytes);

  MockFree(outer_ptr);
}

TEST_F(ScopedThreadHeapUsageTest, AllShimFunctionsAreProvided) {
  const size_t kAllocSize = 100;
  void* alloc = MockMalloc(kAllocSize);
  size_t estimate = MockGetSizeEstimate(alloc);
  ASSERT_TRUE(estimate == 0 || estimate >= kAllocSize);
  MockFree(alloc);

  alloc = MockCalloc(kAllocSize, 1);
  estimate = MockGetSizeEstimate(alloc);
  ASSERT_TRUE(estimate == 0 || estimate >= kAllocSize);
  MockFree(alloc);

  alloc = MockAllocAligned(1, kAllocSize);
  estimate = MockGetSizeEstimate(alloc);
  ASSERT_TRUE(estimate == 0 || estimate >= kAllocSize);

  alloc = MockRealloc(alloc, kAllocSize);
  estimate = MockGetSizeEstimate(alloc);
  ASSERT_TRUE(estimate == 0 || estimate >= kAllocSize);
  MockFree(alloc);
}

#if BUILDFLAG(USE_EXPERIMENTAL_ALLOCATOR_SHIM)
TEST(ScopedThreadHeapShimTest, HooksIntoMallocWhenShimAvailable) {
  ScopedThreadHeapUsage::Initialize();
  ScopedThreadHeapUsage::EnableHeapTracking();

  const size_t kAllocSize = 9993;
  // This test verifies that the scoped heap data is affected by malloc &
  // free only when the shim is available.
  ScopedThreadHeapUsage scoped_usage;

  ScopedThreadHeapUsage::ThreadAllocatorUsage u1 =
      ScopedThreadHeapUsage::CurrentUsage();
  void* ptr = malloc(kAllocSize);
  // Prevent the compiler from optimizing out the malloc/free pair.
  ASSERT_NE(nullptr, ptr);

  ScopedThreadHeapUsage::ThreadAllocatorUsage u2 =
      ScopedThreadHeapUsage::CurrentUsage();
  free(ptr);
  ScopedThreadHeapUsage::ThreadAllocatorUsage u3 =
      ScopedThreadHeapUsage::CurrentUsage();

  // Verify that at least one allocation operation was recorded, and that free
  // operations are at least monotonically growing.
  EXPECT_LE(0U, u1.alloc_ops);
  EXPECT_LE(u1.alloc_ops + 1, u2.alloc_ops);
  EXPECT_LE(u1.alloc_ops + 1, u3.alloc_ops);

  // Verify that at least the bytes above were recorded.
  EXPECT_LE(u1.alloc_bytes + kAllocSize, u2.alloc_bytes);

  // Verify that at least the one free operation above was recorded.
  EXPECT_LE(u2.free_ops + 1, u3.free_ops);

  TestingScopedThreadHeapUsage::DisableHeapTrackingForTesting();
}
#endif  // BUILDFLAG(USE_EXPERIMENTAL_ALLOCATOR_SHIM)

}  // namespace debug
}  // namespace base
