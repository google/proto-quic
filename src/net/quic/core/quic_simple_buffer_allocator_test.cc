// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_simple_buffer_allocator.h"

#include "net/quic/core/quic_packets.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::Eq;

namespace net {
namespace {

TEST(SimpleBufferAllocatorTest, NewDelete) {
  SimpleBufferAllocator alloc;
  char* buf = alloc.New(4);
  EXPECT_NE(nullptr, buf);
  alloc.Delete(buf);
}

TEST(SimpleBufferAllocatorTest, DeleteNull) {
  SimpleBufferAllocator alloc;
  alloc.Delete(nullptr);
}

TEST(SimpleBufferAllocatorTest, StoreInUniqueStreamBuffer) {
  SimpleBufferAllocator alloc;
  UniqueStreamBuffer buf = NewStreamBuffer(&alloc, 4);
  buf.reset();
}

}  // namespace
}  // namespace net
