// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/http2_priority_dependencies.h"

#include "testing/platform_test.h"

namespace net {

class HttpPriorityDependencyTest : public PlatformTest {
 public:
  HttpPriorityDependencyTest() : next_id_(0u) {}

  // Fixed priority values to use for testing.
  enum { HIGHEST = 0, MEDIUM = 2, LOW = 4, LOWEST = 5 };

  SpdyStreamId GetId() { return ++next_id_; }

  void TestStreamCreation(SpdyStreamId new_id,
                          SpdyPriority priority,
                          SpdyStreamId expected_dependent_id) {
    SpdyStreamId dependent_id = 999u;
    bool exclusive = false;
    dependency_state.OnStreamSynSent(new_id, priority, &dependent_id,
                                     &exclusive);
    EXPECT_EQ(expected_dependent_id, dependent_id);
    EXPECT_TRUE(exclusive);
  }

  void OnStreamDestruction(SpdyStreamId id) {
    dependency_state.OnStreamDestruction(id);
  }

 private:
  SpdyStreamId next_id_;
  Http2PriorityDependencies dependency_state;
};

// Confirm dependencies correct for entries at the same priority.
TEST_F(HttpPriorityDependencyTest, SamePriority) {
  Http2PriorityDependencies dependency_state;

  const SpdyStreamId first_id = GetId();
  const SpdyStreamId second_id = GetId();
  const SpdyStreamId third_id = GetId();

  TestStreamCreation(first_id, MEDIUM, 0u);
  TestStreamCreation(second_id, MEDIUM, first_id);
  TestStreamCreation(third_id, MEDIUM, second_id);
}

// Confirm dependencies correct for entries at different priorities, increasing.
TEST_F(HttpPriorityDependencyTest, DifferentPriorityIncreasing) {
  Http2PriorityDependencies dependency_state;

  const SpdyStreamId first_id = GetId();
  const SpdyStreamId second_id = GetId();
  const SpdyStreamId third_id = GetId();

  TestStreamCreation(first_id, LOWEST, 0u);
  TestStreamCreation(second_id, MEDIUM, 0u);
  TestStreamCreation(third_id, HIGHEST, 0u);
}

// Confirm dependencies correct for entries at different priorities, increasing.
TEST_F(HttpPriorityDependencyTest, DifferentPriorityDecreasing) {
  Http2PriorityDependencies dependency_state;

  const SpdyStreamId first_id = GetId();
  const SpdyStreamId second_id = GetId();
  const SpdyStreamId third_id = GetId();

  TestStreamCreation(first_id, HIGHEST, 0u);
  TestStreamCreation(second_id, MEDIUM, first_id);
  TestStreamCreation(third_id, LOWEST, second_id);
}

// Confirm dependencies correct if requests are completed between before
// next creation.
TEST_F(HttpPriorityDependencyTest, CompletionBeforeIssue) {
  Http2PriorityDependencies dependency_state;

  const SpdyStreamId first_id = GetId();
  const SpdyStreamId second_id = GetId();
  const SpdyStreamId third_id = GetId();

  TestStreamCreation(first_id, HIGHEST, 0u);
  OnStreamDestruction(first_id);
  TestStreamCreation(second_id, MEDIUM, 0u);
  OnStreamDestruction(second_id);
  TestStreamCreation(third_id, LOWEST, 0u);
}

// Confirm dependencies correct if some requests are completed between before
// next creation.
TEST_F(HttpPriorityDependencyTest, SomeCompletions) {
  Http2PriorityDependencies dependency_state;

  const SpdyStreamId first_id = GetId();
  const SpdyStreamId second_id = GetId();
  const SpdyStreamId third_id = GetId();

  TestStreamCreation(first_id, HIGHEST, 0u);
  TestStreamCreation(second_id, MEDIUM, first_id);
  OnStreamDestruction(second_id);
  TestStreamCreation(third_id, LOWEST, first_id);
}

// A more complex example parallel to a simple web page.
TEST_F(HttpPriorityDependencyTest, Complex) {
  Http2PriorityDependencies dependency_state;

  const SpdyStreamId first_id = GetId();
  const SpdyStreamId second_id = GetId();
  const SpdyStreamId third_id = GetId();
  const SpdyStreamId fourth_id = GetId();
  const SpdyStreamId fifth_id = GetId();
  const SpdyStreamId sixth_id = GetId();
  const SpdyStreamId seventh_id = GetId();
  const SpdyStreamId eighth_id = GetId();
  const SpdyStreamId nineth_id = GetId();
  const SpdyStreamId tenth_id = GetId();

  TestStreamCreation(first_id, HIGHEST, 0u);
  TestStreamCreation(second_id, MEDIUM, first_id);
  TestStreamCreation(third_id, MEDIUM, second_id);
  OnStreamDestruction(first_id);
  TestStreamCreation(fourth_id, MEDIUM, third_id);
  TestStreamCreation(fifth_id, LOWEST, fourth_id);
  TestStreamCreation(sixth_id, MEDIUM, fourth_id);
  OnStreamDestruction(third_id);
  TestStreamCreation(seventh_id, MEDIUM, sixth_id);
  TestStreamCreation(eighth_id, LOW, seventh_id);
  OnStreamDestruction(second_id);
  OnStreamDestruction(fourth_id);
  OnStreamDestruction(fifth_id);
  OnStreamDestruction(sixth_id);
  OnStreamDestruction(seventh_id);
  TestStreamCreation(nineth_id, MEDIUM, 0u);
  TestStreamCreation(tenth_id, HIGHEST, 0u);
}

}  // namespace net
