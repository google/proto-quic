// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/chromium/http2_priority_dependencies.h"

#include <algorithm>

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/platform_test.h"

using ::testing::ContainerEq;

namespace net {

bool operator==(const Http2PriorityDependencies::DependencyUpdate& a,
                const Http2PriorityDependencies::DependencyUpdate& b) {
  return a.id == b.id && a.dependent_stream_id == b.dependent_stream_id &&
         a.exclusive == b.exclusive;
}

std::ostream& operator<<(
    std::ostream& os,
    const std::vector<Http2PriorityDependencies::DependencyUpdate>& v) {
  for (auto e : v) {
    os << "{" << e.id << "," << e.dependent_stream_id << ","
       << (e.exclusive ? "true" : "false") << "}";
  }
  return os;
}

class HttpPriorityDependencyTest : public PlatformTest {
 public:
  HttpPriorityDependencyTest() : next_id_(0u) {}

  // Fixed priority values to use for testing.
  enum {
    HIGHEST = kV3HighestPriority,
    MEDIUM = HIGHEST + 1,
    LOW = MEDIUM + 1,
    LOWEST = kV3LowestPriority,
  };

  SpdyStreamId GetId() { return ++next_id_; }

  void TestStreamCreation(SpdyStreamId new_id,
                          SpdyPriority priority,
                          SpdyStreamId expected_dependent_id) {
    SpdyStreamId dependent_id = 999u;
    bool exclusive = false;
    dependency_state_.OnStreamCreation(new_id, priority, &dependent_id,
                                       &exclusive);
    if (expected_dependent_id != dependent_id || !exclusive) {
      ADD_FAILURE() << "OnStreamCreation(" << new_id << ", " << int(priority)
                    << ")\n"
                    << "  Got:  (" << dependent_id << ", " << exclusive << ")\n"
                    << "  Want: (" << expected_dependent_id << ", true)\n";
    }
  }

  struct ExpectedDependencyUpdate {
    SpdyStreamId id;
    SpdyStreamId parent_id;
  };

  void TestStreamUpdate(SpdyStreamId id,
                        SpdyPriority new_priority,
                        std::vector<ExpectedDependencyUpdate> expected) {
    auto value = dependency_state_.OnStreamUpdate(id, new_priority);
    std::vector<Http2PriorityDependencies::DependencyUpdate> expected_value;
    for (auto e : expected) {
      expected_value.push_back({e.id, e.parent_id, true /* exclusive */});
    }
    if (value != expected_value) {
      ADD_FAILURE() << "OnStreamUpdate(" << id << ", " << int(new_priority)
                    << ")\n"
                    << "  Value:    " << value << "\n"
                    << "  Expected: " << expected_value << "\n";
    }
  }

  void OnStreamDestruction(SpdyStreamId id) {
    dependency_state_.OnStreamDestruction(id);
  }

 private:
  SpdyStreamId next_id_;
  Http2PriorityDependencies dependency_state_;
};

// Confirm dependencies correct for entries at the same priority.
TEST_F(HttpPriorityDependencyTest, SamePriority) {
  const SpdyStreamId first_id = GetId();
  const SpdyStreamId second_id = GetId();
  const SpdyStreamId third_id = GetId();

  TestStreamCreation(first_id, MEDIUM, 0u);
  TestStreamCreation(second_id, MEDIUM, first_id);
  TestStreamCreation(third_id, MEDIUM, second_id);
}

// Confirm dependencies correct for entries at different priorities, increasing.
TEST_F(HttpPriorityDependencyTest, DifferentPriorityIncreasing) {
  const SpdyStreamId first_id = GetId();
  const SpdyStreamId second_id = GetId();
  const SpdyStreamId third_id = GetId();

  TestStreamCreation(first_id, LOWEST, 0u);
  TestStreamCreation(second_id, MEDIUM, 0u);
  TestStreamCreation(third_id, HIGHEST, 0u);
}

// Confirm dependencies correct for entries at different priorities, increasing.
TEST_F(HttpPriorityDependencyTest, DifferentPriorityDecreasing) {
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

// Confirm dependencies correct after updates with just one stream.
// All updates are no-ops.
TEST_F(HttpPriorityDependencyTest, UpdateSingleStream) {
  const SpdyStreamId id = GetId();

  TestStreamCreation(id, HIGHEST, 0);

  std::vector<ExpectedDependencyUpdate> empty;
  TestStreamUpdate(id, HIGHEST, empty);
  TestStreamUpdate(id, MEDIUM, empty);
  TestStreamUpdate(id, LOWEST, empty);
  TestStreamUpdate(id, HIGHEST, empty);
}

// Confirm dependencies correct after updates with three streams.
TEST_F(HttpPriorityDependencyTest, UpdateThreeStreams) {
  const SpdyStreamId first_id = GetId();
  const SpdyStreamId second_id = GetId();
  const SpdyStreamId third_id = GetId();

  TestStreamCreation(first_id, HIGHEST, 0);
  TestStreamCreation(second_id, MEDIUM, first_id);
  TestStreamCreation(third_id, LOWEST, second_id);

  std::vector<ExpectedDependencyUpdate> empty;

  // no-op: still at top.
  TestStreamUpdate(first_id, HIGHEST, empty);

  // no-op: still below first.
  TestStreamUpdate(second_id, MEDIUM, empty);

  // no-op: still below second.
  TestStreamUpdate(third_id, LOWEST, empty);

  // second moves to top, first moves below second.
  TestStreamUpdate(first_id, MEDIUM, {{second_id, 0}, {first_id, second_id}});

  // third moves to top.
  TestStreamUpdate(third_id, HIGHEST, {{third_id, 0}});

  // third moves to bottom.
  TestStreamUpdate(third_id, LOWEST, {{second_id, 0}, {third_id, first_id}});

  // first moves to top.
  TestStreamUpdate(first_id, HIGHEST, {{third_id, second_id}, {first_id, 0}});
}

// A more complex example parallel to a simple web page with pushed responses.
TEST_F(HttpPriorityDependencyTest, UpdateComplex) {
  const SpdyStreamId first_id = GetId();
  const SpdyStreamId second_id = GetId();  // pushed
  const SpdyStreamId third_id = GetId();   // pushed
  const SpdyStreamId fourth_id = GetId();
  const SpdyStreamId fifth_id = GetId();
  const SpdyStreamId sixth_id = GetId();
  const SpdyStreamId seventh_id = GetId();

  TestStreamCreation(first_id, HIGHEST, 0u);
  TestStreamCreation(second_id, LOWEST, first_id);
  TestStreamCreation(third_id, LOWEST, second_id);
  TestStreamCreation(fourth_id, HIGHEST, first_id);
  TestStreamCreation(fifth_id, MEDIUM, fourth_id);
  TestStreamCreation(sixth_id, MEDIUM, fifth_id);
  TestStreamCreation(seventh_id, LOW, sixth_id);

  // second matches a HIGHEST priority response.
  // 3 moves under 7
  // 2 moves under 4
  TestStreamUpdate(second_id, HIGHEST,
                   {{third_id, seventh_id}, {second_id, fourth_id}});

  // third matches a MEDIUM priority response.
  // 3 moves under 6
  TestStreamUpdate(third_id, MEDIUM, {{third_id, sixth_id}});
}

}  // namespace net
