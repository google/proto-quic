// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/chromium/port_suggester.h"

#include <set>

#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

class PortSuggesterTest : public ::testing::Test {
 protected:
  PortSuggesterTest()
      : entropy_(1345689),
        min_ephemeral_port_(1025),
        max_ephemeral_port_(65535) {}

  uint64_t entropy_;
  int min_ephemeral_port_;
  int max_ephemeral_port_;
};

TEST_F(PortSuggesterTest, SmallRangeTest) {
  // When the range is small (one wide), we always get that as our answer.
  scoped_refptr<PortSuggester> port_suggester =
      new PortSuggester(HostPortPair("www.example.com", 443), entropy_);
  // Test this for a few different (small) ranges.
  for (int port = 2000; port < 2010; ++port) {
    // Use |port| for both |min| and |max| delimiting the suggestion range.
    EXPECT_EQ(port, port_suggester->SuggestPort(port, port));
    EXPECT_EQ(port, port_suggester->previous_suggestion());
  }
}

TEST_F(PortSuggesterTest, SuggestAllPorts) {
  // We should eventually fill out any range, but we'll just ensure that we
  // fill out a small range of ports.
  scoped_refptr<PortSuggester> port_suggester =
      new PortSuggester(HostPortPair("www.example.com", 443), entropy_);
  std::set<int> ports;
  const uint32_t port_range = 20;
  const int insertion_limit = 200;  // We should be done by then.
  for (int i = 0; i < insertion_limit; ++i) {
    ports.insert(port_suggester->SuggestPort(
        min_ephemeral_port_, min_ephemeral_port_ + port_range - 1));
    if (ports.size() == port_range) {
      break;
    }
  }
  EXPECT_EQ(port_range, ports.size());
}

TEST_F(PortSuggesterTest, AvoidDuplication) {
  // When the range is large, duplicates are rare, but we'll ask for a few
  // suggestions and make sure they are unique.
  scoped_refptr<PortSuggester> port_suggester =
      new PortSuggester(HostPortPair("www.example.com", 80), entropy_);
  std::set<int> ports;
  const size_t port_count = 200;
  for (size_t i = 0; i < port_count; ++i) {
    ports.insert(
        port_suggester->SuggestPort(min_ephemeral_port_, max_ephemeral_port_));
  }
  EXPECT_EQ(port_suggester->call_count(), port_count);
  EXPECT_EQ(port_count, ports.size());
}

TEST_F(PortSuggesterTest, ConsistentPorts) {
  // For given hostname, port, and entropy, we should always get the same
  // suggestions.
  scoped_refptr<PortSuggester> port_suggester1 =
      new PortSuggester(HostPortPair("www.example.com", 443), entropy_);
  scoped_refptr<PortSuggester> port_suggester2 =
      new PortSuggester(HostPortPair("www.example.com", 443), entropy_);
  for (int test_count = 20; test_count > 0; --test_count) {
    EXPECT_EQ(
        port_suggester1->SuggestPort(min_ephemeral_port_, min_ephemeral_port_),
        port_suggester2->SuggestPort(min_ephemeral_port_, min_ephemeral_port_));
  }
}

TEST_F(PortSuggesterTest, DifferentHostPortEntropy) {
  // When we have different hosts, port, or entropy, we probably won't collide.
  scoped_refptr<PortSuggester> port_suggester[] = {
      new PortSuggester(HostPortPair("www.example.com", 80), entropy_),
      new PortSuggester(HostPortPair("www.example.ORG", 80), entropy_),
      new PortSuggester(HostPortPair("www.example.com", 443), entropy_),
      new PortSuggester(HostPortPair("www.example.com", 80), entropy_ + 123456),
  };

  std::set<int> ports;
  const int port_count = 40;
  size_t insertion_count = 0;
  for (size_t j = 0; j < arraysize(port_suggester); ++j) {
    for (int i = 0; i < port_count; ++i) {
      ports.insert(port_suggester[j]->SuggestPort(min_ephemeral_port_,
                                                  max_ephemeral_port_));
      ++insertion_count;
    }
  }
  EXPECT_EQ(insertion_count, ports.size());
}

}  // namespace test
}  // namespace net
