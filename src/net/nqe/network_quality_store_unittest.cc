// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/network_quality_store.h"

#include "base/strings/string_number_conversions.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/time/time.h"
#include "net/base/network_change_notifier.h"
#include "net/nqe/cached_network_quality.h"
#include "net/nqe/effective_connection_type.h"
#include "net/nqe/network_id.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

TEST(NetworkQualityStoreTest, TestCaching) {
  nqe::internal::NetworkQualityStore network_quality_store;
  base::SimpleTestTickClock tick_clock;

  // Cached network quality for network with NetworkID (2G, "test1").
  const nqe::internal::CachedNetworkQuality cached_network_quality_2g_test1(
      tick_clock.NowTicks(),
      nqe::internal::NetworkQuality(base::TimeDelta::FromSeconds(1),
                                    base::TimeDelta::FromSeconds(1), 1),
      EFFECTIVE_CONNECTION_TYPE_2G);

  {
    // Entry will be added for (2G, "test1").
    nqe::internal::NetworkID network_id(NetworkChangeNotifier::CONNECTION_2G,
                                        "test1");
    nqe::internal::CachedNetworkQuality read_network_quality;
    network_quality_store.Add(network_id, cached_network_quality_2g_test1);
    EXPECT_TRUE(
        network_quality_store.GetById(network_id, &read_network_quality));
    EXPECT_EQ(cached_network_quality_2g_test1.network_quality(),
              read_network_quality.network_quality());
  }

  {
    // Entry will be added for (2G, "test2").
    nqe::internal::NetworkID network_id(NetworkChangeNotifier::CONNECTION_2G,
                                        "test2");
    nqe::internal::CachedNetworkQuality read_network_quality;
    nqe::internal::CachedNetworkQuality cached_network_quality(
        tick_clock.NowTicks(),
        nqe::internal::NetworkQuality(base::TimeDelta::FromSeconds(2),
                                      base::TimeDelta::FromSeconds(2), 2),
        EFFECTIVE_CONNECTION_TYPE_2G);
    network_quality_store.Add(network_id, cached_network_quality);
    EXPECT_TRUE(
        network_quality_store.GetById(network_id, &read_network_quality));
    EXPECT_EQ(read_network_quality.network_quality(),
              cached_network_quality.network_quality());
  }

  {
    // Entry will be added for (3G, "test3").
    nqe::internal::NetworkID network_id(NetworkChangeNotifier::CONNECTION_3G,
                                        "test3");
    nqe::internal::CachedNetworkQuality read_network_quality;
    nqe::internal::CachedNetworkQuality cached_network_quality(
        tick_clock.NowTicks(),
        nqe::internal::NetworkQuality(base::TimeDelta::FromSeconds(3),
                                      base::TimeDelta::FromSeconds(3), 3),
        EFFECTIVE_CONNECTION_TYPE_3G);
    network_quality_store.Add(network_id, cached_network_quality);
    EXPECT_TRUE(
        network_quality_store.GetById(network_id, &read_network_quality));
    EXPECT_EQ(read_network_quality.network_quality(),
              cached_network_quality.network_quality());
  }

  {
    // Entry will not be added for (Unknown, "").
    nqe::internal::NetworkID network_id(
        NetworkChangeNotifier::CONNECTION_UNKNOWN, "");
    nqe::internal::CachedNetworkQuality read_network_quality;
    nqe::internal::CachedNetworkQuality set_network_quality(
        tick_clock.NowTicks(),
        nqe::internal::NetworkQuality(base::TimeDelta::FromSeconds(4),
                                      base::TimeDelta::FromSeconds(4), 4),
        EFFECTIVE_CONNECTION_TYPE_4G);
    network_quality_store.Add(network_id, set_network_quality);
    EXPECT_FALSE(
        network_quality_store.GetById(network_id, &read_network_quality));
  }

  {
    // Existing entry will be read for (2G, "test1").
    nqe::internal::NetworkID network_id(NetworkChangeNotifier::CONNECTION_2G,
                                        "test1");
    nqe::internal::CachedNetworkQuality read_network_quality;
    EXPECT_TRUE(
        network_quality_store.GetById(network_id, &read_network_quality));
    EXPECT_EQ(cached_network_quality_2g_test1.network_quality(),
              read_network_quality.network_quality());
  }

  {
    // Existing entry will be overwritten for (2G, "test1").
    nqe::internal::NetworkID network_id(NetworkChangeNotifier::CONNECTION_2G,
                                        "test1");
    nqe::internal::CachedNetworkQuality read_network_quality;
    const nqe::internal::CachedNetworkQuality cached_network_quality(
        tick_clock.NowTicks(),
        nqe::internal::NetworkQuality(base::TimeDelta::FromSeconds(5),
                                      base::TimeDelta::FromSeconds(5), 5),
        EFFECTIVE_CONNECTION_TYPE_4G);
    network_quality_store.Add(network_id, cached_network_quality);
    EXPECT_TRUE(
        network_quality_store.GetById(network_id, &read_network_quality));
    EXPECT_EQ(cached_network_quality.network_quality(),
              read_network_quality.network_quality());
  }

  {
    // No entry should exist for (2G, "test4").
    nqe::internal::NetworkID network_id(NetworkChangeNotifier::CONNECTION_2G,
                                        "test4");
    nqe::internal::CachedNetworkQuality read_network_quality;
    EXPECT_FALSE(
        network_quality_store.GetById(network_id, &read_network_quality));
  }
}

// Tests if the cache size remains bounded. Also, ensure that the cache is
// LRU.
TEST(NetworkQualityStoreTest, TestLRUCacheMaximumSize) {
  nqe::internal::NetworkQualityStore network_quality_store;
  base::SimpleTestTickClock tick_clock;

  // Add more networks than the maximum size of the cache.
  const size_t network_count = 11;

  nqe::internal::CachedNetworkQuality read_network_quality(
      tick_clock.NowTicks(),
      nqe::internal::NetworkQuality(base::TimeDelta::FromSeconds(0),
                                    base::TimeDelta::FromSeconds(0), 0),
      EFFECTIVE_CONNECTION_TYPE_2G);

  for (size_t i = 0; i < network_count; ++i) {
    nqe::internal::NetworkID network_id(NetworkChangeNotifier::CONNECTION_2G,
                                        "test" + base::IntToString(i));

    const nqe::internal::CachedNetworkQuality network_quality(
        tick_clock.NowTicks(),
        nqe::internal::NetworkQuality(base::TimeDelta::FromSeconds(1),
                                      base::TimeDelta::FromSeconds(1), 1),
        EFFECTIVE_CONNECTION_TYPE_2G);
    network_quality_store.Add(network_id, network_quality);
    tick_clock.Advance(base::TimeDelta::FromSeconds(1));
  }

  base::TimeTicks earliest_last_update_time = tick_clock.NowTicks();
  size_t cache_match_count = 0;
  for (size_t i = 0; i < network_count; ++i) {
    nqe::internal::NetworkID network_id(NetworkChangeNotifier::CONNECTION_2G,
                                        "test" + base::IntToString(i));

    nqe::internal::CachedNetworkQuality read_network_quality(
        tick_clock.NowTicks(),
        nqe::internal::NetworkQuality(base::TimeDelta::FromSeconds(0),
                                      base::TimeDelta::FromSeconds(0), 0),
        EFFECTIVE_CONNECTION_TYPE_2G);
    if (network_quality_store.GetById(network_id, &read_network_quality)) {
      cache_match_count++;
      earliest_last_update_time = std::min(
          earliest_last_update_time, read_network_quality.last_update_time());
    }
  }

  // Ensure that the number of entries in cache are fewer than |network_count|.
  EXPECT_LT(cache_match_count, network_count);
  EXPECT_GT(cache_match_count, 0u);

  // Ensure that only LRU entries are cached by comparing the
  // |earliest_last_update_time|.
  EXPECT_EQ(
      tick_clock.NowTicks() - base::TimeDelta::FromSeconds(cache_match_count),
      earliest_last_update_time);
}

}  // namespace

}  // namespace net
