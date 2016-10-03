// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/network_qualities_prefs_manager.h"

#include <map>
#include <memory>

#include "base/macros.h"
#include "base/run_loop.h"
#include "base/values.h"
#include "net/base/network_change_notifier.h"
#include "net/nqe/effective_connection_type.h"
#include "net/nqe/network_quality_estimator_test_util.h"
#include "net/nqe/network_quality_store.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

class MockPrefDelegate : public NetworkQualitiesPrefsManager::PrefDelegate {
 public:
  MockPrefDelegate() : write_count_(0) {}
  ~MockPrefDelegate() {}

  void SetDictionaryValue(const base::DictionaryValue& value) override {
    write_count_++;
  }

  size_t write_count() const { return write_count_; }

 private:
  // Number of times prefs were written.
  mutable size_t write_count_;

  DISALLOW_COPY_AND_ASSIGN(MockPrefDelegate);
};

TEST(NetworkQualitiesPrefManager, Write) {
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params, nullptr);

  std::unique_ptr<MockPrefDelegate> prefs_delegate(new MockPrefDelegate());
  MockPrefDelegate* prefs_delegate_ptr = prefs_delegate.get();

  NetworkQualitiesPrefsManager manager(std::move(prefs_delegate));
  manager.InitializeOnNetworkThread(&estimator);
  base::RunLoop().RunUntilIdle();

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "test");
  EXPECT_EQ(0u, prefs_delegate_ptr->write_count());

  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_2G);
  // Run a request so that effective connection type is recomputed, and
  // observers are notified of change in the network quality.
  estimator.RunOneRequest();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, prefs_delegate_ptr->write_count());

  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_3G);
  // Run a request so that effective connection type is recomputed, and
  // observers are notified of change in the network quality..
  estimator.RunOneRequest();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2u, prefs_delegate_ptr->write_count());

  manager.ShutdownOnPrefThread();
}

}  // namespace

}  // namespace net