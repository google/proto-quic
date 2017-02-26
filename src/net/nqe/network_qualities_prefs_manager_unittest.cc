// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/network_qualities_prefs_manager.h"

#include <algorithm>
#include <map>
#include <memory>

#include "base/macros.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/histogram_tester.h"
#include "base/threading/thread_checker.h"
#include "base/values.h"
#include "net/base/network_change_notifier.h"
#include "net/nqe/effective_connection_type.h"
#include "net/nqe/network_quality_estimator_test_util.h"
#include "net/nqe/network_quality_store.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

class TestPrefDelegate : public NetworkQualitiesPrefsManager::PrefDelegate {
 public:
  TestPrefDelegate()
      : write_count_(0), read_count_(0), value_(new base::DictionaryValue) {}

  ~TestPrefDelegate() override {
    DCHECK(thread_checker_.CalledOnValidThread());
    value_->Clear();
    EXPECT_EQ(0U, value_->size());
  }

  void SetDictionaryValue(const base::DictionaryValue& value) override {
    DCHECK(thread_checker_.CalledOnValidThread());

    write_count_++;
    value_.reset(value.DeepCopy());
    ASSERT_EQ(value.size(), value_->size());
  }

  std::unique_ptr<base::DictionaryValue> GetDictionaryValue() override {
    DCHECK(thread_checker_.CalledOnValidThread());

    read_count_++;
    return value_->CreateDeepCopy();
  }

  size_t write_count() const {
    DCHECK(thread_checker_.CalledOnValidThread());
    return write_count_;
  }

  size_t read_count() const {
    DCHECK(thread_checker_.CalledOnValidThread());
    return read_count_;
  }

 private:
  // Number of times prefs were written and read, respectively..
  size_t write_count_;
  size_t read_count_;

  // Current value of the prefs.
  std::unique_ptr<base::DictionaryValue> value_;

  base::ThreadChecker thread_checker_;

  DISALLOW_COPY_AND_ASSIGN(TestPrefDelegate);
};

TEST(NetworkQualitiesPrefManager, Write) {
  TestNetworkQualityEstimator estimator;

  std::unique_ptr<TestPrefDelegate> prefs_delegate(new TestPrefDelegate());
  TestPrefDelegate* prefs_delegate_ptr = prefs_delegate.get();

  NetworkQualitiesPrefsManager manager(std::move(prefs_delegate));
  manager.InitializeOnNetworkThread(&estimator);
  base::RunLoop().RunUntilIdle();

  // Prefs must be read at when NetworkQualitiesPrefsManager is constructed.
  EXPECT_EQ(1u, prefs_delegate_ptr->read_count());

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

  // Prefs should not be read again.
  EXPECT_EQ(1u, prefs_delegate_ptr->read_count());

  manager.ShutdownOnPrefThread();
}

// Verify that the pref is not written if the network ID contains a period.
TEST(NetworkQualitiesPrefManager, WriteWithPeriodInNetworkID) {
  TestNetworkQualityEstimator estimator;

  std::unique_ptr<TestPrefDelegate> prefs_delegate(new TestPrefDelegate());
  TestPrefDelegate* prefs_delegate_ptr = prefs_delegate.get();

  NetworkQualitiesPrefsManager manager(std::move(prefs_delegate));
  manager.InitializeOnNetworkThread(&estimator);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, prefs_delegate_ptr->read_count());

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "te.st");
  EXPECT_EQ(0u, prefs_delegate_ptr->write_count());

  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_2G);
  // Run a request so that effective connection type is recomputed, and
  // observers are notified of change in the network quality.
  estimator.RunOneRequest();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0u, prefs_delegate_ptr->write_count());

  manager.ShutdownOnPrefThread();
}

TEST(NetworkQualitiesPrefManager, WriteAndReadWithMultipleNetworkIDs) {
  static const size_t kMaxCacheSize = 10u;
  TestNetworkQualityEstimator estimator;

  std::unique_ptr<TestPrefDelegate> prefs_delegate(new TestPrefDelegate());

  NetworkQualitiesPrefsManager manager(std::move(prefs_delegate));
  manager.InitializeOnNetworkThread(&estimator);
  base::RunLoop().RunUntilIdle();

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test");

  EXPECT_EQ(0u, manager.ForceReadPrefsForTesting().size());

  estimator.set_recent_effective_connection_type(
      EFFECTIVE_CONNECTION_TYPE_SLOW_2G);
  // Run a request so that effective connection type is recomputed, and
  // observers are notified of change in the network quality.
  estimator.RunOneRequest();
  base::RunLoop().RunUntilIdle();
  // Verify that the observer was notified, and the updated network quality was
  // written to the prefs.
  EXPECT_EQ(1u, manager.ForceReadPrefsForTesting().size());

  // Change the network ID.
  for (size_t i = 0; i < kMaxCacheSize; ++i) {
    estimator.SimulateNetworkChange(
        NetworkChangeNotifier::ConnectionType::CONNECTION_2G,
        "test" + base::IntToString(i));

    estimator.RunOneRequest();
    base::RunLoop().RunUntilIdle();

    EXPECT_EQ(std::min(i + 2, kMaxCacheSize),
              manager.ForceReadPrefsForTesting().size());
  }

  std::map<nqe::internal::NetworkID, nqe::internal::CachedNetworkQuality>
      read_prefs = manager.ForceReadPrefsForTesting();

  // Verify the contents of the prefs.
  for (std::map<nqe::internal::NetworkID,
                nqe::internal::CachedNetworkQuality>::const_iterator it =
           read_prefs.begin();
       it != read_prefs.end(); ++it) {
    EXPECT_EQ(0u, it->first.id.find("test", 0u));
    EXPECT_EQ(NetworkChangeNotifier::ConnectionType::CONNECTION_2G,
              it->first.type);
    EXPECT_EQ(EFFECTIVE_CONNECTION_TYPE_SLOW_2G,
              it->second.effective_connection_type());
  }

  base::HistogramTester histogram_tester;
  estimator.OnPrefsRead(read_prefs);
  histogram_tester.ExpectUniqueSample("NQE.Prefs.ReadSize", kMaxCacheSize, 1);

  manager.ShutdownOnPrefThread();
}

// Verifies that the prefs are cleared correctly.
TEST(NetworkQualitiesPrefManager, ClearPrefs) {
  TestNetworkQualityEstimator estimator;

  std::unique_ptr<TestPrefDelegate> prefs_delegate(new TestPrefDelegate());

  NetworkQualitiesPrefsManager manager(std::move(prefs_delegate));
  manager.InitializeOnNetworkThread(&estimator);
  base::RunLoop().RunUntilIdle();

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "test");

  EXPECT_EQ(0u, manager.ForceReadPrefsForTesting().size());

  estimator.set_recent_effective_connection_type(
      EFFECTIVE_CONNECTION_TYPE_SLOW_2G);
  // Run a request so that effective connection type is recomputed, and
  // observers are notified of change in the network quality.
  estimator.RunOneRequest();
  base::RunLoop().RunUntilIdle();
  // Verify that the observer was notified, and the updated network quality was
  // written to the prefs.
  EXPECT_EQ(1u, manager.ForceReadPrefsForTesting().size());

  // Prefs must be completely cleared.
  manager.ClearPrefs();
  EXPECT_EQ(0u, manager.ForceReadPrefsForTesting().size());
  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_2G);
  // Run a request so that effective connection type is recomputed, and
  // observers are notified of change in the network quality.
  estimator.RunOneRequest();
  base::RunLoop().RunUntilIdle();
  // Verify that the observer was notified, and the updated network quality was
  // written to the prefs.
  EXPECT_EQ(1u, manager.ForceReadPrefsForTesting().size());
  manager.ShutdownOnPrefThread();
}

}  // namespace

}  // namespace net
