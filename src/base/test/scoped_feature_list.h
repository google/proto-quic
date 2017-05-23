// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TEST_SCOPED_FEATURE_LIST_H_
#define BASE_TEST_SCOPED_FEATURE_LIST_H_

#include <initializer_list>

#include "base/feature_list.h"

namespace base {
namespace test {

// ScopedFeatureList resets the global FeatureList instance to a new empty
// instance and restores the original instance upon destruction.
// Note: Re-using the same object is not allowed. To reset the feature
// list and initialize it anew, destroy an existing scoped list and init
// a new one.
//
// ScopedFeatureList needs to be initialized (via one of Init... methods)
// before running code that inspects the state of features.  In practice this
// means:
// - In browser tests, one of Init... methods should be called from the
//   overriden ::testing::Test::SetUp method. For example:
//     void SetUp() override {
//       scoped_feature_list_.InitAndEnableFeature(features::kMyFeatureHere);
//       InProcessBrowserTest::SetUp();
//     }
class ScopedFeatureList final {
 public:
  ScopedFeatureList();
  ~ScopedFeatureList();

  // Initializes and registers a FeatureList instance with no overrides.
  void Init();

  // Initializes and registers the given FeatureList instance.
  void InitWithFeatureList(std::unique_ptr<FeatureList> feature_list);

  // Initializes and registers a FeatureList instance with the given enabled
  // and disabled features.
  void InitWithFeatures(
      const std::initializer_list<base::Feature>& enabled_features,
      const std::initializer_list<base::Feature>& disabled_features);

  // Initializes and registers a FeatureList instance with the given
  // enabled and disabled features (comma-separated names).
  void InitFromCommandLine(const std::string& enable_features,
                           const std::string& disable_features);

  // Initializes and registers a FeatureList instance enabling a single
  // feature.
  void InitAndEnableFeature(const base::Feature& feature);

  // Initializes and registers a FeatureList instance disabling a single
  // feature.
  void InitAndDisableFeature(const base::Feature& feature);

 private:
  std::unique_ptr<FeatureList> original_feature_list_;

  DISALLOW_COPY_AND_ASSIGN(ScopedFeatureList);
};

}  // namespace test
}  // namespace base

#endif  // BASE_TEST_SCOPED_FEATURE_LIST_H_
