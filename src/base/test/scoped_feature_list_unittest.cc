// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_feature_list.h"

#include <string>
#include "base/metrics/field_trial.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace test {

namespace {

const base::Feature kTestFeature1{"TestFeature1",
                                  base::FEATURE_DISABLED_BY_DEFAULT};
const base::Feature kTestFeature2{"TestFeature2",
                                  base::FEATURE_DISABLED_BY_DEFAULT};

void ExpectFeatures(const std::string& enabled_features,
                    const std::string& disabled_features) {
  base::FeatureList* list = base::FeatureList::GetInstance();
  std::string actual_enabled_features;
  std::string actual_disabled_features;

  list->GetFeatureOverrides(&actual_enabled_features,
                            &actual_disabled_features);

  EXPECT_EQ(enabled_features, actual_enabled_features);
  EXPECT_EQ(disabled_features, actual_disabled_features);
}

}  // namespace

class ScopedFeatureListTest : public testing::Test {
 public:
  ScopedFeatureListTest() {
    // Clear default feature list.
    std::unique_ptr<base::FeatureList> feature_list(new base::FeatureList);
    feature_list->InitializeFromCommandLine(std::string(), std::string());
    original_feature_list_ = base::FeatureList::ClearInstanceForTesting();
    base::FeatureList::SetInstance(std::move(feature_list));
  }

  ~ScopedFeatureListTest() override {
    // Restore feature list.
    if (original_feature_list_) {
      base::FeatureList::ClearInstanceForTesting();
      base::FeatureList::RestoreInstanceForTesting(
          std::move(original_feature_list_));
    }
  }

 private:
  // Save the present FeatureList and restore it after test finish.
  std::unique_ptr<FeatureList> original_feature_list_;

  DISALLOW_COPY_AND_ASSIGN(ScopedFeatureListTest);
};

TEST_F(ScopedFeatureListTest, BasicScoped) {
  ExpectFeatures(std::string(), std::string());
  EXPECT_FALSE(FeatureList::IsEnabled(kTestFeature1));
  {
    test::ScopedFeatureList feature_list1;
    feature_list1.InitFromCommandLine("TestFeature1", std::string());
    ExpectFeatures("TestFeature1", std::string());
    EXPECT_TRUE(FeatureList::IsEnabled(kTestFeature1));
  }
  ExpectFeatures(std::string(), std::string());
  EXPECT_FALSE(FeatureList::IsEnabled(kTestFeature1));
}

TEST_F(ScopedFeatureListTest, EnableFeatureOverrideDisable) {
  test::ScopedFeatureList feature_list1;
  feature_list1.InitWithFeatures({}, {kTestFeature1});

  {
    test::ScopedFeatureList feature_list2;
    feature_list2.InitWithFeatures({kTestFeature1}, {});
    ExpectFeatures("TestFeature1", std::string());
  }
}

TEST_F(ScopedFeatureListTest, FeatureOverrideNotMakeDuplicate) {
  test::ScopedFeatureList feature_list1;
  feature_list1.InitWithFeatures({}, {kTestFeature1});

  {
    test::ScopedFeatureList feature_list2;
    feature_list2.InitWithFeatures({}, {kTestFeature1});
    ExpectFeatures(std::string(), "TestFeature1");
  }
}

TEST_F(ScopedFeatureListTest, FeatureOverrideFeatureWithDefault) {
  test::ScopedFeatureList feature_list1;
  feature_list1.InitFromCommandLine("*TestFeature1", std::string());

  {
    test::ScopedFeatureList feature_list2;
    feature_list2.InitWithFeatures({kTestFeature1}, {});
    ExpectFeatures("TestFeature1", std::string());
  }
}

TEST_F(ScopedFeatureListTest, FeatureOverrideFeatureWithDefault2) {
  test::ScopedFeatureList feature_list1;
  feature_list1.InitFromCommandLine("*TestFeature1", std::string());

  {
    test::ScopedFeatureList feature_list2;
    feature_list2.InitWithFeatures({}, {kTestFeature1});
    ExpectFeatures(std::string(), "TestFeature1");
  }
}

TEST_F(ScopedFeatureListTest, FeatureOverrideFeatureWithEnabledFieldTried) {
  test::ScopedFeatureList feature_list1;

  std::unique_ptr<FeatureList> feature_list(new FeatureList);
  FieldTrialList field_trial_list(nullptr);
  FieldTrial* trial = FieldTrialList::CreateFieldTrial("TrialExample", "A");
  feature_list->RegisterFieldTrialOverride(
      kTestFeature1.name, FeatureList::OVERRIDE_ENABLE_FEATURE, trial);
  feature_list1.InitWithFeatureList(std::move(feature_list));

  {
    test::ScopedFeatureList feature_list2;
    feature_list2.InitWithFeatures({kTestFeature1}, {});
    ExpectFeatures("TestFeature1", std::string());
  }
}

TEST_F(ScopedFeatureListTest, FeatureOverrideFeatureWithDisabledFieldTried) {
  test::ScopedFeatureList feature_list1;

  std::unique_ptr<FeatureList> feature_list(new FeatureList);
  FieldTrialList field_trial_list(nullptr);
  FieldTrial* trial = FieldTrialList::CreateFieldTrial("TrialExample", "A");
  feature_list->RegisterFieldTrialOverride(
      kTestFeature1.name, FeatureList::OVERRIDE_DISABLE_FEATURE, trial);
  feature_list1.InitWithFeatureList(std::move(feature_list));

  {
    test::ScopedFeatureList feature_list2;
    feature_list2.InitWithFeatures({kTestFeature1}, {});
    ExpectFeatures("TestFeature1", std::string());
  }
}

TEST_F(ScopedFeatureListTest, FeatureOverrideKeepsOtherExistingFeature) {
  test::ScopedFeatureList feature_list1;
  feature_list1.InitWithFeatures({}, {kTestFeature1});

  {
    test::ScopedFeatureList feature_list2;
    feature_list2.InitWithFeatures({}, {kTestFeature2});
    EXPECT_FALSE(FeatureList::IsEnabled(kTestFeature1));
    EXPECT_FALSE(FeatureList::IsEnabled(kTestFeature2));
  }
}

TEST_F(ScopedFeatureListTest, FeatureOverrideKeepsOtherExistingFeature2) {
  test::ScopedFeatureList feature_list1;
  feature_list1.InitWithFeatures({}, {kTestFeature1});

  {
    test::ScopedFeatureList feature_list2;
    feature_list2.InitWithFeatures({kTestFeature2}, {});
    ExpectFeatures("TestFeature2", "TestFeature1");
  }
}

TEST_F(ScopedFeatureListTest, FeatureOverrideKeepsOtherExistingDefaultFeature) {
  test::ScopedFeatureList feature_list1;
  feature_list1.InitFromCommandLine("*TestFeature1", std::string());

  {
    test::ScopedFeatureList feature_list2;
    feature_list2.InitWithFeatures({}, {kTestFeature2});
    ExpectFeatures("*TestFeature1", "TestFeature2");
  }
}

}  // namespace test
}  // namespace base
