// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_feature_list.h"

#include <map>
#include <string>
#include <utility>

#include "base/metrics/field_trial.h"
#include "base/metrics/field_trial_params.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace test {

namespace {

const Feature kTestFeature1{"TestFeature1", FEATURE_DISABLED_BY_DEFAULT};
const Feature kTestFeature2{"TestFeature2", FEATURE_DISABLED_BY_DEFAULT};

void ExpectFeatures(const std::string& enabled_features,
                    const std::string& disabled_features) {
  FeatureList* list = FeatureList::GetInstance();
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
    std::unique_ptr<FeatureList> feature_list(new FeatureList);
    feature_list->InitializeFromCommandLine(std::string(), std::string());
    original_feature_list_ = FeatureList::ClearInstanceForTesting();
    FeatureList::SetInstance(std::move(feature_list));
  }

  ~ScopedFeatureListTest() override {
    // Restore feature list.
    if (original_feature_list_) {
      FeatureList::ClearInstanceForTesting();
      FeatureList::RestoreInstanceForTesting(std::move(original_feature_list_));
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

TEST_F(ScopedFeatureListTest, EnableWithFeatureParameters) {
  const char kParam1[] = "param_1";
  const char kParam2[] = "param_2";
  const char kValue1[] = "value_1";
  const char kValue2[] = "value_2";
  std::map<std::string, std::string> parameters;
  parameters[kParam1] = kValue1;
  parameters[kParam2] = kValue2;

  ExpectFeatures(std::string(), std::string());
  EXPECT_EQ(nullptr, FeatureList::GetFieldTrial(kTestFeature1));
  EXPECT_EQ("", GetFieldTrialParamValueByFeature(kTestFeature1, kParam1));
  EXPECT_EQ("", GetFieldTrialParamValueByFeature(kTestFeature1, kParam2));
  FieldTrial::ActiveGroups active_groups;
  FieldTrialList::GetActiveFieldTrialGroups(&active_groups);
  EXPECT_EQ(0u, active_groups.size());

  {
    test::ScopedFeatureList feature_list;

    feature_list.InitAndEnableFeatureWithParameters(kTestFeature1, parameters);
    EXPECT_TRUE(FeatureList::IsEnabled(kTestFeature1));
    EXPECT_EQ(kValue1,
              GetFieldTrialParamValueByFeature(kTestFeature1, kParam1));
    EXPECT_EQ(kValue2,
              GetFieldTrialParamValueByFeature(kTestFeature1, kParam2));
    active_groups.clear();
    FieldTrialList::GetActiveFieldTrialGroups(&active_groups);
    EXPECT_EQ(1u, active_groups.size());
  }

  ExpectFeatures(std::string(), std::string());
  EXPECT_EQ(nullptr, FeatureList::GetFieldTrial(kTestFeature1));
  EXPECT_EQ("", GetFieldTrialParamValueByFeature(kTestFeature1, kParam1));
  EXPECT_EQ("", GetFieldTrialParamValueByFeature(kTestFeature1, kParam2));
  active_groups.clear();
  FieldTrialList::GetActiveFieldTrialGroups(&active_groups);
  EXPECT_EQ(0u, active_groups.size());
}

TEST_F(ScopedFeatureListTest, OverrideWithFeatureParameters) {
  FieldTrialList field_trial_list(nullptr);
  scoped_refptr<FieldTrial> trial =
      FieldTrialList::CreateFieldTrial("foo", "bar");
  const char kParam[] = "param_1";
  const char kValue[] = "value_1";
  std::map<std::string, std::string> parameters;
  parameters[kParam] = kValue;

  test::ScopedFeatureList feature_list1;
  feature_list1.InitFromCommandLine("TestFeature1<foo,TestFeature2",
                                    std::string());

  // Check initial state.
  ExpectFeatures("TestFeature1<foo,TestFeature2", std::string());
  EXPECT_TRUE(FeatureList::IsEnabled(kTestFeature1));
  EXPECT_TRUE(FeatureList::IsEnabled(kTestFeature2));
  EXPECT_EQ(trial.get(), FeatureList::GetFieldTrial(kTestFeature1));
  EXPECT_EQ(nullptr, FeatureList::GetFieldTrial(kTestFeature2));
  EXPECT_EQ("", GetFieldTrialParamValueByFeature(kTestFeature1, kParam));
  EXPECT_EQ("", GetFieldTrialParamValueByFeature(kTestFeature2, kParam));

  {
    // Override feature with existing field trial.
    test::ScopedFeatureList feature_list2;

    feature_list2.InitAndEnableFeatureWithParameters(kTestFeature1, parameters);
    EXPECT_TRUE(FeatureList::IsEnabled(kTestFeature1));
    EXPECT_TRUE(FeatureList::IsEnabled(kTestFeature2));
    EXPECT_EQ(kValue, GetFieldTrialParamValueByFeature(kTestFeature1, kParam));
    EXPECT_EQ("", GetFieldTrialParamValueByFeature(kTestFeature2, kParam));
    EXPECT_NE(trial.get(), FeatureList::GetFieldTrial(kTestFeature1));
    EXPECT_NE(nullptr, FeatureList::GetFieldTrial(kTestFeature1));
    EXPECT_EQ(nullptr, FeatureList::GetFieldTrial(kTestFeature2));
  }

  // Check that initial state is restored.
  ExpectFeatures("TestFeature1<foo,TestFeature2", std::string());
  EXPECT_TRUE(FeatureList::IsEnabled(kTestFeature1));
  EXPECT_TRUE(FeatureList::IsEnabled(kTestFeature2));
  EXPECT_EQ(trial.get(), FeatureList::GetFieldTrial(kTestFeature1));
  EXPECT_EQ(nullptr, FeatureList::GetFieldTrial(kTestFeature2));
  EXPECT_EQ("", GetFieldTrialParamValueByFeature(kTestFeature1, kParam));
  EXPECT_EQ("", GetFieldTrialParamValueByFeature(kTestFeature2, kParam));

  {
    // Override feature with no existing field trial.
    test::ScopedFeatureList feature_list2;

    feature_list2.InitAndEnableFeatureWithParameters(kTestFeature2, parameters);
    EXPECT_TRUE(FeatureList::IsEnabled(kTestFeature1));
    EXPECT_TRUE(FeatureList::IsEnabled(kTestFeature2));
    EXPECT_EQ("", GetFieldTrialParamValueByFeature(kTestFeature1, kParam));
    EXPECT_EQ("", GetFieldTrialParamValueByFeature(kTestFeature2, kParam));
    EXPECT_EQ(trial.get(), FeatureList::GetFieldTrial(kTestFeature1));
    EXPECT_NE(nullptr, FeatureList::GetFieldTrial(kTestFeature2));
  }

  // Check that initial state is restored.
  ExpectFeatures("TestFeature1<foo,TestFeature2", std::string());
  EXPECT_TRUE(FeatureList::IsEnabled(kTestFeature1));
  EXPECT_TRUE(FeatureList::IsEnabled(kTestFeature2));
  EXPECT_EQ(trial.get(), FeatureList::GetFieldTrial(kTestFeature1));
  EXPECT_EQ(nullptr, FeatureList::GetFieldTrial(kTestFeature2));
  EXPECT_EQ("", GetFieldTrialParamValueByFeature(kTestFeature1, kParam));
  EXPECT_EQ("", GetFieldTrialParamValueByFeature(kTestFeature2, kParam));
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

TEST_F(ScopedFeatureListTest, FeatureOverrideFeatureWithEnabledFieldTrial) {
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

TEST_F(ScopedFeatureListTest, FeatureOverrideFeatureWithDisabledFieldTrial) {
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
