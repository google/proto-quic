// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/metrics/field_trial_params.h"

#include "base/feature_list.h"
#include "base/macros.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/field_trial_param_associator.h"
#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

namespace {

// Call FieldTrialList::FactoryGetFieldTrial() with a future expiry date.
scoped_refptr<FieldTrial> CreateFieldTrial(
    const std::string& trial_name,
    int total_probability,
    const std::string& default_group_name,
    int* default_group_number) {
  return FieldTrialList::FactoryGetFieldTrial(
      trial_name, total_probability, default_group_name,
      FieldTrialList::kNoExpirationYear, 1, 1, FieldTrial::SESSION_RANDOMIZED,
      default_group_number);
}

}  // namespace

class FieldTrialParamsTest : public ::testing::Test {
 public:
  FieldTrialParamsTest() : field_trial_list_(nullptr) {}

  ~FieldTrialParamsTest() override {
    // Ensure that the maps are cleared between tests, since they are stored as
    // process singletons.
    FieldTrialParamAssociator::GetInstance()->ClearAllParamsForTesting();
  }

  void CreateFeatureWithTrial(const Feature& feature,
                              FeatureList::OverrideState override_state,
                              FieldTrial* trial) {
    std::unique_ptr<FeatureList> feature_list(new FeatureList);
    feature_list->RegisterFieldTrialOverride(feature.name, override_state,
                                             trial);
    scoped_feature_list_.InitWithFeatureList(std::move(feature_list));
  }

 private:
  FieldTrialList field_trial_list_;
  test::ScopedFeatureList scoped_feature_list_;

  DISALLOW_COPY_AND_ASSIGN(FieldTrialParamsTest);
};

TEST_F(FieldTrialParamsTest, AssociateFieldTrialParams) {
  const std::string kTrialName = "AssociateFieldTrialParams";

  {
    std::map<std::string, std::string> params;
    params["a"] = "10";
    params["b"] = "test";
    ASSERT_TRUE(AssociateFieldTrialParams(kTrialName, "A", params));
  }
  {
    std::map<std::string, std::string> params;
    params["a"] = "5";
    ASSERT_TRUE(AssociateFieldTrialParams(kTrialName, "B", params));
  }

  FieldTrialList::CreateFieldTrial(kTrialName, "B");
  EXPECT_EQ("5", GetFieldTrialParamValue(kTrialName, "a"));
  EXPECT_EQ(std::string(), GetFieldTrialParamValue(kTrialName, "b"));
  EXPECT_EQ(std::string(), GetFieldTrialParamValue(kTrialName, "x"));

  std::map<std::string, std::string> params;
  EXPECT_TRUE(GetFieldTrialParams(kTrialName, &params));
  EXPECT_EQ(1U, params.size());
  EXPECT_EQ("5", params["a"]);
}

TEST_F(FieldTrialParamsTest, AssociateFieldTrialParams_Fail) {
  const std::string kTrialName = "AssociateFieldTrialParams_Fail";
  const std::string kGroupName = "A";

  std::map<std::string, std::string> params;
  params["a"] = "10";
  ASSERT_TRUE(AssociateFieldTrialParams(kTrialName, kGroupName, params));
  params["a"] = "1";
  params["b"] = "2";
  ASSERT_FALSE(AssociateFieldTrialParams(kTrialName, kGroupName, params));

  FieldTrialList::CreateFieldTrial(kTrialName, kGroupName);
  EXPECT_EQ("10", GetFieldTrialParamValue(kTrialName, "a"));
  EXPECT_EQ(std::string(), GetFieldTrialParamValue(kTrialName, "b"));
}

TEST_F(FieldTrialParamsTest, AssociateFieldTrialParams_TrialActiveFail) {
  const std::string kTrialName = "AssociateFieldTrialParams_TrialActiveFail";
  FieldTrialList::CreateFieldTrial(kTrialName, "A");
  ASSERT_EQ("A", FieldTrialList::FindFullName(kTrialName));

  std::map<std::string, std::string> params;
  params["a"] = "10";
  EXPECT_FALSE(AssociateFieldTrialParams(kTrialName, "B", params));
  EXPECT_FALSE(AssociateFieldTrialParams(kTrialName, "A", params));
}

TEST_F(FieldTrialParamsTest, AssociateFieldTrialParams_DoesntActivateTrial) {
  const std::string kTrialName =
      "AssociateFieldTrialParams_DoesntActivateTrial";

  ASSERT_FALSE(FieldTrialList::IsTrialActive(kTrialName));
  scoped_refptr<FieldTrial> trial(
      CreateFieldTrial(kTrialName, 100, "A", nullptr));
  ASSERT_FALSE(FieldTrialList::IsTrialActive(kTrialName));

  std::map<std::string, std::string> params;
  params["a"] = "10";
  EXPECT_TRUE(AssociateFieldTrialParams(kTrialName, "A", params));
  ASSERT_FALSE(FieldTrialList::IsTrialActive(kTrialName));
}

TEST_F(FieldTrialParamsTest, GetFieldTrialParams_NoTrial) {
  const std::string kTrialName = "GetFieldTrialParams_NoParams";

  std::map<std::string, std::string> params;
  EXPECT_FALSE(GetFieldTrialParams(kTrialName, &params));
  EXPECT_EQ(std::string(), GetFieldTrialParamValue(kTrialName, "x"));
  EXPECT_EQ(std::string(), GetFieldTrialParamValue(kTrialName, "y"));
}

TEST_F(FieldTrialParamsTest, GetFieldTrialParams_NoParams) {
  const std::string kTrialName = "GetFieldTrialParams_NoParams";

  FieldTrialList::CreateFieldTrial(kTrialName, "A");

  std::map<std::string, std::string> params;
  EXPECT_FALSE(GetFieldTrialParams(kTrialName, &params));
  EXPECT_EQ(std::string(), GetFieldTrialParamValue(kTrialName, "x"));
  EXPECT_EQ(std::string(), GetFieldTrialParamValue(kTrialName, "y"));
}

TEST_F(FieldTrialParamsTest, GetFieldTrialParams_ActivatesTrial) {
  const std::string kTrialName = "GetFieldTrialParams_ActivatesTrial";

  ASSERT_FALSE(FieldTrialList::IsTrialActive(kTrialName));
  scoped_refptr<FieldTrial> trial(
      CreateFieldTrial(kTrialName, 100, "A", nullptr));
  ASSERT_FALSE(FieldTrialList::IsTrialActive(kTrialName));

  std::map<std::string, std::string> params;
  EXPECT_FALSE(GetFieldTrialParams(kTrialName, &params));
  ASSERT_TRUE(FieldTrialList::IsTrialActive(kTrialName));
}

TEST_F(FieldTrialParamsTest, GetFieldTrialParamValue_ActivatesTrial) {
  const std::string kTrialName = "GetFieldTrialParamValue_ActivatesTrial";

  ASSERT_FALSE(FieldTrialList::IsTrialActive(kTrialName));
  scoped_refptr<FieldTrial> trial(
      CreateFieldTrial(kTrialName, 100, "A", nullptr));
  ASSERT_FALSE(FieldTrialList::IsTrialActive(kTrialName));

  std::map<std::string, std::string> params;
  EXPECT_EQ(std::string(), GetFieldTrialParamValue(kTrialName, "x"));
  ASSERT_TRUE(FieldTrialList::IsTrialActive(kTrialName));
}

TEST_F(FieldTrialParamsTest, GetFieldTrialParamsByFeature) {
  const std::string kTrialName = "GetFieldTrialParamsByFeature";
  const Feature kFeature{"TestFeature", FEATURE_DISABLED_BY_DEFAULT};

  std::map<std::string, std::string> params;
  params["x"] = "1";
  AssociateFieldTrialParams(kTrialName, "A", params);
  scoped_refptr<FieldTrial> trial(
      CreateFieldTrial(kTrialName, 100, "A", nullptr));

  CreateFeatureWithTrial(kFeature, FeatureList::OVERRIDE_ENABLE_FEATURE,
                         trial.get());

  std::map<std::string, std::string> actualParams;
  EXPECT_TRUE(GetFieldTrialParamsByFeature(kFeature, &actualParams));
  EXPECT_EQ(params, actualParams);
}

TEST_F(FieldTrialParamsTest, GetFieldTrialParamValueByFeature) {
  const std::string kTrialName = "GetFieldTrialParamsByFeature";
  const Feature kFeature{"TestFeature", FEATURE_DISABLED_BY_DEFAULT};

  std::map<std::string, std::string> params;
  params["x"] = "1";
  AssociateFieldTrialParams(kTrialName, "A", params);
  scoped_refptr<FieldTrial> trial(
      CreateFieldTrial(kTrialName, 100, "A", nullptr));

  CreateFeatureWithTrial(kFeature, FeatureList::OVERRIDE_ENABLE_FEATURE,
                         trial.get());

  std::map<std::string, std::string> actualParams;
  EXPECT_EQ(params["x"], GetFieldTrialParamValueByFeature(kFeature, "x"));
}

TEST_F(FieldTrialParamsTest, GetFieldTrialParamsByFeature_Disable) {
  const std::string kTrialName = "GetFieldTrialParamsByFeature";
  const Feature kFeature{"TestFeature", FEATURE_DISABLED_BY_DEFAULT};

  std::map<std::string, std::string> params;
  params["x"] = "1";
  AssociateFieldTrialParams(kTrialName, "A", params);
  scoped_refptr<FieldTrial> trial(
      CreateFieldTrial(kTrialName, 100, "A", nullptr));

  CreateFeatureWithTrial(kFeature, FeatureList::OVERRIDE_DISABLE_FEATURE,
                         trial.get());

  std::map<std::string, std::string> actualParams;
  EXPECT_FALSE(GetFieldTrialParamsByFeature(kFeature, &actualParams));
}

TEST_F(FieldTrialParamsTest, GetFieldTrialParamValueByFeature_Disable) {
  const std::string kTrialName = "GetFieldTrialParamsByFeature";
  const Feature kFeature{"TestFeature", FEATURE_DISABLED_BY_DEFAULT};

  std::map<std::string, std::string> params;
  params["x"] = "1";
  AssociateFieldTrialParams(kTrialName, "A", params);
  scoped_refptr<FieldTrial> trial(
      CreateFieldTrial(kTrialName, 100, "A", nullptr));

  CreateFeatureWithTrial(kFeature, FeatureList::OVERRIDE_DISABLE_FEATURE,
                         trial.get());

  std::map<std::string, std::string> actualParams;
  EXPECT_EQ(std::string(), GetFieldTrialParamValueByFeature(kFeature, "x"));
}

TEST_F(FieldTrialParamsTest, GetFieldTrialParamByFeatureAsInt) {
  const std::string kTrialName = "GetFieldTrialParamsByFeature";
  const Feature kFeature{"TestFeature", FEATURE_DISABLED_BY_DEFAULT};

  std::map<std::string, std::string> params;
  params["a"] = "1";
  params["b"] = "1.5";
  params["c"] = "foo";
  params["d"] = "";
  // "e" is not registered
  AssociateFieldTrialParams(kTrialName, "A", params);
  scoped_refptr<FieldTrial> trial(
      CreateFieldTrial(kTrialName, 100, "A", nullptr));

  CreateFeatureWithTrial(kFeature, FeatureList::OVERRIDE_ENABLE_FEATURE,
                         trial.get());

  std::map<std::string, std::string> actualParams;
  EXPECT_EQ(1, GetFieldTrialParamByFeatureAsInt(kFeature, "a", 0));
  EXPECT_EQ(0, GetFieldTrialParamByFeatureAsInt(kFeature, "b", 0));  // invalid
  EXPECT_EQ(0, GetFieldTrialParamByFeatureAsInt(kFeature, "c", 0));  // invalid
  EXPECT_EQ(0, GetFieldTrialParamByFeatureAsInt(kFeature, "d", 0));  // empty
  EXPECT_EQ(0, GetFieldTrialParamByFeatureAsInt(kFeature, "e", 0));  // empty
}

TEST_F(FieldTrialParamsTest, GetFieldTrialParamByFeatureAsDouble) {
  const std::string kTrialName = "GetFieldTrialParamsByFeature";
  const Feature kFeature{"TestFeature", FEATURE_DISABLED_BY_DEFAULT};

  std::map<std::string, std::string> params;
  params["a"] = "1";
  params["b"] = "1.5";
  params["c"] = "1.0e-10";
  params["d"] = "foo";
  params["e"] = "";
  // "f" is not registered
  AssociateFieldTrialParams(kTrialName, "A", params);
  scoped_refptr<FieldTrial> trial(
      CreateFieldTrial(kTrialName, 100, "A", nullptr));

  CreateFeatureWithTrial(kFeature, FeatureList::OVERRIDE_ENABLE_FEATURE,
                         trial.get());

  std::map<std::string, std::string> actualParams;
  EXPECT_EQ(1, GetFieldTrialParamByFeatureAsDouble(kFeature, "a", 0));
  EXPECT_EQ(1.5, GetFieldTrialParamByFeatureAsDouble(kFeature, "b", 0));
  EXPECT_EQ(1.0e-10, GetFieldTrialParamByFeatureAsDouble(kFeature, "c", 0));
  EXPECT_EQ(0,
            GetFieldTrialParamByFeatureAsDouble(kFeature, "d", 0));  // invalid
  EXPECT_EQ(0, GetFieldTrialParamByFeatureAsDouble(kFeature, "e", 0));  // empty
  EXPECT_EQ(0, GetFieldTrialParamByFeatureAsDouble(kFeature, "f", 0));  // empty
}

TEST_F(FieldTrialParamsTest, GetFieldTrialParamByFeatureAsBool) {
  const std::string kTrialName = "GetFieldTrialParamsByFeature";
  const Feature kFeature{"TestFeature", FEATURE_DISABLED_BY_DEFAULT};

  std::map<std::string, std::string> params;
  params["a"] = "true";
  params["b"] = "false";
  params["c"] = "1";
  params["d"] = "False";
  params["e"] = "";
  // "f" is not registered
  AssociateFieldTrialParams(kTrialName, "A", params);
  scoped_refptr<FieldTrial> trial(
      CreateFieldTrial(kTrialName, 100, "A", nullptr));

  CreateFeatureWithTrial(kFeature, FeatureList::OVERRIDE_ENABLE_FEATURE,
                         trial.get());

  std::map<std::string, std::string> actualParams;
  EXPECT_TRUE(GetFieldTrialParamByFeatureAsBool(kFeature, "a", false));
  EXPECT_FALSE(GetFieldTrialParamByFeatureAsBool(kFeature, "b", true));
  EXPECT_FALSE(
      GetFieldTrialParamByFeatureAsBool(kFeature, "c", false));  // invalid
  EXPECT_TRUE(
      GetFieldTrialParamByFeatureAsBool(kFeature, "d", true));  // invalid
  EXPECT_TRUE(GetFieldTrialParamByFeatureAsBool(kFeature, "e", true));  // empty
  EXPECT_TRUE(GetFieldTrialParamByFeatureAsBool(kFeature, "f", true));  // empty
}

}  // namespace base
