// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_feature_list.h"

#include <algorithm>
#include <string>
#include <vector>

#include "base/stl_util.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"

namespace base {
namespace test {

namespace {

std::vector<StringPiece> GetFeatureVector(
    const std::initializer_list<base::Feature>& features) {
  std::vector<StringPiece> output;
  for (const base::Feature& feature : features) {
    output.push_back(feature.name);
  }

  return output;
}

// Extracts a feature name from a feature state string. For example, given
// the input "*MyLovelyFeature<SomeFieldTrial", returns "MyLovelyFeature".
StringPiece GetFeatureName(StringPiece feature) {
  StringPiece feature_name = feature;

  // Remove default info.
  if (feature_name.starts_with("*"))
    feature_name = feature_name.substr(1);

  // Remove field_trial info.
  std::size_t index = feature_name.find("<");
  if (index != std::string::npos)
    feature_name = feature_name.substr(0, index);

  return feature_name;
}

struct Features {
  std::vector<StringPiece> enabled_feature_list;
  std::vector<StringPiece> disabled_feature_list;
};

// Merges previously-specified feature overrides with those passed into one of
// the Init() methods. |features| should be a list of features previously
// overridden to be in the |override_state|. |merged_features| should contain
// the enabled and disabled features passed into the Init() method, plus any
// overrides merged as a result of previous calls to this function.
void OverrideFeatures(const std::string& features,
                      base::FeatureList::OverrideState override_state,
                      Features* merged_features) {
  std::vector<StringPiece> features_list =
      SplitStringPiece(features, ",", TRIM_WHITESPACE, SPLIT_WANT_NONEMPTY);

  for (StringPiece feature : features_list) {
    StringPiece feature_name = GetFeatureName(feature);

    if (ContainsValue(merged_features->enabled_feature_list, feature_name) ||
        ContainsValue(merged_features->disabled_feature_list, feature_name))
      continue;

    if (override_state == FeatureList::OverrideState::OVERRIDE_ENABLE_FEATURE) {
      merged_features->enabled_feature_list.push_back(feature);
    } else {
      DCHECK_EQ(override_state,
                FeatureList::OverrideState::OVERRIDE_DISABLE_FEATURE);
      merged_features->disabled_feature_list.push_back(feature);
    }
  }
}

}  // namespace

ScopedFeatureList::ScopedFeatureList() {}

ScopedFeatureList::~ScopedFeatureList() {
  if (original_feature_list_) {
    base::FeatureList::ClearInstanceForTesting();
    base::FeatureList::RestoreInstanceForTesting(
        std::move(original_feature_list_));
  }
}

void ScopedFeatureList::Init() {
  std::unique_ptr<base::FeatureList> feature_list(new base::FeatureList);
  feature_list->InitializeFromCommandLine(std::string(), std::string());
  InitWithFeatureList(std::move(feature_list));
}

void ScopedFeatureList::InitWithFeatureList(
    std::unique_ptr<FeatureList> feature_list) {
  DCHECK(!original_feature_list_);
  original_feature_list_ = base::FeatureList::ClearInstanceForTesting();
  base::FeatureList::SetInstance(std::move(feature_list));
}

void ScopedFeatureList::InitFromCommandLine(
    const std::string& enable_features,
    const std::string& disable_features) {
  std::unique_ptr<base::FeatureList> feature_list(new base::FeatureList);
  feature_list->InitializeFromCommandLine(enable_features, disable_features);
  InitWithFeatureList(std::move(feature_list));
}

void ScopedFeatureList::InitWithFeatures(
    const std::initializer_list<base::Feature>& enabled_features,
    const std::initializer_list<base::Feature>& disabled_features) {
  Features merged_features;
  merged_features.enabled_feature_list = GetFeatureVector(enabled_features);
  merged_features.disabled_feature_list = GetFeatureVector(disabled_features);

  base::FeatureList* feature_list = base::FeatureList::GetInstance();

  // |current_enabled_features| and |current_disabled_features| must declare out
  // of if scope to avoid them out of scope before JoinString calls because
  // |merged_features| may contains StringPiece which holding pointer points to
  // |current_enabled_features| and |current_disabled_features|.
  std::string current_enabled_features;
  std::string current_disabled_features;
  if (feature_list) {
    base::FeatureList::GetInstance()->GetFeatureOverrides(
        &current_enabled_features, &current_disabled_features);
    OverrideFeatures(current_enabled_features,
                     FeatureList::OverrideState::OVERRIDE_ENABLE_FEATURE,
                     &merged_features);
    OverrideFeatures(current_disabled_features,
                     FeatureList::OverrideState::OVERRIDE_DISABLE_FEATURE,
                     &merged_features);
  }

  std::string enabled = JoinString(merged_features.enabled_feature_list, ",");
  std::string disabled = JoinString(merged_features.disabled_feature_list, ",");
  InitFromCommandLine(enabled, disabled);
}

void ScopedFeatureList::InitAndEnableFeature(const base::Feature& feature) {
  InitWithFeatures({feature}, {});
}

void ScopedFeatureList::InitAndDisableFeature(const base::Feature& feature) {
  InitWithFeatures({}, {feature});
}

}  // namespace test
}  // namespace base
