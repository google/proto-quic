// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_feature_list.h"

#include <string>

namespace base {
namespace test {

namespace {

static std::string GetFeatureString(
    const std::initializer_list<base::Feature>& features) {
  std::string output;
  for (const base::Feature& feature : features) {
    if (!output.empty())
      output += ",";
    output += feature.name;
  }
  return output;
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

void ScopedFeatureList::InitWithFeatures(
    const std::initializer_list<base::Feature>& enabled_features,
    const std::initializer_list<base::Feature>& disabled_features) {
  InitFromCommandLine(GetFeatureString(enabled_features),
                      GetFeatureString(disabled_features));
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

void ScopedFeatureList::InitAndEnableFeature(const base::Feature& feature) {
  InitFromCommandLine(feature.name, std::string());
}

void ScopedFeatureList::InitAndDisableFeature(const base::Feature& feature) {
  InitFromCommandLine(std::string(), feature.name);
}

}  // namespace test
}  // namespace base
