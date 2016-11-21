// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/simple/simple_experiment.h"

#include <map>
#include <string>

#include "base/metrics/field_trial.h"
#include "base/metrics/field_trial_param_associator.h"
#include "base/strings/string_number_conversions.h"

namespace disk_cache {

const base::Feature kSimpleSizeExperiment = {"SimpleSizeExperiment",
                                             base::FEATURE_DISABLED_BY_DEFAULT};
const char kSizeMultiplierParam[] = "SizeMultiplier";

namespace {

// Returns true if the experiment is found and properly defined.
bool CheckForSimpleSizeExperiment(disk_cache::SimpleExperiment* experiment) {
  DCHECK_EQ(disk_cache::SimpleExperimentType::NONE, experiment->type);
  DCHECK_EQ(0u, experiment->param);

  if (!base::FeatureList::IsEnabled(kSimpleSizeExperiment))
    return false;

  base::FieldTrial* trial =
      base::FeatureList::GetFieldTrial(kSimpleSizeExperiment);
  if (!trial)
    return false;

  std::map<std::string, std::string> params;
  base::FieldTrialParamAssociator::GetInstance()->GetFieldTrialParams(
      trial->trial_name(), &params);
  auto iter = params.find(kSizeMultiplierParam);
  if (iter == params.end())
    return false;

  uint32_t param;
  if (!base::StringToUint(iter->second, &param))
    return false;

  experiment->type = disk_cache::SimpleExperimentType::SIZE;
  experiment->param = param;
  return true;
}

}  // namespace

// Returns the experiment for the given |cache_type|.
SimpleExperiment GetSimpleExperiment(net::CacheType cache_type) {
  SimpleExperiment experiment;

  if (cache_type != net::DISK_CACHE)
    return experiment;

  CheckForSimpleSizeExperiment(&experiment);
  return experiment;
}

}  // namespace disk_cache
