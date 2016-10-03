// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// GENERATED FROM THE SCHEMA DEFINITION AND DESCRIPTION IN
//   fieldtrial_testing_config_schema.json
//   test_config.json
// DO NOT EDIT.

#include "test_output.h"


const char* const array_kFieldTrialConfig_enable_features_1[] = {
      "X",
};
const FieldTrialTestingExperiment array_kFieldTrialConfig_experiments_1[] = {
    {
      "TestGroup3",
      NULL,
      0,
      array_kFieldTrialConfig_enable_features_1,
      1,
      NULL,
      0,
    },
};
const char* const array_kFieldTrialConfig_disable_features_0[] = {
      "F",
};
const char* const array_kFieldTrialConfig_enable_features_0[] = {
      "D",
      "E",
};
const FieldTrialTestingExperimentParams array_kFieldTrialConfig_params_0[] = {
      {
        "x",
        "3",
      },
      {
        "y",
        "4",
      },
};
const char* const array_kFieldTrialConfig_disable_features[] = {
      "C",
};
const char* const array_kFieldTrialConfig_enable_features[] = {
      "A",
      "B",
};
const FieldTrialTestingExperimentParams array_kFieldTrialConfig_params[] = {
      {
        "x",
        "1",
      },
      {
        "y",
        "2",
      },
};
const FieldTrialTestingExperiment array_kFieldTrialConfig_experiments_0[] = {
    {
      "TestGroup2",
      array_kFieldTrialConfig_params,
      2,
      array_kFieldTrialConfig_enable_features,
      2,
      array_kFieldTrialConfig_disable_features,
      1,
    },
    {
      "TestGroup2-2",
      array_kFieldTrialConfig_params_0,
      2,
      array_kFieldTrialConfig_enable_features_0,
      2,
      array_kFieldTrialConfig_disable_features_0,
      1,
    },
};
const FieldTrialTestingExperiment array_kFieldTrialConfig_experiments[] = {
    {
      "TestGroup1",
      NULL,
      0,
      NULL,
      0,
      NULL,
      0,
    },
};
const FieldTrialTestingStudy array_kFieldTrialConfig_studies[] = {
  {
    "TestTrial1",
    array_kFieldTrialConfig_experiments,
    1,
  },
  {
    "TestTrial2",
    array_kFieldTrialConfig_experiments_0,
    2,
  },
  {
    "TestTrial3",
    array_kFieldTrialConfig_experiments_1,
    1,
  },
};
const FieldTrialTestingConfig kFieldTrialConfig = {
  array_kFieldTrialConfig_studies,
  3,
};
