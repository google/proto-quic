// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_METRICS_FIELD_TRIAL_PARAMS_H_
#define BASE_METRICS_FIELD_TRIAL_PARAMS_H_

#include <map>
#include <string>

#include "base/base_export.h"

namespace base {

struct Feature;

// Associates the specified set of key-value |params| with the field trial
// specified by |trial_name| and |group_name|. Fails and returns false if the
// specified field trial already has params associated with it or the trial
// is already active (group() has been called on it). Thread safe.
BASE_EXPORT bool AssociateFieldTrialParams(
    const std::string& trial_name,
    const std::string& group_name,
    const std::map<std::string, std::string>& params);

// Retrieves the set of key-value |params| for the specified field trial, based
// on its selected group. If the field trial does not exist or its selected
// group does not have any parameters associated with it, returns false and
// does not modify |params|. Calling this function will result in the field
// trial being marked as active if found (i.e. group() will be called on it),
// if it wasn't already. Thread safe.
BASE_EXPORT bool GetFieldTrialParams(
    const std::string& trial_name,
    std::map<std::string, std::string>* params);

// Retrieves the set of key-value |params| for the field trial associated with
// the specified |feature|. A feature is associated with at most one field
// trial and selected group. See  base/feature_list.h for more information on
// features. If the feature is not enabled, or if there's no associated params,
// returns false and does not modify |params|. Calling this function will
// result in the associated field trial being marked as active if found (i.e.
// group() will be called on it), if it wasn't already. Thread safe.
BASE_EXPORT bool GetFieldTrialParamsByFeature(
    const base::Feature& feature,
    std::map<std::string, std::string>* params);

// Retrieves a specific parameter value corresponding to |param_name| for the
// specified field trial, based on its selected group. If the field trial does
// not exist or the specified parameter does not exist, returns an empty
// string. Calling this function will result in the field trial being marked as
// active if found (i.e. group() will be called on it), if it wasn't already.
// Thread safe.
BASE_EXPORT std::string GetFieldTrialParamValue(const std::string& trial_name,
                                                const std::string& param_name);

// Retrieves a specific parameter value corresponding to |param_name| for the
// field trial associated with the specified |feature|. A feature is associated
// with at most one field trial and selected group. See base/feature_list.h for
// more information on features. If the feature is not enabled, or the
// specified parameter does not exist, returns an empty string. Calling this
// function will result in the associated field trial being marked as active if
// found (i.e. group() will be called on it), if it wasn't already. Thread safe.
BASE_EXPORT std::string GetFieldTrialParamValueByFeature(
    const base::Feature& feature,
    const std::string& param_name);

// Same as GetFieldTrialParamValueByFeature(). On top of that, it converts the
// string value into an int using base::StringToInt() and returns it, if
// successful. Otherwise, it returns |default_value|. If the string value is not
// empty and the conversion does not succeed, it produces a warning to LOG.
BASE_EXPORT int GetFieldTrialParamByFeatureAsInt(const base::Feature& feature,
                                                 const std::string& param_name,
                                                 int default_value);

// Same as GetFieldTrialParamValueByFeature(). On top of that, it converts the
// string value into a double using base::StringToDouble() and returns it, if
// successful. Otherwise, it returns |default_value|. If the string value is not
// empty and the conversion does not succeed, it produces a warning to LOG.
BASE_EXPORT double GetFieldTrialParamByFeatureAsDouble(
    const base::Feature& feature,
    const std::string& param_name,
    double default_value);

// Same as GetFieldTrialParamValueByFeature(). On top of that, it converts the
// string value into a boolean and returns it, if successful. Otherwise, it
// returns |default_value|. The only string representations accepted here are
// "true" and "false". If the string value is not empty and the conversion does
// not succeed, it produces a warning to LOG.
BASE_EXPORT bool GetFieldTrialParamByFeatureAsBool(
    const base::Feature& feature,
    const std::string& param_name,
    bool default_value);

}  // namespace base

#endif  // BASE_METRICS_FIELD_TRIAL_PARAMS_H_
