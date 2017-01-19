// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/feature_list.h"

#include <stddef.h>

#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial.h"
#include "base/pickle.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"

namespace base {

namespace {

// Pointer to the FeatureList instance singleton that was set via
// FeatureList::SetInstance(). Does not use base/memory/singleton.h in order to
// have more control over initialization timing. Leaky.
FeatureList* g_instance = nullptr;

// Tracks whether the FeatureList instance was initialized via an accessor.
bool g_initialized_from_accessor = false;

// An allocator entry for a feature in shared memory. The FeatureEntry is
// followed by a base::Pickle object that contains the feature and trial name.
struct FeatureEntry {
  // SHA1(FeatureEntry): Increment this if structure changes!
  static constexpr uint32_t kPersistentTypeId = 0x06567CA6 + 1;

  // Expected size for 32/64-bit check.
  static constexpr size_t kExpectedInstanceSize = 8;

  // Specifies whether a feature override enables or disables the feature. Same
  // values as the OverrideState enum in feature_list.h
  uint32_t override_state;

  // Size of the pickled structure, NOT the total size of this entry.
  uint32_t pickle_size;

  // Reads the feature and trial name from the pickle. Calling this is only
  // valid on an initialized entry that's in shared memory.
  bool GetFeatureAndTrialName(StringPiece* feature_name,
                              StringPiece* trial_name) const {
    const char* src =
        reinterpret_cast<const char*>(this) + sizeof(FeatureEntry);

    Pickle pickle(src, pickle_size);
    PickleIterator pickle_iter(pickle);

    if (!pickle_iter.ReadStringPiece(feature_name))
      return false;

    // Return true because we are not guaranteed to have a trial name anyways.
    auto sink = pickle_iter.ReadStringPiece(trial_name);
    ALLOW_UNUSED_LOCAL(sink);
    return true;
  }
};

// Some characters are not allowed to appear in feature names or the associated
// field trial names, as they are used as special characters for command-line
// serialization. This function checks that the strings are ASCII (since they
// are used in command-line API functions that require ASCII) and whether there
// are any reserved characters present, returning true if the string is valid.
// Only called in DCHECKs.
bool IsValidFeatureOrFieldTrialName(const std::string& name) {
  return IsStringASCII(name) && name.find_first_of(",<*") == std::string::npos;
}

}  // namespace

FeatureList::FeatureList() {}

FeatureList::~FeatureList() {}

void FeatureList::InitializeFromCommandLine(
    const std::string& enable_features,
    const std::string& disable_features) {
  DCHECK(!initialized_);

  // Process disabled features first, so that disabled ones take precedence over
  // enabled ones (since RegisterOverride() uses insert()).
  RegisterOverridesFromCommandLine(disable_features, OVERRIDE_DISABLE_FEATURE);
  RegisterOverridesFromCommandLine(enable_features, OVERRIDE_ENABLE_FEATURE);

  initialized_from_command_line_ = true;
}

void FeatureList::InitializeFromSharedMemory(
    PersistentMemoryAllocator* allocator) {
  DCHECK(!initialized_);

  PersistentMemoryAllocator::Iterator iter(allocator);
  const FeatureEntry* entry;
  while ((entry = iter.GetNextOfObject<FeatureEntry>()) != nullptr) {
    OverrideState override_state =
        static_cast<OverrideState>(entry->override_state);

    StringPiece feature_name;
    StringPiece trial_name;
    if (!entry->GetFeatureAndTrialName(&feature_name, &trial_name))
      continue;

    FieldTrial* trial = FieldTrialList::Find(trial_name.as_string());
    RegisterOverride(feature_name, override_state, trial);
  }
}

bool FeatureList::IsFeatureOverriddenFromCommandLine(
    const std::string& feature_name,
    OverrideState state) const {
  auto it = overrides_.find(feature_name);
  return it != overrides_.end() && it->second.overridden_state == state &&
         !it->second.overridden_by_field_trial;
}

void FeatureList::AssociateReportingFieldTrial(
    const std::string& feature_name,
    OverrideState for_overridden_state,
    FieldTrial* field_trial) {
  DCHECK(
      IsFeatureOverriddenFromCommandLine(feature_name, for_overridden_state));

  // Only one associated field trial is supported per feature. This is generally
  // enforced server-side.
  OverrideEntry* entry = &overrides_.find(feature_name)->second;
  if (entry->field_trial) {
    NOTREACHED() << "Feature " << feature_name
                 << " already has trial: " << entry->field_trial->trial_name()
                 << ", associating trial: " << field_trial->trial_name();
    return;
  }

  entry->field_trial = field_trial;
}

void FeatureList::RegisterFieldTrialOverride(const std::string& feature_name,
                                             OverrideState override_state,
                                             FieldTrial* field_trial) {
  DCHECK(field_trial);
  DCHECK(!ContainsKey(overrides_, feature_name) ||
         !overrides_.find(feature_name)->second.field_trial)
      << "Feature " << feature_name
      << " has conflicting field trial overrides: "
      << overrides_.find(feature_name)->second.field_trial->trial_name()
      << " / " << field_trial->trial_name();

  RegisterOverride(feature_name, override_state, field_trial);
}

void FeatureList::AddFeaturesToAllocator(PersistentMemoryAllocator* allocator) {
  DCHECK(initialized_);

  for (const auto& override : overrides_) {
    Pickle pickle;
    pickle.WriteString(override.first);
    if (override.second.field_trial)
      pickle.WriteString(override.second.field_trial->trial_name());

    size_t total_size = sizeof(FeatureEntry) + pickle.size();
    FeatureEntry* entry = allocator->AllocateObject<FeatureEntry>(total_size);
    if (!entry)
      return;

    entry->override_state = override.second.overridden_state;
    entry->pickle_size = pickle.size();

    char* dst = reinterpret_cast<char*>(entry) + sizeof(FeatureEntry);
    memcpy(dst, pickle.data(), pickle.size());

    allocator->MakeIterable(entry);
  }
}

void FeatureList::GetFeatureOverrides(std::string* enable_overrides,
                                      std::string* disable_overrides) {
  DCHECK(initialized_);

  enable_overrides->clear();
  disable_overrides->clear();

  // Note: Since |overrides_| is a std::map, iteration will be in alphabetical
  // order. This not guaranteed to users of this function, but is useful for
  // tests to assume the order.
  for (const auto& entry : overrides_) {
    std::string* target_list = nullptr;
    switch (entry.second.overridden_state) {
      case OVERRIDE_USE_DEFAULT:
      case OVERRIDE_ENABLE_FEATURE:
        target_list = enable_overrides;
        break;
      case OVERRIDE_DISABLE_FEATURE:
        target_list = disable_overrides;
        break;
    }

    if (!target_list->empty())
      target_list->push_back(',');
    if (entry.second.overridden_state == OVERRIDE_USE_DEFAULT)
      target_list->push_back('*');
    target_list->append(entry.first);
    if (entry.second.field_trial) {
      target_list->push_back('<');
      target_list->append(entry.second.field_trial->trial_name());
    }
  }
}

// static
bool FeatureList::IsEnabled(const Feature& feature) {
  if (!g_instance) {
    g_initialized_from_accessor = true;
    return feature.default_state == FEATURE_ENABLED_BY_DEFAULT;
  }
  return g_instance->IsFeatureEnabled(feature);
}

// static
FieldTrial* FeatureList::GetFieldTrial(const Feature& feature) {
  return GetInstance()->GetAssociatedFieldTrial(feature);
}

// static
std::vector<std::string> FeatureList::SplitFeatureListString(
    const std::string& input) {
  return SplitString(input, ",", TRIM_WHITESPACE, SPLIT_WANT_NONEMPTY);
}

// static
bool FeatureList::InitializeInstance(const std::string& enable_features,
                                     const std::string& disable_features) {
  // We want to initialize a new instance here to support command-line features
  // in testing better. For example, we initialize a dummy instance in
  // base/test/test_suite.cc, and override it in content/browser/
  // browser_main_loop.cc.
  // On the other hand, we want to avoid re-initialization from command line.
  // For example, we initialize an instance in chrome/browser/
  // chrome_browser_main.cc and do not override it in content/browser/
  // browser_main_loop.cc.
  // If the singleton was previously initialized from within an accessor, we
  // want to prevent callers from reinitializing the singleton and masking the
  // accessor call(s) which likely returned incorrect information.
  CHECK(!g_initialized_from_accessor);
  bool instance_existed_before = false;
  if (g_instance) {
    if (g_instance->initialized_from_command_line_)
      return false;

    delete g_instance;
    g_instance = nullptr;
    instance_existed_before = true;
  }

  std::unique_ptr<base::FeatureList> feature_list(new base::FeatureList);
  feature_list->InitializeFromCommandLine(enable_features, disable_features);
  base::FeatureList::SetInstance(std::move(feature_list));
  return !instance_existed_before;
}

// static
FeatureList* FeatureList::GetInstance() {
  return g_instance;
}

// static
void FeatureList::SetInstance(std::unique_ptr<FeatureList> instance) {
  DCHECK(!g_instance);
  instance->FinalizeInitialization();

  // Note: Intentional leak of global singleton.
  g_instance = instance.release();
}

// static
std::unique_ptr<FeatureList> FeatureList::ClearInstanceForTesting() {
  FeatureList* old_instance = g_instance;
  g_instance = nullptr;
  g_initialized_from_accessor = false;
  return base::WrapUnique(old_instance);
}

// static
void FeatureList::RestoreInstanceForTesting(
    std::unique_ptr<FeatureList> instance) {
  DCHECK(!g_instance);
  // Note: Intentional leak of global singleton.
  g_instance = instance.release();
}

void FeatureList::FinalizeInitialization() {
  DCHECK(!initialized_);
  initialized_ = true;
}

bool FeatureList::IsFeatureEnabled(const Feature& feature) {
  DCHECK(initialized_);
  DCHECK(IsValidFeatureOrFieldTrialName(feature.name)) << feature.name;
  DCHECK(CheckFeatureIdentity(feature)) << feature.name;

  auto it = overrides_.find(feature.name);
  if (it != overrides_.end()) {
    const OverrideEntry& entry = it->second;

    // Activate the corresponding field trial, if necessary.
    if (entry.field_trial)
      entry.field_trial->group();

    // TODO(asvitkine) Expand this section as more support is added.

    // If marked as OVERRIDE_USE_DEFAULT, simply return the default state below.
    if (entry.overridden_state != OVERRIDE_USE_DEFAULT)
      return entry.overridden_state == OVERRIDE_ENABLE_FEATURE;
  }
  // Otherwise, return the default state.
  return feature.default_state == FEATURE_ENABLED_BY_DEFAULT;
}

FieldTrial* FeatureList::GetAssociatedFieldTrial(const Feature& feature) {
  DCHECK(initialized_);
  DCHECK(IsValidFeatureOrFieldTrialName(feature.name)) << feature.name;
  DCHECK(CheckFeatureIdentity(feature)) << feature.name;

  auto it = overrides_.find(feature.name);
  if (it != overrides_.end()) {
    const OverrideEntry& entry = it->second;
    return entry.field_trial;
  }

  return nullptr;
}

void FeatureList::RegisterOverridesFromCommandLine(
    const std::string& feature_list,
    OverrideState overridden_state) {
  for (const auto& value : SplitFeatureListString(feature_list)) {
    StringPiece feature_name(value);
    base::FieldTrial* trial = nullptr;

    // The entry may be of the form FeatureName<FieldTrialName - in which case,
    // this splits off the field trial name and associates it with the override.
    std::string::size_type pos = feature_name.find('<');
    if (pos != std::string::npos) {
      feature_name.set(value.data(), pos);
      trial = base::FieldTrialList::Find(value.substr(pos + 1));
    }

    RegisterOverride(feature_name, overridden_state, trial);
  }
}

void FeatureList::RegisterOverride(StringPiece feature_name,
                                   OverrideState overridden_state,
                                   FieldTrial* field_trial) {
  DCHECK(!initialized_);
  if (field_trial) {
    DCHECK(IsValidFeatureOrFieldTrialName(field_trial->trial_name()))
        << field_trial->trial_name();
  }
  if (feature_name.starts_with("*")) {
    feature_name = feature_name.substr(1);
    overridden_state = OVERRIDE_USE_DEFAULT;
  }

  // Note: The semantics of insert() is that it does not overwrite the entry if
  // one already exists for the key. Thus, only the first override for a given
  // feature name takes effect.
  overrides_.insert(std::make_pair(
      feature_name.as_string(), OverrideEntry(overridden_state, field_trial)));
}

bool FeatureList::CheckFeatureIdentity(const Feature& feature) {
  AutoLock auto_lock(feature_identity_tracker_lock_);

  auto it = feature_identity_tracker_.find(feature.name);
  if (it == feature_identity_tracker_.end()) {
    // If it's not tracked yet, register it.
    feature_identity_tracker_[feature.name] = &feature;
    return true;
  }
  // Compare address of |feature| to the existing tracked entry.
  return it->second == &feature;
}

FeatureList::OverrideEntry::OverrideEntry(OverrideState overridden_state,
                                          FieldTrial* field_trial)
    : overridden_state(overridden_state),
      field_trial(field_trial),
      overridden_by_field_trial(field_trial != nullptr) {}

}  // namespace base
