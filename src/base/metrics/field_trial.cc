// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/metrics/field_trial.h"

#include <algorithm>

#include "base/build_time.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/rand_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"

namespace base {

namespace {

// Define a separator character to use when creating a persistent form of an
// instance.  This is intended for use as a command line argument, passed to a
// second process to mimic our state (i.e., provide the same group name).
const char kPersistentStringSeparator = '/';  // Currently a slash.

// Define a marker character to be used as a prefix to a trial name on the
// command line which forces its activation.
const char kActivationMarker = '*';

// Created a time value based on |year|, |month| and |day_of_month| parameters.
Time CreateTimeFromParams(int year, int month, int day_of_month) {
  DCHECK_GT(year, 1970);
  DCHECK_GT(month, 0);
  DCHECK_LT(month, 13);
  DCHECK_GT(day_of_month, 0);
  DCHECK_LT(day_of_month, 32);

  Time::Exploded exploded;
  exploded.year = year;
  exploded.month = month;
  exploded.day_of_week = 0;  // Should be unused.
  exploded.day_of_month = day_of_month;
  exploded.hour = 0;
  exploded.minute = 0;
  exploded.second = 0;
  exploded.millisecond = 0;

  return Time::FromLocalExploded(exploded);
}

// Returns the boundary value for comparing against the FieldTrial's added
// groups for a given |divisor| (total probability) and |entropy_value|.
FieldTrial::Probability GetGroupBoundaryValue(
    FieldTrial::Probability divisor,
    double entropy_value) {
  // Add a tiny epsilon value to get consistent results when converting floating
  // points to int. Without it, boundary values have inconsistent results, e.g.:
  //
  //   static_cast<FieldTrial::Probability>(100 * 0.56) == 56
  //   static_cast<FieldTrial::Probability>(100 * 0.57) == 56
  //   static_cast<FieldTrial::Probability>(100 * 0.58) == 57
  //   static_cast<FieldTrial::Probability>(100 * 0.59) == 59
  const double kEpsilon = 1e-8;
  const FieldTrial::Probability result =
      static_cast<FieldTrial::Probability>(divisor * entropy_value + kEpsilon);
  // Ensure that adding the epsilon still results in a value < |divisor|.
  return std::min(result, divisor - 1);
}

// Parses the --force-fieldtrials string |trials_string| into |entries|.
// Returns true if the string was parsed correctly. On failure, the |entries|
// array may end up being partially filled.
bool ParseFieldTrialsString(const std::string& trials_string,
                            std::vector<FieldTrial::State>* entries) {
  const StringPiece trials_string_piece(trials_string);

  size_t next_item = 0;
  while (next_item < trials_string.length()) {
    size_t name_end = trials_string.find(kPersistentStringSeparator, next_item);
    if (name_end == trials_string.npos || next_item == name_end)
      return false;
    size_t group_name_end =
        trials_string.find(kPersistentStringSeparator, name_end + 1);
    if (name_end + 1 == group_name_end)
      return false;
    if (group_name_end == trials_string.npos)
      group_name_end = trials_string.length();

    FieldTrial::State entry;
    // Verify if the trial should be activated or not.
    if (trials_string[next_item] == kActivationMarker) {
      // Name cannot be only the indicator.
      if (name_end - next_item == 1)
        return false;
      next_item++;
      entry.activated = true;
    }
    entry.trial_name =
        trials_string_piece.substr(next_item, name_end - next_item);
    entry.group_name =
        trials_string_piece.substr(name_end + 1, group_name_end - name_end - 1);
    next_item = group_name_end + 1;

    entries->push_back(entry);
  }
  return true;
}

void CheckTrialGroup(const std::string& trial_name,
                     const std::string& trial_group,
                     std::map<std::string, std::string>* seen_states) {
  if (ContainsKey(*seen_states, trial_name)) {
    CHECK_EQ((*seen_states)[trial_name], trial_group) << trial_name;
  } else {
    (*seen_states)[trial_name] = trial_group;
  }
}

// A second copy of FieldTrialList::seen_states_ that is meant to outlive the
// FieldTrialList object to determine if the inconsistency happens because there
// might be multiple FieldTrialList objects.
// TODO(asvitkine): Remove when crbug.com/359406 is resolved.
base::LazyInstance<std::map<std::string, std::string>>::Leaky g_seen_states =
    LAZY_INSTANCE_INITIALIZER;

// A debug token generated during FieldTrialList construction. Used to diagnose
// crbug.com/359406.
// TODO(asvitkine): Remove when crbug.com/359406 is resolved.
int32_t g_debug_token = -1;

// Tracks whether |g_seen_states| is used. Defaults to false, because unit tests
// will create multiple FieldTrialList instances. Also controls whether
// |g_debug_token| is included in the field trial state string.
bool g_use_global_check_states = false;

}  // namespace

// statics
const int FieldTrial::kNotFinalized = -1;
const int FieldTrial::kDefaultGroupNumber = 0;
bool FieldTrial::enable_benchmarking_ = false;

int FieldTrialList::kNoExpirationYear = 0;

//------------------------------------------------------------------------------
// FieldTrial methods and members.

FieldTrial::EntropyProvider::~EntropyProvider() {
}

FieldTrial::State::State() : activated(false) {}

FieldTrial::State::State(const State& other) = default;

FieldTrial::State::~State() {}

void FieldTrial::Disable() {
  DCHECK(!group_reported_);
  enable_field_trial_ = false;

  // In case we are disabled after initialization, we need to switch
  // the trial to the default group.
  if (group_ != kNotFinalized) {
    // Only reset when not already the default group, because in case we were
    // forced to the default group, the group number may not be
    // kDefaultGroupNumber, so we should keep it as is.
    if (group_name_ != default_group_name_)
      SetGroupChoice(default_group_name_, kDefaultGroupNumber);
  }
}

int FieldTrial::AppendGroup(const std::string& name,
                            Probability group_probability) {
  // When the group choice was previously forced, we only need to return the
  // the id of the chosen group, and anything can be returned for the others.
  if (forced_) {
    DCHECK(!group_name_.empty());
    if (name == group_name_) {
      // Note that while |group_| may be equal to |kDefaultGroupNumber| on the
      // forced trial, it will not have the same value as the default group
      // number returned from the non-forced |FactoryGetFieldTrial()| call,
      // which takes care to ensure that this does not happen.
      return group_;
    }
    DCHECK_NE(next_group_number_, group_);
    // We still return different numbers each time, in case some caller need
    // them to be different.
    return next_group_number_++;
  }

  DCHECK_LE(group_probability, divisor_);
  DCHECK_GE(group_probability, 0);

  if (enable_benchmarking_ || !enable_field_trial_)
    group_probability = 0;

  accumulated_group_probability_ += group_probability;

  DCHECK_LE(accumulated_group_probability_, divisor_);
  if (group_ == kNotFinalized && accumulated_group_probability_ > random_) {
    // This is the group that crossed the random line, so we do the assignment.
    SetGroupChoice(name, next_group_number_);
  }
  return next_group_number_++;
}

int FieldTrial::group() {
  FinalizeGroupChoice();
  if (trial_registered_)
    FieldTrialList::NotifyFieldTrialGroupSelection(this);
  return group_;
}

const std::string& FieldTrial::group_name() {
  // Call |group()| to ensure group gets assigned and observers are notified.
  group();
  DCHECK(!group_name_.empty());
  return group_name_;
}

const std::string& FieldTrial::GetGroupNameWithoutActivation() {
  FinalizeGroupChoice();
  return group_name_;
}

void FieldTrial::SetForced() {
  // We might have been forced before (e.g., by CreateFieldTrial) and it's
  // first come first served, e.g., command line switch has precedence.
  if (forced_)
    return;

  // And we must finalize the group choice before we mark ourselves as forced.
  FinalizeGroupChoice();
  forced_ = true;
}

// static
void FieldTrial::EnableBenchmarking() {
  DCHECK_EQ(0u, FieldTrialList::GetFieldTrialCount());
  enable_benchmarking_ = true;
}

// static
FieldTrial* FieldTrial::CreateSimulatedFieldTrial(
    const std::string& trial_name,
    Probability total_probability,
    const std::string& default_group_name,
    double entropy_value) {
  return new FieldTrial(trial_name, total_probability, default_group_name,
                        entropy_value);
}

FieldTrial::FieldTrial(const std::string& trial_name,
                       const Probability total_probability,
                       const std::string& default_group_name,
                       double entropy_value)
    : trial_name_(trial_name),
      divisor_(total_probability),
      default_group_name_(default_group_name),
      random_(GetGroupBoundaryValue(total_probability, entropy_value)),
      accumulated_group_probability_(0),
      next_group_number_(kDefaultGroupNumber + 1),
      group_(kNotFinalized),
      enable_field_trial_(true),
      forced_(false),
      group_reported_(false),
      trial_registered_(false) {
  DCHECK_GT(total_probability, 0);
  DCHECK(!trial_name_.empty());
  DCHECK(!default_group_name_.empty());

  if (g_debug_token == -1)
    g_debug_token = RandInt(1, INT32_MAX);
}

FieldTrial::~FieldTrial() {}

void FieldTrial::SetTrialRegistered() {
  DCHECK_EQ(kNotFinalized, group_);
  DCHECK(!trial_registered_);
  trial_registered_ = true;
}

void FieldTrial::SetGroupChoice(const std::string& group_name, int number) {
  group_ = number;
  if (group_name.empty())
    StringAppendF(&group_name_, "%d", group_);
  else
    group_name_ = group_name;
  DVLOG(1) << "Field trial: " << trial_name_ << " Group choice:" << group_name_;
}

void FieldTrial::FinalizeGroupChoice() {
  if (group_ != kNotFinalized)
    return;
  accumulated_group_probability_ = divisor_;
  // Here it's OK to use |kDefaultGroupNumber| since we can't be forced and not
  // finalized.
  DCHECK(!forced_);
  SetGroupChoice(default_group_name_, kDefaultGroupNumber);
}

bool FieldTrial::GetActiveGroup(ActiveGroup* active_group) const {
  if (!group_reported_ || !enable_field_trial_)
    return false;
  DCHECK_NE(group_, kNotFinalized);
  active_group->trial_name = trial_name_;
  active_group->group_name = group_name_;
  return true;
}

bool FieldTrial::GetState(State* field_trial_state) {
  if (!enable_field_trial_)
    return false;
  FinalizeGroupChoice();
  field_trial_state->trial_name = trial_name_;
  field_trial_state->group_name = group_name_;
  field_trial_state->activated = group_reported_;
  return true;
}

//------------------------------------------------------------------------------
// FieldTrialList methods and members.

// static
FieldTrialList* FieldTrialList::global_ = NULL;

// static
bool FieldTrialList::used_without_global_ = false;

FieldTrialList::Observer::~Observer() {
}

FieldTrialList::FieldTrialList(
    const FieldTrial::EntropyProvider* entropy_provider)
    : entropy_provider_(entropy_provider),
      observer_list_(new ObserverListThreadSafe<FieldTrialList::Observer>(
          ObserverListBase<FieldTrialList::Observer>::NOTIFY_EXISTING_ONLY)) {
  // TODO(asvitkine): Turn into a DCHECK after http://crbug.com/359406 is fixed.
  CHECK(!global_);
  DCHECK(!used_without_global_);
  global_ = this;

  Time two_years_from_build_time = GetBuildTime() + TimeDelta::FromDays(730);
  Time::Exploded exploded;
  two_years_from_build_time.LocalExplode(&exploded);
  kNoExpirationYear = exploded.year;
}

FieldTrialList::~FieldTrialList() {
  AutoLock auto_lock(lock_);
  while (!registered_.empty()) {
    RegistrationMap::iterator it = registered_.begin();
    it->second->Release();
    registered_.erase(it->first);
  }
  DCHECK_EQ(this, global_);
  global_ = NULL;
}

// static
void FieldTrialList::EnableGlobalStateChecks() {
  CHECK(!g_use_global_check_states);
  g_use_global_check_states = true;
}

// static
int32_t FieldTrialList::GetDebugToken() {
  return g_debug_token;
}

// static
FieldTrial* FieldTrialList::FactoryGetFieldTrial(
    const std::string& trial_name,
    FieldTrial::Probability total_probability,
    const std::string& default_group_name,
    const int year,
    const int month,
    const int day_of_month,
    FieldTrial::RandomizationType randomization_type,
    int* default_group_number) {
  return FactoryGetFieldTrialWithRandomizationSeed(
      trial_name, total_probability, default_group_name,
      year, month, day_of_month, randomization_type, 0, default_group_number);
}

// static
FieldTrial* FieldTrialList::FactoryGetFieldTrialWithRandomizationSeed(
    const std::string& trial_name,
    FieldTrial::Probability total_probability,
    const std::string& default_group_name,
    const int year,
    const int month,
    const int day_of_month,
    FieldTrial::RandomizationType randomization_type,
    uint32_t randomization_seed,
    int* default_group_number) {
  if (default_group_number)
    *default_group_number = FieldTrial::kDefaultGroupNumber;
  // Check if the field trial has already been created in some other way.
  FieldTrial* existing_trial = Find(trial_name);
  if (existing_trial) {
    CHECK(existing_trial->forced_);
    // If the default group name differs between the existing forced trial
    // and this trial, then use a different value for the default group number.
    if (default_group_number &&
        default_group_name != existing_trial->default_group_name()) {
      // If the new default group number corresponds to the group that was
      // chosen for the forced trial (which has been finalized when it was
      // forced), then set the default group number to that.
      if (default_group_name == existing_trial->group_name_internal()) {
        *default_group_number = existing_trial->group_;
      } else {
        // Otherwise, use |kNonConflictingGroupNumber| (-2) for the default
        // group number, so that it does not conflict with the |AppendGroup()|
        // result for the chosen group.
        const int kNonConflictingGroupNumber = -2;
        static_assert(
            kNonConflictingGroupNumber != FieldTrial::kDefaultGroupNumber,
            "The 'non-conflicting' group number conflicts");
        static_assert(kNonConflictingGroupNumber != FieldTrial::kNotFinalized,
                      "The 'non-conflicting' group number conflicts");
        *default_group_number = kNonConflictingGroupNumber;
      }
    }
    return existing_trial;
  }

  double entropy_value;
  if (randomization_type == FieldTrial::ONE_TIME_RANDOMIZED) {
    const FieldTrial::EntropyProvider* entropy_provider =
        GetEntropyProviderForOneTimeRandomization();
    CHECK(entropy_provider);
    entropy_value = entropy_provider->GetEntropyForTrial(trial_name,
                                                         randomization_seed);
  } else {
    DCHECK_EQ(FieldTrial::SESSION_RANDOMIZED, randomization_type);
    DCHECK_EQ(0U, randomization_seed);
    entropy_value = RandDouble();
  }

  FieldTrial* field_trial = new FieldTrial(trial_name, total_probability,
                                           default_group_name, entropy_value);
  if (GetBuildTime() > CreateTimeFromParams(year, month, day_of_month))
    field_trial->Disable();
  FieldTrialList::Register(field_trial);
  return field_trial;
}

// static
FieldTrial* FieldTrialList::Find(const std::string& trial_name) {
  if (!global_)
    return NULL;
  AutoLock auto_lock(global_->lock_);
  return global_->PreLockedFind(trial_name);
}

// static
int FieldTrialList::FindValue(const std::string& trial_name) {
  FieldTrial* field_trial = Find(trial_name);
  if (field_trial)
    return field_trial->group();
  return FieldTrial::kNotFinalized;
}

// static
std::string FieldTrialList::FindFullName(const std::string& trial_name) {
  FieldTrial* field_trial = Find(trial_name);
  if (field_trial)
    return field_trial->group_name();
  return std::string();
}

// static
bool FieldTrialList::TrialExists(const std::string& trial_name) {
  return Find(trial_name) != NULL;
}

// static
bool FieldTrialList::IsTrialActive(const std::string& trial_name) {
  FieldTrial* field_trial = Find(trial_name);
  FieldTrial::ActiveGroup active_group;
  return field_trial && field_trial->GetActiveGroup(&active_group);
}

// static
void FieldTrialList::StatesToString(std::string* output) {
  FieldTrial::ActiveGroups active_groups;
  GetActiveFieldTrialGroups(&active_groups);
  for (FieldTrial::ActiveGroups::const_iterator it = active_groups.begin();
       it != active_groups.end(); ++it) {
    DCHECK_EQ(std::string::npos,
              it->trial_name.find(kPersistentStringSeparator));
    DCHECK_EQ(std::string::npos,
              it->group_name.find(kPersistentStringSeparator));
    output->append(it->trial_name);
    output->append(1, kPersistentStringSeparator);
    output->append(it->group_name);
    output->append(1, kPersistentStringSeparator);
  }
  if (g_use_global_check_states) {
    output->append("DebugToken");
    output->append(1, kPersistentStringSeparator);
    output->append(IntToString(g_debug_token));
    output->append(1, kPersistentStringSeparator);
  }
}

// static
void FieldTrialList::AllStatesToString(std::string* output) {
  if (!global_)
    return;
  AutoLock auto_lock(global_->lock_);

  for (const auto& registered : global_->registered_) {
    FieldTrial::State trial;
    if (!registered.second->GetState(&trial))
      continue;
    DCHECK_EQ(std::string::npos,
              trial.trial_name.find(kPersistentStringSeparator));
    DCHECK_EQ(std::string::npos,
              trial.group_name.find(kPersistentStringSeparator));
    if (trial.activated)
      output->append(1, kActivationMarker);
    trial.trial_name.AppendToString(output);
    output->append(1, kPersistentStringSeparator);
    trial.group_name.AppendToString(output);
    output->append(1, kPersistentStringSeparator);

    // TODO(asvitkine): Remove these when http://crbug.com/359406 is fixed.
    CheckTrialGroup(trial.trial_name.as_string(), trial.group_name.as_string(),
                    &global_->seen_states_);
    if (g_use_global_check_states) {
      CheckTrialGroup(trial.trial_name.as_string(),
                      trial.group_name.as_string(), &g_seen_states.Get());
    }
  }
}

// static
void FieldTrialList::GetActiveFieldTrialGroups(
    FieldTrial::ActiveGroups* active_groups) {
  DCHECK(active_groups->empty());
  if (!global_)
    return;
  AutoLock auto_lock(global_->lock_);

  for (RegistrationMap::iterator it = global_->registered_.begin();
       it != global_->registered_.end(); ++it) {
    FieldTrial::ActiveGroup active_group;
    if (it->second->GetActiveGroup(&active_group))
      active_groups->push_back(active_group);
  }
}

// static
void FieldTrialList::GetActiveFieldTrialGroupsFromString(
    const std::string& trials_string,
    FieldTrial::ActiveGroups* active_groups) {
  std::vector<FieldTrial::State> entries;
  if (!ParseFieldTrialsString(trials_string, &entries))
    return;

  for (const auto& entry : entries) {
    if (entry.activated) {
      FieldTrial::ActiveGroup group;
      group.trial_name = entry.trial_name.as_string();
      group.group_name = entry.group_name.as_string();
      active_groups->push_back(group);
    }
  }
}

// static
bool FieldTrialList::CreateTrialsFromString(
    const std::string& trials_string,
    const std::set<std::string>& ignored_trial_names) {
  DCHECK(global_);
  if (trials_string.empty() || !global_)
    return true;

  std::vector<FieldTrial::State> entries;
  if (!ParseFieldTrialsString(trials_string, &entries))
    return false;

  for (const auto& entry : entries) {
    const std::string trial_name = entry.trial_name.as_string();
    const std::string group_name = entry.group_name.as_string();

    if (ContainsKey(ignored_trial_names, trial_name))
      continue;

    FieldTrial* trial = CreateFieldTrial(trial_name, group_name);
    if (!trial)
      return false;
    if (entry.activated) {
      // Call |group()| to mark the trial as "used" and notify observers, if
      // any. This is useful to ensure that field trials created in child
      // processes are properly reported in crash reports.
      trial->group();
    }
  }
  return true;
}

// static
FieldTrial* FieldTrialList::CreateFieldTrial(
    const std::string& name,
    const std::string& group_name) {
  DCHECK(global_);
  DCHECK_GE(name.size(), 0u);
  DCHECK_GE(group_name.size(), 0u);
  if (name.empty() || group_name.empty() || !global_)
    return NULL;

  FieldTrial* field_trial = FieldTrialList::Find(name);
  if (field_trial) {
    // In single process mode, or when we force them from the command line,
    // we may have already created the field trial.
    if (field_trial->group_name_internal() != group_name)
      return NULL;
    return field_trial;
  }
  const int kTotalProbability = 100;
  field_trial = new FieldTrial(name, kTotalProbability, group_name, 0);
  FieldTrialList::Register(field_trial);
  // Force the trial, which will also finalize the group choice.
  field_trial->SetForced();
  return field_trial;
}

// static
void FieldTrialList::AddObserver(Observer* observer) {
  if (!global_)
    return;
  global_->observer_list_->AddObserver(observer);
}

// static
void FieldTrialList::RemoveObserver(Observer* observer) {
  if (!global_)
    return;
  global_->observer_list_->RemoveObserver(observer);
}

// static
void FieldTrialList::NotifyFieldTrialGroupSelection(FieldTrial* field_trial) {
  if (!global_)
    return;

  {
    AutoLock auto_lock(global_->lock_);
    if (field_trial->group_reported_)
      return;
    field_trial->group_reported_ = true;
  }

  if (!field_trial->enable_field_trial_)
    return;

  // TODO(asvitkine): Remove this block when http://crbug.com/359406 is fixed.
  {
    AutoLock auto_lock(global_->lock_);
    CheckTrialGroup(field_trial->trial_name(),
                    field_trial->group_name_internal(), &global_->seen_states_);
    if (g_use_global_check_states) {
      CheckTrialGroup(field_trial->trial_name(),
                      field_trial->group_name_internal(), &g_seen_states.Get());
    }
  }
  global_->observer_list_->Notify(
      FROM_HERE, &FieldTrialList::Observer::OnFieldTrialGroupFinalized,
      field_trial->trial_name(), field_trial->group_name_internal());
}

// static
size_t FieldTrialList::GetFieldTrialCount() {
  if (!global_)
    return 0;
  AutoLock auto_lock(global_->lock_);
  return global_->registered_.size();
}

// static
const FieldTrial::EntropyProvider*
    FieldTrialList::GetEntropyProviderForOneTimeRandomization() {
  if (!global_) {
    used_without_global_ = true;
    return NULL;
  }

  return global_->entropy_provider_.get();
}

FieldTrial* FieldTrialList::PreLockedFind(const std::string& name) {
  RegistrationMap::iterator it = registered_.find(name);
  if (registered_.end() == it)
    return NULL;
  return it->second;
}

// static
void FieldTrialList::Register(FieldTrial* trial) {
  if (!global_) {
    used_without_global_ = true;
    return;
  }
  AutoLock auto_lock(global_->lock_);
  CHECK(!global_->PreLockedFind(trial->trial_name())) << trial->trial_name();
  trial->AddRef();
  trial->SetTrialRegistered();
  global_->registered_[trial->trial_name()] = trial;
}

}  // namespace base
