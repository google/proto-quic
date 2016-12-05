// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/metrics/field_trial.h"

#include <algorithm>
#include <utility>

#include "base/base_switches.h"
#include "base/build_time.h"
#include "base/command_line.h"
#include "base/feature_list.h"
#include "base/logging.h"
#include "base/metrics/field_trial_param_associator.h"
#include "base/pickle.h"
#include "base/process/memory.h"
#include "base/rand_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"

// On systems that use the zygote process to spawn child processes, we must
// retrieve the correct fd using the mapping in GlobalDescriptors.
#if defined(OS_POSIX) && !defined(OS_NACL) && !defined(OS_MACOSX) && \
    !defined(OS_ANDROID)
#define POSIX_WITH_ZYGOTE 1
#endif

#if defined(POSIX_WITH_ZYGOTE)
#include "base/posix/global_descriptors.h"
#endif

namespace base {

namespace {

// Define a separator character to use when creating a persistent form of an
// instance.  This is intended for use as a command line argument, passed to a
// second process to mimic our state (i.e., provide the same group name).
const char kPersistentStringSeparator = '/';  // Currently a slash.

// Define a marker character to be used as a prefix to a trial name on the
// command line which forces its activation.
const char kActivationMarker = '*';

// Use shared memory to communicate field trial (experiment) state. Set to false
// for now while the implementation is fleshed out (e.g. data format, single
// shared memory segment). See https://codereview.chromium.org/2365273004/ and
// crbug.com/653874
const bool kUseSharedMemoryForFieldTrials = true;

// Constants for the field trial allocator.
const char kAllocatorName[] = "FieldTrialAllocator";
const uint32_t kFieldTrialType = 0xABA17E13 + 2;  // SHA1(FieldTrialEntry) v2

// We allocate 128 KiB to hold all the field trial data. This should be enough,
// as most people use 3 - 25 KiB for field trials (as of 11/25/2016).
// This also doesn't allocate all 128 KiB at once -- the pages only get mapped
// to physical memory when they are touched. If the size of the allocated field
// trials does get larger than 128 KiB, then we will drop some field trials in
// child processes, leading to an inconsistent view between browser and child
// processes and possibly causing crashes (see crbug.com/661617).
#if !defined(OS_NACL)
const size_t kFieldTrialAllocationSize = 128 << 10;  // 128 KiB
#endif

// We create one FieldTrialEntry per field trial in shared memory, via
// AddToAllocatorWhileLocked. The FieldTrialEntry is followed by a base::Pickle
// object that we unpickle and read from. Any changes to this structure requires
// a bump in kFieldTrialType id defined above.
struct FieldTrialEntry {
  // Expected size for 32/64-bit check.
  static constexpr size_t kExpectedInstanceSize = 8;

  // Whether or not this field trial is activated. This is really just a boolean
  // but marked as a uint32_t for portability reasons.
  uint32_t activated;

  // Size of the pickled structure, NOT the total size of this entry.
  uint32_t size;

  // Returns an iterator over the data containing names and params.
  PickleIterator GetPickleIterator() const {
    char* src = reinterpret_cast<char*>(const_cast<FieldTrialEntry*>(this)) +
                sizeof(FieldTrialEntry);

    Pickle pickle(src, size);
    return PickleIterator(pickle);
  }

  // Takes the iterator and writes out the first two items into |trial_name| and
  // |group_name|.
  bool ReadStringPair(PickleIterator* iter,
                      StringPiece* trial_name,
                      StringPiece* group_name) const {
    if (!iter->ReadStringPiece(trial_name))
      return false;
    if (!iter->ReadStringPiece(group_name))
      return false;
    return true;
  }

  // Calling this is only valid when the entry is initialized. That is, it
  // resides in shared memory and has a pickle containing the trial name and
  // group name following it.
  bool GetTrialAndGroupName(StringPiece* trial_name,
                            StringPiece* group_name) const {
    PickleIterator iter = GetPickleIterator();
    return ReadStringPair(&iter, trial_name, group_name);
  }

  // Calling this is only valid when the entry is initialized as well. Reads the
  // parameters following the trial and group name and stores them as key-value
  // mappings in |params|.
  bool GetParams(std::map<std::string, std::string>* params) const {
    PickleIterator iter = GetPickleIterator();
    StringPiece tmp;
    if (!ReadStringPair(&iter, &tmp, &tmp))
      return false;

    while (true) {
      StringPiece key;
      StringPiece value;
      if (!ReadStringPair(&iter, &key, &value))
        return key.empty();  // Non-empty is bad: got one of a pair.
      (*params)[key.as_string()] = value.as_string();
    }
  }
};

// Writes out string1 and then string2 to pickle.
bool WriteStringPair(Pickle* pickle,
                     const StringPiece& string1,
                     const StringPiece& string2) {
  if (!pickle->WriteString(string1))
    return false;
  if (!pickle->WriteString(string2))
    return false;
  return true;
}

// Writes out the field trial's contents (via trial_state) to the pickle. The
// format of the pickle looks like:
// TrialName, GroupName, ParamKey1, ParamValue1, ParamKey2, ParamValue2, ...
// If there are no parameters, then it just ends at GroupName.
bool PickleFieldTrial(const FieldTrial::State& trial_state, Pickle* pickle) {
  if (!WriteStringPair(pickle, trial_state.trial_name, trial_state.group_name))
    return false;

  // Get field trial params.
  std::map<std::string, std::string> params;
  FieldTrialParamAssociator::GetInstance()->GetFieldTrialParamsWithoutFallback(
      trial_state.trial_name.as_string(), trial_state.group_name.as_string(),
      &params);

  // Write params to pickle.
  for (const auto& param : params) {
    if (!WriteStringPair(pickle, param.first, param.second))
      return false;
  }
  return true;
}

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
  Time out_time;
  if (!Time::FromLocalExploded(exploded, &out_time)) {
    // TODO(maksims): implement failure handling.
    // We might just return |out_time|, which is Time(0).
    NOTIMPLEMENTED();
  }

  return out_time;
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

    entries->push_back(std::move(entry));
  }
  return true;
}

void AddForceFieldTrialsFlag(CommandLine* cmd_line) {
  std::string field_trial_states;
  FieldTrialList::AllStatesToString(&field_trial_states);
  if (!field_trial_states.empty()) {
    cmd_line->AppendSwitchASCII(switches::kForceFieldTrials,
                                field_trial_states);
  }
}

#if defined(OS_WIN)
HANDLE CreateReadOnlyHandle(FieldTrialList::FieldTrialAllocator* allocator) {
  HANDLE src = allocator->shared_memory()->handle().GetHandle();
  ProcessHandle process = GetCurrentProcess();
  DWORD access = SECTION_MAP_READ | SECTION_QUERY;
  HANDLE dst;
  if (!::DuplicateHandle(process, src, process, &dst, access, true, 0))
    return kInvalidPlatformFile;
  return dst;
}
#endif

#if defined(POSIX_WITH_ZYGOTE)
int CreateReadOnlyHandle(FieldTrialList::FieldTrialAllocator* allocator) {
  SharedMemoryHandle new_handle;
  allocator->shared_memory()->ShareReadOnlyToProcess(GetCurrentProcessHandle(),
                                                     &new_handle);
  return SharedMemory::GetFdFromSharedMemoryHandle(new_handle);
}
#endif

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
      trial_registered_(false),
      ref_(FieldTrialList::FieldTrialAllocator::kReferenceNull) {
  DCHECK_GT(total_probability, 0);
  DCHECK(!trial_name_.empty());
  DCHECK(!default_group_name_.empty());
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
  FinalizeGroupChoiceImpl(false);
}

void FieldTrial::FinalizeGroupChoiceImpl(bool is_locked) {
  if (group_ != kNotFinalized)
    return;
  accumulated_group_probability_ = divisor_;
  // Here it's OK to use |kDefaultGroupNumber| since we can't be forced and not
  // finalized.
  DCHECK(!forced_);
  SetGroupChoice(default_group_name_, kDefaultGroupNumber);

  // Add the field trial to shared memory.
  if (kUseSharedMemoryForFieldTrials && trial_registered_)
    FieldTrialList::OnGroupFinalized(is_locked, this);
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

bool FieldTrial::GetStateWhileLocked(State* field_trial_state) {
  if (!enable_field_trial_)
    return false;
  FinalizeGroupChoiceImpl(true);
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
    std::unique_ptr<const FieldTrial::EntropyProvider> entropy_provider)
    : entropy_provider_(std::move(entropy_provider)),
      observer_list_(new ObserverListThreadSafe<FieldTrialList::Observer>(
          ObserverListBase<FieldTrialList::Observer>::NOTIFY_EXISTING_ONLY)) {
  DCHECK(!global_);
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
      trial_name, total_probability, default_group_name, year, month,
      day_of_month, randomization_type, 0, default_group_number, NULL);
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
    int* default_group_number,
    const FieldTrial::EntropyProvider* override_entropy_provider) {
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
    // If an override entropy provider is given, use it.
    const FieldTrial::EntropyProvider* entropy_provider =
        override_entropy_provider ? override_entropy_provider
                                  : GetEntropyProviderForOneTimeRandomization();
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
}

// static
void FieldTrialList::AllStatesToString(std::string* output) {
  if (!global_)
    return;
  AutoLock auto_lock(global_->lock_);

  for (const auto& registered : global_->registered_) {
    FieldTrial::State trial;
    if (!registered.second->GetStateWhileLocked(&trial))
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
void FieldTrialList::GetInitiallyActiveFieldTrials(
    const base::CommandLine& command_line,
    FieldTrial::ActiveGroups* active_groups) {
  DCHECK(global_->create_trials_from_command_line_called_);

  if (!global_->field_trial_allocator_) {
    GetActiveFieldTrialGroupsFromString(
        command_line.GetSwitchValueASCII(switches::kForceFieldTrials),
        active_groups);
    return;
  }

  FieldTrialAllocator* allocator = global_->field_trial_allocator_.get();
  FieldTrialAllocator::Iterator mem_iter(allocator);
  FieldTrial::FieldTrialRef ref;
  while ((ref = mem_iter.GetNextOfType(kFieldTrialType)) !=
         SharedPersistentMemoryAllocator::kReferenceNull) {
    const FieldTrialEntry* entry =
        allocator->GetAsObject<const FieldTrialEntry>(ref, kFieldTrialType);

    StringPiece trial_name;
    StringPiece group_name;
    if (entry->activated &&
        entry->GetTrialAndGroupName(&trial_name, &group_name)) {
      FieldTrial::ActiveGroup group;
      group.trial_name = trial_name.as_string();
      group.group_name = group_name.as_string();
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
void FieldTrialList::CreateTrialsFromCommandLine(
    const CommandLine& cmd_line,
    const char* field_trial_handle_switch,
    int fd_key) {
  global_->create_trials_from_command_line_called_ = true;

#if defined(OS_WIN)
  if (cmd_line.HasSwitch(field_trial_handle_switch)) {
    std::string handle_switch =
        cmd_line.GetSwitchValueASCII(field_trial_handle_switch);
    bool result = CreateTrialsFromHandleSwitch(handle_switch);
    DCHECK(result);
  }
#endif

#if defined(POSIX_WITH_ZYGOTE)
  // If we failed to create trials from the descriptor, fallback to the command
  // line. Otherwise we're good -- return.
  if (CreateTrialsFromDescriptor(fd_key))
    return;
#endif

  if (cmd_line.HasSwitch(switches::kForceFieldTrials)) {
    bool result = FieldTrialList::CreateTrialsFromString(
        cmd_line.GetSwitchValueASCII(switches::kForceFieldTrials),
        std::set<std::string>());
    DCHECK(result);
  }
}

#if defined(POSIX_WITH_ZYGOTE)
// static
bool FieldTrialList::CreateTrialsFromDescriptor(int fd_key) {
  if (!kUseSharedMemoryForFieldTrials)
    return false;

  if (fd_key == -1)
    return false;

  int fd = GlobalDescriptors::GetInstance()->MaybeGet(fd_key);
  if (fd == -1)
    return false;

  SharedMemoryHandle shm_handle(fd, true);
  bool result = FieldTrialList::CreateTrialsFromSharedMemoryHandle(shm_handle);
  DCHECK(result);
  return true;
}
#endif

#if defined(OS_WIN)
// static
void FieldTrialList::AppendFieldTrialHandleIfNeeded(
    HandlesToInheritVector* handles) {
  if (!global_)
    return;
  if (kUseSharedMemoryForFieldTrials) {
    InstantiateFieldTrialAllocatorIfNeeded();
    if (global_->readonly_allocator_handle_)
      handles->push_back(global_->readonly_allocator_handle_);
  }
}
#endif

#if defined(OS_POSIX) && !defined(OS_NACL)
// static
int FieldTrialList::GetFieldTrialHandle() {
  if (global_ && kUseSharedMemoryForFieldTrials) {
    InstantiateFieldTrialAllocatorIfNeeded();
    // We check for an invalid handle where this gets called.
    return global_->readonly_allocator_handle_;
  }
  return kInvalidPlatformFile;
}
#endif

// static
void FieldTrialList::CopyFieldTrialStateToFlags(
    const char* field_trial_handle_switch,
    CommandLine* cmd_line) {
  // TODO(lawrencewu): Ideally, having the global would be guaranteed. However,
  // content browser tests currently don't create a FieldTrialList because they
  // don't run ChromeBrowserMainParts code where it's done for Chrome.
  if (!global_)
    return;

#if defined(OS_WIN) || defined(POSIX_WITH_ZYGOTE)
  // Use shared memory to pass the state if the feature is enabled, otherwise
  // fallback to passing it via the command line as a string.
  if (kUseSharedMemoryForFieldTrials) {
    InstantiateFieldTrialAllocatorIfNeeded();
    // If the readonly handle didn't get duplicated properly, then fallback to
    // original behavior.
    if (global_->readonly_allocator_handle_ == kInvalidPlatformFile) {
      AddForceFieldTrialsFlag(cmd_line);
      return;
    }

    global_->field_trial_allocator_->UpdateTrackingHistograms();

#if defined(OS_WIN)
    // We need to pass a named anonymous handle to shared memory over the
    // command line on Windows, since the child doesn't know which of the
    // handles it inherited it should open. On POSIX, we don't need to do this
    // -- we dup the fd into a fixed fd kFieldTrialDescriptor, so we can just
    // look it up there.
    // PlatformFile is typedef'd to HANDLE which is typedef'd to void *. We
    // basically cast the handle into an int (uintptr_t, to be exact), stringify
    // the int, and pass it as a command-line flag. The child process will do
    // the reverse conversions to retrieve the handle. See
    // http://stackoverflow.com/a/153077
    auto uintptr_handle =
        reinterpret_cast<uintptr_t>(global_->readonly_allocator_handle_);
    std::string field_trial_handle = std::to_string(uintptr_handle);
    cmd_line->AppendSwitchASCII(field_trial_handle_switch, field_trial_handle);
#endif
    return;
  }
#endif

  AddForceFieldTrialsFlag(cmd_line);
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
void FieldTrialList::OnGroupFinalized(bool is_locked, FieldTrial* field_trial) {
  if (!global_)
    return;
  if (is_locked) {
    AddToAllocatorWhileLocked(field_trial);
  } else {
    AutoLock auto_lock(global_->lock_);
    AddToAllocatorWhileLocked(field_trial);
  }
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

    if (!field_trial->enable_field_trial_)
      return;

    if (kUseSharedMemoryForFieldTrials)
      ActivateFieldTrialEntryWhileLocked(field_trial);
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
bool FieldTrialList::GetParamsFromSharedMemory(
    FieldTrial* field_trial,
    std::map<std::string, std::string>* params) {
  DCHECK(global_);
  // If the field trial allocator is not set up yet, then there are several
  // cases:
  //   - We are in the browser process and the allocator has not been set up
  //   yet. If we got here, then we couldn't find the params in
  //   FieldTrialParamAssociator, so it's definitely not here. Return false.
  //   - Using shared memory for field trials is not enabled. If we got here,
  //   then there's nothing in shared memory. Return false.
  //   - We are in the child process and the allocator has not been set up yet.
  //   If this is the case, then you are calling this too early. The field trial
  //   allocator should get set up very early in the lifecycle. Try to see if
  //   you can call it after it's been set up.
  AutoLock auto_lock(global_->lock_);
  if (!global_->field_trial_allocator_)
    return false;

  // If ref_ isn't set, then the field trial data can't be in shared memory.
  if (!field_trial->ref_)
    return false;

  const FieldTrialEntry* entry =
      global_->field_trial_allocator_->GetAsObject<const FieldTrialEntry>(
          field_trial->ref_, kFieldTrialType);

  size_t allocated_size =
      global_->field_trial_allocator_->GetAllocSize(field_trial->ref_);
  size_t actual_size = sizeof(FieldTrialEntry) + entry->size;
  if (allocated_size < actual_size)
    return false;

  return entry->GetParams(params);
}

// static
void FieldTrialList::ClearParamsFromSharedMemoryForTesting() {
  if (!global_)
    return;

  AutoLock auto_lock(global_->lock_);
  if (!global_->field_trial_allocator_)
    return;

  // To clear the params, we iterate through every item in the allocator, copy
  // just the trial and group name into a newly-allocated segment and then clear
  // the existing item.
  FieldTrialAllocator* allocator = global_->field_trial_allocator_.get();
  FieldTrialAllocator::Iterator mem_iter(allocator);

  // List of refs to eventually be made iterable. We can't make it in the loop,
  // since it would go on forever.
  std::vector<FieldTrial::FieldTrialRef> new_refs;

  FieldTrial::FieldTrialRef prev_ref;
  while ((prev_ref = mem_iter.GetNextOfType(kFieldTrialType)) !=
         FieldTrialAllocator::kReferenceNull) {
    // Get the existing field trial entry in shared memory.
    const FieldTrialEntry* prev_entry =
        allocator->GetAsObject<const FieldTrialEntry>(prev_ref,
                                                      kFieldTrialType);
    StringPiece trial_name;
    StringPiece group_name;
    if (!prev_entry->GetTrialAndGroupName(&trial_name, &group_name))
      continue;

    // Write a new entry, minus the params.
    Pickle pickle;
    pickle.WriteString(trial_name);
    pickle.WriteString(group_name);
    size_t total_size = sizeof(FieldTrialEntry) + pickle.size();
    FieldTrial::FieldTrialRef new_ref =
        allocator->Allocate(total_size, kFieldTrialType);
    FieldTrialEntry* new_entry =
        allocator->GetAsObject<FieldTrialEntry>(new_ref, kFieldTrialType);
    new_entry->activated = prev_entry->activated;
    new_entry->size = pickle.size();

    // TODO(lawrencewu): Modify base::Pickle to be able to write over a section
    // in memory, so we can avoid this memcpy.
    char* dst = reinterpret_cast<char*>(new_entry) + sizeof(FieldTrialEntry);
    memcpy(dst, pickle.data(), pickle.size());

    // Update the ref on the field trial and add it to the list to be made
    // iterable.
    FieldTrial* trial = global_->PreLockedFind(trial_name.as_string());
    trial->ref_ = new_ref;
    new_refs.push_back(new_ref);

    // Mark the existing entry as unused.
    allocator->ChangeType(prev_ref, 0, kFieldTrialType);
  }

  for (const auto& ref : new_refs) {
    allocator->MakeIterable(ref);
  }
}

#if defined(OS_WIN)
// static
bool FieldTrialList::CreateTrialsFromHandleSwitch(
    const std::string& handle_switch) {
  int field_trial_handle = std::stoi(handle_switch);
  HANDLE handle = reinterpret_cast<HANDLE>(field_trial_handle);
  SharedMemoryHandle shm_handle(handle, GetCurrentProcId());
  return FieldTrialList::CreateTrialsFromSharedMemoryHandle(shm_handle);
}
#endif

#if !defined(OS_NACL)
// static
bool FieldTrialList::CreateTrialsFromSharedMemoryHandle(
    SharedMemoryHandle shm_handle) {
  // shm gets deleted when it gets out of scope, but that's OK because we need
  // it only for the duration of this method.
  std::unique_ptr<SharedMemory> shm(new SharedMemory(shm_handle, true));
  if (!shm.get()->Map(kFieldTrialAllocationSize))
    TerminateBecauseOutOfMemory(kFieldTrialAllocationSize);

  return FieldTrialList::CreateTrialsFromSharedMemory(std::move(shm));
}
#endif

// static
bool FieldTrialList::CreateTrialsFromSharedMemory(
    std::unique_ptr<SharedMemory> shm) {
  global_->field_trial_allocator_.reset(
      new FieldTrialAllocator(std::move(shm), 0, kAllocatorName, true));
  FieldTrialAllocator* shalloc = global_->field_trial_allocator_.get();
  FieldTrialAllocator::Iterator mem_iter(shalloc);

  FieldTrial::FieldTrialRef ref;
  while ((ref = mem_iter.GetNextOfType(kFieldTrialType)) !=
         FieldTrialAllocator::kReferenceNull) {
    const FieldTrialEntry* entry =
        shalloc->GetAsObject<const FieldTrialEntry>(ref, kFieldTrialType);

    StringPiece trial_name;
    StringPiece group_name;
    if (!entry->GetTrialAndGroupName(&trial_name, &group_name))
      return false;

    // TODO(lawrencewu): Convert the API for CreateFieldTrial to take
    // StringPieces.
    FieldTrial* trial =
        CreateFieldTrial(trial_name.as_string(), group_name.as_string());

    trial->ref_ = ref;
    if (entry->activated) {
      // Call |group()| to mark the trial as "used" and notify observers, if
      // any. This is useful to ensure that field trials created in child
      // processes are properly reported in crash reports.
      trial->group();
    }
  }
  return true;
}

#if !defined(OS_NACL)
// static
void FieldTrialList::InstantiateFieldTrialAllocatorIfNeeded() {
  if (!global_)
    return;
  AutoLock auto_lock(global_->lock_);
  // Create the allocator if not already created and add all existing trials.
  if (global_->field_trial_allocator_ != nullptr)
    return;

  SharedMemoryCreateOptions options;
  options.size = kFieldTrialAllocationSize;
  options.share_read_only = true;

  std::unique_ptr<SharedMemory> shm(new SharedMemory());
  if (!shm->Create(options))
    TerminateBecauseOutOfMemory(kFieldTrialAllocationSize);

  if (!shm->Map(kFieldTrialAllocationSize))
    TerminateBecauseOutOfMemory(kFieldTrialAllocationSize);

  global_->field_trial_allocator_.reset(
      new FieldTrialAllocator(std::move(shm), 0, kAllocatorName, false));
  global_->field_trial_allocator_->CreateTrackingHistograms(kAllocatorName);

  // Add all existing field trials.
  for (const auto& registered : global_->registered_) {
    AddToAllocatorWhileLocked(registered.second);
  }

#if defined(OS_WIN) || defined(POSIX_WITH_ZYGOTE)
  // Set |readonly_allocator_handle_| so we can pass it to be inherited and
  // via the command line.
  global_->readonly_allocator_handle_ =
      CreateReadOnlyHandle(global_->field_trial_allocator_.get());
#endif
}
#endif

// static
void FieldTrialList::AddToAllocatorWhileLocked(FieldTrial* field_trial) {
  FieldTrialAllocator* allocator = global_->field_trial_allocator_.get();

  // Don't do anything if the allocator hasn't been instantiated yet.
  if (allocator == nullptr)
    return;

  // Or if the allocator is read only, which means we are in a child process and
  // shouldn't be writing to it.
  if (allocator->IsReadonly())
    return;

  FieldTrial::State trial_state;
  if (!field_trial->GetStateWhileLocked(&trial_state))
    return;

  // Or if we've already added it. We must check after GetState since it can
  // also add to the allocator.
  if (field_trial->ref_)
    return;

  Pickle pickle;
  if (!PickleFieldTrial(trial_state, &pickle)) {
    NOTREACHED();
    return;
  }

  size_t total_size = sizeof(FieldTrialEntry) + pickle.size();
  FieldTrial::FieldTrialRef ref =
      allocator->Allocate(total_size, kFieldTrialType);
  if (ref == FieldTrialAllocator::kReferenceNull) {
    NOTREACHED();
    return;
  }

  FieldTrialEntry* entry =
      allocator->GetAsObject<FieldTrialEntry>(ref, kFieldTrialType);
  entry->activated = trial_state.activated;
  entry->size = pickle.size();

  // TODO(lawrencewu): Modify base::Pickle to be able to write over a section in
  // memory, so we can avoid this memcpy.
  char* dst = reinterpret_cast<char*>(entry) + sizeof(FieldTrialEntry);
  memcpy(dst, pickle.data(), pickle.size());

  allocator->MakeIterable(ref);
  field_trial->ref_ = ref;
}

// static
void FieldTrialList::ActivateFieldTrialEntryWhileLocked(
    FieldTrial* field_trial) {
  FieldTrialAllocator* allocator = global_->field_trial_allocator_.get();

  // Check if we're in the child process and return early if so.
  if (allocator && allocator->IsReadonly())
    return;

  FieldTrial::FieldTrialRef ref = field_trial->ref_;
  if (ref == FieldTrialAllocator::kReferenceNull) {
    // It's fine to do this even if the allocator hasn't been instantiated
    // yet -- it'll just return early.
    AddToAllocatorWhileLocked(field_trial);
  } else {
    // It's also okay to do this even though the callee doesn't have a lock --
    // the only thing that happens on a stale read here is a slight performance
    // hit from the child re-synchronizing activation state.
    FieldTrialEntry* entry =
        allocator->GetAsObject<FieldTrialEntry>(ref, kFieldTrialType);
    entry->activated = true;
  }
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
