// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/network_qualities_prefs_manager.h"

#include <utility>

#include "base/bind.h"
#include "base/sequenced_task_runner.h"
#include "base/threading/thread_checker.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/values.h"
#include "net/nqe/cached_network_quality.h"
#include "net/nqe/network_quality_estimator.h"

namespace net {

NetworkQualitiesPrefsManager::NetworkQualitiesPrefsManager(
    std::unique_ptr<PrefDelegate> pref_delegate)
    : pref_delegate_(std::move(pref_delegate)),
      pref_task_runner_(base::ThreadTaskRunnerHandle::Get()),
      network_quality_estimator_(nullptr),
      pref_weak_ptr_factory_(this) {
  DCHECK(pref_delegate_);

  pref_weak_ptr_ = pref_weak_ptr_factory_.GetWeakPtr();
}

NetworkQualitiesPrefsManager::~NetworkQualitiesPrefsManager() {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  if (network_quality_estimator_)
    network_quality_estimator_->RemoveNetworkQualitiesCacheObserver(this);
}

void NetworkQualitiesPrefsManager::InitializeOnNetworkThread(
    NetworkQualityEstimator* network_quality_estimator) {
  DCHECK(!network_task_runner_);
  DCHECK(network_quality_estimator);

  network_task_runner_ = base::ThreadTaskRunnerHandle::Get();
  network_quality_estimator_ = network_quality_estimator;
  network_quality_estimator_->AddNetworkQualitiesCacheObserver(this);
}

void NetworkQualitiesPrefsManager::OnChangeInCachedNetworkQuality(
    const nqe::internal::NetworkID& network_id,
    const nqe::internal::CachedNetworkQuality& cached_network_quality) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());

  // Notify |this| on the pref thread.
  pref_task_runner_->PostTask(
      FROM_HERE,
      base::Bind(&NetworkQualitiesPrefsManager::
                     OnChangeInCachedNetworkQualityOnPrefThread,
                 pref_weak_ptr_, network_id, cached_network_quality));
}

void NetworkQualitiesPrefsManager::ShutdownOnPrefThread() {
  DCHECK(pref_task_runner_->RunsTasksOnCurrentThread());
  pref_delegate_.reset();
}

void NetworkQualitiesPrefsManager::OnChangeInCachedNetworkQualityOnPrefThread(
    const nqe::internal::NetworkID& network_id,
    const nqe::internal::CachedNetworkQuality& cached_network_quality) {
  // The prefs can only be written on the pref thread.
  DCHECK(pref_task_runner_->RunsTasksOnCurrentThread());

  base::DictionaryValue dictionary_value;
  dictionary_value.SetString(
      network_id.ToString(),
      GetNameForEffectiveConnectionType(
          cached_network_quality.effective_connection_type()));

  // Notify the pref delegate so that it updates the prefs on the disk.
  pref_delegate_->SetDictionaryValue(dictionary_value);
}

}  // namespace net
