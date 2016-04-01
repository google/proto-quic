// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_backoff_manager.h"

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "net/http/http_response_headers.h"

namespace net {

const uint16_t URLRequestBackoffManager::kMinimumBackoffInSeconds = 1;
const uint16_t URLRequestBackoffManager::kMaximumBackoffInSeconds = 50000;
const uint16_t URLRequestBackoffManager::kNewEntriesBetweenCollecting = 200;

URLRequestBackoffManager::URLRequestBackoffManager()
    : new_entries_since_last_gc_(0) {
  url_id_replacements_.ClearPassword();
  url_id_replacements_.ClearUsername();
  url_id_replacements_.ClearQuery();
  url_id_replacements_.ClearRef();

  NetworkChangeNotifier::AddIPAddressObserver(this);
  NetworkChangeNotifier::AddConnectionTypeObserver(this);
}

URLRequestBackoffManager::~URLRequestBackoffManager() {
  NetworkChangeNotifier::RemoveIPAddressObserver(this);
  NetworkChangeNotifier::RemoveConnectionTypeObserver(this);
  for (UrlEntryMap::iterator it = url_entries_.begin();
       it != url_entries_.end(); ++it) {
    delete it->second;
  }
  url_entries_.clear();
}

void URLRequestBackoffManager::UpdateWithResponse(
    const GURL& url,
    HttpResponseHeaders* headers,
    const base::Time& response_time) {
  CalledOnValidThread();
  base::TimeDelta result;
  if (GetBackoffTime(headers, &result)) {
    new_entries_since_last_gc_++;
    std::string url_id = GetIdFromUrl(url);
    auto it = url_entries_.find(url_id);
    if (it != url_entries_.end())
      delete it->second;
    url_entries_[url_id] =
        new Entry(response_time + result, response_time + result * 1.1);
    GarbageCollectEntriesIfNecessary();
  }
}

bool URLRequestBackoffManager::ShouldRejectRequest(
    const GURL& url,
    const base::Time& request_time) {
  CalledOnValidThread();
  std::string url_id = GetIdFromUrl(url);
  UrlEntryMap::iterator it = url_entries_.find(url_id);
  if (it == url_entries_.end())
    return false;
  Entry* entry = it->second;
  if (request_time < entry->throttled_time)
    return true;
  // Allow one request between throttled_time and release_time.
  if (request_time >= entry->throttled_time &&
      request_time < entry->release_time) {
    if (entry->used)
      return true;
    entry->used = true;
  }
  return false;
}

void URLRequestBackoffManager::OnIPAddressChanged() {
  OnNetworkChange();
}

void URLRequestBackoffManager::OnConnectionTypeChanged(
    NetworkChangeNotifier::ConnectionType type) {
  OnNetworkChange();
}

int URLRequestBackoffManager::GetNumberOfEntriesForTests() const {
  return url_entries_.size();
}

void URLRequestBackoffManager::GarbageCollectEntriesIfNecessary() {
  CalledOnValidThread();
  if (new_entries_since_last_gc_ < kNewEntriesBetweenCollecting)
    return;

  new_entries_since_last_gc_ = 0;
  UrlEntryMap::iterator it = url_entries_.begin();
  while (it != url_entries_.end()) {
    Entry* entry = it->second;
    if (entry->IsOutDated()) {
      url_entries_.erase(it++);
      delete entry;
    } else {
      ++it;
    }
  }
}

bool URLRequestBackoffManager::GetBackoffTime(HttpResponseHeaders* headers,
                                              base::TimeDelta* result) const {
  base::StringPiece name("Backoff");
  std::string value;
  size_t iter = 0;
  while (headers->EnumerateHeader(&iter, name, &value)) {
    int64_t seconds;
    base::StringToInt64(value, &seconds);
    if (seconds >= kMinimumBackoffInSeconds &&
        seconds <= kMaximumBackoffInSeconds) {
      *result = base::TimeDelta::FromSeconds(seconds);
      return true;
    }
  }
  return false;
}

std::string URLRequestBackoffManager::GetIdFromUrl(const GURL& url) const {
  if (!url.is_valid())
    return url.possibly_invalid_spec();

  GURL id = url.ReplaceComponents(url_id_replacements_);
  return base::ToLowerASCII(id.spec());
}

void URLRequestBackoffManager::OnNetworkChange() {
  CalledOnValidThread();

  new_entries_since_last_gc_ = 0;
  // Remove all entries.
  for (UrlEntryMap::iterator it = url_entries_.begin();
       it != url_entries_.end(); ++it) {
    delete it->second;
  }
  url_entries_.clear();
}

}  // namespace net
