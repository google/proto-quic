// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_URL_REQUEST_URL_REQUEST_BACKOFF_MANAGER_H_
#define NET_URL_REQUEST_URL_REQUEST_BACKOFF_MANAGER_H_

#include <stdint.h>

#include <map>
#include <string>

#include "base/macros.h"
#include "base/threading/non_thread_safe.h"
#include "base/time/time.h"
#include "net/base/net_export.h"
#include "net/base/network_change_notifier.h"
#include "url/gurl.h"

namespace net {

class HttpResponseHeaders;

// Class that manages information on Backoff headers. URL requests for HTTPS
// contents should update their URLs in this manager on each response.
//
// Design doc:
// https://docs.google.com/document/d/1aAxwXK7Vw3VigFd6MmrItbAIgMdKAf-XxXXbhWXdID0/edit?usp=sharing
//
// URLRequestBackoffManager maintains a map of URL IDs to
// URLRequestBackoffManager::Entry. It creates an entry when a request receives
// a Backoff header, and does garbage collection from time to time in order to
// clean out outdated entries. URL ID consists of lowercased scheme, host, port
// and path. A newer request with the same ID will override the old entry.
//
// Note that the class does not implement logic to retry a request at random
// with uniform distribution.
// TODO(xunjieli): Expose release time so that the caller can retry accordingly.
class NET_EXPORT URLRequestBackoffManager
    : NON_EXPORTED_BASE(public base::NonThreadSafe),
      public NetworkChangeNotifier::IPAddressObserver,
      public NetworkChangeNotifier::ConnectionTypeObserver {
 public:
  // Minimum number of seconds that a Backoff header can specify.
  static const uint16_t kMinimumBackoffInSeconds;
  // Maximum number of seconds that a Backoff header can specify.
  static const uint16_t kMaximumBackoffInSeconds;
  // Number of throttled requests that will be made between garbage collection.
  static const uint16_t kNewEntriesBetweenCollecting;

  URLRequestBackoffManager();
  ~URLRequestBackoffManager() override;

  // Updates internal states with a response.
  void UpdateWithResponse(const GURL& url,
                          HttpResponseHeaders* headers,
                          const base::Time& response_time);

  // Returns whether the request should be rejected because of a Backoff header.
  bool ShouldRejectRequest(const GURL& url, const base::Time& request_time);

  // IPAddressObserver implementation.
  void OnIPAddressChanged() override;

  // ConnectionTypeObserver implementation.
  void OnConnectionTypeChanged(
      NetworkChangeNotifier::ConnectionType type) override;

  // Used by tests.
  int GetNumberOfEntriesForTests() const;

 private:
  // An struct that holds relevant information obtained from a Backoff header.
  struct Entry {
    Entry(const base::Time& time1, const base::Time& time2)
        : throttled_time(time1), release_time(time2), used(false) {}
    ~Entry() {}

    // Returns whether this entry is outdated.
    bool IsOutDated() { return base::Time::Now() >= release_time; }

    // Before this time, requests with the same URL ID should be throttled.
    const base::Time throttled_time;

    // Only one request with the same URL ID should be allowed in
    // [|throttled_time|, |release_time|).
    // After this time, all requests with the same URL ID are allowed.
    const base::Time release_time;

    // Indicates whether a request has been made in
    // [|throttled_time|, |release_time|).
    bool used;
  };

  // From each URL, generate an ID composed of the scheme, host, port and path
  // that allows unique mapping an entry to it.
  typedef std::map<std::string, Entry*> UrlEntryMap;

  // Method that ensures the map gets cleaned from time to time. The period at
  // which garbage collecting happens is adjustable with the
  // kNewEntriesBetweenCollecting constant.
  void GarbageCollectEntriesIfNecessary();

  // Return true if there is a well-formed Backoff header key-value pair,
  // and write the Backoff header value in |result|. Return false if no header
  // is found or the value is invalid (i.e. less than kMinimumBackoffInSeconds
  // or greater than kMaximumBackoffInSeconds).
  bool GetBackoffTime(HttpResponseHeaders* headers,
                      base::TimeDelta* result) const;

  // Method that transforms a URL into an ID that can be used in the map.
  // Resulting IDs will be lowercase and consist of the scheme, host, port
  // and path (without query string, fragment, etc.).
  // If the URL is invalid, the invalid spec will be returned, without any
  // transformation.
  std::string GetIdFromUrl(const GURL& url) const;

  // When switching from online to offline or change IP addresses,
  // clear all back-off history. This is a precaution in case the change in
  // online state now allows communicating without errors with servers that
  // were previously returning Backoff headers.
  void OnNetworkChange();

  UrlEntryMap url_entries_;

  // Keeps track of how many new entries are created since last garbage
  // collection.
  unsigned int new_entries_since_last_gc_;

  // Valid after construction.
  GURL::Replacements url_id_replacements_;

  DISALLOW_COPY_AND_ASSIGN(URLRequestBackoffManager);
};

}  // namespace net

#endif  // NET_URL_REQUEST_URL_REQUEST_BACKOFF_MANAGER_H_
