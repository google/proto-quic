// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_FILTER_MOCK_FILTER_CONTEXT_H_
#define NET_FILTER_MOCK_FILTER_CONTEXT_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>

#include "base/macros.h"
#include "net/base/sdch_manager.h"
#include "net/filter/filter.h"
#include "net/log/net_log.h"
#include "url/gurl.h"

namespace net {

class URLRequestContext;

class MockFilterContext : public FilterContext {
 public:
  MockFilterContext();
  ~MockFilterContext() override;

  void SetMimeType(const std::string& mime_type) { mime_type_ = mime_type; }
  void SetURL(const GURL& gurl) { gurl_ = gurl; }
  void SetRequestTime(const base::Time time) { request_time_ = time; }
  void SetCached(bool is_cached) { is_cached_content_ = is_cached; }
  void SetResponseCode(int response_code) { response_code_ = response_code; }
  void SetSdchResponse(std::unique_ptr<SdchManager::DictionarySet> handle) {
    dictionaries_handle_ = std::move(handle);
  }
  URLRequestContext* GetModifiableURLRequestContext() const {
    return context_.get();
  }

  // After a URLRequest's destructor is called, some interfaces may become
  // unstable. This method is used to signal that state, so we can tag use
  // of those interfaces as coding errors.
  void NukeUnstableInterfaces();

  bool GetMimeType(std::string* mime_type) const override;

  // What URL was used to access this data?
  // Return false if gurl is not present.
  bool GetURL(GURL* gurl) const override;

  // What was this data requested from a server?
  base::Time GetRequestTime() const override;

  // Is data supplied from cache, or fresh across the net?
  bool IsCachedContent() const override;

  // Handle to dictionaries advertised.
  SdchManager::DictionarySet* SdchDictionariesAdvertised() const override;

  // How many bytes were fed to filter(s) so far?
  int64_t GetByteReadCount() const override;

  int GetResponseCode() const override;

  // The URLRequestContext associated with the request.
  const URLRequestContext* GetURLRequestContext() const override;

  void RecordPacketStats(StatisticSelector statistic) const override {}

  const BoundNetLog& GetNetLog() const override;

 private:
  std::string mime_type_;
  GURL gurl_;
  base::Time request_time_;
  bool is_cached_content_;
  std::unique_ptr<SdchManager::DictionarySet> dictionaries_handle_;
  bool ok_to_call_get_url_;
  int response_code_;
  std::unique_ptr<URLRequestContext> context_;
  BoundNetLog net_log_;

  DISALLOW_COPY_AND_ASSIGN(MockFilterContext);
};

}  // namespace net

#endif  // NET_FILTER_MOCK_FILTER_CONTEXT_H_
