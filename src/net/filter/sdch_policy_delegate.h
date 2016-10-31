// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_FILTER_SDCH_POLICY_DELEGATE_H_
#define NET_FILTER_SDCH_POLICY_DELEGATE_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/supports_user_data.h"
#include "net/base/net_export.h"
#include "net/base/sdch_manager.h"
#include "net/filter/sdch_source_stream.h"
#include "net/log/net_log.h"
#include "net/log/net_log_with_source.h"
#include "url/gurl.h"

namespace net {

class URLRequestHttpJob;
class SdchSourceStream;

// This class implements the SdchSourceStream::Delegate interface to perform
// the SDCH error handling and stats gathering. The Context object supplies
// details about the request needed for this object to make error-handling
// decisions. See the SdchSourceStream::Delegate documentation for more details.
class NET_EXPORT_PRIVATE SdchPolicyDelegate
    : public SdchSourceStream::Delegate {
 public:
  enum StatisticSelector {
    SDCH_DECODE,
    SDCH_PASSTHROUGH,
    SDCH_EXPERIMENT_DECODE,
    SDCH_EXPERIMENT_HOLDBACK,
  };

  SdchPolicyDelegate(bool possible_pass_through,
                     URLRequestHttpJob* job,
                     std::string mime_type,
                     const GURL& url,
                     bool is_cached_content,
                     SdchManager* sdch_manager,
                     std::unique_ptr<SdchManager::DictionarySet> dictionary_set,
                     int response_code,
                     const NetLogWithSource& net_log);

  ~SdchPolicyDelegate() override;

  // Sdch specific hacks to fix up encoding types.
  static void FixUpSdchContentEncodings(
      const NetLogWithSource& net_log,
      const std::string& mime_type,
      SdchManager::DictionarySet* dictionary_set,
      std::vector<SourceStream::SourceType>* types);

  // SdchSourceStream::Delegate implementation.
  ErrorRecovery OnDictionaryIdError(std::string* replace_output) override;
  ErrorRecovery OnGetDictionaryError(std::string* replace_output) override;
  ErrorRecovery OnDecodingError(std::string* replace_output) override;
  bool OnGetDictionary(const std::string& server_id,
                       const std::string** text) override;

  void OnStreamDestroyed(SdchSourceStream::InputState input_state,
                         bool buffered_output_present,
                         bool decoding_not_finished) override;

 private:
  // Issues a meta-refresh if the context's MIME type supports it, and returns
  // whether a ErrorRecovery which should either be NONE (meta-refresh not
  // issued) or REPLACE_OUTPUT (meta-refresh issued). For response not coming
  // from the cache, the domain will be blacklisted as a side effect temporarily
  // (for HTML payloads) or permanently (for non-HTML payloads).
  ErrorRecovery IssueMetaRefreshIfPossible(std::string* replace_output);

  // Set when the SdchSourceStream is used as a possible pass-through.
  const bool possible_pass_through_;

  // Fields from URLRequestHttpJob.
  const URLRequestHttpJob* job_;
  const std::string mime_type_;
  const GURL url_;
  const bool is_cached_content_;
  SdchManager* sdch_manager_;
  std::unique_ptr<SdchManager::DictionarySet> dictionary_set_;
  const int response_code_;
  const NetLogWithSource net_log_;

  std::string server_id_;

  // If the response was encoded with a dictionary different than those
  // advertised (e.g. a cached response using an old dictionary), this
  // variable preserves that dictionary from deletion during decoding.
  std::unique_ptr<SdchManager::DictionarySet> unexpected_dictionary_set_;

  DISALLOW_COPY_AND_ASSIGN(SdchPolicyDelegate);
};

}  // namespace net

#endif  // NET_FILTER_SDCH_POLICY_DELEGATE_H_
