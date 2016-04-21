// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/sdch_manager.h"

#include <limits.h>

#include <utility>

#include "base/base64url.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/time/default_clock.h"
#include "base/values.h"
#include "crypto/sha2.h"
#include "net/base/parse_number.h"
#include "net/base/sdch_observer.h"
#include "net/url_request/url_request_http_job.h"

namespace {

void StripTrailingDot(GURL* gurl) {
  std::string host(gurl->host());

  if (host.empty())
    return;

  if (*host.rbegin() != '.')
    return;

  host.resize(host.size() - 1);

  GURL::Replacements replacements;
  replacements.SetHostStr(host);
  *gurl = gurl->ReplaceComponents(replacements);
  return;
}

}  // namespace

namespace net {

SdchManager::DictionarySet::DictionarySet() {}

SdchManager::DictionarySet::~DictionarySet() {}

std::string SdchManager::DictionarySet::GetDictionaryClientHashList() const {
  std::string result;
  bool first = true;
  for (const auto& entry: dictionaries_) {
    if (!first)
      result.append(",");

    result.append(entry.second->data.client_hash());
    first = false;
  }
  return result;
}

bool SdchManager::DictionarySet::Empty() const {
  return dictionaries_.empty();
}

const std::string* SdchManager::DictionarySet::GetDictionaryText(
    const std::string& server_hash) const {
  auto it = dictionaries_.find(server_hash);
  if (it == dictionaries_.end())
    return nullptr;
  return &it->second->data.text();
}

void SdchManager::DictionarySet::AddDictionary(
    const std::string& server_hash,
    const scoped_refptr<base::RefCountedData<SdchDictionary>>& dictionary) {
  DCHECK(dictionaries_.end() == dictionaries_.find(server_hash));

  dictionaries_[server_hash] = dictionary;
}

SdchManager::SdchManager() {
  DCHECK(thread_checker_.CalledOnValidThread());
}

SdchManager::~SdchManager() {
  DCHECK(thread_checker_.CalledOnValidThread());
  while (!dictionaries_.empty()) {
    auto it = dictionaries_.begin();
    dictionaries_.erase(it->first);
  }
}

void SdchManager::ClearData() {
  blacklisted_domains_.clear();
  allow_latency_experiment_.clear();
  dictionaries_.clear();
  FOR_EACH_OBSERVER(SdchObserver, observers_, OnClearDictionaries());
}

// static
void SdchManager::SdchErrorRecovery(SdchProblemCode problem) {
  UMA_HISTOGRAM_ENUMERATION("Sdch3.ProblemCodes_5", problem,
                            SDCH_MAX_PROBLEM_CODE);
}

void SdchManager::BlacklistDomain(const GURL& url,
                                  SdchProblemCode blacklist_reason) {
  SetAllowLatencyExperiment(url, false);

  BlacklistInfo* blacklist_info = &blacklisted_domains_[url.host()];

  if (blacklist_info->count > 0)
    return;  // Domain is already blacklisted.

  if (blacklist_info->exponential_count > (INT_MAX - 1) / 2) {
    blacklist_info->exponential_count = INT_MAX;
  } else {
    blacklist_info->exponential_count =
        blacklist_info->exponential_count * 2 + 1;
  }

  blacklist_info->count = blacklist_info->exponential_count;
  blacklist_info->reason = blacklist_reason;
}

void SdchManager::BlacklistDomainForever(const GURL& url,
                                         SdchProblemCode blacklist_reason) {
  SetAllowLatencyExperiment(url, false);

  BlacklistInfo* blacklist_info = &blacklisted_domains_[url.host()];
  blacklist_info->count = INT_MAX;
  blacklist_info->exponential_count = INT_MAX;
  blacklist_info->reason = blacklist_reason;
}

void SdchManager::ClearBlacklistings() {
  blacklisted_domains_.clear();
}

void SdchManager::ClearDomainBlacklisting(const std::string& domain) {
  BlacklistInfo* blacklist_info =
      &blacklisted_domains_[base::ToLowerASCII(domain)];
  blacklist_info->count = 0;
  blacklist_info->reason = SDCH_OK;
}

int SdchManager::BlackListDomainCount(const std::string& domain) {
  std::string domain_lower(base::ToLowerASCII(domain));

  if (blacklisted_domains_.end() == blacklisted_domains_.find(domain_lower))
    return 0;
  return blacklisted_domains_[domain_lower].count;
}

int SdchManager::BlacklistDomainExponential(const std::string& domain) {
  std::string domain_lower(base::ToLowerASCII(domain));

  if (blacklisted_domains_.end() == blacklisted_domains_.find(domain_lower))
    return 0;
  return blacklisted_domains_[domain_lower].exponential_count;
}

SdchProblemCode SdchManager::IsInSupportedDomain(const GURL& url) {
  DCHECK(thread_checker_.CalledOnValidThread());
  if (blacklisted_domains_.empty())
    return SDCH_OK;

  auto it = blacklisted_domains_.find(url.host());
  if (blacklisted_domains_.end() == it || it->second.count == 0)
    return SDCH_OK;

  UMA_HISTOGRAM_ENUMERATION("Sdch3.BlacklistReason", it->second.reason,
                            SDCH_MAX_PROBLEM_CODE);

  int count = it->second.count - 1;
  if (count > 0) {
    it->second.count = count;
  } else {
    it->second.count = 0;
    it->second.reason = SDCH_OK;
  }

  return SDCH_DOMAIN_BLACKLIST_INCLUDES_TARGET;
}

SdchProblemCode SdchManager::OnGetDictionary(const GURL& request_url,
                                             const GURL& dictionary_url) {
  DCHECK(thread_checker_.CalledOnValidThread());
  SdchProblemCode rv = CanFetchDictionary(request_url, dictionary_url);
  if (rv != SDCH_OK)
    return rv;

  FOR_EACH_OBSERVER(SdchObserver,
                    observers_,
                    OnGetDictionary(request_url, dictionary_url));

  return SDCH_OK;
}

void SdchManager::OnDictionaryUsed(const std::string& server_hash) {
  FOR_EACH_OBSERVER(SdchObserver, observers_,
                    OnDictionaryUsed(server_hash));
}

SdchProblemCode SdchManager::CanFetchDictionary(
    const GURL& referring_url,
    const GURL& dictionary_url) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  /* The user agent may retrieve a dictionary from the dictionary URL if all of
     the following are true:
       1 The dictionary URL host name matches the referrer URL host name and
           scheme.
       2 The dictionary URL host name domain matches the parent domain of the
           referrer URL host name
       3 The parent domain of the referrer URL host name is not a top level
           domain
   */
  // Item (1) above implies item (2). Spec should be updated.
  // I take "host name match" to be "is identical to"
  if (referring_url.host_piece() != dictionary_url.host_piece() ||
      referring_url.scheme_piece() != dictionary_url.scheme_piece())
    return SDCH_DICTIONARY_LOAD_ATTEMPT_FROM_DIFFERENT_HOST;

  // TODO(jar): Remove this failsafe conservative hack which is more restrictive
  // than current SDCH spec when needed, and justified by security audit.
  if (!referring_url.SchemeIsHTTPOrHTTPS())
    return SDCH_DICTIONARY_SELECTED_FROM_NON_HTTP;

  return SDCH_OK;
}

std::unique_ptr<SdchManager::DictionarySet> SdchManager::GetDictionarySet(
    const GURL& target_url) {
  if (IsInSupportedDomain(target_url) != SDCH_OK)
    return NULL;

  int count = 0;
  std::unique_ptr<SdchManager::DictionarySet> result(new DictionarySet);
  for (const auto& entry: dictionaries_) {
    if (entry.second->data.CanUse(target_url) != SDCH_OK)
      continue;
    if (entry.second->data.Expired())
      continue;
    ++count;
    result->AddDictionary(entry.first, entry.second);
  }

  if (count == 0)
    return NULL;

  UMA_HISTOGRAM_COUNTS("Sdch3.Advertisement_Count", count);

  return result;
}

std::unique_ptr<SdchManager::DictionarySet> SdchManager::GetDictionarySetByHash(
    const GURL& target_url,
    const std::string& server_hash,
    SdchProblemCode* problem_code) {
  std::unique_ptr<SdchManager::DictionarySet> result;

  *problem_code = SDCH_DICTIONARY_HASH_NOT_FOUND;
  const auto& it = dictionaries_.find(server_hash);
  if (it == dictionaries_.end())
    return result;

  *problem_code = it->second->data.CanUse(target_url);
  if (*problem_code != SDCH_OK)
    return result;

  result.reset(new DictionarySet);
  result->AddDictionary(it->first, it->second);
  return result;
}

// static
void SdchManager::GenerateHash(const std::string& dictionary_text,
    std::string* client_hash, std::string* server_hash) {
  char binary_hash[32];
  crypto::SHA256HashString(dictionary_text, binary_hash, sizeof(binary_hash));

  base::StringPiece first_48_bits(&binary_hash[0], 6);
  base::StringPiece second_48_bits(&binary_hash[6], 6);

  base::Base64UrlEncode(
      first_48_bits, base::Base64UrlEncodePolicy::INCLUDE_PADDING, client_hash);
  base::Base64UrlEncode(second_48_bits,
                        base::Base64UrlEncodePolicy::INCLUDE_PADDING,
                        server_hash);

  DCHECK_EQ(server_hash->length(), 8u);
  DCHECK_EQ(client_hash->length(), 8u);
}

// Methods for supporting latency experiments.

bool SdchManager::AllowLatencyExperiment(const GURL& url) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return allow_latency_experiment_.end() !=
      allow_latency_experiment_.find(url.host());
}

void SdchManager::SetAllowLatencyExperiment(const GURL& url, bool enable) {
  DCHECK(thread_checker_.CalledOnValidThread());
  if (enable) {
    allow_latency_experiment_.insert(url.host());
    return;
  }
  ExperimentSet::iterator it = allow_latency_experiment_.find(url.host());
  if (allow_latency_experiment_.end() == it)
    return;  // It was already erased, or never allowed.
  SdchErrorRecovery(SDCH_LATENCY_TEST_DISALLOWED);
  allow_latency_experiment_.erase(it);
}

void SdchManager::AddObserver(SdchObserver* observer) {
  observers_.AddObserver(observer);
}

void SdchManager::RemoveObserver(SdchObserver* observer) {
  observers_.RemoveObserver(observer);
}

SdchProblemCode SdchManager::AddSdchDictionary(
    const std::string& dictionary_text,
    const GURL& dictionary_url,
    std::string* server_hash_p) {
  DCHECK(thread_checker_.CalledOnValidThread());
  std::string client_hash;
  std::string server_hash;
  GenerateHash(dictionary_text, &client_hash, &server_hash);
  if (dictionaries_.find(server_hash) != dictionaries_.end())
    return SDCH_DICTIONARY_ALREADY_LOADED;  // Already loaded.

  std::string domain, path;
  std::set<int> ports;
  base::Time expiration(base::Time::Now() + base::TimeDelta::FromDays(30));

  if (dictionary_text.empty())
    return SDCH_DICTIONARY_HAS_NO_TEXT;  // Missing header.

  size_t header_end = dictionary_text.find("\n\n");
  if (std::string::npos == header_end)
    return SDCH_DICTIONARY_HAS_NO_HEADER;  // Missing header.

  size_t line_start = 0;  // Start of line being parsed.
  while (1) {
    size_t line_end = dictionary_text.find('\n', line_start);
    DCHECK(std::string::npos != line_end);
    DCHECK_LE(line_end, header_end);

    size_t colon_index = dictionary_text.find(':', line_start);
    if (std::string::npos == colon_index)
      return SDCH_DICTIONARY_HEADER_LINE_MISSING_COLON;  // Illegal line missing
                                                         // a colon.

    if (colon_index > line_end)
      break;

    size_t value_start = dictionary_text.find_first_not_of(" \t",
                                                           colon_index + 1);
    if (std::string::npos != value_start) {
      if (value_start >= line_end)
        break;
      std::string name(dictionary_text, line_start, colon_index - line_start);
      std::string value(dictionary_text, value_start, line_end - value_start);
      name = base::ToLowerASCII(name);
      if (name == "domain") {
        domain = value;
      } else if (name == "path") {
        path = value;
      } else if (name == "format-version") {
        if (value != "1.0")
          return SDCH_DICTIONARY_UNSUPPORTED_VERSION;
      } else if (name == "max-age") {
        // max-age must be a non-negative number. If it is very large saturate
        // to 2^32 - 1. If it is invalid then treat it as expired.
        // TODO(eroman): crbug.com/602691 be stricter on failure.
        uint32_t seconds = std::numeric_limits<uint32_t>::max();
        ParseIntError parse_int_error;
        if (ParseUint32(value, &seconds, &parse_int_error) ||
            parse_int_error == ParseIntError::FAILED_OVERFLOW) {
          expiration =
              base::Time::Now() + base::TimeDelta::FromSeconds(seconds);
        } else {
          expiration = base::Time();
        }
      } else if (name == "port") {
        // TODO(eroman): crbug.com/602691 be stricter on failure.
        int port;
        if (ParseInt32(value, ParseIntFormat::NON_NEGATIVE, &port))
          ports.insert(port);
      }
    }

    if (line_end >= header_end)
      break;
    line_start = line_end + 1;
  }

  // Narrow fix for http://crbug.com/389451.
  GURL dictionary_url_normalized(dictionary_url);
  StripTrailingDot(&dictionary_url_normalized);

  SdchProblemCode rv = IsInSupportedDomain(dictionary_url_normalized);
  if (rv != SDCH_OK)
    return rv;

  rv = SdchDictionary::CanSet(domain, path, ports, dictionary_url_normalized);
  if (rv != SDCH_OK)
    return rv;

  UMA_HISTOGRAM_COUNTS("Sdch3.Dictionary size loaded", dictionary_text.size());
  DVLOG(1) << "Loaded dictionary with client hash " << client_hash
           << " and server hash " << server_hash;
  SdchDictionary dictionary(dictionary_text, header_end + 2, client_hash,
                            server_hash, dictionary_url_normalized, domain,
                            path, expiration, ports);
  dictionaries_[server_hash] =
      new base::RefCountedData<SdchDictionary>(dictionary);
  if (server_hash_p)
    *server_hash_p = server_hash;

  FOR_EACH_OBSERVER(SdchObserver, observers_,
                    OnDictionaryAdded(dictionary_url, server_hash));

  return SDCH_OK;
}

SdchProblemCode SdchManager::RemoveSdchDictionary(
    const std::string& server_hash) {
  if (dictionaries_.find(server_hash) == dictionaries_.end())
    return SDCH_DICTIONARY_HASH_NOT_FOUND;

  dictionaries_.erase(server_hash);

  FOR_EACH_OBSERVER(SdchObserver, observers_, OnDictionaryRemoved(server_hash));

  return SDCH_OK;
}

// static
std::unique_ptr<SdchManager::DictionarySet>
SdchManager::CreateEmptyDictionarySetForTesting() {
  return std::unique_ptr<DictionarySet>(new DictionarySet);
}

std::unique_ptr<base::Value> SdchManager::SdchInfoToValue() const {
  std::unique_ptr<base::DictionaryValue> value(new base::DictionaryValue());

  value->SetBoolean("sdch_enabled", true);

  std::unique_ptr<base::ListValue> entry_list(new base::ListValue());
  for (const auto& entry: dictionaries_) {
    std::unique_ptr<base::DictionaryValue> entry_dict(
        new base::DictionaryValue());
    entry_dict->SetString("url", entry.second->data.url().spec());
    entry_dict->SetString("client_hash", entry.second->data.client_hash());
    entry_dict->SetString("domain", entry.second->data.domain());
    entry_dict->SetString("path", entry.second->data.path());
    std::unique_ptr<base::ListValue> port_list(new base::ListValue());
    for (std::set<int>::const_iterator port_it =
             entry.second->data.ports().begin();
         port_it != entry.second->data.ports().end(); ++port_it) {
      port_list->AppendInteger(*port_it);
    }
    entry_dict->Set("ports", std::move(port_list));
    entry_dict->SetString("server_hash", entry.first);
    entry_list->Append(std::move(entry_dict));
  }
  value->Set("dictionaries", std::move(entry_list));

  entry_list.reset(new base::ListValue());
  for (DomainBlacklistInfo::const_iterator it = blacklisted_domains_.begin();
       it != blacklisted_domains_.end(); ++it) {
    if (it->second.count == 0)
      continue;
    std::unique_ptr<base::DictionaryValue> entry_dict(
        new base::DictionaryValue());
    entry_dict->SetString("domain", it->first);
    if (it->second.count != INT_MAX)
      entry_dict->SetInteger("tries", it->second.count);
    entry_dict->SetInteger("reason", it->second.reason);
    entry_list->Append(std::move(entry_dict));
  }
  value->Set("blacklisted", std::move(entry_list));

  return std::move(value);
}

}  // namespace net
