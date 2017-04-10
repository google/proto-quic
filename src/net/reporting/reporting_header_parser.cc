// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_header_parser.h"

#include <string>

#include "base/json/json_reader.h"
#include "base/logging.h"
#include "base/time/tick_clock.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_context.h"

namespace net {

namespace {

const char kUrlKey[] = "url";
const char kIncludeSubdomainsKey[] = "includeSubdomains";
const char kGroupKey[] = "group";
const char kGroupDefaultValue[] = "default";
const char kMaxAgeKey[] = "max-age";

}  // namespace

// static
void ReportingHeaderParser::ParseHeader(ReportingContext* context,
                                        const GURL& url,
                                        const std::string& json_value) {
  DCHECK(url.SchemeIsCryptographic());

  std::unique_ptr<base::Value> value =
      base::JSONReader::Read("[" + json_value + "]");
  if (!value)
    return;

  const base::ListValue* list = nullptr;
  bool is_list = value->GetAsList(&list);
  DCHECK(is_list);

  ReportingCache* cache = context->cache();
  base::TimeTicks now = context->tick_clock()->NowTicks();
  for (size_t i = 0; i < list->GetSize(); i++) {
    const base::Value* endpoint = nullptr;
    bool got_endpoint = list->Get(i, &endpoint);
    DCHECK(got_endpoint);
    ProcessEndpoint(cache, now, url, *endpoint);
  }
}

// static
void ReportingHeaderParser::ProcessEndpoint(ReportingCache* cache,
                                            base::TimeTicks now,
                                            const GURL& url,
                                            const base::Value& value) {
  const base::DictionaryValue* dict = nullptr;
  if (!value.GetAsDictionary(&dict))
    return;
  DCHECK(dict);

  std::string endpoint_url_string;
  if (!dict->GetString(kUrlKey, &endpoint_url_string))
    return;

  GURL endpoint_url(endpoint_url_string);
  if (!endpoint_url.is_valid())
    return;
  if (!endpoint_url.SchemeIsCryptographic())
    return;

  int ttl_sec = -1;
  if (!dict->GetInteger(kMaxAgeKey, &ttl_sec) || ttl_sec < 0)
    return;

  std::string group = kGroupDefaultValue;
  if (dict->HasKey(kGroupKey) && !dict->GetString(kGroupKey, &group))
    return;

  ReportingClient::Subdomains subdomains = ReportingClient::Subdomains::EXCLUDE;
  bool subdomains_bool = false;
  if (dict->HasKey(kIncludeSubdomainsKey) &&
      dict->GetBoolean(kIncludeSubdomainsKey, &subdomains_bool) &&
      subdomains_bool == true) {
    subdomains = ReportingClient::Subdomains::INCLUDE;
  }

  if (ttl_sec > 0) {
    cache->SetClient(url::Origin(url), endpoint_url, subdomains, group,
                     now + base::TimeDelta::FromSeconds(ttl_sec));
  } else {
    cache->RemoveClientForOriginAndEndpoint(url::Origin(url), endpoint_url);
  }
}

}  // namespace net
