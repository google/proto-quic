// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/log/net_log_util.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/logging.h"
#include "base/metrics/field_trial.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/address_family.h"
#include "net/base/load_states.h"
#include "net/base/net_errors.h"
#include "net/base/sdch_manager.h"
#include "net/disk_cache/disk_cache.h"
#include "net/dns/host_cache.h"
#include "net/dns/host_resolver.h"
#include "net/http/http_cache.h"
#include "net/http/http_network_session.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_transaction_factory.h"
#include "net/log/net_log.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_entry.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_parameters_callback.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy/proxy_config.h"
#include "net/proxy/proxy_retry_info.h"
#include "net/proxy/proxy_service.h"
#include "net/quic/core/quic_error_codes.h"
#include "net/quic/core/quic_packets.h"
#include "net/socket/ssl_client_socket.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"

namespace net {

namespace {

// This should be incremented when significant changes are made that will
// invalidate the old loading code.
const int kLogFormatVersion = 1;

struct StringToConstant {
  const char* name;
  const int constant;
};

const StringToConstant kCertStatusFlags[] = {
#define CERT_STATUS_FLAG(label, value) \
  { #label, value }                    \
  ,
#include "net/cert/cert_status_flags_list.h"
#undef CERT_STATUS_FLAG
};

const StringToConstant kLoadFlags[] = {
#define LOAD_FLAG(label, value) \
  { #label, value }             \
  ,
#include "net/base/load_flags_list.h"
#undef LOAD_FLAG
};

const StringToConstant kLoadStateTable[] = {
#define LOAD_STATE(label, value) \
  { #label, LOAD_STATE_##label } \
  ,
#include "net/base/load_states_list.h"
#undef LOAD_STATE
};

const short kNetErrors[] = {
#define NET_ERROR(label, value) value,
#include "net/base/net_error_list.h"
#undef NET_ERROR
};

const StringToConstant kSdchProblems[] = {
#define SDCH_PROBLEM_CODE(label, value) \
  { #label, value }                     \
  ,
#include "net/base/sdch_problem_code_list.h"
#undef SDCH_PROBLEM_CODE
};

const char* NetInfoSourceToString(NetInfoSource source) {
  switch (source) {
#define NET_INFO_SOURCE(label, string, value) \
  case NET_INFO_##label:                      \
    return string;
#include "net/base/net_info_source_list.h"
#undef NET_INFO_SOURCE
    case NET_INFO_ALL_SOURCES:
      return "All";
  }
  return "?";
}

// Returns the disk cache backend for |context| if there is one, or NULL.
// Despite the name, can return an in memory "disk cache".
disk_cache::Backend* GetDiskCacheBackend(URLRequestContext* context) {
  if (!context->http_transaction_factory())
    return NULL;

  HttpCache* http_cache = context->http_transaction_factory()->GetCache();
  if (!http_cache)
    return NULL;

  return http_cache->GetCurrentBackend();
}

// Returns true if |request1| was created before |request2|.
bool RequestCreatedBefore(const URLRequest* request1,
                          const URLRequest* request2) {
  if (request1->creation_time() < request2->creation_time())
    return true;
  if (request1->creation_time() > request2->creation_time())
    return false;
  // If requests were created at the same time, sort by ID.  Mostly matters for
  // testing purposes.
  return request1->identifier() < request2->identifier();
}

// Returns a Value representing the state of a pre-existing URLRequest when
// net-internals was opened.
std::unique_ptr<base::Value> GetRequestStateAsValue(
    const net::URLRequest* request,
    NetLogCaptureMode capture_mode) {
  return request->GetStateAsValue();
}

}  // namespace

std::unique_ptr<base::DictionaryValue> GetNetConstants() {
  std::unique_ptr<base::DictionaryValue> constants_dict(
      new base::DictionaryValue());

  // Version of the file format.
  constants_dict->SetInteger("logFormatVersion", kLogFormatVersion);

  // Add a dictionary with information on the relationship between event type
  // enums and their symbolic names.
  constants_dict->Set("logEventTypes", NetLog::GetEventTypesAsValue());

  // Add a dictionary with information about the relationship between CertStatus
  // flags and their symbolic names.
  {
    std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

    for (const auto& flag : kCertStatusFlags)
      dict->SetInteger(flag.name, flag.constant);

    constants_dict->Set("certStatusFlag", std::move(dict));
  }

  // Add a dictionary with information about the relationship between load flag
  // enums and their symbolic names.
  {
    std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

    for (const auto& flag : kLoadFlags)
      dict->SetInteger(flag.name, flag.constant);

    constants_dict->Set("loadFlag", std::move(dict));
  }

  // Add a dictionary with information about the relationship between load state
  // enums and their symbolic names.
  {
    std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

    for (const auto& state : kLoadStateTable)
      dict->SetInteger(state.name, state.constant);

    constants_dict->Set("loadState", std::move(dict));
  }

  {
    std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
#define NET_INFO_SOURCE(label, string, value) \
  dict->SetInteger(string, NET_INFO_##label);
#include "net/base/net_info_source_list.h"
#undef NET_INFO_SOURCE
    constants_dict->Set("netInfoSources", std::move(dict));
  }

  // Add information on the relationship between net error codes and their
  // symbolic names.
  {
    std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

    for (const auto& error : kNetErrors)
      dict->SetInteger(ErrorToShortString(error), error);

    constants_dict->Set("netError", std::move(dict));
  }

  // Add information on the relationship between QUIC error codes and their
  // symbolic names.
  {
    std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

    for (QuicErrorCode error = QUIC_NO_ERROR; error < QUIC_LAST_ERROR;
         error = static_cast<QuicErrorCode>(error + 1)) {
      dict->SetInteger(QuicErrorCodeToString(error), static_cast<int>(error));
    }

    constants_dict->Set("quicError", std::move(dict));
  }

  // Add information on the relationship between QUIC RST_STREAM error codes
  // and their symbolic names.
  {
    std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

    for (QuicRstStreamErrorCode error = QUIC_STREAM_NO_ERROR;
         error < QUIC_STREAM_LAST_ERROR;
         error = static_cast<QuicRstStreamErrorCode>(error + 1)) {
      dict->SetInteger(QuicRstStreamErrorCodeToString(error),
                       static_cast<int>(error));
    }

    constants_dict->Set("quicRstStreamError", std::move(dict));
  }

  // Add information on the relationship between SDCH problem codes and their
  // symbolic names.
  {
    std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

    for (const auto& problem : kSdchProblems)
      dict->SetInteger(problem.name, problem.constant);

    constants_dict->Set("sdchProblemCode", std::move(dict));
  }

  // Information about the relationship between event phase enums and their
  // symbolic names.
  {
    std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

    dict->SetInteger("PHASE_BEGIN", static_cast<int>(NetLogEventPhase::BEGIN));
    dict->SetInteger("PHASE_END", static_cast<int>(NetLogEventPhase::END));
    dict->SetInteger("PHASE_NONE", static_cast<int>(NetLogEventPhase::NONE));

    constants_dict->Set("logEventPhase", std::move(dict));
  }

  // Information about the relationship between source type enums and
  // their symbolic names.
  constants_dict->Set("logSourceType", NetLog::GetSourceTypesAsValue());

  // TODO(eroman): This is here for compatibility in loading new log files with
  // older builds of Chrome. Safe to remove this once M45 is on the stable
  // channel.
  constants_dict->Set("logLevelType", new base::DictionaryValue());

  // Information about the relationship between address family enums and
  // their symbolic names.
  {
    std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

    dict->SetInteger("ADDRESS_FAMILY_UNSPECIFIED", ADDRESS_FAMILY_UNSPECIFIED);
    dict->SetInteger("ADDRESS_FAMILY_IPV4", ADDRESS_FAMILY_IPV4);
    dict->SetInteger("ADDRESS_FAMILY_IPV6", ADDRESS_FAMILY_IPV6);

    constants_dict->Set("addressFamily", std::move(dict));
  }

  // Information about how the "time ticks" values we have given it relate to
  // actual system times.  Time ticks are used throughout since they are stable
  // across system clock changes. Note: |timeTickOffset| is only comparable to
  // TimeTicks values in milliseconds.
  // TODO(csharrison): This is an imprecise way to convert TimeTicks to unix
  // time. In fact, there isn't really a good way to do this unless we log Time
  // and TimeTicks values side by side for every event. crbug.com/593157 tracks
  // a change where the user will be notified if a timing anomaly occured that
  // would skew the conversion (i.e. the machine entered suspend mode while
  // logging).
  {
    base::TimeDelta time_since_epoch =
        base::Time::Now() - base::Time::UnixEpoch();
    base::TimeDelta reference_time_ticks =
        base::TimeTicks::Now() - base::TimeTicks();
    int64_t tick_to_unix_time_ms =
        (time_since_epoch - reference_time_ticks).InMilliseconds();

    // Pass it as a string, since it may be too large to fit in an integer.
    constants_dict->SetString("timeTickOffset",
                              base::Int64ToString(tick_to_unix_time_ms));
  }

  // "clientInfo" key is required for some WriteToFileNetLogObserver log
  // readers. Provide a default empty value for compatibility.
  constants_dict->Set("clientInfo", new base::DictionaryValue());

  // Add a list of active field experiments.
  {
    base::FieldTrial::ActiveGroups active_groups;
    base::FieldTrialList::GetActiveFieldTrialGroups(&active_groups);
    base::ListValue* field_trial_groups = new base::ListValue();
    for (base::FieldTrial::ActiveGroups::const_iterator it =
             active_groups.begin();
         it != active_groups.end(); ++it) {
      field_trial_groups->AppendString(it->trial_name + ":" + it->group_name);
    }
    constants_dict->Set("activeFieldTrialGroups", field_trial_groups);
  }

  return constants_dict;
}

NET_EXPORT std::unique_ptr<base::DictionaryValue> GetNetInfo(
    URLRequestContext* context,
    int info_sources) {
  // May only be called on the context's thread.
  DCHECK(context->CalledOnValidThread());

  std::unique_ptr<base::DictionaryValue> net_info_dict(
      new base::DictionaryValue());

  // TODO(mmenke):  The code for most of these sources should probably be moved
  // into the sources themselves.
  if (info_sources & NET_INFO_PROXY_SETTINGS) {
    ProxyService* proxy_service = context->proxy_service();

    std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
    if (proxy_service->fetched_config().is_valid())
      dict->Set("original", proxy_service->fetched_config().ToValue());
    if (proxy_service->config().is_valid())
      dict->Set("effective", proxy_service->config().ToValue());

    net_info_dict->Set(NetInfoSourceToString(NET_INFO_PROXY_SETTINGS),
                       std::move(dict));
  }

  if (info_sources & NET_INFO_BAD_PROXIES) {
    const ProxyRetryInfoMap& bad_proxies_map =
        context->proxy_service()->proxy_retry_info();

    base::ListValue* list = new base::ListValue();

    for (ProxyRetryInfoMap::const_iterator it = bad_proxies_map.begin();
         it != bad_proxies_map.end(); ++it) {
      const std::string& proxy_uri = it->first;
      const ProxyRetryInfo& retry_info = it->second;

      std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
      dict->SetString("proxy_uri", proxy_uri);
      dict->SetString("bad_until",
                      NetLog::TickCountToString(retry_info.bad_until));

      list->Append(std::move(dict));
    }

    net_info_dict->Set(NetInfoSourceToString(NET_INFO_BAD_PROXIES), list);
  }

  if (info_sources & NET_INFO_HOST_RESOLVER) {
    HostResolver* host_resolver = context->host_resolver();
    DCHECK(host_resolver);
    HostCache* cache = host_resolver->GetHostCache();
    if (cache) {
      std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
      std::unique_ptr<base::Value> dns_config =
          host_resolver->GetDnsConfigAsValue();
      if (dns_config)
        dict->Set("dns_config", std::move(dns_config));

      base::DictionaryValue* cache_info_dict = new base::DictionaryValue();

      cache_info_dict->SetInteger("capacity",
                                  static_cast<int>(cache->max_entries()));

      base::ListValue* entry_list = new base::ListValue();

      for (const auto& pair : cache->entries()) {
        const HostCache::Key& key = pair.first;
        const HostCache::Entry& entry = pair.second;

        std::unique_ptr<base::DictionaryValue> entry_dict(
            new base::DictionaryValue());

        entry_dict->SetString("hostname", key.hostname);
        entry_dict->SetInteger("address_family",
                               static_cast<int>(key.address_family));
        entry_dict->SetString("expiration",
                              NetLog::TickCountToString(entry.expires()));

        if (entry.error() != OK) {
          entry_dict->SetInteger("error", entry.error());
        } else {
          const AddressList& addresses = entry.addresses();
          // Append all of the resolved addresses.
          base::ListValue* address_list = new base::ListValue();
          for (size_t i = 0; i < addresses.size(); ++i)
            address_list->AppendString(addresses[i].ToStringWithoutPort());
          entry_dict->Set("addresses", address_list);
        }

        entry_list->Append(std::move(entry_dict));
      }

      cache_info_dict->Set("entries", entry_list);
      dict->Set("cache", cache_info_dict);
      net_info_dict->Set(NetInfoSourceToString(NET_INFO_HOST_RESOLVER),
                         std::move(dict));
    }
  }

  HttpNetworkSession* http_network_session =
      context->http_transaction_factory()->GetSession();

  if (info_sources & NET_INFO_SOCKET_POOL) {
    net_info_dict->Set(NetInfoSourceToString(NET_INFO_SOCKET_POOL),
                       http_network_session->SocketPoolInfoToValue());
  }

  if (info_sources & NET_INFO_SPDY_SESSIONS) {
    net_info_dict->Set(NetInfoSourceToString(NET_INFO_SPDY_SESSIONS),
                       http_network_session->SpdySessionPoolInfoToValue());
  }

  if (info_sources & NET_INFO_SPDY_STATUS) {
    base::DictionaryValue* status_dict = new base::DictionaryValue();

    status_dict->SetBoolean("enable_http2",
                            http_network_session->params().enable_http2);

    NextProtoVector alpn_protos;
    http_network_session->GetAlpnProtos(&alpn_protos);
    if (!alpn_protos.empty()) {
      std::string next_protos_string;
      for (NextProto proto : alpn_protos) {
        if (!next_protos_string.empty())
          next_protos_string.append(",");
        next_protos_string.append(NextProtoToString(proto));
      }
      status_dict->SetString("alpn_protos", next_protos_string);
    }

    net_info_dict->Set(NetInfoSourceToString(NET_INFO_SPDY_STATUS),
                       status_dict);
  }

  if (info_sources & NET_INFO_ALT_SVC_MAPPINGS) {
    const HttpServerProperties& http_server_properties =
        *context->http_server_properties();
    net_info_dict->Set(
        NetInfoSourceToString(NET_INFO_ALT_SVC_MAPPINGS),
        http_server_properties.GetAlternativeServiceInfoAsValue());
  }

  if (info_sources & NET_INFO_QUIC) {
    net_info_dict->Set(NetInfoSourceToString(NET_INFO_QUIC),
                       http_network_session->QuicInfoToValue());
  }

  if (info_sources & NET_INFO_HTTP_CACHE) {
    base::DictionaryValue* info_dict = new base::DictionaryValue();
    base::DictionaryValue* stats_dict = new base::DictionaryValue();

    disk_cache::Backend* disk_cache = GetDiskCacheBackend(context);

    if (disk_cache) {
      // Extract the statistics key/value pairs from the backend.
      base::StringPairs stats;
      disk_cache->GetStats(&stats);
      for (size_t i = 0; i < stats.size(); ++i) {
        stats_dict->SetStringWithoutPathExpansion(stats[i].first,
                                                  stats[i].second);
      }
    }
    info_dict->Set("stats", stats_dict);

    net_info_dict->Set(NetInfoSourceToString(NET_INFO_HTTP_CACHE), info_dict);
  }

  if (info_sources & NET_INFO_SDCH) {
    std::unique_ptr<base::Value> info_dict;
    SdchManager* sdch_manager = context->sdch_manager();
    if (sdch_manager) {
      info_dict = sdch_manager->SdchInfoToValue();
    } else {
      info_dict.reset(new base::DictionaryValue());
    }
    net_info_dict->Set(NetInfoSourceToString(NET_INFO_SDCH),
                       std::move(info_dict));
  }

  return net_info_dict;
}

NET_EXPORT void CreateNetLogEntriesForActiveObjects(
    const std::set<URLRequestContext*>& contexts,
    NetLog::ThreadSafeObserver* observer) {
  // Put together the list of all requests.
  std::vector<const URLRequest*> requests;
  for (auto* context : contexts) {
    // May only be called on the context's thread.
    DCHECK(context->CalledOnValidThread());
    // Contexts should all be using the same NetLog.
    DCHECK_EQ((*contexts.begin())->net_log(), context->net_log());
    for (auto* request : *context->url_requests()) {
      requests.push_back(request);
    }
  }

  // Sort by creation time.
  std::sort(requests.begin(), requests.end(), RequestCreatedBefore);

  // Create fake events.
  for (auto* request : requests) {
    NetLogParametersCallback callback =
        base::Bind(&GetRequestStateAsValue, base::Unretained(request));

    // Note that passing the hardcoded NetLogCaptureMode::Default() below is
    // fine, since GetRequestStateAsValue() ignores the capture mode.
    NetLogEntryData entry_data(
        NetLogEventType::REQUEST_ALIVE, request->net_log().source(),
        NetLogEventPhase::BEGIN, request->creation_time(), &callback);
    NetLogEntry entry(&entry_data, NetLogCaptureMode::Default());
    observer->OnAddEntry(entry);
  }
}

}  // namespace net
