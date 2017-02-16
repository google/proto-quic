// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_server_properties_impl.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/single_thread_task_runner.h"
#include "base/stl_util.h"
#include "base/strings/string_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/values.h"

namespace net {

namespace {

// Initial delay for broken alternative services.
const uint64_t kBrokenAlternativeProtocolDelaySecs = 300;
// Subsequent failures result in exponential (base 2) backoff.
// Limit binary shift to limit delay to approximately 2 days.
const int kBrokenDelayMaxShift = 9;

}  // namespace

HttpServerPropertiesImpl::HttpServerPropertiesImpl()
    : spdy_servers_map_(SpdyServersMap::NO_AUTO_EVICT),
      alternative_service_map_(AlternativeServiceMap::NO_AUTO_EVICT),
      server_network_stats_map_(ServerNetworkStatsMap::NO_AUTO_EVICT),
      quic_server_info_map_(QuicServerInfoMap::NO_AUTO_EVICT),
      max_server_configs_stored_in_properties_(kMaxQuicServersToPersist),
      weak_ptr_factory_(this) {
  canonical_suffixes_.push_back(".ggpht.com");
  canonical_suffixes_.push_back(".c.youtube.com");
  canonical_suffixes_.push_back(".googlevideo.com");
  canonical_suffixes_.push_back(".googleusercontent.com");
}

HttpServerPropertiesImpl::~HttpServerPropertiesImpl() {
}

void HttpServerPropertiesImpl::SetSpdyServers(
    std::vector<std::string>* spdy_servers,
    bool support_spdy) {
  DCHECK(CalledOnValidThread());
  if (!spdy_servers)
    return;

  // Add the entries from persisted data.
  SpdyServersMap spdy_servers_map(SpdyServersMap::NO_AUTO_EVICT);
  for (std::vector<std::string>::reverse_iterator it = spdy_servers->rbegin();
       it != spdy_servers->rend(); ++it) {
    spdy_servers_map.Put(*it, support_spdy);
  }

  // |spdy_servers_map| will have the memory cache.
  spdy_servers_map_.Swap(spdy_servers_map);

  // Add the entries from the memory cache.
  for (SpdyServersMap::reverse_iterator it = spdy_servers_map.rbegin();
       it != spdy_servers_map.rend(); ++it) {
    // Add the entry if it is not in the cache, otherwise move it to the front
    // of recency list.
    if (spdy_servers_map_.Get(it->first) == spdy_servers_map_.end())
      spdy_servers_map_.Put(it->first, it->second);
  }
}

void HttpServerPropertiesImpl::SetAlternativeServiceServers(
    AlternativeServiceMap* alternative_service_map) {
  int32_t size_diff =
      alternative_service_map->size() - alternative_service_map_.size();
  if (size_diff > 0) {
    UMA_HISTOGRAM_COUNTS("Net.AlternativeServiceServers.MorePrefsEntries",
                         size_diff);
  } else {
    UMA_HISTOGRAM_COUNTS(
        "Net.AlternativeServiceServers.MoreOrEqualCacheEntries", -size_diff);
  }

  AlternativeServiceMap new_alternative_service_map(
      AlternativeServiceMap::NO_AUTO_EVICT);
  // Add the entries from persisted data.
  for (AlternativeServiceMap::reverse_iterator input_it =
           alternative_service_map->rbegin();
       input_it != alternative_service_map->rend(); ++input_it) {
    DCHECK(!input_it->second.empty());
    new_alternative_service_map.Put(input_it->first, input_it->second);
  }

  alternative_service_map_.Swap(new_alternative_service_map);

  // Add the entries from the memory cache.
  for (AlternativeServiceMap::reverse_iterator input_it =
           new_alternative_service_map.rbegin();
       input_it != new_alternative_service_map.rend(); ++input_it) {
    if (alternative_service_map_.Get(input_it->first) ==
        alternative_service_map_.end()) {
      alternative_service_map_.Put(input_it->first, input_it->second);
    }
  }

  // Attempt to find canonical servers. Canonical suffix only apply to HTTPS.
  const uint16_t kCanonicalPort = 443;
  const char* kCanonicalScheme = "https";
  for (const std::string& canonical_suffix : canonical_suffixes_) {
    url::SchemeHostPort canonical_server(kCanonicalScheme, canonical_suffix,
                                         kCanonicalPort);
    // If we already have a valid canonical server, we're done.
    if (base::ContainsKey(canonical_host_to_origin_map_, canonical_server) &&
        (alternative_service_map_.Peek(
             canonical_host_to_origin_map_[canonical_server]) !=
         alternative_service_map_.end())) {
      continue;
    }
    // Now attempt to find a server which matches this origin and set it as
    // canonical.
    for (AlternativeServiceMap::const_iterator it =
             alternative_service_map_.begin();
         it != alternative_service_map_.end(); ++it) {
      if (base::EndsWith(it->first.host(), canonical_suffix,
                         base::CompareCase::INSENSITIVE_ASCII) &&
          it->first.scheme() == canonical_server.scheme()) {
        canonical_host_to_origin_map_[canonical_server] = it->first;
        break;
      }
    }
  }
}

void HttpServerPropertiesImpl::SetSupportsQuic(IPAddress* last_address) {
  if (last_address)
    last_quic_address_ = *last_address;
}

void HttpServerPropertiesImpl::SetServerNetworkStats(
    ServerNetworkStatsMap* server_network_stats_map) {
  // Add the entries from persisted data.
  ServerNetworkStatsMap new_server_network_stats_map(
      ServerNetworkStatsMap::NO_AUTO_EVICT);
  for (ServerNetworkStatsMap::reverse_iterator it =
           server_network_stats_map->rbegin();
       it != server_network_stats_map->rend(); ++it) {
    new_server_network_stats_map.Put(it->first, it->second);
  }

  server_network_stats_map_.Swap(new_server_network_stats_map);

  // Add the entries from the memory cache.
  for (ServerNetworkStatsMap::reverse_iterator it =
           new_server_network_stats_map.rbegin();
       it != new_server_network_stats_map.rend(); ++it) {
    if (server_network_stats_map_.Get(it->first) ==
        server_network_stats_map_.end()) {
      server_network_stats_map_.Put(it->first, it->second);
    }
  }
}

void HttpServerPropertiesImpl::SetQuicServerInfoMap(
    QuicServerInfoMap* quic_server_info_map) {
  // Add the entries from persisted data.
  QuicServerInfoMap temp_map(QuicServerInfoMap::NO_AUTO_EVICT);
  for (QuicServerInfoMap::reverse_iterator it = quic_server_info_map->rbegin();
       it != quic_server_info_map->rend(); ++it) {
    temp_map.Put(it->first, it->second);
  }

  quic_server_info_map_.Swap(temp_map);

  // Add the entries from the memory cache.
  for (QuicServerInfoMap::reverse_iterator it = temp_map.rbegin();
       it != temp_map.rend(); ++it) {
    if (quic_server_info_map_.Get(it->first) == quic_server_info_map_.end()) {
      quic_server_info_map_.Put(it->first, it->second);
    }
  }
}

void HttpServerPropertiesImpl::GetSpdyServerList(
    base::ListValue* spdy_server_list,
    size_t max_size) const {
  DCHECK(CalledOnValidThread());
  DCHECK(spdy_server_list);
  spdy_server_list->Clear();
  size_t count = 0;
  // Get the list of servers (scheme/host/port) that support SPDY.
  for (SpdyServersMap::const_iterator it = spdy_servers_map_.begin();
       it != spdy_servers_map_.end() && count < max_size; ++it) {
    const std::string spdy_server = it->first;
    if (it->second) {
      spdy_server_list->AppendString(spdy_server);
      ++count;
    }
  }
}

void HttpServerPropertiesImpl::Clear() {
  DCHECK(CalledOnValidThread());
  spdy_servers_map_.Clear();
  alternative_service_map_.Clear();
  canonical_host_to_origin_map_.clear();
  last_quic_address_ = IPAddress();
  server_network_stats_map_.Clear();
  quic_server_info_map_.Clear();
}

bool HttpServerPropertiesImpl::SupportsRequestPriority(
    const url::SchemeHostPort& server) {
  DCHECK(CalledOnValidThread());
  if (server.host().empty())
    return false;

  if (GetSupportsSpdy(server))
    return true;
  const AlternativeServiceVector alternative_service_vector =
      GetAlternativeServices(server);
  for (const AlternativeService& alternative_service :
       alternative_service_vector) {
    if (alternative_service.protocol == kProtoQUIC) {
      return true;
    }
  }
  return false;
}

bool HttpServerPropertiesImpl::GetSupportsSpdy(
    const url::SchemeHostPort& server) {
  DCHECK(CalledOnValidThread());
  if (server.host().empty())
    return false;

  SpdyServersMap::iterator spdy_server =
      spdy_servers_map_.Get(server.Serialize());
  return spdy_server != spdy_servers_map_.end() && spdy_server->second;
}

void HttpServerPropertiesImpl::SetSupportsSpdy(
    const url::SchemeHostPort& server,
    bool support_spdy) {
  DCHECK(CalledOnValidThread());
  if (server.host().empty())
    return;

  SpdyServersMap::iterator spdy_server =
      spdy_servers_map_.Get(server.Serialize());
  if ((spdy_server != spdy_servers_map_.end()) &&
      (spdy_server->second == support_spdy)) {
    return;
  }
  // Cache the data.
  spdy_servers_map_.Put(server.Serialize(), support_spdy);
}

bool HttpServerPropertiesImpl::RequiresHTTP11(
    const HostPortPair& host_port_pair) {
  DCHECK(CalledOnValidThread());
  if (host_port_pair.host().empty())
    return false;

  return (http11_servers_.find(host_port_pair) != http11_servers_.end());
}

void HttpServerPropertiesImpl::SetHTTP11Required(
    const HostPortPair& host_port_pair) {
  DCHECK(CalledOnValidThread());
  if (host_port_pair.host().empty())
    return;

  http11_servers_.insert(host_port_pair);
}

void HttpServerPropertiesImpl::MaybeForceHTTP11(const HostPortPair& server,
                                                SSLConfig* ssl_config) {
  if (RequiresHTTP11(server)) {
    ForceHTTP11(ssl_config);
  }
}

const std::string* HttpServerPropertiesImpl::GetCanonicalSuffix(
    const std::string& host) const {
  // If this host ends with a canonical suffix, then return the canonical
  // suffix.
  for (const std::string& canonical_suffix : canonical_suffixes_) {
    if (base::EndsWith(host, canonical_suffix,
                       base::CompareCase::INSENSITIVE_ASCII)) {
      return &canonical_suffix;
    }
  }
  return nullptr;
}

AlternativeServiceVector HttpServerPropertiesImpl::GetAlternativeServices(
    const url::SchemeHostPort& origin) {
  // Copy valid alternative services into |valid_alternative_services|.
  AlternativeServiceVector valid_alternative_services;
  const base::Time now = base::Time::Now();
  AlternativeServiceMap::iterator map_it = alternative_service_map_.Get(origin);
  if (map_it != alternative_service_map_.end()) {
    HostPortPair host_port_pair(origin.host(), origin.port());
    for (AlternativeServiceInfoVector::iterator it = map_it->second.begin();
         it != map_it->second.end();) {
      if (it->expiration < now) {
        it = map_it->second.erase(it);
        continue;
      }
      AlternativeService alternative_service(it->alternative_service);
      if (alternative_service.host.empty()) {
        alternative_service.host = origin.host();
      }
      // If the alternative service is equivalent to the origin (same host, same
      // port, and both TCP), skip it.
      if (host_port_pair.Equals(alternative_service.host_port_pair()) &&
          alternative_service.protocol == kProtoHTTP2) {
        ++it;
        continue;
      }
      valid_alternative_services.push_back(alternative_service);
      ++it;
    }
    if (map_it->second.empty()) {
      alternative_service_map_.Erase(map_it);
    }
    return valid_alternative_services;
  }

  CanonicalHostMap::const_iterator canonical = GetCanonicalHost(origin);
  if (canonical == canonical_host_to_origin_map_.end()) {
    return AlternativeServiceVector();
  }
  map_it = alternative_service_map_.Get(canonical->second);
  if (map_it == alternative_service_map_.end()) {
    return AlternativeServiceVector();
  }
  for (AlternativeServiceInfoVector::iterator it = map_it->second.begin();
       it != map_it->second.end();) {
    if (it->expiration < now) {
      it = map_it->second.erase(it);
      continue;
    }
    AlternativeService alternative_service(it->alternative_service);
    if (alternative_service.host.empty()) {
      alternative_service.host = canonical->second.host();
      if (IsAlternativeServiceBroken(alternative_service)) {
        ++it;
        continue;
      }
      alternative_service.host = origin.host();
    } else if (IsAlternativeServiceBroken(alternative_service)) {
      ++it;
      continue;
    }
    valid_alternative_services.push_back(alternative_service);
    ++it;
  }
  if (map_it->second.empty()) {
    alternative_service_map_.Erase(map_it);
  }
  return valid_alternative_services;
}

bool HttpServerPropertiesImpl::SetAlternativeService(
    const url::SchemeHostPort& origin,
    const AlternativeService& alternative_service,
    base::Time expiration) {
  return SetAlternativeServices(
      origin,
      AlternativeServiceInfoVector(
          /*size=*/1, AlternativeServiceInfo(alternative_service, expiration)));
}

bool HttpServerPropertiesImpl::SetAlternativeServices(
    const url::SchemeHostPort& origin,
    const AlternativeServiceInfoVector& alternative_service_info_vector) {
  AlternativeServiceMap::iterator it = alternative_service_map_.Peek(origin);

  if (alternative_service_info_vector.empty()) {
    RemoveCanonicalHost(origin);
    if (it == alternative_service_map_.end())
      return false;

    alternative_service_map_.Erase(it);
    return true;
  }

  bool changed = true;
  if (it != alternative_service_map_.end()) {
    DCHECK(!it->second.empty());
    if (it->second.size() == alternative_service_info_vector.size()) {
      const base::Time now = base::Time::Now();
      changed = false;
      auto new_it = alternative_service_info_vector.begin();
      for (const auto& old : it->second) {
        // Persist to disk immediately if new entry has different scheme, host,
        // or port.
        if (old.alternative_service != new_it->alternative_service) {
          changed = true;
          break;
        }
        // Also persist to disk if new expiration it more that twice as far or
        // less than half as far in the future.
        base::Time old_time = old.expiration;
        base::Time new_time = new_it->expiration;
        if (new_time - now > 2 * (old_time - now) ||
            2 * (new_time - now) < (old_time - now)) {
          changed = true;
          break;
        }
        ++new_it;
      }
    }
  }

  const bool previously_no_alternative_services =
      (GetAlternateProtocolIterator(origin) == alternative_service_map_.end());

  alternative_service_map_.Put(origin, alternative_service_info_vector);

  if (previously_no_alternative_services &&
      !GetAlternativeServices(origin).empty()) {
    // TODO(rch): Consider the case where multiple requests are started
    // before the first completes. In this case, only one of the jobs
    // would reach this code, whereas all of them should should have.
    HistogramAlternateProtocolUsage(ALTERNATE_PROTOCOL_USAGE_MAPPING_MISSING,
                                    false);
  }

  // If this host ends with a canonical suffix, then set it as the
  // canonical host.
  const char* kCanonicalScheme = "https";
  if (origin.scheme() == kCanonicalScheme) {
    const std::string* canonical_suffix = GetCanonicalSuffix(origin.host());
    if (canonical_suffix != nullptr) {
      url::SchemeHostPort canonical_server(kCanonicalScheme, *canonical_suffix,
                                           origin.port());
      canonical_host_to_origin_map_[canonical_server] = origin;
    }
  }
  return changed;
}

void HttpServerPropertiesImpl::MarkAlternativeServiceBroken(
    const AlternativeService& alternative_service) {
  // Empty host means use host of origin, callers are supposed to substitute.
  DCHECK(!alternative_service.host.empty());
  if (alternative_service.protocol == kProtoUnknown) {
    LOG(DFATAL) << "Trying to mark unknown alternate protocol broken.";
    return;
  }
  ++recently_broken_alternative_services_[alternative_service];
  int shift = recently_broken_alternative_services_[alternative_service] - 1;
  if (shift > kBrokenDelayMaxShift)
    shift = kBrokenDelayMaxShift;
  base::TimeDelta delay =
      base::TimeDelta::FromSeconds(kBrokenAlternativeProtocolDelaySecs);
  base::TimeTicks when = base::TimeTicks::Now() + delay * (1 << shift);
  auto result = broken_alternative_services_.insert(
      std::make_pair(alternative_service, when));
  // Return if alternative service is already in expiration queue.
  if (!result.second) {
    return;
  }

  // If this is the only entry in the list, schedule an expiration task.
  // Otherwise it will be rescheduled automatically when the pending task runs.
  if (broken_alternative_services_.size() == 1) {
    ScheduleBrokenAlternateProtocolMappingsExpiration();
  }
}

void HttpServerPropertiesImpl::MarkAlternativeServiceRecentlyBroken(
    const AlternativeService& alternative_service) {
  if (!base::ContainsKey(recently_broken_alternative_services_,
                         alternative_service))
    recently_broken_alternative_services_[alternative_service] = 1;
}

bool HttpServerPropertiesImpl::IsAlternativeServiceBroken(
    const AlternativeService& alternative_service) const {
  // Empty host means use host of origin, callers are supposed to substitute.
  DCHECK(!alternative_service.host.empty());
  return base::ContainsKey(broken_alternative_services_, alternative_service);
}

bool HttpServerPropertiesImpl::WasAlternativeServiceRecentlyBroken(
    const AlternativeService& alternative_service) {
  if (alternative_service.protocol == kProtoUnknown)
    return false;
  return base::ContainsKey(recently_broken_alternative_services_,
                           alternative_service);
}

void HttpServerPropertiesImpl::ConfirmAlternativeService(
    const AlternativeService& alternative_service) {
  if (alternative_service.protocol == kProtoUnknown)
    return;
  broken_alternative_services_.erase(alternative_service);
  recently_broken_alternative_services_.erase(alternative_service);
}

const AlternativeServiceMap& HttpServerPropertiesImpl::alternative_service_map()
    const {
  return alternative_service_map_;
}

std::unique_ptr<base::Value>
HttpServerPropertiesImpl::GetAlternativeServiceInfoAsValue() const {
  std::unique_ptr<base::ListValue> dict_list(new base::ListValue);
  for (const auto& alternative_service_map_item : alternative_service_map_) {
    std::unique_ptr<base::ListValue> alternative_service_list(
        new base::ListValue);
    const url::SchemeHostPort& server = alternative_service_map_item.first;
    for (const AlternativeServiceInfo& alternative_service_info :
         alternative_service_map_item.second) {
      std::string alternative_service_string(
          alternative_service_info.ToString());
      AlternativeService alternative_service(
          alternative_service_info.alternative_service);
      if (alternative_service.host.empty()) {
        alternative_service.host = server.host();
      }
      if (IsAlternativeServiceBroken(alternative_service)) {
        alternative_service_string.append(" (broken)");
      }
      alternative_service_list->AppendString(alternative_service_string);
    }
    if (alternative_service_list->empty())
      continue;
    std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
    dict->SetString("server", server.Serialize());
    dict->Set("alternative_service", std::unique_ptr<base::Value>(
                                         std::move(alternative_service_list)));
    dict_list->Append(std::move(dict));
  }
  return std::move(dict_list);
}

bool HttpServerPropertiesImpl::GetSupportsQuic(IPAddress* last_address) const {
  if (last_quic_address_.empty())
    return false;

  *last_address = last_quic_address_;
  return true;
}

void HttpServerPropertiesImpl::SetSupportsQuic(bool used_quic,
                                               const IPAddress& address) {
  if (!used_quic) {
    last_quic_address_ = IPAddress();
  } else {
    last_quic_address_ = address;
  }
}

void HttpServerPropertiesImpl::SetServerNetworkStats(
    const url::SchemeHostPort& server,
    ServerNetworkStats stats) {
  server_network_stats_map_.Put(server, stats);
}

const ServerNetworkStats* HttpServerPropertiesImpl::GetServerNetworkStats(
    const url::SchemeHostPort& server) {
  ServerNetworkStatsMap::iterator it = server_network_stats_map_.Get(server);
  if (it == server_network_stats_map_.end()) {
    return NULL;
  }
  return &it->second;
}

const ServerNetworkStatsMap&
HttpServerPropertiesImpl::server_network_stats_map() const {
  return server_network_stats_map_;
}

bool HttpServerPropertiesImpl::SetQuicServerInfo(
    const QuicServerId& server_id,
    const std::string& server_info) {
  QuicServerInfoMap::iterator it = quic_server_info_map_.Peek(server_id);
  bool changed =
      (it == quic_server_info_map_.end() || it->second != server_info);
  quic_server_info_map_.Put(server_id, server_info);
  return changed;
}

const std::string* HttpServerPropertiesImpl::GetQuicServerInfo(
    const QuicServerId& server_id) {
  QuicServerInfoMap::iterator it = quic_server_info_map_.Get(server_id);
  if (it == quic_server_info_map_.end())
    return nullptr;
  return &it->second;
}

const QuicServerInfoMap& HttpServerPropertiesImpl::quic_server_info_map()
    const {
  return quic_server_info_map_;
}

size_t HttpServerPropertiesImpl::max_server_configs_stored_in_properties()
    const {
  return max_server_configs_stored_in_properties_;
}

void HttpServerPropertiesImpl::SetMaxServerConfigsStoredInProperties(
    size_t max_server_configs_stored_in_properties) {
  max_server_configs_stored_in_properties_ =
      max_server_configs_stored_in_properties;

  // MRUCache doesn't allow the size of the cache to be changed. Thus create a
  // new map with the new size and add current elements and swap the new map.
  quic_server_info_map_.ShrinkToSize(max_server_configs_stored_in_properties_);
  QuicServerInfoMap temp_map(max_server_configs_stored_in_properties_);
  for (QuicServerInfoMap::reverse_iterator it = quic_server_info_map_.rbegin();
       it != quic_server_info_map_.rend(); ++it) {
    temp_map.Put(it->first, it->second);
  }

  quic_server_info_map_.Swap(temp_map);
}

bool HttpServerPropertiesImpl::IsInitialized() const {
  // No initialization is needed.
  return true;
}

AlternativeServiceMap::const_iterator
HttpServerPropertiesImpl::GetAlternateProtocolIterator(
    const url::SchemeHostPort& server) {
  AlternativeServiceMap::const_iterator it =
      alternative_service_map_.Get(server);
  if (it != alternative_service_map_.end())
    return it;

  CanonicalHostMap::const_iterator canonical = GetCanonicalHost(server);
  if (canonical == canonical_host_to_origin_map_.end()) {
    return alternative_service_map_.end();
  }

  const url::SchemeHostPort canonical_server = canonical->second;
  it = alternative_service_map_.Get(canonical_server);
  if (it == alternative_service_map_.end()) {
    return alternative_service_map_.end();
  }

  for (const AlternativeServiceInfo& alternative_service_info : it->second) {
    AlternativeService alternative_service(
        alternative_service_info.alternative_service);
    if (alternative_service.host.empty()) {
      alternative_service.host = canonical_server.host();
    }
    if (!IsAlternativeServiceBroken(alternative_service)) {
      return it;
    }
  }

  RemoveCanonicalHost(canonical_server);
  return alternative_service_map_.end();
}

HttpServerPropertiesImpl::CanonicalHostMap::const_iterator
HttpServerPropertiesImpl::GetCanonicalHost(
    const url::SchemeHostPort& server) const {
  const char* kCanonicalScheme = "https";
  if (server.scheme() != kCanonicalScheme)
    return canonical_host_to_origin_map_.end();

  const std::string* canonical_suffix = GetCanonicalSuffix(server.host());
  if (canonical_suffix == nullptr)
    return canonical_host_to_origin_map_.end();

  url::SchemeHostPort canonical_server(kCanonicalScheme, *canonical_suffix,
                                       server.port());
  return canonical_host_to_origin_map_.find(canonical_server);
}

void HttpServerPropertiesImpl::RemoveCanonicalHost(
    const url::SchemeHostPort& server) {
  CanonicalHostMap::const_iterator canonical = GetCanonicalHost(server);
  if (canonical == canonical_host_to_origin_map_.end())
    return;

  canonical_host_to_origin_map_.erase(canonical->first);
}

void HttpServerPropertiesImpl::ExpireBrokenAlternateProtocolMappings() {
  base::TimeTicks now = base::TimeTicks::Now();
  while (!broken_alternative_services_.empty()) {
    BrokenAlternativeServices::iterator it =
        broken_alternative_services_.begin();
    if (now < it->second) {
      break;
    }

    const AlternativeService expired_alternative_service = it->first;
    broken_alternative_services_.erase(it);

    // Remove every occurrence of |expired_alternative_service| from
    // |alternative_service_map_|.
    for (AlternativeServiceMap::iterator map_it =
             alternative_service_map_.begin();
         map_it != alternative_service_map_.end();) {
      for (AlternativeServiceInfoVector::iterator it = map_it->second.begin();
           it != map_it->second.end();) {
        AlternativeService alternative_service(it->alternative_service);
        // Empty hostname in map means hostname of key: substitute before
        // comparing to |expired_alternative_service|.
        if (alternative_service.host.empty()) {
          alternative_service.host = map_it->first.host();
        }
        if (alternative_service == expired_alternative_service) {
          it = map_it->second.erase(it);
          continue;
        }
        ++it;
      }
      // If an origin has an empty list of alternative services, then remove it
      // from both |canonical_host_to_origin_map_| and
      // |alternative_service_map_|.
      if (map_it->second.empty()) {
        RemoveCanonicalHost(map_it->first);
        map_it = alternative_service_map_.Erase(map_it);
        continue;
      }
      ++map_it;
    }
  }
  ScheduleBrokenAlternateProtocolMappingsExpiration();
}

void
HttpServerPropertiesImpl::ScheduleBrokenAlternateProtocolMappingsExpiration() {
  if (broken_alternative_services_.empty()) {
    return;
  }
  base::TimeTicks now = base::TimeTicks::Now();
  base::TimeTicks when = broken_alternative_services_.front().second;
  base::TimeDelta delay = when > now ? when - now : base::TimeDelta();
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE,
      base::Bind(
          &HttpServerPropertiesImpl::ExpireBrokenAlternateProtocolMappings,
          weak_ptr_factory_.GetWeakPtr()),
      delay);
}

}  // namespace net
