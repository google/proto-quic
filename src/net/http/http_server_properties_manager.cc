// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_server_properties_manager.h"

#include <utility>

#include "base/bind.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_macros.h"
#include "base/single_thread_task_runner.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/values.h"
#include "net/base/ip_address.h"
#include "net/base/port_util.h"
#include "net/quic/platform/api/quic_hostname_utils.h"
#include "url/gurl.h"

namespace net {

namespace {

// Time to wait before starting an update the http_server_properties_impl_ cache
// from preferences. Scheduling another update during this period will be a
// no-op.
constexpr base::TimeDelta kUpdateCacheDelay = base::TimeDelta::FromSeconds(1);

// Time to wait before starting an update the preferences from the
// http_server_properties_impl_ cache. Scheduling another update during this
// period will be a no-op.
constexpr base::TimeDelta kUpdatePrefsDelay = base::TimeDelta::FromSeconds(60);

// "version" 0 indicates, http_server_properties doesn't have "version"
// property.
const int kMissingVersion = 0;

// The version number of persisted http_server_properties.
const int kVersionNumber = 5;

// Persist 200 MRU AlternateProtocolHostPortPairs.
const int kMaxAlternateProtocolHostsToPersist = 200;

// Persist 300 MRU SupportsSpdyServerHostPortPairs.
const int kMaxSupportsSpdyServerHostsToPersist = 300;

// Persist 200 ServerNetworkStats.
const int kMaxServerNetworkStatsHostsToPersist = 200;

const char kVersionKey[] = "version";
const char kServersKey[] = "servers";
const char kSupportsSpdyKey[] = "supports_spdy";
const char kSupportsQuicKey[] = "supports_quic";
const char kQuicServers[] = "quic_servers";
const char kServerInfoKey[] = "server_info";
const char kUsedQuicKey[] = "used_quic";
const char kAddressKey[] = "address";
const char kAlternativeServiceKey[] = "alternative_service";
const char kProtocolKey[] = "protocol_str";
const char kHostKey[] = "host";
const char kPortKey[] = "port";
const char kExpirationKey[] = "expiration";
const char kNetworkStatsKey[] = "network_stats";
const char kSrttKey[] = "srtt";

}  // namespace

////////////////////////////////////////////////////////////////////////////////
//  HttpServerPropertiesManager

HttpServerPropertiesManager::PrefDelegate::~PrefDelegate() {}

HttpServerPropertiesManager::HttpServerPropertiesManager(
    PrefDelegate* pref_delegate,
    scoped_refptr<base::SingleThreadTaskRunner> pref_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> network_task_runner)
    : pref_task_runner_(std::move(pref_task_runner)),
      pref_delegate_(pref_delegate),
      setting_prefs_(false),
      is_initialized_(false),
      network_task_runner_(std::move(network_task_runner)) {
  DCHECK(pref_task_runner_->RunsTasksOnCurrentThread());
  DCHECK(pref_delegate_);
  pref_weak_ptr_factory_.reset(
      new base::WeakPtrFactory<HttpServerPropertiesManager>(this));
  pref_weak_ptr_ = pref_weak_ptr_factory_->GetWeakPtr();
  pref_cache_update_timer_.reset(new base::OneShotTimer);
  pref_cache_update_timer_->SetTaskRunner(pref_task_runner_);
  pref_delegate_->StartListeningForUpdates(
      base::Bind(&HttpServerPropertiesManager::OnHttpServerPropertiesChanged,
                 base::Unretained(this)));
}

HttpServerPropertiesManager::~HttpServerPropertiesManager() {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  network_weak_ptr_factory_.reset();
}

void HttpServerPropertiesManager::InitializeOnNetworkThread() {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());

  network_weak_ptr_factory_.reset(
      new base::WeakPtrFactory<HttpServerPropertiesManager>(this));
  http_server_properties_impl_.reset(new HttpServerPropertiesImpl());

  network_prefs_update_timer_.reset(new base::OneShotTimer);
  network_prefs_update_timer_->SetTaskRunner(network_task_runner_);
  // UpdateCacheFromPrefsOnPrefThread() will post a task to network thread to
  // update server properties. SetInitialized() will be run after that task is
  // run as |network_task_runner_| is single threaded.
  pref_task_runner_->PostTaskAndReply(
      FROM_HERE,
      base::Bind(&HttpServerPropertiesManager::UpdateCacheFromPrefsOnPrefThread,
                 pref_weak_ptr_),
      base::Bind(&HttpServerPropertiesManager::SetInitialized,
                 network_weak_ptr_factory_->GetWeakPtr()));
}

void HttpServerPropertiesManager::ShutdownOnPrefThread() {
  DCHECK(pref_task_runner_->RunsTasksOnCurrentThread());
  // Cancel any pending updates, and stop listening for pref change updates.
  pref_cache_update_timer_->Stop();
  pref_weak_ptr_factory_.reset();
  pref_delegate_->StopListeningForUpdates();
}

// static
void HttpServerPropertiesManager::SetVersion(
    base::DictionaryValue* http_server_properties_dict,
    int version_number) {
  if (version_number < 0)
    version_number = kVersionNumber;
  DCHECK_LE(version_number, kVersionNumber);
  if (version_number <= kVersionNumber)
    http_server_properties_dict->SetInteger(kVersionKey, version_number);
}

void HttpServerPropertiesManager::Clear() {
  Clear(base::Closure());
}

void HttpServerPropertiesManager::Clear(const base::Closure& completion) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());

  http_server_properties_impl_->Clear();
  UpdatePrefsFromCacheOnNetworkThread(completion);
}

bool HttpServerPropertiesManager::SupportsRequestPriority(
    const url::SchemeHostPort& server) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  return http_server_properties_impl_->SupportsRequestPriority(server);
}

bool HttpServerPropertiesManager::GetSupportsSpdy(
    const url::SchemeHostPort& server) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  return http_server_properties_impl_->GetSupportsSpdy(server);
}

void HttpServerPropertiesManager::SetSupportsSpdy(
    const url::SchemeHostPort& server,
    bool support_spdy) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());

  bool old_support_spdy = http_server_properties_impl_->GetSupportsSpdy(server);
  http_server_properties_impl_->SetSupportsSpdy(server, support_spdy);
  bool new_support_spdy = http_server_properties_impl_->GetSupportsSpdy(server);
  if (old_support_spdy != new_support_spdy)
    ScheduleUpdatePrefsOnNetworkThread(SUPPORTS_SPDY);
}

bool HttpServerPropertiesManager::RequiresHTTP11(const HostPortPair& server) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  return http_server_properties_impl_->RequiresHTTP11(server);
}

void HttpServerPropertiesManager::SetHTTP11Required(
    const HostPortPair& server) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());

  http_server_properties_impl_->SetHTTP11Required(server);
  ScheduleUpdatePrefsOnNetworkThread(HTTP_11_REQUIRED);
}

void HttpServerPropertiesManager::MaybeForceHTTP11(const HostPortPair& server,
                                                   SSLConfig* ssl_config) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  http_server_properties_impl_->MaybeForceHTTP11(server, ssl_config);
}

AlternativeServiceVector HttpServerPropertiesManager::GetAlternativeServices(
    const url::SchemeHostPort& origin) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  return http_server_properties_impl_->GetAlternativeServices(origin);
}

bool HttpServerPropertiesManager::SetAlternativeService(
    const url::SchemeHostPort& origin,
    const AlternativeService& alternative_service,
    base::Time expiration) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  const bool changed = http_server_properties_impl_->SetAlternativeService(
      origin, alternative_service, expiration);
  if (changed) {
    ScheduleUpdatePrefsOnNetworkThread(SET_ALTERNATIVE_SERVICES);
  }
  return changed;
}

bool HttpServerPropertiesManager::SetAlternativeServices(
    const url::SchemeHostPort& origin,
    const AlternativeServiceInfoVector& alternative_service_info_vector) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  const bool changed = http_server_properties_impl_->SetAlternativeServices(
      origin, alternative_service_info_vector);
  if (changed) {
    ScheduleUpdatePrefsOnNetworkThread(SET_ALTERNATIVE_SERVICES);
  }
  return changed;
}

void HttpServerPropertiesManager::MarkAlternativeServiceBroken(
    const AlternativeService& alternative_service) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  http_server_properties_impl_->MarkAlternativeServiceBroken(
      alternative_service);
  ScheduleUpdatePrefsOnNetworkThread(MARK_ALTERNATIVE_SERVICE_BROKEN);
}

void HttpServerPropertiesManager::MarkAlternativeServiceRecentlyBroken(
    const AlternativeService& alternative_service) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  http_server_properties_impl_->MarkAlternativeServiceRecentlyBroken(
      alternative_service);
  ScheduleUpdatePrefsOnNetworkThread(MARK_ALTERNATIVE_SERVICE_RECENTLY_BROKEN);
}

bool HttpServerPropertiesManager::IsAlternativeServiceBroken(
    const AlternativeService& alternative_service) const {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  return http_server_properties_impl_->IsAlternativeServiceBroken(
      alternative_service);
}

bool HttpServerPropertiesManager::WasAlternativeServiceRecentlyBroken(
    const AlternativeService& alternative_service) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  return http_server_properties_impl_->WasAlternativeServiceRecentlyBroken(
      alternative_service);
}

void HttpServerPropertiesManager::ConfirmAlternativeService(
    const AlternativeService& alternative_service) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  bool old_value = http_server_properties_impl_->IsAlternativeServiceBroken(
      alternative_service);
  http_server_properties_impl_->ConfirmAlternativeService(alternative_service);
  bool new_value = http_server_properties_impl_->IsAlternativeServiceBroken(
      alternative_service);
  // For persisting, we only care about the value returned by
  // IsAlternativeServiceBroken. If that value changes, then call persist.
  if (old_value != new_value)
    ScheduleUpdatePrefsOnNetworkThread(CONFIRM_ALTERNATIVE_SERVICE);
}

const AlternativeServiceMap&
HttpServerPropertiesManager::alternative_service_map() const {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  return http_server_properties_impl_->alternative_service_map();
}

std::unique_ptr<base::Value>
HttpServerPropertiesManager::GetAlternativeServiceInfoAsValue() const {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  return http_server_properties_impl_->GetAlternativeServiceInfoAsValue();
}

bool HttpServerPropertiesManager::GetSupportsQuic(
    IPAddress* last_address) const {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  return http_server_properties_impl_->GetSupportsQuic(last_address);
}

void HttpServerPropertiesManager::SetSupportsQuic(bool used_quic,
                                                  const IPAddress& address) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  IPAddress old_last_quic_addr;
  http_server_properties_impl_->GetSupportsQuic(&old_last_quic_addr);
  http_server_properties_impl_->SetSupportsQuic(used_quic, address);
  IPAddress new_last_quic_addr;
  http_server_properties_impl_->GetSupportsQuic(&new_last_quic_addr);
  if (old_last_quic_addr != new_last_quic_addr)
    ScheduleUpdatePrefsOnNetworkThread(SET_SUPPORTS_QUIC);
}

void HttpServerPropertiesManager::SetServerNetworkStats(
    const url::SchemeHostPort& server,
    ServerNetworkStats stats) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  ServerNetworkStats old_stats;
  const ServerNetworkStats* old_stats_ptr =
      http_server_properties_impl_->GetServerNetworkStats(server);
  if (http_server_properties_impl_->GetServerNetworkStats(server))
    old_stats = *old_stats_ptr;
  http_server_properties_impl_->SetServerNetworkStats(server, stats);
  ServerNetworkStats new_stats =
      *(http_server_properties_impl_->GetServerNetworkStats(server));
  if (old_stats != new_stats)
    ScheduleUpdatePrefsOnNetworkThread(SET_SERVER_NETWORK_STATS);
}

const ServerNetworkStats* HttpServerPropertiesManager::GetServerNetworkStats(
    const url::SchemeHostPort& server) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  return http_server_properties_impl_->GetServerNetworkStats(server);
}

const ServerNetworkStatsMap&
HttpServerPropertiesManager::server_network_stats_map() const {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  return http_server_properties_impl_->server_network_stats_map();
}

bool HttpServerPropertiesManager::SetQuicServerInfo(
    const QuicServerId& server_id,
    const std::string& server_info) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  bool changed =
      http_server_properties_impl_->SetQuicServerInfo(server_id, server_info);
  if (changed)
    ScheduleUpdatePrefsOnNetworkThread(SET_QUIC_SERVER_INFO);
  return changed;
}

const std::string* HttpServerPropertiesManager::GetQuicServerInfo(
    const QuicServerId& server_id) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  return http_server_properties_impl_->GetQuicServerInfo(server_id);
}

const QuicServerInfoMap& HttpServerPropertiesManager::quic_server_info_map()
    const {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  return http_server_properties_impl_->quic_server_info_map();
}

size_t HttpServerPropertiesManager::max_server_configs_stored_in_properties()
    const {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  return http_server_properties_impl_
      ->max_server_configs_stored_in_properties();
}

void HttpServerPropertiesManager::SetMaxServerConfigsStoredInProperties(
    size_t max_server_configs_stored_in_properties) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  return http_server_properties_impl_->SetMaxServerConfigsStoredInProperties(
      max_server_configs_stored_in_properties);
}

bool HttpServerPropertiesManager::IsInitialized() const {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());

  return is_initialized_;
}

// static
base::TimeDelta HttpServerPropertiesManager::GetUpdateCacheDelayForTesting() {
  return kUpdateCacheDelay;
}

// static
base::TimeDelta HttpServerPropertiesManager::GetUpdatePrefsDelayForTesting() {
  return kUpdatePrefsDelay;
}

//
// Update the HttpServerPropertiesImpl's cache with data from preferences.
//
void HttpServerPropertiesManager::ScheduleUpdateCacheOnPrefThread() {
  DCHECK(pref_task_runner_->RunsTasksOnCurrentThread());
  // Do not schedule a new update if there is already one scheduled.
  if (pref_cache_update_timer_->IsRunning())
    return;

  pref_cache_update_timer_->Start(
      FROM_HERE, kUpdateCacheDelay, this,
      &HttpServerPropertiesManager::UpdateCacheFromPrefsOnPrefThread);
}

void HttpServerPropertiesManager::UpdateCacheFromPrefsOnPrefThread() {
  // The preferences can only be read on the pref thread.
  DCHECK(pref_task_runner_->RunsTasksOnCurrentThread());

  if (!pref_delegate_->HasServerProperties())
    return;

  bool detected_corrupted_prefs = false;
  const base::DictionaryValue& http_server_properties_dict =
      pref_delegate_->GetServerProperties();

  int version = kMissingVersion;
  if (!http_server_properties_dict.GetIntegerWithoutPathExpansion(kVersionKey,
                                                                  &version)) {
    DVLOG(1) << "Missing version. Clearing all properties.";
    return;
  }

  const base::DictionaryValue* servers_dict = nullptr;
  const base::ListValue* servers_list = nullptr;
  if (version < 4) {
    // The properties for a given server is in
    // http_server_properties_dict["servers"][server].
    // Before Version 4, server data was stored in the following format in
    // alphabetical order.
    //
    //   "http_server_properties": {
    //      "servers": {
    //         "0-edge-chat.facebook.com:443" : {...},
    //         "0.client-channel.google.com:443" : {...},
    //         "yt3.ggpht.com:80" : {...},
    //         ...
    //      }, ...
    // },
    if (!http_server_properties_dict.GetDictionaryWithoutPathExpansion(
            kServersKey, &servers_dict)) {
      DVLOG(1) << "Malformed http_server_properties for servers.";
      return;
    }
  } else {
    // For Version 4, data was stored in the following format.
    // |servers| are saved in MRU order.
    //
    // "http_server_properties": {
    //      "servers": [
    //          {"yt3.ggpht.com:443" : {...}},
    //          {"0.client-channel.google.com:443" : {...}},
    //          {"0-edge-chat.facebook.com:80" : {...}},
    //          ...
    //      ], ...
    // },
    // For Version 5, data was stored in the following format.
    // |servers| are saved in MRU order. |servers| are in the format flattened
    // representation of (scheme/host/port) where port might be ignored if is
    // default with scheme.
    //
    // "http_server_properties": {
    //      "servers": [
    //          {"https://yt3.ggpht.com" : {...}},
    //          {"http://0.client-channel.google.com:443" : {...}},
    //          {"http://0-edge-chat.facebook.com" : {...}},
    //          ...
    //      ], ...
    // },
    if (!http_server_properties_dict.GetListWithoutPathExpansion(
            kServersKey, &servers_list)) {
      DVLOG(1) << "Malformed http_server_properties for servers list.";
      return;
    }
  }

  IPAddress* addr = new IPAddress;
  ReadSupportsQuic(http_server_properties_dict, addr);

  // String is "scheme://host:port" tuple of spdy server.
  std::unique_ptr<ServerList> spdy_servers(new ServerList);
  std::unique_ptr<AlternativeServiceMap> alternative_service_map(
      new AlternativeServiceMap(kMaxAlternateProtocolHostsToPersist));
  std::unique_ptr<ServerNetworkStatsMap> server_network_stats_map(
      new ServerNetworkStatsMap(kMaxServerNetworkStatsHostsToPersist));
  std::unique_ptr<QuicServerInfoMap> quic_server_info_map(
      new QuicServerInfoMap(QuicServerInfoMap::NO_AUTO_EVICT));

  if (version < 4) {
    if (!AddServersData(*servers_dict, spdy_servers.get(),
                        alternative_service_map.get(),
                        server_network_stats_map.get(), version)) {
      detected_corrupted_prefs = true;
    }
  } else {
    for (base::ListValue::const_iterator it = servers_list->begin();
         it != servers_list->end(); ++it) {
      if (!(*it)->GetAsDictionary(&servers_dict)) {
        DVLOG(1) << "Malformed http_server_properties for servers dictionary.";
        detected_corrupted_prefs = true;
        continue;
      }
      if (!AddServersData(*servers_dict, spdy_servers.get(),
                          alternative_service_map.get(),
                          server_network_stats_map.get(), version)) {
        detected_corrupted_prefs = true;
      }
    }
  }

  if (!AddToQuicServerInfoMap(http_server_properties_dict,
                              quic_server_info_map.get())) {
    detected_corrupted_prefs = true;
  }

  network_task_runner_->PostTask(
      FROM_HERE,
      base::Bind(
          &HttpServerPropertiesManager::UpdateCacheFromPrefsOnNetworkThread,
          base::Unretained(this), base::Owned(spdy_servers.release()),
          base::Owned(alternative_service_map.release()), base::Owned(addr),
          base::Owned(server_network_stats_map.release()),
          base::Owned(quic_server_info_map.release()),
          detected_corrupted_prefs));
}

bool HttpServerPropertiesManager::AddServersData(
    const base::DictionaryValue& servers_dict,
    ServerList* spdy_servers,
    AlternativeServiceMap* alternative_service_map,
    ServerNetworkStatsMap* network_stats_map,
    int version) {
  for (base::DictionaryValue::Iterator it(servers_dict); !it.IsAtEnd();
       it.Advance()) {
    // Get server's scheme/host/pair.
    const std::string& server_str = it.key();
    std::string spdy_server_url = server_str;
    if (version < 5) {
      // For old version disk data, always use HTTPS as the scheme.
      spdy_server_url.insert(0, "https://");
    }
    url::SchemeHostPort spdy_server((GURL(spdy_server_url)));
    if (spdy_server.host().empty()) {
      DVLOG(1) << "Malformed http_server_properties for server: " << server_str;
      return false;
    }

    const base::DictionaryValue* server_pref_dict = nullptr;
    if (!it.value().GetAsDictionary(&server_pref_dict)) {
      DVLOG(1) << "Malformed http_server_properties server: " << server_str;
      return false;
    }

    // Get if server supports Spdy.
    bool supports_spdy = false;
    if ((server_pref_dict->GetBoolean(kSupportsSpdyKey, &supports_spdy)) &&
        supports_spdy) {
      spdy_servers->push_back(spdy_server.Serialize());
    }

    if (!AddToAlternativeServiceMap(spdy_server, *server_pref_dict,
                                    alternative_service_map) ||
        !AddToNetworkStatsMap(spdy_server, *server_pref_dict,
                              network_stats_map)) {
      return false;
    }
  }
  return true;
}

bool HttpServerPropertiesManager::ParseAlternativeServiceDict(
    const base::DictionaryValue& alternative_service_dict,
    const std::string& server_str,
    AlternativeServiceInfo* alternative_service_info) {
  // Protocol is mandatory.
  std::string protocol_str;
  if (!alternative_service_dict.GetStringWithoutPathExpansion(kProtocolKey,
                                                              &protocol_str)) {
    DVLOG(1) << "Malformed alternative service protocol string for server: "
             << server_str;
    return false;
  }
  NextProto protocol = NextProtoFromString(protocol_str);
  if (!IsAlternateProtocolValid(protocol)) {
    DVLOG(1) << "Invalid alternative service protocol string for server: "
             << server_str;
    return false;
  }
  alternative_service_info->alternative_service.protocol = protocol;

  // Host is optional, defaults to "".
  alternative_service_info->alternative_service.host.clear();
  if (alternative_service_dict.HasKey(kHostKey) &&
      !alternative_service_dict.GetStringWithoutPathExpansion(
          kHostKey, &(alternative_service_info->alternative_service.host))) {
    DVLOG(1) << "Malformed alternative service host string for server: "
             << server_str;
    return false;
  }

  // Port is mandatory.
  int port = 0;
  if (!alternative_service_dict.GetInteger(kPortKey, &port) ||
      !IsPortValid(port)) {
    DVLOG(1) << "Malformed alternative service port for server: " << server_str;
    return false;
  }
  alternative_service_info->alternative_service.port =
      static_cast<uint32_t>(port);

  // Expiration is optional, defaults to one day.
  base::Time expiration;
  if (!alternative_service_dict.HasKey(kExpirationKey)) {
    alternative_service_info->expiration =
        base::Time::Now() + base::TimeDelta::FromDays(1);
    return true;
  }

  std::string expiration_string;
  if (alternative_service_dict.GetStringWithoutPathExpansion(
          kExpirationKey, &expiration_string)) {
    int64_t expiration_int64 = 0;
    if (!base::StringToInt64(expiration_string, &expiration_int64)) {
      DVLOG(1) << "Malformed alternative service expiration for server: "
               << server_str;
      return false;
    }
    alternative_service_info->expiration =
        base::Time::FromInternalValue(expiration_int64);
    return true;
  }

  DVLOG(1) << "Malformed alternative service expiration for server: "
           << server_str;
  return false;
}

bool HttpServerPropertiesManager::AddToAlternativeServiceMap(
    const url::SchemeHostPort& server,
    const base::DictionaryValue& server_pref_dict,
    AlternativeServiceMap* alternative_service_map) {
  DCHECK(alternative_service_map->Peek(server) ==
         alternative_service_map->end());
  const base::ListValue* alternative_service_list;
  if (!server_pref_dict.GetListWithoutPathExpansion(
          kAlternativeServiceKey, &alternative_service_list)) {
    return true;
  }
  if (server.scheme() != "https") {
    return false;
  }

  AlternativeServiceInfoVector alternative_service_info_vector;
  for (const auto& alternative_service_list_item : *alternative_service_list) {
    const base::DictionaryValue* alternative_service_dict;
    if (!alternative_service_list_item->GetAsDictionary(
            &alternative_service_dict))
      return false;
    AlternativeServiceInfo alternative_service_info;
    if (!ParseAlternativeServiceDict(*alternative_service_dict,
                                     server.Serialize(),
                                     &alternative_service_info)) {
      return false;
    }
    if (base::Time::Now() < alternative_service_info.expiration) {
      alternative_service_info_vector.push_back(alternative_service_info);
    }
  }

  if (alternative_service_info_vector.empty()) {
    return false;
  }

  alternative_service_map->Put(server, alternative_service_info_vector);
  return true;
}

bool HttpServerPropertiesManager::ReadSupportsQuic(
    const base::DictionaryValue& http_server_properties_dict,
    IPAddress* last_quic_address) {
  const base::DictionaryValue* supports_quic_dict = nullptr;
  if (!http_server_properties_dict.GetDictionaryWithoutPathExpansion(
          kSupportsQuicKey, &supports_quic_dict)) {
    return true;
  }
  bool used_quic = false;
  if (!supports_quic_dict->GetBooleanWithoutPathExpansion(kUsedQuicKey,
                                                          &used_quic)) {
    DVLOG(1) << "Malformed SupportsQuic";
    return false;
  }
  if (!used_quic)
    return false;

  std::string address;
  if (!supports_quic_dict->GetStringWithoutPathExpansion(kAddressKey,
                                                         &address) ||
      !last_quic_address->AssignFromIPLiteral(address)) {
    DVLOG(1) << "Malformed SupportsQuic";
    return false;
  }
  return true;
}

bool HttpServerPropertiesManager::AddToNetworkStatsMap(
    const url::SchemeHostPort& server,
    const base::DictionaryValue& server_pref_dict,
    ServerNetworkStatsMap* network_stats_map) {
  DCHECK(network_stats_map->Peek(server) == network_stats_map->end());
  const base::DictionaryValue* server_network_stats_dict = nullptr;
  if (!server_pref_dict.GetDictionaryWithoutPathExpansion(
          kNetworkStatsKey, &server_network_stats_dict)) {
    return true;
  }
  int srtt;
  if (!server_network_stats_dict->GetIntegerWithoutPathExpansion(kSrttKey,
                                                                 &srtt)) {
    DVLOG(1) << "Malformed ServerNetworkStats for server: "
             << server.Serialize();
    return false;
  }
  ServerNetworkStats server_network_stats;
  server_network_stats.srtt = base::TimeDelta::FromInternalValue(srtt);
  // TODO(rtenneti): When QUIC starts using bandwidth_estimate, then persist
  // bandwidth_estimate.
  network_stats_map->Put(server, server_network_stats);
  return true;
}

bool HttpServerPropertiesManager::AddToQuicServerInfoMap(
    const base::DictionaryValue& http_server_properties_dict,
    QuicServerInfoMap* quic_server_info_map) {
  const base::DictionaryValue* quic_servers_dict = nullptr;
  if (!http_server_properties_dict.GetDictionaryWithoutPathExpansion(
          kQuicServers, &quic_servers_dict)) {
    DVLOG(1) << "Malformed http_server_properties for quic_servers.";
    return true;
  }

  bool detected_corrupted_prefs = false;
  for (base::DictionaryValue::Iterator it(*quic_servers_dict); !it.IsAtEnd();
       it.Advance()) {
    // Get quic_server_id.
    const std::string& quic_server_id_str = it.key();
    QuicServerId quic_server_id;
    QuicHostnameUtils::StringToQuicServerId(quic_server_id_str,
                                            &quic_server_id);
    if (quic_server_id.host().empty()) {
      DVLOG(1) << "Malformed http_server_properties for quic server: "
               << quic_server_id_str;
      detected_corrupted_prefs = true;
      continue;
    }

    const base::DictionaryValue* quic_server_pref_dict = nullptr;
    if (!it.value().GetAsDictionary(&quic_server_pref_dict)) {
      DVLOG(1) << "Malformed http_server_properties quic server dict: "
               << quic_server_id_str;
      detected_corrupted_prefs = true;
      continue;
    }

    std::string quic_server_info;
    if (!quic_server_pref_dict->GetStringWithoutPathExpansion(
            kServerInfoKey, &quic_server_info)) {
      DVLOG(1) << "Malformed http_server_properties quic server info: "
               << quic_server_id_str;
      detected_corrupted_prefs = true;
      continue;
    }
    quic_server_info_map->Put(quic_server_id, quic_server_info);
  }
  return !detected_corrupted_prefs;
}

void HttpServerPropertiesManager::UpdateCacheFromPrefsOnNetworkThread(
    ServerList* spdy_servers,
    AlternativeServiceMap* alternative_service_map,
    IPAddress* last_quic_address,
    ServerNetworkStatsMap* server_network_stats_map,
    QuicServerInfoMap* quic_server_info_map,
    bool detected_corrupted_prefs) {
  // Preferences have the master data because admins might have pushed new
  // preferences. Update the cached data with new data from preferences.
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());

  UMA_HISTOGRAM_COUNTS("Net.CountOfSpdyServers", spdy_servers->size());
  http_server_properties_impl_->SetSpdyServers(spdy_servers, true);

  // Update the cached data and use the new alternative service list from
  // preferences.
  UMA_HISTOGRAM_COUNTS("Net.CountOfAlternateProtocolServers",
                       alternative_service_map->size());
  http_server_properties_impl_->SetAlternativeServiceServers(
      alternative_service_map);

  http_server_properties_impl_->SetSupportsQuic(last_quic_address);

  http_server_properties_impl_->SetServerNetworkStats(server_network_stats_map);

  UMA_HISTOGRAM_COUNTS_1000("Net.CountOfQuicServerInfos",
                            quic_server_info_map->size());

  http_server_properties_impl_->SetQuicServerInfoMap(quic_server_info_map);

  // Update the prefs with what we have read (delete all corrupted prefs).
  if (detected_corrupted_prefs)
    ScheduleUpdatePrefsOnNetworkThread(DETECTED_CORRUPTED_PREFS);
}

//
// Update Preferences with data from the cached data.
//
void HttpServerPropertiesManager::ScheduleUpdatePrefsOnNetworkThread(
    Location location) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  // Do not schedule a new update if there is already one scheduled.
  if (network_prefs_update_timer_->IsRunning())
    return;

  network_prefs_update_timer_->Start(
      FROM_HERE, kUpdatePrefsDelay, this,
      &HttpServerPropertiesManager::UpdatePrefsFromCacheOnNetworkThread);

  // TODO(rtenneti): Delete the following histogram after collecting some data.
  UMA_HISTOGRAM_ENUMERATION("Net.HttpServerProperties.UpdatePrefs", location,
                            HttpServerPropertiesManager::NUM_LOCATIONS);
}

// This is required so we can set this as the callback for a timer.
void HttpServerPropertiesManager::UpdatePrefsFromCacheOnNetworkThread() {
  UpdatePrefsFromCacheOnNetworkThread(base::Closure());
}

void HttpServerPropertiesManager::UpdatePrefsFromCacheOnNetworkThread(
    const base::Closure& completion) {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());

  // It is in MRU order.
  base::ListValue* spdy_server_list = new base::ListValue;
  http_server_properties_impl_->GetSpdyServerList(
      spdy_server_list, kMaxSupportsSpdyServerHostsToPersist);

  AlternativeServiceMap* alternative_service_map =
      new AlternativeServiceMap(kMaxAlternateProtocolHostsToPersist);
  const AlternativeServiceMap& map =
      http_server_properties_impl_->alternative_service_map();
  UMA_HISTOGRAM_COUNTS("Net.CountOfAlternateProtocolServers.Memory",
                       map.size());
  int count = 0;
  typedef std::map<std::string, bool> CanonicalHostPersistedMap;
  CanonicalHostPersistedMap persisted_map;
  // Maintain MRU order.
  for (AlternativeServiceMap::const_reverse_iterator it = map.rbegin();
       it != map.rend() && count < kMaxAlternateProtocolHostsToPersist; ++it) {
    const url::SchemeHostPort& server = it->first;
    AlternativeServiceInfoVector notbroken_alternative_service_info_vector;
    for (const AlternativeServiceInfo& alternative_service_info : it->second) {
      // Do not persist expired entries.
      if (alternative_service_info.expiration < base::Time::Now()) {
        continue;
      }
      AlternativeService alternative_service(
          alternative_service_info.alternative_service);
      if (!IsAlternateProtocolValid(alternative_service.protocol)) {
        continue;
      }
      if (alternative_service.host.empty()) {
        alternative_service.host = server.host();
      }
      if (IsAlternativeServiceBroken(alternative_service)) {
        continue;
      }
      notbroken_alternative_service_info_vector.push_back(
          alternative_service_info);
    }
    if (notbroken_alternative_service_info_vector.empty()) {
      continue;
    }
    const std::string* canonical_suffix =
        http_server_properties_impl_->GetCanonicalSuffix(server.host());
    if (canonical_suffix != nullptr) {
      if (persisted_map.find(*canonical_suffix) != persisted_map.end())
        continue;
      persisted_map[*canonical_suffix] = true;
    }
    alternative_service_map->Put(server,
                                 notbroken_alternative_service_info_vector);
    ++count;
  }

  ServerNetworkStatsMap* server_network_stats_map =
      new ServerNetworkStatsMap(kMaxServerNetworkStatsHostsToPersist);
  const ServerNetworkStatsMap& network_stats_map =
      http_server_properties_impl_->server_network_stats_map();
  count = 0;
  for (ServerNetworkStatsMap::const_reverse_iterator
           it = network_stats_map.rbegin();
       it != network_stats_map.rend() &&
       count < kMaxServerNetworkStatsHostsToPersist;
       ++it, ++count) {
    server_network_stats_map->Put(it->first, it->second);
  }

  QuicServerInfoMap* quic_server_info_map = nullptr;
  const QuicServerInfoMap& main_quic_server_info_map =
      http_server_properties_impl_->quic_server_info_map();
  if (main_quic_server_info_map.size() > 0) {
    quic_server_info_map =
        new QuicServerInfoMap(max_server_configs_stored_in_properties());
    for (const std::pair<const QuicServerId, std::string>& entry :
         main_quic_server_info_map) {
      quic_server_info_map->Put(entry.first, entry.second);
    }
  }

  IPAddress* last_quic_addr = new IPAddress;
  http_server_properties_impl_->GetSupportsQuic(last_quic_addr);
  // Update the preferences on the pref thread.
  pref_task_runner_->PostTask(
      FROM_HERE,
      base::Bind(
          &HttpServerPropertiesManager::UpdatePrefsOnPrefThread, pref_weak_ptr_,
          base::Owned(spdy_server_list), base::Owned(alternative_service_map),
          base::Owned(last_quic_addr), base::Owned(server_network_stats_map),
          base::Owned(quic_server_info_map), completion));
}

// A local or temporary data structure to hold |supports_spdy|, SpdySettings,
// AlternativeServiceInfoVector, and SupportsQuic preferences for a server. This
// is used only in UpdatePrefsOnPrefThread.
struct ServerPref {
  ServerPref()
      : supports_spdy(false),
        settings_map(nullptr),
        alternative_service_info_vector(nullptr),
        supports_quic(nullptr),
        server_network_stats(nullptr) {}
  ServerPref(
      bool supports_spdy,
      const SettingsMap* settings_map,
      const AlternativeServiceInfoVector* alternative_service_info_vector,
      const SupportsQuic* supports_quic,
      const ServerNetworkStats* server_network_stats)
      : supports_spdy(supports_spdy),
        settings_map(settings_map),
        alternative_service_info_vector(alternative_service_info_vector),
        supports_quic(supports_quic),
        server_network_stats(server_network_stats) {}
  bool supports_spdy;
  const SettingsMap* settings_map;
  const AlternativeServiceInfoVector* alternative_service_info_vector;
  const SupportsQuic* supports_quic;
  const ServerNetworkStats* server_network_stats;
};

// All maps and lists are in MRU order.
void HttpServerPropertiesManager::UpdatePrefsOnPrefThread(
    base::ListValue* spdy_server_list,
    AlternativeServiceMap* alternative_service_map,
    IPAddress* last_quic_address,
    ServerNetworkStatsMap* server_network_stats_map,
    QuicServerInfoMap* quic_server_info_map,
    const base::Closure& completion) {
  typedef base::MRUCache<url::SchemeHostPort, ServerPref> ServerPrefMap;
  ServerPrefMap server_pref_map(ServerPrefMap::NO_AUTO_EVICT);

  DCHECK(pref_task_runner_->RunsTasksOnCurrentThread());

  // Add servers that support spdy to server_pref_map in the MRU order.
  for (size_t index = spdy_server_list->GetSize(); index > 0; --index) {
    std::string server_str;
    if (spdy_server_list->GetString(index - 1, &server_str)) {
      url::SchemeHostPort server((GURL(server_str)));
      ServerPrefMap::iterator it = server_pref_map.Get(server);
      if (it == server_pref_map.end()) {
        ServerPref server_pref;
        server_pref.supports_spdy = true;
        server_pref_map.Put(server, server_pref);
      } else {
        it->second.supports_spdy = true;
      }
    }
  }

  // Add alternative services to server_pref_map in the MRU order.
  for (AlternativeServiceMap::const_reverse_iterator map_it =
           alternative_service_map->rbegin();
       map_it != alternative_service_map->rend(); ++map_it) {
    const url::SchemeHostPort server = map_it->first;
    ServerPrefMap::iterator it = server_pref_map.Get(server);
    if (it == server_pref_map.end()) {
      ServerPref server_pref;
      server_pref.alternative_service_info_vector = &map_it->second;
      server_pref_map.Put(server, server_pref);
    } else {
      it->second.alternative_service_info_vector = &map_it->second;
    }
  }

  // Add ServerNetworkStats servers to server_pref_map in the MRU order.
  for (ServerNetworkStatsMap::const_reverse_iterator map_it =
           server_network_stats_map->rbegin();
       map_it != server_network_stats_map->rend(); ++map_it) {
    const url::SchemeHostPort server = map_it->first;
    ServerPrefMap::iterator it = server_pref_map.Get(server);
    if (it == server_pref_map.end()) {
      ServerPref server_pref;
      server_pref.server_network_stats = &map_it->second;
      server_pref_map.Put(server, server_pref);
    } else {
      it->second.server_network_stats = &map_it->second;
    }
  }

  // Persist properties to the prefs in the MRU order.
  base::DictionaryValue http_server_properties_dict;
  base::ListValue* servers_list = new base::ListValue;
  for (ServerPrefMap::const_reverse_iterator map_it = server_pref_map.rbegin();
       map_it != server_pref_map.rend(); ++map_it) {
    const url::SchemeHostPort server = map_it->first;
    const ServerPref& server_pref = map_it->second;

    auto servers_dict = base::MakeUnique<base::DictionaryValue>();
    auto server_pref_dict = base::MakeUnique<base::DictionaryValue>();

    // Save supports_spdy.
    if (server_pref.supports_spdy)
      server_pref_dict->SetBoolean(kSupportsSpdyKey, server_pref.supports_spdy);
    SaveAlternativeServiceToServerPrefs(
        server_pref.alternative_service_info_vector, server_pref_dict.get());
    SaveNetworkStatsToServerPrefs(server_pref.server_network_stats,
                                  server_pref_dict.get());

    servers_dict->SetWithoutPathExpansion(server.Serialize(),
                                          std::move(server_pref_dict));
    bool value = servers_list->AppendIfNotPresent(std::move(servers_dict));
    DCHECK(value);  // Should never happen.
  }

  http_server_properties_dict.SetWithoutPathExpansion(kServersKey,
                                                      servers_list);
  SetVersion(&http_server_properties_dict, kVersionNumber);

  SaveSupportsQuicToPrefs(last_quic_address, &http_server_properties_dict);

  SaveQuicServerInfoMapToServerPrefs(quic_server_info_map,
                                     &http_server_properties_dict);

  setting_prefs_ = true;
  pref_delegate_->SetServerProperties(http_server_properties_dict);
  setting_prefs_ = false;

  // Note that |completion| will be fired after we have written everything to
  // the Preferences, but likely before these changes are serialized to disk.
  // This is not a problem though, as JSONPrefStore guarantees that this will
  // happen, pretty soon, and even in the case we shut down immediately.
  if (!completion.is_null())
    completion.Run();
}

void HttpServerPropertiesManager::SaveAlternativeServiceToServerPrefs(
    const AlternativeServiceInfoVector* alternative_service_info_vector,
    base::DictionaryValue* server_pref_dict) {
  if (!alternative_service_info_vector ||
      alternative_service_info_vector->empty()) {
    return;
  }
  std::unique_ptr<base::ListValue> alternative_service_list(
      new base::ListValue);
  for (const AlternativeServiceInfo& alternative_service_info :
       *alternative_service_info_vector) {
    const AlternativeService alternative_service =
        alternative_service_info.alternative_service;
    DCHECK(IsAlternateProtocolValid(alternative_service.protocol));
    std::unique_ptr<base::DictionaryValue> alternative_service_dict(
        new base::DictionaryValue);
    alternative_service_dict->SetInteger(kPortKey, alternative_service.port);
    if (!alternative_service.host.empty()) {
      alternative_service_dict->SetString(kHostKey, alternative_service.host);
    }
    alternative_service_dict->SetString(
        kProtocolKey, NextProtoToString(alternative_service.protocol));
    // JSON cannot store int64_t, so expiration is converted to a string.
    alternative_service_dict->SetString(
        kExpirationKey,
        base::Int64ToString(
            alternative_service_info.expiration.ToInternalValue()));
    alternative_service_list->Append(std::move(alternative_service_dict));
  }
  if (alternative_service_list->GetSize() == 0)
    return;
  server_pref_dict->SetWithoutPathExpansion(kAlternativeServiceKey,
                                            alternative_service_list.release());
}

void HttpServerPropertiesManager::SaveSupportsQuicToPrefs(
    const IPAddress* last_quic_address,
    base::DictionaryValue* http_server_properties_dict) {
  if (!last_quic_address || !last_quic_address->IsValid())
    return;

  base::DictionaryValue* supports_quic_dict = new base::DictionaryValue;
  supports_quic_dict->SetBoolean(kUsedQuicKey, true);
  supports_quic_dict->SetString(kAddressKey, last_quic_address->ToString());
  http_server_properties_dict->SetWithoutPathExpansion(kSupportsQuicKey,
                                                       supports_quic_dict);
}

void HttpServerPropertiesManager::SaveNetworkStatsToServerPrefs(
    const ServerNetworkStats* server_network_stats,
    base::DictionaryValue* server_pref_dict) {
  if (!server_network_stats)
    return;

  base::DictionaryValue* server_network_stats_dict = new base::DictionaryValue;
  // Becasue JSON doesn't support int64_t, persist int64_t as a string.
  server_network_stats_dict->SetInteger(
      kSrttKey, static_cast<int>(server_network_stats->srtt.ToInternalValue()));
  // TODO(rtenneti): When QUIC starts using bandwidth_estimate, then persist
  // bandwidth_estimate.
  server_pref_dict->SetWithoutPathExpansion(kNetworkStatsKey,
                                            server_network_stats_dict);
}

void HttpServerPropertiesManager::SaveQuicServerInfoMapToServerPrefs(
    QuicServerInfoMap* quic_server_info_map,
    base::DictionaryValue* http_server_properties_dict) {
  if (!quic_server_info_map)
    return;

  base::DictionaryValue* quic_servers_dict = new base::DictionaryValue;
  for (const std::pair<QuicServerId, std::string>& entry :
       *quic_server_info_map) {
    const QuicServerId& server_id = entry.first;
    base::DictionaryValue* quic_server_pref_dict = new base::DictionaryValue;
    quic_server_pref_dict->SetStringWithoutPathExpansion(kServerInfoKey,
                                                         entry.second);
    quic_servers_dict->SetWithoutPathExpansion(server_id.ToString(),
                                               quic_server_pref_dict);
  }
  http_server_properties_dict->SetWithoutPathExpansion(kQuicServers,
                                                       quic_servers_dict);
}

void HttpServerPropertiesManager::OnHttpServerPropertiesChanged() {
  DCHECK(pref_task_runner_->RunsTasksOnCurrentThread());
  if (!setting_prefs_)
    ScheduleUpdateCacheOnPrefThread();
}

void HttpServerPropertiesManager::SetInitialized() {
  DCHECK(network_task_runner_->RunsTasksOnCurrentThread());
  is_initialized_ = true;
}

}  // namespace net
