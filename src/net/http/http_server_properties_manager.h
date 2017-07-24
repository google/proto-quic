// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_HTTP_SERVER_PROPERTIES_MANAGER_H_
#define NET_HTTP_HTTP_SERVER_PROPERTIES_MANAGER_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "base/compiler_specific.h"
#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/time/default_tick_clock.h"
#include "base/timer/timer.h"
#include "base/values.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_export.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_server_properties_impl.h"
#include "net/log/net_log_with_source.h"

namespace base {
class SingleThreadTaskRunner;
}

namespace net {

class IPAddress;

////////////////////////////////////////////////////////////////////////////////
// HttpServerPropertiesManager

// The manager for creating and updating an HttpServerProperties (for example it
// tracks if a server supports SPDY or not).
//
// This class interacts with both the pref thread, where notifications of pref
// changes are received from, and the network thread, which owns it, and it
// persists the changes from network stack whether server supports SPDY or not.
//
// There are two SingleThreadTaskRunners:
// |pref_task_runner_| should be bound with the pref thread and is used to post
// cache update to the pref thread;
// |network_task_runner_| should be bound with the network thread and is used
// to post pref update to the cache thread.
//
// It must be constructed with correct task runners passed in to set up
// |pref_task_runner_| and |network_task_runner| as well as the prefs listeners.
//
// ShutdownOnPrefSequence must be called from pref thread before destruction, to
// release the prefs listeners on the pref thread.
//
// Class requires that update tasks from the Pref thread can post safely to the
// network thread, so the destruction order must guarantee that if |this|
// exists in pref thread, then a potential destruction on network thread will
// come after any task posted to network thread from that method on pref thread.
// This is used to go through network thread before the actual update starts,
// and grab a WeakPtr.
class NET_EXPORT HttpServerPropertiesManager : public HttpServerProperties {
 public:
  // Provides an interface to interface with persistent preferences storage
  // implemented by the embedder.
  class NET_EXPORT PrefDelegate {
   public:
    virtual ~PrefDelegate();

    // Returns true if the pref system has data for the server properties.
    virtual bool HasServerProperties() = 0;

    // Returns the branch of the preferences system for the server properties.
    virtual const base::DictionaryValue& GetServerProperties() const = 0;

    // Sets the server properties to the given value.
    virtual void SetServerProperties(const base::DictionaryValue& value) = 0;

    // Start and stop listening for external storage changes. There will only
    // be one callback active at a time.
    virtual void StartListeningForUpdates(const base::Closure& callback) = 0;
    virtual void StopListeningForUpdates() = 0;
  };

  // Create an instance of the HttpServerPropertiesManager.
  //
  // Ownership of the PrefDelegate pointer is taken by this class. This is
  // passed as a raw pointer rather than a scoped_refptr currently because
  // the test uses gmock and it doesn't forward move semantics properly.
  //
  // There are two SingleThreadTaskRunners:
  // |pref_task_runner| should be bound with the pref thread and is used to post
  // cache update to the pref thread;
  // |network_task_runner| should be bound with the network thread and is used
  // to post pref update to the cache thread.
  //
  // |clock| is used for setting expiration times and scheduling the
  // expiration of broken alternative services. If null, the default clock will
  // be used.
  HttpServerPropertiesManager(
      PrefDelegate* pref_delegate,
      scoped_refptr<base::SingleThreadTaskRunner> pref_task_runner,
      scoped_refptr<base::SingleThreadTaskRunner> network_task_runner,
      NetLog* net_log,
      base::TickClock* clock);

  // Default clock will be used.
  HttpServerPropertiesManager(
      PrefDelegate* pref_delegate,
      scoped_refptr<base::SingleThreadTaskRunner> pref_task_runner,
      scoped_refptr<base::SingleThreadTaskRunner> network_task_runner,
      NetLog* net_log);

  ~HttpServerPropertiesManager() override;

  // Initialize on Network thread.
  void InitializeOnNetworkSequence();

  // Prepare for shutdown. Must be called on the Pref thread before destruction.
  void ShutdownOnPrefSequence();

  // Helper function for unit tests to set the version in the dictionary.
  static void SetVersion(base::DictionaryValue* http_server_properties_dict,
                         int version_number);

  // Deletes all data. Works asynchronously, but if a |completion| callback is
  // provided, it will be fired on the pref thread when everything is done.
  void Clear(const base::Closure& completion);

  // ----------------------------------
  // HttpServerProperties methods:
  // ----------------------------------

  void Clear() override;
  bool SupportsRequestPriority(const url::SchemeHostPort& server) override;
  bool GetSupportsSpdy(const url::SchemeHostPort& server) override;
  void SetSupportsSpdy(const url::SchemeHostPort& server,
                       bool support_spdy) override;
  bool RequiresHTTP11(const HostPortPair& server) override;
  void SetHTTP11Required(const HostPortPair& server) override;
  void MaybeForceHTTP11(const HostPortPair& server,
                        SSLConfig* ssl_config) override;
  AlternativeServiceInfoVector GetAlternativeServiceInfos(
      const url::SchemeHostPort& origin) override;
  bool SetHttp2AlternativeService(const url::SchemeHostPort& origin,
                                  const AlternativeService& alternative_service,
                                  base::Time expiration) override;
  bool SetQuicAlternativeService(
      const url::SchemeHostPort& origin,
      const AlternativeService& alternative_service,
      base::Time expiration,
      const QuicVersionVector& advertised_versions) override;
  bool SetAlternativeServices(const url::SchemeHostPort& origin,
                              const AlternativeServiceInfoVector&
                                  alternative_service_info_vector) override;
  void MarkAlternativeServiceBroken(
      const AlternativeService& alternative_service) override;
  void MarkAlternativeServiceRecentlyBroken(
      const AlternativeService& alternative_service) override;
  bool IsAlternativeServiceBroken(
      const AlternativeService& alternative_service) const override;
  bool WasAlternativeServiceRecentlyBroken(
      const AlternativeService& alternative_service) override;
  void ConfirmAlternativeService(
      const AlternativeService& alternative_service) override;
  const AlternativeServiceMap& alternative_service_map() const override;
  std::unique_ptr<base::Value> GetAlternativeServiceInfoAsValue()
      const override;
  bool GetSupportsQuic(IPAddress* last_address) const override;
  void SetSupportsQuic(bool used_quic, const IPAddress& last_address) override;
  void SetServerNetworkStats(const url::SchemeHostPort& server,
                             ServerNetworkStats stats) override;
  void ClearServerNetworkStats(const url::SchemeHostPort& server) override;
  const ServerNetworkStats* GetServerNetworkStats(
      const url::SchemeHostPort& server) override;
  const ServerNetworkStatsMap& server_network_stats_map() const override;
  bool SetQuicServerInfo(const QuicServerId& server_id,
                         const std::string& server_info) override;
  const std::string* GetQuicServerInfo(const QuicServerId& server_id) override;
  const QuicServerInfoMap& quic_server_info_map() const override;
  size_t max_server_configs_stored_in_properties() const override;
  void SetMaxServerConfigsStoredInProperties(
      size_t max_server_configs_stored_in_properties) override;
  bool IsInitialized() const override;

  static base::TimeDelta GetUpdateCacheDelayForTesting();
  static base::TimeDelta GetUpdatePrefsDelayForTesting();

 protected:
  // The location where ScheduleUpdatePrefsOnNetworkSequence was called.
  // Must be kept up to date with HttpServerPropertiesUpdatePrefsLocation in
  // histograms.xml.
  enum Location {
    SUPPORTS_SPDY = 0,
    HTTP_11_REQUIRED = 1,
    SET_ALTERNATIVE_SERVICES = 2,
    MARK_ALTERNATIVE_SERVICE_BROKEN = 3,
    MARK_ALTERNATIVE_SERVICE_RECENTLY_BROKEN = 4,
    CONFIRM_ALTERNATIVE_SERVICE = 5,
    CLEAR_ALTERNATIVE_SERVICE = 6,
    // deprecated: SET_SPDY_SETTING = 7,
    // deprecated: CLEAR_SPDY_SETTINGS = 8,
    // deprecated: CLEAR_ALL_SPDY_SETTINGS = 9,
    SET_SUPPORTS_QUIC = 10,
    SET_SERVER_NETWORK_STATS = 11,
    DETECTED_CORRUPTED_PREFS = 12,
    SET_QUIC_SERVER_INFO = 13,
    CLEAR_SERVER_NETWORK_STATS = 14,
    NUM_LOCATIONS = 15,
  };

  // --------------------
  // SPDY related methods

  // These are used to delay updating of the cached data in
  // |http_server_properties_impl_| while the preferences are changing, and
  // execute only one update per simultaneous prefs changes.
  void ScheduleUpdateCacheOnPrefThread();

  // Update cached prefs in |http_server_properties_impl_| with data from
  // preferences. It gets the data on pref thread and calls
  // UpdateSpdyServersFromPrefsOnNetworkThread() to perform the update on
  // network thread.
  virtual void UpdateCacheFromPrefsOnPrefSequence();

  // Starts the update of cached prefs in |http_server_properties_impl_| on the
  // network thread. Protected for testing.
  void UpdateCacheFromPrefsOnNetworkSequence(
      std::unique_ptr<SpdyServersMap> spdy_servers_map,
      std::unique_ptr<AlternativeServiceMap> alternative_service_map,
      std::unique_ptr<IPAddress> last_quic_address,
      std::unique_ptr<ServerNetworkStatsMap> server_network_stats_map,
      std::unique_ptr<QuicServerInfoMap> quic_server_info_map,
      std::unique_ptr<BrokenAlternativeServiceList>
          broken_alternative_service_list,
      std::unique_ptr<RecentlyBrokenAlternativeServices>
          recently_broken_alternative_services,
      bool detected_corrupted_prefs);

  // These are used to delay updating the preferences when cached data in
  // |http_server_properties_impl_| is changing, and execute only one update per
  // simultaneous changes.
  // |location| specifies where this method is called from. Virtual for testing.
  virtual void ScheduleUpdatePrefsOnNetworkSequence(Location location);

  // Update prefs::kHttpServerProperties in preferences with the cached data
  // from |http_server_properties_impl_|. This gets the data on network thread
  // and posts a task (UpdatePrefsOnPrefThread) to update preferences on pref
  // thread.
  void UpdatePrefsFromCacheOnNetworkSequence();

  // Same as above, but fires an optional |completion| callback on pref thread
  // when finished. Virtual for testing.
  virtual void UpdatePrefsFromCacheOnNetworkSequence(
      const base::Closure& completion);

  // Update prefs::kHttpServerProperties preferences on pref thread. Executes an
  // optional |completion| callback when finished. Protected for testing.
  void UpdatePrefsOnPrefThread(
      std::unique_ptr<std::vector<std::string>> spdy_servers,
      std::unique_ptr<AlternativeServiceMap> alternative_service_map,
      std::unique_ptr<IPAddress> last_quic_address,
      std::unique_ptr<ServerNetworkStatsMap> server_network_stats_map,
      std::unique_ptr<QuicServerInfoMap> quic_server_info_map,
      std::unique_ptr<BrokenAlternativeServiceList>
          broken_alternative_service_list,
      std::unique_ptr<RecentlyBrokenAlternativeServices>
          recently_broken_alternative_services,
      const base::Closure& completion);

 private:
  FRIEND_TEST_ALL_PREFIXES(HttpServerPropertiesManagerTest,
                           AddToAlternativeServiceMap);
  FRIEND_TEST_ALL_PREFIXES(HttpServerPropertiesManagerTest,
                           ReadAdvertisedVersionsFromPref);
  FRIEND_TEST_ALL_PREFIXES(HttpServerPropertiesManagerTest,
                           DoNotLoadAltSvcForInsecureOrigins);
  FRIEND_TEST_ALL_PREFIXES(HttpServerPropertiesManagerTest,
                           DoNotLoadExpiredAlternativeService);
  void OnHttpServerPropertiesChanged();

  bool AddServersData(const base::DictionaryValue& server_dict,
                      SpdyServersMap* spdy_servers_map,
                      AlternativeServiceMap* alternative_service_map,
                      ServerNetworkStatsMap* network_stats_map,
                      int version);
  // Helper method used for parsing an alternative service from JSON.
  // |dict| is the JSON dictionary to be parsed. It should contain fields
  // corresponding to members of AlternativeService.
  // |host_optional| determines whether or not the "host" field is optional. If
  // optional, the default value is empty string.
  // |parsing_under| is used only for debug log outputs in case of error; it
  // should describe what section of the JSON prefs is currently being parsed.
  // |alternative_service| is the output of parsing |dict|.
  // Return value is true if parsing is successful.
  bool ParseAlternativeServiceDict(const base::DictionaryValue& dict,
                                   bool host_optional,
                                   const std::string& parsing_under,
                                   AlternativeService* alternative_service);
  bool ParseAlternativeServiceInfoDictOfServer(
      const base::DictionaryValue& dict,
      const std::string& server_str,
      AlternativeServiceInfo* alternative_service_info);
  bool AddToAlternativeServiceMap(
      const url::SchemeHostPort& server,
      const base::DictionaryValue& server_dict,
      AlternativeServiceMap* alternative_service_map);
  bool ReadSupportsQuic(const base::DictionaryValue& server_dict,
                        IPAddress* last_quic_address);
  bool AddToNetworkStatsMap(const url::SchemeHostPort& server,
                            const base::DictionaryValue& server_dict,
                            ServerNetworkStatsMap* network_stats_map);
  bool AddToQuicServerInfoMap(const base::DictionaryValue& server_dict,
                              QuicServerInfoMap* quic_server_info_map);
  bool AddToBrokenAlternativeServices(
      const base::DictionaryValue& broken_alt_svc_entry_dict,
      BrokenAlternativeServiceList* broken_alternative_service_list,
      RecentlyBrokenAlternativeServices* recently_broken_alternative_services);

  void SaveAlternativeServiceToServerPrefs(
      const AlternativeServiceInfoVector& alternative_service_info_vector,
      base::DictionaryValue* server_pref_dict);
  void SaveSupportsQuicToPrefs(
      const IPAddress& last_quic_address,
      base::DictionaryValue* http_server_properties_dict);
  void SaveNetworkStatsToServerPrefs(
      const ServerNetworkStats& server_network_stats,
      base::DictionaryValue* server_pref_dict);
  void SaveQuicServerInfoMapToServerPrefs(
      const QuicServerInfoMap& quic_server_info_map,
      base::DictionaryValue* http_server_properties_dict);
  void SaveBrokenAlternativeServicesToPrefs(
      const BrokenAlternativeServiceList* broken_alternative_service_list,
      const RecentlyBrokenAlternativeServices*
          recently_broken_alternative_services,
      base::DictionaryValue* http_server_properties_dict);

  void SetInitialized();

  base::DefaultTickClock default_clock_;

  // -----------
  // Pref thread
  // -----------

  const scoped_refptr<base::SingleThreadTaskRunner> pref_task_runner_;

  base::WeakPtr<HttpServerPropertiesManager> pref_weak_ptr_;

  // Used to post cache update tasks.
  std::unique_ptr<base::OneShotTimer> pref_cache_update_timer_;

  std::unique_ptr<PrefDelegate> pref_delegate_;
  bool setting_prefs_;

  base::TickClock* clock_;  // Unowned

  // --------------
  // Network thread
  // --------------

  // Whether InitializeOnNetworkSequence() has completed.
  bool is_initialized_;

  const scoped_refptr<base::SingleThreadTaskRunner> network_task_runner_;

  // Used to post |prefs::kHttpServerProperties| pref update tasks.
  std::unique_ptr<base::OneShotTimer> network_prefs_update_timer_;

  std::unique_ptr<HttpServerPropertiesImpl> http_server_properties_impl_;

  // Used to get |weak_ptr_| to self on the pref thread.
  std::unique_ptr<base::WeakPtrFactory<HttpServerPropertiesManager>>
      pref_weak_ptr_factory_;

  // Used to get |weak_ptr_| to self on the network thread.
  std::unique_ptr<base::WeakPtrFactory<HttpServerPropertiesManager>>
      network_weak_ptr_factory_;

  const NetLogWithSource net_log_;

  DISALLOW_COPY_AND_ASSIGN(HttpServerPropertiesManager);
};

}  // namespace net

#endif  // NET_HTTP_HTTP_SERVER_PROPERTIES_MANAGER_H_
