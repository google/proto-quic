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
#include "base/timer/timer.h"
#include "base/values.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_export.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_server_properties_impl.h"

namespace base {
class SequencedTaskRunner;
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
// It must be constructed on the pref thread, to set up |pref_task_runner_| and
// the prefs listeners.
//
// ShutdownOnPrefThread must be called from pref thread before destruction, to
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
  // Must be constructed on the Pref thread.
  HttpServerPropertiesManager(
      PrefDelegate* pref_delegate,
      scoped_refptr<base::SequencedTaskRunner> network_task_runner);
  ~HttpServerPropertiesManager() override;

  // Initialize on Network thread.
  void InitializeOnNetworkThread();

  // Prepare for shutdown. Must be called on the Pref thread before destruction.
  void ShutdownOnPrefThread();

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
  AlternativeServiceVector GetAlternativeServices(
      const url::SchemeHostPort& origin) override;
  bool SetAlternativeService(const url::SchemeHostPort& origin,
                             const AlternativeService& alternative_service,
                             base::Time expiration) override;
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

 protected:
  // The location where ScheduleUpdatePrefsOnNetworkThread was called.
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
    NUM_LOCATIONS = 14,
  };

  // --------------------
  // SPDY related methods

  // These are used to delay updating of the cached data in
  // |http_server_properties_impl_| while the preferences are changing, and
  // execute only one update per simultaneous prefs changes.
  void ScheduleUpdateCacheOnPrefThread();

  // Starts the timers to update the cached prefs. This are overridden in tests
  // to prevent the delay.
  virtual void StartCacheUpdateTimerOnPrefThread(base::TimeDelta delay);

  // Update cached prefs in |http_server_properties_impl_| with data from
  // preferences. It gets the data on pref thread and calls
  // UpdateSpdyServersFromPrefsOnNetworkThread() to perform the update on
  // network thread.
  virtual void UpdateCacheFromPrefsOnPrefThread();

  // Starts the update of cached prefs in |http_server_properties_impl_| on the
  // network thread. Protected for testing.
  void UpdateCacheFromPrefsOnNetworkThread(
      std::vector<std::string>* spdy_servers,
      AlternativeServiceMap* alternative_service_map,
      IPAddress* last_quic_address,
      ServerNetworkStatsMap* server_network_stats_map,
      QuicServerInfoMap* quic_server_info_map,
      bool detected_corrupted_prefs);

  // These are used to delay updating the preferences when cached data in
  // |http_server_properties_impl_| is changing, and execute only one update per
  // simultaneous spdy_servers or spdy_settings or alternative_service changes.
  // |location| specifies where this method is called from. Virtual for testing.
  virtual void ScheduleUpdatePrefsOnNetworkThread(Location location);

  // Starts the timers to update the prefs from cache. This are overridden in
  // tests to prevent the delay.
  virtual void StartPrefsUpdateTimerOnNetworkThread(base::TimeDelta delay);

  // Update prefs::kHttpServerProperties in preferences with the cached data
  // from |http_server_properties_impl_|. This gets the data on network thread
  // and posts a task (UpdatePrefsOnPrefThread) to update preferences on pref
  // thread.
  void UpdatePrefsFromCacheOnNetworkThread();

  // Same as above, but fires an optional |completion| callback on pref thread
  // when finished. Virtual for testing.
  virtual void UpdatePrefsFromCacheOnNetworkThread(
      const base::Closure& completion);

  // Update prefs::kHttpServerProperties preferences on pref thread. Executes an
  // optional |completion| callback when finished. Protected for testing.
  void UpdatePrefsOnPrefThread(base::ListValue* spdy_server_list,
                               AlternativeServiceMap* alternative_service_map,
                               IPAddress* last_quic_address,
                               ServerNetworkStatsMap* server_network_stats_map,
                               QuicServerInfoMap* quic_server_info_map,
                               const base::Closure& completion);

 private:
  typedef std::vector<std::string> ServerList;

  FRIEND_TEST_ALL_PREFIXES(HttpServerPropertiesManagerTest,
                           AddToAlternativeServiceMap);
  FRIEND_TEST_ALL_PREFIXES(HttpServerPropertiesManagerTest,
                           DoNotLoadAltSvcForInsecureOrigins);
  FRIEND_TEST_ALL_PREFIXES(HttpServerPropertiesManagerTest,
                           DoNotLoadExpiredAlternativeService);
  void OnHttpServerPropertiesChanged();

  bool AddServersData(const base::DictionaryValue& server_dict,
                      ServerList* spdy_servers,
                      AlternativeServiceMap* alternative_service_map,
                      ServerNetworkStatsMap* network_stats_map,
                      int version);
  bool ParseAlternativeServiceDict(
      const base::DictionaryValue& alternative_service_dict,
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

  void SaveAlternativeServiceToServerPrefs(
      const AlternativeServiceInfoVector* alternative_service_info_vector,
      base::DictionaryValue* server_pref_dict);
  void SaveSupportsQuicToPrefs(
      const IPAddress* last_quic_address,
      base::DictionaryValue* http_server_properties_dict);
  void SaveNetworkStatsToServerPrefs(
      const ServerNetworkStats* server_network_stats,
      base::DictionaryValue* server_pref_dict);
  void SaveQuicServerInfoMapToServerPrefs(
      QuicServerInfoMap* quic_server_info_map,
      base::DictionaryValue* http_server_properties_dict);

  // -----------
  // Pref thread
  // -----------

  const scoped_refptr<base::SequencedTaskRunner> pref_task_runner_;

  base::WeakPtr<HttpServerPropertiesManager> pref_weak_ptr_;

  // Used to post cache update tasks.
  std::unique_ptr<base::OneShotTimer> pref_cache_update_timer_;

  std::unique_ptr<PrefDelegate> pref_delegate_;
  bool setting_prefs_;

  // --------------
  // Network thread
  // --------------

  const scoped_refptr<base::SequencedTaskRunner> network_task_runner_;

  // Used to post |prefs::kHttpServerProperties| pref update tasks.
  std::unique_ptr<base::OneShotTimer> network_prefs_update_timer_;

  std::unique_ptr<HttpServerPropertiesImpl> http_server_properties_impl_;

  // Used to get |weak_ptr_| to self on the pref thread.
  std::unique_ptr<base::WeakPtrFactory<HttpServerPropertiesManager>>
      pref_weak_ptr_factory_;

  // Used to get |weak_ptr_| to self on the network thread.
  std::unique_ptr<base::WeakPtrFactory<HttpServerPropertiesManager>>
      network_weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(HttpServerPropertiesManager);
};

}  // namespace net

#endif  // NET_HTTP_HTTP_SERVER_PROPERTIES_MANAGER_H_
