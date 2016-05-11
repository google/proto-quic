// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_STREAM_FACTORY_H_
#define NET_QUIC_QUIC_STREAM_FACTORY_H_

#include <stddef.h>
#include <stdint.h>

#include <deque>
#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "base/gtest_prod_util.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/time/time.h"
#include "net/base/address_list.h"
#include "net/base/completion_callback.h"
#include "net/base/host_port_pair.h"
#include "net/base/network_change_notifier.h"
#include "net/cert/cert_database.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_stream_factory.h"
#include "net/log/net_log.h"
#include "net/proxy/proxy_server.h"
#include "net/quic/network_connection.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/quic/quic_client_push_promise_index.h"
#include "net/quic/quic_config.h"
#include "net/quic/quic_crypto_stream.h"
#include "net/quic/quic_http_stream.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_server_id.h"
#include "net/ssl/ssl_config_service.h"

namespace net {

class CTPolicyEnforcer;
class CertVerifier;
class ChannelIDService;
class ClientSocketFactory;
class CTVerifier;
class HostResolver;
class HttpServerProperties;
class QuicClock;
class QuicChromiumAlarmFactory;
class QuicChromiumClientSession;
class QuicChromiumConnectionHelper;
class QuicCryptoClientStreamFactory;
class QuicRandom;
class QuicServerInfo;
class QuicServerInfoFactory;
class QuicStreamFactory;
class SocketPerformanceWatcherFactory;
class TransportSecurityState;
class BidirectionalStreamImpl;

namespace test {
class QuicStreamFactoryPeer;
}  // namespace test

// When a connection is idle for 30 seconds it will be closed.
const int kIdleConnectionTimeoutSeconds = 30;

// Encapsulates a pending request for a QuicHttpStream.
// If the request is still pending when it is destroyed, it will
// cancel the request with the factory.
class NET_EXPORT_PRIVATE QuicStreamRequest {
 public:
  explicit QuicStreamRequest(QuicStreamFactory* factory);
  ~QuicStreamRequest();

  // |cert_verify_flags| is bitwise OR'd of CertVerifier::VerifyFlags and it is
  // passed to CertVerifier::Verify.
  // |destination| will be resolved and resulting IPEndPoint used to open a
  // QuicConnection.  This can be different than HostPortPair::FromURL(url).
  int Request(const HostPortPair& destination,
              PrivacyMode privacy_mode,
              int cert_verify_flags,
              const GURL& url,
              base::StringPiece method,
              const BoundNetLog& net_log,
              const CompletionCallback& callback);

  void OnRequestComplete(int rv);

  // Helper method that calls |factory_|'s GetTimeDelayForWaitingJob(). It
  // returns the amount of time waiting job should be delayed.
  base::TimeDelta GetTimeDelayForWaitingJob() const;

  std::unique_ptr<QuicHttpStream> CreateStream();

  std::unique_ptr<BidirectionalStreamImpl> CreateBidirectionalStreamImpl();

  // Sets |session_|.
  void SetSession(QuicChromiumClientSession* session);

  const QuicServerId& server_id() const { return server_id_; }

  const BoundNetLog& net_log() const { return net_log_; }

 private:
  QuicStreamFactory* factory_;
  QuicServerId server_id_;
  BoundNetLog net_log_;
  CompletionCallback callback_;
  base::WeakPtr<QuicChromiumClientSession> session_;

  DISALLOW_COPY_AND_ASSIGN(QuicStreamRequest);
};

// A factory for creating new QuicHttpStreams on top of a pool of
// QuicChromiumClientSessions.
class NET_EXPORT_PRIVATE QuicStreamFactory
    : public NetworkChangeNotifier::IPAddressObserver,
      public NetworkChangeNotifier::NetworkObserver,
      public SSLConfigService::Observer,
      public CertDatabase::Observer {
 public:
  // This class encompasses |destination| and |server_id|.
  // |destination| is a HostPortPair which is resolved
  // and a QuicConnection is made to the resulting IP address.
  // |server_id| identifies the origin of the request,
  // the crypto handshake advertises |server_id.host()| to the server,
  // and the certificate is also matched against |server_id.host()|.
  class NET_EXPORT_PRIVATE QuicSessionKey {
   public:
    QuicSessionKey() = default;
    QuicSessionKey(const HostPortPair& destination,
                   const QuicServerId& server_id);
    ~QuicSessionKey() = default;

    // Needed to be an element of std::set.
    bool operator<(const QuicSessionKey& other) const;
    bool operator==(const QuicSessionKey& other) const;

    const HostPortPair& destination() const { return destination_; }
    const QuicServerId& server_id() const { return server_id_; }

   private:
    HostPortPair destination_;
    QuicServerId server_id_;
  };

  QuicStreamFactory(
      HostResolver* host_resolver,
      ClientSocketFactory* client_socket_factory,
      base::WeakPtr<HttpServerProperties> http_server_properties,
      CertVerifier* cert_verifier,
      CTPolicyEnforcer* ct_policy_enforcer,
      ChannelIDService* channel_id_service,
      TransportSecurityState* transport_security_state,
      CTVerifier* cert_transparency_verifier,
      SocketPerformanceWatcherFactory* socket_performance_watcher_factory,
      QuicCryptoClientStreamFactory* quic_crypto_client_stream_factory,
      QuicRandom* random_generator,
      QuicClock* clock,
      size_t max_packet_length,
      const std::string& user_agent_id,
      const QuicVersionVector& supported_versions,
      bool enable_port_selection,
      bool always_require_handshake_confirmation,
      bool disable_connection_pooling,
      float load_server_info_timeout_srtt_multiplier,
      bool enable_connection_racing,
      bool enable_non_blocking_io,
      bool disable_disk_cache,
      bool prefer_aes,
      int max_number_of_lossy_connections,
      float packet_loss_threshold,
      int max_recent_disabled_reasons,
      int threshold_timeouts_with_streams_open,
      int threshold_public_resets_post_handshake,
      int socket_receive_buffer_size,
      int max_server_configs_stored_in_properties,
      bool close_sessions_on_ip_change,
      bool disable_quic_on_timeout_with_open_streams,
      int idle_connection_timeout_seconds,
      bool migrate_sessions_on_network_change,
      bool migrate_sessions_early,
      const QuicTagVector& connection_options,
      bool enable_token_binding);
  ~QuicStreamFactory() override;

  // Returns true if there is an existing session for |server_id| or if the
  // request can be pooled to an existing session to the IP address of
  // |destination|.
  bool CanUseExistingSession(const QuicServerId& server_id,
                             const HostPortPair& destination);

  // Creates a new QuicHttpStream to |host_port_pair| which will be
  // owned by |request|.
  // If a matching session already exists, this method will return OK.  If no
  // matching session exists, this will return ERR_IO_PENDING and will invoke
  // OnRequestComplete asynchronously.
  int Create(const QuicServerId& server_id,
             const HostPortPair& destination,
             int cert_verify_flags,
             const GURL& url,
             base::StringPiece method,
             const BoundNetLog& net_log,
             QuicStreamRequest* request);

  // If |packet_loss_rate| is greater than or equal to |packet_loss_threshold_|
  // it marks QUIC as recently broken for the port of the session. Increments
  // |number_of_lossy_connections_| by port. If |number_of_lossy_connections_|
  // is greater than or equal to |max_number_of_lossy_connections_| then it
  // disables QUIC. If QUIC is disabled then it closes the connection.
  //
  // Returns true if QUIC is disabled for the port of the session.
  bool OnHandshakeConfirmed(QuicChromiumClientSession* session,
                            float packet_loss_rate);

  // Called when a TCP job completes for an origin that QUIC potentially
  // could be used for.
  void OnTcpJobCompleted(bool succeeded);

  // Returns true if QUIC is disabled for this port.
  bool IsQuicDisabled(uint16_t port) const;

  // Returns reason QUIC is disabled for this port, or QUIC_DISABLED_NOT if not.
  QuicChromiumClientSession::QuicDisabledReason QuicDisabledReason(
      uint16_t port) const;

  // Returns reason QUIC is disabled as string for net-internals, or
  // returns empty string if QUIC is not disabled.
  const char* QuicDisabledReasonString() const;

  // Called by a session when it becomes idle.
  void OnIdleSession(QuicChromiumClientSession* session);

  // Called by a session when it is going away and no more streams should be
  // created on it.
  void OnSessionGoingAway(QuicChromiumClientSession* session);

  // Called by a session after it shuts down.
  void OnSessionClosed(QuicChromiumClientSession* session);

  // Called by a session whose connection has timed out.
  void OnSessionConnectTimeout(QuicChromiumClientSession* session);

  // Cancels a pending request.
  void CancelRequest(QuicStreamRequest* request);

  // Closes all current sessions with specified network and QUIC error codes.
  void CloseAllSessions(int error, QuicErrorCode quic_error);

  std::unique_ptr<base::Value> QuicStreamFactoryInfoToValue() const;

  // Delete all cached state objects in |crypto_config_|.
  void ClearCachedStatesInCryptoConfig();

  // Helper method that configures a DatagramClientSocket. Socket is
  // bound to the default network if the |network| param is
  // NetworkChangeNotifier::kInvalidNetworkHandle.
  // Returns net_error code.
  int ConfigureSocket(DatagramClientSocket* socket,
                      IPEndPoint addr,
                      NetworkChangeNotifier::NetworkHandle network);

  // Finds an alternative to |old_network| from the platform's list of connected
  // networks. Returns NetworkChangeNotifier::kInvalidNetworkHandle if no
  // alternative is found.
  NetworkChangeNotifier::NetworkHandle FindAlternateNetwork(
      NetworkChangeNotifier::NetworkHandle old_network);

  // Method that initiates migration of active sessions
  // currently bound to |network| to an alternate network, if one
  // exists. Idle sessions bound to |network| are closed. If there is
  // no alternate network to migrate active sessions onto, active
  // sessions are closed if |force_close| is true, and continue using
  // |network| otherwise. Sessions not bound to |network| are left unchanged.
  void MaybeMigrateOrCloseSessions(NetworkChangeNotifier::NetworkHandle network,
                                   bool force_close);

  // Method that initiates early migration of |session| if |session| is
  // active and if there is an alternate network than the one to which
  // |session| is currently bound.
  void MaybeMigrateSessionEarly(QuicChromiumClientSession* session);

  // Method that migrates |session| over to using |new_network|.
  void MigrateSessionToNetwork(
      QuicChromiumClientSession* session,
      NetworkChangeNotifier::NetworkHandle new_network);

  // NetworkChangeNotifier::IPAddressObserver methods:

  // Until the servers support roaming, close all connections when the local
  // IP address changes.
  void OnIPAddressChanged() override;

  // NetworkChangeNotifier::NetworkObserver methods:
  void OnNetworkConnected(
      NetworkChangeNotifier::NetworkHandle network) override;
  void OnNetworkDisconnected(
      NetworkChangeNotifier::NetworkHandle network) override;
  void OnNetworkSoonToDisconnect(
      NetworkChangeNotifier::NetworkHandle network) override;
  void OnNetworkMadeDefault(
      NetworkChangeNotifier::NetworkHandle network) override;

  // SSLConfigService::Observer methods:

  // We perform the same flushing as described above when SSL settings change.
  void OnSSLConfigChanged() override;

  // CertDatabase::Observer methods:

  // We close all sessions when certificate database is changed.
  void OnCertAdded(const X509Certificate* cert) override;
  void OnCACertChanged(const X509Certificate* cert) override;

  bool require_confirmation() const { return require_confirmation_; }

  void set_require_confirmation(bool require_confirmation);

  bool ZeroRTTEnabledFor(const QuicServerId& server_id);

  // It returns the amount of time waiting job should be delayed.
  base::TimeDelta GetTimeDelayForWaitingJob(const QuicServerId& server_id);

  QuicChromiumConnectionHelper* helper() { return helper_.get(); }

  QuicChromiumAlarmFactory* alarm_factory() { return alarm_factory_.get(); }

  bool enable_port_selection() const { return enable_port_selection_; }

  bool has_quic_server_info_factory() {
    return quic_server_info_factory_.get() != nullptr;
  }

  void set_quic_server_info_factory(
      QuicServerInfoFactory* quic_server_info_factory);

  bool enable_connection_racing() const { return enable_connection_racing_; }
  void set_enable_connection_racing(bool enable_connection_racing) {
    enable_connection_racing_ = enable_connection_racing;
  }

  int socket_receive_buffer_size() const { return socket_receive_buffer_size_; }

 private:
  class Job;
  friend class test::QuicStreamFactoryPeer;
  FRIEND_TEST_ALL_PREFIXES(HttpStreamFactoryTest, QuicLossyProxyMarkedAsBad);

  typedef std::map<QuicServerId, QuicChromiumClientSession*> SessionMap;
  typedef std::map<QuicChromiumClientSession*, QuicSessionKey> SessionIdMap;
  typedef std::set<QuicSessionKey> AliasSet;
  typedef std::map<QuicChromiumClientSession*, AliasSet> SessionAliasMap;
  typedef std::set<QuicChromiumClientSession*> SessionSet;
  typedef std::map<IPEndPoint, SessionSet> IPAliasMap;
  typedef std::map<QuicServerId, QuicCryptoClientConfig*> CryptoConfigMap;
  typedef std::set<Job*> JobSet;
  typedef std::map<QuicServerId, JobSet> JobMap;
  typedef std::map<QuicStreamRequest*, QuicServerId> RequestMap;
  typedef std::set<QuicStreamRequest*> RequestSet;
  typedef std::map<QuicServerId, RequestSet> ServerIDRequestsMap;
  typedef std::deque<enum QuicChromiumClientSession::QuicDisabledReason>
      DisabledReasonsQueue;

  enum FactoryStatus {
    OPEN,     // New streams may be created.
    CLOSED,   // No new streams may be created temporarily.
    DISABLED  // No more streams may be created until the network changes.
  };

  // Creates a job which doesn't wait for server config to be loaded from the
  // disk cache. This job is started via a PostTask.
  void CreateAuxilaryJob(const QuicSessionKey& key,
                         int cert_verify_flags,
                         bool is_post,
                         const BoundNetLog& net_log);

  // Returns a newly created QuicHttpStream owned by the caller.
  std::unique_ptr<QuicHttpStream> CreateFromSession(
      QuicChromiumClientSession* session);

  bool OnResolution(const QuicSessionKey& key, const AddressList& address_list);
  void OnJobComplete(Job* job, int rv);
  bool HasActiveSession(const QuicServerId& server_id) const;
  bool HasActiveJob(const QuicServerId& server_id) const;
  int CreateSession(const QuicSessionKey& key,
                    int cert_verify_flags,
                    std::unique_ptr<QuicServerInfo> quic_server_info,
                    const AddressList& address_list,
                    base::TimeTicks dns_resolution_end_time,
                    const BoundNetLog& net_log,
                    QuicChromiumClientSession** session);
  void ActivateSession(const QuicSessionKey& key,
                       QuicChromiumClientSession* session);

  // Returns |srtt| in micro seconds from ServerNetworkStats. Returns 0 if there
  // is no |http_server_properties_| or if |http_server_properties_| doesn't
  // have ServerNetworkStats for the given |server_id|.
  int64_t GetServerNetworkStatsSmoothedRttInMicroseconds(
      const QuicServerId& server_id) const;

  // Helper methods.
  bool WasQuicRecentlyBroken(const QuicServerId& server_id) const;

  bool CryptoConfigCacheIsEmpty(const QuicServerId& server_id);

  // Initializes the cached state associated with |server_id| in
  // |crypto_config_| with the information in |server_info|. Populates
  // |connection_id| with the next server designated connection id,
  // if any, and otherwise leaves it unchanged.
  void InitializeCachedStateInCryptoConfig(
      const QuicServerId& server_id,
      const std::unique_ptr<QuicServerInfo>& server_info,
      QuicConnectionId* connection_id);

  // Initialize |quic_supported_servers_at_startup_| with the list of servers
  // that supported QUIC at start up and also initialize in-memory cache of
  // QuicServerInfo objects from HttpServerProperties.
  void MaybeInitialize();

  void ProcessGoingAwaySession(QuicChromiumClientSession* session,
                               const QuicServerId& server_id,
                               bool was_session_active);

  // Collect stats from recent connections, possibly disabling Quic.
  void MaybeDisableQuic(QuicChromiumClientSession* session);

  void MaybeDisableQuic(uint16_t port);

  bool require_confirmation_;
  HostResolver* host_resolver_;
  ClientSocketFactory* client_socket_factory_;
  base::WeakPtr<HttpServerProperties> http_server_properties_;
  TransportSecurityState* transport_security_state_;
  CTVerifier* cert_transparency_verifier_;
  std::unique_ptr<QuicServerInfoFactory> quic_server_info_factory_;
  QuicCryptoClientStreamFactory* quic_crypto_client_stream_factory_;
  QuicRandom* random_generator_;
  std::unique_ptr<QuicClock> clock_;
  const size_t max_packet_length_;

  // Factory which is used to create socket performance watcher. A new watcher
  // is created for every QUIC connection.
  // |socket_performance_watcher_factory_| may be null.
  SocketPerformanceWatcherFactory* socket_performance_watcher_factory_;

  // The helper used for all connections.
  std::unique_ptr<QuicChromiumConnectionHelper> helper_;

  // The alarm factory used for all connections.
  std::unique_ptr<QuicChromiumAlarmFactory> alarm_factory_;

  // Contains owning pointers to all sessions that currently exist.
  SessionIdMap all_sessions_;
  // Contains non-owning pointers to currently active session
  // (not going away session, once they're implemented).
  SessionMap active_sessions_;
  // Map from session to set of aliases that this session is known by.
  SessionAliasMap session_aliases_;
  // Map from IP address to sessions which are connected to this address.
  IPAliasMap ip_aliases_;

  // Origins which have gone away recently.
  AliasSet gone_away_aliases_;

  const QuicConfig config_;
  QuicCryptoClientConfig crypto_config_;

  JobMap active_jobs_;
  ServerIDRequestsMap job_requests_map_;
  RequestMap active_requests_;

  QuicVersionVector supported_versions_;

  // Determine if we should consistently select a client UDP port. If false,
  // then we will just let the OS select a random client port for each new
  // connection.
  bool enable_port_selection_;

  // Set if we always require handshake confirmation. If true, this will
  // introduce at least one RTT for the handshake before the client sends data.
  bool always_require_handshake_confirmation_;

  // Set if we do not want connection pooling.
  bool disable_connection_pooling_;

  // Specifies the ratio between time to load QUIC server information from disk
  // cache to 'smoothed RTT'. This ratio is used to calculate the timeout in
  // milliseconds to wait for loading of QUIC server information. If we don't
  // want to timeout, set |load_server_info_timeout_srtt_multiplier_| to 0.
  float load_server_info_timeout_srtt_multiplier_;

  // Set if we want to race connections - one connection that sends
  // INCHOATE_HELLO and another connection that sends CHLO after loading server
  // config from the disk cache.
  bool enable_connection_racing_;

  // Set if experimental non-blocking IO should be used on windows sockets.
  bool enable_non_blocking_io_;

  // Set if we do not want to load server config from the disk cache.
  bool disable_disk_cache_;

  // Set if AES-GCM should be preferred, even if there is no hardware support.
  bool prefer_aes_;

  // Set if we want to disable QUIC when there is high packet loss rate.
  // Specifies the maximum number of connections with high packet loss in a row
  // after which QUIC will be disabled.
  int max_number_of_lossy_connections_;
  // Specifies packet loss rate in fraction after which a connection is closed
  // and is considered as a lossy connection.
  float packet_loss_threshold_;
  // Count number of lossy connections by port.
  std::map<uint16_t, int> number_of_lossy_connections_;

  // Keep track of stats for recently closed connections, using a
  // bounded queue.
  int max_disabled_reasons_;
  DisabledReasonsQueue disabled_reasons_;
  // Events that can trigger disabling QUIC
  int num_public_resets_post_handshake_;
  int num_timeouts_with_open_streams_;
  // Keep track the largest values for UMA histograms, that will help
  // determine good threshold values.
  int max_public_resets_post_handshake_;
  int max_timeouts_with_open_streams_;
  // Thresholds if greater than zero, determine when to
  int threshold_timeouts_with_open_streams_;
  int threshold_public_resets_post_handshake_;

  // Size of the UDP receive buffer.
  int socket_receive_buffer_size_;

  // If more than |yield_after_packets_| packets have been read or more than
  // |yield_after_duration_| time has passed, then
  // QuicChromiumPacketReader::StartReading() yields by doing a PostTask().
  int yield_after_packets_;
  QuicTime::Delta yield_after_duration_;

  // Set if all sessions should be closed when any local IP address changes.
  const bool close_sessions_on_ip_change_;

  // Set if migration should be attempted on active sessions when primary
  // interface changes.
  const bool migrate_sessions_on_network_change_;

  // Set if early migration should be attempted when the connection
  // experiences poor connectivity.
  const bool migrate_sessions_early_;

  // Each profile will (probably) have a unique port_seed_ value.  This value
  // is used to help seed a pseudo-random number generator (PortSuggester) so
  // that we consistently (within this profile) suggest the same ephemeral
  // port when we re-connect to any given server/port.  The differences between
  // profiles (probablistically) prevent two profiles from colliding in their
  // ephemeral port requests.
  uint64_t port_seed_;

  // Local address of socket that was created in CreateSession.
  IPEndPoint local_address_;
  bool check_persisted_supports_quic_;
  bool has_initialized_data_;
  std::set<HostPortPair> quic_supported_servers_at_startup_;

  NetworkConnection network_connection_;

  int num_push_streams_created_;

  QuicClientPushPromiseIndex push_promise_index_;

  // Current status of the factory's ability to create streams.
  FactoryStatus status_;

  base::TaskRunner* task_runner_;

  base::WeakPtrFactory<QuicStreamFactory> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(QuicStreamFactory);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_STREAM_FACTORY_H_
