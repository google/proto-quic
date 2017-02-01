// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_stream_factory.h"

#include <openssl/aead.h>

#include <algorithm>
#include <tuple>
#include <utility>

#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "base/rand_util.h"
#include "base/single_thread_task_runner.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/trace_event.h"
#include "base/values.h"
#include "crypto/openssl_util.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_verifier.h"
#include "net/dns/host_resolver.h"
#include "net/dns/single_request_host_resolver.h"
#include "net/http/bidirectional_stream_impl.h"
#include "net/quic/bidirectional_stream_quic_impl.h"
#include "net/quic/crypto/channel_id_chromium.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/crypto/properties_based_quic_server_info.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/crypto/quic_server_info.h"
#include "net/quic/port_suggester.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/quic/quic_chromium_packet_writer.h"
#include "net/quic/quic_client_promised_info.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_crypto_client_stream_factory.h"
#include "net/quic/quic_flags.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/socket_performance_watcher_factory.h"
#include "net/ssl/token_binding.h"
#include "net/udp/udp_client_socket.h"

using std::min;
using NetworkHandle = net::NetworkChangeNotifier::NetworkHandle;

namespace net {

namespace {

enum CreateSessionFailure {
  CREATION_ERROR_CONNECTING_SOCKET,
  CREATION_ERROR_SETTING_RECEIVE_BUFFER,
  CREATION_ERROR_SETTING_SEND_BUFFER,
  CREATION_ERROR_MAX
};

enum QuicConnectionMigrationStatus {
  MIGRATION_STATUS_NO_MIGRATABLE_STREAMS,
  MIGRATION_STATUS_ALREADY_MIGRATED,
  MIGRATION_STATUS_INTERNAL_ERROR,
  MIGRATION_STATUS_TOO_MANY_CHANGES,
  MIGRATION_STATUS_SUCCESS,
  MIGRATION_STATUS_NON_MIGRATABLE_STREAM,
  MIGRATION_STATUS_DISABLED,
  MIGRATION_STATUS_MAX
};

// The maximum receive window sizes for QUIC sessions and streams.
const int32_t kQuicSessionMaxRecvWindowSize = 15 * 1024 * 1024;  // 15 MB
const int32_t kQuicStreamMaxRecvWindowSize = 6 * 1024 * 1024;    // 6 MB

// Set the maximum number of undecryptable packets the connection will store.
const int32_t kMaxUndecryptablePackets = 100;

std::unique_ptr<base::Value> NetLogQuicConnectionMigrationTriggerCallback(
    std::string trigger,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("trigger", trigger);
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicConnectionMigrationFailureCallback(
    QuicConnectionId connection_id,
    std::string reason,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("connection_id", base::Uint64ToString(connection_id));
  dict->SetString("reason", reason);
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicConnectionMigrationSuccessCallback(
    QuicConnectionId connection_id,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("connection_id", base::Uint64ToString(connection_id));
  return std::move(dict);
}

// Helper class that is used to log a connection migration event.
class ScopedConnectionMigrationEventLog {
 public:
  ScopedConnectionMigrationEventLog(NetLog* net_log, std::string trigger)
      : net_log_(BoundNetLog::Make(net_log,
                                   NetLog::SOURCE_QUIC_CONNECTION_MIGRATION)) {
    net_log_.BeginEvent(
        NetLog::TYPE_QUIC_CONNECTION_MIGRATION_TRIGGERED,
        base::Bind(&NetLogQuicConnectionMigrationTriggerCallback, trigger));
  }

  ~ScopedConnectionMigrationEventLog() {
    net_log_.EndEvent(NetLog::TYPE_QUIC_CONNECTION_MIGRATION_TRIGGERED);
  }

  const BoundNetLog& net_log() { return net_log_; }

 private:
  const BoundNetLog net_log_;
};

void HistogramCreateSessionFailure(enum CreateSessionFailure error) {
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.CreationError", error,
                            CREATION_ERROR_MAX);
}

void HistogramAndLogMigrationFailure(const BoundNetLog& net_log,
                                     enum QuicConnectionMigrationStatus status,
                                     QuicConnectionId connection_id,
                                     std::string reason) {
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.ConnectionMigration", status,
                            MIGRATION_STATUS_MAX);
  net_log.AddEvent(NetLog::TYPE_QUIC_CONNECTION_MIGRATION_FAILURE,
                   base::Bind(&NetLogQuicConnectionMigrationFailureCallback,
                              connection_id, reason));
}

void HistogramMigrationStatus(enum QuicConnectionMigrationStatus status) {
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.ConnectionMigration", status,
                            MIGRATION_STATUS_MAX);
}

QuicConfig InitializeQuicConfig(const QuicTagVector& connection_options,
                                int idle_connection_timeout_seconds) {
  DCHECK_GT(idle_connection_timeout_seconds, 0);
  QuicConfig config;
  config.SetIdleConnectionStateLifetime(
      QuicTime::Delta::FromSeconds(idle_connection_timeout_seconds),
      QuicTime::Delta::FromSeconds(idle_connection_timeout_seconds));
  config.SetConnectionOptionsToSend(connection_options);
  return config;
}

}  // namespace

// Responsible for creating a new QUIC session to the specified server, and
// for notifying any associated requests when complete.
class QuicStreamFactory::Job {
 public:
  Job(QuicStreamFactory* factory,
      HostResolver* host_resolver,
      const QuicSessionKey& key,
      bool was_alternative_service_recently_broken,
      int cert_verify_flags,
      QuicServerInfo* server_info,
      const BoundNetLog& net_log);

  // Creates a new job to handle the resumption of for connecting an
  // existing session.
  Job(QuicStreamFactory* factory,
      HostResolver* host_resolver,
      QuicChromiumClientSession* session,
      const QuicSessionKey& key);

  ~Job();

  int Run(const CompletionCallback& callback);

  int DoLoop(int rv);
  int DoResolveHost();
  int DoResolveHostComplete(int rv);
  int DoLoadServerInfo();
  int DoLoadServerInfoComplete(int rv);
  int DoConnect();
  int DoResumeConnect();
  int DoConnectComplete(int rv);

  void OnIOComplete(int rv);

  void RunAuxilaryJob();

  void Cancel();

  void CancelWaitForDataReadyCallback();

  const QuicSessionKey& key() const { return key_; }

  base::WeakPtr<Job> GetWeakPtr() { return weak_factory_.GetWeakPtr(); }

 private:
  enum IoState {
    STATE_NONE,
    STATE_RESOLVE_HOST,
    STATE_RESOLVE_HOST_COMPLETE,
    STATE_LOAD_SERVER_INFO,
    STATE_LOAD_SERVER_INFO_COMPLETE,
    STATE_CONNECT,
    STATE_RESUME_CONNECT,
    STATE_CONNECT_COMPLETE,
  };
  IoState io_state_;

  QuicStreamFactory* factory_;
  SingleRequestHostResolver host_resolver_;
  QuicSessionKey key_;
  int cert_verify_flags_;
  bool was_alternative_service_recently_broken_;
  std::unique_ptr<QuicServerInfo> server_info_;
  bool started_another_job_;
  const BoundNetLog net_log_;
  int num_sent_client_hellos_;
  QuicChromiumClientSession* session_;
  CompletionCallback callback_;
  AddressList address_list_;
  base::TimeTicks dns_resolution_start_time_;
  base::TimeTicks dns_resolution_end_time_;
  base::WeakPtrFactory<Job> weak_factory_;
  DISALLOW_COPY_AND_ASSIGN(Job);
};

QuicStreamFactory::Job::Job(QuicStreamFactory* factory,
                            HostResolver* host_resolver,
                            const QuicSessionKey& key,
                            bool was_alternative_service_recently_broken,
                            int cert_verify_flags,
                            QuicServerInfo* server_info,
                            const BoundNetLog& net_log)
    : io_state_(STATE_RESOLVE_HOST),
      factory_(factory),
      host_resolver_(host_resolver),
      key_(key),
      cert_verify_flags_(cert_verify_flags),
      was_alternative_service_recently_broken_(
          was_alternative_service_recently_broken),
      server_info_(server_info),
      started_another_job_(false),
      net_log_(net_log),
      num_sent_client_hellos_(0),
      session_(nullptr),
      weak_factory_(this) {}

QuicStreamFactory::Job::Job(QuicStreamFactory* factory,
                            HostResolver* host_resolver,
                            QuicChromiumClientSession* session,
                            const QuicSessionKey& key)
    : io_state_(STATE_RESUME_CONNECT),
      factory_(factory),
      host_resolver_(host_resolver),  // unused
      key_(key),
      cert_verify_flags_(0),                            // unused
      was_alternative_service_recently_broken_(false),  // unused
      started_another_job_(false),                      // unused
      net_log_(session->net_log()),                     // unused
      num_sent_client_hellos_(0),
      session_(session),
      weak_factory_(this) {}

QuicStreamFactory::Job::~Job() {
  // If disk cache has a pending WaitForDataReadyCallback, cancel that callback.
  if (server_info_)
    server_info_->ResetWaitForDataReadyCallback();
}

int QuicStreamFactory::Job::Run(const CompletionCallback& callback) {
  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING)
    callback_ = callback;

  return rv > 0 ? OK : rv;
}

int QuicStreamFactory::Job::DoLoop(int rv) {
  TRACE_EVENT0("net", "QuicStreamFactory::Job::DoLoop");
  do {
    IoState state = io_state_;
    io_state_ = STATE_NONE;
    switch (state) {
      case STATE_RESOLVE_HOST:
        CHECK_EQ(OK, rv);
        rv = DoResolveHost();
        break;
      case STATE_RESOLVE_HOST_COMPLETE:
        rv = DoResolveHostComplete(rv);
        break;
      case STATE_LOAD_SERVER_INFO:
        CHECK_EQ(OK, rv);
        rv = DoLoadServerInfo();
        break;
      case STATE_LOAD_SERVER_INFO_COMPLETE:
        rv = DoLoadServerInfoComplete(rv);
        break;
      case STATE_CONNECT:
        CHECK_EQ(OK, rv);
        rv = DoConnect();
        break;
      case STATE_RESUME_CONNECT:
        CHECK_EQ(OK, rv);
        rv = DoResumeConnect();
        break;
      case STATE_CONNECT_COMPLETE:
        rv = DoConnectComplete(rv);
        break;
      default:
        NOTREACHED() << "io_state_: " << io_state_;
        break;
    }
  } while (io_state_ != STATE_NONE && rv != ERR_IO_PENDING);
  return rv;
}

void QuicStreamFactory::Job::OnIOComplete(int rv) {
  rv = DoLoop(rv);
  if (rv != ERR_IO_PENDING && !callback_.is_null()) {
    callback_.Run(rv);
  }
}

void QuicStreamFactory::Job::RunAuxilaryJob() {
  int rv = Run(base::Bind(&QuicStreamFactory::OnJobComplete,
                          base::Unretained(factory_), this));
  if (rv != ERR_IO_PENDING)
    factory_->OnJobComplete(this, rv);
}

void QuicStreamFactory::Job::Cancel() {
  callback_.Reset();
  if (session_)
    session_->connection()->CloseConnection(
        QUIC_CONNECTION_CANCELLED, "New job canceled.",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

void QuicStreamFactory::Job::CancelWaitForDataReadyCallback() {
  // If we are waiting for WaitForDataReadyCallback, then cancel the callback.
  if (io_state_ != STATE_LOAD_SERVER_INFO_COMPLETE)
    return;
  server_info_->CancelWaitForDataReadyCallback();
  OnIOComplete(OK);
}

int QuicStreamFactory::Job::DoResolveHost() {
  // Start loading the data now, and wait for it after we resolve the host.
  if (server_info_) {
    server_info_->Start();
  }

  io_state_ = STATE_RESOLVE_HOST_COMPLETE;
  dns_resolution_start_time_ = base::TimeTicks::Now();
  return host_resolver_.Resolve(
      HostResolver::RequestInfo(key_.destination()), DEFAULT_PRIORITY,
      &address_list_,
      base::Bind(&QuicStreamFactory::Job::OnIOComplete, GetWeakPtr()),
      net_log_);
}

int QuicStreamFactory::Job::DoResolveHostComplete(int rv) {
  dns_resolution_end_time_ = base::TimeTicks::Now();
  UMA_HISTOGRAM_TIMES("Net.QuicSession.HostResolutionTime",
                      dns_resolution_end_time_ - dns_resolution_start_time_);
  if (rv != OK)
    return rv;

  DCHECK(!factory_->HasActiveSession(key_.server_id()));

  // Inform the factory of this resolution, which will set up
  // a session alias, if possible.
  if (factory_->OnResolution(key_, address_list_)) {
    return OK;
  }

  if (server_info_)
    io_state_ = STATE_LOAD_SERVER_INFO;
  else
    io_state_ = STATE_CONNECT;
  return OK;
}

int QuicStreamFactory::Job::DoLoadServerInfo() {
  io_state_ = STATE_LOAD_SERVER_INFO_COMPLETE;

  DCHECK(server_info_);

  // To mitigate the effects of disk cache taking too long to load QUIC server
  // information, set up a timer to cancel WaitForDataReady's callback.
  if (factory_->load_server_info_timeout_srtt_multiplier_ > 0) {
    const int kMaxLoadServerInfoTimeoutMs = 50;
    // Wait for DiskCache a maximum of 50ms.
    int64_t load_server_info_timeout_ms =
        std::min(static_cast<int>(
                     (factory_->load_server_info_timeout_srtt_multiplier_ *
                      factory_->GetServerNetworkStatsSmoothedRttInMicroseconds(
                          key_.server_id())) /
                     1000),
                 kMaxLoadServerInfoTimeoutMs);
    if (load_server_info_timeout_ms > 0) {
      factory_->task_runner_->PostDelayedTask(
          FROM_HERE,
          base::Bind(&QuicStreamFactory::Job::CancelWaitForDataReadyCallback,
                     GetWeakPtr()),
          base::TimeDelta::FromMilliseconds(load_server_info_timeout_ms));
    }
  }

  int rv = server_info_->WaitForDataReady(
      base::Bind(&QuicStreamFactory::Job::OnIOComplete, GetWeakPtr()));
  if (rv == ERR_IO_PENDING && factory_->enable_connection_racing()) {
    // If we are waiting to load server config from the disk cache, then start
    // another job.
    started_another_job_ = true;
    factory_->CreateAuxilaryJob(key_, cert_verify_flags_, net_log_);
  }
  return rv;
}

int QuicStreamFactory::Job::DoLoadServerInfoComplete(int rv) {
  UMA_HISTOGRAM_TIMES("Net.QuicServerInfo.DiskCacheWaitForDataReadyTime",
                      base::TimeTicks::Now() - dns_resolution_end_time_);

  if (rv != OK)
    server_info_.reset();

  if (started_another_job_ &&
      (!server_info_ || server_info_->state().server_config.empty() ||
       !factory_->CryptoConfigCacheIsEmpty(key_.server_id()))) {
    // If we have started another job and if we didn't load the server config
    // from the disk cache or if we have received a new server config from the
    // server, then cancel the current job.
    io_state_ = STATE_NONE;
    return ERR_CONNECTION_CLOSED;
  }

  io_state_ = STATE_CONNECT;
  return OK;
}

int QuicStreamFactory::Job::DoConnect() {
  io_state_ = STATE_CONNECT_COMPLETE;

  int rv = factory_->CreateSession(
      key_, cert_verify_flags_, std::move(server_info_), address_list_,
      dns_resolution_end_time_, net_log_, &session_);
  if (rv != OK) {
    DCHECK(rv != ERR_IO_PENDING);
    DCHECK(!session_);
    return rv;
  }

  if (!session_->connection()->connected()) {
    return ERR_CONNECTION_CLOSED;
  }

  session_->StartReading();
  if (!session_->connection()->connected()) {
    return ERR_QUIC_PROTOCOL_ERROR;
  }
  bool require_confirmation = factory_->require_confirmation() ||
                              was_alternative_service_recently_broken_;

  rv = session_->CryptoConnect(
      require_confirmation,
      base::Bind(&QuicStreamFactory::Job::OnIOComplete, GetWeakPtr()));

  if (!session_->connection()->connected() &&
      session_->error() == QUIC_PROOF_INVALID)
    return ERR_QUIC_HANDSHAKE_FAILED;

  return rv;
}

int QuicStreamFactory::Job::DoResumeConnect() {
  io_state_ = STATE_CONNECT_COMPLETE;

  int rv = session_->ResumeCryptoConnect(
      base::Bind(&QuicStreamFactory::Job::OnIOComplete, GetWeakPtr()));

  return rv;
}

int QuicStreamFactory::Job::DoConnectComplete(int rv) {
  if (session_ && session_->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
    num_sent_client_hellos_ += session_->GetNumSentClientHellos();
    if (num_sent_client_hellos_ >= QuicCryptoClientStream::kMaxClientHellos) {
      return ERR_QUIC_HANDSHAKE_FAILED;
    }
    // The handshake was rejected statelessly, so create another connection
    // to resume the handshake.
    io_state_ = STATE_CONNECT;
    return OK;
  }

  if (rv != OK)
    return rv;

  DCHECK(!factory_->HasActiveSession(key_.server_id()));
  // There may well now be an active session for this IP.  If so, use the
  // existing session instead.
  AddressList address(session_->connection()->peer_address());
  if (factory_->OnResolution(key_, address)) {
    session_->connection()->CloseConnection(
        QUIC_CONNECTION_IP_POOLED, "An active session exists for the given IP.",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    session_ = nullptr;
    return OK;
  }

  factory_->ActivateSession(key_, session_);

  return OK;
}

QuicStreamRequest::QuicStreamRequest(QuicStreamFactory* factory)
    : factory_(factory) {}

QuicStreamRequest::~QuicStreamRequest() {
  if (factory_ && !callback_.is_null())
    factory_->CancelRequest(this);
}

int QuicStreamRequest::Request(const HostPortPair& destination,
                               PrivacyMode privacy_mode,
                               int cert_verify_flags,
                               const GURL& url,
                               base::StringPiece method,
                               const BoundNetLog& net_log,
                               const CompletionCallback& callback) {
  DCHECK(callback_.is_null());
  DCHECK(factory_);
  server_id_ = QuicServerId(HostPortPair::FromURL(url), privacy_mode);

  int rv = factory_->Create(server_id_, destination, cert_verify_flags, url,
                            method, net_log, this);
  if (rv == ERR_IO_PENDING) {
    net_log_ = net_log;
    callback_ = callback;
  } else {
    factory_ = nullptr;
  }
  if (rv == OK)
    DCHECK(session_);
  return rv;
}

void QuicStreamRequest::SetSession(QuicChromiumClientSession* session) {
  DCHECK(session);
  session_ = session->GetWeakPtr();
}

void QuicStreamRequest::OnRequestComplete(int rv) {
  factory_ = nullptr;
  callback_.Run(rv);
}

base::TimeDelta QuicStreamRequest::GetTimeDelayForWaitingJob() const {
  if (!factory_)
    return base::TimeDelta();
  return factory_->GetTimeDelayForWaitingJob(server_id_);
}

std::unique_ptr<QuicHttpStream> QuicStreamRequest::CreateStream() {
  if (!session_)
    return nullptr;
  return base::WrapUnique(new QuicHttpStream(session_));
}

std::unique_ptr<BidirectionalStreamImpl>
QuicStreamRequest::CreateBidirectionalStreamImpl() {
  if (!session_)
    return nullptr;
  return base::WrapUnique(new BidirectionalStreamQuicImpl(session_));
}

QuicStreamFactory::QuicStreamFactory(
    NetLog* net_log,
    HostResolver* host_resolver,
    SSLConfigService* ssl_config_service,
    ClientSocketFactory* client_socket_factory,
    HttpServerProperties* http_server_properties,
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
    int max_disabled_reasons,
    int threshold_public_resets_post_handshake,
    int threshold_timeouts_with_open_streams,
    int socket_receive_buffer_size,
    bool delay_tcp_race,
    int max_server_configs_stored_in_properties,
    bool close_sessions_on_ip_change,
    bool disable_quic_on_timeout_with_open_streams,
    int idle_connection_timeout_seconds,
    bool migrate_sessions_on_network_change,
    bool migrate_sessions_early,
    bool allow_server_migration,
    bool force_hol_blocking,
    const QuicTagVector& connection_options,
    bool enable_token_binding)
    : require_confirmation_(true),
      net_log_(net_log),
      host_resolver_(host_resolver),
      client_socket_factory_(client_socket_factory),
      http_server_properties_(http_server_properties),
      transport_security_state_(transport_security_state),
      cert_transparency_verifier_(cert_transparency_verifier),
      quic_crypto_client_stream_factory_(quic_crypto_client_stream_factory),
      random_generator_(random_generator),
      clock_(clock),
      max_packet_length_(max_packet_length),
      socket_performance_watcher_factory_(socket_performance_watcher_factory),
      config_(InitializeQuicConfig(connection_options,
                                   idle_connection_timeout_seconds)),
      crypto_config_(base::WrapUnique(
          new ProofVerifierChromium(cert_verifier,
                                    ct_policy_enforcer,
                                    transport_security_state,
                                    cert_transparency_verifier))),
      supported_versions_(supported_versions),
      enable_port_selection_(enable_port_selection),
      always_require_handshake_confirmation_(
          always_require_handshake_confirmation),
      disable_connection_pooling_(disable_connection_pooling),
      load_server_info_timeout_srtt_multiplier_(
          load_server_info_timeout_srtt_multiplier),
      enable_connection_racing_(enable_connection_racing),
      enable_non_blocking_io_(enable_non_blocking_io),
      disable_disk_cache_(disable_disk_cache),
      prefer_aes_(prefer_aes),
      max_number_of_lossy_connections_(max_number_of_lossy_connections),
      packet_loss_threshold_(packet_loss_threshold),
      max_disabled_reasons_(max_disabled_reasons),
      num_public_resets_post_handshake_(0),
      num_timeouts_with_open_streams_(0),
      max_public_resets_post_handshake_(0),
      max_timeouts_with_open_streams_(0),
      threshold_timeouts_with_open_streams_(
          threshold_timeouts_with_open_streams),
      threshold_public_resets_post_handshake_(
          threshold_public_resets_post_handshake),
      socket_receive_buffer_size_(socket_receive_buffer_size),
      delay_tcp_race_(delay_tcp_race),
      yield_after_packets_(kQuicYieldAfterPacketsRead),
      yield_after_duration_(QuicTime::Delta::FromMilliseconds(
          kQuicYieldAfterDurationMilliseconds)),
      close_sessions_on_ip_change_(close_sessions_on_ip_change),
      migrate_sessions_on_network_change_(
          migrate_sessions_on_network_change &&
          NetworkChangeNotifier::AreNetworkHandlesSupported()),
      migrate_sessions_early_(migrate_sessions_early &&
                              migrate_sessions_on_network_change_),
      allow_server_migration_(allow_server_migration),
      force_hol_blocking_(force_hol_blocking),
      port_seed_(random_generator_->RandUint64()),
      check_persisted_supports_quic_(true),
      has_initialized_data_(false),
      num_push_streams_created_(0),
      status_(OPEN),
      task_runner_(nullptr),
      ssl_config_service_(ssl_config_service),
      weak_factory_(this) {
  if (ssl_config_service_.get())
    ssl_config_service_->AddObserver(this);
  if (disable_quic_on_timeout_with_open_streams)
    threshold_timeouts_with_open_streams_ = 1;
  DCHECK(transport_security_state_);
  DCHECK(http_server_properties_);
  crypto_config_.set_user_agent_id(user_agent_id);
  crypto_config_.AddCanonicalSuffix(".c.youtube.com");
  crypto_config_.AddCanonicalSuffix(".ggpht.com");
  crypto_config_.AddCanonicalSuffix(".googlevideo.com");
  crypto_config_.AddCanonicalSuffix(".googleusercontent.com");
  // TODO(rtenneti): http://crbug.com/487355. Temporary fix for b/20760730 until
  // channel_id_service is supported in cronet.
  if (channel_id_service) {
    crypto_config_.SetChannelIDSource(
        new ChannelIDSourceChromium(channel_id_service));
  }
  if (enable_token_binding && channel_id_service)
    crypto_config_.tb_key_params.push_back(kP256);
  crypto::EnsureOpenSSLInit();
  bool has_aes_hardware_support = !!EVP_has_aes_hardware();
  UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.PreferAesGcm",
                        has_aes_hardware_support);
  if (has_aes_hardware_support || prefer_aes_)
    crypto_config_.PreferAesGcm();
  // When disk cache is used to store the server configs, HttpCache code calls
  // |set_quic_server_info_factory| if |quic_server_info_factory_| wasn't
  // created.
  if (max_server_configs_stored_in_properties > 0) {
    quic_server_info_factory_.reset(
        new PropertiesBasedQuicServerInfoFactory(http_server_properties_));
  }

  // migrate_sessions_early should only be set to true if
  // migrate_sessions_on_network_change is set to true.
  if (migrate_sessions_early)
    DCHECK(migrate_sessions_on_network_change);
  // close_sessions_on_ip_change and migrate_sessions_on_network_change should
  // never be simultaneously set to true.
  DCHECK(!(close_sessions_on_ip_change && migrate_sessions_on_network_change));

  if (migrate_sessions_on_network_change_) {
    NetworkChangeNotifier::AddNetworkObserver(this);
  } else if (close_sessions_on_ip_change_) {
    NetworkChangeNotifier::AddIPAddressObserver(this);
  }
}

QuicStreamFactory::~QuicStreamFactory() {
  CloseAllSessions(ERR_ABORTED, QUIC_CONNECTION_CANCELLED);
  while (!all_sessions_.empty()) {
    delete all_sessions_.begin()->first;
    all_sessions_.erase(all_sessions_.begin());
  }
  while (!active_jobs_.empty()) {
    const QuicServerId server_id = active_jobs_.begin()->first;
    STLDeleteElements(&(active_jobs_[server_id]));
    active_jobs_.erase(server_id);
  }
  if (ssl_config_service_.get())
    ssl_config_service_->RemoveObserver(this);
  if (migrate_sessions_on_network_change_) {
    NetworkChangeNotifier::RemoveNetworkObserver(this);
  } else if (close_sessions_on_ip_change_) {
    NetworkChangeNotifier::RemoveIPAddressObserver(this);
  }
}

void QuicStreamFactory::set_require_confirmation(bool require_confirmation) {
  require_confirmation_ = require_confirmation;
  if (!(local_address_ == IPEndPoint())) {
    http_server_properties_->SetSupportsQuic(!require_confirmation,
                                             local_address_.address());
  }
}

bool QuicStreamFactory::ZeroRTTEnabledFor(const QuicServerId& quic_server_id) {
  return !(require_confirmation_ || CryptoConfigCacheIsEmpty(quic_server_id));
}

base::TimeDelta QuicStreamFactory::GetTimeDelayForWaitingJob(
    const QuicServerId& server_id) {
  if (!delay_tcp_race_ || require_confirmation_)
    return base::TimeDelta();
  int64_t srtt =
      1.5 * GetServerNetworkStatsSmoothedRttInMicroseconds(server_id);
  // Picked 300ms based on mean time from
  // Net.QuicSession.HostResolution.HandshakeConfirmedTime histogram.
  const int kDefaultRTT = 300 * kNumMicrosPerMilli;
  if (!srtt)
    srtt = kDefaultRTT;
  return base::TimeDelta::FromMicroseconds(srtt);
}

void QuicStreamFactory::set_quic_server_info_factory(
    QuicServerInfoFactory* quic_server_info_factory) {
  quic_server_info_factory_.reset(quic_server_info_factory);
}

bool QuicStreamFactory::CanUseExistingSession(const QuicServerId& server_id,
                                              const HostPortPair& destination) {
  // TODO(zhongyi): delete active_sessions_.empty() checks once the
  // android crash issue(crbug.com/498823) is resolved.
  if (active_sessions_.empty())
    return false;

  if (ContainsKey(active_sessions_, server_id))
    return true;

  for (const auto& key_value : active_sessions_) {
    QuicChromiumClientSession* session = key_value.second;
    if (destination.Equals(all_sessions_[session].destination()) &&
        session->CanPool(server_id.host(), server_id.privacy_mode())) {
      return true;
    }
  }

  return false;
}

int QuicStreamFactory::Create(const QuicServerId& server_id,
                              const HostPortPair& destination,
                              int cert_verify_flags,
                              const GURL& url,
                              base::StringPiece method,
                              const BoundNetLog& net_log,
                              QuicStreamRequest* request) {
  DCHECK(server_id.host_port_pair().Equals(HostPortPair::FromURL(url)));
  // Enforce session affinity for promised streams.
  QuicClientPromisedInfo* promised =
      push_promise_index_.GetPromised(url.spec());
  if (promised) {
    QuicChromiumClientSession* session =
        static_cast<QuicChromiumClientSession*>(promised->session());
    DCHECK(session);
    if (session->server_id().privacy_mode() == server_id.privacy_mode()) {
      request->SetSession(session);
      ++num_push_streams_created_;
      return OK;
    }
    // This should happen extremely rarely (if ever), but if somehow a
    // request comes in with a mismatched privacy mode, consider the
    // promise borked.
    promised->Cancel();
  }

  // Use active session for |server_id| if such exists.
  // TODO(rtenneti): crbug.com/498823 - delete active_sessions_.empty() checks.
  if (!active_sessions_.empty()) {
    SessionMap::iterator it = active_sessions_.find(server_id);
    if (it != active_sessions_.end()) {
      QuicChromiumClientSession* session = it->second;
      request->SetSession(session);
      return OK;
    }
  }

  // Associate with active job to |server_id| if such exists.
  if (HasActiveJob(server_id)) {
    active_requests_[request] = server_id;
    job_requests_map_[server_id].insert(request);
    return ERR_IO_PENDING;
  }

  // Pool to active session to |destination| if possible.
  if (!active_sessions_.empty() && !disable_connection_pooling_) {
    for (const auto& key_value : active_sessions_) {
      QuicChromiumClientSession* session = key_value.second;
      if (destination.Equals(all_sessions_[session].destination()) &&
          session->CanPool(server_id.host(), server_id.privacy_mode())) {
        request->SetSession(session);
        return OK;
      }
    }
  }

  // TODO(rtenneti): |task_runner_| is used by the Job. Initialize task_runner_
  // in the constructor after WebRequestActionWithThreadsTest.* tests are fixed.
  if (!task_runner_)
    task_runner_ = base::ThreadTaskRunnerHandle::Get().get();

  QuicServerInfo* quic_server_info = nullptr;
  if (quic_server_info_factory_.get()) {
    bool load_from_disk_cache = !disable_disk_cache_;
    MaybeInitialize();
    if (!ContainsKey(quic_supported_servers_at_startup_, destination)) {
      // If there is no entry for QUIC, consider that as a new server and
      // don't wait for Cache thread to load the data for that server.
      load_from_disk_cache = false;
    }
    if (load_from_disk_cache && CryptoConfigCacheIsEmpty(server_id)) {
      quic_server_info = quic_server_info_factory_->GetForServer(server_id);
    }
  }

  QuicSessionKey key(destination, server_id);
  std::unique_ptr<Job> job(
      new Job(this, host_resolver_, key, WasQuicRecentlyBroken(server_id),
              cert_verify_flags, quic_server_info, net_log));
  int rv = job->Run(base::Bind(&QuicStreamFactory::OnJobComplete,
                               base::Unretained(this), job.get()));
  if (rv == ERR_IO_PENDING) {
    active_requests_[request] = server_id;
    job_requests_map_[server_id].insert(request);
    active_jobs_[server_id].insert(job.release());
    return rv;
  }
  if (rv == OK) {
    // TODO(rtenneti): crbug.com/498823 - revert active_sessions_.empty()
    // related changes.
    if (active_sessions_.empty())
      return ERR_QUIC_PROTOCOL_ERROR;
    SessionMap::iterator it = active_sessions_.find(server_id);
    DCHECK(it != active_sessions_.end());
    if (it == active_sessions_.end())
      return ERR_QUIC_PROTOCOL_ERROR;
    QuicChromiumClientSession* session = it->second;
    request->SetSession(session);
  }
  return rv;
}

QuicStreamFactory::QuicSessionKey::QuicSessionKey(
    const HostPortPair& destination,
    const QuicServerId& server_id)
    : destination_(destination), server_id_(server_id) {}

bool QuicStreamFactory::QuicSessionKey::operator<(
    const QuicSessionKey& other) const {
  return std::tie(destination_, server_id_) <
         std::tie(other.destination_, other.server_id_);
}

bool QuicStreamFactory::QuicSessionKey::operator==(
    const QuicSessionKey& other) const {
  return destination_.Equals(other.destination_) &&
         server_id_ == other.server_id_;
}

void QuicStreamFactory::CreateAuxilaryJob(const QuicSessionKey& key,
                                          int cert_verify_flags,
                                          const BoundNetLog& net_log) {
  Job* aux_job =
      new Job(this, host_resolver_, key, WasQuicRecentlyBroken(key.server_id()),
              cert_verify_flags, nullptr, net_log);
  active_jobs_[key.server_id()].insert(aux_job);
  task_runner_->PostTask(FROM_HERE,
                         base::Bind(&QuicStreamFactory::Job::RunAuxilaryJob,
                                    aux_job->GetWeakPtr()));
}

bool QuicStreamFactory::OnResolution(const QuicSessionKey& key,
                                     const AddressList& address_list) {
  const QuicServerId& server_id(key.server_id());
  DCHECK(!HasActiveSession(server_id));
  if (disable_connection_pooling_) {
    return false;
  }
  for (const IPEndPoint& address : address_list) {
    if (!ContainsKey(ip_aliases_, address))
      continue;

    const SessionSet& sessions = ip_aliases_[address];
    for (QuicChromiumClientSession* session : sessions) {
      if (!session->CanPool(server_id.host(), server_id.privacy_mode()))
        continue;
      active_sessions_[server_id] = session;
      session_aliases_[session].insert(key);
      return true;
    }
  }
  return false;
}

void QuicStreamFactory::OnJobComplete(Job* job, int rv) {
  // Copy |server_id|, because |job| might be destroyed before this method
  // returns.
  const QuicServerId server_id(job->key().server_id());
  if (rv != OK) {
    JobSet* jobs = &(active_jobs_[server_id]);
    if (jobs->size() > 1) {
      // If there is another pending job, then we can delete this job and let
      // the other job handle the request.
      job->Cancel();
      jobs->erase(job);
      delete job;
      return;
    }
  }

  if (rv == OK) {
    if (!always_require_handshake_confirmation_)
      set_require_confirmation(false);

    if (!job_requests_map_[server_id].empty()) {
      SessionMap::iterator session_it = active_sessions_.find(server_id);
      DCHECK(session_it != active_sessions_.end());
      QuicChromiumClientSession* session = session_it->second;
      for (QuicStreamRequest* request : job_requests_map_[server_id]) {
        DCHECK(request->server_id() == server_id);
        // Do not notify |request| yet.
        request->SetSession(session);
      }
    }
  }

  while (!job_requests_map_[server_id].empty()) {
    RequestSet::iterator it = job_requests_map_[server_id].begin();
    QuicStreamRequest* request = *it;
    job_requests_map_[server_id].erase(it);
    active_requests_.erase(request);
    // Even though we're invoking callbacks here, we don't need to worry
    // about |this| being deleted, because the factory is owned by the
    // profile which can not be deleted via callbacks.
    request->OnRequestComplete(rv);
  }

  for (Job* other_job : active_jobs_[server_id]) {
    if (other_job != job)
      other_job->Cancel();
  }

  STLDeleteElements(&(active_jobs_[server_id]));
  active_jobs_.erase(server_id);
  job_requests_map_.erase(server_id);
}

std::unique_ptr<QuicHttpStream> QuicStreamFactory::CreateFromSession(
    QuicChromiumClientSession* session) {
  return std::unique_ptr<QuicHttpStream>(
      new QuicHttpStream(session->GetWeakPtr()));
}

QuicChromiumClientSession::QuicDisabledReason
QuicStreamFactory::QuicDisabledReason(uint16_t port) const {
  if (max_number_of_lossy_connections_ > 0 &&
      number_of_lossy_connections_.find(port) !=
          number_of_lossy_connections_.end() &&
      number_of_lossy_connections_.at(port) >=
          max_number_of_lossy_connections_) {
    return QuicChromiumClientSession::QUIC_DISABLED_BAD_PACKET_LOSS_RATE;
  }
  if (threshold_public_resets_post_handshake_ > 0 &&
      num_public_resets_post_handshake_ >=
          threshold_public_resets_post_handshake_) {
    return QuicChromiumClientSession::QUIC_DISABLED_PUBLIC_RESET_POST_HANDSHAKE;
  }
  if (threshold_timeouts_with_open_streams_ > 0 &&
      num_timeouts_with_open_streams_ >=
          threshold_timeouts_with_open_streams_) {
    return QuicChromiumClientSession::QUIC_DISABLED_TIMEOUT_WITH_OPEN_STREAMS;
  }
  return QuicChromiumClientSession::QUIC_DISABLED_NOT;
}

const char* QuicStreamFactory::QuicDisabledReasonString() const {
  // TODO(ckrasic) - better solution for port/lossy connections?
  const uint16_t port = 443;
  switch (QuicDisabledReason(port)) {
    case QuicChromiumClientSession::QUIC_DISABLED_BAD_PACKET_LOSS_RATE:
      return "Bad packet loss rate.";
    case QuicChromiumClientSession::QUIC_DISABLED_PUBLIC_RESET_POST_HANDSHAKE:
      return "Public resets after successful handshakes.";
    case QuicChromiumClientSession::QUIC_DISABLED_TIMEOUT_WITH_OPEN_STREAMS:
      return "Connection timeouts with streams open.";
    default:
      return "";
  }
}

bool QuicStreamFactory::IsQuicDisabled(uint16_t port) const {
  return status_ != OPEN;
}

bool QuicStreamFactory::OnHandshakeConfirmed(QuicChromiumClientSession* session,
                                             float packet_loss_rate) {
  DCHECK(session);
  uint16_t port = session->server_id().port();
  if (packet_loss_rate < packet_loss_threshold_) {
    number_of_lossy_connections_[port] = 0;
    return false;
  }

  // We mark it as recently broken, which means that 0-RTT will be disabled
  // but we'll still race.
  http_server_properties_->MarkAlternativeServiceRecentlyBroken(
      AlternativeService(QUIC, session->server_id().host(), port));

  bool was_quic_disabled = IsQuicDisabled(port);
  ++number_of_lossy_connections_[port];

  // Collect data for port 443 for packet loss events.
  if (port == 443 && max_number_of_lossy_connections_ > 0) {
    UMA_HISTOGRAM_SPARSE_SLOWLY(
        base::StringPrintf("Net.QuicStreamFactory.BadPacketLossEvents%d",
                           max_number_of_lossy_connections_),
        std::min(number_of_lossy_connections_[port],
                 max_number_of_lossy_connections_));
  }

  MaybeDisableQuic(port);

  bool is_quic_disabled = IsQuicDisabled(port);
  if (is_quic_disabled) {
    // Close QUIC connection if Quic is disabled for this port.
    session->CloseSessionOnErrorAndNotifyFactoryLater(
        ERR_ABORTED, QUIC_BAD_PACKET_LOSS_RATE);

    // If this bad packet loss rate disabled the QUIC, then record it.
    if (!was_quic_disabled)
      UMA_HISTOGRAM_SPARSE_SLOWLY("Net.QuicStreamFactory.QuicIsDisabled", port);
  }
  return is_quic_disabled;
}

void QuicStreamFactory::OnTcpJobCompleted(bool succeeded) {
  if (status_ != CLOSED)
    return;

  // If QUIC connections are failing while TCP connections are working,
  // then stop using QUIC. On the other hand if both QUIC and TCP are
  // failing, then attempt to use QUIC again.
  if (succeeded) {
    status_ = DISABLED;
    return;
  }

  status_ = OPEN;
  num_timeouts_with_open_streams_ = 0;
}

void QuicStreamFactory::OnIdleSession(QuicChromiumClientSession* session) {}

void QuicStreamFactory::OnSessionGoingAway(QuicChromiumClientSession* session) {
  const AliasSet& aliases = session_aliases_[session];
  for (AliasSet::const_iterator it = aliases.begin(); it != aliases.end();
       ++it) {
    const QuicServerId& server_id = it->server_id();
    DCHECK(active_sessions_.count(server_id));
    DCHECK_EQ(session, active_sessions_[server_id]);
    // Track sessions which have recently gone away so that we can disable
    // port suggestions.
    if (session->goaway_received()) {
      gone_away_aliases_.insert(*it);
    }

    active_sessions_.erase(server_id);
    ProcessGoingAwaySession(session, server_id, true);
  }
  ProcessGoingAwaySession(session, all_sessions_[session].server_id(), false);
  if (!aliases.empty()) {
    const IPEndPoint peer_address = session->connection()->peer_address();
    ip_aliases_[peer_address].erase(session);
    if (ip_aliases_[peer_address].empty()) {
      ip_aliases_.erase(peer_address);
    }
  }
  session_aliases_.erase(session);
}

void QuicStreamFactory::MaybeDisableQuic(QuicChromiumClientSession* session) {
  DCHECK(session);
  uint16_t port = session->server_id().port();
  if (IsQuicDisabled(port))
    return;

  // Expire the oldest disabled_reason if appropriate.  This enforces that we
  // only consider the max_disabled_reasons_ most recent sessions.
  QuicChromiumClientSession::QuicDisabledReason disabled_reason;
  if (static_cast<int>(disabled_reasons_.size()) == max_disabled_reasons_) {
    disabled_reason = disabled_reasons_.front();
    disabled_reasons_.pop_front();
    if (disabled_reason ==
        QuicChromiumClientSession::QUIC_DISABLED_PUBLIC_RESET_POST_HANDSHAKE) {
      --num_public_resets_post_handshake_;
    } else if (disabled_reason == QuicChromiumClientSession::
                                      QUIC_DISABLED_TIMEOUT_WITH_OPEN_STREAMS) {
      --num_timeouts_with_open_streams_;
    }
  }
  disabled_reason = session->disabled_reason();
  disabled_reasons_.push_back(disabled_reason);
  if (disabled_reason ==
      QuicChromiumClientSession::QUIC_DISABLED_PUBLIC_RESET_POST_HANDSHAKE) {
    ++num_public_resets_post_handshake_;
  } else if (disabled_reason == QuicChromiumClientSession::
                                    QUIC_DISABLED_TIMEOUT_WITH_OPEN_STREAMS) {
    ++num_timeouts_with_open_streams_;
  }
  if (num_timeouts_with_open_streams_ > max_timeouts_with_open_streams_) {
    max_timeouts_with_open_streams_ = num_timeouts_with_open_streams_;
    UMA_HISTOGRAM_CUSTOM_COUNTS("Net.QuicStreamFactory.TimeoutsWithOpenStreams",
                                num_timeouts_with_open_streams_, 0, 20, 10);
  }

  if (num_public_resets_post_handshake_ > max_public_resets_post_handshake_) {
    max_public_resets_post_handshake_ = num_public_resets_post_handshake_;
    UMA_HISTOGRAM_CUSTOM_COUNTS(
        "Net.QuicStreamFactory.PublicResetsPostHandshake",
        num_public_resets_post_handshake_, 0, 20, 10);
  }

  MaybeDisableQuic(port);
  if (IsQuicDisabled(port)) {
    if (disabled_reason ==
        QuicChromiumClientSession::QUIC_DISABLED_PUBLIC_RESET_POST_HANDSHAKE) {
      session->CloseSessionOnErrorAndNotifyFactoryLater(
          ERR_ABORTED, QUIC_PUBLIC_RESETS_POST_HANDSHAKE);
    } else if (disabled_reason == QuicChromiumClientSession::
                                      QUIC_DISABLED_TIMEOUT_WITH_OPEN_STREAMS) {
      session->CloseSessionOnErrorAndNotifyFactoryLater(
          ERR_ABORTED, QUIC_TIMEOUTS_WITH_OPEN_STREAMS);
    }
    UMA_HISTOGRAM_ENUMERATION("Net.QuicStreamFactory.DisabledReasons",
                              disabled_reason,
                              QuicChromiumClientSession::QUIC_DISABLED_MAX);
  }
}

void QuicStreamFactory::MaybeDisableQuic(uint16_t port) {
  if (status_ == DISABLED)
    return;

  QuicChromiumClientSession::QuicDisabledReason disabled_reason =
      QuicDisabledReason(port);
  if (disabled_reason == QuicChromiumClientSession::QUIC_DISABLED_NOT) {
    DCHECK_EQ(OPEN, status_);
    return;
  }

  if (disabled_reason ==
      QuicChromiumClientSession::QUIC_DISABLED_TIMEOUT_WITH_OPEN_STREAMS) {
    // When QUIC there are too many timeouts with open stream, the factory
    // should be closed. When TCP jobs complete, they will move the factory
    // to either fully disabled or back to open.
    status_ = CLOSED;
    DCHECK(IsQuicDisabled(port));
    DCHECK_NE(QuicChromiumClientSession::QuicDisabledReason(port),
              QuicChromiumClientSession::QUIC_DISABLED_NOT);
    return;
  }

  status_ = DISABLED;
  DCHECK(IsQuicDisabled(port));
  DCHECK_NE(QuicChromiumClientSession::QuicDisabledReason(port),
            QuicChromiumClientSession::QUIC_DISABLED_NOT);
}

void QuicStreamFactory::OnSessionClosed(QuicChromiumClientSession* session) {
  DCHECK_EQ(0u, session->GetNumActiveStreams());
  MaybeDisableQuic(session);
  OnSessionGoingAway(session);
  delete session;
  all_sessions_.erase(session);
}

void QuicStreamFactory::OnSessionConnectTimeout(
    QuicChromiumClientSession* session) {
  const AliasSet& aliases = session_aliases_[session];

  if (aliases.empty()) {
    return;
  }

  for (const QuicSessionKey& key : aliases) {
    const QuicServerId& server_id = key.server_id();
    SessionMap::iterator session_it = active_sessions_.find(server_id);
    DCHECK(session_it != active_sessions_.end());
    DCHECK_EQ(session, session_it->second);
    active_sessions_.erase(session_it);
  }

  const IPEndPoint peer_address = session->connection()->peer_address();
  ip_aliases_[peer_address].erase(session);
  if (ip_aliases_[peer_address].empty()) {
    ip_aliases_.erase(peer_address);
  }
  QuicSessionKey key = *aliases.begin();
  session_aliases_.erase(session);
  Job* job = new Job(this, host_resolver_, session, key);
  active_jobs_[key.server_id()].insert(job);
  int rv = job->Run(base::Bind(&QuicStreamFactory::OnJobComplete,
                               base::Unretained(this), job));
  DCHECK_EQ(ERR_IO_PENDING, rv);
}

void QuicStreamFactory::CancelRequest(QuicStreamRequest* request) {
  RequestMap::iterator request_it = active_requests_.find(request);
  DCHECK(request_it != active_requests_.end());
  const QuicServerId& server_id = request_it->second;
  job_requests_map_[server_id].erase(request);
  active_requests_.erase(request_it);
}

void QuicStreamFactory::CloseAllSessions(int error, QuicErrorCode quic_error) {
  UMA_HISTOGRAM_SPARSE_SLOWLY("Net.QuicSession.CloseAllSessionsError", -error);
  while (!active_sessions_.empty()) {
    size_t initial_size = active_sessions_.size();
    active_sessions_.begin()->second->CloseSessionOnError(error, quic_error);
    DCHECK_NE(initial_size, active_sessions_.size());
  }
  while (!all_sessions_.empty()) {
    size_t initial_size = all_sessions_.size();
    all_sessions_.begin()->first->CloseSessionOnError(error, quic_error);
    DCHECK_NE(initial_size, all_sessions_.size());
  }
  DCHECK(all_sessions_.empty());
}

std::unique_ptr<base::Value> QuicStreamFactory::QuicStreamFactoryInfoToValue()
    const {
  std::unique_ptr<base::ListValue> list(new base::ListValue());

  for (SessionMap::const_iterator it = active_sessions_.begin();
       it != active_sessions_.end(); ++it) {
    const QuicServerId& server_id = it->first;
    QuicChromiumClientSession* session = it->second;
    const AliasSet& aliases = session_aliases_.find(session)->second;
    // Only add a session to the list once.
    if (server_id == aliases.begin()->server_id()) {
      std::set<HostPortPair> hosts;
      for (AliasSet::const_iterator alias_it = aliases.begin();
           alias_it != aliases.end(); ++alias_it) {
        hosts.insert(alias_it->server_id().host_port_pair());
      }
      list->Append(session->GetInfoAsValue(hosts));
    }
  }
  return std::move(list);
}

void QuicStreamFactory::ClearCachedStatesInCryptoConfig() {
  crypto_config_.ClearCachedStates();
}

void QuicStreamFactory::OnIPAddressChanged() {
  num_timeouts_with_open_streams_ = 0;
  status_ = OPEN;
  CloseAllSessions(ERR_NETWORK_CHANGED, QUIC_IP_ADDRESS_CHANGED);
  set_require_confirmation(true);
}

void QuicStreamFactory::OnNetworkConnected(NetworkHandle network) {
  num_timeouts_with_open_streams_ = 0;
  status_ = OPEN;
}

void QuicStreamFactory::OnNetworkMadeDefault(NetworkHandle network) {}

void QuicStreamFactory::OnNetworkDisconnected(NetworkHandle network) {
  ScopedConnectionMigrationEventLog scoped_event_log(net_log_,
                                                     "OnNetworkDisconnected");
  MaybeMigrateOrCloseSessions(network, /*force_close=*/true,
                              scoped_event_log.net_log());
  set_require_confirmation(true);
}

// This method is expected to only be called when migrating from Cellular to
// WiFi on Android.
void QuicStreamFactory::OnNetworkSoonToDisconnect(NetworkHandle network) {
  ScopedConnectionMigrationEventLog scoped_event_log(
      net_log_, "OnNetworkSoonToDisconnect");
  MaybeMigrateOrCloseSessions(network, /*force_close=*/false,
                              scoped_event_log.net_log());
}

NetworkHandle QuicStreamFactory::FindAlternateNetwork(
    NetworkHandle old_network) {
  // Find a new network that sessions bound to |old_network| can be migrated to.
  NetworkChangeNotifier::NetworkList network_list;
  NetworkChangeNotifier::GetConnectedNetworks(&network_list);
  for (NetworkHandle new_network : network_list) {
    if (new_network != old_network) {
      return new_network;
    }
  }
  return NetworkChangeNotifier::kInvalidNetworkHandle;
}

void QuicStreamFactory::MaybeMigrateOrCloseSessions(
    NetworkHandle network,
    bool force_close,
    const BoundNetLog& bound_net_log) {
  DCHECK_NE(NetworkChangeNotifier::kInvalidNetworkHandle, network);
  NetworkHandle new_network = FindAlternateNetwork(network);

  QuicStreamFactory::SessionIdMap::iterator it = all_sessions_.begin();
  while (it != all_sessions_.end()) {
    QuicChromiumClientSession* session = it->first;
    ++it;

    if (session->GetDefaultSocket()->GetBoundNetwork() != network) {
      // If session is not bound to |network|, move on.
      HistogramAndLogMigrationFailure(
          bound_net_log, MIGRATION_STATUS_ALREADY_MIGRATED,
          session->connection_id(), "Not bound to network");
      continue;
    }
    if (session->GetNumActiveStreams() == 0) {
      // Close idle sessions.
      HistogramAndLogMigrationFailure(
          bound_net_log, MIGRATION_STATUS_NO_MIGRATABLE_STREAMS,
          session->connection_id(), "No active sessions");
      session->CloseSessionOnError(
          ERR_NETWORK_CHANGED, QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS);
      continue;
    }
    // If session has active streams, mark it as going away.
    OnSessionGoingAway(session);

    if (new_network == NetworkChangeNotifier::kInvalidNetworkHandle) {
      // No new network was found.
      // TODO (jri): Add histogram for this failure case.
      bound_net_log.AddEvent(
          NetLog::TYPE_QUIC_CONNECTION_MIGRATION_FAILURE,
          base::Bind(&NetLogQuicConnectionMigrationFailureCallback,
                     session->connection_id(), "No new network"));
      if (force_close) {
        session->CloseSessionOnError(ERR_NETWORK_CHANGED,
                                     QUIC_CONNECTION_MIGRATION_NO_NEW_NETWORK);
      }
      continue;
    }
    if (session->config()->DisableConnectionMigration()) {
      // Do not migrate sessions where connection migration is disabled by
      // config.
      HistogramAndLogMigrationFailure(bound_net_log, MIGRATION_STATUS_DISABLED,
                                      session->connection_id(),
                                      "Migration disabled");
      if (force_close) {
        // Close sessions where connection migration is disabled.
        session->CloseSessionOnError(ERR_NETWORK_CHANGED,
                                     QUIC_IP_ADDRESS_CHANGED);
      }
      continue;
    }
    if (session->HasNonMigratableStreams()) {
      // Do not migrate sessions with non-migratable streams.
      HistogramAndLogMigrationFailure(
          bound_net_log, MIGRATION_STATUS_NON_MIGRATABLE_STREAM,
          session->connection_id(), "Non-migratable stream");
      if (force_close) {
        // Close sessions with non-migratable streams.
        session->CloseSessionOnError(
            ERR_NETWORK_CHANGED,
            QUIC_CONNECTION_MIGRATION_NON_MIGRATABLE_STREAM);
      }
      continue;
    }

    MigrateSessionToNewNetwork(session, new_network, bound_net_log, nullptr);
  }
}

void QuicStreamFactory::MaybeMigrateSingleSession(
    QuicChromiumClientSession* session,
    MigrationCause migration_cause,
    scoped_refptr<StringIOBuffer> packet) {
  ScopedConnectionMigrationEventLog scoped_event_log(
      net_log_,
      migration_cause == EARLY_MIGRATION ? "EarlyMigration" : "WriteError");
  if (!migrate_sessions_on_network_change_ ||
      (migration_cause == EARLY_MIGRATION && !migrate_sessions_early_) ||
      session->HasNonMigratableStreams() ||
      session->config()->DisableConnectionMigration()) {
    HistogramAndLogMigrationFailure(
        scoped_event_log.net_log(), MIGRATION_STATUS_DISABLED,
        session->connection_id(), "Migration disabled");
    return;
  }
  NetworkHandle new_network =
      FindAlternateNetwork(session->GetDefaultSocket()->GetBoundNetwork());
  if (new_network == NetworkChangeNotifier::kInvalidNetworkHandle) {
    // No alternate network found.
    // TODO (jri): Add histogram for this failure case.
    scoped_event_log.net_log().AddEvent(
        NetLog::TYPE_QUIC_CONNECTION_MIGRATION_FAILURE,
        base::Bind(&NetLogQuicConnectionMigrationFailureCallback,
                   session->connection_id(), "No new network"));
    return;
  }
  OnSessionGoingAway(session);
  MigrateSessionToNewNetwork(session, new_network, scoped_event_log.net_log(),
                             packet);
}

void QuicStreamFactory::MigrateSessionToNewPeerAddress(
    QuicChromiumClientSession* session,
    IPEndPoint peer_address,
    const BoundNetLog& bound_net_log) {
  if (!allow_server_migration_)
    return;
  // Specifying kInvalidNetworkHandle for the |network| parameter
  // causes the session to use the default network for the new socket.
  MigrateSession(session, peer_address,
                 NetworkChangeNotifier::kInvalidNetworkHandle, bound_net_log,
                 nullptr);
}

void QuicStreamFactory::MigrateSessionToNewNetwork(
    QuicChromiumClientSession* session,
    NetworkHandle network,
    const BoundNetLog& bound_net_log,
    scoped_refptr<StringIOBuffer> packet) {
  MigrateSession(session, session->connection()->peer_address(), network,
                 bound_net_log, packet);
}

void QuicStreamFactory::MigrateSession(QuicChromiumClientSession* session,
                                       IPEndPoint peer_address,
                                       NetworkHandle network,
                                       const BoundNetLog& bound_net_log,
                                       scoped_refptr<StringIOBuffer> packet) {
  // Use OS-specified port for socket (DEFAULT_BIND) instead of
  // using the PortSuggester since the connection is being migrated
  // and not being newly created.
  std::unique_ptr<DatagramClientSocket> socket(
      client_socket_factory_->CreateDatagramClientSocket(
          DatagramSocket::DEFAULT_BIND, RandIntCallback(),
          session->net_log().net_log(), session->net_log().source()));
  if (ConfigureSocket(socket.get(), peer_address, network) != OK) {
    session->CloseSessionOnError(ERR_NETWORK_CHANGED, QUIC_INTERNAL_ERROR);
    HistogramAndLogMigrationFailure(
        bound_net_log, MIGRATION_STATUS_INTERNAL_ERROR,
        session->connection_id(), "Socket configuration failed");
    return;
  }
  std::unique_ptr<QuicChromiumPacketReader> new_reader(
      new QuicChromiumPacketReader(socket.get(), clock_.get(), session,
                                   yield_after_packets_, yield_after_duration_,
                                   session->net_log()));
  std::unique_ptr<QuicChromiumPacketWriter> new_writer(
      new QuicChromiumPacketWriter(socket.get()));
  net::QuicChromiumPacketWriter::WriteErrorObserver* observer = session;
  //  new_writer->Initialize(observer, session->connection());

  if (!session->MigrateToSocket(std::move(socket), std::move(new_reader),
                                std::move(new_writer), packet)) {
    session->CloseSessionOnError(ERR_NETWORK_CHANGED,
                                 QUIC_CONNECTION_MIGRATION_TOO_MANY_CHANGES);
    HistogramAndLogMigrationFailure(
        bound_net_log, MIGRATION_STATUS_TOO_MANY_CHANGES,
        session->connection_id(), "Too many migrations");
    return;
  }
  HistogramMigrationStatus(MIGRATION_STATUS_SUCCESS);
  bound_net_log.AddEvent(
      NetLog::TYPE_QUIC_CONNECTION_MIGRATION_SUCCESS,
      base::Bind(&NetLogQuicConnectionMigrationSuccessCallback,
                 session->connection_id()));
}

void QuicStreamFactory::OnSSLConfigChanged() {
  CloseAllSessions(ERR_CERT_DATABASE_CHANGED, QUIC_CONNECTION_CANCELLED);
}

void QuicStreamFactory::OnCertAdded(const X509Certificate* cert) {
  CloseAllSessions(ERR_CERT_DATABASE_CHANGED, QUIC_CONNECTION_CANCELLED);
}

void QuicStreamFactory::OnCACertChanged(const X509Certificate* cert) {
  // We should flush the sessions if we removed trust from a
  // cert, because a previously trusted server may have become
  // untrusted.
  //
  // We should not flush the sessions if we added trust to a cert.
  //
  // Since the OnCACertChanged method doesn't tell us what
  // kind of change it is, we have to flush the socket
  // pools to be safe.
  CloseAllSessions(ERR_CERT_DATABASE_CHANGED, QUIC_CONNECTION_CANCELLED);
}

bool QuicStreamFactory::HasActiveSession(const QuicServerId& server_id) const {
  // TODO(rtenneti): crbug.com/498823 - delete active_sessions_.empty() check.
  if (active_sessions_.empty())
    return false;
  return ContainsKey(active_sessions_, server_id);
}

bool QuicStreamFactory::HasActiveJob(const QuicServerId& server_id) const {
  return ContainsKey(active_jobs_, server_id);
}

int QuicStreamFactory::ConfigureSocket(DatagramClientSocket* socket,
                                       IPEndPoint addr,
                                       NetworkHandle network) {
  if (enable_non_blocking_io_ &&
      client_socket_factory_ == ClientSocketFactory::GetDefaultFactory()) {
#if defined(OS_WIN)
    static_cast<UDPClientSocket*>(socket)->UseNonBlockingIO();
#endif
  }

  int rv;
  if (migrate_sessions_on_network_change_) {
    // If caller leaves network unspecified, use current default network.
    if (network == NetworkChangeNotifier::kInvalidNetworkHandle) {
      rv = socket->ConnectUsingDefaultNetwork(addr);
    } else {
      rv = socket->ConnectUsingNetwork(network, addr);
    }
  } else {
    rv = socket->Connect(addr);
  }
  if (rv != OK) {
    HistogramCreateSessionFailure(CREATION_ERROR_CONNECTING_SOCKET);
    return rv;
  }

  rv = socket->SetReceiveBufferSize(socket_receive_buffer_size_);
  if (rv != OK) {
    HistogramCreateSessionFailure(CREATION_ERROR_SETTING_RECEIVE_BUFFER);
    return rv;
  }

  // Set a buffer large enough to contain the initial CWND's worth of packet
  // to work around the problem with CHLO packets being sent out with the
  // wrong encryption level, when the send buffer is full.
  rv = socket->SetSendBufferSize(kMaxPacketSize * 20);
  if (rv != OK) {
    HistogramCreateSessionFailure(CREATION_ERROR_SETTING_SEND_BUFFER);
    return rv;
  }

  socket->GetLocalAddress(&local_address_);
  if (check_persisted_supports_quic_) {
    check_persisted_supports_quic_ = false;
    IPAddress last_address;
    if (http_server_properties_->GetSupportsQuic(&last_address) &&
        last_address == local_address_.address()) {
      require_confirmation_ = false;
    }
  }

  return OK;
}

int QuicStreamFactory::CreateSession(
    const QuicSessionKey& key,
    int cert_verify_flags,
    std::unique_ptr<QuicServerInfo> server_info,
    const AddressList& address_list,
    base::TimeTicks dns_resolution_end_time,
    const BoundNetLog& net_log,
    QuicChromiumClientSession** session) {
  TRACE_EVENT0("net", "QuicStreamFactory::CreateSession");
  IPEndPoint addr = *address_list.begin();
  bool enable_port_selection = enable_port_selection_;
  if (enable_port_selection && ContainsKey(gone_away_aliases_, key)) {
    // Disable port selection when the server is going away.
    // There is no point in trying to return to the same server, if
    // that server is no longer handling requests.
    enable_port_selection = false;
    gone_away_aliases_.erase(key);
  }
  const QuicServerId& server_id = key.server_id();
  scoped_refptr<PortSuggester> port_suggester =
      new PortSuggester(server_id.host_port_pair(), port_seed_);
  DatagramSocket::BindType bind_type =
      enable_port_selection ? DatagramSocket::RANDOM_BIND
                            :            // Use our callback.
          DatagramSocket::DEFAULT_BIND;  // Use OS to randomize.

  std::unique_ptr<DatagramClientSocket> socket(
      client_socket_factory_->CreateDatagramClientSocket(
          bind_type, base::Bind(&PortSuggester::SuggestPort, port_suggester),
          net_log.net_log(), net_log.source()));

  // Passing in kInvalidNetworkHandle binds socket to default network.
  int rv = ConfigureSocket(socket.get(), addr,
                           NetworkChangeNotifier::kInvalidNetworkHandle);
  if (rv != OK) {
    return rv;
  }

  if (enable_port_selection) {
    DCHECK_LE(1u, port_suggester->call_count());
  } else {
    DCHECK_EQ(0u, port_suggester->call_count());
  }

  if (!helper_.get()) {
    helper_.reset(
        new QuicChromiumConnectionHelper(clock_.get(), random_generator_));
  }

  if (!alarm_factory_.get()) {
    alarm_factory_.reset(new QuicChromiumAlarmFactory(
        base::ThreadTaskRunnerHandle::Get().get(), clock_.get()));
  }
  QuicConnectionId connection_id = random_generator_->RandUint64();
  InitializeCachedStateInCryptoConfig(server_id, server_info, &connection_id);

  QuicChromiumPacketWriter* writer = new QuicChromiumPacketWriter(socket.get());
  QuicConnection* connection = new QuicConnection(
      connection_id, addr, helper_.get(), alarm_factory_.get(), writer,
      true /* owns_writer */, Perspective::IS_CLIENT, supported_versions_);
  connection->SetMaxPacketLength(max_packet_length_);

  QuicConfig config = config_;
  config.SetSocketReceiveBufferToSend(socket_receive_buffer_size_);
  config.set_max_undecryptable_packets(kMaxUndecryptablePackets);
  config.SetInitialSessionFlowControlWindowToSend(
      kQuicSessionMaxRecvWindowSize);
  config.SetInitialStreamFlowControlWindowToSend(kQuicStreamMaxRecvWindowSize);
  int64_t srtt = GetServerNetworkStatsSmoothedRttInMicroseconds(server_id);
  if (srtt > 0)
    config.SetInitialRoundTripTimeUsToSend(static_cast<uint32_t>(srtt));
  config.SetBytesForConnectionIdToSend(0);

  if (force_hol_blocking_)
    config.SetForceHolBlocking();

  if (quic_server_info_factory_.get() && !server_info) {
    // Start the disk cache loading so that we can persist the newer QUIC server
    // information and/or inform the disk cache that we have reused
    // |server_info|.
    server_info.reset(quic_server_info_factory_->GetForServer(server_id));
    server_info->Start();
  }

  // Use the factory to create a new socket performance watcher, and pass the
  // ownership to QuicChromiumClientSession.
  std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher;
  if (socket_performance_watcher_factory_) {
    socket_performance_watcher =
        socket_performance_watcher_factory_->CreateSocketPerformanceWatcher(
            SocketPerformanceWatcherFactory::PROTOCOL_QUIC);
  }

  *session = new QuicChromiumClientSession(
      connection, std::move(socket), this, quic_crypto_client_stream_factory_,
      clock_.get(), transport_security_state_, std::move(server_info),
      server_id, yield_after_packets_, yield_after_duration_, cert_verify_flags,
      config, &crypto_config_, network_connection_.GetDescription(),
      dns_resolution_end_time, &push_promise_index_,
      base::ThreadTaskRunnerHandle::Get().get(),
      std::move(socket_performance_watcher), net_log.net_log());

  all_sessions_[*session] = key;  // owning pointer
  writer->Initialize(*session, connection);

  (*session)->Initialize();
  bool closed_during_initialize = !ContainsKey(all_sessions_, *session) ||
                                  !(*session)->connection()->connected();
  UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.ClosedDuringInitializeSession",
                        closed_during_initialize);
  if (closed_during_initialize) {
    DLOG(DFATAL) << "Session closed during initialize";
    *session = nullptr;
    return ERR_CONNECTION_CLOSED;
  }
  return OK;
}

void QuicStreamFactory::ActivateSession(const QuicSessionKey& key,
                                        QuicChromiumClientSession* session) {
  const QuicServerId& server_id(key.server_id());
  DCHECK(!HasActiveSession(server_id));
  UMA_HISTOGRAM_COUNTS("Net.QuicActiveSessions", active_sessions_.size());
  active_sessions_[server_id] = session;
  session_aliases_[session].insert(key);
  const IPEndPoint peer_address = session->connection()->peer_address();
  DCHECK(!ContainsKey(ip_aliases_[peer_address], session));
  ip_aliases_[peer_address].insert(session);
}

int64_t QuicStreamFactory::GetServerNetworkStatsSmoothedRttInMicroseconds(
    const QuicServerId& server_id) const {
  url::SchemeHostPort server("https", server_id.host_port_pair().host(),
                             server_id.host_port_pair().port());
  const ServerNetworkStats* stats =
      http_server_properties_->GetServerNetworkStats(server);
  if (stats == nullptr)
    return 0;
  return stats->srtt.InMicroseconds();
}

bool QuicStreamFactory::WasQuicRecentlyBroken(
    const QuicServerId& server_id) const {
  const AlternativeService alternative_service(QUIC,
                                               server_id.host_port_pair());
  return http_server_properties_->WasAlternativeServiceRecentlyBroken(
      alternative_service);
}

bool QuicStreamFactory::CryptoConfigCacheIsEmpty(
    const QuicServerId& server_id) {
  QuicCryptoClientConfig::CachedState* cached =
      crypto_config_.LookupOrCreate(server_id);
  return cached->IsEmpty();
}

void QuicStreamFactory::InitializeCachedStateInCryptoConfig(
    const QuicServerId& server_id,
    const std::unique_ptr<QuicServerInfo>& server_info,
    QuicConnectionId* connection_id) {
  QuicCryptoClientConfig::CachedState* cached =
      crypto_config_.LookupOrCreate(server_id);
  if (cached->has_server_designated_connection_id())
    *connection_id = cached->GetNextServerDesignatedConnectionId();

  if (!cached->IsEmpty())
    return;

  // |server_info| will be NULL, if a non-empty server config already exists in
  // the memory cache.
  if (!server_info)
    return;

  // TODO(rtenneti): Delete the following histogram after collecting stats.
  // If the AlternativeServiceMap contained an entry for this host, check if
  // the disk cache contained an entry for it.
  if (ContainsKey(quic_supported_servers_at_startup_,
                  server_id.host_port_pair())) {
    UMA_HISTOGRAM_BOOLEAN("Net.QuicServerInfo.ExpectConfigMissingFromDiskCache",
                          server_info->state().server_config.empty());
  }

  cached->Initialize(server_info->state().server_config,
                     server_info->state().source_address_token,
                     server_info->state().certs, server_info->state().cert_sct,
                     server_info->state().chlo_hash,
                     server_info->state().server_config_sig, clock_->WallNow());
}

void QuicStreamFactory::MaybeInitialize() {
  // We don't initialize data from HttpServerProperties in the constructor
  // because HttpServerProperties has not yet initialized. We're guaranteed
  // HttpServerProperties has been initialized by the first time a request is
  // made.
  if (has_initialized_data_)
    return;

  has_initialized_data_ = true;
  for (const std::pair<const url::SchemeHostPort, AlternativeServiceInfoVector>&
           key_value : http_server_properties_->alternative_service_map()) {
    HostPortPair host_port_pair(key_value.first.host(), key_value.first.port());
    for (const AlternativeServiceInfo& alternative_service_info :
         key_value.second) {
      if (alternative_service_info.alternative_service.protocol == QUIC) {
        quic_supported_servers_at_startup_.insert(host_port_pair);
        break;
      }
    }
  }

  if (http_server_properties_->max_server_configs_stored_in_properties() == 0)
    return;
  // Create a temporary QuicServerInfo object to deserialize and to populate the
  // in-memory crypto server config cache in the MRU order.
  std::unique_ptr<QuicServerInfo> server_info;
  CompletionCallback callback;
  // Get the list of servers to be deserialized first because WaitForDataReady
  // touches quic_server_info_map.
  const QuicServerInfoMap& quic_server_info_map =
      http_server_properties_->quic_server_info_map();
  std::vector<QuicServerId> server_list(quic_server_info_map.size());
  for (const auto& key_value : quic_server_info_map)
    server_list.push_back(key_value.first);
  for (auto it = server_list.rbegin(); it != server_list.rend(); ++it) {
    const QuicServerId& server_id = *it;
    server_info.reset(quic_server_info_factory_->GetForServer(server_id));
    if (server_info->WaitForDataReady(callback) == OK) {
      DVLOG(1) << "Initialized server config for: " << server_id.ToString();
      InitializeCachedStateInCryptoConfig(server_id, server_info, nullptr);
    }
  }
}

void QuicStreamFactory::ProcessGoingAwaySession(
    QuicChromiumClientSession* session,
    const QuicServerId& server_id,
    bool session_was_active) {
  if (!http_server_properties_)
    return;

  const QuicConnectionStats& stats = session->connection()->GetStats();
  const AlternativeService alternative_service(QUIC,
                                               server_id.host_port_pair());
  if (session->IsCryptoHandshakeConfirmed()) {
    http_server_properties_->ConfirmAlternativeService(alternative_service);
    ServerNetworkStats network_stats;
    network_stats.srtt = base::TimeDelta::FromMicroseconds(stats.srtt_us);
    network_stats.bandwidth_estimate = stats.estimated_bandwidth;
    url::SchemeHostPort server("https", server_id.host_port_pair().host(),
                               server_id.host_port_pair().port());
    http_server_properties_->SetServerNetworkStats(server, network_stats);
    return;
  }

  UMA_HISTOGRAM_COUNTS("Net.QuicHandshakeNotConfirmedNumPacketsReceived",
                       stats.packets_received);

  if (!session_was_active)
    return;

  // TODO(rch):  In the special case where the session has received no
  // packets from the peer, we should consider blacklisting this
  // differently so that we still race TCP but we don't consider the
  // session connected until the handshake has been confirmed.
  HistogramBrokenAlternateProtocolLocation(
      BROKEN_ALTERNATE_PROTOCOL_LOCATION_QUIC_STREAM_FACTORY);

  // Since the session was active, there's no longer an
  // HttpStreamFactoryImpl::Job running which can mark it broken, unless the TCP
  // job also fails. So to avoid not using QUIC when we otherwise could, we mark
  // it as recently broken, which means that 0-RTT will be disabled but we'll
  // still race.
  http_server_properties_->MarkAlternativeServiceRecentlyBroken(
      alternative_service);
}

}  // namespace net
