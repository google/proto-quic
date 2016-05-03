// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A client specific QuicSession subclass.  This class owns the underlying
// QuicConnection and QuicConnectionHelper objects.  The connection stores
// a non-owning pointer to the helper so this session needs to ensure that
// the helper outlives the connection.

#ifndef NET_QUIC_QUIC_CHROMIUM_CLIENT_SESSION_H_
#define NET_QUIC_QUIC_CHROMIUM_CLIENT_SESSION_H_

#include <stddef.h>

#include <memory>
#include <string>

#include "base/containers/mru_cache.h"
#include "base/macros.h"
#include "base/time/time.h"
#include "net/base/completion_callback.h"
#include "net/base/net_error_details.h"
#include "net/cert/ct_verify_result.h"
#include "net/proxy/proxy_server.h"
#include "net/quic/quic_chromium_client_stream.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/quic/quic_client_session_base.h"
#include "net/quic/quic_connection_logger.h"
#include "net/quic/quic_crypto_client_stream.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"
#include "net/socket/socket_performance_watcher.h"

namespace net {

class CertVerifyResult;
class DatagramClientSocket;
class QuicChromiumConnectionHelper;
class QuicCryptoClientStreamFactory;
class QuicServerId;
class QuicServerInfo;
class QuicStreamFactory;
class SSLInfo;
class TransportSecurityState;

using TokenBindingSignatureMap =
    base::MRUCache<std::string, std::vector<uint8_t>>;

namespace test {
class QuicChromiumClientSessionPeer;
}  // namespace test

class NET_EXPORT_PRIVATE QuicChromiumClientSession
    : public QuicClientSessionBase,
      public QuicChromiumPacketReader::Visitor {
 public:
  // Reasons to disable QUIC, that is under certain pathological
  // connection errors.  Note: these values must be kept in sync with
  // the corresponding values of QuicDisabledReason in:
  // tools/metrics/histograms/histograms.xml
  enum QuicDisabledReason {
    QUIC_DISABLED_NOT = 0,  // default, not disabled
    QUIC_DISABLED_PUBLIC_RESET_POST_HANDSHAKE = 1,
    QUIC_DISABLED_TIMEOUT_WITH_OPEN_STREAMS = 2,
    QUIC_DISABLED_BAD_PACKET_LOSS_RATE = 3,
    QUIC_DISABLED_MAX = 4,
  };

  // An interface for observing events on a session.
  class NET_EXPORT_PRIVATE Observer {
   public:
    virtual ~Observer() {}
    virtual void OnCryptoHandshakeConfirmed() = 0;
    virtual void OnSessionClosed(int error, bool port_migration_detected) = 0;
  };

  // A helper class used to manage a request to create a stream.
  class NET_EXPORT_PRIVATE StreamRequest {
   public:
    StreamRequest();
    ~StreamRequest();

    // Starts a request to create a stream.  If OK is returned, then
    // |stream| will be updated with the newly created stream.  If
    // ERR_IO_PENDING is returned, then when the request is eventuallly
    // complete |callback| will be called.
    int StartRequest(const base::WeakPtr<QuicChromiumClientSession>& session,
                     QuicChromiumClientStream** stream,
                     const CompletionCallback& callback);

    // Cancels any pending stream creation request. May be called
    // repeatedly.
    void CancelRequest();

   private:
    friend class QuicChromiumClientSession;

    // Called by |session_| for an asynchronous request when the stream
    // request has finished successfully.
    void OnRequestCompleteSuccess(QuicChromiumClientStream* stream);

    // Called by |session_| for an asynchronous request when the stream
    // request has finished with an error. Also called with ERR_ABORTED
    // if |session_| is destroyed while the stream request is still pending.
    void OnRequestCompleteFailure(int rv);

    base::WeakPtr<QuicChromiumClientSession> session_;
    CompletionCallback callback_;
    QuicChromiumClientStream** stream_;

    DISALLOW_COPY_AND_ASSIGN(StreamRequest);
  };

  // Constructs a new session which will own |connection|, but not
  // |stream_factory|, which must outlive this session.
  // TODO(rch): decouple the factory from the session via a Delegate interface.
  QuicChromiumClientSession(
      QuicConnection* connection,
      std::unique_ptr<DatagramClientSocket> socket,
      QuicStreamFactory* stream_factory,
      QuicCryptoClientStreamFactory* crypto_client_stream_factory,
      QuicClock* clock,
      TransportSecurityState* transport_security_state,
      std::unique_ptr<QuicServerInfo> server_info,
      const QuicServerId& server_id,
      int yield_after_packets,
      QuicTime::Delta yield_after_duration,
      int cert_verify_flags,
      const QuicConfig& config,
      QuicCryptoClientConfig* crypto_config,
      const char* const connection_description,
      base::TimeTicks dns_resolution_end_time,
      QuicClientPushPromiseIndex* push_promise_index,
      base::TaskRunner* task_runner,
      std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
      NetLog* net_log);
  ~QuicChromiumClientSession() override;

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

  // Attempts to create a new stream.  If the stream can be
  // created immediately, returns OK.  If the open stream limit
  // has been reached, returns ERR_IO_PENDING, and |request|
  // will be added to the stream requets queue and will
  // be completed asynchronously.
  // TODO(rch): remove |stream| from this and use setter on |request|
  // and fix in spdy too.
  int TryCreateStream(StreamRequest* request,
                      QuicChromiumClientStream** stream);

  // Cancels the pending stream creation request.
  void CancelRequest(StreamRequest* request);

  // QuicSpdySession methods:
  void OnHeadersHeadOfLineBlocking(QuicTime::Delta delta) override;

  // QuicSession methods:
  void OnStreamFrame(const QuicStreamFrame& frame) override;
  QuicChromiumClientStream* CreateOutgoingDynamicStream(
      SpdyPriority priority) override;
  QuicCryptoClientStream* GetCryptoStream() override;
  void CloseStream(QuicStreamId stream_id) override;
  void SendRstStream(QuicStreamId id,
                     QuicRstStreamErrorCode error,
                     QuicStreamOffset bytes_written) override;
  void OnCryptoHandshakeEvent(CryptoHandshakeEvent event) override;
  void OnCryptoHandshakeMessageSent(
      const CryptoHandshakeMessage& message) override;
  void OnCryptoHandshakeMessageReceived(
      const CryptoHandshakeMessage& message) override;
  void OnGoAway(const QuicGoAwayFrame& frame) override;
  void OnRstStream(const QuicRstStreamFrame& frame) override;

  // QuicClientSessionBase methods:
  void OnProofValid(const QuicCryptoClientConfig::CachedState& cached) override;
  void OnProofVerifyDetailsAvailable(
      const ProofVerifyDetails& verify_details) override;

  // QuicConnectionVisitorInterface methods:
  void OnConnectionClosed(QuicErrorCode error,
                          const std::string& error_details,
                          ConnectionCloseSource source) override;
  void OnSuccessfulVersionNegotiation(const QuicVersion& version) override;
  void OnPathDegrading() override;

  // QuicChromiumPacketReader::Visitor methods:
  void OnReadError(int result, const DatagramClientSocket* socket) override;
  bool OnPacket(const QuicReceivedPacket& packet,
                IPEndPoint local_address,
                IPEndPoint peer_address) override;

  // Gets the SSL connection information.
  bool GetSSLInfo(SSLInfo* ssl_info) const;

  // Signs the exported keying material used for Token Binding using key |*key|
  // and puts the signature in |*out|. Returns a net error code.
  Error GetTokenBindingSignature(crypto::ECPrivateKey* key,
                                 std::vector<uint8_t>* out);

  // Performs a crypto handshake with the server.
  int CryptoConnect(bool require_confirmation,
                    const CompletionCallback& callback);

  // Resumes a crypto handshake with the server after a timeout.
  int ResumeCryptoConnect(const CompletionCallback& callback);

  // Causes the QuicConnectionHelper to start reading from all sockets
  // and passing the data along to the QuicConnection.
  void StartReading();

  // Close the session because of |error| and notifies the factory
  // that this session has been closed, which will delete the session.
  void CloseSessionOnError(int error, QuicErrorCode quic_error);

  // Close the session because of |error| and notifies the factory later that
  // this session has been closed, which will delete the session.
  void CloseSessionOnErrorAndNotifyFactoryLater(int error,
                                                QuicErrorCode quic_error);

  std::unique_ptr<base::Value> GetInfoAsValue(
      const std::set<HostPortPair>& aliases);

  const BoundNetLog& net_log() const { return net_log_; }

  base::WeakPtr<QuicChromiumClientSession> GetWeakPtr();

  // Returns the number of client hello messages that have been sent on the
  // crypto stream. If the handshake has completed then this is one greater
  // than the number of round-trips needed for the handshake.
  int GetNumSentClientHellos() const;

  // Returns true if |hostname| may be pooled onto this session.  If this
  // is a secure QUIC session, then |hostname| must match the certificate
  // presented during the handshake.
  bool CanPool(const std::string& hostname, PrivacyMode privacy_mode) const;

  const QuicServerId& server_id() const { return server_id_; }

  QuicDisabledReason disabled_reason() const { return disabled_reason_; }

  // Migrates session onto new socket, i.e., starts reading from |socket|
  // in addition to any previous sockets, and sets |writer| to be the new
  // default writer. Returns true if socket was successfully added to the
  // session and the session was successfully migrated to using the new socket.
  // Returns false if number of migrations exceeds kMaxReadersPerQuicSession.
  // Takes ownership of |socket|, |reader|, and |writer|.
  bool MigrateToSocket(std::unique_ptr<DatagramClientSocket> socket,
                       std::unique_ptr<QuicChromiumPacketReader> reader,
                       std::unique_ptr<QuicPacketWriter> writer);

  // Populates network error details for this session.
  void PopulateNetErrorDetails(NetErrorDetails* details);

  // Returns current default socket. This is the socket over which all
  // QUIC packets are sent. This default socket can change, so do not store the
  // returned socket.
  const DatagramClientSocket* GetDefaultSocket() const;

  bool IsAuthorized(const std::string& hostname) override;

  // Returns true if session has one ore more streams marked as non-migratable.
  bool HasNonMigratableStreams() const;

  void HandlePromised(QuicStreamId associated_id,
                      QuicStreamId promised_id,
                      const SpdyHeaderBlock& headers) override;

  void DeletePromised(QuicClientPromisedInfo* promised) override;

 protected:
  // QuicSession methods:
  bool ShouldCreateIncomingDynamicStream(QuicStreamId id) override;
  bool ShouldCreateOutgoingDynamicStream() override;

  QuicChromiumClientStream* CreateIncomingDynamicStream(
      QuicStreamId id) override;

 private:
  friend class test::QuicChromiumClientSessionPeer;

  typedef std::set<Observer*> ObserverSet;
  typedef std::list<StreamRequest*> StreamRequestQueue;

  QuicChromiumClientStream* CreateOutgoingReliableStreamImpl();
  QuicChromiumClientStream* CreateIncomingReliableStreamImpl(QuicStreamId id);
  // A completion callback invoked when a read completes.
  void OnReadComplete(int result);

  void OnClosedStream();

  // Close the session because of |error| and records it in UMA histogram.
  void RecordAndCloseSessionOnError(int error, QuicErrorCode quic_error);

  // A Session may be closed via any of three methods:
  // OnConnectionClosed - called by the connection when the connection has been
  //     closed, perhaps due to a timeout or a protocol error.
  // CloseSessionOnError - called from the owner of the session,
  //     the QuicStreamFactory, when there is an error.
  // OnReadComplete - when there is a read error.
  // This method closes all stream and performs any necessary cleanup.
  void CloseSessionOnErrorInner(int net_error, QuicErrorCode quic_error);

  void CloseAllStreams(int net_error);
  void CloseAllObservers(int net_error);

  // Notifies the factory that this session is going away and no more streams
  // should be created from it.  This needs to be called before closing any
  // streams, because closing a stream may cause a new stream to be created.
  void NotifyFactoryOfSessionGoingAway();

  // Posts a task to notify the factory that this session has been closed.
  void NotifyFactoryOfSessionClosedLater();

  // Notifies the factory that this session has been closed which will
  // delete |this|.
  void NotifyFactoryOfSessionClosed();

  void OnConnectTimeout();

  QuicServerId server_id_;
  bool require_confirmation_;
  std::unique_ptr<QuicCryptoClientStream> crypto_stream_;
  QuicStreamFactory* stream_factory_;
  std::vector<std::unique_ptr<DatagramClientSocket>> sockets_;
  TransportSecurityState* transport_security_state_;
  std::unique_ptr<QuicServerInfo> server_info_;
  std::unique_ptr<CertVerifyResult> cert_verify_result_;
  std::unique_ptr<ct::CTVerifyResult> ct_verify_result_;
  std::string pinning_failure_log_;
  ObserverSet observers_;
  StreamRequestQueue stream_requests_;
  CompletionCallback callback_;
  size_t num_total_streams_;
  base::TaskRunner* task_runner_;
  BoundNetLog net_log_;
  std::vector<std::unique_ptr<QuicChromiumPacketReader>> packet_readers_;
  base::TimeTicks dns_resolution_end_time_;
  base::TimeTicks handshake_start_;  // Time the handshake was started.
  std::unique_ptr<QuicConnectionLogger> logger_;
  // True when the session is going away, and streams may no longer be created
  // on this session. Existing stream will continue to be processed.
  bool going_away_;
  // True when the session receives a go away from server due to port migration.
  bool port_migration_detected_;
  QuicDisabledReason disabled_reason_;
  TokenBindingSignatureMap token_binding_signatures_;
  // UMA histogram counters for streams pushed to this session.
  int streams_pushed_count_;
  int streams_pushed_and_claimed_count_;
  base::WeakPtrFactory<QuicChromiumClientSession> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(QuicChromiumClientSession);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_CHROMIUM_CLIENT_SESSION_H_
