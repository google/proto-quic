// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A base class for the toy client, which connects to a specified port and sends
// QUIC request to that endpoint.

#ifndef NET_TOOLS_QUIC_QUIC_CLIENT_BASE_H_
#define NET_TOOLS_QUIC_QUIC_CLIENT_BASE_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "net/base/ip_endpoint.h"
#include "net/log/net_log.h"
#include "net/quic/crypto/crypto_handshake.h"
#include "net/quic/crypto/quic_crypto_client_config.h"
#include "net/quic/quic_alarm_factory.h"
#include "net/quic/quic_bandwidth.h"
#include "net/quic/quic_client_push_promise_index.h"
#include "net/quic/quic_config.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_packet_writer.h"
#include "net/quic/quic_protocol.h"
#include "net/tools/quic/quic_client_session.h"
#include "net/tools/quic/quic_spdy_client_stream.h"

namespace net {

class ProofVerifier;
class QuicServerId;

class QuicClientBase {
 public:
  QuicClientBase(const QuicServerId& server_id,
                 const QuicVersionVector& supported_versions,
                 const QuicConfig& config,
                 QuicConnectionHelperInterface* helper,
                 QuicAlarmFactory* alarm_factory,
                 ProofVerifier* proof_verifier);

  ~QuicClientBase();

  // Initializes the client to create a connection. Should be called exactly
  // once before calling StartConnect or Connect. Returns true if the
  // initialization succeeds, false otherwise.
  virtual bool Initialize();

  // Returns true if the crypto handshake has yet to establish encryption.
  // Returns false if encryption is active (even if the server hasn't confirmed
  // the handshake) or if the connection has been closed.
  bool EncryptionBeingEstablished();

  // Returns a newly created QuicSpdyClientStream, owned by the
  // QuicSimpleClient.
  QuicSpdyClientStream* CreateReliableClientStream();

  // Wait for events until the stream with the given ID is closed.
  void WaitForStreamToClose(QuicStreamId id);

  // Wait for events until the handshake is confirmed.
  void WaitForCryptoHandshakeConfirmed();

  // Wait up to 50ms, and handle any events which occur.
  // Returns true if there are any outstanding requests.
  virtual bool WaitForEvents() = 0;

  QuicClientSession* session() { return session_.get(); }

  bool connected() const;
  bool goaway_received() const;

  const QuicServerId& server_id() const { return server_id_; }

  // This should only be set before the initial Connect()
  void set_server_id(const QuicServerId& server_id) { server_id_ = server_id; }

  void SetUserAgentID(const std::string& user_agent_id) {
    crypto_config_.set_user_agent_id(user_agent_id);
  }

  // SetChannelIDSource sets a ChannelIDSource that will be called, when the
  // server supports channel IDs, to obtain a channel ID for signing a message
  // proving possession of the channel ID. This object takes ownership of
  // |source|.
  void SetChannelIDSource(ChannelIDSource* source) {
    crypto_config_.SetChannelIDSource(source);
  }

  const QuicVersionVector& supported_versions() const {
    return supported_versions_;
  }

  void SetSupportedVersions(const QuicVersionVector& versions) {
    supported_versions_ = versions;
  }

  QuicConfig* config() { return &config_; }

  QuicCryptoClientConfig* crypto_config() { return &crypto_config_; }

  // Change the initial maximum packet size of the connection.  Has to be called
  // before Connect()/StartConnect() in order to have any effect.
  void set_initial_max_packet_length(QuicByteCount initial_max_packet_length) {
    initial_max_packet_length_ = initial_max_packet_length;
  }

  int num_stateless_rejects_received() const {
    return num_stateless_rejects_received_;
  }

  // The number of client hellos sent, taking stateless rejects into
  // account.  In the case of a stateless reject, the initial
  // connection object may be torn down and a new one created.  The
  // user cannot rely upon the latest connection object to get the
  // total number of client hellos sent, and should use this function
  // instead.
  int GetNumSentClientHellos();

  // Gather the stats for the last session and update the stats for the overall
  // connection.
  void UpdateStats();

  // The number of server config updates received.  We assume no
  // updates can be sent during a previously, statelessly rejected
  // connection, so only the latest session is taken into account.
  int GetNumReceivedServerConfigUpdates();

  // Returns any errors that occurred at the connection-level (as
  // opposed to the session-level).  When a stateless reject occurs,
  // the error of the last session may not reflect the overall state
  // of the connection.
  QuicErrorCode connection_error() const;
  void set_connection_error(QuicErrorCode connection_error) {
    connection_error_ = connection_error;
  }

  bool connected_or_attempting_connect() const {
    return connected_or_attempting_connect_;
  }
  void set_connected_or_attempting_connect(
      bool connected_or_attempting_connect) {
    connected_or_attempting_connect_ = connected_or_attempting_connect;
  }

  QuicPacketWriter* writer() { return writer_.get(); }
  void set_writer(QuicPacketWriter* writer) {
    if (writer_.get() != writer) {
      writer_.reset(writer);
    }
  }
  void reset_writer() { writer_.reset(); }

  QuicByteCount initial_max_packet_length() {
    return initial_max_packet_length_;
  }

  ProofVerifier* proof_verifier() const;

  void set_session(QuicClientSession* session) { session_.reset(session); }

  QuicClientPushPromiseIndex* push_promise_index() {
    return &push_promise_index_;
  }

 protected:
  virtual QuicClientSession* CreateQuicClientSession(
      QuicConnection* connection);

  // Generates the next ConnectionId for |server_id_|.  By default, if the
  // cached server config contains a server-designated ID, that ID will be
  // returned.  Otherwise, the next random ID will be returned.
  QuicConnectionId GetNextConnectionId();

  // Returns the next server-designated ConnectionId from the cached config for
  // |server_id_|, if it exists.  Otherwise, returns 0.
  QuicConnectionId GetNextServerDesignatedConnectionId();

  // Generates a new, random connection ID (as opposed to a server-designated
  // connection ID).
  virtual QuicConnectionId GenerateNewConnectionId();

  QuicConnectionHelperInterface* helper() { return helper_.get(); }

  QuicAlarmFactory* alarm_factory() { return alarm_factory_.get(); }

  void set_num_sent_client_hellos(int num_sent_client_hellos) {
    num_sent_client_hellos_ = num_sent_client_hellos;
  }

  void set_num_stateless_rejects_received(int num_stateless_rejects_received) {
    num_stateless_rejects_received_ = num_stateless_rejects_received;
  }

 private:
  // |server_id_| is a tuple (hostname, port, is_https) of the server.
  QuicServerId server_id_;

  // config_ and crypto_config_ contain configuration and cached state about
  // servers.
  QuicConfig config_;
  QuicCryptoClientConfig crypto_config_;

  // Helper to be used by created connections. Needs to outlive |session_|.
  std::unique_ptr<QuicConnectionHelperInterface> helper_;

  // Helper to be used by created connections. Needs to outlive |session_|.
  std::unique_ptr<QuicAlarmFactory> alarm_factory_;

  // Writer used to actually send packets to the wire. Needs to outlive
  // |session_|.
  std::unique_ptr<QuicPacketWriter> writer_;

  // Session which manages streams.
  std::unique_ptr<QuicClientSession> session_;

  // This vector contains QUIC versions which we currently support.
  // This should be ordered such that the highest supported version is the first
  // element, with subsequent elements in descending order (versions can be
  // skipped as necessary). We will always pick supported_versions_[0] as the
  // initial version to use.
  QuicVersionVector supported_versions_;

  // The initial value of maximum packet size of the connection.  If set to
  // zero, the default is used.
  QuicByteCount initial_max_packet_length_;

  // The number of stateless rejects received during the current/latest
  // connection.
  // TODO(jokulik): Consider some consistent naming scheme (or other) for member
  // variables that are kept per-request, per-connection, and over the client's
  // lifetime.
  int num_stateless_rejects_received_;

  // The number of hellos sent during the current/latest connection.
  int num_sent_client_hellos_;

  // Used to store any errors that occurred with the overall connection (as
  // opposed to that associated with the last session object).
  QuicErrorCode connection_error_;

  // True when the client is attempting to connect or re-connect the session (in
  // the case of a stateless reject).  Set to false  between a call to
  // Disconnect() and the subsequent call to StartConnect().  When
  // connected_or_attempting_connect_ is false, the session object corresponds
  // to the previous client-level connection.
  bool connected_or_attempting_connect_;

  QuicClientPushPromiseIndex push_promise_index_;

  DISALLOW_COPY_AND_ASSIGN(QuicClientBase);
};

}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_CLIENT_BASE_H_
