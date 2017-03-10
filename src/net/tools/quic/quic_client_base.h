// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A base class for the toy client, which connects to a specified port and sends
// QUIC request to that endpoint.

#ifndef NET_TOOLS_QUIC_QUIC_CLIENT_BASE_H_
#define NET_TOOLS_QUIC_QUIC_CLIENT_BASE_H_

#include <string>

#include "base/macros.h"
#include "net/quic/core/crypto/crypto_handshake.h"
#include "net/quic/core/quic_client_push_promise_index.h"
#include "net/quic/core/quic_config.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/quic/platform/api/quic_string_piece.h"
#include "net/tools/quic/quic_client_session.h"
#include "net/tools/quic/quic_spdy_client_stream.h"

namespace net {

class ProofVerifier;
class QuicServerId;

class QuicClientBase : public QuicClientPushPromiseIndex::Delegate,
                       public QuicSpdyStream::Visitor {
 public:
  // A ResponseListener is notified when a complete response is received.
  class ResponseListener {
   public:
    ResponseListener() {}
    virtual ~ResponseListener() {}
    virtual void OnCompleteResponse(QuicStreamId id,
                                    const SpdyHeaderBlock& response_headers,
                                    const std::string& response_body) = 0;
  };

  // The client uses these objects to keep track of any data to resend upon
  // receipt of a stateless reject.  Recall that the client API allows callers
  // to optimistically send data to the server prior to handshake-confirmation.
  // If the client subsequently receives a stateless reject, it must tear down
  // its existing session, create a new session, and resend all previously sent
  // data.  It uses these objects to keep track of all the sent data, and to
  // resend the data upon a subsequent connection.
  class QuicDataToResend {
   public:
    // |headers| may be null, since it's possible to send data without headers.
    QuicDataToResend(std::unique_ptr<SpdyHeaderBlock> headers,
                     QuicStringPiece body,
                     bool fin);

    virtual ~QuicDataToResend();

    // Must be overridden by specific classes with the actual method for
    // re-sending data.
    virtual void Resend() = 0;

   protected:
    std::unique_ptr<SpdyHeaderBlock> headers_;
    QuicStringPiece body_;
    bool fin_;

   private:
    DISALLOW_COPY_AND_ASSIGN(QuicDataToResend);
  };

  QuicClientBase(const QuicServerId& server_id,
                 const QuicVersionVector& supported_versions,
                 const QuicConfig& config,
                 QuicConnectionHelperInterface* helper,
                 QuicAlarmFactory* alarm_factory,
                 std::unique_ptr<ProofVerifier> proof_verifier);

  ~QuicClientBase() override;

  // QuicSpdyStream::Visitor
  void OnClose(QuicSpdyStream* stream) override;

  // Initializes the client to create a connection. Should be called exactly
  // once before calling StartConnect or Connect. Returns true if the
  // initialization succeeds, false otherwise.
  virtual bool Initialize();

  // "Connect" to the QUIC server, including performing synchronous crypto
  // handshake.
  bool Connect();

  // Start the crypto handshake.  This can be done in place of the synchronous
  // Connect(), but callers are responsible for making sure the crypto handshake
  // completes.
  void StartConnect();

  // Disconnects from the QUIC server.
  void Disconnect();

  // Returns true if the crypto handshake has yet to establish encryption.
  // Returns false if encryption is active (even if the server hasn't confirmed
  // the handshake) or if the connection has been closed.
  bool EncryptionBeingEstablished();

  // Sends an HTTP request and does not wait for response before returning.
  void SendRequest(const SpdyHeaderBlock& headers,
                   QuicStringPiece body,
                   bool fin);

  // Sends an HTTP request and waits for response before returning.
  void SendRequestAndWaitForResponse(const SpdyHeaderBlock& headers,
                                     QuicStringPiece body,
                                     bool fin);

  // Sends a request simple GET for each URL in |url_list|, and then waits for
  // each to complete.
  void SendRequestsAndWaitForResponse(const std::vector<std::string>& url_list);

  // Returns a newly created QuicSpdyClientStream, owned by the
  // QuicSimpleClient.
  virtual QuicSpdyClientStream* CreateClientStream();

  // Wait for events until the stream with the given ID is closed.
  void WaitForStreamToClose(QuicStreamId id);

  // Wait for events until the handshake is confirmed.
  // Returns true if the crypto handshake succeeds, false otherwise.
  bool WaitForCryptoHandshakeConfirmed() WARN_UNUSED_RESULT;

  // Wait up to 50ms, and handle any events which occur.
  // Returns true if there are any outstanding requests.
  bool WaitForEvents();

  // Migrate to a new socket during an active connection.
  bool MigrateSocket(const QuicIpAddress& new_host);

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

  // UseTokenBinding enables token binding negotiation in the client.  This
  // should only be called before the initial Connect().  The client will still
  // need to check that token binding is negotiated with the server, and add
  // token binding headers to requests if so.  server, and add token binding
  // headers to requests if so.  The negotiated token binding parameters can be
  // found on the QuicCryptoNegotiatedParameters object in
  // token_binding_key_param.
  void UseTokenBinding() {
    crypto_config_.tb_key_params = QuicTagVector{kTB10};
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

  bool CheckVary(const SpdyHeaderBlock& client_request,
                 const SpdyHeaderBlock& promise_request,
                 const SpdyHeaderBlock& promise_response) override;
  void OnRendezvousResult(QuicSpdyStream*) override;

  // If the crypto handshake has not yet been confirmed, adds the data to the
  // queue of data to resend if the client receives a stateless reject.
  // Otherwise, deletes the data.
  void MaybeAddQuicDataToResend(
      std::unique_ptr<QuicDataToResend> data_to_resend);

  void set_store_response(bool val) { store_response_ = val; }

  size_t latest_response_code() const;
  const std::string& latest_response_headers() const;
  const std::string& preliminary_response_headers() const;
  const SpdyHeaderBlock& latest_response_header_block() const;
  const std::string& latest_response_body() const;
  const std::string& latest_response_trailers() const;

  void set_response_listener(std::unique_ptr<ResponseListener> listener) {
    response_listener_ = std::move(listener);
  }

  void set_bind_to_address(QuicIpAddress address) {
    bind_to_address_ = address;
  }

  QuicIpAddress bind_to_address() const { return bind_to_address_; }

  void set_local_port(int local_port) { local_port_ = local_port; }

  int local_port() const { return local_port_; }

  const QuicSocketAddress& server_address() const { return server_address_; }

  void set_server_address(const QuicSocketAddress& server_address) {
    server_address_ = server_address;
  }

 protected:
  // Creates a packet writer to be used for the next connection.
  virtual QuicPacketWriter* CreateQuicPacketWriter() = 0;

  // Takes ownership of |connection|.
  virtual QuicClientSession* CreateQuicClientSession(
      QuicConnection* connection);

  // Runs one iteration of the event loop.
  virtual void RunEventLoop() = 0;

  // Used during initialization: creates the UDP socket FD, sets socket options,
  // and binds the socket to our address.
  virtual bool CreateUDPSocketAndBind(QuicSocketAddress server_address,
                                      QuicIpAddress bind_to_address,
                                      int bind_to_port) = 0;

  // Unregister and close all open UDP sockets.
  virtual void CleanUpAllUDPSockets() = 0;

  // If the client has at least one UDP socket, return address of the latest
  // created one. Otherwise, return an empty socket address.
  virtual QuicSocketAddress GetLatestClientAddress() const = 0;

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

  // If the crypto handshake has not yet been confirmed, adds the data to the
  // queue of data to resend if the client receives a stateless reject.
  // Otherwise, deletes the data.
  void MaybeAddDataToResend(const SpdyHeaderBlock& headers,
                            QuicStringPiece body,
                            bool fin);

  void ClearDataToResend();

  void ResendSavedData();

  void AddPromiseDataToResend(const SpdyHeaderBlock& headers,
                              QuicStringPiece body,
                              bool fin);

  QuicConnectionHelperInterface* helper() { return helper_.get(); }

  QuicAlarmFactory* alarm_factory() { return alarm_factory_.get(); }

  void set_num_sent_client_hellos(int num_sent_client_hellos) {
    num_sent_client_hellos_ = num_sent_client_hellos;
  }

  void set_num_stateless_rejects_received(int num_stateless_rejects_received) {
    num_stateless_rejects_received_ = num_stateless_rejects_received;
  }

 private:
  // Specific QuicClient class for storing data to resend.
  class ClientQuicDataToResend : public QuicDataToResend {
   public:
    ClientQuicDataToResend(std::unique_ptr<SpdyHeaderBlock> headers,
                           QuicStringPiece body,
                           bool fin,
                           QuicClientBase* client)
        : QuicDataToResend(std::move(headers), body, fin), client_(client) {
      DCHECK(headers_);
      DCHECK(client);
    }

    ~ClientQuicDataToResend() override {}

    void Resend() override;

   private:
    QuicClientBase* client_;

    DISALLOW_COPY_AND_ASSIGN(ClientQuicDataToResend);
  };

  // |server_id_| is a tuple (hostname, port, is_https) of the server.
  QuicServerId server_id_;

  // Tracks if the client is initialized to connect.
  bool initialized_;

  // Address of the server.
  QuicSocketAddress server_address_;

  // If initialized, the address to bind to.
  QuicIpAddress bind_to_address_;

  // Local port to bind to. Initialize to 0.
  int local_port_;

  // config_ and crypto_config_ contain configuration and cached state about
  // servers.
  QuicConfig config_;
  QuicCryptoClientConfig crypto_config_;

  // Helper to be used by created connections. Must outlive |session_|.
  std::unique_ptr<QuicConnectionHelperInterface> helper_;

  // Alarm factory to be used by created connections. Must outlive |session_|.
  std::unique_ptr<QuicAlarmFactory> alarm_factory_;

  // Writer used to actually send packets to the wire. Must outlive |session_|.
  std::unique_ptr<QuicPacketWriter> writer_;

  // Index of pending promised streams. Must outlive |session_|.
  QuicClientPushPromiseIndex push_promise_index_;

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

  // If true, store the latest response code, headers, and body.
  bool store_response_;
  // HTTP response code from most recent response.
  int latest_response_code_;
  // HTTP/2 headers from most recent response.
  std::string latest_response_headers_;
  // preliminary 100 Continue HTTP/2 headers from most recent response, if any.
  std::string preliminary_response_headers_;
  // HTTP/2 headers from most recent response.
  SpdyHeaderBlock latest_response_header_block_;
  // Body of most recent response.
  std::string latest_response_body_;
  // HTTP/2 trailers from most recent response.
  std::string latest_response_trailers_;

  // Listens for full responses.
  std::unique_ptr<ResponseListener> response_listener_;

  // Keeps track of any data that must be resent upon a subsequent successful
  // connection, in case the client receives a stateless reject.
  std::vector<std::unique_ptr<QuicDataToResend>> data_to_resend_on_connect_;

  std::unique_ptr<ClientQuicDataToResend> push_promise_data_to_resend_;

  DISALLOW_COPY_AND_ASSIGN(QuicClientBase);
};

}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_CLIENT_BASE_H_
