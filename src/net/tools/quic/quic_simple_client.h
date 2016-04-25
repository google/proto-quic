// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A toy client, which connects to a specified port and sends QUIC
// request to that endpoint.

#ifndef NET_TOOLS_QUIC_QUIC_SIMPLE_CLIENT_H_
#define NET_TOOLS_QUIC_QUIC_SIMPLE_CLIENT_H_

#include <stddef.h>

#include <memory>
#include <string>

#include "base/command_line.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/quic/quic_config.h"
#include "net/quic/quic_spdy_stream.h"
#include "net/tools/quic/quic_client_base.h"

namespace net {

struct HttpRequestInfo;
class QuicChromiumAlarmFactory;
class QuicChromiumConnectionHelper;
class UDPClientSocket;


namespace test {
class QuicClientPeer;
}  // namespace test

class QuicSimpleClient : public QuicClientBase,
                         public QuicSpdyStream::Visitor,
                         public QuicChromiumPacketReader::Visitor {
 public:
  class ResponseListener {
   public:
    ResponseListener() {}
    virtual ~ResponseListener() {}
    virtual void OnCompleteResponse(QuicStreamId id,
                                    const HttpResponseHeaders& response_headers,
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
    // Takes ownership of |headers|.  |headers| may be null, since it's possible
    // to send data without headers.
    QuicDataToResend(HttpRequestInfo* headers,
                     base::StringPiece body,
                     bool fin);

    virtual ~QuicDataToResend();

    // Must be overridden by specific classes with the actual method for
    // re-sending data.
    virtual void Resend() = 0;

   protected:
    HttpRequestInfo* headers_;
    base::StringPiece body_;
    bool fin_;

   private:
    DISALLOW_COPY_AND_ASSIGN(QuicDataToResend);
  };

  // Create a quic client, which will have events managed by an externally owned
  // EpollServer.
  QuicSimpleClient(IPEndPoint server_address,
                   const QuicServerId& server_id,
                   const QuicVersionVector& supported_versions,
                   ProofVerifier* proof_verifier);
  QuicSimpleClient(IPEndPoint server_address,
                   const QuicServerId& server_id,
                   const QuicVersionVector& supported_versions,
                   const QuicConfig& config,
                   ProofVerifier* proof_verifier);

  ~QuicSimpleClient() override;

  // From QuicClientBase
  bool Initialize() override;
  bool WaitForEvents() override;
  QuicConnectionId GenerateNewConnectionId() override;

  // "Connect" to the QUIC server, including performing synchronous crypto
  // handshake.
  bool Connect();

  // Start the crypto handshake.  This can be done in place of the synchronous
  // Connect(), but callers are responsible for making sure the crypto handshake
  // completes.
  void StartConnect();

  // Disconnects from the QUIC server.
  void Disconnect();

  // Sends an HTTP request and does not wait for response before returning.
  void SendRequest(const HttpRequestInfo& headers,
                   base::StringPiece body,
                   bool fin);

  // Sends an HTTP request and waits for response before returning.
  void SendRequestAndWaitForResponse(const HttpRequestInfo& headers,
                                     base::StringPiece body,
                                     bool fin);

  // Sends a request simple GET for each URL in |args|, and then waits for
  // each to complete.
  void SendRequestsAndWaitForResponse(
      const base::CommandLine::StringVector& url_list);

  // Migrate to a new socket during an active connection.
  bool MigrateSocket(const IPAddress& new_host);

  // QuicChromiumPacketReader::Visitor
  void OnReadError(int result, const DatagramClientSocket* socket) override;
  bool OnPacket(const QuicReceivedPacket& packet,
                IPEndPoint local_address,
                IPEndPoint peer_address) override;

  // QuicSpdyStream::Visitor
  void OnClose(QuicSpdyStream* stream) override;

  // If the crypto handshake has not yet been confirmed, adds the data to the
  // queue of data to resend if the client receives a stateless reject.
  // Otherwise, deletes the data.  Takes ownerership of |data_to_resend|.
  void MaybeAddQuicDataToResend(QuicDataToResend* data_to_resend);

  void set_bind_to_address(const IPAddress& address) {
    bind_to_address_ = address;
  }

  const IPAddress& bind_to_address() const { return bind_to_address_; }

  void set_local_port(int local_port) { local_port_ = local_port; }

  const IPEndPoint& server_address() const { return server_address_; }

  const IPEndPoint& client_address() const { return client_address_; }

  // Takes ownership of the listener.
  void set_response_listener(ResponseListener* listener) {
    response_listener_.reset(listener);
  }

  void set_store_response(bool val) { store_response_ = val; }

  size_t latest_response_code() const;
  const std::string& latest_response_headers() const;
  const std::string& latest_response_body() const;

 protected:
  virtual QuicChromiumAlarmFactory* CreateQuicAlarmFactory();
  virtual QuicChromiumConnectionHelper* CreateQuicConnectionHelper();
  virtual QuicPacketWriter* CreateQuicPacketWriter();

 private:
  friend class net::test::QuicClientPeer;

  // Specific QuicClient class for storing data to resend.
  class ClientQuicDataToResend : public QuicDataToResend {
   public:
    // Takes ownership of |headers|.
    ClientQuicDataToResend(HttpRequestInfo* headers,
                           base::StringPiece body,
                           bool fin,
                           QuicSimpleClient* client)
        : QuicDataToResend(headers, body, fin), client_(client) {
      DCHECK(headers);
      DCHECK(client);
    }

    ~ClientQuicDataToResend() override {}

    void Resend() override;

   private:
    QuicSimpleClient* client_;

    DISALLOW_COPY_AND_ASSIGN(ClientQuicDataToResend);
  };

  // Used during initialization: creates the UDP socket FD, sets socket options,
  // and binds the socket to our address.
  bool CreateUDPSocket();

  // Read a UDP packet and hand it to the framer.
  bool ReadAndProcessPacket();

  void StartPacketReaderIfNotStarted();

  //  Used by |helper_| to time alarms.
  QuicClock clock_;

  // Address of the server.
  const IPEndPoint server_address_;

  // Address of the client if the client is connected to the server.
  IPEndPoint client_address_;

  // If initialized, the address to bind to.
  IPAddress bind_to_address_;

  // Local port to bind to. Initialize to 0.
  int local_port_;

  // UDP socket connected to the server.
  std::unique_ptr<UDPClientSocket> socket_;

  // Listens for full responses.
  std::unique_ptr<ResponseListener> response_listener_;

  // Tracks if the client is initialized to connect.
  bool initialized_;

  // If overflow_supported_ is true, this will be the number of packets dropped
  // during the lifetime of the server.
  QuicPacketCount packets_dropped_;

  // True if the kernel supports SO_RXQ_OVFL, the number of packets dropped
  // because the socket would otherwise overflow.
  bool overflow_supported_;

  // If true, store the latest response code, headers, and body.
  bool store_response_;
  // HTTP response code from most recent response.
  size_t latest_response_code_;
  // HTTP headers from most recent response.
  std::string latest_response_headers_;
  // Body of most recent response.
  std::string latest_response_body_;

  // Keeps track of any data sent before the handshake.
  std::vector<QuicDataToResend*> data_sent_before_handshake_;

  // Once the client receives a stateless reject, keeps track of any data that
  // must be resent upon a subsequent successful connection.
  std::vector<QuicDataToResend*> data_to_resend_on_connect_;

  // The log used for the sockets.
  NetLog net_log_;

  std::unique_ptr<QuicChromiumPacketReader> packet_reader_;

  bool packet_reader_started_;

  base::WeakPtrFactory<QuicSimpleClient> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(QuicSimpleClient);
};

}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_SIMPLE_CLIENT_H_
