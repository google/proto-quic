// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A toy client, which connects to a specified port and sends QUIC
// request to that endpoint.

#ifndef NET_TOOLS_QUIC_QUIC_CLIENT_H_
#define NET_TOOLS_QUIC_QUIC_CLIENT_H_

#include <cstdint>
#include <memory>
#include <string>

#include "base/command_line.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/quic_client_push_promise_index.h"
#include "net/quic/quic_config.h"
#include "net/quic/quic_spdy_stream.h"
#include "net/tools/balsa/balsa_headers.h"
#include "net/tools/epoll_server/epoll_server.h"
#include "net/tools/quic/quic_client_base.h"
#include "net/tools/quic/quic_client_session.h"
#include "net/tools/quic/quic_packet_reader.h"
#include "net/tools/quic/quic_process_packet_interface.h"

namespace net {

class QuicServerId;

class QuicEpollConnectionHelper;

namespace test {
class QuicClientPeer;
}  // namespace test

class QuicClient : public QuicClientBase,
                   public EpollCallbackInterface,
                   public QuicSpdyStream::Visitor,
                   public ProcessPacketInterface,
                   public QuicClientPushPromiseIndex::Delegate {
 public:
  class ResponseListener {
   public:
    ResponseListener() {}
    virtual ~ResponseListener() {}
    virtual void OnCompleteResponse(QuicStreamId id,
                                    const BalsaHeaders& response_headers,
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
    QuicDataToResend(BalsaHeaders* headers, base::StringPiece body, bool fin);

    virtual ~QuicDataToResend();

    // Must be overridden by specific classes with the actual method for
    // re-sending data.
    virtual void Resend() = 0;

   protected:
    BalsaHeaders* headers_;
    base::StringPiece body_;
    bool fin_;

   private:
    DISALLOW_COPY_AND_ASSIGN(QuicDataToResend);
  };

  // Create a quic client, which will have events managed by an externally owned
  // EpollServer.
  QuicClient(IPEndPoint server_address,
             const QuicServerId& server_id,
             const QuicVersionVector& supported_versions,
             EpollServer* epoll_server,
             ProofVerifier* proof_verifier);
  QuicClient(IPEndPoint server_address,
             const QuicServerId& server_id,
             const QuicVersionVector& supported_versions,
             const QuicConfig& config,
             EpollServer* epoll_server,
             ProofVerifier* proof_verifier);

  ~QuicClient() override;

  // From QuicClientBase
  bool Initialize() override;
  bool WaitForEvents() override;

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
  void SendRequest(const BalsaHeaders& headers,
                   base::StringPiece body,
                   bool fin);

  // Sends an HTTP request and waits for response before returning.
  void SendRequestAndWaitForResponse(const BalsaHeaders& headers,
                                     base::StringPiece body,
                                     bool fin);

  // Sends a request simple GET for each URL in |args|, and then waits for
  // each to complete.
  void SendRequestsAndWaitForResponse(const std::vector<std::string>& url_list);

  // Migrate to a new socket during an active connection.
  bool MigrateSocket(const IPAddress& new_host);

  // From EpollCallbackInterface
  void OnRegistration(EpollServer* eps, int fd, int event_mask) override {}
  void OnModification(int fd, int event_mask) override {}
  void OnEvent(int fd, EpollEvent* event) override;
  // |fd_| can be unregistered without the client being disconnected. This
  // happens in b3m QuicProber where we unregister |fd_| to feed in events to
  // the client from the SelectServer.
  void OnUnregistration(int fd, bool replaced) override {}
  void OnShutdown(EpollServer* eps, int fd) override {}

  // QuicSpdyStream::Visitor
  void OnClose(QuicSpdyStream* stream) override;

  bool CheckVary(const SpdyHeaderBlock& client_request,
                 const SpdyHeaderBlock& promise_request,
                 const SpdyHeaderBlock& promise_response) override;
  void OnRendezvousResult(QuicSpdyStream*) override;

  // If the crypto handshake has not yet been confirmed, adds the data to the
  // queue of data to resend if the client receives a stateless reject.
  // Otherwise, deletes the data.  Takes ownerership of |data_to_resend|.
  void MaybeAddQuicDataToResend(QuicDataToResend* data_to_resend);

  // If the client has at least one UDP socket, return address of the latest
  // created one. Otherwise, return an empty socket address.
  const IPEndPoint GetLatestClientAddress() const;

  // If the client has at least one UDP socket, return the latest created one.
  // Otherwise, return -1.
  int GetLatestFD() const;

  void set_bind_to_address(const IPAddress& address) {
    bind_to_address_ = address;
  }

  const IPAddress& bind_to_address() const { return bind_to_address_; }

  void set_local_port(int local_port) { local_port_ = local_port; }

  const IPEndPoint& server_address() const { return server_address_; }

  // Takes ownership of the listener.
  void set_response_listener(ResponseListener* listener) {
    response_listener_.reset(listener);
  }

  void set_store_response(bool val) { store_response_ = val; }

  size_t latest_response_code() const;
  const std::string& latest_response_headers() const;
  const std::string& latest_response_body() const;
  const std::string& latest_response_trailers() const;

  // Implements ProcessPacketInterface. This will be called for each received
  // packet.
  void ProcessPacket(const IPEndPoint& self_address,
                     const IPEndPoint& peer_address,
                     const QuicReceivedPacket& packet) override;

  virtual QuicPacketWriter* CreateQuicPacketWriter();

  // If |fd| is an open UDP socket, unregister and close it. Otherwise, do
  // nothing.
  virtual void CleanUpUDPSocket(int fd);

  // Unregister and close all open UDP sockets.
  virtual void CleanUpAllUDPSockets();

  EpollServer* epoll_server() { return epoll_server_; }

  const linked_hash_map<int, IPEndPoint>& fd_address_map() const {
    return fd_address_map_;
  }

 private:
  friend class net::test::QuicClientPeer;

  // Specific QuicClient class for storing data to resend.
  class ClientQuicDataToResend : public QuicDataToResend {
   public:
    // Takes ownership of |headers|.
    ClientQuicDataToResend(BalsaHeaders* headers,
                           base::StringPiece body,
                           bool fin,
                           QuicClient* client)
        : QuicDataToResend(headers, body, fin), client_(client) {
      DCHECK(headers);
      DCHECK(client);
    }

    ~ClientQuicDataToResend() override {}

    void Resend() override;

   private:
    QuicClient* client_;

    DISALLOW_COPY_AND_ASSIGN(ClientQuicDataToResend);
  };

  // Used during initialization: creates the UDP socket FD, sets socket options,
  // and binds the socket to our address.
  bool CreateUDPSocketAndBind();

  // Actually clean up |fd|.
  void CleanUpUDPSocketImpl(int fd);

  // If the request URL matches a push promise, bypass sending the
  // request.
  bool MaybeHandlePromised(const BalsaHeaders& headers,
                           const SpdyHeaderBlock& spdy_headers,
                           base::StringPiece body,
                           bool fin);

  // Address of the server.
  const IPEndPoint server_address_;

  // If initialized, the address to bind to.
  IPAddress bind_to_address_;

  // Local port to bind to. Initialize to 0.
  int local_port_;

  // Listens for events on the client socket.
  EpollServer* epoll_server_;

  // Map mapping created UDP sockets to their addresses. By using linked hash
  // map, the order of socket creation can be recorded.
  linked_hash_map<int, IPEndPoint> fd_address_map_;

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
  // HTTP/2 headers from most recent response.
  std::string latest_response_headers_;
  // Body of most recent response.
  std::string latest_response_body_;
  // HTTP/2 trailers from most recent response.
  std::string latest_response_trailers_;

  // Keeps track of any data sent before the handshake.
  std::vector<QuicDataToResend*> data_sent_before_handshake_;

  // Once the client receives a stateless reject, keeps track of any data that
  // must be resent upon a subsequent successful connection.
  std::vector<QuicDataToResend*> data_to_resend_on_connect_;

  // Point to a QuicPacketReader object on the heap. The reader allocates more
  // space than allowed on the stack.
  //
  // TODO(rtenneti): Chromium code doesn't use |packet_reader_|. Add support for
  // QuicPacketReader
  std::unique_ptr<QuicPacketReader> packet_reader_;

  std::unique_ptr<ClientQuicDataToResend> push_promise_data_to_resend_;

  DISALLOW_COPY_AND_ASSIGN(QuicClient);
};

}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_CLIENT_H_
