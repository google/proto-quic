// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_QUIC_TEST_TOOLS_QUIC_TEST_CLIENT_H_
#define NET_TOOLS_QUIC_TEST_TOOLS_QUIC_TEST_CLIENT_H_

#include <stddef.h>
#include <stdint.h>

#include <cstdint>
#include <memory>
#include <string>

#include "base/macros.h"
#include "net/quic/core/proto/cached_network_parameters.pb.h"
#include "net/quic/core/quic_framer.h"
#include "net/quic/core/quic_packet_creator.h"
#include "net/quic/core/quic_packets.h"
#include "net/tools/epoll_server/epoll_server.h"
#include "net/tools/quic/quic_client.h"
#include "testing/gmock/include/gmock/gmock.h"

using base::StringPiece;

namespace net {

class ProofVerifier;

class ProofVerifier;
class QuicPacketWriterWrapper;

namespace test {

class MockableQuicClient;

// A quic client which allows mocking out reads and writes.
class MockableQuicClient : public QuicClient {
 public:
  MockableQuicClient(QuicSocketAddress server_address,
                     const QuicServerId& server_id,
                     const QuicVersionVector& supported_versions,
                     EpollServer* epoll_server);

  MockableQuicClient(QuicSocketAddress server_address,
                     const QuicServerId& server_id,
                     const QuicConfig& config,
                     const QuicVersionVector& supported_versions,
                     EpollServer* epoll_server);

  MockableQuicClient(QuicSocketAddress server_address,
                     const QuicServerId& server_id,
                     const QuicConfig& config,
                     const QuicVersionVector& supported_versions,
                     EpollServer* epoll_server,
                     std::unique_ptr<ProofVerifier> proof_verifier);

  ~MockableQuicClient() override;

  void ProcessPacket(const QuicSocketAddress& self_address,
                     const QuicSocketAddress& peer_address,
                     const QuicReceivedPacket& packet) override;

  QuicPacketWriter* CreateQuicPacketWriter() override;
  QuicConnectionId GenerateNewConnectionId() override;
  void UseWriter(QuicPacketWriterWrapper* writer);
  void UseConnectionId(QuicConnectionId connection_id);
  void SendCachedNetworkParamaters(
      const CachedNetworkParameters& cached_network_params) {
    cached_network_paramaters_ = cached_network_params;
  }
  const QuicReceivedPacket* last_incoming_packet() {
    return last_incoming_packet_.get();
  }
  void set_track_last_incoming_packet(bool track) {
    track_last_incoming_packet_ = track;
  }

 private:
  QuicConnectionId override_connection_id_;  // ConnectionId to use, if nonzero
  QuicPacketWriterWrapper* test_writer_;
  CachedNetworkParameters cached_network_paramaters_;
  // The last incoming packet, iff |track_last_incoming_packet_| is true.
  std::unique_ptr<QuicReceivedPacket> last_incoming_packet_;
  // If true, copy each packet from ProcessPacket into |last_incoming_packet_|
  bool track_last_incoming_packet_;

  DISALLOW_COPY_AND_ASSIGN(MockableQuicClient);
};

// A toy QUIC client used for testing.
class QuicTestClient : public QuicSpdyStream::Visitor,
                       public QuicClientPushPromiseIndex::Delegate {
 public:
  QuicTestClient(QuicSocketAddress server_address,
                 const std::string& server_hostname,
                 const QuicVersionVector& supported_versions);
  QuicTestClient(QuicSocketAddress server_address,
                 const std::string& server_hostname,
                 const QuicConfig& config,
                 const QuicVersionVector& supported_versions);
  QuicTestClient(QuicSocketAddress server_address,
                 const std::string& server_hostname,
                 const QuicConfig& config,
                 const QuicVersionVector& supported_versions,
                 std::unique_ptr<ProofVerifier> proof_verifier);

  ~QuicTestClient() override;

  // Sets the |user_agent_id| of the |client_|.
  void SetUserAgentID(const std::string& user_agent_id);

  // Wraps data in a quic packet and sends it.
  ssize_t SendData(const std::string& data, bool last_data);
  // As above, but |delegate| will be notified when |data| is ACKed.
  ssize_t SendData(const std::string& data,
                   bool last_data,
                   QuicAckListenerInterface* delegate);

  // Clears any outstanding state and sends a simple GET of 'uri' to the
  // server.  Returns 0 if the request failed and no bytes were written.
  ssize_t SendRequest(const std::string& uri);
  // Sends requests for all the urls and waits for the responses.  To process
  // the individual responses as they are returned, the caller should use the
  // set the response_listener on the client().
  void SendRequestsAndWaitForResponses(
      const std::vector<std::string>& url_list);
  // Sends a request containing |headers| and |body| and returns the number of
  // bytes sent (the size of the serialized request headers and body).
  ssize_t SendMessage(const SpdyHeaderBlock& headers, base::StringPiece body);
  // Sends a request containing |headers| and |body| with the fin bit set to
  // |fin| and returns the number of bytes sent (the size of the serialized
  // request headers and body).
  ssize_t SendMessage(const SpdyHeaderBlock& headers,
                      base::StringPiece body,
                      bool fin);
  // Sends a request containing |headers| and |body|, waits for the response,
  // and returns the response body.
  std::string SendCustomSynchronousRequest(const SpdyHeaderBlock& headers,
                                           const std::string& body);
  // Sends a GET request for |uri|, waits for the response, and returns the
  // response body.
  std::string SendSynchronousRequest(const std::string& uri);
  void Connect();
  void ResetConnection();
  void Disconnect();
  QuicSocketAddress local_address() const;
  void ClearPerRequestState();
  bool WaitUntil(int timeout_ms, std::function<bool()> trigger);
  ssize_t Send(const void* buffer, size_t size);
  bool response_complete() const;
  bool response_headers_complete() const;
  const SpdyHeaderBlock* response_headers() const;
  int64_t response_size() const;
  int64_t response_body_size() const;
  size_t bytes_read() const;
  size_t bytes_written() const;
  bool buffer_body() const;
  void set_buffer_body(bool buffer_body);
  const std::string& response_body();
  bool connected() const;

  // Returns once a complete response or a connection close has been received
  // from the server.
  void WaitForResponse() { WaitForResponseForMs(-1); }

  // Waits for some data or response from the server.
  void WaitForInitialResponse() { WaitForInitialResponseForMs(-1); }

  // Returns once a complete response or a connection close has been received
  // from the server, or once the timeout expires. -1 for no timeout.
  void WaitForResponseForMs(int timeout_ms) {
    WaitUntil(timeout_ms, [this]() { return response_complete(); });
    if (response_complete()) {
      VLOG(1) << "Client received response:"
              << response_headers()->DebugString() << response_body();
    }
  }

  // Waits for some data or response from the server, or once the timeout
  // expires. -1 for no timeout.
  void WaitForInitialResponseForMs(int timeout_ms) {
    WaitUntil(timeout_ms, [this]() { return response_size() != 0; });
  }

  void MigrateSocket(const QuicIpAddress& new_host);
  QuicIpAddress bind_to_address() const;
  void set_bind_to_address(QuicIpAddress address);
  const QuicSocketAddress& address() const;

  // Returns the response trailers as received by the |stream_|.
  const SpdyHeaderBlock& response_trailers() const;

  // From QuicSpdyStream::Visitor
  void OnClose(QuicSpdyStream* stream) override;

  // From QuicClientPushPromiseIndex::Delegate
  bool CheckVary(const SpdyHeaderBlock& client_request,
                 const SpdyHeaderBlock& promise_request,
                 const SpdyHeaderBlock& promise_response) override;
  void OnRendezvousResult(QuicSpdyStream*) override;

  // Configures client_ to take ownership of and use the writer.
  // Must be called before initial connect.
  void UseWriter(QuicPacketWriterWrapper* writer);
  // If the given ConnectionId is nonzero, configures client_ to use a specific
  // ConnectionId instead of a random one.
  void UseConnectionId(QuicConnectionId connection_id);

  // Update internal stream_ pointer and perform accompanying housekeeping.
  void SetStream(QuicSpdyClientStream* stream);
  // Returns nullptr if the maximum number of streams have already been created.
  QuicSpdyClientStream* GetOrCreateStream();

  // Calls GetOrCreateStream(), sends the request on the stream, and
  // stores the request in case it needs to be resent.  If |headers| is
  // null, only the body will be sent on the stream.
  ssize_t GetOrCreateStreamAndSendRequest(const SpdyHeaderBlock* headers,
                                          base::StringPiece body,
                                          bool fin,
                                          QuicAckListenerInterface* delegate);

  QuicRstStreamErrorCode stream_error() { return stream_error_; }
  QuicErrorCode connection_error();

  MockableQuicClient* client();

  // cert_common_name returns the common name value of the server's certificate,
  // or the empty string if no certificate was presented.
  const std::string& cert_common_name() const;

  // cert_sct returns the signed timestamp of the server's certificate,
  // or the empty string if no signed timestamp was presented.
  const std::string& cert_sct() const;

  // Get the server config map.
  QuicTagValueMap GetServerConfig() const;

  void set_auto_reconnect(bool reconnect) { auto_reconnect_ = reconnect; }

  void set_priority(SpdyPriority priority) { priority_ = priority; }

  void WaitForWriteToFlush();

  EpollServer* epoll_server() { return &epoll_server_; }

  void set_allow_bidirectional_data(bool value) {
    allow_bidirectional_data_ = value;
  }

  bool allow_bidirectional_data() const { return allow_bidirectional_data_; }

  size_t num_requests() const { return num_requests_; }

  size_t num_responses() const { return num_responses_; }

  void set_server_address(const QuicSocketAddress& server_address) {
    client_->set_server_address(server_address);
  }

  // Explicitly set the SNI value for this client, overriding the default
  // behavior which extracts the SNI value from the request URL.
  void OverrideSni(const std::string& sni) {
    override_sni_set_ = true;
    override_sni_ = sni;
  }

  void Initialize();

  void set_client(MockableQuicClient* client) { client_.reset(client); }

 protected:
  QuicTestClient();

 private:
  class TestClientDataToResend : public QuicClient::QuicDataToResend {
   public:
    TestClientDataToResend(std::unique_ptr<SpdyHeaderBlock> headers,
                           base::StringPiece body,
                           bool fin,
                           QuicTestClient* test_client,
                           QuicAckListenerInterface* delegate)
        : QuicClient::QuicDataToResend(std::move(headers), body, fin),
          test_client_(test_client),
          delegate_(delegate) {}

    ~TestClientDataToResend() override {}

    void Resend() override;

   protected:
    QuicTestClient* test_client_;
    QuicAckListenerInterface* delegate_;
  };

  // Given |uri|, populates the fields in |headers| for a simple GET
  // request. If |uri| is a relative URL, the QuicServerId will be
  // use to specify the authority.
  bool PopulateHeaderBlockFromUrl(const std::string& uri,
                                  SpdyHeaderBlock* headers);

  bool HaveActiveStream();

  EpollServer epoll_server_;
  std::unique_ptr<MockableQuicClient> client_;  // The actual client
  QuicSpdyClientStream* stream_;

  QuicRstStreamErrorCode stream_error_;

  bool response_complete_;
  bool response_headers_complete_;
  mutable SpdyHeaderBlock response_headers_;

  // Parsed response trailers (if present), copied from the stream in OnClose.
  SpdyHeaderBlock response_trailers_;

  SpdyPriority priority_;
  std::string response_;
  // bytes_read_ and bytes_written_ are updated only when stream_ is released;
  // prefer bytes_read() and bytes_written() member functions.
  uint64_t bytes_read_;
  uint64_t bytes_written_;
  // The number of HTTP body bytes received.
  int64_t response_body_size_;
  // True if we tried to connect already since the last call to Disconnect().
  bool connect_attempted_;
  // The client will auto-connect exactly once before sending data.  If
  // something causes a connection reset, it will not automatically reconnect
  // unless auto_reconnect_ is true.
  bool auto_reconnect_;
  // Should we buffer the response body? Defaults to true.
  bool buffer_body_;
  // When true allows the sending of a request to continue while the response is
  // arriving.
  bool allow_bidirectional_data_;
  // For async push promise rendezvous, validation may fail in which
  // case the request should be retried.
  std::unique_ptr<TestClientDataToResend> push_promise_data_to_resend_;
  // Number of requests/responses this client has sent/received.
  size_t num_requests_;
  size_t num_responses_;

  // If set, this value is used for the connection SNI, overriding the usual
  // logic which extracts the SNI from the request URL.
  bool override_sni_set_ = false;
  std::string override_sni_;

  DISALLOW_COPY_AND_ASSIGN(QuicTestClient);
};

}  // namespace test

}  // namespace net

#endif  // NET_TOOLS_QUIC_TEST_TOOLS_QUIC_TEST_CLIENT_H_
