// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_client.h"

#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "base/logging.h"
#include "base/run_loop.h"
#include "net/base/sockaddr_storage.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_data_reader.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_server_id.h"
#include "net/tools/quic/quic_epoll_alarm_factory.h"
#include "net/tools/quic/quic_epoll_connection_helper.h"
#include "net/tools/quic/quic_socket_utils.h"
#include "net/tools/quic/spdy_balsa_utils.h"

#ifndef SO_RXQ_OVFL
#define SO_RXQ_OVFL 40
#endif

// TODO(rtenneti): Add support for MMSG_MORE.
#define MMSG_MORE 0

using base::StringPiece;
using std::string;
using std::vector;

namespace net {

const int kEpollFlags = EPOLLIN | EPOLLOUT | EPOLLET;

void QuicClient::ClientQuicDataToResend::Resend() {
  client_->SendRequest(*headers_, body_, fin_);
  delete headers_;
  headers_ = nullptr;
}

QuicClient::QuicClient(IPEndPoint server_address,
                       const QuicServerId& server_id,
                       const QuicVersionVector& supported_versions,
                       EpollServer* epoll_server,
                       ProofVerifier* proof_verifier)
    : QuicClient(server_address,
                 server_id,
                 supported_versions,
                 QuicConfig(),
                 epoll_server,
                 proof_verifier) {}

QuicClient::QuicClient(IPEndPoint server_address,
                       const QuicServerId& server_id,
                       const QuicVersionVector& supported_versions,
                       const QuicConfig& config,
                       EpollServer* epoll_server,
                       ProofVerifier* proof_verifier)
    : QuicClientBase(
          server_id,
          supported_versions,
          config,
          new QuicEpollConnectionHelper(epoll_server, QuicAllocator::SIMPLE),
          new QuicEpollAlarmFactory(epoll_server),
          proof_verifier),
      server_address_(server_address),
      local_port_(0),
      epoll_server_(epoll_server),
      initialized_(false),
      packets_dropped_(0),
      overflow_supported_(false),
      store_response_(false),
      latest_response_code_(-1),
      packet_reader_(new QuicPacketReader()) {}

QuicClient::~QuicClient() {
  if (connected()) {
    session()->connection()->CloseConnection(
        QUIC_PEER_GOING_AWAY, "Client being torn down",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }

  STLDeleteElements(&data_to_resend_on_connect_);
  STLDeleteElements(&data_sent_before_handshake_);

  CleanUpAllUDPSockets();
}

bool QuicClient::Initialize() {
  QuicClientBase::Initialize();

  set_num_sent_client_hellos(0);
  set_num_stateless_rejects_received(0);
  set_connection_error(QUIC_NO_ERROR);

  // If an initial flow control window has not explicitly been set, then use the
  // same values that Chrome uses.
  const uint32_t kSessionMaxRecvWindowSize = 15 * 1024 * 1024;  // 15 MB
  const uint32_t kStreamMaxRecvWindowSize = 6 * 1024 * 1024;    //  6 MB
  if (config()->GetInitialStreamFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config()->SetInitialStreamFlowControlWindowToSend(kStreamMaxRecvWindowSize);
  }
  if (config()->GetInitialSessionFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config()->SetInitialSessionFlowControlWindowToSend(
        kSessionMaxRecvWindowSize);
  }

  epoll_server_->set_timeout_in_us(50 * 1000);

  if (!CreateUDPSocketAndBind()) {
    return false;
  }

  epoll_server_->RegisterFD(GetLatestFD(), this, kEpollFlags);
  initialized_ = true;
  return true;
}

QuicClient::QuicDataToResend::QuicDataToResend(BalsaHeaders* headers,
                                               StringPiece body,
                                               bool fin)
    : headers_(headers), body_(body), fin_(fin) {}

QuicClient::QuicDataToResend::~QuicDataToResend() {
  if (headers_) {
    delete headers_;
  }
}

bool QuicClient::CreateUDPSocketAndBind() {
  int fd =
      QuicSocketUtils::CreateUDPSocket(server_address_, &overflow_supported_);
  if (fd < 0) {
    return false;
  }

  IPEndPoint client_address;
  if (bind_to_address_.size() != 0) {
    client_address = IPEndPoint(bind_to_address_, local_port_);
  } else if (server_address_.GetSockAddrFamily() == AF_INET) {
    client_address = IPEndPoint(IPAddress::IPv4AllZeros(), local_port_);
  } else {
    IPAddress any6 = IPAddress::IPv6AllZeros();
    client_address = IPEndPoint(any6, local_port_);
  }

  sockaddr_storage raw_addr;
  socklen_t raw_addr_len = sizeof(raw_addr);
  CHECK(client_address.ToSockAddr(reinterpret_cast<sockaddr*>(&raw_addr),
                                  &raw_addr_len));
  int rc =
      bind(fd, reinterpret_cast<const sockaddr*>(&raw_addr), sizeof(raw_addr));
  if (rc < 0) {
    LOG(ERROR) << "Bind failed: " << strerror(errno);
    return false;
  }

  SockaddrStorage storage;
  if (getsockname(fd, storage.addr, &storage.addr_len) != 0 ||
      !client_address.FromSockAddr(storage.addr, storage.addr_len)) {
    LOG(ERROR) << "Unable to get self address.  Error: " << strerror(errno);
  }

  fd_address_map_[fd] = client_address;

  return true;
}

bool QuicClient::Connect() {
  // Attempt multiple connects until the maximum number of client hellos have
  // been sent.
  while (!connected() &&
         GetNumSentClientHellos() <= QuicCryptoClientStream::kMaxClientHellos) {
    StartConnect();
    while (EncryptionBeingEstablished()) {
      WaitForEvents();
    }
    if (FLAGS_enable_quic_stateless_reject_support && connected() &&
        !data_to_resend_on_connect_.empty()) {
      // A connection has been established and there was previously queued data
      // to resend.  Resend it and empty the queue.
      for (QuicDataToResend* data : data_to_resend_on_connect_) {
        data->Resend();
      }
      STLDeleteElements(&data_to_resend_on_connect_);
    }
    if (session() != nullptr &&
        session()->error() != QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
      // We've successfully created a session but we're not connected, and there
      // is no stateless reject to recover from.  Give up trying.
      break;
    }
  }
  if (!connected() &&
      GetNumSentClientHellos() > QuicCryptoClientStream::kMaxClientHellos &&
      session() != nullptr &&
      session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
    // The overall connection failed due too many stateless rejects.
    set_connection_error(QUIC_CRYPTO_TOO_MANY_REJECTS);
  }
  return session()->connection()->connected();
}

void QuicClient::StartConnect() {
  DCHECK(initialized_);
  DCHECK(!connected());

  QuicPacketWriter* writer = CreateQuicPacketWriter();

  if (connected_or_attempting_connect()) {
    // Before we destroy the last session and create a new one, gather its stats
    // and update the stats for the overall connection.
    UpdateStats();
    if (session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
      // If the last error was due to a stateless reject, queue up the data to
      // be resent on the next successful connection.
      // TODO(jokulik): I'm a little bit concerned about ordering here.  Maybe
      // we should just maintain one queue?
      DCHECK(data_to_resend_on_connect_.empty());
      data_to_resend_on_connect_.swap(data_sent_before_handshake_);
    }
  }

  CreateQuicClientSession(new QuicConnection(
      GetNextConnectionId(), server_address_, helper(), alarm_factory(), writer,
      /* owns_writer= */ false, Perspective::IS_CLIENT, supported_versions()));

  // Reset |writer_| after |session()| so that the old writer outlives the old
  // session.
  set_writer(writer);
  session()->Initialize();
  session()->CryptoConnect();
  set_connected_or_attempting_connect(true);
}

void QuicClient::Disconnect() {
  DCHECK(initialized_);

  if (connected()) {
    session()->connection()->CloseConnection(
        QUIC_PEER_GOING_AWAY, "Client disconnecting",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }
  STLDeleteElements(&data_to_resend_on_connect_);
  STLDeleteElements(&data_sent_before_handshake_);

  CleanUpAllUDPSockets();

  initialized_ = false;
}

void QuicClient::CleanUpUDPSocket(int fd) {
  CleanUpUDPSocketImpl(fd);
  fd_address_map_.erase(fd);
}

void QuicClient::CleanUpAllUDPSockets() {
  for (std::pair<int, IPEndPoint> fd_address : fd_address_map_) {
    CleanUpUDPSocketImpl(fd_address.first);
  }
  fd_address_map_.clear();
}

void QuicClient::CleanUpUDPSocketImpl(int fd) {
  if (fd > -1) {
    epoll_server_->UnregisterFD(fd);
    int rc = close(fd);
    DCHECK_EQ(0, rc);
  }
}

void QuicClient::SendRequest(const BalsaHeaders& headers,
                             StringPiece body,
                             bool fin) {
  QuicClientPushPromiseIndex::TryHandle* handle;
  QuicAsyncStatus rv = push_promise_index()->Try(
      SpdyBalsaUtils::RequestHeadersToSpdyHeaders(headers), this, &handle);
  if (rv == QUIC_SUCCESS)
    return;

  if (rv == QUIC_PENDING) {
    // May need to retry request if asynchronous rendezvous fails.
    auto new_headers = new BalsaHeaders;
    new_headers->CopyFrom(headers);
    push_promise_data_to_resend_.reset(
        new ClientQuicDataToResend(new_headers, body, fin, this));
    return;
  }

  QuicSpdyClientStream* stream = CreateReliableClientStream();
  if (stream == nullptr) {
    QUIC_BUG << "stream creation failed!";
    return;
  }
  stream->set_visitor(this);
  stream->SendRequest(SpdyBalsaUtils::RequestHeadersToSpdyHeaders(headers),
                      body, fin);
  if (FLAGS_enable_quic_stateless_reject_support) {
    // Record this in case we need to resend.
    auto new_headers = new BalsaHeaders;
    new_headers->CopyFrom(headers);
    auto data_to_resend =
        new ClientQuicDataToResend(new_headers, body, fin, this);
    MaybeAddQuicDataToResend(data_to_resend);
  }
}

void QuicClient::MaybeAddQuicDataToResend(QuicDataToResend* data_to_resend) {
  DCHECK(FLAGS_enable_quic_stateless_reject_support);
  if (session()->IsCryptoHandshakeConfirmed()) {
    // The handshake is confirmed.  No need to continue saving requests to
    // resend.
    STLDeleteElements(&data_sent_before_handshake_);
    delete data_to_resend;
    return;
  }

  // The handshake is not confirmed.  Push the data onto the queue of data to
  // resend if statelessly rejected.
  data_sent_before_handshake_.push_back(data_to_resend);
}

void QuicClient::SendRequestAndWaitForResponse(const BalsaHeaders& headers,
                                               StringPiece body,
                                               bool fin) {
  SendRequest(headers, body, fin);
  while (WaitForEvents()) {
  }
}

void QuicClient::SendRequestsAndWaitForResponse(
    const vector<string>& url_list) {
  for (size_t i = 0; i < url_list.size(); ++i) {
    BalsaHeaders headers;
    headers.SetRequestFirstlineFromStringPieces("GET", url_list[i], "HTTP/1.1");
    SendRequest(headers, "", true);
  }
  while (WaitForEvents()) {
  }
}

bool QuicClient::WaitForEvents() {
  DCHECK(connected());

  epoll_server_->WaitForEventsAndExecuteCallbacks();
  base::RunLoop().RunUntilIdle();

  DCHECK(session() != nullptr);
  if (!connected() &&
      session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
    DCHECK(FLAGS_enable_quic_stateless_reject_support);
    DVLOG(1) << "Detected stateless reject while waiting for events.  "
             << "Attempting to reconnect.";
    Connect();
  }

  return session()->num_active_requests() != 0;
}

bool QuicClient::MigrateSocket(const IPAddress& new_host) {
  if (!connected()) {
    return false;
  }

  CleanUpUDPSocket(GetLatestFD());

  bind_to_address_ = new_host;
  if (!CreateUDPSocketAndBind()) {
    return false;
  }

  epoll_server_->RegisterFD(GetLatestFD(), this, kEpollFlags);
  session()->connection()->SetSelfAddress(GetLatestClientAddress());

  QuicPacketWriter* writer = CreateQuicPacketWriter();
  set_writer(writer);
  session()->connection()->SetQuicPacketWriter(writer, false);

  return true;
}

void QuicClient::OnEvent(int fd, EpollEvent* event) {
  DCHECK_EQ(fd, GetLatestFD());

  if (event->in_events & EPOLLIN) {
    bool more_to_read = true;
    while (connected() && more_to_read) {
      more_to_read = packet_reader_->ReadAndDispatchPackets(
          GetLatestFD(), QuicClient::GetLatestClientAddress().port(),
          *helper()->GetClock(), this,
          overflow_supported_ ? &packets_dropped_ : nullptr);
    }
  }
  if (connected() && (event->in_events & EPOLLOUT)) {
    writer()->SetWritable();
    session()->connection()->OnCanWrite();
  }
  if (event->in_events & EPOLLERR) {
    DVLOG(1) << "Epollerr";
  }
}

void QuicClient::OnClose(QuicSpdyStream* stream) {
  DCHECK(stream != nullptr);
  QuicSpdyClientStream* client_stream =
      static_cast<QuicSpdyClientStream*>(stream);
  BalsaHeaders response_headers;
  SpdyBalsaUtils::SpdyHeadersToResponseHeaders(
      client_stream->response_headers(), &response_headers);

  if (response_listener_.get() != nullptr) {
    response_listener_->OnCompleteResponse(stream->id(), response_headers,
                                           client_stream->data());
  }

  // Store response headers and body.
  if (store_response_) {
    latest_response_code_ = response_headers.parsed_response_code();
    response_headers.DumpHeadersToString(&latest_response_headers_);
    latest_response_body_ = client_stream->data();
    latest_response_trailers_ =
        client_stream->received_trailers().DebugString();
  }
}

bool QuicClient::CheckVary(const SpdyHeaderBlock& client_request,
                           const SpdyHeaderBlock& promise_request,
                           const SpdyHeaderBlock& promise_response) {
  return true;
}

void QuicClient::OnRendezvousResult(QuicSpdyStream* stream) {
  std::unique_ptr<ClientQuicDataToResend> data_to_resend =
      std::move(push_promise_data_to_resend_);
  if (stream) {
    stream->set_visitor(this);
    stream->OnDataAvailable();
  } else if (data_to_resend.get()) {
    data_to_resend->Resend();
  }
}

size_t QuicClient::latest_response_code() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return latest_response_code_;
}

const string& QuicClient::latest_response_headers() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return latest_response_headers_;
}

const string& QuicClient::latest_response_body() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return latest_response_body_;
}

const string& QuicClient::latest_response_trailers() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return latest_response_trailers_;
}

QuicPacketWriter* QuicClient::CreateQuicPacketWriter() {
  return new QuicDefaultPacketWriter(GetLatestFD());
}

const IPEndPoint QuicClient::GetLatestClientAddress() const {
  if (fd_address_map_.empty()) {
    return IPEndPoint();
  }

  return fd_address_map_.back().second;
}

int QuicClient::GetLatestFD() const {
  if (fd_address_map_.empty()) {
    return -1;
  }

  return fd_address_map_.back().first;
}

void QuicClient::ProcessPacket(const IPEndPoint& self_address,
                               const IPEndPoint& peer_address,
                               const QuicReceivedPacket& packet) {
  session()->connection()->ProcessUdpPacket(self_address, peer_address, packet);
}

}  // namespace net
