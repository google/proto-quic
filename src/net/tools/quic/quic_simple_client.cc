// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_simple_client.h"

#include <utility>

#include "base/logging.h"
#include "base/run_loop.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/net_errors.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_info.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/quic/quic_chromium_packet_writer.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_server_id.h"
#include "net/quic/spdy_utils.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/udp/udp_client_socket.h"

using std::string;
using std::vector;

namespace net {

void QuicSimpleClient::ClientQuicDataToResend::Resend() {
  client_->SendRequest(*headers_, body_, fin_);
  delete headers_;
  headers_ = nullptr;
}

QuicSimpleClient::QuicSimpleClient(IPEndPoint server_address,
                                   const QuicServerId& server_id,
                                   const QuicVersionVector& supported_versions,
                                   ProofVerifier* proof_verifier)
    : QuicClientBase(server_id,
                     supported_versions,
                     QuicConfig(),
                     CreateQuicConnectionHelper(),
                     CreateQuicAlarmFactory(),
                     proof_verifier),
      server_address_(server_address),
      local_port_(0),
      initialized_(false),
      packet_reader_started_(false),
      weak_factory_(this) {}

QuicSimpleClient::QuicSimpleClient(IPEndPoint server_address,
                                   const QuicServerId& server_id,
                                   const QuicVersionVector& supported_versions,
                                   const QuicConfig& config,
                                   ProofVerifier* proof_verifier)
    : QuicClientBase(server_id,
                     supported_versions,
                     config,
                     CreateQuicConnectionHelper(),
                     CreateQuicAlarmFactory(),
                     proof_verifier),
      server_address_(server_address),
      local_port_(0),
      initialized_(false),
      packet_reader_started_(false),
      weak_factory_(this) {}

QuicSimpleClient::~QuicSimpleClient() {
  if (connected()) {
    session()->connection()->CloseConnection(
        QUIC_PEER_GOING_AWAY, "Shutting down",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }
  STLDeleteElements(&data_to_resend_on_connect_);
  STLDeleteElements(&data_sent_before_handshake_);
}

bool QuicSimpleClient::Initialize() {
  DCHECK(!initialized_);

  QuicClientBase::Initialize();

  if (!CreateUDPSocket()) {
    return false;
  }

  initialized_ = true;
  return true;
}

QuicSimpleClient::QuicDataToResend::QuicDataToResend(HttpRequestInfo* headers,
                                                     base::StringPiece body,
                                                     bool fin)
    : headers_(headers), body_(body), fin_(fin) {}

QuicSimpleClient::QuicDataToResend::~QuicDataToResend() {
  if (headers_) {
    delete headers_;
  }
}

bool QuicSimpleClient::CreateUDPSocket() {
  std::unique_ptr<UDPClientSocket> socket(
      new UDPClientSocket(DatagramSocket::DEFAULT_BIND, RandIntCallback(),
                          &net_log_, NetLog::Source()));

  int address_family = server_address_.GetSockAddrFamily();
  if (bind_to_address_.size() != 0) {
    client_address_ = IPEndPoint(bind_to_address_, local_port_);
  } else if (address_family == AF_INET) {
    client_address_ = IPEndPoint(IPAddress::IPv4AllZeros(), local_port_);
  } else {
    client_address_ = IPEndPoint(IPAddress::IPv6AllZeros(), local_port_);
  }

  int rc = socket->Connect(server_address_);
  if (rc != OK) {
    LOG(ERROR) << "Connect failed: " << ErrorToShortString(rc);
    return false;
  }

  rc = socket->SetReceiveBufferSize(kDefaultSocketReceiveBuffer);
  if (rc != OK) {
    LOG(ERROR) << "SetReceiveBufferSize() failed: " << ErrorToShortString(rc);
    return false;
  }

  rc = socket->SetSendBufferSize(kDefaultSocketReceiveBuffer);
  if (rc != OK) {
    LOG(ERROR) << "SetSendBufferSize() failed: " << ErrorToShortString(rc);
    return false;
  }

  rc = socket->GetLocalAddress(&client_address_);
  if (rc != OK) {
    LOG(ERROR) << "GetLocalAddress failed: " << ErrorToShortString(rc);
    return false;
  }

  socket_.swap(socket);
  packet_reader_.reset(new QuicChromiumPacketReader(
      socket_.get(), &clock_, this, kQuicYieldAfterPacketsRead,
      QuicTime::Delta::FromMilliseconds(kQuicYieldAfterDurationMilliseconds),
      BoundNetLog()));

  if (socket != nullptr) {
    socket->Close();
  }

  return true;
}

void QuicSimpleClient::StartPacketReaderIfNotStarted() {
  if (!packet_reader_started_) {
    packet_reader_->StartReading();
    packet_reader_started_ = true;
  }
}

bool QuicSimpleClient::Connect() {
  // Attempt multiple connects until the maximum number of client hellos have
  // been sent.
  while (!connected() &&
         GetNumSentClientHellos() <= QuicCryptoClientStream::kMaxClientHellos) {
    StartConnect();
    StartPacketReaderIfNotStarted();
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

void QuicSimpleClient::StartConnect() {
  DCHECK(initialized_);
  DCHECK(!connected());

  set_writer(CreateQuicPacketWriter());

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
      GetNextConnectionId(), server_address_, helper(), alarm_factory(),
      writer(),
      /* owns_writer= */ false, Perspective::IS_CLIENT, supported_versions()));

  session()->Initialize();
  session()->CryptoConnect();
  set_connected_or_attempting_connect(true);
}

void QuicSimpleClient::Disconnect() {
  DCHECK(initialized_);

  if (connected()) {
    session()->connection()->CloseConnection(
        QUIC_PEER_GOING_AWAY, "Client disconnecting",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }
  STLDeleteElements(&data_to_resend_on_connect_);
  STLDeleteElements(&data_sent_before_handshake_);

  reset_writer();
  packet_reader_.reset();
  packet_reader_started_ = false;

  initialized_ = false;
}

void QuicSimpleClient::SendRequest(const HttpRequestInfo& headers,
                                   base::StringPiece body,
                                   bool fin) {
  QuicSpdyClientStream* stream = CreateReliableClientStream();
  if (stream == nullptr) {
    LOG(DFATAL) << "stream creation failed!";
    return;
  }
  SpdyHeaderBlock header_block;
  CreateSpdyHeadersFromHttpRequest(headers, headers.extra_headers, net::HTTP2,
                                   true, &header_block);
  stream->set_visitor(this);
  stream->SendRequest(std::move(header_block), body, fin);
  if (FLAGS_enable_quic_stateless_reject_support) {
    // Record this in case we need to resend.
    auto* new_headers = new HttpRequestInfo;
    *new_headers = headers;
    auto* data_to_resend =
        new ClientQuicDataToResend(new_headers, body, fin, this);
    MaybeAddQuicDataToResend(data_to_resend);
  }
}

void QuicSimpleClient::MaybeAddQuicDataToResend(
    QuicDataToResend* data_to_resend) {
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

void QuicSimpleClient::SendRequestAndWaitForResponse(
    const HttpRequestInfo& request,
    base::StringPiece body,
    bool fin) {
  SendRequest(request, body, fin);
  while (WaitForEvents()) {
  }
}

void QuicSimpleClient::SendRequestsAndWaitForResponse(
    const base::CommandLine::StringVector& url_list) {
  for (size_t i = 0; i < url_list.size(); ++i) {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL(url_list[i]);
    SendRequest(request, "", true);
  }

  while (WaitForEvents()) {
  }
}

bool QuicSimpleClient::WaitForEvents() {
  DCHECK(connected());

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

bool QuicSimpleClient::MigrateSocket(const IPAddress& new_host) {
  if (!connected()) {
    return false;
  }

  bind_to_address_ = new_host;
  if (!CreateUDPSocket()) {
    return false;
  }

  session()->connection()->SetSelfAddress(client_address_);

  QuicPacketWriter* writer = CreateQuicPacketWriter();
  set_writer(writer);
  session()->connection()->SetQuicPacketWriter(writer, false);

  return true;
}

void QuicSimpleClient::OnClose(QuicSpdyStream* stream) {
  DCHECK(stream != nullptr);
  QuicSpdyClientStream* client_stream =
      static_cast<QuicSpdyClientStream*>(stream);
  HttpResponseInfo response;
  SpdyHeadersToHttpResponse(client_stream->response_headers(), net::HTTP2,
                            &response);
  if (response_listener_.get() != nullptr) {
    response_listener_->OnCompleteResponse(stream->id(), *response.headers,
                                           client_stream->data());
  }

  // Store response headers and body.
  if (store_response_) {
    latest_response_code_ = client_stream->response_code();
    response.headers->GetNormalizedHeaders(&latest_response_headers_);
    latest_response_body_ = client_stream->data();
  }
}

size_t QuicSimpleClient::latest_response_code() const {
  LOG_IF(DFATAL, !store_response_) << "Response not stored!";
  return latest_response_code_;
}

const string& QuicSimpleClient::latest_response_headers() const {
  LOG_IF(DFATAL, !store_response_) << "Response not stored!";
  return latest_response_headers_;
}

const string& QuicSimpleClient::latest_response_body() const {
  LOG_IF(DFATAL, !store_response_) << "Response not stored!";
  return latest_response_body_;
}

QuicConnectionId QuicSimpleClient::GenerateNewConnectionId() {
  return helper()->GetRandomGenerator()->RandUint64();
}

QuicChromiumConnectionHelper* QuicSimpleClient::CreateQuicConnectionHelper() {
  return new QuicChromiumConnectionHelper(&clock_, QuicRandom::GetInstance());
}

QuicChromiumAlarmFactory* QuicSimpleClient::CreateQuicAlarmFactory() {
  return new QuicChromiumAlarmFactory(base::ThreadTaskRunnerHandle::Get().get(),
                                      &clock_);
}

QuicPacketWriter* QuicSimpleClient::CreateQuicPacketWriter() {
  return new QuicChromiumPacketWriter(socket_.get());
}

void QuicSimpleClient::OnReadError(int result,
                                   const DatagramClientSocket* socket) {
  LOG(ERROR) << "QuicSimpleClient read failed: " << ErrorToShortString(result);
  Disconnect();
}

bool QuicSimpleClient::OnPacket(const QuicReceivedPacket& packet,
                                IPEndPoint local_address,
                                IPEndPoint peer_address) {
  session()->connection()->ProcessUdpPacket(local_address, peer_address,
                                            packet);
  if (!session()->connection()->connected()) {
    return false;
  }

  return true;
}

}  // namespace net
