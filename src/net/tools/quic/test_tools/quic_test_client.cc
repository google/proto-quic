// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/test_tools/quic_test_client.h"

#include <memory>
#include <utility>

#include "base/time/time.h"
#include "net/base/completion_callback.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/x509_certificate.h"
#include "net/quic/crypto/proof_verifier.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_server_id.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_spdy_session_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/reliable_quic_stream_peer.h"
#include "net/tools/balsa/balsa_headers.h"
#include "net/tools/quic/quic_epoll_connection_helper.h"
#include "net/tools/quic/quic_packet_writer_wrapper.h"
#include "net/tools/quic/quic_spdy_client_stream.h"
#include "net/tools/quic/spdy_balsa_utils.h"
#include "net/tools/quic/test_tools/http_message.h"
#include "net/tools/quic/test_tools/quic_client_peer.h"
#include "url/gurl.h"

using base::StringPiece;
using net::QuicServerId;
using net::test::QuicConnectionPeer;
using net::test::QuicSpdySessionPeer;
using net::test::ReliableQuicStreamPeer;
using std::string;
using std::vector;

namespace net {
namespace test {
namespace {

// RecordingProofVerifier accepts any certificate chain and records the common
// name of the leaf.
class RecordingProofVerifier : public ProofVerifier {
 public:
  // ProofVerifier interface.
  QuicAsyncStatus VerifyProof(const string& hostname,
                              const uint16_t port,
                              const string& server_config,
                              QuicVersion quic_version,
                              StringPiece chlo_hash,
                              const vector<string>& certs,
                              const string& cert_sct,
                              const string& signature,
                              const ProofVerifyContext* context,
                              string* error_details,
                              std::unique_ptr<ProofVerifyDetails>* details,
                              ProofVerifierCallback* callback) override {
    common_name_.clear();
    if (certs.empty()) {
      return QUIC_FAILURE;
    }

    // Convert certs to X509Certificate.
    vector<StringPiece> cert_pieces(certs.size());
    for (unsigned i = 0; i < certs.size(); i++) {
      cert_pieces[i] = StringPiece(certs[i]);
    }
    // TODO(rtenneti): Fix after adding support for real certs. Currently,
    // cert_pieces are "leaf" and "intermediate" and CreateFromDERCertChain
    // fails to return cert from these cert_pieces.
    //    scoped_refptr<net::X509Certificate> cert =
    //        net::X509Certificate::CreateFromDERCertChain(cert_pieces);
    //    if (!cert.get()) {
    //      return QUIC_FAILURE;
    //    }
    //
    //    common_name_ = cert->subject().GetDisplayName();
    cert_sct_ = cert_sct;

    return QUIC_SUCCESS;
  }

  const string& common_name() const { return common_name_; }

  const string& cert_sct() const { return cert_sct_; }

 private:
  string common_name_;
  string cert_sct_;
};

}  // anonymous namespace

BalsaHeaders* MungeHeaders(const BalsaHeaders* const_headers) {
  StringPiece uri = const_headers->request_uri();
  if (uri.empty()) {
    return nullptr;
  }
  if (const_headers->request_method() == "CONNECT") {
    return nullptr;
  }
  BalsaHeaders* headers = new BalsaHeaders;
  headers->CopyFrom(*const_headers);
  if (!uri.starts_with("https://") && !uri.starts_with("http://")) {
    // If we have a relative URL, set some defaults.
    string full_uri = "https://www.google.com";
    full_uri.append(uri.as_string());
    headers->SetRequestUri(full_uri);
  }
  return headers;
}

MockableQuicClient::MockableQuicClient(
    IPEndPoint server_address,
    const QuicServerId& server_id,
    const QuicVersionVector& supported_versions,
    EpollServer* epoll_server)
    : MockableQuicClient(server_address,
                         server_id,
                         QuicConfig(),
                         supported_versions,
                         epoll_server) {}

MockableQuicClient::MockableQuicClient(
    IPEndPoint server_address,
    const QuicServerId& server_id,
    const QuicConfig& config,
    const QuicVersionVector& supported_versions,
    EpollServer* epoll_server)
    : QuicClient(server_address,
                 server_id,
                 supported_versions,
                 config,
                 epoll_server,
                 new RecordingProofVerifier()),
      override_connection_id_(0),
      test_writer_(nullptr) {}

MockableQuicClient::~MockableQuicClient() {
  if (connected()) {
    Disconnect();
  }
}

QuicPacketWriter* MockableQuicClient::CreateQuicPacketWriter() {
  QuicPacketWriter* writer = QuicClient::CreateQuicPacketWriter();
  if (!test_writer_) {
    return writer;
  }
  test_writer_->set_writer(writer);
  return test_writer_;
}

QuicConnectionId MockableQuicClient::GenerateNewConnectionId() {
  return override_connection_id_ ? override_connection_id_
                                 : QuicClient::GenerateNewConnectionId();
}

// Takes ownership of writer.
void MockableQuicClient::UseWriter(QuicPacketWriterWrapper* writer) {
  CHECK(test_writer_ == nullptr);
  test_writer_ = writer;
}

void MockableQuicClient::UseConnectionId(QuicConnectionId connection_id) {
  override_connection_id_ = connection_id;
}

QuicTestClient::QuicTestClient(IPEndPoint server_address,
                               const string& server_hostname,
                               const QuicVersionVector& supported_versions)
    : QuicTestClient(server_address,
                     server_hostname,
                     QuicConfig(),
                     supported_versions) {}

QuicTestClient::QuicTestClient(IPEndPoint server_address,
                               const string& server_hostname,
                               const QuicConfig& config,
                               const QuicVersionVector& supported_versions)
    : client_(new MockableQuicClient(server_address,
                                     QuicServerId(server_hostname,
                                                  server_address.port(),
                                                  PRIVACY_MODE_DISABLED),
                                     config,
                                     supported_versions,
                                     &epoll_server_)),
      allow_bidirectional_data_(false) {
  Initialize();
}

QuicTestClient::QuicTestClient() : allow_bidirectional_data_(false) {}

QuicTestClient::~QuicTestClient() {
  if (stream_) {
    stream_->set_visitor(nullptr);
  }
  client_->Disconnect();
}

void QuicTestClient::Initialize() {
  priority_ = 3;
  connect_attempted_ = false;
  auto_reconnect_ = false;
  buffer_body_ = true;
  num_requests_ = 0;
  num_responses_ = 0;
  ClearPerRequestState();
  // As chrome will generally do this, we want it to be the default when it's
  // not overridden.
  if (!client_->config()->HasSetBytesForConnectionIdToSend()) {
    client_->config()->SetBytesForConnectionIdToSend(0);
  }
}

void QuicTestClient::SetUserAgentID(const string& user_agent_id) {
  client_->SetUserAgentID(user_agent_id);
}

ssize_t QuicTestClient::SendRequest(const string& uri) {
  HTTPMessage message;
  FillInRequest(uri, &message);
  return SendMessage(message);
}

void QuicTestClient::SendRequestsAndWaitForResponses(
    const vector<string>& url_list) {
  for (const string& url : url_list) {
    SendRequest(url);
  }
  while (client()->WaitForEvents()) {
  }
  return;
}

ssize_t QuicTestClient::GetOrCreateStreamAndSendRequest(
    const BalsaHeaders* headers,
    StringPiece body,
    bool fin,
    QuicAckListenerInterface* delegate) {
  if (headers) {
    QuicClientPushPromiseIndex::TryHandle* handle;
    QuicAsyncStatus rv = client()->push_promise_index()->Try(
        SpdyBalsaUtils::RequestHeadersToSpdyHeaders(*headers), this, &handle);
    if (rv == QUIC_SUCCESS)
      return 1;
    if (rv == QUIC_PENDING) {
      // May need to retry request if asynchronous rendezvous fails.
      auto* new_headers = new BalsaHeaders;
      new_headers->CopyFrom(*headers);
      push_promise_data_to_resend_.reset(
          new TestClientDataToResend(new_headers, body, fin, this, delegate));
      return 1;
    }
  }

  // Maybe it's better just to overload this.  it's just that we need
  // for the GetOrCreateStream function to call something else...which
  // is icky and complicated, but maybe not worse than this.
  QuicSpdyClientStream* stream = GetOrCreateStream();
  if (stream == nullptr) {
    return 0;
  }

  ssize_t ret = 0;
  if (headers != nullptr) {
    SpdyHeaderBlock spdy_headers =
        SpdyBalsaUtils::RequestHeadersToSpdyHeaders(*headers);
    if (headers->HasHeader("transfer-encoding")) {
      // We have tests which rely on sending a non-standards-compliant
      // T-E header.
      string encoding;
      headers->GetAllOfHeaderAsString("transfer-encoding", &encoding);
      spdy_headers.insert(std::make_pair("transfer-encoding", encoding));
    }
    if (static_cast<StringPiece>(spdy_headers[":authority"]).empty()) {
      // HTTP/2 requests should include the :authority pseudo hader.
      spdy_headers[":authority"] = client_->server_id().host();
    }
    ret = stream->SendRequest(std::move(spdy_headers), body, fin);
    ++num_requests_;
  } else {
    stream->WriteOrBufferBody(body.as_string(), fin, delegate);
    ret = body.length();
  }
  if (FLAGS_enable_quic_stateless_reject_support) {
    BalsaHeaders* new_headers = nullptr;
    if (headers) {
      new_headers = new BalsaHeaders;
      new_headers->CopyFrom(*headers);
    }
    auto* data_to_resend =
        new TestClientDataToResend(new_headers, body, fin, this, delegate);
    client()->MaybeAddQuicDataToResend(data_to_resend);
  }
  return ret;
}

ssize_t QuicTestClient::SendMessage(const HTTPMessage& message) {
  stream_ = nullptr;  // Always force creation of a stream for SendMessage.

  // If we're not connected, try to find an sni hostname.
  if (!connected()) {
    GURL url(message.headers()->request_uri().as_string());
    if (override_sni_set_) {
      client_->set_server_id(QuicServerId(override_sni_, url.EffectiveIntPort(),
                                          PRIVACY_MODE_DISABLED));
    } else {
      if (!url.host().empty()) {
        client_->set_server_id(QuicServerId(url.host(), url.EffectiveIntPort(),
                                            PRIVACY_MODE_DISABLED));
      }
    }
  }

  // TODO(rtenneti): Add support for HTTPMessage::body_chunks().
  // CHECK(message.body_chunks().empty())
  //      << "HTTPMessage::body_chunks not supported";

  std::unique_ptr<BalsaHeaders> munged_headers(MungeHeaders(message.headers()));
  ssize_t ret = GetOrCreateStreamAndSendRequest(
      (munged_headers.get() ? munged_headers.get() : message.headers()),
      message.body(), message.has_complete_message(), nullptr);
  WaitForWriteToFlush();
  return ret;
}

ssize_t QuicTestClient::SendData(const string& data, bool last_data) {
  return SendData(data, last_data, nullptr);
}

ssize_t QuicTestClient::SendData(const string& data,
                                 bool last_data,
                                 QuicAckListenerInterface* delegate) {
  return GetOrCreateStreamAndSendRequest(nullptr, StringPiece(data), last_data,
                                         delegate);
}

bool QuicTestClient::response_complete() const {
  return response_complete_;
}

int QuicTestClient::response_header_size() const {
  return response_header_size_;
}

int64_t QuicTestClient::response_body_size() const {
  return response_body_size_;
}

bool QuicTestClient::buffer_body() const {
  return buffer_body_;
}

void QuicTestClient::set_buffer_body(bool buffer_body) {
  buffer_body_ = buffer_body;
}

bool QuicTestClient::ServerInLameDuckMode() const {
  return false;
}

const string& QuicTestClient::response_body() {
  return response_;
}

string QuicTestClient::SendCustomSynchronousRequest(
    const HTTPMessage& message) {
  if (SendMessage(message) == 0) {
    DLOG(ERROR) << "Failed the request for uri:"
                << message.headers()->request_uri();
    // Set the response_ explicitly.  Otherwise response_ will contain the
    // response from the previously successful request.
    response_ = "";
  } else {
    WaitForResponse();
  }
  return response_;
}

string QuicTestClient::SendSynchronousRequest(const string& uri) {
  HTTPMessage message;
  FillInRequest(uri, &message);
  return SendCustomSynchronousRequest(message);
}

QuicSpdyClientStream* QuicTestClient::GetOrCreateStream() {
  if (!connect_attempted_ || auto_reconnect_) {
    if (!connected()) {
      Connect();
    }
    if (!connected()) {
      return nullptr;
    }
  }
  if (!stream_) {
    stream_ = client_->CreateReliableClientStream();
    if (stream_ == nullptr) {
      return nullptr;
    }
    stream_->set_visitor(this);
    QuicSpdyClientStream* cs = reinterpret_cast<QuicSpdyClientStream*>(stream_);
    cs->SetPriority(priority_);
    cs->set_allow_bidirectional_data(allow_bidirectional_data_);
  }

  return stream_;
}

QuicErrorCode QuicTestClient::connection_error() {
  return client()->connection_error();
}

MockableQuicClient* QuicTestClient::client() {
  return client_.get();
}

const string& QuicTestClient::cert_common_name() const {
  return reinterpret_cast<RecordingProofVerifier*>(client_->proof_verifier())
      ->common_name();
}

const string& QuicTestClient::cert_sct() const {
  return reinterpret_cast<RecordingProofVerifier*>(client_->proof_verifier())
      ->cert_sct();
}

QuicTagValueMap QuicTestClient::GetServerConfig() const {
  QuicCryptoClientConfig* config = client_->crypto_config();
  QuicCryptoClientConfig::CachedState* state =
      config->LookupOrCreate(client_->server_id());
  const CryptoHandshakeMessage* handshake_msg = state->GetServerConfig();
  if (handshake_msg != nullptr) {
    return handshake_msg->tag_value_map();
  } else {
    return QuicTagValueMap();
  }
}

bool QuicTestClient::connected() const {
  return client_->connected();
}

void QuicTestClient::Connect() {
  DCHECK(!connected());
  if (!connect_attempted_) {
    client_->Initialize();
  }
  client_->Connect();
  connect_attempted_ = true;
}

void QuicTestClient::ResetConnection() {
  Disconnect();
  Connect();
}

void QuicTestClient::Disconnect() {
  client_->Disconnect();
  connect_attempted_ = false;
}

IPEndPoint QuicTestClient::local_address() const {
  return client_->GetLatestClientAddress();
}

void QuicTestClient::ClearPerRequestState() {
  stream_error_ = QUIC_STREAM_NO_ERROR;
  stream_ = nullptr;
  response_ = "";
  response_complete_ = false;
  response_headers_complete_ = false;
  response_headers_.Clear();
  bytes_read_ = 0;
  bytes_written_ = 0;
  response_header_size_ = 0;
  response_body_size_ = 0;
}

bool QuicTestClient::HaveActiveStream() {
  return push_promise_data_to_resend_.get() ||
         (stream_ != nullptr &&
          !client_->session()->IsClosedStream(stream_->id()));
}

void QuicTestClient::WaitForResponseForMs(int timeout_ms) {
  int64_t timeout_us = timeout_ms * base::Time::kMicrosecondsPerMillisecond;
  int64_t old_timeout_us = epoll_server()->timeout_in_us();
  if (timeout_us > 0) {
    epoll_server()->set_timeout_in_us(timeout_us);
  }
  const QuicClock* clock =
      QuicConnectionPeer::GetHelper(client()->session()->connection())
          ->GetClock();
  QuicTime end_waiting_time =
      clock->Now().Add(QuicTime::Delta::FromMicroseconds(timeout_us));
  while (HaveActiveStream() &&
         (timeout_us < 0 || clock->Now() < end_waiting_time)) {
    client_->WaitForEvents();
  }
  if (timeout_us > 0) {
    epoll_server()->set_timeout_in_us(old_timeout_us);
  }
}

void QuicTestClient::WaitForInitialResponseForMs(int timeout_ms) {
  int64_t timeout_us = timeout_ms * base::Time::kMicrosecondsPerMillisecond;
  int64_t old_timeout_us = epoll_server()->timeout_in_us();
  if (timeout_us > 0) {
    epoll_server()->set_timeout_in_us(timeout_us);
  }
  const QuicClock* clock =
      QuicConnectionPeer::GetHelper(client()->session()->connection())
          ->GetClock();
  QuicTime end_waiting_time =
      clock->Now().Add(QuicTime::Delta::FromMicroseconds(timeout_us));
  while (stream_ != nullptr &&
         !client_->session()->IsClosedStream(stream_->id()) &&
         stream_->stream_bytes_read() == 0 &&
         (timeout_us < 0 || clock->Now() < end_waiting_time)) {
    client_->WaitForEvents();
  }
  if (timeout_us > 0) {
    epoll_server()->set_timeout_in_us(old_timeout_us);
  }
}

ssize_t QuicTestClient::Send(const void* buffer, size_t size) {
  return SendData(string(static_cast<const char*>(buffer), size), false);
}

bool QuicTestClient::response_headers_complete() const {
  if (stream_ != nullptr) {
    return stream_->headers_decompressed();
  }
  return response_headers_complete_;
}

const BalsaHeaders* QuicTestClient::response_headers() const {
  if (stream_ != nullptr) {
    SpdyBalsaUtils::SpdyHeadersToResponseHeaders(stream_->response_headers(),
                                                 &response_headers_);
    return &response_headers_;
  } else {
    return &response_headers_;
  }
}

const SpdyHeaderBlock& QuicTestClient::response_trailers() const {
  return response_trailers_;
}

int64_t QuicTestClient::response_size() const {
  return bytes_read_;
}

size_t QuicTestClient::bytes_read() const {
  return bytes_read_;
}

size_t QuicTestClient::bytes_written() const {
  return bytes_written_;
}

void QuicTestClient::OnClose(QuicSpdyStream* stream) {
  if (stream != nullptr) {
    // Always close the stream, regardless of whether it was the last stream
    // written.
    client()->OnClose(stream);
    ++num_responses_;
  }
  if (stream_ != stream) {
    return;
  }
  if (buffer_body()) {
    // TODO(fnk): The stream still buffers the whole thing. Fix that.
    response_ = stream_->data();
  }
  response_complete_ = true;
  response_headers_complete_ = stream_->headers_decompressed();
  SpdyBalsaUtils::SpdyHeadersToResponseHeaders(stream_->response_headers(),
                                               &response_headers_);
  response_trailers_ = stream_->received_trailers().Clone();
  stream_error_ = stream_->stream_error();
  bytes_read_ = stream_->stream_bytes_read() + stream_->header_bytes_read();
  bytes_written_ =
      stream_->stream_bytes_written() + stream_->header_bytes_written();
  response_header_size_ = response_headers_.GetSizeForWriteBuffer();
  response_body_size_ = stream_->data().size();
  stream_ = nullptr;
}

bool QuicTestClient::CheckVary(const SpdyHeaderBlock& client_request,
                               const SpdyHeaderBlock& promise_request,
                               const SpdyHeaderBlock& promise_response) {
  return true;
}

void QuicTestClient::OnRendezvousResult(QuicSpdyStream* stream) {
  std::unique_ptr<TestClientDataToResend> data_to_resend =
      std::move(push_promise_data_to_resend_);
  stream_ = static_cast<QuicSpdyClientStream*>(stream);
  if (stream) {
    stream->set_visitor(this);
    stream->OnDataAvailable();
  } else if (data_to_resend.get()) {
    data_to_resend->Resend();
  }
}

void QuicTestClient::UseWriter(QuicPacketWriterWrapper* writer) {
  client_->UseWriter(writer);
}

void QuicTestClient::UseConnectionId(QuicConnectionId connection_id) {
  DCHECK(!connected());
  client_->UseConnectionId(connection_id);
}

ssize_t QuicTestClient::SendAndWaitForResponse(const void* buffer,
                                               size_t size) {
  LOG(DFATAL) << "Not implemented";
  return 0;
}

void QuicTestClient::Bind(IPEndPoint* local_address) {
  DLOG(WARNING) << "Bind will be done during connect";
}

void QuicTestClient::MigrateSocket(const IPAddress& new_host) {
  client_->MigrateSocket(new_host);
}

string QuicTestClient::SerializeMessage(const HTTPMessage& message) {
  LOG(DFATAL) << "Not implemented";
  return "";
}

IPAddress QuicTestClient::bind_to_address() const {
  return client_->bind_to_address();
}

void QuicTestClient::set_bind_to_address(const IPAddress& address) {
  client_->set_bind_to_address(address);
}

const IPEndPoint& QuicTestClient::address() const {
  return client_->server_address();
}

size_t QuicTestClient::requests_sent() const {
  LOG(DFATAL) << "Not implemented";
  return 0;
}

void QuicTestClient::WaitForWriteToFlush() {
  while (connected() && client()->session()->HasDataToWrite()) {
    client_->WaitForEvents();
  }
}

void QuicTestClient::TestClientDataToResend::Resend() {
  test_client_->GetOrCreateStreamAndSendRequest(headers_, body_, fin_,
                                                delegate_);
  if (headers_ != nullptr) {
    delete headers_;
    headers_ = nullptr;
  }
}

// static
void QuicTestClient::FillInRequest(const string& uri, HTTPMessage* message) {
  CHECK(message);
  message->headers()->SetRequestVersion(
      HTTPMessage::VersionToString(HttpConstants::HTTP_1_1));
  message->headers()->SetRequestMethod(
      HTTPMessage::MethodToString(HttpConstants::GET));
  message->headers()->SetRequestUri(uri);
}

}  // namespace test
}  // namespace net
