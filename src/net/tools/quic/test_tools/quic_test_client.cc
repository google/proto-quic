// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/test_tools/quic_test_client.h"

#include <memory>
#include <utility>
#include <vector>

#include "base/memory/ptr_util.h"
#include "base/time/time.h"
#include "net/base/completion_callback.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/x509_certificate.h"
#include "net/quic/core/crypto/proof_verifier.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_server_id.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/test_tools/crypto_test_utils.h"
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
using testing::_;
using testing::Invoke;

namespace net {
namespace test {
namespace {

// RecordingProofVerifier accepts any certificate chain and records the common
// name of the leaf and then delegates the actual verfication to an actual
// verifier. If no optional verifier is provided, then VerifyProof will return
// success.
class RecordingProofVerifier : public ProofVerifier {
 public:
  explicit RecordingProofVerifier(std::unique_ptr<ProofVerifier> verifier)
      : verifier_(std::move(verifier)) {}

  // ProofVerifier interface.
  QuicAsyncStatus VerifyProof(
      const string& hostname,
      const uint16_t port,
      const string& server_config,
      QuicVersion quic_version,
      StringPiece chlo_hash,
      const std::vector<string>& certs,
      const string& cert_sct,
      const string& signature,
      const ProofVerifyContext* context,
      string* error_details,
      std::unique_ptr<ProofVerifyDetails>* details,
      std::unique_ptr<ProofVerifierCallback> callback) override {
    common_name_.clear();
    if (certs.empty()) {
      return QUIC_FAILURE;
    }

    // Convert certs to X509Certificate.
    std::vector<StringPiece> cert_pieces(certs.size());
    for (unsigned i = 0; i < certs.size(); i++) {
      cert_pieces[i] = StringPiece(certs[i]);
    }
    // TODO(rtenneti): Fix after adding support for real certs. Currently,
    // cert_pieces are "leaf" and "intermediate" and CreateFromDERCertChain
    // fails to return cert from these cert_pieces.
    //    bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &data, certs[0].size()));
    //    if (!cert.get()) {
    //      return QUIC_FAILURE;
    //    }
    //
    //    common_name_ = cert->subject().GetDisplayName();
    cert_sct_ = cert_sct;

    if (!verifier_) {
      return QUIC_SUCCESS;
    }

    return verifier_->VerifyProof(
        hostname, port, server_config, quic_version, chlo_hash, certs, cert_sct,
        signature, context, error_details, details, std::move(callback));
  }

  QuicAsyncStatus VerifyCertChain(
      const std::string& hostname,
      const std::vector<std::string>& certs,
      const ProofVerifyContext* verify_context,
      std::string* error_details,
      std::unique_ptr<ProofVerifyDetails>* verify_details,
      std::unique_ptr<ProofVerifierCallback> callback) override {
    return QUIC_SUCCESS;
  }

  const string& common_name() const { return common_name_; }

  const string& cert_sct() const { return cert_sct_; }

 private:
  std::unique_ptr<ProofVerifier> verifier_;
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
  if (!base::StartsWith(uri, "https://",
                        base::CompareCase::INSENSITIVE_ASCII) &&
      !base::StartsWith(uri, "http://", base::CompareCase::INSENSITIVE_ASCII)) {
    // If we have a relative URL, set some defaults.
    string full_uri = "https://test.example.com";
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
    : MockableQuicClient(server_address,
                         server_id,
                         config,
                         supported_versions,
                         epoll_server,
                         nullptr) {}

MockableQuicClient::MockableQuicClient(
    IPEndPoint server_address,
    const QuicServerId& server_id,
    const QuicConfig& config,
    const QuicVersionVector& supported_versions,
    EpollServer* epoll_server,
    std::unique_ptr<ProofVerifier> proof_verifier)
    : QuicClient(server_address,
                 server_id,
                 supported_versions,
                 config,
                 epoll_server,
                 base::WrapUnique(
                     new RecordingProofVerifier(std::move(proof_verifier)))),
      override_connection_id_(0),
      test_writer_(nullptr),
      track_last_incoming_packet_(false) {}

void MockableQuicClient::ProcessPacket(const IPEndPoint& self_address,
                                       const IPEndPoint& peer_address,
                                       const QuicReceivedPacket& packet) {
  QuicClient::ProcessPacket(self_address, peer_address, packet);
  if (track_last_incoming_packet_)
    last_incoming_packet_ = packet.Clone();
}

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
      response_complete_(false),
      allow_bidirectional_data_(false) {
  Initialize();
}

QuicTestClient::QuicTestClient(IPEndPoint server_address,
                               const string& server_hostname,
                               const QuicConfig& config,
                               const QuicVersionVector& supported_versions,
                               std::unique_ptr<ProofVerifier> proof_verifier)
    : client_(new MockableQuicClient(server_address,
                                     QuicServerId(server_hostname,
                                                  server_address.port(),
                                                  PRIVACY_MODE_DISABLED),
                                     config,
                                     supported_versions,
                                     &epoll_server_,
                                     std::move(proof_verifier))),
      response_complete_(false),
      allow_bidirectional_data_(false) {
  Initialize();
}

QuicTestClient::QuicTestClient()
    : response_complete_(false), allow_bidirectional_data_(false) {}

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
    const std::vector<string>& url_list) {
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
      std::unique_ptr<SpdyHeaderBlock> new_headers(new SpdyHeaderBlock(
          SpdyBalsaUtils::RequestHeadersToSpdyHeaders(*headers)));
      push_promise_data_to_resend_.reset(new TestClientDataToResend(
          std::move(new_headers), body, fin, this, delegate));
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
    auto authority = spdy_headers.find(":authority");
    if (authority == spdy_headers.end() || authority->second.empty()) {
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
    std::unique_ptr<SpdyHeaderBlock> new_headers;
    if (headers) {
      new_headers.reset(new SpdyHeaderBlock(
          SpdyBalsaUtils::RequestHeadersToSpdyHeaders(*headers)));
    }
    std::unique_ptr<QuicClientBase::QuicDataToResend> data_to_resend(
        new TestClientDataToResend(std::move(new_headers), body, fin, this,
                                   delegate));
    client()->MaybeAddQuicDataToResend(std::move(data_to_resend));
  }
  return ret;
}

ssize_t QuicTestClient::SendMessage(const HTTPMessage& message) {
  stream_ = nullptr;  // Always force creation of a stream for SendMessage.
  // Any response we might have received for a previous request would no longer
  // be valid.  TODO(jeffpiazza): There's probably additional client state that
  // should be reset here, too, if we were being more careful.
  response_complete_ = false;

  // If we're not connected, try to find an sni hostname.
  if (!connected()) {
    GURL url(message.headers()->request_uri());
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

void QuicTestClient::SetStream(QuicSpdyClientStream* stream) {
  stream_ = stream;
  if (stream_ != nullptr) {
    response_complete_ = false;
    stream_->set_visitor(this);
  }
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
    SetStream(client_->CreateReliableClientStream());
    if (stream_) {
      stream_->SetPriority(priority_);
      stream_->set_allow_bidirectional_data(allow_bidirectional_data_);
    }
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

bool QuicTestClient::WaitUntil(int timeout_ms, std::function<bool()> trigger) {
  int64_t timeout_us = timeout_ms * base::Time::kMicrosecondsPerMillisecond;
  int64_t old_timeout_us = epoll_server()->timeout_in_us();
  if (timeout_us > 0) {
    epoll_server()->set_timeout_in_us(timeout_us);
  }
  const QuicClock* clock =
      QuicConnectionPeer::GetHelper(client()->session()->connection())
          ->GetClock();
  QuicTime end_waiting_time =
      clock->Now() + QuicTime::Delta::FromMicroseconds(timeout_us);
  while (HaveActiveStream() && !(trigger && trigger()) &&
         (timeout_us < 0 || clock->Now() < end_waiting_time)) {
    client_->WaitForEvents();
  }
  if (timeout_us > 0) {
    epoll_server()->set_timeout_in_us(old_timeout_us);
  }
  if (trigger && !trigger()) {
    VLOG(1) << "Client WaitUntil returning with trigger returning false.";
    return false;
  }
  return true;
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
  return bytes_read();
}

size_t QuicTestClient::bytes_read() const {
  // While stream_ is available, its member functions provide more accurate
  // information.  bytes_read_ is updated only when stream_ becomes null.
  if (stream_) {
    return stream_->stream_bytes_read() + stream_->header_bytes_read();
  } else {
    return bytes_read_;
  }
}

size_t QuicTestClient::bytes_written() const {
  // While stream_ is available, its member functions provide more accurate
  // information.  bytes_written_ is updated only when stream_ becomes null.
  if (stream_) {
    return stream_->stream_bytes_written() + stream_->header_bytes_written();
  } else {
    return bytes_written_;
  }
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
  SetStream(static_cast<QuicSpdyClientStream*>(stream));
  if (stream) {
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

void QuicTestClient::MigrateSocket(const IPAddress& new_host) {
  client_->MigrateSocket(new_host);
}

IPAddress QuicTestClient::bind_to_address() const {
  return client_->bind_to_address();
}

void QuicTestClient::set_bind_to_address(IPAddress address) {
  client_->set_bind_to_address(address);
}

const IPEndPoint& QuicTestClient::address() const {
  return client_->server_address();
}

void QuicTestClient::WaitForWriteToFlush() {
  while (connected() && client()->session()->HasDataToWrite()) {
    client_->WaitForEvents();
  }
}

void QuicTestClient::TestClientDataToResend::Resend() {
  BalsaHeaders balsa_headers;
  SpdyBalsaUtils::SpdyHeadersToRequestHeaders(*headers_, &balsa_headers);
  test_client_->GetOrCreateStreamAndSendRequest(&balsa_headers, body_, fin_,
                                                delegate_);
  headers_.reset();
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
