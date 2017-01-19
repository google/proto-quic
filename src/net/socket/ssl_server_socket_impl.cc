// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/ssl_server_socket_impl.h"

#include <utility>

#include "base/callback_helpers.h"
#include "base/logging.h"
#include "base/strings/string_util.h"
#include "crypto/openssl_util.h"
#include "crypto/rsa_private_key.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/client_cert_verifier.h"
#include "net/cert/x509_util_openssl.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/socket_bio_adapter.h"
#include "net/ssl/openssl_ssl_util.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_info.h"
#include "third_party/boringssl/src/include/openssl/err.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"
#include "third_party/boringssl/src/include/openssl/x509.h"

#define GotoState(s) next_handshake_state_ = s

namespace net {

namespace {

// Creates an X509Certificate out of the concatenation of |cert|, if non-null,
// with |chain|.
scoped_refptr<X509Certificate> CreateX509Certificate(X509* cert,
                                                     STACK_OF(X509) * chain) {
  std::vector<base::StringPiece> der_chain;
  base::StringPiece der_cert;
  scoped_refptr<X509Certificate> client_cert;
  if (cert) {
    if (!x509_util::GetDER(cert, &der_cert))
      return nullptr;
    der_chain.push_back(der_cert);
  }

  for (size_t i = 0; i < sk_X509_num(chain); ++i) {
    X509* x = sk_X509_value(chain, i);
    if (!x509_util::GetDER(x, &der_cert))
      return nullptr;
    der_chain.push_back(der_cert);
  }

  return X509Certificate::CreateFromDERCertChain(der_chain);
}

class SSLServerSocketImpl : public SSLServerSocket,
                            public SocketBIOAdapter::Delegate {
 public:
  // See comments on CreateSSLServerSocket for details of how these
  // parameters are used.
  SSLServerSocketImpl(std::unique_ptr<StreamSocket> socket,
                      bssl::UniquePtr<SSL> ssl);
  ~SSLServerSocketImpl() override;

  // SSLServerSocket interface.
  int Handshake(const CompletionCallback& callback) override;

  // SSLSocket interface.
  int ExportKeyingMaterial(const base::StringPiece& label,
                           bool has_context,
                           const base::StringPiece& context,
                           unsigned char* out,
                           unsigned int outlen) override;

  // Socket interface (via StreamSocket).
  int Read(IOBuffer* buf,
           int buf_len,
           const CompletionCallback& callback) override;
  int Write(IOBuffer* buf,
            int buf_len,
            const CompletionCallback& callback) override;
  int SetReceiveBufferSize(int32_t size) override;
  int SetSendBufferSize(int32_t size) override;

  // StreamSocket implementation.
  int Connect(const CompletionCallback& callback) override;
  void Disconnect() override;
  bool IsConnected() const override;
  bool IsConnectedAndIdle() const override;
  int GetPeerAddress(IPEndPoint* address) const override;
  int GetLocalAddress(IPEndPoint* address) const override;
  const NetLogWithSource& NetLog() const override;
  void SetSubresourceSpeculation() override;
  void SetOmniboxSpeculation() override;
  bool WasEverUsed() const override;
  bool WasAlpnNegotiated() const override;
  NextProto GetNegotiatedProtocol() const override;
  bool GetSSLInfo(SSLInfo* ssl_info) override;
  void GetConnectionAttempts(ConnectionAttempts* out) const override;
  void ClearConnectionAttempts() override {}
  void AddConnectionAttempts(const ConnectionAttempts& attempts) override {}
  int64_t GetTotalReceivedBytes() const override;
  static int CertVerifyCallback(X509_STORE_CTX* store_ctx, void* arg);

  // SocketBIOAdapter::Delegate implementation.
  void OnReadReady() override;
  void OnWriteReady() override;

 private:
  enum State {
    STATE_NONE,
    STATE_HANDSHAKE,
  };

  void OnHandshakeIOComplete(int result);

  int DoPayloadRead();
  int DoPayloadWrite();

  int DoHandshakeLoop(int last_io_result);
  int DoHandshake();
  void DoHandshakeCallback(int result);
  void DoReadCallback(int result);
  void DoWriteCallback(int result);

  int Init();
  void ExtractClientCert();

  NetLogWithSource net_log_;

  CompletionCallback user_handshake_callback_;
  CompletionCallback user_read_callback_;
  CompletionCallback user_write_callback_;

  // Used by Read function.
  scoped_refptr<IOBuffer> user_read_buf_;
  int user_read_buf_len_;

  // Used by Write function.
  scoped_refptr<IOBuffer> user_write_buf_;
  int user_write_buf_len_;

  // OpenSSL stuff
  bssl::UniquePtr<SSL> ssl_;

  // StreamSocket for sending and receiving data.
  std::unique_ptr<StreamSocket> transport_socket_;
  std::unique_ptr<SocketBIOAdapter> transport_adapter_;

  // Certificate for the client.
  scoped_refptr<X509Certificate> client_cert_;

  State next_handshake_state_;
  bool completed_handshake_;

  DISALLOW_COPY_AND_ASSIGN(SSLServerSocketImpl);
};

SSLServerSocketImpl::SSLServerSocketImpl(
    std::unique_ptr<StreamSocket> transport_socket,
    bssl::UniquePtr<SSL> ssl)
    : user_read_buf_len_(0),
      user_write_buf_len_(0),
      ssl_(std::move(ssl)),
      transport_socket_(std::move(transport_socket)),
      next_handshake_state_(STATE_NONE),
      completed_handshake_(false) {}

SSLServerSocketImpl::~SSLServerSocketImpl() {
  if (ssl_) {
    // Calling SSL_shutdown prevents the session from being marked as
    // unresumable.
    SSL_shutdown(ssl_.get());
    ssl_.reset();
  }
}

int SSLServerSocketImpl::Handshake(const CompletionCallback& callback) {
  net_log_.BeginEvent(NetLogEventType::SSL_SERVER_HANDSHAKE);

  // Set up new ssl object.
  int rv = Init();
  if (rv != OK) {
    LOG(ERROR) << "Failed to initialize OpenSSL: rv=" << rv;
    net_log_.EndEventWithNetErrorCode(NetLogEventType::SSL_SERVER_HANDSHAKE,
                                      rv);
    return rv;
  }

  // Set SSL to server mode. Handshake happens in the loop below.
  SSL_set_accept_state(ssl_.get());

  GotoState(STATE_HANDSHAKE);
  rv = DoHandshakeLoop(OK);
  if (rv == ERR_IO_PENDING) {
    user_handshake_callback_ = callback;
  } else {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::SSL_SERVER_HANDSHAKE,
                                      rv);
  }

  return rv > OK ? OK : rv;
}

int SSLServerSocketImpl::ExportKeyingMaterial(const base::StringPiece& label,
                                              bool has_context,
                                              const base::StringPiece& context,
                                              unsigned char* out,
                                              unsigned int outlen) {
  if (!IsConnected())
    return ERR_SOCKET_NOT_CONNECTED;

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  int rv = SSL_export_keying_material(
      ssl_.get(), out, outlen, label.data(), label.size(),
      reinterpret_cast<const unsigned char*>(context.data()), context.length(),
      context.length() > 0);

  if (rv != 1) {
    int ssl_error = SSL_get_error(ssl_.get(), rv);
    LOG(ERROR) << "Failed to export keying material;"
               << " returned " << rv << ", SSL error code " << ssl_error;
    return MapOpenSSLError(ssl_error, err_tracer);
  }
  return OK;
}

int SSLServerSocketImpl::Read(IOBuffer* buf,
                              int buf_len,
                              const CompletionCallback& callback) {
  DCHECK(user_read_callback_.is_null());
  DCHECK(user_handshake_callback_.is_null());
  DCHECK(!user_read_buf_);
  DCHECK(!callback.is_null());

  user_read_buf_ = buf;
  user_read_buf_len_ = buf_len;

  DCHECK(completed_handshake_);

  int rv = DoPayloadRead();

  if (rv == ERR_IO_PENDING) {
    user_read_callback_ = callback;
  } else {
    user_read_buf_ = NULL;
    user_read_buf_len_ = 0;
  }

  return rv;
}

int SSLServerSocketImpl::Write(IOBuffer* buf,
                               int buf_len,
                               const CompletionCallback& callback) {
  DCHECK(user_write_callback_.is_null());
  DCHECK(!user_write_buf_);
  DCHECK(!callback.is_null());

  user_write_buf_ = buf;
  user_write_buf_len_ = buf_len;

  int rv = DoPayloadWrite();

  if (rv == ERR_IO_PENDING) {
    user_write_callback_ = callback;
  } else {
    user_write_buf_ = NULL;
    user_write_buf_len_ = 0;
  }
  return rv;
}

int SSLServerSocketImpl::SetReceiveBufferSize(int32_t size) {
  return transport_socket_->SetReceiveBufferSize(size);
}

int SSLServerSocketImpl::SetSendBufferSize(int32_t size) {
  return transport_socket_->SetSendBufferSize(size);
}

int SSLServerSocketImpl::Connect(const CompletionCallback& callback) {
  NOTIMPLEMENTED();
  return ERR_NOT_IMPLEMENTED;
}

void SSLServerSocketImpl::Disconnect() {
  transport_socket_->Disconnect();
}

bool SSLServerSocketImpl::IsConnected() const {
  // TODO(wtc): Find out if we should check transport_socket_->IsConnected()
  // as well.
  return completed_handshake_;
}

bool SSLServerSocketImpl::IsConnectedAndIdle() const {
  return completed_handshake_ && transport_socket_->IsConnectedAndIdle();
}

int SSLServerSocketImpl::GetPeerAddress(IPEndPoint* address) const {
  if (!IsConnected())
    return ERR_SOCKET_NOT_CONNECTED;
  return transport_socket_->GetPeerAddress(address);
}

int SSLServerSocketImpl::GetLocalAddress(IPEndPoint* address) const {
  if (!IsConnected())
    return ERR_SOCKET_NOT_CONNECTED;
  return transport_socket_->GetLocalAddress(address);
}

const NetLogWithSource& SSLServerSocketImpl::NetLog() const {
  return net_log_;
}

void SSLServerSocketImpl::SetSubresourceSpeculation() {
  transport_socket_->SetSubresourceSpeculation();
}

void SSLServerSocketImpl::SetOmniboxSpeculation() {
  transport_socket_->SetOmniboxSpeculation();
}

bool SSLServerSocketImpl::WasEverUsed() const {
  return transport_socket_->WasEverUsed();
}

bool SSLServerSocketImpl::WasAlpnNegotiated() const {
  NOTIMPLEMENTED();
  return false;
}

NextProto SSLServerSocketImpl::GetNegotiatedProtocol() const {
  // ALPN is not supported by this class.
  return kProtoUnknown;
}

bool SSLServerSocketImpl::GetSSLInfo(SSLInfo* ssl_info) {
  ssl_info->Reset();
  if (!completed_handshake_)
    return false;

  ssl_info->cert = client_cert_;

  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_.get());
  CHECK(cipher);
  ssl_info->security_bits = SSL_CIPHER_get_bits(cipher, NULL);

  SSLConnectionStatusSetCipherSuite(
      static_cast<uint16_t>(SSL_CIPHER_get_id(cipher)),
      &ssl_info->connection_status);
  SSLConnectionStatusSetVersion(GetNetSSLVersion(ssl_.get()),
                                &ssl_info->connection_status);

  ssl_info->handshake_type = SSL_session_reused(ssl_.get())
                                 ? SSLInfo::HANDSHAKE_RESUME
                                 : SSLInfo::HANDSHAKE_FULL;

  return true;
}

void SSLServerSocketImpl::GetConnectionAttempts(ConnectionAttempts* out) const {
  out->clear();
}

int64_t SSLServerSocketImpl::GetTotalReceivedBytes() const {
  return transport_socket_->GetTotalReceivedBytes();
}

void SSLServerSocketImpl::OnReadReady() {
  if (next_handshake_state_ == STATE_HANDSHAKE) {
    // In handshake phase. The parameter to OnHandshakeIOComplete is unused.
    OnHandshakeIOComplete(OK);
    return;
  }

  // BoringSSL does not support renegotiation as a server, so the only other
  // operation blocked on Read is DoPayloadRead.
  if (!user_read_buf_)
    return;

  int rv = DoPayloadRead();
  if (rv != ERR_IO_PENDING)
    DoReadCallback(rv);
}

void SSLServerSocketImpl::OnWriteReady() {
  if (next_handshake_state_ == STATE_HANDSHAKE) {
    // In handshake phase. The parameter to OnHandshakeIOComplete is unused.
    OnHandshakeIOComplete(OK);
    return;
  }

  // BoringSSL does not support renegotiation as a server, so the only other
  // operation blocked on Read is DoPayloadWrite.
  if (!user_write_buf_)
    return;

  int rv = DoPayloadWrite();
  if (rv != ERR_IO_PENDING)
    DoWriteCallback(rv);
}

void SSLServerSocketImpl::OnHandshakeIOComplete(int result) {
  int rv = DoHandshakeLoop(result);
  if (rv == ERR_IO_PENDING)
    return;

  net_log_.EndEventWithNetErrorCode(NetLogEventType::SSL_SERVER_HANDSHAKE, rv);
  if (!user_handshake_callback_.is_null())
    DoHandshakeCallback(rv);
}


int SSLServerSocketImpl::DoPayloadRead() {
  DCHECK(completed_handshake_);
  DCHECK_EQ(STATE_NONE, next_handshake_state_);
  DCHECK(user_read_buf_);
  DCHECK_GT(user_read_buf_len_, 0);

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  int rv = SSL_read(ssl_.get(), user_read_buf_->data(), user_read_buf_len_);
  if (rv >= 0)
    return rv;
  int ssl_error = SSL_get_error(ssl_.get(), rv);
  OpenSSLErrorInfo error_info;
  int net_error =
      MapOpenSSLErrorWithDetails(ssl_error, err_tracer, &error_info);
  if (net_error != ERR_IO_PENDING) {
    net_log_.AddEvent(
        NetLogEventType::SSL_READ_ERROR,
        CreateNetLogOpenSSLErrorCallback(net_error, ssl_error, error_info));
  }
  return net_error;
}

int SSLServerSocketImpl::DoPayloadWrite() {
  DCHECK(completed_handshake_);
  DCHECK_EQ(STATE_NONE, next_handshake_state_);
  DCHECK(user_write_buf_);

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  int rv = SSL_write(ssl_.get(), user_write_buf_->data(), user_write_buf_len_);
  if (rv >= 0)
    return rv;
  int ssl_error = SSL_get_error(ssl_.get(), rv);
  OpenSSLErrorInfo error_info;
  int net_error =
      MapOpenSSLErrorWithDetails(ssl_error, err_tracer, &error_info);
  if (net_error != ERR_IO_PENDING) {
    net_log_.AddEvent(
        NetLogEventType::SSL_WRITE_ERROR,
        CreateNetLogOpenSSLErrorCallback(net_error, ssl_error, error_info));
  }
  return net_error;
}

int SSLServerSocketImpl::DoHandshakeLoop(int last_io_result) {
  int rv = last_io_result;
  do {
    // Default to STATE_NONE for next state.
    // (This is a quirk carried over from the windows
    // implementation.  It makes reading the logs a bit harder.)
    // State handlers can and often do call GotoState just
    // to stay in the current state.
    State state = next_handshake_state_;
    GotoState(STATE_NONE);
    switch (state) {
      case STATE_HANDSHAKE:
        rv = DoHandshake();
        break;
      case STATE_NONE:
      default:
        rv = ERR_UNEXPECTED;
        LOG(DFATAL) << "unexpected state " << state;
        break;
    }
  } while (rv != ERR_IO_PENDING && next_handshake_state_ != STATE_NONE);
  return rv;
}

int SSLServerSocketImpl::DoHandshake() {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  int net_error = OK;
  int rv = SSL_do_handshake(ssl_.get());

  if (rv == 1) {
    completed_handshake_ = true;
    // The results of SSL_get_peer_certificate() must be explicitly freed.
    bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl_.get()));
    if (cert) {
      // The caller does not take ownership of SSL_get_peer_cert_chain's
      // results.
      STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl_.get());
      client_cert_ = CreateX509Certificate(cert.get(), chain);
      if (!client_cert_.get())
        return ERR_SSL_CLIENT_AUTH_CERT_BAD_FORMAT;
    }
  } else {
    int ssl_error = SSL_get_error(ssl_.get(), rv);
    OpenSSLErrorInfo error_info;
    net_error = MapOpenSSLErrorWithDetails(ssl_error, err_tracer, &error_info);

    // This hack is necessary because the mapping of SSL error codes to
    // net_errors assumes (correctly for client sockets, but erroneously for
    // server sockets) that peer cert verification failure can only occur if
    // the cert changed during a renego. crbug.com/570351
    if (net_error == ERR_SSL_SERVER_CERT_CHANGED)
      net_error = ERR_BAD_SSL_CLIENT_AUTH_CERT;

    // If not done, stay in this state
    if (net_error == ERR_IO_PENDING) {
      GotoState(STATE_HANDSHAKE);
    } else {
      LOG(ERROR) << "handshake failed; returned " << rv << ", SSL error code "
                 << ssl_error << ", net_error " << net_error;
      net_log_.AddEvent(
          NetLogEventType::SSL_HANDSHAKE_ERROR,
          CreateNetLogOpenSSLErrorCallback(net_error, ssl_error, error_info));
    }
  }
  return net_error;
}

void SSLServerSocketImpl::DoHandshakeCallback(int rv) {
  DCHECK_NE(rv, ERR_IO_PENDING);
  base::ResetAndReturn(&user_handshake_callback_).Run(rv > OK ? OK : rv);
}

void SSLServerSocketImpl::DoReadCallback(int rv) {
  DCHECK(rv != ERR_IO_PENDING);
  DCHECK(!user_read_callback_.is_null());

  user_read_buf_ = NULL;
  user_read_buf_len_ = 0;
  base::ResetAndReturn(&user_read_callback_).Run(rv);
}

void SSLServerSocketImpl::DoWriteCallback(int rv) {
  DCHECK(rv != ERR_IO_PENDING);
  DCHECK(!user_write_callback_.is_null());

  user_write_buf_ = NULL;
  user_write_buf_len_ = 0;
  base::ResetAndReturn(&user_write_callback_).Run(rv);
}

int SSLServerSocketImpl::Init() {
  static const int kBufferSize = 17 * 1024;

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  if (!ssl_)
    return ERR_UNEXPECTED;

  transport_adapter_.reset(new SocketBIOAdapter(
      transport_socket_.get(), kBufferSize, kBufferSize, this));
  BIO* transport_bio = transport_adapter_->bio();

  BIO_up_ref(transport_bio);  // SSL_set0_rbio takes ownership.
  SSL_set0_rbio(ssl_.get(), transport_bio);

  BIO_up_ref(transport_bio);  // SSL_set0_wbio takes ownership.
  SSL_set0_wbio(ssl_.get(), transport_bio);

  return OK;
}

// static
int SSLServerSocketImpl::CertVerifyCallback(X509_STORE_CTX* store_ctx,
                                            void* arg) {
  ClientCertVerifier* verifier = reinterpret_cast<ClientCertVerifier*>(arg);
  // If a verifier was not supplied, all certificates are accepted.
  if (!verifier)
    return 1;
  STACK_OF(X509)* chain = store_ctx->untrusted;
  scoped_refptr<X509Certificate> client_cert(
      CreateX509Certificate(nullptr, chain));
  if (!client_cert.get()) {
    X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_CERT_REJECTED);
    return 0;
  }
  // Asynchronous completion of Verify is currently not supported.
  // http://crbug.com/347402
  // The API for Verify supports the parts needed for async completion
  // but is currently expected to complete synchronously.
  std::unique_ptr<ClientCertVerifier::Request> ignore_async;
  int res =
      verifier->Verify(client_cert.get(), CompletionCallback(), &ignore_async);
  DCHECK_NE(res, ERR_IO_PENDING);

  if (res != OK) {
    X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_CERT_REJECTED);
    return 0;
  }
  return 1;
}

}  // namespace

std::unique_ptr<SSLServerContext> CreateSSLServerContext(
    X509Certificate* certificate,
    const crypto::RSAPrivateKey& key,
    const SSLServerConfig& ssl_server_config) {
  return std::unique_ptr<SSLServerContext>(
      new SSLServerContextImpl(certificate, key, ssl_server_config));
}

SSLServerContextImpl::SSLServerContextImpl(
    X509Certificate* certificate,
    const crypto::RSAPrivateKey& key,
    const SSLServerConfig& ssl_server_config)
    : ssl_server_config_(ssl_server_config),
      cert_(certificate),
      key_(key.Copy()) {
  CHECK(key_);
  crypto::EnsureOpenSSLInit();
  ssl_ctx_.reset(SSL_CTX_new(TLS_method()));
  SSL_CTX_set_session_cache_mode(ssl_ctx_.get(), SSL_SESS_CACHE_SERVER);
  uint8_t session_ctx_id = 0;
  SSL_CTX_set_session_id_context(ssl_ctx_.get(), &session_ctx_id,
                                 sizeof(session_ctx_id));

  int verify_mode = 0;
  switch (ssl_server_config_.client_cert_type) {
    case SSLServerConfig::ClientCertType::REQUIRE_CLIENT_CERT:
      verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    // Fall-through
    case SSLServerConfig::ClientCertType::OPTIONAL_CLIENT_CERT:
      verify_mode |= SSL_VERIFY_PEER;
      SSL_CTX_set_verify(ssl_ctx_.get(), verify_mode, nullptr);
      SSL_CTX_set_cert_verify_callback(ssl_ctx_.get(),
                                       SSLServerSocketImpl::CertVerifyCallback,
                                       ssl_server_config_.client_cert_verifier);
      break;
    case SSLServerConfig::ClientCertType::NO_CLIENT_CERT:
      break;
  }

  // Set certificate and private key.
  DCHECK(cert_->os_cert_handle());
#if defined(USE_OPENSSL_CERTS)
  CHECK(SSL_CTX_use_certificate(ssl_ctx_.get(), cert_->os_cert_handle()));
#else
  // Convert OSCertHandle to X509 structure.
  std::string der_string;
  CHECK(X509Certificate::GetDEREncoded(cert_->os_cert_handle(), &der_string));

  const unsigned char* der_string_array =
      reinterpret_cast<const unsigned char*>(der_string.data());

  bssl::UniquePtr<X509> x509(
      d2i_X509(NULL, &der_string_array, der_string.length()));
  CHECK(x509);

  // On success, SSL_CTX_use_certificate acquires a reference to |x509|.
  CHECK(SSL_CTX_use_certificate(ssl_ctx_.get(), x509.get()));
#endif  // USE_OPENSSL_CERTS

  DCHECK(key_->key());
  CHECK(SSL_CTX_use_PrivateKey(ssl_ctx_.get(), key_->key()));

  DCHECK_LT(SSL3_VERSION, ssl_server_config_.version_min);
  DCHECK_LT(SSL3_VERSION, ssl_server_config_.version_max);
  CHECK(SSL_CTX_set_min_proto_version(ssl_ctx_.get(),
                                      ssl_server_config_.version_min));
  CHECK(SSL_CTX_set_max_proto_version(ssl_ctx_.get(),
                                      ssl_server_config_.version_max));

  // OpenSSL defaults some options to on, others to off. To avoid ambiguity,
  // set everything we care about to an absolute value.
  SslSetClearMask options;
  options.ConfigureFlag(SSL_OP_NO_COMPRESSION, true);

  SSL_CTX_set_options(ssl_ctx_.get(), options.set_mask);
  SSL_CTX_clear_options(ssl_ctx_.get(), options.clear_mask);

  // Same as above, this time for the SSL mode.
  SslSetClearMask mode;

  mode.ConfigureFlag(SSL_MODE_RELEASE_BUFFERS, true);

  SSL_CTX_set_mode(ssl_ctx_.get(), mode.set_mask);
  SSL_CTX_clear_mode(ssl_ctx_.get(), mode.clear_mask);

  // See SSLServerConfig::disabled_cipher_suites for description of the suites
  // disabled by default. Note that !SHA256 and !SHA384 only remove HMAC-SHA256
  // and HMAC-SHA384 cipher suites, not GCM cipher suites with SHA256 or SHA384
  // as the handshake hash.
  std::string command("DEFAULT:!SHA256:!SHA384:!AESGCM+AES256:!aPSK");

  if (ssl_server_config_.require_ecdhe)
    command.append(":!kRSA:!kDHE");

  // Remove any disabled ciphers.
  for (uint16_t id : ssl_server_config_.disabled_cipher_suites) {
    const SSL_CIPHER* cipher = SSL_get_cipher_by_value(id);
    if (cipher) {
      command.append(":!");
      command.append(SSL_CIPHER_get_name(cipher));
    }
  }

  int rv = SSL_CTX_set_cipher_list(ssl_ctx_.get(), command.c_str());
  // If this fails (rv = 0) it means there are no ciphers enabled on this SSL.
  // This will almost certainly result in the socket failing to complete the
  // handshake at which point the appropriate error is bubbled up to the client.
  LOG_IF(WARNING, rv != 1) << "SSL_set_cipher_list('" << command
                           << "') returned " << rv;

  if (ssl_server_config_.client_cert_type !=
          SSLServerConfig::ClientCertType::NO_CLIENT_CERT &&
      !ssl_server_config_.cert_authorities_.empty()) {
    bssl::UniquePtr<STACK_OF(X509_NAME)> stack(sk_X509_NAME_new_null());
    for (const auto& authority : ssl_server_config_.cert_authorities_) {
      const uint8_t* name = reinterpret_cast<const uint8_t*>(authority.c_str());
      const uint8_t* name_start = name;
      bssl::UniquePtr<X509_NAME> subj(
          d2i_X509_NAME(nullptr, &name, authority.length()));
      CHECK(subj && name == name_start + authority.length());
      sk_X509_NAME_push(stack.get(), subj.release());
    }
    SSL_CTX_set_client_CA_list(ssl_ctx_.get(), stack.release());
  }
}

SSLServerContextImpl::~SSLServerContextImpl() {}

std::unique_ptr<SSLServerSocket> SSLServerContextImpl::CreateSSLServerSocket(
    std::unique_ptr<StreamSocket> socket) {
  bssl::UniquePtr<SSL> ssl(SSL_new(ssl_ctx_.get()));
  return std::unique_ptr<SSLServerSocket>(
      new SSLServerSocketImpl(std::move(socket), std::move(ssl)));
}

}  // namespace net
