// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/ssl_client_socket_impl.h"

#include <errno.h>
#include <openssl/bio.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/ssl.h>
#include <string.h>

#include <utility>

#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/lazy_instance.h"
#include "base/macros.h"
#include "base/memory/singleton.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "base/profiler/scoped_tracker.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_local.h"
#include "base/trace_event/trace_event.h"
#include "base/values.h"
#include "crypto/auto_cbb.h"
#include "crypto/ec_private_key.h"
#include "crypto/openssl_util.h"
#include "crypto/scoped_openssl_types.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_ev_whitelist.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/ct_verifier.h"
#include "net/cert/x509_certificate_net_log_param.h"
#include "net/cert/x509_util_openssl.h"
#include "net/http/transport_security_state.h"
#include "net/ssl/scoped_openssl_types.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_cipher_suite_names.h"
#include "net/ssl/ssl_client_session_cache.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_failure_state.h"
#include "net/ssl/ssl_info.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/token_binding.h"

#if !defined(OS_NACL)
#include "net/ssl/ssl_key_logger.h"
#endif

#if defined(USE_NSS_CERTS)
#include "net/cert_net/nss_ocsp.h"
#endif

namespace net {

namespace {

// Enable this to see logging for state machine state transitions.
#if 0
#define GotoState(s)                                                          \
  do {                                                                        \
    DVLOG(2) << (void*)this << " " << __FUNCTION__ << " jump to state " << s; \
    next_handshake_state_ = s;                                                \
  } while (0)
#else
#define GotoState(s) next_handshake_state_ = s
#endif

// This constant can be any non-negative/non-zero value (eg: it does not
// overlap with any value of the net::Error range, including net::OK).
const int kNoPendingResult = 1;

// If a client doesn't have a list of protocols that it supports, but
// the server supports NPN, choosing "http/1.1" is the best answer.
const char kDefaultSupportedNPNProtocol[] = "http/1.1";

// Default size of the internal BoringSSL buffers.
const int KDefaultOpenSSLBufferSize = 17 * 1024;

// TLS extension number use for Token Binding.
const unsigned int kTbExtNum = 24;

// Token Binding ProtocolVersions supported.
const uint8_t kTbProtocolVersionMajor = 0;
const uint8_t kTbProtocolVersionMinor = 5;
const uint8_t kTbMinProtocolVersionMajor = 0;
const uint8_t kTbMinProtocolVersionMinor = 3;

bool EVP_MDToPrivateKeyHash(const EVP_MD* md, SSLPrivateKey::Hash* hash) {
  switch (EVP_MD_type(md)) {
    case NID_md5_sha1:
      *hash = SSLPrivateKey::Hash::MD5_SHA1;
      return true;
    case NID_sha1:
      *hash = SSLPrivateKey::Hash::SHA1;
      return true;
    case NID_sha256:
      *hash = SSLPrivateKey::Hash::SHA256;
      return true;
    case NID_sha384:
      *hash = SSLPrivateKey::Hash::SHA384;
      return true;
    case NID_sha512:
      *hash = SSLPrivateKey::Hash::SHA512;
      return true;
    default:
      return false;
  }
}

std::unique_ptr<base::Value> NetLogPrivateKeyOperationCallback(
    SSLPrivateKey::Type type,
    SSLPrivateKey::Hash hash,
    NetLogCaptureMode mode) {
  std::string type_str;
  switch (type) {
    case SSLPrivateKey::Type::RSA:
      type_str = "RSA";
      break;
    case SSLPrivateKey::Type::ECDSA:
      type_str = "ECDSA";
      break;
  }

  std::string hash_str;
  switch (hash) {
    case SSLPrivateKey::Hash::MD5_SHA1:
      hash_str = "MD5_SHA1";
      break;
    case SSLPrivateKey::Hash::SHA1:
      hash_str = "SHA1";
      break;
    case SSLPrivateKey::Hash::SHA256:
      hash_str = "SHA256";
      break;
    case SSLPrivateKey::Hash::SHA384:
      hash_str = "SHA384";
      break;
    case SSLPrivateKey::Hash::SHA512:
      hash_str = "SHA512";
      break;
  }

  std::unique_ptr<base::DictionaryValue> value(new base::DictionaryValue);
  value->SetString("type", type_str);
  value->SetString("hash", hash_str);
  return std::move(value);
}

std::unique_ptr<base::Value> NetLogChannelIDLookupCallback(
    ChannelIDService* channel_id_service,
    NetLogCaptureMode capture_mode) {
  ChannelIDStore* store = channel_id_service->GetChannelIDStore();
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetBoolean("ephemeral", store->IsEphemeral());
  dict->SetString("service", base::HexEncode(&channel_id_service,
                                             sizeof(channel_id_service)));
  dict->SetString("store", base::HexEncode(&store, sizeof(store)));
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogChannelIDLookupCompleteCallback(
    crypto::ECPrivateKey* key,
    int result,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("net_error", result);
  std::string raw_key;
  if (result == OK && key && key->ExportRawPublicKey(&raw_key)) {
    std::string key_to_log = "redacted";
    if (capture_mode.include_cookies_and_credentials()) {
      key_to_log = base::HexEncode(raw_key.data(), raw_key.length());
    }
    dict->SetString("key", key_to_log);
  }
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogSSLInfoCallback(
    SSLClientSocketImpl* socket,
    NetLogCaptureMode capture_mode) {
  SSLInfo ssl_info;
  if (!socket->GetSSLInfo(&ssl_info))
    return nullptr;

  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  const char* version_str;
  SSLVersionToString(&version_str,
                     SSLConnectionStatusToVersion(ssl_info.connection_status));
  dict->SetString("version", version_str);
  dict->SetBoolean("is_resumed",
                   ssl_info.handshake_type == SSLInfo::HANDSHAKE_RESUME);
  dict->SetInteger("cipher_suite", SSLConnectionStatusToCipherSuite(
                                       ssl_info.connection_status));

  std::string next_proto;
  socket->GetNextProto(&next_proto);
  dict->SetString("next_proto", next_proto);

  return std::move(dict);
}

}  // namespace

class SSLClientSocketImpl::SSLContext {
 public:
  static SSLContext* GetInstance() {
    return base::Singleton<SSLContext>::get();
  }
  SSL_CTX* ssl_ctx() { return ssl_ctx_.get(); }
  SSLClientSessionCache* session_cache() { return &session_cache_; }

  SSLClientSocketImpl* GetClientSocketFromSSL(const SSL* ssl) {
    DCHECK(ssl);
    SSLClientSocketImpl* socket = static_cast<SSLClientSocketImpl*>(
        SSL_get_ex_data(ssl, ssl_socket_data_index_));
    DCHECK(socket);
    return socket;
  }

  bool SetClientSocketForSSL(SSL* ssl, SSLClientSocketImpl* socket) {
    return SSL_set_ex_data(ssl, ssl_socket_data_index_, socket) != 0;
  }

#if !defined(OS_NACL)
  void SetSSLKeyLogFile(
      const base::FilePath& path,
      const scoped_refptr<base::SequencedTaskRunner>& task_runner) {
    DCHECK(!ssl_key_logger_);
    ssl_key_logger_.reset(new SSLKeyLogger(path, task_runner));
    SSL_CTX_set_keylog_callback(ssl_ctx_.get(), KeyLogCallback);
  }
#endif

  static const SSL_PRIVATE_KEY_METHOD kPrivateKeyMethod;

 private:
  friend struct base::DefaultSingletonTraits<SSLContext>;

  SSLContext() : session_cache_(SSLClientSessionCache::Config()) {
    crypto::EnsureOpenSSLInit();
    ssl_socket_data_index_ = SSL_get_ex_new_index(0, 0, 0, 0, 0);
    DCHECK_NE(ssl_socket_data_index_, -1);
    ssl_ctx_.reset(SSL_CTX_new(SSLv23_client_method()));
    SSL_CTX_set_cert_verify_callback(ssl_ctx_.get(), CertVerifyCallback, NULL);
    SSL_CTX_set_cert_cb(ssl_ctx_.get(), ClientCertRequestCallback, NULL);
    SSL_CTX_set_verify(ssl_ctx_.get(), SSL_VERIFY_PEER, NULL);
    // This stops |SSL_shutdown| from generating the close_notify message, which
    // is currently not sent on the network.
    // TODO(haavardm): Remove setting quiet shutdown once 118366 is fixed.
    SSL_CTX_set_quiet_shutdown(ssl_ctx_.get(), 1);
    // Note that SSL_OP_DISABLE_NPN is used to disable NPN if
    // ssl_config_.next_proto is empty.
    SSL_CTX_set_next_proto_select_cb(ssl_ctx_.get(), SelectNextProtoCallback,
                                     NULL);

    // Disable the internal session cache. Session caching is handled
    // externally (i.e. by SSLClientSessionCache).
    SSL_CTX_set_session_cache_mode(
        ssl_ctx_.get(), SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
    SSL_CTX_sess_set_new_cb(ssl_ctx_.get(), NewSessionCallback);

    if (!SSL_CTX_add_client_custom_ext(ssl_ctx_.get(), kTbExtNum,
                                       &TokenBindingAddCallback,
                                       &TokenBindingFreeCallback, nullptr,
                                       &TokenBindingParseCallback, nullptr)) {
      NOTREACHED();
    }
  }

  static int TokenBindingAddCallback(SSL* ssl,
                                     unsigned int extension_value,
                                     const uint8_t** out,
                                     size_t* out_len,
                                     int* out_alert_value,
                                     void* add_arg) {
    DCHECK_EQ(extension_value, kTbExtNum);
    SSLClientSocketImpl* socket =
        SSLClientSocketImpl::SSLContext::GetInstance()->GetClientSocketFromSSL(
            ssl);
    return socket->TokenBindingAdd(out, out_len, out_alert_value);
  }

  static void TokenBindingFreeCallback(SSL* ssl,
                                       unsigned extension_value,
                                       const uint8_t* out,
                                       void* add_arg) {
    DCHECK_EQ(extension_value, kTbExtNum);
    OPENSSL_free(const_cast<unsigned char*>(out));
  }

  static int TokenBindingParseCallback(SSL* ssl,
                                       unsigned int extension_value,
                                       const uint8_t* contents,
                                       size_t contents_len,
                                       int* out_alert_value,
                                       void* parse_arg) {
    DCHECK_EQ(extension_value, kTbExtNum);
    SSLClientSocketImpl* socket =
        SSLClientSocketImpl::SSLContext::GetInstance()->GetClientSocketFromSSL(
            ssl);
    return socket->TokenBindingParse(contents, contents_len, out_alert_value);
  }

  static int ClientCertRequestCallback(SSL* ssl, void* arg) {
    SSLClientSocketImpl* socket = GetInstance()->GetClientSocketFromSSL(ssl);
    DCHECK(socket);
    return socket->ClientCertRequestCallback(ssl);
  }

  static int CertVerifyCallback(X509_STORE_CTX* store_ctx, void* arg) {
    SSL* ssl = reinterpret_cast<SSL*>(X509_STORE_CTX_get_ex_data(
        store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
    SSLClientSocketImpl* socket = GetInstance()->GetClientSocketFromSSL(ssl);
    CHECK(socket);

    return socket->CertVerifyCallback(store_ctx);
  }

  static int SelectNextProtoCallback(SSL* ssl,
                                     unsigned char** out,
                                     unsigned char* outlen,
                                     const unsigned char* in,
                                     unsigned int inlen,
                                     void* arg) {
    SSLClientSocketImpl* socket = GetInstance()->GetClientSocketFromSSL(ssl);
    return socket->SelectNextProtoCallback(out, outlen, in, inlen);
  }

  static int NewSessionCallback(SSL* ssl, SSL_SESSION* session) {
    SSLClientSocketImpl* socket = GetInstance()->GetClientSocketFromSSL(ssl);
    return socket->NewSessionCallback(session);
  }

  static int PrivateKeyTypeCallback(SSL* ssl) {
    SSLClientSocketImpl* socket = GetInstance()->GetClientSocketFromSSL(ssl);
    return socket->PrivateKeyTypeCallback();
  }

  static size_t PrivateKeyMaxSignatureLenCallback(SSL* ssl) {
    SSLClientSocketImpl* socket = GetInstance()->GetClientSocketFromSSL(ssl);
    return socket->PrivateKeyMaxSignatureLenCallback();
  }

  static ssl_private_key_result_t PrivateKeySignCallback(SSL* ssl,
                                                         uint8_t* out,
                                                         size_t* out_len,
                                                         size_t max_out,
                                                         const EVP_MD* md,
                                                         const uint8_t* in,
                                                         size_t in_len) {
    SSLClientSocketImpl* socket = GetInstance()->GetClientSocketFromSSL(ssl);
    return socket->PrivateKeySignCallback(out, out_len, max_out, md, in,
                                          in_len);
  }

  static ssl_private_key_result_t PrivateKeySignCompleteCallback(
      SSL* ssl,
      uint8_t* out,
      size_t* out_len,
      size_t max_out) {
    SSLClientSocketImpl* socket = GetInstance()->GetClientSocketFromSSL(ssl);
    return socket->PrivateKeySignCompleteCallback(out, out_len, max_out);
  }

#if !defined(OS_NACL)
  static void KeyLogCallback(const SSL* ssl, const char* line) {
    GetInstance()->ssl_key_logger_->WriteLine(line);
  }
#endif

  // This is the index used with SSL_get_ex_data to retrieve the owner
  // SSLClientSocketImpl object from an SSL instance.
  int ssl_socket_data_index_;

  ScopedSSL_CTX ssl_ctx_;

#if !defined(OS_NACL)
  std::unique_ptr<SSLKeyLogger> ssl_key_logger_;
#endif

  // TODO(davidben): Use a separate cache per URLRequestContext.
  // https://crbug.com/458365
  //
  // TODO(davidben): Sessions should be invalidated on fatal
  // alerts. https://crbug.com/466352
  SSLClientSessionCache session_cache_;
};

const SSL_PRIVATE_KEY_METHOD
    SSLClientSocketImpl::SSLContext::kPrivateKeyMethod = {
        &SSLClientSocketImpl::SSLContext::PrivateKeyTypeCallback,
        &SSLClientSocketImpl::SSLContext::PrivateKeyMaxSignatureLenCallback,
        &SSLClientSocketImpl::SSLContext::PrivateKeySignCallback,
        &SSLClientSocketImpl::SSLContext::PrivateKeySignCompleteCallback,
};

// PeerCertificateChain is a helper object which extracts the certificate
// chain, as given by the server, from an OpenSSL socket and performs the needed
// resource management. The first element of the chain is the leaf certificate
// and the other elements are in the order given by the server.
class SSLClientSocketImpl::PeerCertificateChain {
 public:
  explicit PeerCertificateChain(STACK_OF(X509) * chain) { Reset(chain); }
  PeerCertificateChain(const PeerCertificateChain& other) { *this = other; }
  ~PeerCertificateChain() {}
  PeerCertificateChain& operator=(const PeerCertificateChain& other);

  // Resets the PeerCertificateChain to the set of certificates in|chain|,
  // which may be NULL, indicating to empty the store certificates.
  // Note: If an error occurs, such as being unable to parse the certificates,
  // this will behave as if Reset(NULL) was called.
  void Reset(STACK_OF(X509) * chain);

  // Note that when USE_OPENSSL_CERTS is defined, OSCertHandle is X509*
  scoped_refptr<X509Certificate> AsOSChain() const;

  size_t size() const {
    if (!openssl_chain_.get())
      return 0;
    return sk_X509_num(openssl_chain_.get());
  }

  bool empty() const { return size() == 0; }

  X509* Get(size_t index) const {
    DCHECK_LT(index, size());
    return sk_X509_value(openssl_chain_.get(), index);
  }

 private:
  ScopedX509Stack openssl_chain_;
};

SSLClientSocketImpl::PeerCertificateChain&
SSLClientSocketImpl::PeerCertificateChain::operator=(
    const PeerCertificateChain& other) {
  if (this == &other)
    return *this;

  openssl_chain_.reset(X509_chain_up_ref(other.openssl_chain_.get()));
  return *this;
}

void SSLClientSocketImpl::PeerCertificateChain::Reset(STACK_OF(X509) * chain) {
  openssl_chain_.reset(chain ? X509_chain_up_ref(chain) : NULL);
}

scoped_refptr<X509Certificate>
SSLClientSocketImpl::PeerCertificateChain::AsOSChain() const {
#if defined(USE_OPENSSL_CERTS)
  // When OSCertHandle is typedef'ed to X509, this implementation does a short
  // cut to avoid converting back and forth between DER and the X509 struct.
  X509Certificate::OSCertHandles intermediates;
  for (size_t i = 1; i < sk_X509_num(openssl_chain_.get()); ++i) {
    intermediates.push_back(sk_X509_value(openssl_chain_.get(), i));
  }

  return X509Certificate::CreateFromHandle(
      sk_X509_value(openssl_chain_.get(), 0), intermediates);
#else
  // DER-encode the chain and convert to a platform certificate handle.
  std::vector<base::StringPiece> der_chain;
  for (size_t i = 0; i < sk_X509_num(openssl_chain_.get()); ++i) {
    X509* x = sk_X509_value(openssl_chain_.get(), i);
    base::StringPiece der;
    if (!x509_util::GetDER(x, &der))
      return NULL;
    der_chain.push_back(der);
  }

  return X509Certificate::CreateFromDERCertChain(der_chain);
#endif
}

// static
void SSLClientSocket::ClearSessionCache() {
  SSLClientSocketImpl::SSLContext* context =
      SSLClientSocketImpl::SSLContext::GetInstance();
  context->session_cache()->Flush();
}

SSLClientSocketImpl::SSLClientSocketImpl(
    std::unique_ptr<ClientSocketHandle> transport_socket,
    const HostPortPair& host_and_port,
    const SSLConfig& ssl_config,
    const SSLClientSocketContext& context)
    : transport_send_busy_(false),
      transport_recv_busy_(false),
      pending_read_error_(kNoPendingResult),
      pending_read_ssl_error_(SSL_ERROR_NONE),
      transport_read_error_(OK),
      transport_write_error_(OK),
      server_cert_chain_(new PeerCertificateChain(NULL)),
      completed_connect_(false),
      was_ever_used_(false),
      cert_verifier_(context.cert_verifier),
      cert_transparency_verifier_(context.cert_transparency_verifier),
      channel_id_service_(context.channel_id_service),
      tb_was_negotiated_(false),
      tb_negotiated_param_(TB_PARAM_ECDSAP256),
      tb_signed_ekm_map_(10),
      ssl_(NULL),
      transport_bio_(NULL),
      transport_(std::move(transport_socket)),
      host_and_port_(host_and_port),
      ssl_config_(ssl_config),
      ssl_session_cache_shard_(context.ssl_session_cache_shard),
      next_handshake_state_(STATE_NONE),
      disconnected_(false),
      npn_status_(kNextProtoUnsupported),
      channel_id_sent_(false),
      session_pending_(false),
      certificate_verified_(false),
      ssl_failure_state_(SSL_FAILURE_NONE),
      signature_result_(kNoPendingResult),
      transport_security_state_(context.transport_security_state),
      policy_enforcer_(context.ct_policy_enforcer),
      net_log_(transport_->socket()->NetLog()),
      weak_factory_(this) {
  DCHECK(cert_verifier_);
}

SSLClientSocketImpl::~SSLClientSocketImpl() {
  Disconnect();
}

#if !defined(OS_NACL)
void SSLClientSocketImpl::SetSSLKeyLogFile(
    const base::FilePath& ssl_keylog_file,
    const scoped_refptr<base::SequencedTaskRunner>& task_runner) {
  SSLContext::GetInstance()->SetSSLKeyLogFile(ssl_keylog_file, task_runner);
}
#endif

void SSLClientSocketImpl::GetSSLCertRequestInfo(
    SSLCertRequestInfo* cert_request_info) {
  cert_request_info->host_and_port = host_and_port_;
  cert_request_info->cert_authorities = cert_authorities_;
  cert_request_info->cert_key_types = cert_key_types_;
}

SSLClientSocket::NextProtoStatus SSLClientSocketImpl::GetNextProto(
    std::string* proto) const {
  *proto = npn_proto_;
  return npn_status_;
}

ChannelIDService* SSLClientSocketImpl::GetChannelIDService() const {
  return channel_id_service_;
}

Error SSLClientSocketImpl::GetSignedEKMForTokenBinding(
    crypto::ECPrivateKey* key,
    std::vector<uint8_t>* out) {
  // The same key will be used across multiple requests to sign the same value,
  // so the signature is cached.
  std::string raw_public_key;
  if (!key->ExportRawPublicKey(&raw_public_key))
    return ERR_FAILED;
  SignedEkmMap::iterator it = tb_signed_ekm_map_.Get(raw_public_key);
  if (it != tb_signed_ekm_map_.end()) {
    *out = it->second;
    return OK;
  }

  uint8_t tb_ekm_buf[32];
  static const char kTokenBindingExporterLabel[] = "EXPORTER-Token-Binding";
  if (!SSL_export_keying_material(ssl_, tb_ekm_buf, sizeof(tb_ekm_buf),
                                  kTokenBindingExporterLabel,
                                  strlen(kTokenBindingExporterLabel), nullptr,
                                  0, false /* no context */)) {
    return ERR_FAILED;
  }

  if (!SignTokenBindingEkm(
          base::StringPiece(reinterpret_cast<char*>(tb_ekm_buf),
                            sizeof(tb_ekm_buf)),
          key, out))
    return ERR_FAILED;

  tb_signed_ekm_map_.Put(raw_public_key, *out);
  return OK;
}

crypto::ECPrivateKey* SSLClientSocketImpl::GetChannelIDKey() const {
  return channel_id_key_.get();
}

SSLFailureState SSLClientSocketImpl::GetSSLFailureState() const {
  return ssl_failure_state_;
}

int SSLClientSocketImpl::ExportKeyingMaterial(const base::StringPiece& label,
                                              bool has_context,
                                              const base::StringPiece& context,
                                              unsigned char* out,
                                              unsigned int outlen) {
  if (!IsConnected())
    return ERR_SOCKET_NOT_CONNECTED;

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  int rv = SSL_export_keying_material(
      ssl_, out, outlen, label.data(), label.size(),
      reinterpret_cast<const unsigned char*>(context.data()), context.length(),
      has_context ? 1 : 0);

  if (rv != 1) {
    int ssl_error = SSL_get_error(ssl_, rv);
    LOG(ERROR) << "Failed to export keying material;"
               << " returned " << rv << ", SSL error code " << ssl_error;
    return MapOpenSSLError(ssl_error, err_tracer);
  }
  return OK;
}

int SSLClientSocketImpl::Connect(const CompletionCallback& callback) {
  // It is an error to create an SSLClientSocket whose context has no
  // TransportSecurityState.
  DCHECK(transport_security_state_);

  // Although StreamSocket does allow calling Connect() after Disconnect(),
  // this has never worked for layered sockets. CHECK to detect any consumers
  // reconnecting an SSL socket.
  //
  // TODO(davidben,mmenke): Remove this API feature. See
  // https://crbug.com/499289.
  CHECK(!disconnected_);

  net_log_.BeginEvent(NetLog::TYPE_SSL_CONNECT);

  // Set up new ssl object.
  int rv = Init();
  if (rv != OK) {
    LogConnectEndEvent(rv);
    return rv;
  }

  // Set SSL to client mode. Handshake happens in the loop below.
  SSL_set_connect_state(ssl_);

  GotoState(STATE_HANDSHAKE);
  rv = DoHandshakeLoop(OK);
  if (rv == ERR_IO_PENDING) {
    user_connect_callback_ = callback;
  } else {
    LogConnectEndEvent(rv);
  }

  return rv > OK ? OK : rv;
}

void SSLClientSocketImpl::Disconnect() {
  crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

  if (ssl_) {
    // Calling SSL_shutdown prevents the session from being marked as
    // unresumable.
    SSL_shutdown(ssl_);
    SSL_free(ssl_);
    ssl_ = NULL;
  }
  if (transport_bio_) {
    BIO_free_all(transport_bio_);
    transport_bio_ = NULL;
  }

  disconnected_ = true;

  // Shut down anything that may call us back.
  cert_verifier_request_.reset();
  transport_->socket()->Disconnect();

  // Null all callbacks, delete all buffers.
  transport_send_busy_ = false;
  send_buffer_ = NULL;
  transport_recv_busy_ = false;
  recv_buffer_ = NULL;

  user_connect_callback_.Reset();
  user_read_callback_.Reset();
  user_write_callback_.Reset();
  user_read_buf_ = NULL;
  user_read_buf_len_ = 0;
  user_write_buf_ = NULL;
  user_write_buf_len_ = 0;

  pending_read_error_ = kNoPendingResult;
  pending_read_ssl_error_ = SSL_ERROR_NONE;
  pending_read_error_info_ = OpenSSLErrorInfo();

  transport_read_error_ = OK;
  transport_write_error_ = OK;

  server_cert_verify_result_.Reset();
  completed_connect_ = false;

  cert_authorities_.clear();
  cert_key_types_.clear();

  start_cert_verification_time_ = base::TimeTicks();

  npn_status_ = kNextProtoUnsupported;
  npn_proto_.clear();

  channel_id_sent_ = false;
  tb_was_negotiated_ = false;
  session_pending_ = false;
  certificate_verified_ = false;
  channel_id_request_.Cancel();
  ssl_failure_state_ = SSL_FAILURE_NONE;

  signature_result_ = kNoPendingResult;
  signature_.clear();
}

bool SSLClientSocketImpl::IsConnected() const {
  // If the handshake has not yet completed.
  if (!completed_connect_)
    return false;
  // If an asynchronous operation is still pending.
  if (user_read_buf_.get() || user_write_buf_.get())
    return true;

  return transport_->socket()->IsConnected();
}

bool SSLClientSocketImpl::IsConnectedAndIdle() const {
  // If the handshake has not yet completed.
  if (!completed_connect_)
    return false;
  // If an asynchronous operation is still pending.
  if (user_read_buf_.get() || user_write_buf_.get())
    return false;

  // If there is data read from the network that has not yet been consumed, do
  // not treat the connection as idle.
  //
  // Note that this does not check |BIO_pending|, whether there is ciphertext
  // that has not yet been flushed to the network. |Write| returns early, so
  // this can cause race conditions which cause a socket to not be treated
  // reusable when it should be. See https://crbug.com/466147.
  if (BIO_wpending(transport_bio_) > 0)
    return false;

  return transport_->socket()->IsConnectedAndIdle();
}

int SSLClientSocketImpl::GetPeerAddress(IPEndPoint* addressList) const {
  return transport_->socket()->GetPeerAddress(addressList);
}

int SSLClientSocketImpl::GetLocalAddress(IPEndPoint* addressList) const {
  return transport_->socket()->GetLocalAddress(addressList);
}

const BoundNetLog& SSLClientSocketImpl::NetLog() const {
  return net_log_;
}

void SSLClientSocketImpl::SetSubresourceSpeculation() {
  if (transport_.get() && transport_->socket()) {
    transport_->socket()->SetSubresourceSpeculation();
  } else {
    NOTREACHED();
  }
}

void SSLClientSocketImpl::SetOmniboxSpeculation() {
  if (transport_.get() && transport_->socket()) {
    transport_->socket()->SetOmniboxSpeculation();
  } else {
    NOTREACHED();
  }
}

bool SSLClientSocketImpl::WasEverUsed() const {
  return was_ever_used_;
}

bool SSLClientSocketImpl::GetSSLInfo(SSLInfo* ssl_info) {
  ssl_info->Reset();
  if (server_cert_chain_->empty())
    return false;

  ssl_info->cert = server_cert_verify_result_.verified_cert;
  ssl_info->unverified_cert = server_cert_;
  ssl_info->cert_status = server_cert_verify_result_.cert_status;
  ssl_info->is_issued_by_known_root =
      server_cert_verify_result_.is_issued_by_known_root;
  ssl_info->public_key_hashes = server_cert_verify_result_.public_key_hashes;
  ssl_info->client_cert_sent =
      ssl_config_.send_client_cert && ssl_config_.client_cert.get();
  ssl_info->channel_id_sent = channel_id_sent_;
  ssl_info->token_binding_negotiated = tb_was_negotiated_;
  ssl_info->token_binding_key_param = tb_negotiated_param_;
  ssl_info->pinning_failure_log = pinning_failure_log_;

  AddCTInfoToSSLInfo(ssl_info);

  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_);
  CHECK(cipher);
  ssl_info->security_bits = SSL_CIPHER_get_bits(cipher, NULL);
  ssl_info->key_exchange_info =
      SSL_SESSION_get_key_exchange_info(SSL_get_session(ssl_));

  SSLConnectionStatusSetCipherSuite(
      static_cast<uint16_t>(SSL_CIPHER_get_id(cipher)),
      &ssl_info->connection_status);
  SSLConnectionStatusSetVersion(GetNetSSLVersion(ssl_),
                                &ssl_info->connection_status);

  if (!SSL_get_secure_renegotiation_support(ssl_))
    ssl_info->connection_status |= SSL_CONNECTION_NO_RENEGOTIATION_EXTENSION;

  if (ssl_config_.version_fallback)
    ssl_info->connection_status |= SSL_CONNECTION_VERSION_FALLBACK;

  ssl_info->handshake_type = SSL_session_reused(ssl_)
                                 ? SSLInfo::HANDSHAKE_RESUME
                                 : SSLInfo::HANDSHAKE_FULL;

  DVLOG(3) << "Encoded connection status: cipher suite = "
           << SSLConnectionStatusToCipherSuite(ssl_info->connection_status)
           << " version = "
           << SSLConnectionStatusToVersion(ssl_info->connection_status);
  return true;
}

void SSLClientSocketImpl::GetConnectionAttempts(ConnectionAttempts* out) const {
  out->clear();
}

int64_t SSLClientSocketImpl::GetTotalReceivedBytes() const {
  return transport_->socket()->GetTotalReceivedBytes();
}

int SSLClientSocketImpl::Read(IOBuffer* buf,
                              int buf_len,
                              const CompletionCallback& callback) {
  user_read_buf_ = buf;
  user_read_buf_len_ = buf_len;

  int rv = DoReadLoop();

  if (rv == ERR_IO_PENDING) {
    user_read_callback_ = callback;
  } else {
    if (rv > 0)
      was_ever_used_ = true;
    user_read_buf_ = NULL;
    user_read_buf_len_ = 0;
  }

  return rv;
}

int SSLClientSocketImpl::Write(IOBuffer* buf,
                               int buf_len,
                               const CompletionCallback& callback) {
  user_write_buf_ = buf;
  user_write_buf_len_ = buf_len;

  int rv = DoWriteLoop();

  if (rv == ERR_IO_PENDING) {
    user_write_callback_ = callback;
  } else {
    if (rv > 0)
      was_ever_used_ = true;
    user_write_buf_ = NULL;
    user_write_buf_len_ = 0;
  }

  return rv;
}

int SSLClientSocketImpl::SetReceiveBufferSize(int32_t size) {
  return transport_->socket()->SetReceiveBufferSize(size);
}

int SSLClientSocketImpl::SetSendBufferSize(int32_t size) {
  return transport_->socket()->SetSendBufferSize(size);
}

int SSLClientSocketImpl::Init() {
  DCHECK(!ssl_);
  DCHECK(!transport_bio_);

#if defined(USE_NSS_CERTS)
  if (ssl_config_.cert_io_enabled) {
    // TODO(davidben): Move this out of SSLClientSocket. See
    // https://crbug.com/539520.
    EnsureNSSHttpIOInit();
  }
#endif

  SSLContext* context = SSLContext::GetInstance();
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  ssl_ = SSL_new(context->ssl_ctx());
  if (!ssl_ || !context->SetClientSocketForSSL(ssl_, this))
    return ERR_UNEXPECTED;

  // SNI should only contain valid DNS hostnames, not IP addresses (see RFC
  // 6066, Section 3).
  //
  // TODO(rsleevi): Should this code allow hostnames that violate the LDH rule?
  // See https://crbug.com/496472 and https://crbug.com/496468 for discussion.
  IPAddress unused;
  if (!unused.AssignFromIPLiteral(host_and_port_.host()) &&
      !SSL_set_tlsext_host_name(ssl_, host_and_port_.host().c_str())) {
    return ERR_UNEXPECTED;
  }

  ScopedSSL_SESSION session =
      context->session_cache()->Lookup(GetSessionCacheKey());
  if (session)
    SSL_set_session(ssl_, session.get());

  send_buffer_ = new GrowableIOBuffer();
  send_buffer_->SetCapacity(KDefaultOpenSSLBufferSize);
  recv_buffer_ = new GrowableIOBuffer();
  recv_buffer_->SetCapacity(KDefaultOpenSSLBufferSize);

  BIO* ssl_bio = NULL;

  // SSLClientSocketImpl retains ownership of the BIO buffers.
  if (!BIO_new_bio_pair_external_buf(
          &ssl_bio, send_buffer_->capacity(),
          reinterpret_cast<uint8_t*>(send_buffer_->data()), &transport_bio_,
          recv_buffer_->capacity(),
          reinterpret_cast<uint8_t*>(recv_buffer_->data())))
    return ERR_UNEXPECTED;
  DCHECK(ssl_bio);
  DCHECK(transport_bio_);

  // Install a callback on OpenSSL's end to plumb transport errors through.
  BIO_set_callback(ssl_bio, &SSLClientSocketImpl::BIOCallback);
  BIO_set_callback_arg(ssl_bio, reinterpret_cast<char*>(this));

  SSL_set_bio(ssl_, ssl_bio, ssl_bio);

  DCHECK_LT(SSL3_VERSION, ssl_config_.version_min);
  DCHECK_LT(SSL3_VERSION, ssl_config_.version_max);
  SSL_set_min_version(ssl_, ssl_config_.version_min);
  SSL_set_max_version(ssl_, ssl_config_.version_max);

  // OpenSSL defaults some options to on, others to off. To avoid ambiguity,
  // set everything we care about to an absolute value.
  SslSetClearMask options;
  options.ConfigureFlag(SSL_OP_NO_COMPRESSION, true);

  // TODO(joth): Set this conditionally, see http://crbug.com/55410
  options.ConfigureFlag(SSL_OP_LEGACY_SERVER_CONNECT, true);

  SSL_set_options(ssl_, options.set_mask);
  SSL_clear_options(ssl_, options.clear_mask);

  // Same as above, this time for the SSL mode.
  SslSetClearMask mode;

  mode.ConfigureFlag(SSL_MODE_RELEASE_BUFFERS, true);
  mode.ConfigureFlag(SSL_MODE_CBC_RECORD_SPLITTING, true);

  mode.ConfigureFlag(SSL_MODE_ENABLE_FALSE_START,
                     ssl_config_.false_start_enabled);

  mode.ConfigureFlag(SSL_MODE_SEND_FALLBACK_SCSV, ssl_config_.version_fallback);

  SSL_set_mode(ssl_, mode.set_mask);
  SSL_clear_mode(ssl_, mode.clear_mask);

  // Use BoringSSL defaults, but disable HMAC-SHA256 and HMAC-SHA384 ciphers
  // (note that SHA256 and SHA384 only select legacy CBC ciphers). Also disable
  // DHE_RSA_WITH_AES_256_GCM_SHA384. Historically, AES_256_GCM was not
  // supported. As DHE is being deprecated, don't add a cipher only to remove it
  // immediately.
  std::string command(
      "DEFAULT:!SHA256:!SHA384:!DHE-RSA-AES256-GCM-SHA384:!aPSK");

  if (ssl_config_.require_ecdhe)
    command.append(":!kRSA:!kDHE");

  if (!(ssl_config_.rc4_enabled &&
        ssl_config_.deprecated_cipher_suites_enabled)) {
    command.append(":!RC4");
  }

  if (!ssl_config_.deprecated_cipher_suites_enabled) {
    // Only offer DHE on the second handshake. https://crbug.com/538690
    command.append(":!kDHE");
  }

  // Remove any disabled ciphers.
  for (uint16_t id : ssl_config_.disabled_cipher_suites) {
    const SSL_CIPHER* cipher = SSL_get_cipher_by_value(id);
    if (cipher) {
      command.append(":!");
      command.append(SSL_CIPHER_get_name(cipher));
    }
  }

  int rv = SSL_set_cipher_list(ssl_, command.c_str());
  // If this fails (rv = 0) it means there are no ciphers enabled on this SSL.
  // This will almost certainly result in the socket failing to complete the
  // handshake at which point the appropriate error is bubbled up to the client.
  LOG_IF(WARNING, rv != 1) << "SSL_set_cipher_list('" << command << "') "
                                                                    "returned "
                           << rv;

  // TLS channel ids.
  if (IsChannelIDEnabled(ssl_config_, channel_id_service_)) {
    SSL_enable_tls_channel_id(ssl_);
  }

  if (!ssl_config_.alpn_protos.empty()) {
    // Get list of ciphers that are enabled.
    STACK_OF(SSL_CIPHER)* enabled_ciphers = SSL_get_ciphers(ssl_);
    DCHECK(enabled_ciphers);
    std::vector<uint16_t> enabled_ciphers_vector;
    for (size_t i = 0; i < sk_SSL_CIPHER_num(enabled_ciphers); ++i) {
      const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(enabled_ciphers, i);
      const uint16_t id = static_cast<uint16_t>(SSL_CIPHER_get_id(cipher));
      enabled_ciphers_vector.push_back(id);
    }

    NextProtoVector alpn_protos = ssl_config_.alpn_protos;
    if (!HasCipherAdequateForHTTP2(enabled_ciphers_vector) ||
        !IsTLSVersionAdequateForHTTP2(ssl_config_)) {
      DisableHTTP2(&alpn_protos);
    }
    std::vector<uint8_t> wire_protos = SerializeNextProtos(alpn_protos);
    SSL_set_alpn_protos(ssl_, wire_protos.empty() ? NULL : &wire_protos[0],
                        wire_protos.size());
  }

  if (ssl_config_.npn_protos.empty())
    SSL_set_options(ssl_, SSL_OP_DISABLE_NPN);

  if (ssl_config_.signed_cert_timestamps_enabled) {
    SSL_enable_signed_cert_timestamps(ssl_);
    SSL_enable_ocsp_stapling(ssl_);
  }

  if (cert_verifier_->SupportsOCSPStapling())
    SSL_enable_ocsp_stapling(ssl_);

  return OK;
}

void SSLClientSocketImpl::DoReadCallback(int rv) {
  // Since Run may result in Read being called, clear |user_read_callback_|
  // up front.
  if (rv > 0)
    was_ever_used_ = true;
  user_read_buf_ = NULL;
  user_read_buf_len_ = 0;
  base::ResetAndReturn(&user_read_callback_).Run(rv);
}

void SSLClientSocketImpl::DoWriteCallback(int rv) {
  // Since Run may result in Write being called, clear |user_write_callback_|
  // up front.
  if (rv > 0)
    was_ever_used_ = true;
  user_write_buf_ = NULL;
  user_write_buf_len_ = 0;
  base::ResetAndReturn(&user_write_callback_).Run(rv);
}

bool SSLClientSocketImpl::DoTransportIO() {
  bool network_moved = false;
  int rv;
  // Read and write as much data as possible. The loop is necessary because
  // Write() may return synchronously.
  do {
    rv = BufferSend();
    if (rv != ERR_IO_PENDING && rv != 0)
      network_moved = true;
  } while (rv > 0);
  if (transport_read_error_ == OK && BufferRecv() != ERR_IO_PENDING)
    network_moved = true;
  return network_moved;
}

// TODO(cbentzel): Remove including "base/threading/thread_local.h" and
// g_first_run_completed once crbug.com/424386 is fixed.
base::LazyInstance<base::ThreadLocalBoolean>::Leaky g_first_run_completed =
    LAZY_INSTANCE_INITIALIZER;

int SSLClientSocketImpl::DoHandshake() {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  int rv;

  // TODO(cbentzel): Leave only 1 call to SSL_do_handshake once crbug.com/424386
  // is fixed.
  if (ssl_config_.send_client_cert && ssl_config_.client_cert.get()) {
    rv = SSL_do_handshake(ssl_);
  } else {
    if (g_first_run_completed.Get().Get()) {
      // TODO(cbentzel): Remove ScopedTracker below once crbug.com/424386 is
      // fixed.
      tracked_objects::ScopedTracker tracking_profile(
          FROM_HERE_WITH_EXPLICIT_FUNCTION("424386 SSL_do_handshake()"));

      rv = SSL_do_handshake(ssl_);
    } else {
      g_first_run_completed.Get().Set(true);
      rv = SSL_do_handshake(ssl_);
    }
  }

  int net_error = OK;
  if (rv <= 0) {
    int ssl_error = SSL_get_error(ssl_, rv);
    if (ssl_error == SSL_ERROR_WANT_CHANNEL_ID_LOOKUP) {
      // The server supports channel ID. Stop to look one up before returning to
      // the handshake.
      GotoState(STATE_CHANNEL_ID_LOOKUP);
      return OK;
    }
    if (ssl_error == SSL_ERROR_WANT_X509_LOOKUP &&
        !ssl_config_.send_client_cert) {
      return ERR_SSL_CLIENT_AUTH_CERT_NEEDED;
    }
    if (ssl_error == SSL_ERROR_WANT_PRIVATE_KEY_OPERATION) {
      DCHECK(ssl_config_.client_private_key);
      DCHECK_NE(kNoPendingResult, signature_result_);
      GotoState(STATE_HANDSHAKE);
      return ERR_IO_PENDING;
    }

    OpenSSLErrorInfo error_info;
    net_error = MapOpenSSLErrorWithDetails(ssl_error, err_tracer, &error_info);
    if (net_error == ERR_IO_PENDING) {
      // If not done, stay in this state
      GotoState(STATE_HANDSHAKE);
      return ERR_IO_PENDING;
    }

    LOG(ERROR) << "handshake failed; returned " << rv << ", SSL error code "
               << ssl_error << ", net_error " << net_error;
    net_log_.AddEvent(
        NetLog::TYPE_SSL_HANDSHAKE_ERROR,
        CreateNetLogOpenSSLErrorCallback(net_error, ssl_error, error_info));

    // Classify the handshake failure. This is used to determine causes of the
    // TLS version fallback.

    // |cipher| is the current outgoing cipher suite, so it is non-null iff
    // ChangeCipherSpec was sent.
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_);
    if (SSL_get_state(ssl_) == SSL3_ST_CR_SRVR_HELLO_A) {
      ssl_failure_state_ = SSL_FAILURE_CLIENT_HELLO;
    } else if (cipher && (SSL_CIPHER_get_id(cipher) ==
                              TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
                          SSL_CIPHER_get_id(cipher) ==
                              TLS1_CK_RSA_WITH_AES_128_GCM_SHA256)) {
      ssl_failure_state_ = SSL_FAILURE_BUGGY_GCM;
    } else if (cipher && ssl_config_.send_client_cert) {
      ssl_failure_state_ = SSL_FAILURE_CLIENT_AUTH;
    } else if (ERR_GET_LIB(error_info.error_code) == ERR_LIB_SSL &&
               ERR_GET_REASON(error_info.error_code) ==
                   SSL_R_OLD_SESSION_VERSION_NOT_RETURNED) {
      ssl_failure_state_ = SSL_FAILURE_SESSION_MISMATCH;
    } else if (cipher && npn_status_ != kNextProtoUnsupported) {
      ssl_failure_state_ = SSL_FAILURE_NEXT_PROTO;
    } else {
      ssl_failure_state_ = SSL_FAILURE_UNKNOWN;
    }
  }

  GotoState(STATE_HANDSHAKE_COMPLETE);
  return net_error;
}

int SSLClientSocketImpl::DoHandshakeComplete(int result) {
  if (result < 0)
    return result;

  if (ssl_config_.version_fallback &&
      ssl_config_.version_max < ssl_config_.version_fallback_min) {
    return ERR_SSL_FALLBACK_BEYOND_MINIMUM_VERSION;
  }

  // Check that if token binding was negotiated, then extended master secret
  // must also be negotiated.
  if (tb_was_negotiated_ && !SSL_get_extms_support(ssl_))
    return ERR_SSL_PROTOCOL_ERROR;

  // SSL handshake is completed. If NPN wasn't negotiated, see if ALPN was.
  if (npn_status_ == kNextProtoUnsupported) {
    const uint8_t* alpn_proto = NULL;
    unsigned alpn_len = 0;
    SSL_get0_alpn_selected(ssl_, &alpn_proto, &alpn_len);
    if (alpn_len > 0) {
      npn_proto_.assign(reinterpret_cast<const char*>(alpn_proto), alpn_len);
      npn_status_ = kNextProtoNegotiated;
      set_negotiation_extension(kExtensionALPN);
    }
  }

  RecordNegotiationExtension();
  RecordChannelIDSupport(channel_id_service_, channel_id_sent_,
                         ssl_config_.channel_id_enabled);

  // Only record OCSP histograms if OCSP was requested.
  if (ssl_config_.signed_cert_timestamps_enabled ||
      cert_verifier_->SupportsOCSPStapling()) {
    const uint8_t* ocsp_response;
    size_t ocsp_response_len;
    SSL_get0_ocsp_response(ssl_, &ocsp_response, &ocsp_response_len);

    set_stapled_ocsp_response_received(ocsp_response_len != 0);
    UMA_HISTOGRAM_BOOLEAN("Net.OCSPResponseStapled", ocsp_response_len != 0);
  }

  const uint8_t* sct_list;
  size_t sct_list_len;
  SSL_get0_signed_cert_timestamp_list(ssl_, &sct_list, &sct_list_len);
  set_signed_cert_timestamps_received(sct_list_len != 0);

  if (IsRenegotiationAllowed())
    SSL_set_renegotiate_mode(ssl_, ssl_renegotiate_freely);

  uint8_t server_key_exchange_hash = SSL_get_server_key_exchange_hash(ssl_);
  if (server_key_exchange_hash != TLSEXT_hash_none) {
    UMA_HISTOGRAM_SPARSE_SLOWLY("Net.SSLServerKeyExchangeHash",
                                server_key_exchange_hash);
  }

  // Verify the certificate.
  UpdateServerCert();
  GotoState(STATE_VERIFY_CERT);
  return OK;
}

int SSLClientSocketImpl::DoChannelIDLookup() {
  NetLog::ParametersCallback callback = base::Bind(
      &NetLogChannelIDLookupCallback, base::Unretained(channel_id_service_));
  net_log_.BeginEvent(NetLog::TYPE_SSL_GET_CHANNEL_ID, callback);
  GotoState(STATE_CHANNEL_ID_LOOKUP_COMPLETE);
  return channel_id_service_->GetOrCreateChannelID(
      host_and_port_.host(), &channel_id_key_,
      base::Bind(&SSLClientSocketImpl::OnHandshakeIOComplete,
                 base::Unretained(this)),
      &channel_id_request_);
}

int SSLClientSocketImpl::DoChannelIDLookupComplete(int result) {
  net_log_.EndEvent(NetLog::TYPE_SSL_GET_CHANNEL_ID,
                    base::Bind(&NetLogChannelIDLookupCompleteCallback,
                               channel_id_key_.get(), result));
  if (result < 0)
    return result;

  // Hand the key to OpenSSL. Check for error in case OpenSSL rejects the key
  // type.
  DCHECK(channel_id_key_);
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  int rv = SSL_set1_tls_channel_id(ssl_, channel_id_key_->key());
  if (!rv) {
    LOG(ERROR) << "Failed to set Channel ID.";
    int err = SSL_get_error(ssl_, rv);
    return MapOpenSSLError(err, err_tracer);
  }

  // Return to the handshake.
  channel_id_sent_ = true;
  GotoState(STATE_HANDSHAKE);
  return OK;
}

int SSLClientSocketImpl::DoVerifyCert(int result) {
  DCHECK(!server_cert_chain_->empty());
  DCHECK(start_cert_verification_time_.is_null());

  GotoState(STATE_VERIFY_CERT_COMPLETE);

  // OpenSSL decoded the certificate, but the platform certificate
  // implementation could not. This is treated as a fatal SSL-level protocol
  // error rather than a certificate error. See https://crbug.com/91341.
  if (!server_cert_.get())
    return ERR_SSL_SERVER_CERT_BAD_FORMAT;

  // If the certificate is bad and has been previously accepted, use
  // the previous status and bypass the error.
  base::StringPiece der_cert;
  if (!x509_util::GetDER(server_cert_chain_->Get(0), &der_cert)) {
    NOTREACHED();
    return ERR_CERT_INVALID;
  }
  CertStatus cert_status;
  if (ssl_config_.IsAllowedBadCert(der_cert, &cert_status)) {
    VLOG(1) << "Received an expected bad cert with status: " << cert_status;
    server_cert_verify_result_.Reset();
    server_cert_verify_result_.cert_status = cert_status;
    server_cert_verify_result_.verified_cert = server_cert_;
    return OK;
  }

  std::string ocsp_response;
  if (cert_verifier_->SupportsOCSPStapling()) {
    const uint8_t* ocsp_response_raw;
    size_t ocsp_response_len;
    SSL_get0_ocsp_response(ssl_, &ocsp_response_raw, &ocsp_response_len);
    ocsp_response.assign(reinterpret_cast<const char*>(ocsp_response_raw),
                         ocsp_response_len);
  }

  start_cert_verification_time_ = base::TimeTicks::Now();

  return cert_verifier_->Verify(
      server_cert_.get(), host_and_port_.host(), ocsp_response,
      ssl_config_.GetCertVerifyFlags(),
      // TODO(davidben): Route the CRLSet through SSLConfig so
      // SSLClientSocket doesn't depend on SSLConfigService.
      SSLConfigService::GetCRLSet().get(), &server_cert_verify_result_,
      base::Bind(&SSLClientSocketImpl::OnHandshakeIOComplete,
                 base::Unretained(this)),
      &cert_verifier_request_, net_log_);
}

int SSLClientSocketImpl::DoVerifyCertComplete(int result) {
  cert_verifier_request_.reset();

  if (!start_cert_verification_time_.is_null()) {
    base::TimeDelta verify_time =
        base::TimeTicks::Now() - start_cert_verification_time_;
    if (result == OK) {
      UMA_HISTOGRAM_TIMES("Net.SSLCertVerificationTime", verify_time);
    } else {
      UMA_HISTOGRAM_TIMES("Net.SSLCertVerificationTimeError", verify_time);
    }
  }

  const CertStatus cert_status = server_cert_verify_result_.cert_status;
  if (transport_security_state_ &&
      (result == OK ||
       (IsCertificateError(result) && IsCertStatusMinorError(cert_status))) &&
      !transport_security_state_->CheckPublicKeyPins(
          host_and_port_, server_cert_verify_result_.is_issued_by_known_root,
          server_cert_verify_result_.public_key_hashes, server_cert_.get(),
          server_cert_verify_result_.verified_cert.get(),
          TransportSecurityState::ENABLE_PIN_REPORTS, &pinning_failure_log_)) {
    result = ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN;
  }

  if (result == OK) {
    // Only check Certificate Transparency if there were no other errors with
    // the connection.
    VerifyCT();

    DCHECK(!certificate_verified_);
    certificate_verified_ = true;
    MaybeCacheSession();
  } else {
    DVLOG(1) << "DoVerifyCertComplete error " << ErrorToString(result) << " ("
             << result << ")";
  }

  completed_connect_ = true;
  // Exit DoHandshakeLoop and return the result to the caller to Connect.
  DCHECK_EQ(STATE_NONE, next_handshake_state_);
  return result;
}

void SSLClientSocketImpl::DoConnectCallback(int rv) {
  if (!user_connect_callback_.is_null()) {
    CompletionCallback c = user_connect_callback_;
    user_connect_callback_.Reset();
    c.Run(rv > OK ? OK : rv);
  }
}

void SSLClientSocketImpl::UpdateServerCert() {
  server_cert_chain_->Reset(SSL_get_peer_cert_chain(ssl_));
  server_cert_ = server_cert_chain_->AsOSChain();
  if (server_cert_.get()) {
    net_log_.AddEvent(NetLog::TYPE_SSL_CERTIFICATES_RECEIVED,
                      base::Bind(&NetLogX509CertificateCallback,
                                 base::Unretained(server_cert_.get())));
  }
}

void SSLClientSocketImpl::VerifyCT() {
  if (!cert_transparency_verifier_)
    return;

  const uint8_t* ocsp_response_raw;
  size_t ocsp_response_len;
  SSL_get0_ocsp_response(ssl_, &ocsp_response_raw, &ocsp_response_len);
  std::string ocsp_response;
  if (ocsp_response_len > 0) {
    ocsp_response.assign(reinterpret_cast<const char*>(ocsp_response_raw),
                         ocsp_response_len);
  }

  const uint8_t* sct_list_raw;
  size_t sct_list_len;
  SSL_get0_signed_cert_timestamp_list(ssl_, &sct_list_raw, &sct_list_len);
  std::string sct_list;
  if (sct_list_len > 0)
    sct_list.assign(reinterpret_cast<const char*>(sct_list_raw), sct_list_len);

  // Note that this is a completely synchronous operation: The CT Log Verifier
  // gets all the data it needs for SCT verification and does not do any
  // external communication.
  cert_transparency_verifier_->Verify(
      server_cert_verify_result_.verified_cert.get(), ocsp_response, sct_list,
      &ct_verify_result_, net_log_);

  ct_verify_result_.ct_policies_applied = (policy_enforcer_ != nullptr);
  ct_verify_result_.ev_policy_compliance =
      ct::EVPolicyCompliance::EV_POLICY_DOES_NOT_APPLY;
  if (policy_enforcer_) {
    if ((server_cert_verify_result_.cert_status & CERT_STATUS_IS_EV)) {
      scoped_refptr<ct::EVCertsWhitelist> ev_whitelist =
          SSLConfigService::GetEVCertsWhitelist();
      ct::EVPolicyCompliance ev_policy_compliance =
          policy_enforcer_->DoesConformToCTEVPolicy(
              server_cert_verify_result_.verified_cert.get(),
              ev_whitelist.get(), ct_verify_result_.verified_scts, net_log_);
      ct_verify_result_.ev_policy_compliance = ev_policy_compliance;
      if (ev_policy_compliance !=
              ct::EVPolicyCompliance::EV_POLICY_DOES_NOT_APPLY &&
          ev_policy_compliance !=
              ct::EVPolicyCompliance::EV_POLICY_COMPLIES_VIA_WHITELIST &&
          ev_policy_compliance !=
              ct::EVPolicyCompliance::EV_POLICY_COMPLIES_VIA_SCTS) {
        // TODO(eranm): Log via the BoundNetLog, see crbug.com/437766
        VLOG(1) << "EV certificate for "
                << server_cert_verify_result_.verified_cert->subject()
                       .GetDisplayName()
                << " does not conform to CT policy, removing EV status.";
        server_cert_verify_result_.cert_status |=
            CERT_STATUS_CT_COMPLIANCE_FAILED;
        server_cert_verify_result_.cert_status &= ~CERT_STATUS_IS_EV;
      }
    }
    ct_verify_result_.cert_policy_compliance =
        policy_enforcer_->DoesConformToCertPolicy(
            server_cert_verify_result_.verified_cert.get(),
            ct_verify_result_.verified_scts, net_log_);
  }
}

void SSLClientSocketImpl::OnHandshakeIOComplete(int result) {
  int rv = DoHandshakeLoop(result);
  if (rv != ERR_IO_PENDING) {
    LogConnectEndEvent(rv);
    DoConnectCallback(rv);
  }
}

void SSLClientSocketImpl::OnSendComplete(int result) {
  if (next_handshake_state_ == STATE_HANDSHAKE) {
    // In handshake phase.
    OnHandshakeIOComplete(result);
    return;
  }

  // During a renegotiation, a Read call may also be blocked on a transport
  // write, so retry both operations.
  PumpReadWriteEvents();
}

void SSLClientSocketImpl::OnRecvComplete(int result) {
  TRACE_EVENT0("net", "SSLClientSocketImpl::OnRecvComplete");
  if (next_handshake_state_ == STATE_HANDSHAKE) {
    // In handshake phase.
    OnHandshakeIOComplete(result);
    return;
  }

  // Network layer received some data, check if client requested to read
  // decrypted data.
  if (!user_read_buf_.get())
    return;

  int rv = DoReadLoop();
  if (rv != ERR_IO_PENDING)
    DoReadCallback(rv);
}

int SSLClientSocketImpl::DoHandshakeLoop(int last_io_result) {
  TRACE_EVENT0("net", "SSLClientSocketImpl::DoHandshakeLoop");
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
      case STATE_HANDSHAKE_COMPLETE:
        rv = DoHandshakeComplete(rv);
        break;
      case STATE_CHANNEL_ID_LOOKUP:
        DCHECK_EQ(OK, rv);
        rv = DoChannelIDLookup();
        break;
      case STATE_CHANNEL_ID_LOOKUP_COMPLETE:
        rv = DoChannelIDLookupComplete(rv);
        break;
      case STATE_VERIFY_CERT:
        DCHECK_EQ(OK, rv);
        rv = DoVerifyCert(rv);
        break;
      case STATE_VERIFY_CERT_COMPLETE:
        rv = DoVerifyCertComplete(rv);
        break;
      case STATE_NONE:
      default:
        rv = ERR_UNEXPECTED;
        NOTREACHED() << "unexpected state" << state;
        break;
    }

    bool network_moved = DoTransportIO();
    if (network_moved && next_handshake_state_ == STATE_HANDSHAKE) {
      // In general we exit the loop if rv is ERR_IO_PENDING.  In this
      // special case we keep looping even if rv is ERR_IO_PENDING because
      // the transport IO may allow DoHandshake to make progress.
      rv = OK;  // This causes us to stay in the loop.
    }
  } while (rv != ERR_IO_PENDING && next_handshake_state_ != STATE_NONE);
  return rv;
}

int SSLClientSocketImpl::DoReadLoop() {
  bool network_moved;
  int rv;
  do {
    rv = DoPayloadRead();
    network_moved = DoTransportIO();
  } while (rv == ERR_IO_PENDING && network_moved);

  return rv;
}

int SSLClientSocketImpl::DoWriteLoop() {
  bool network_moved;
  int rv;
  do {
    rv = DoPayloadWrite();
    network_moved = DoTransportIO();
  } while (rv == ERR_IO_PENDING && network_moved);

  return rv;
}

int SSLClientSocketImpl::DoPayloadRead() {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  DCHECK_LT(0, user_read_buf_len_);
  DCHECK(user_read_buf_.get());

  int rv;
  if (pending_read_error_ != kNoPendingResult) {
    rv = pending_read_error_;
    pending_read_error_ = kNoPendingResult;
    if (rv == 0) {
      net_log_.AddByteTransferEvent(NetLog::TYPE_SSL_SOCKET_BYTES_RECEIVED, rv,
                                    user_read_buf_->data());
    } else {
      net_log_.AddEvent(
          NetLog::TYPE_SSL_READ_ERROR,
          CreateNetLogOpenSSLErrorCallback(rv, pending_read_ssl_error_,
                                           pending_read_error_info_));
    }
    pending_read_ssl_error_ = SSL_ERROR_NONE;
    pending_read_error_info_ = OpenSSLErrorInfo();
    return rv;
  }

  int total_bytes_read = 0;
  int ssl_ret;
  do {
    ssl_ret = SSL_read(ssl_, user_read_buf_->data() + total_bytes_read,
                       user_read_buf_len_ - total_bytes_read);
    if (ssl_ret > 0)
      total_bytes_read += ssl_ret;
  } while (total_bytes_read < user_read_buf_len_ && ssl_ret > 0);

  // Although only the final SSL_read call may have failed, the failure needs to
  // processed immediately, while the information still available in OpenSSL's
  // error queue.
  if (ssl_ret <= 0) {
    // A zero return from SSL_read may mean any of:
    // - The underlying BIO_read returned 0.
    // - The peer sent a close_notify.
    // - Any arbitrary error. https://crbug.com/466303
    //
    // TransportReadComplete converts the first to an ERR_CONNECTION_CLOSED
    // error, so it does not occur. The second and third are distinguished by
    // SSL_ERROR_ZERO_RETURN.
    pending_read_ssl_error_ = SSL_get_error(ssl_, ssl_ret);
    if (pending_read_ssl_error_ == SSL_ERROR_ZERO_RETURN) {
      pending_read_error_ = 0;
    } else if (pending_read_ssl_error_ == SSL_ERROR_WANT_X509_LOOKUP &&
               !ssl_config_.send_client_cert) {
      pending_read_error_ = ERR_SSL_CLIENT_AUTH_CERT_NEEDED;
    } else if (pending_read_ssl_error_ ==
               SSL_ERROR_WANT_PRIVATE_KEY_OPERATION) {
      DCHECK(ssl_config_.client_private_key);
      DCHECK_NE(kNoPendingResult, signature_result_);
      pending_read_error_ = ERR_IO_PENDING;
    } else {
      pending_read_error_ = MapOpenSSLErrorWithDetails(
          pending_read_ssl_error_, err_tracer, &pending_read_error_info_);
    }

    // Many servers do not reliably send a close_notify alert when shutting down
    // a connection, and instead terminate the TCP connection. This is reported
    // as ERR_CONNECTION_CLOSED. Because of this, map the unclean shutdown to a
    // graceful EOF, instead of treating it as an error as it should be.
    if (pending_read_error_ == ERR_CONNECTION_CLOSED)
      pending_read_error_ = 0;
  }

  if (total_bytes_read > 0) {
    // Return any bytes read to the caller. The error will be deferred to the
    // next call of DoPayloadRead.
    rv = total_bytes_read;

    // Do not treat insufficient data as an error to return in the next call to
    // DoPayloadRead() - instead, let the call fall through to check SSL_read()
    // again. This is because DoTransportIO() may complete in between the next
    // call to DoPayloadRead(), and thus it is important to check SSL_read() on
    // subsequent invocations to see if a complete record may now be read.
    if (pending_read_error_ == ERR_IO_PENDING)
      pending_read_error_ = kNoPendingResult;
  } else {
    // No bytes were returned. Return the pending read error immediately.
    DCHECK_NE(kNoPendingResult, pending_read_error_);
    rv = pending_read_error_;
    pending_read_error_ = kNoPendingResult;
  }

  if (rv >= 0) {
    net_log_.AddByteTransferEvent(NetLog::TYPE_SSL_SOCKET_BYTES_RECEIVED, rv,
                                  user_read_buf_->data());
  } else if (rv != ERR_IO_PENDING) {
    net_log_.AddEvent(
        NetLog::TYPE_SSL_READ_ERROR,
        CreateNetLogOpenSSLErrorCallback(rv, pending_read_ssl_error_,
                                         pending_read_error_info_));
    pending_read_ssl_error_ = SSL_ERROR_NONE;
    pending_read_error_info_ = OpenSSLErrorInfo();
  }
  return rv;
}

int SSLClientSocketImpl::DoPayloadWrite() {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  int rv = SSL_write(ssl_, user_write_buf_->data(), user_write_buf_len_);

  if (rv >= 0) {
    net_log_.AddByteTransferEvent(NetLog::TYPE_SSL_SOCKET_BYTES_SENT, rv,
                                  user_write_buf_->data());
    return rv;
  }

  int ssl_error = SSL_get_error(ssl_, rv);
  if (ssl_error == SSL_ERROR_WANT_PRIVATE_KEY_OPERATION)
    return ERR_IO_PENDING;
  OpenSSLErrorInfo error_info;
  int net_error =
      MapOpenSSLErrorWithDetails(ssl_error, err_tracer, &error_info);

  if (net_error != ERR_IO_PENDING) {
    net_log_.AddEvent(
        NetLog::TYPE_SSL_WRITE_ERROR,
        CreateNetLogOpenSSLErrorCallback(net_error, ssl_error, error_info));
  }
  return net_error;
}

void SSLClientSocketImpl::PumpReadWriteEvents() {
  int rv_read = ERR_IO_PENDING;
  int rv_write = ERR_IO_PENDING;
  bool network_moved;
  do {
    if (user_read_buf_.get())
      rv_read = DoPayloadRead();
    if (user_write_buf_.get())
      rv_write = DoPayloadWrite();
    network_moved = DoTransportIO();
  } while (rv_read == ERR_IO_PENDING && rv_write == ERR_IO_PENDING &&
           (user_read_buf_.get() || user_write_buf_.get()) && network_moved);

  // Performing the Read callback may cause |this| to be deleted. If this
  // happens, the Write callback should not be invoked. Guard against this by
  // holding a WeakPtr to |this| and ensuring it's still valid.
  base::WeakPtr<SSLClientSocketImpl> guard(weak_factory_.GetWeakPtr());
  if (user_read_buf_.get() && rv_read != ERR_IO_PENDING)
    DoReadCallback(rv_read);

  if (!guard.get())
    return;

  if (user_write_buf_.get() && rv_write != ERR_IO_PENDING)
    DoWriteCallback(rv_write);
}

int SSLClientSocketImpl::BufferSend(void) {
  if (transport_send_busy_)
    return ERR_IO_PENDING;

  size_t buffer_read_offset;
  uint8_t* read_buf;
  size_t max_read;
  int status = BIO_zero_copy_get_read_buf(transport_bio_, &read_buf,
                                          &buffer_read_offset, &max_read);
  DCHECK_EQ(status, 1);  // Should never fail.
  if (!max_read)
    return 0;  // Nothing pending in the OpenSSL write BIO.
  CHECK_EQ(read_buf, reinterpret_cast<uint8_t*>(send_buffer_->StartOfBuffer()));
  CHECK_LT(buffer_read_offset, static_cast<size_t>(send_buffer_->capacity()));
  send_buffer_->set_offset(buffer_read_offset);

  int rv = transport_->socket()->Write(
      send_buffer_.get(), max_read,
      base::Bind(&SSLClientSocketImpl::BufferSendComplete,
                 base::Unretained(this)));
  if (rv == ERR_IO_PENDING) {
    transport_send_busy_ = true;
  } else {
    TransportWriteComplete(rv);
  }
  return rv;
}

int SSLClientSocketImpl::BufferRecv(void) {
  if (transport_recv_busy_)
    return ERR_IO_PENDING;

  // Determine how much was requested from |transport_bio_| that was not
  // actually available.
  size_t requested = BIO_ctrl_get_read_request(transport_bio_);
  if (requested == 0) {
    // This is not a perfect match of error codes, as no operation is
    // actually pending. However, returning 0 would be interpreted as
    // a possible sign of EOF, which is also an inappropriate match.
    return ERR_IO_PENDING;
  }

  // Known Issue: While only reading |requested| data is the more correct
  // implementation, it has the downside of resulting in frequent reads:
  // One read for the SSL record header (~5 bytes) and one read for the SSL
  // record body. Rather than issuing these reads to the underlying socket
  // (and constantly allocating new IOBuffers), a single Read() request to
  // fill |transport_bio_| is issued. As long as an SSL client socket cannot
  // be gracefully shutdown (via SSL close alerts) and re-used for non-SSL
  // traffic, this over-subscribed Read()ing will not cause issues.

  size_t buffer_write_offset;
  uint8_t* write_buf;
  size_t max_write;
  int status = BIO_zero_copy_get_write_buf(transport_bio_, &write_buf,
                                           &buffer_write_offset, &max_write);
  DCHECK_EQ(status, 1);  // Should never fail.
  if (!max_write)
    return ERR_IO_PENDING;

  CHECK_EQ(write_buf,
           reinterpret_cast<uint8_t*>(recv_buffer_->StartOfBuffer()));
  CHECK_LT(buffer_write_offset, static_cast<size_t>(recv_buffer_->capacity()));

  recv_buffer_->set_offset(buffer_write_offset);
  int rv = transport_->socket()->Read(
      recv_buffer_.get(), max_write,
      base::Bind(&SSLClientSocketImpl::BufferRecvComplete,
                 base::Unretained(this)));
  if (rv == ERR_IO_PENDING) {
    transport_recv_busy_ = true;
  } else {
    rv = TransportReadComplete(rv);
  }
  return rv;
}

void SSLClientSocketImpl::BufferSendComplete(int result) {
  TransportWriteComplete(result);
  OnSendComplete(result);
}

void SSLClientSocketImpl::BufferRecvComplete(int result) {
  result = TransportReadComplete(result);
  OnRecvComplete(result);
}

void SSLClientSocketImpl::TransportWriteComplete(int result) {
  DCHECK(ERR_IO_PENDING != result);
  int bytes_written = 0;
  if (result < 0) {
    // Record the error. Save it to be reported in a future read or write on
    // transport_bio_'s peer.
    transport_write_error_ = result;
  } else {
    bytes_written = result;
  }
  DCHECK_GE(send_buffer_->RemainingCapacity(), bytes_written);
  int ret = BIO_zero_copy_get_read_buf_done(transport_bio_, bytes_written);
  DCHECK_EQ(1, ret);
  transport_send_busy_ = false;
}

int SSLClientSocketImpl::TransportReadComplete(int result) {
  DCHECK(ERR_IO_PENDING != result);
  // If an EOF, canonicalize to ERR_CONNECTION_CLOSED here so MapOpenSSLError
  // does not report success.
  if (result == 0)
    result = ERR_CONNECTION_CLOSED;
  int bytes_read = 0;
  if (result < 0) {
    DVLOG(1) << "TransportReadComplete result " << result;
    // Received an error. Save it to be reported in a future read on
    // transport_bio_'s peer.
    transport_read_error_ = result;
  } else {
    bytes_read = result;
  }
  DCHECK_GE(recv_buffer_->RemainingCapacity(), bytes_read);
  int ret = BIO_zero_copy_get_write_buf_done(transport_bio_, bytes_read);
  DCHECK_EQ(1, ret);
  transport_recv_busy_ = false;
  return result;
}

int SSLClientSocketImpl::ClientCertRequestCallback(SSL* ssl) {
  DVLOG(3) << "OpenSSL ClientCertRequestCallback called";
  DCHECK(ssl == ssl_);

  net_log_.AddEvent(NetLog::TYPE_SSL_CLIENT_CERT_REQUESTED);

  // Clear any currently configured certificates.
  SSL_certs_clear(ssl_);

#if defined(OS_IOS)
  // TODO(droger): Support client auth on iOS. See http://crbug.com/145954).
  LOG(WARNING) << "Client auth is not supported";
#else   // !defined(OS_IOS)
  if (!ssl_config_.send_client_cert) {
    // First pass: we know that a client certificate is needed, but we do not
    // have one at hand.
    STACK_OF(X509_NAME)* authorities = SSL_get_client_CA_list(ssl);
    for (size_t i = 0; i < sk_X509_NAME_num(authorities); i++) {
      X509_NAME* ca_name = (X509_NAME*)sk_X509_NAME_value(authorities, i);
      unsigned char* str = NULL;
      int length = i2d_X509_NAME(ca_name, &str);
      cert_authorities_.push_back(std::string(
          reinterpret_cast<const char*>(str), static_cast<size_t>(length)));
      OPENSSL_free(str);
    }

    const unsigned char* client_cert_types;
    size_t num_client_cert_types =
        SSL_get0_certificate_types(ssl, &client_cert_types);
    for (size_t i = 0; i < num_client_cert_types; i++) {
      cert_key_types_.push_back(
          static_cast<SSLClientCertType>(client_cert_types[i]));
    }

    // Suspends handshake. SSL_get_error will return SSL_ERROR_WANT_X509_LOOKUP.
    return -1;
  }

  // Second pass: a client certificate should have been selected.
  if (ssl_config_.client_cert.get()) {
    ScopedX509 leaf_x509 =
        OSCertHandleToOpenSSL(ssl_config_.client_cert->os_cert_handle());
    if (!leaf_x509) {
      LOG(WARNING) << "Failed to import certificate";
      OpenSSLPutNetError(FROM_HERE, ERR_SSL_CLIENT_AUTH_CERT_BAD_FORMAT);
      return -1;
    }

    ScopedX509Stack chain = OSCertHandlesToOpenSSL(
        ssl_config_.client_cert->GetIntermediateCertificates());
    if (!chain) {
      LOG(WARNING) << "Failed to import intermediate certificates";
      OpenSSLPutNetError(FROM_HERE, ERR_SSL_CLIENT_AUTH_CERT_BAD_FORMAT);
      return -1;
    }

    if (!SSL_use_certificate(ssl_, leaf_x509.get()) ||
        !SSL_set1_chain(ssl_, chain.get())) {
      LOG(WARNING) << "Failed to set client certificate";
      return -1;
    }

    if (!ssl_config_.client_private_key) {
      // The caller supplied a null private key. Fail the handshake and surface
      // an appropriate error to the caller.
      LOG(WARNING) << "Client cert found without private key";
      OpenSSLPutNetError(FROM_HERE, ERR_SSL_CLIENT_AUTH_CERT_NO_PRIVATE_KEY);
      return -1;
    }

    SSL_set_private_key_method(ssl_, &SSLContext::kPrivateKeyMethod);

    std::vector<SSLPrivateKey::Hash> digest_prefs =
        ssl_config_.client_private_key->GetDigestPreferences();

    size_t digests_len = digest_prefs.size();
    std::vector<int> digests;
    for (size_t i = 0; i < digests_len; i++) {
      switch (digest_prefs[i]) {
        case SSLPrivateKey::Hash::SHA1:
          digests.push_back(NID_sha1);
          break;
        case SSLPrivateKey::Hash::SHA256:
          digests.push_back(NID_sha256);
          break;
        case SSLPrivateKey::Hash::SHA384:
          digests.push_back(NID_sha384);
          break;
        case SSLPrivateKey::Hash::SHA512:
          digests.push_back(NID_sha512);
          break;
        case SSLPrivateKey::Hash::MD5_SHA1:
          // MD5-SHA1 is not used in TLS 1.2.
          break;
      }
    }

    SSL_set_private_key_digest_prefs(ssl_, digests.data(), digests.size());

    int cert_count = 1 + sk_X509_num(chain.get());
    net_log_.AddEvent(NetLog::TYPE_SSL_CLIENT_CERT_PROVIDED,
                      NetLog::IntCallback("cert_count", cert_count));
    return 1;
  }
#endif  // defined(OS_IOS)

  // Send no client certificate.
  net_log_.AddEvent(NetLog::TYPE_SSL_CLIENT_CERT_PROVIDED,
                    NetLog::IntCallback("cert_count", 0));
  return 1;
}

int SSLClientSocketImpl::CertVerifyCallback(X509_STORE_CTX* store_ctx) {
  if (!completed_connect_) {
    // If the first handshake hasn't completed then we accept any certificates
    // because we verify after the handshake.
    return 1;
  }

  // Disallow the server certificate to change in a renegotiation.
  if (server_cert_chain_->empty()) {
    LOG(ERROR) << "Received invalid certificate chain between handshakes";
    return 0;
  }
  base::StringPiece old_der, new_der;
  if (store_ctx->cert == NULL ||
      !x509_util::GetDER(server_cert_chain_->Get(0), &old_der) ||
      !x509_util::GetDER(store_ctx->cert, &new_der)) {
    LOG(ERROR) << "Failed to encode certificates";
    return 0;
  }
  if (old_der != new_der) {
    LOG(ERROR) << "Server certificate changed between handshakes";
    return 0;
  }

  return 1;
}

// SelectNextProtoCallback is called by OpenSSL during the handshake. If the
// server supports NPN, selects a protocol from the list that the server
// provides. According to third_party/boringssl/src/ssl/ssl_lib.c, the
// callback can assume that |in| is syntactically valid.
int SSLClientSocketImpl::SelectNextProtoCallback(unsigned char** out,
                                                 unsigned char* outlen,
                                                 const unsigned char* in,
                                                 unsigned int inlen) {
  if (ssl_config_.npn_protos.empty()) {
    *out = reinterpret_cast<uint8_t*>(
        const_cast<char*>(kDefaultSupportedNPNProtocol));
    *outlen = arraysize(kDefaultSupportedNPNProtocol) - 1;
    npn_status_ = kNextProtoUnsupported;
    return SSL_TLSEXT_ERR_OK;
  }

  // Assume there's no overlap between our protocols and the server's list.
  npn_status_ = kNextProtoNoOverlap;

  // For each protocol in server preference order, see if we support it.
  for (unsigned int i = 0; i < inlen; i += in[i] + 1) {
    for (NextProto next_proto : ssl_config_.npn_protos) {
      const std::string proto = NextProtoToString(next_proto);
      if (in[i] == proto.size() &&
          memcmp(&in[i + 1], proto.data(), in[i]) == 0) {
        // We found a match.
        *out = const_cast<unsigned char*>(in) + i + 1;
        *outlen = in[i];
        npn_status_ = kNextProtoNegotiated;
        break;
      }
    }
    if (npn_status_ == kNextProtoNegotiated)
      break;
  }

  // If we didn't find a protocol, we select the last one from our list.
  if (npn_status_ == kNextProtoNoOverlap) {
    // NextProtoToString returns a pointer to a static string.
    const char* proto = NextProtoToString(ssl_config_.npn_protos.back());
    *out = reinterpret_cast<unsigned char*>(const_cast<char*>(proto));
    *outlen = strlen(proto);
  }

  npn_proto_.assign(reinterpret_cast<const char*>(*out), *outlen);
  DVLOG(2) << "next protocol: '" << npn_proto_ << "' status: " << npn_status_;
  set_negotiation_extension(kExtensionNPN);
  return SSL_TLSEXT_ERR_OK;
}

long SSLClientSocketImpl::MaybeReplayTransportError(BIO* bio,
                                                    int cmd,
                                                    const char* argp,
                                                    int argi,
                                                    long argl,
                                                    long retvalue) {
  if (cmd == (BIO_CB_READ | BIO_CB_RETURN) && retvalue <= 0) {
    // If there is no more data in the buffer, report any pending errors that
    // were observed. Note that both the readbuf and the writebuf are checked
    // for errors, since the application may have encountered a socket error
    // while writing that would otherwise not be reported until the application
    // attempted to write again - which it may never do. See
    // https://crbug.com/249848.
    if (transport_read_error_ != OK) {
      OpenSSLPutNetError(FROM_HERE, transport_read_error_);
      return -1;
    }
    if (transport_write_error_ != OK) {
      OpenSSLPutNetError(FROM_HERE, transport_write_error_);
      return -1;
    }
  } else if (cmd == BIO_CB_WRITE) {
    // Because of the write buffer, this reports a failure from the previous
    // write payload. If the current payload fails to write, the error will be
    // reported in a future write or read to |bio|.
    if (transport_write_error_ != OK) {
      OpenSSLPutNetError(FROM_HERE, transport_write_error_);
      return -1;
    }
  }
  return retvalue;
}

// static
long SSLClientSocketImpl::BIOCallback(BIO* bio,
                                      int cmd,
                                      const char* argp,
                                      int argi,
                                      long argl,
                                      long retvalue) {
  SSLClientSocketImpl* socket =
      reinterpret_cast<SSLClientSocketImpl*>(BIO_get_callback_arg(bio));
  CHECK(socket);
  return socket->MaybeReplayTransportError(bio, cmd, argp, argi, argl,
                                           retvalue);
}

void SSLClientSocketImpl::MaybeCacheSession() {
  // Only cache the session once both a new session has been established and the
  // certificate has been verified. Due to False Start, these events may happen
  // in either order.
  if (!session_pending_ || !certificate_verified_)
    return;

  SSLContext::GetInstance()->session_cache()->Insert(GetSessionCacheKey(),
                                                     SSL_get_session(ssl_));
  session_pending_ = false;
}

int SSLClientSocketImpl::NewSessionCallback(SSL_SESSION* session) {
  DCHECK_EQ(session, SSL_get_session(ssl_));

  // Only sessions from the initial handshake get cached. Note this callback may
  // be signaled on abbreviated handshakes if the ticket was renewed.
  session_pending_ = true;
  MaybeCacheSession();

  // OpenSSL passes a reference to |session|, but the session cache does not
  // take this reference, so release it.
  SSL_SESSION_free(session);
  return 1;
}

void SSLClientSocketImpl::AddCTInfoToSSLInfo(SSLInfo* ssl_info) const {
  ssl_info->UpdateCertificateTransparencyInfo(ct_verify_result_);
}

std::string SSLClientSocketImpl::GetSessionCacheKey() const {
  std::string result = host_and_port_.ToString();
  result.append("/");
  result.append(ssl_session_cache_shard_);

  // Shard the session cache based on maximum protocol version. This causes
  // fallback connections to use a separate session cache.
  result.append("/");
  switch (ssl_config_.version_max) {
    case SSL_PROTOCOL_VERSION_TLS1:
      result.append("tls1");
      break;
    case SSL_PROTOCOL_VERSION_TLS1_1:
      result.append("tls1.1");
      break;
    case SSL_PROTOCOL_VERSION_TLS1_2:
      result.append("tls1.2");
      break;
    default:
      NOTREACHED();
  }

  result.append("/");
  if (ssl_config_.deprecated_cipher_suites_enabled)
    result.append("deprecated");

  result.append("/");
  if (ssl_config_.channel_id_enabled)
    result.append("channelid");

  return result;
}

bool SSLClientSocketImpl::IsRenegotiationAllowed() const {
  if (tb_was_negotiated_)
    return false;

  if (npn_status_ == kNextProtoUnsupported)
    return ssl_config_.renego_allowed_default;

  NextProto next_proto = NextProtoFromString(npn_proto_);
  for (NextProto allowed : ssl_config_.renego_allowed_for_protos) {
    if (next_proto == allowed)
      return true;
  }
  return false;
}

int SSLClientSocketImpl::PrivateKeyTypeCallback() {
  switch (ssl_config_.client_private_key->GetType()) {
    case SSLPrivateKey::Type::RSA:
      return EVP_PKEY_RSA;
    case SSLPrivateKey::Type::ECDSA:
      return EVP_PKEY_EC;
  }
  NOTREACHED();
  return EVP_PKEY_NONE;
}

size_t SSLClientSocketImpl::PrivateKeyMaxSignatureLenCallback() {
  return ssl_config_.client_private_key->GetMaxSignatureLengthInBytes();
}

ssl_private_key_result_t SSLClientSocketImpl::PrivateKeySignCallback(
    uint8_t* out,
    size_t* out_len,
    size_t max_out,
    const EVP_MD* md,
    const uint8_t* in,
    size_t in_len) {
  DCHECK_EQ(kNoPendingResult, signature_result_);
  DCHECK(signature_.empty());
  DCHECK(ssl_config_.client_private_key);

  SSLPrivateKey::Hash hash;
  if (!EVP_MDToPrivateKeyHash(md, &hash)) {
    OpenSSLPutNetError(FROM_HERE, ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED);
    return ssl_private_key_failure;
  }

  net_log_.BeginEvent(
      NetLog::TYPE_SSL_PRIVATE_KEY_OPERATION,
      base::Bind(&NetLogPrivateKeyOperationCallback,
                 ssl_config_.client_private_key->GetType(), hash));

  signature_result_ = ERR_IO_PENDING;
  ssl_config_.client_private_key->SignDigest(
      hash, base::StringPiece(reinterpret_cast<const char*>(in), in_len),
      base::Bind(&SSLClientSocketImpl::OnPrivateKeySignComplete,
                 weak_factory_.GetWeakPtr()));
  return ssl_private_key_retry;
}

ssl_private_key_result_t SSLClientSocketImpl::PrivateKeySignCompleteCallback(
    uint8_t* out,
    size_t* out_len,
    size_t max_out) {
  DCHECK_NE(kNoPendingResult, signature_result_);
  DCHECK(ssl_config_.client_private_key);

  if (signature_result_ == ERR_IO_PENDING)
    return ssl_private_key_retry;
  if (signature_result_ != OK) {
    OpenSSLPutNetError(FROM_HERE, signature_result_);
    return ssl_private_key_failure;
  }
  if (signature_.size() > max_out) {
    OpenSSLPutNetError(FROM_HERE, ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED);
    return ssl_private_key_failure;
  }
  memcpy(out, signature_.data(), signature_.size());
  *out_len = signature_.size();
  signature_.clear();
  return ssl_private_key_success;
}

void SSLClientSocketImpl::OnPrivateKeySignComplete(
    Error error,
    const std::vector<uint8_t>& signature) {
  DCHECK_EQ(ERR_IO_PENDING, signature_result_);
  DCHECK(signature_.empty());
  DCHECK(ssl_config_.client_private_key);

  net_log_.EndEventWithNetErrorCode(NetLog::TYPE_SSL_PRIVATE_KEY_OPERATION,
                                    error);

  signature_result_ = error;
  if (signature_result_ == OK)
    signature_ = signature;

  if (next_handshake_state_ == STATE_HANDSHAKE) {
    OnHandshakeIOComplete(signature_result_);
    return;
  }

  // During a renegotiation, either Read or Write calls may be blocked on an
  // asynchronous private key operation.
  PumpReadWriteEvents();
}

int SSLClientSocketImpl::TokenBindingAdd(const uint8_t** out,
                                         size_t* out_len,
                                         int* out_alert_value) {
  if (ssl_config_.token_binding_params.empty()) {
    return 0;
  }
  crypto::AutoCBB output;
  CBB parameters_list;
  if (!CBB_init(output.get(), 7) ||
      !CBB_add_u8(output.get(), kTbProtocolVersionMajor) ||
      !CBB_add_u8(output.get(), kTbProtocolVersionMinor) ||
      !CBB_add_u8_length_prefixed(output.get(), &parameters_list)) {
    *out_alert_value = SSL_AD_INTERNAL_ERROR;
    return -1;
  }
  for (size_t i = 0; i < ssl_config_.token_binding_params.size(); ++i) {
    if (!CBB_add_u8(&parameters_list, ssl_config_.token_binding_params[i])) {
      *out_alert_value = SSL_AD_INTERNAL_ERROR;
      return -1;
    }
  }
  // |*out| will be freed by TokenBindingFreeCallback.
  if (!CBB_finish(output.get(), const_cast<uint8_t**>(out), out_len)) {
    *out_alert_value = SSL_AD_INTERNAL_ERROR;
    return -1;
  }

  return 1;
}

int SSLClientSocketImpl::TokenBindingParse(const uint8_t* contents,
                                           size_t contents_len,
                                           int* out_alert_value) {
  if (completed_connect_) {
    // Token Binding may only be negotiated on the initial handshake.
    *out_alert_value = SSL_AD_ILLEGAL_PARAMETER;
    return 0;
  }

  CBS extension;
  CBS_init(&extension, contents, contents_len);

  CBS parameters_list;
  uint8_t version_major, version_minor, param;
  if (!CBS_get_u8(&extension, &version_major) ||
      !CBS_get_u8(&extension, &version_minor) ||
      !CBS_get_u8_length_prefixed(&extension, &parameters_list) ||
      !CBS_get_u8(&parameters_list, &param) || CBS_len(&parameters_list) > 0 ||
      CBS_len(&extension) > 0) {
    *out_alert_value = SSL_AD_DECODE_ERROR;
    return 0;
  }
  // The server-negotiated version must be less than or equal to our version.
  if (version_major > kTbProtocolVersionMajor ||
      (version_minor > kTbProtocolVersionMinor &&
       version_major == kTbProtocolVersionMajor)) {
    *out_alert_value = SSL_AD_ILLEGAL_PARAMETER;
    return 0;
  }
  // If the version the server negotiated is older than we support, don't fail
  // parsing the extension, but also don't set |negotiated_|.
  if (version_major < kTbMinProtocolVersionMajor ||
      (version_minor < kTbMinProtocolVersionMinor &&
       version_major == kTbMinProtocolVersionMajor)) {
    return 1;
  }

  for (size_t i = 0; i < ssl_config_.token_binding_params.size(); ++i) {
    if (param == ssl_config_.token_binding_params[i]) {
      tb_negotiated_param_ = ssl_config_.token_binding_params[i];
      tb_was_negotiated_ = true;
      return 1;
    }
  }

  *out_alert_value = SSL_AD_ILLEGAL_PARAMETER;
  return 0;
}

void SSLClientSocketImpl::LogConnectEndEvent(int rv) {
  if (rv != OK) {
    net_log_.EndEventWithNetErrorCode(NetLog::TYPE_SSL_CONNECT, rv);
    return;
  }

  net_log_.EndEvent(NetLog::TYPE_SSL_CONNECT,
                    base::Bind(&NetLogSSLInfoCallback, base::Unretained(this)));
}

}  // namespace net
