// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/ssl_client_socket_impl.h"

#include <errno.h>
#include <string.h>

#include <algorithm>
#include <utility>

#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/feature_list.h"
#include "base/lazy_instance.h"
#include "base/macros.h"
#include "base/memory/singleton.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "base/profiler/scoped_tracker.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_local.h"
#include "base/trace_event/process_memory_dump.h"
#include "base/trace_event/trace_event.h"
#include "base/values.h"
#include "crypto/ec_private_key.h"
#include "crypto/openssl_util.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"
#include "net/base/trace_constants.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_ev_whitelist.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/ct_verifier.h"
#include "net/cert/x509_certificate_net_log_param.h"
#include "net/cert/x509_util_openssl.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_parameters_callback.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_cipher_suite_names.h"
#include "net/ssl/ssl_client_session_cache.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_info.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/token_binding.h"
#include "third_party/boringssl/src/include/openssl/bio.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/err.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

#if !defined(OS_NACL)
#include "net/ssl/ssl_key_logger.h"
#endif

#if defined(USE_NSS_CERTS)
#include "net/cert_net/nss_ocsp.h"
#endif

namespace net {

namespace {

// This constant can be any non-negative/non-zero value (eg: it does not
// overlap with any value of the net::Error range, including net::OK).
const int kNoPendingResult = 1;

// Default size of the internal BoringSSL buffers.
const int kDefaultOpenSSLBufferSize = 17 * 1024;

// TLS extension number use for Token Binding.
const unsigned int kTbExtNum = 24;

// Token Binding ProtocolVersions supported.
const uint8_t kTbProtocolVersionMajor = 0;
const uint8_t kTbProtocolVersionMinor = 10;
const uint8_t kTbMinProtocolVersionMajor = 0;
const uint8_t kTbMinProtocolVersionMinor = 10;

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
    case SSLPrivateKey::Type::ECDSA_P256:
      type_str = "ECDSA_P256";
      break;
    case SSLPrivateKey::Type::ECDSA_P384:
      type_str = "ECDSA_P384";
      break;
    case SSLPrivateKey::Type::ECDSA_P521:
      type_str = "ECDSA_P521";
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
    std::string key_to_log = base::HexEncode(raw_key.data(), raw_key.length());
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

  dict->SetString("next_proto",
                  NextProtoToString(socket->GetNegotiatedProtocol()));

  return std::move(dict);
}

int GetBufferSize(const char* field_trial) {
  // Get buffer sizes from field trials, if possible. If values not present,
  // use default.  Also make sure values are in reasonable range.
  int buffer_size = kDefaultOpenSSLBufferSize;
#if !defined(OS_NACL)
  int override_buffer_size;
  if (base::StringToInt(base::FieldTrialList::FindFullName(field_trial),
                        &override_buffer_size)) {
    buffer_size = override_buffer_size;
    buffer_size = std::max(buffer_size, 1000);
    buffer_size = std::min(buffer_size, 2 * kDefaultOpenSSLBufferSize);
  }
#endif  // !defined(OS_NACL)
  return buffer_size;
}

#if defined(OS_NACL)
bool AreLegacyECDSACiphersEnabled() {
  return false;
}
#else
// TODO(davidben): Remove this after the ECDSA CBC removal sticks.
// https:/crbug.com/666191.
const base::Feature kLegacyECDSACiphersFeature{
    "SSLLegacyECDSACiphers", base::FEATURE_DISABLED_BY_DEFAULT};

bool AreLegacyECDSACiphersEnabled() {
  return base::FeatureList::IsEnabled(kLegacyECDSACiphersFeature);
}
#endif

const base::Feature kShortRecordHeaderFeature{
    "SSLShortRecordHeader", base::FEATURE_DISABLED_BY_DEFAULT};

}  // namespace

class SSLClientSocketImpl::SSLContext {
 public:
  static SSLContext* GetInstance() {
    return base::Singleton<SSLContext,
                           base::LeakySingletonTraits<SSLContext>>::get();
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

    // Disable the internal session cache. Session caching is handled
    // externally (i.e. by SSLClientSessionCache).
    SSL_CTX_set_session_cache_mode(
        ssl_ctx_.get(), SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
    SSL_CTX_sess_set_new_cb(ssl_ctx_.get(), NewSessionCallback);
    SSL_CTX_set_timeout(ssl_ctx_.get(), 1 * 60 * 60 /* one hour */);

    SSL_CTX_set_grease_enabled(ssl_ctx_.get(), 1);

    if (base::FeatureList::IsEnabled(kShortRecordHeaderFeature)) {
      SSL_CTX_set_short_header_enabled(ssl_ctx_.get(), 1);
    }

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

  static ssl_private_key_result_t PrivateKeySignDigestCallback(
      SSL* ssl,
      uint8_t* out,
      size_t* out_len,
      size_t max_out,
      const EVP_MD* md,
      const uint8_t* in,
      size_t in_len) {
    SSLClientSocketImpl* socket = GetInstance()->GetClientSocketFromSSL(ssl);
    return socket->PrivateKeySignDigestCallback(out, out_len, max_out, md, in,
                                                in_len);
  }

  static ssl_private_key_result_t PrivateKeyCompleteCallback(SSL* ssl,
                                                             uint8_t* out,
                                                             size_t* out_len,
                                                             size_t max_out) {
    SSLClientSocketImpl* socket = GetInstance()->GetClientSocketFromSSL(ssl);
    return socket->PrivateKeyCompleteCallback(out, out_len, max_out);
  }

#if !defined(OS_NACL)
  static void KeyLogCallback(const SSL* ssl, const char* line) {
    GetInstance()->ssl_key_logger_->WriteLine(line);
  }
#endif

  // This is the index used with SSL_get_ex_data to retrieve the owner
  // SSLClientSocketImpl object from an SSL instance.
  int ssl_socket_data_index_;

  bssl::UniquePtr<SSL_CTX> ssl_ctx_;

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

// TODO(davidben): Switch from sign_digest to sign.
const SSL_PRIVATE_KEY_METHOD
    SSLClientSocketImpl::SSLContext::kPrivateKeyMethod = {
        &SSLClientSocketImpl::SSLContext::PrivateKeyTypeCallback,
        &SSLClientSocketImpl::SSLContext::PrivateKeyMaxSignatureLenCallback,
        nullptr /* sign */,
        &SSLClientSocketImpl::SSLContext::PrivateKeySignDigestCallback,
        nullptr /* decrypt */,
        &SSLClientSocketImpl::SSLContext::PrivateKeyCompleteCallback,
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
  bssl::UniquePtr<STACK_OF(X509)> openssl_chain_;
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
  // DER-encode the chain and convert to a platform certificate handle.
  std::vector<std::string> chain;
  chain.reserve(sk_X509_num(openssl_chain_.get()));
  for (size_t i = 0; i < sk_X509_num(openssl_chain_.get()); ++i) {
    X509* x = sk_X509_value(openssl_chain_.get(), i);
    // Note: This intentionally avoids using x509_util::GetDER(), which may
    // cache the encoded DER on |x|, as |x| is shared with the underlying
    // socket (SSL*) this chain belongs to. As the DER will only be used
    // once in //net, within this code, this avoids needlessly caching
    // additional data. See https://crbug.com/642082
    int len = i2d_X509(x, nullptr);
    if (len < 0)
      return nullptr;
    std::string cert;
    uint8_t* ptr = reinterpret_cast<uint8_t*>(base::WriteInto(&cert, len + 1));
    len = i2d_X509(x, &ptr);
    if (len < 0) {
      NOTREACHED();
      return nullptr;
    }
    chain.push_back(std::move(cert));
  }
  std::vector<base::StringPiece> stringpiece_chain;
  for (const auto& cert : chain)
    stringpiece_chain.push_back(cert);

  return X509Certificate::CreateFromDERCertChain(stringpiece_chain);
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
    : pending_read_error_(kNoPendingResult),
      pending_read_ssl_error_(SSL_ERROR_NONE),
      server_cert_chain_(new PeerCertificateChain(NULL)),
      completed_connect_(false),
      was_ever_used_(false),
      cert_verifier_(context.cert_verifier),
      cert_transparency_verifier_(context.cert_transparency_verifier),
      channel_id_service_(context.channel_id_service),
      tb_was_negotiated_(false),
      tb_negotiated_param_(TB_PARAM_ECDSAP256),
      tb_signature_map_(10),
      transport_(std::move(transport_socket)),
      host_and_port_(host_and_port),
      ssl_config_(ssl_config),
      ssl_session_cache_shard_(context.ssl_session_cache_shard),
      next_handshake_state_(STATE_NONE),
      disconnected_(false),
      negotiated_protocol_(kProtoUnknown),
      channel_id_sent_(false),
      certificate_verified_(false),
      certificate_requested_(false),
      signature_result_(kNoPendingResult),
      transport_security_state_(context.transport_security_state),
      policy_enforcer_(context.ct_policy_enforcer),
      pkp_bypassed_(false),
      net_log_(transport_->socket()->NetLog()),
      weak_factory_(this) {
  CHECK(cert_verifier_);
  CHECK(transport_security_state_);
  CHECK(cert_transparency_verifier_);
  CHECK(policy_enforcer_);
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
  if (!ssl_) {
    NOTREACHED();
    return;
  }

  cert_request_info->host_and_port = host_and_port_;

  cert_request_info->cert_authorities.clear();
  STACK_OF(X509_NAME)* authorities = SSL_get_client_CA_list(ssl_.get());
  for (size_t i = 0; i < sk_X509_NAME_num(authorities); i++) {
    X509_NAME* ca_name = sk_X509_NAME_value(authorities, i);
    uint8_t* str = nullptr;
    int length = i2d_X509_NAME(ca_name, &str);
    if (length > 0) {
      cert_request_info->cert_authorities.push_back(std::string(
          reinterpret_cast<const char*>(str), static_cast<size_t>(length)));
    } else {
      NOTREACHED();  // Error serializing |ca_name|.
    }
    OPENSSL_free(str);
  }

  cert_request_info->cert_key_types.clear();
  const uint8_t* client_cert_types;
  size_t num_client_cert_types =
      SSL_get0_certificate_types(ssl_.get(), &client_cert_types);
  for (size_t i = 0; i < num_client_cert_types; i++) {
    cert_request_info->cert_key_types.push_back(
        static_cast<SSLClientCertType>(client_cert_types[i]));
  }
}

ChannelIDService* SSLClientSocketImpl::GetChannelIDService() const {
  return channel_id_service_;
}

Error SSLClientSocketImpl::GetTokenBindingSignature(crypto::ECPrivateKey* key,
                                                    TokenBindingType tb_type,
                                                    std::vector<uint8_t>* out) {
  // The same key will be used across multiple requests to sign the same value,
  // so the signature is cached.
  std::string raw_public_key;
  if (!key->ExportRawPublicKey(&raw_public_key))
    return ERR_FAILED;
  auto it = tb_signature_map_.Get(std::make_pair(tb_type, raw_public_key));
  if (it != tb_signature_map_.end()) {
    *out = it->second;
    return OK;
  }

  uint8_t tb_ekm_buf[32];
  static const char kTokenBindingExporterLabel[] = "EXPORTER-Token-Binding";
  if (!SSL_export_keying_material(ssl_.get(), tb_ekm_buf, sizeof(tb_ekm_buf),
                                  kTokenBindingExporterLabel,
                                  strlen(kTokenBindingExporterLabel), nullptr,
                                  0, false /* no context */)) {
    return ERR_FAILED;
  }

  if (!CreateTokenBindingSignature(
          base::StringPiece(reinterpret_cast<char*>(tb_ekm_buf),
                            sizeof(tb_ekm_buf)),
          tb_type, key, out))
    return ERR_FAILED;

  tb_signature_map_.Put(std::make_pair(tb_type, raw_public_key), *out);
  return OK;
}

crypto::ECPrivateKey* SSLClientSocketImpl::GetChannelIDKey() const {
  return channel_id_key_.get();
}

int SSLClientSocketImpl::ExportKeyingMaterial(const base::StringPiece& label,
                                              bool has_context,
                                              const base::StringPiece& context,
                                              unsigned char* out,
                                              unsigned int outlen) {
  if (!IsConnected())
    return ERR_SOCKET_NOT_CONNECTED;

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  if (!SSL_export_keying_material(
          ssl_.get(), out, outlen, label.data(), label.size(),
          reinterpret_cast<const unsigned char*>(context.data()),
          context.length(), has_context ? 1 : 0)) {
    LOG(ERROR) << "Failed to export keying material.";
    return ERR_FAILED;
  }

  return OK;
}

int SSLClientSocketImpl::Connect(const CompletionCallback& callback) {
  // Although StreamSocket does allow calling Connect() after Disconnect(),
  // this has never worked for layered sockets. CHECK to detect any consumers
  // reconnecting an SSL socket.
  //
  // TODO(davidben,mmenke): Remove this API feature. See
  // https://crbug.com/499289.
  CHECK(!disconnected_);

  net_log_.BeginEvent(NetLogEventType::SSL_CONNECT);

  // Set up new ssl object.
  int rv = Init();
  if (rv != OK) {
    LogConnectEndEvent(rv);
    return rv;
  }

  // Set SSL to client mode. Handshake happens in the loop below.
  SSL_set_connect_state(ssl_.get());

  next_handshake_state_ = STATE_HANDSHAKE;
  rv = DoHandshakeLoop(OK);
  if (rv == ERR_IO_PENDING) {
    user_connect_callback_ = callback;
  } else {
    LogConnectEndEvent(rv);
  }

  return rv > OK ? OK : rv;
}

void SSLClientSocketImpl::Disconnect() {
  disconnected_ = true;

  // Shut down anything that may call us back.
  cert_verifier_request_.reset();
  channel_id_request_.Cancel();
  weak_factory_.InvalidateWeakPtrs();
  transport_adapter_.reset();

  // Release user callbacks.
  user_connect_callback_.Reset();
  user_read_callback_.Reset();
  user_write_callback_.Reset();
  user_read_buf_ = NULL;
  user_read_buf_len_ = 0;
  user_write_buf_ = NULL;
  user_write_buf_len_ = 0;

  transport_->socket()->Disconnect();
}

bool SSLClientSocketImpl::IsConnected() const {
  // If the handshake has not yet completed or the socket has been explicitly
  // disconnected.
  if (!completed_connect_ || disconnected_)
    return false;
  // If an asynchronous operation is still pending.
  if (user_read_buf_.get() || user_write_buf_.get())
    return true;

  return transport_->socket()->IsConnected();
}

bool SSLClientSocketImpl::IsConnectedAndIdle() const {
  // If the handshake has not yet completed or the socket has been explicitly
  // disconnected.
  if (!completed_connect_ || disconnected_)
    return false;
  // If an asynchronous operation is still pending.
  if (user_read_buf_.get() || user_write_buf_.get())
    return false;

  // If there is data read from the network that has not yet been consumed, do
  // not treat the connection as idle.
  //
  // Note that this does not check whether there is ciphertext that has not yet
  // been flushed to the network. |Write| returns early, so this can cause race
  // conditions which cause a socket to not be treated reusable when it should
  // be. See https://crbug.com/466147.
  if (transport_adapter_->HasPendingReadData())
    return false;

  return transport_->socket()->IsConnectedAndIdle();
}

int SSLClientSocketImpl::GetPeerAddress(IPEndPoint* addressList) const {
  return transport_->socket()->GetPeerAddress(addressList);
}

int SSLClientSocketImpl::GetLocalAddress(IPEndPoint* addressList) const {
  return transport_->socket()->GetLocalAddress(addressList);
}

const NetLogWithSource& SSLClientSocketImpl::NetLog() const {
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

bool SSLClientSocketImpl::WasAlpnNegotiated() const {
  return negotiated_protocol_ != kProtoUnknown;
}

NextProto SSLClientSocketImpl::GetNegotiatedProtocol() const {
  return negotiated_protocol_;
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
  ssl_info->pkp_bypassed = pkp_bypassed_;
  ssl_info->public_key_hashes = server_cert_verify_result_.public_key_hashes;
  ssl_info->client_cert_sent =
      ssl_config_.send_client_cert && ssl_config_.client_cert.get();
  ssl_info->channel_id_sent = channel_id_sent_;
  ssl_info->token_binding_negotiated = tb_was_negotiated_;
  ssl_info->token_binding_key_param = tb_negotiated_param_;
  ssl_info->pinning_failure_log = pinning_failure_log_;
  ssl_info->ocsp_result = server_cert_verify_result_.ocsp_result;

  AddCTInfoToSSLInfo(ssl_info);

  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_.get());
  CHECK(cipher);
  ssl_info->security_bits = SSL_CIPHER_get_bits(cipher, NULL);
  // Historically, the "group" was known as "curve".
  ssl_info->key_exchange_group = SSL_get_curve_id(ssl_.get());

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

void SSLClientSocketImpl::GetConnectionAttempts(ConnectionAttempts* out) const {
  out->clear();
}

int64_t SSLClientSocketImpl::GetTotalReceivedBytes() const {
  return transport_->socket()->GetTotalReceivedBytes();
}

void SSLClientSocketImpl::DumpMemoryStats(SocketMemoryStats* stats) const {
  if (transport_adapter_)
    stats->buffer_size = transport_adapter_->GetAllocationSize();
  if (server_cert_chain_) {
    for (size_t i = 0; i < server_cert_chain_->size(); ++i) {
      X509* cert = server_cert_chain_->Get(i);
      // This measures the lower bound of the serialized certificate. It doesn't
      // measure the actual memory used, which is 4x this amount (see
      // crbug.com/671420 for more details).
      stats->serialized_cert_size += i2d_X509(cert, nullptr);
    }
    stats->cert_count = server_cert_chain_->size();
  }
  stats->total_size = stats->buffer_size + stats->serialized_cert_size;
}

// static
void SSLClientSocketImpl::DumpSSLClientSessionMemoryStats(
    base::trace_event::ProcessMemoryDump* pmd) {
  SSLContext::GetInstance()->session_cache()->DumpMemoryStats(pmd);
}

int SSLClientSocketImpl::Read(IOBuffer* buf,
                              int buf_len,
                              const CompletionCallback& callback) {
  user_read_buf_ = buf;
  user_read_buf_len_ = buf_len;

  int rv = DoPayloadRead();

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

  int rv = DoPayloadWrite();

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

void SSLClientSocketImpl::OnReadReady() {
  // During a renegotiation, either Read or Write calls may be blocked on a
  // transport read.
  RetryAllOperations();
}

void SSLClientSocketImpl::OnWriteReady() {
  // During a renegotiation, either Read or Write calls may be blocked on a
  // transport read.
  RetryAllOperations();
}

int SSLClientSocketImpl::Init() {
  DCHECK(!ssl_);

#if defined(USE_NSS_CERTS)
  if (ssl_config_.cert_io_enabled) {
    // TODO(davidben): Move this out of SSLClientSocket. See
    // https://crbug.com/539520.
    EnsureNSSHttpIOInit();
  }
#endif

  SSLContext* context = SSLContext::GetInstance();
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  ssl_.reset(SSL_new(context->ssl_ctx()));
  if (!ssl_ || !context->SetClientSocketForSSL(ssl_.get(), this))
    return ERR_UNEXPECTED;

  // SNI should only contain valid DNS hostnames, not IP addresses (see RFC
  // 6066, Section 3).
  //
  // TODO(rsleevi): Should this code allow hostnames that violate the LDH rule?
  // See https://crbug.com/496472 and https://crbug.com/496468 for discussion.
  IPAddress unused;
  if (!unused.AssignFromIPLiteral(host_and_port_.host()) &&
      !SSL_set_tlsext_host_name(ssl_.get(), host_and_port_.host().c_str())) {
    return ERR_UNEXPECTED;
  }

  bssl::UniquePtr<SSL_SESSION> session = context->session_cache()->Lookup(
      GetSessionCacheKey(), &ssl_session_cache_lookup_count_);
  if (session)
    SSL_set_session(ssl_.get(), session.get());

  transport_adapter_.reset(new SocketBIOAdapter(
      transport_->socket(), GetBufferSize("SSLBufferSizeRecv"),
      GetBufferSize("SSLBufferSizeSend"), this));
  BIO* transport_bio = transport_adapter_->bio();

  BIO_up_ref(transport_bio);  // SSL_set0_rbio takes ownership.
  SSL_set0_rbio(ssl_.get(), transport_bio);

  BIO_up_ref(transport_bio);  // SSL_set0_wbio takes ownership.
  SSL_set0_wbio(ssl_.get(), transport_bio);

  DCHECK_LT(SSL3_VERSION, ssl_config_.version_min);
  DCHECK_LT(SSL3_VERSION, ssl_config_.version_max);
  if (!SSL_set_min_proto_version(ssl_.get(), ssl_config_.version_min) ||
      !SSL_set_max_proto_version(ssl_.get(), ssl_config_.version_max)) {
    return ERR_UNEXPECTED;
  }

  // OpenSSL defaults some options to on, others to off. To avoid ambiguity,
  // set everything we care about to an absolute value.
  SslSetClearMask options;
  options.ConfigureFlag(SSL_OP_NO_COMPRESSION, true);

  // TODO(joth): Set this conditionally, see http://crbug.com/55410
  options.ConfigureFlag(SSL_OP_LEGACY_SERVER_CONNECT, true);

  SSL_set_options(ssl_.get(), options.set_mask);
  SSL_clear_options(ssl_.get(), options.clear_mask);

  // Same as above, this time for the SSL mode.
  SslSetClearMask mode;

  mode.ConfigureFlag(SSL_MODE_RELEASE_BUFFERS, true);
  mode.ConfigureFlag(SSL_MODE_CBC_RECORD_SPLITTING, true);

  mode.ConfigureFlag(SSL_MODE_ENABLE_FALSE_START,
                     ssl_config_.false_start_enabled);

  SSL_set_mode(ssl_.get(), mode.set_mask);
  SSL_clear_mode(ssl_.get(), mode.clear_mask);

  // Use BoringSSL defaults, but disable HMAC-SHA256 and HMAC-SHA384 ciphers
  // (note that SHA256 and SHA384 only select legacy CBC ciphers). Also disable
  // DHE_RSA_WITH_AES_256_GCM_SHA384. Historically, AES_256_GCM was not
  // supported. As DHE is being deprecated, don't add a cipher only to remove
  // it immediately.
  //
  // TODO(davidben): Remove the DHE_RSA_WITH_AES_256_GCM_SHA384 exclusion when
  // the DHEEnabled administrative policy expires.
  std::string command(
      "ALL:!SHA256:!SHA384:!DHE-RSA-AES256-GCM-SHA384:!aPSK:!RC4");

  if (ssl_config_.require_ecdhe)
    command.append(":!kRSA:!kDHE");

  if (!ssl_config_.deprecated_cipher_suites_enabled) {
    // Only offer DHE on the second handshake. https://crbug.com/538690
    command.append(":!kDHE");
  }

  // Additionally disable HMAC-SHA1 ciphers in ECDSA. These are the remaining
  // CBC-mode ECDSA ciphers.
  if (!AreLegacyECDSACiphersEnabled())
    command.append("!ECDSA+SHA1");

  // Remove any disabled ciphers.
  for (uint16_t id : ssl_config_.disabled_cipher_suites) {
    const SSL_CIPHER* cipher = SSL_get_cipher_by_value(id);
    if (cipher) {
      command.append(":!");
      command.append(SSL_CIPHER_get_name(cipher));
    }
  }

  int rv = SSL_set_cipher_list(ssl_.get(), command.c_str());
  // If this fails (rv = 0) it means there are no ciphers enabled on this SSL.
  // This will almost certainly result in the socket failing to complete the
  // handshake at which point the appropriate error is bubbled up to the client.
  LOG_IF(WARNING, rv != 1) << "SSL_set_cipher_list('" << command << "') "
                                                                    "returned "
                           << rv;

  // TLS channel ids.
  if (IsChannelIDEnabled()) {
    SSL_enable_tls_channel_id(ssl_.get());
  }

  if (!ssl_config_.alpn_protos.empty()) {
    std::vector<uint8_t> wire_protos =
        SerializeNextProtos(ssl_config_.alpn_protos);
    SSL_set_alpn_protos(ssl_.get(),
                        wire_protos.empty() ? NULL : &wire_protos[0],
                        wire_protos.size());
  }

  if (ssl_config_.signed_cert_timestamps_enabled) {
    SSL_enable_signed_cert_timestamps(ssl_.get());
    SSL_enable_ocsp_stapling(ssl_.get());
  }

  if (cert_verifier_->SupportsOCSPStapling())
    SSL_enable_ocsp_stapling(ssl_.get());

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
    rv = SSL_do_handshake(ssl_.get());
  } else {
    if (g_first_run_completed.Get().Get()) {
      // TODO(cbentzel): Remove ScopedTracker below once crbug.com/424386 is
      // fixed.
      tracked_objects::ScopedTracker tracking_profile(
          FROM_HERE_WITH_EXPLICIT_FUNCTION("424386 SSL_do_handshake()"));

      rv = SSL_do_handshake(ssl_.get());
    } else {
      g_first_run_completed.Get().Set(true);
      rv = SSL_do_handshake(ssl_.get());
    }
  }

  int net_error = OK;
  if (rv <= 0) {
    int ssl_error = SSL_get_error(ssl_.get(), rv);
    if (ssl_error == SSL_ERROR_WANT_CHANNEL_ID_LOOKUP) {
      // The server supports channel ID. Stop to look one up before returning to
      // the handshake.
      next_handshake_state_ = STATE_CHANNEL_ID_LOOKUP;
      return OK;
    }
    if (ssl_error == SSL_ERROR_WANT_X509_LOOKUP &&
        !ssl_config_.send_client_cert) {
      return ERR_SSL_CLIENT_AUTH_CERT_NEEDED;
    }
    if (ssl_error == SSL_ERROR_WANT_PRIVATE_KEY_OPERATION) {
      DCHECK(ssl_config_.client_private_key);
      DCHECK_NE(kNoPendingResult, signature_result_);
      next_handshake_state_ = STATE_HANDSHAKE;
      return ERR_IO_PENDING;
    }

    OpenSSLErrorInfo error_info;
    net_error = MapLastOpenSSLError(ssl_error, err_tracer, &error_info);
    if (net_error == ERR_IO_PENDING) {
      // If not done, stay in this state
      next_handshake_state_ = STATE_HANDSHAKE;
      return ERR_IO_PENDING;
    }

    LOG(ERROR) << "handshake failed; returned " << rv << ", SSL error code "
               << ssl_error << ", net_error " << net_error;
    net_log_.AddEvent(
        NetLogEventType::SSL_HANDSHAKE_ERROR,
        CreateNetLogOpenSSLErrorCallback(net_error, ssl_error, error_info));
  }

  next_handshake_state_ = STATE_HANDSHAKE_COMPLETE;
  return net_error;
}

int SSLClientSocketImpl::DoHandshakeComplete(int result) {
  if (result < 0)
    return result;

  SSLContext::GetInstance()->session_cache()->ResetLookupCount(
      GetSessionCacheKey());
  // If we got a session from the session cache, log how many concurrent
  // handshakes that session was used in before we finished our handshake. This
  // is only recorded if the session from the cache was actually used, and only
  // if the ALPN protocol is h2 (under the assumption that TLS 1.3 servers will
  // be speaking h2). See https://crbug.com/631988.
  if (ssl_session_cache_lookup_count_ && negotiated_protocol_ == kProtoHTTP2 &&
      SSL_session_reused(ssl_.get())) {
    UMA_HISTOGRAM_EXACT_LINEAR("Net.SSLSessionConcurrentLookupCount",
                               ssl_session_cache_lookup_count_, 20);
  }

  // DHE is offered on the deprecated cipher fallback and then rejected
  // afterwards. This is to aid in diagnosing connection failures because a
  // server requires DHE ciphers.
  //
  // TODO(davidben): A few releases after DHE's removal, remove this logic.
  if (!ssl_config_.dhe_enabled &&
      SSL_CIPHER_is_DHE(SSL_get_current_cipher(ssl_.get()))) {
    return ERR_SSL_OBSOLETE_CIPHER;
  }

  // Check that if token binding was negotiated, then extended master secret
  // and renegotiation indication must also be negotiated.
  if (tb_was_negotiated_ &&
      !(SSL_get_extms_support(ssl_.get()) &&
        SSL_get_secure_renegotiation_support(ssl_.get()))) {
    return ERR_SSL_PROTOCOL_ERROR;
  }

  const uint8_t* alpn_proto = NULL;
  unsigned alpn_len = 0;
  SSL_get0_alpn_selected(ssl_.get(), &alpn_proto, &alpn_len);
  if (alpn_len > 0) {
    base::StringPiece proto(reinterpret_cast<const char*>(alpn_proto),
                            alpn_len);
    negotiated_protocol_ = NextProtoFromString(proto);
  }

  RecordNegotiatedProtocol();
  RecordChannelIDSupport();

  const uint8_t* ocsp_response_raw;
  size_t ocsp_response_len;
  SSL_get0_ocsp_response(ssl_.get(), &ocsp_response_raw, &ocsp_response_len);
  set_stapled_ocsp_response_received(ocsp_response_len != 0);
  UMA_HISTOGRAM_BOOLEAN("Net.OCSPResponseStapled", ocsp_response_len != 0);

  const uint8_t* sct_list;
  size_t sct_list_len;
  SSL_get0_signed_cert_timestamp_list(ssl_.get(), &sct_list, &sct_list_len);
  set_signed_cert_timestamps_received(sct_list_len != 0);

  if (IsRenegotiationAllowed())
    SSL_set_renegotiate_mode(ssl_.get(), ssl_renegotiate_freely);

  uint16_t signature_algorithm = SSL_get_peer_signature_algorithm(ssl_.get());
  if (signature_algorithm != 0) {
    UMA_HISTOGRAM_SPARSE_SLOWLY("Net.SSLSignatureAlgorithm",
                                signature_algorithm);
  }

  // Verify the certificate.
  UpdateServerCert();
  next_handshake_state_ = STATE_VERIFY_CERT;
  return OK;
}

int SSLClientSocketImpl::DoChannelIDLookup() {
  NetLogParametersCallback callback = base::Bind(
      &NetLogChannelIDLookupCallback, base::Unretained(channel_id_service_));
  net_log_.BeginEvent(NetLogEventType::SSL_GET_CHANNEL_ID, callback);
  next_handshake_state_ = STATE_CHANNEL_ID_LOOKUP_COMPLETE;
  return channel_id_service_->GetOrCreateChannelID(
      host_and_port_.host(), &channel_id_key_,
      base::Bind(&SSLClientSocketImpl::OnHandshakeIOComplete,
                 base::Unretained(this)),
      &channel_id_request_);
}

int SSLClientSocketImpl::DoChannelIDLookupComplete(int result) {
  net_log_.EndEvent(NetLogEventType::SSL_GET_CHANNEL_ID,
                    base::Bind(&NetLogChannelIDLookupCompleteCallback,
                               channel_id_key_.get(), result));
  if (result < 0)
    return result;

  // Hand the key to OpenSSL. Check for error in case OpenSSL rejects the key
  // type.
  DCHECK(channel_id_key_);
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  if (!SSL_set1_tls_channel_id(ssl_.get(), channel_id_key_->key())) {
    LOG(ERROR) << "Failed to set Channel ID.";
    return ERR_FAILED;
  }

  // Return to the handshake.
  channel_id_sent_ = true;
  next_handshake_state_ = STATE_HANDSHAKE;
  return OK;
}

int SSLClientSocketImpl::DoVerifyCert(int result) {
  DCHECK(!server_cert_chain_->empty());
  DCHECK(start_cert_verification_time_.is_null());

  next_handshake_state_ = STATE_VERIFY_CERT_COMPLETE;

  // OpenSSL decoded the certificate, but the platform certificate
  // implementation could not. This is treated as a fatal SSL-level protocol
  // error rather than a certificate error. See https://crbug.com/91341.
  if (!server_cert_)
    return ERR_SSL_SERVER_CERT_BAD_FORMAT;

  // If the certificate is bad and has been previously accepted, use
  // the previous status and bypass the error.
  CertStatus cert_status;
  if (ssl_config_.IsAllowedBadCert(server_cert_.get(), &cert_status)) {
    server_cert_verify_result_.Reset();
    server_cert_verify_result_.cert_status = cert_status;
    server_cert_verify_result_.verified_cert = server_cert_;
    return OK;
  }

  start_cert_verification_time_ = base::TimeTicks::Now();

  const uint8_t* ocsp_response_raw;
  size_t ocsp_response_len;
  SSL_get0_ocsp_response(ssl_.get(), &ocsp_response_raw, &ocsp_response_len);
  base::StringPiece ocsp_response(
      reinterpret_cast<const char*>(ocsp_response_raw), ocsp_response_len);

  return cert_verifier_->Verify(
      CertVerifier::RequestParams(server_cert_, host_and_port_.host(),
                                  ssl_config_.GetCertVerifyFlags(),
                                  ocsp_response.as_string(), CertificateList()),
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

  // If the connection was good, check HPKP and CT status simultaneously,
  // but prefer to treat the HPKP error as more serious, if there was one.
  const CertStatus cert_status = server_cert_verify_result_.cert_status;
  if ((result == OK ||
       (IsCertificateError(result) && IsCertStatusMinorError(cert_status)))) {
    int ct_result = VerifyCT();
    TransportSecurityState::PKPStatus pin_validity =
        transport_security_state_->CheckPublicKeyPins(
            host_and_port_, server_cert_verify_result_.is_issued_by_known_root,
            server_cert_verify_result_.public_key_hashes, server_cert_.get(),
            server_cert_verify_result_.verified_cert.get(),
            TransportSecurityState::ENABLE_PIN_REPORTS, &pinning_failure_log_);
    switch (pin_validity) {
      case TransportSecurityState::PKPStatus::VIOLATED:
        server_cert_verify_result_.cert_status |=
            CERT_STATUS_PINNED_KEY_MISSING;
        result = ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN;
        break;
      case TransportSecurityState::PKPStatus::BYPASSED:
        pkp_bypassed_ = true;
      // Fall through.
      case TransportSecurityState::PKPStatus::OK:
        // Do nothing.
        break;
    }
    if (result != ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN && ct_result != OK)
      result = ct_result;
  }

  if (result == OK) {
    DCHECK(!certificate_verified_);
    certificate_verified_ = true;
    MaybeCacheSession();
    SSLInfo ssl_info;
    bool ok = GetSSLInfo(&ssl_info);
    DCHECK(ok);

    const uint8_t* ocsp_response_raw;
    size_t ocsp_response_len;
    SSL_get0_ocsp_response(ssl_.get(), &ocsp_response_raw, &ocsp_response_len);
    base::StringPiece ocsp_response(
        reinterpret_cast<const char*>(ocsp_response_raw), ocsp_response_len);

    transport_security_state_->CheckExpectStaple(host_and_port_, ssl_info,
                                                 ocsp_response);
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
  server_cert_chain_->Reset(SSL_get_peer_cert_chain(ssl_.get()));
  server_cert_ = server_cert_chain_->AsOSChain();
  if (server_cert_.get()) {
    net_log_.AddEvent(NetLogEventType::SSL_CERTIFICATES_RECEIVED,
                      base::Bind(&NetLogX509CertificateCallback,
                                 base::Unretained(server_cert_.get())));
  }
}

void SSLClientSocketImpl::OnHandshakeIOComplete(int result) {
  int rv = DoHandshakeLoop(result);
  if (rv != ERR_IO_PENDING) {
    LogConnectEndEvent(rv);
    DoConnectCallback(rv);
  }
}

int SSLClientSocketImpl::DoHandshakeLoop(int last_io_result) {
  TRACE_EVENT0(kNetTracingCategory, "SSLClientSocketImpl::DoHandshakeLoop");
  int rv = last_io_result;
  do {
    // Default to STATE_NONE for next state.
    // (This is a quirk carried over from the windows
    // implementation.  It makes reading the logs a bit harder.)
    // State handlers can and often do call GotoState just
    // to stay in the current state.
    State state = next_handshake_state_;
    next_handshake_state_ = STATE_NONE;
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
  } while (rv != ERR_IO_PENDING && next_handshake_state_ != STATE_NONE);
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
      net_log_.AddByteTransferEvent(NetLogEventType::SSL_SOCKET_BYTES_RECEIVED,
                                    rv, user_read_buf_->data());
    } else {
      net_log_.AddEvent(
          NetLogEventType::SSL_READ_ERROR,
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
    ssl_ret = SSL_read(ssl_.get(), user_read_buf_->data() + total_bytes_read,
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
    pending_read_ssl_error_ = SSL_get_error(ssl_.get(), ssl_ret);
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
      pending_read_error_ = MapLastOpenSSLError(
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
    // again. The transport may have data available by then.
    if (pending_read_error_ == ERR_IO_PENDING)
      pending_read_error_ = kNoPendingResult;
  } else {
    // No bytes were returned. Return the pending read error immediately.
    DCHECK_NE(kNoPendingResult, pending_read_error_);
    rv = pending_read_error_;
    pending_read_error_ = kNoPendingResult;
  }

  if (rv >= 0) {
    net_log_.AddByteTransferEvent(NetLogEventType::SSL_SOCKET_BYTES_RECEIVED,
                                  rv, user_read_buf_->data());
  } else if (rv != ERR_IO_PENDING) {
    net_log_.AddEvent(
        NetLogEventType::SSL_READ_ERROR,
        CreateNetLogOpenSSLErrorCallback(rv, pending_read_ssl_error_,
                                         pending_read_error_info_));
    pending_read_ssl_error_ = SSL_ERROR_NONE;
    pending_read_error_info_ = OpenSSLErrorInfo();
  }
  return rv;
}

int SSLClientSocketImpl::DoPayloadWrite() {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  int rv = SSL_write(ssl_.get(), user_write_buf_->data(), user_write_buf_len_);

  if (rv >= 0) {
    net_log_.AddByteTransferEvent(NetLogEventType::SSL_SOCKET_BYTES_SENT, rv,
                                  user_write_buf_->data());
    return rv;
  }

  int ssl_error = SSL_get_error(ssl_.get(), rv);
  if (ssl_error == SSL_ERROR_WANT_PRIVATE_KEY_OPERATION)
    return ERR_IO_PENDING;
  OpenSSLErrorInfo error_info;
  int net_error = MapLastOpenSSLError(ssl_error, err_tracer, &error_info);

  if (net_error != ERR_IO_PENDING) {
    net_log_.AddEvent(
        NetLogEventType::SSL_WRITE_ERROR,
        CreateNetLogOpenSSLErrorCallback(net_error, ssl_error, error_info));
  }
  return net_error;
}

void SSLClientSocketImpl::RetryAllOperations() {
  // SSL_do_handshake, SSL_read, and SSL_write may all be retried when blocked,
  // so retry all operations for simplicity. (Otherwise, SSL_get_error for each
  // operation may be remembered to retry only the blocked ones.)

  if (next_handshake_state_ == STATE_HANDSHAKE) {
    // In handshake phase. The parameter to OnHandshakeIOComplete is unused.
    OnHandshakeIOComplete(OK);
    return;
  }

  int rv_read = ERR_IO_PENDING;
  int rv_write = ERR_IO_PENDING;
  if (user_read_buf_)
    rv_read = DoPayloadRead();
  if (user_write_buf_)
    rv_write = DoPayloadWrite();

  // Performing the Read callback may cause |this| to be deleted. If this
  // happens, the Write callback should not be invoked. Guard against this by
  // holding a WeakPtr to |this| and ensuring it's still valid.
  base::WeakPtr<SSLClientSocketImpl> guard(weak_factory_.GetWeakPtr());
  if (rv_read != ERR_IO_PENDING)
    DoReadCallback(rv_read);

  if (!guard.get())
    return;

  if (rv_write != ERR_IO_PENDING)
    DoWriteCallback(rv_write);
}

int SSLClientSocketImpl::VerifyCT() {
  const uint8_t* sct_list_raw;
  size_t sct_list_len;
  SSL_get0_signed_cert_timestamp_list(ssl_.get(), &sct_list_raw, &sct_list_len);
  base::StringPiece sct_list(reinterpret_cast<const char*>(sct_list_raw),
                             sct_list_len);

  const uint8_t* ocsp_response_raw;
  size_t ocsp_response_len;
  SSL_get0_ocsp_response(ssl_.get(), &ocsp_response_raw, &ocsp_response_len);
  base::StringPiece ocsp_response(
      reinterpret_cast<const char*>(ocsp_response_raw), ocsp_response_len);

  // Note that this is a completely synchronous operation: The CT Log Verifier
  // gets all the data it needs for SCT verification and does not do any
  // external communication.
  cert_transparency_verifier_->Verify(
      server_cert_verify_result_.verified_cert.get(), ocsp_response, sct_list,
      &ct_verify_result_.scts, net_log_);

  ct_verify_result_.ct_policies_applied = true;
  ct_verify_result_.ev_policy_compliance =
      ct::EVPolicyCompliance::EV_POLICY_DOES_NOT_APPLY;

  SCTList verified_scts =
      ct::SCTsMatchingStatus(ct_verify_result_.scts, ct::SCT_STATUS_OK);

  if (server_cert_verify_result_.cert_status & CERT_STATUS_IS_EV) {
    scoped_refptr<ct::EVCertsWhitelist> ev_whitelist =
        SSLConfigService::GetEVCertsWhitelist();
    ct::EVPolicyCompliance ev_policy_compliance =
        policy_enforcer_->DoesConformToCTEVPolicy(
            server_cert_verify_result_.verified_cert.get(), ev_whitelist.get(),
            verified_scts, net_log_);
    ct_verify_result_.ev_policy_compliance = ev_policy_compliance;
    if (ev_policy_compliance !=
            ct::EVPolicyCompliance::EV_POLICY_DOES_NOT_APPLY &&
        ev_policy_compliance !=
            ct::EVPolicyCompliance::EV_POLICY_COMPLIES_VIA_WHITELIST &&
        ev_policy_compliance !=
            ct::EVPolicyCompliance::EV_POLICY_COMPLIES_VIA_SCTS) {
      server_cert_verify_result_.cert_status |=
          CERT_STATUS_CT_COMPLIANCE_FAILED;
      server_cert_verify_result_.cert_status &= ~CERT_STATUS_IS_EV;
    }
  }
  ct_verify_result_.cert_policy_compliance =
      policy_enforcer_->DoesConformToCertPolicy(
          server_cert_verify_result_.verified_cert.get(), verified_scts,
          net_log_);

  if (ct_verify_result_.cert_policy_compliance !=
          ct::CertPolicyCompliance::CERT_POLICY_COMPLIES_VIA_SCTS &&
      ct_verify_result_.cert_policy_compliance !=
          ct::CertPolicyCompliance::CERT_POLICY_BUILD_NOT_TIMELY &&
      transport_security_state_->ShouldRequireCT(
          host_and_port_.host(), server_cert_verify_result_.verified_cert.get(),
          server_cert_verify_result_.public_key_hashes)) {
    server_cert_verify_result_.cert_status |=
        CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED;
    return ERR_CERTIFICATE_TRANSPARENCY_REQUIRED;
  }

  return OK;
}

int SSLClientSocketImpl::ClientCertRequestCallback(SSL* ssl) {
  DCHECK(ssl == ssl_.get());

  net_log_.AddEvent(NetLogEventType::SSL_CLIENT_CERT_REQUESTED);
  certificate_requested_ = true;

  // Clear any currently configured certificates.
  SSL_certs_clear(ssl_.get());

#if defined(OS_IOS)
  // TODO(droger): Support client auth on iOS. See http://crbug.com/145954).
  LOG(WARNING) << "Client auth is not supported";
#else   // !defined(OS_IOS)
  if (!ssl_config_.send_client_cert) {
    // First pass: we know that a client certificate is needed, but we do not
    // have one at hand. Suspend the handshake. SSL_get_error will return
    // SSL_ERROR_WANT_X509_LOOKUP.
    return -1;
  }

  // Second pass: a client certificate should have been selected.
  if (ssl_config_.client_cert.get()) {
    bssl::UniquePtr<X509> leaf_x509 =
        OSCertHandleToOpenSSL(ssl_config_.client_cert->os_cert_handle());
    if (!leaf_x509) {
      LOG(WARNING) << "Failed to import certificate";
      OpenSSLPutNetError(FROM_HERE, ERR_SSL_CLIENT_AUTH_CERT_BAD_FORMAT);
      return -1;
    }

    bssl::UniquePtr<STACK_OF(X509)> chain = OSCertHandlesToOpenSSL(
        ssl_config_.client_cert->GetIntermediateCertificates());
    if (!chain) {
      LOG(WARNING) << "Failed to import intermediate certificates";
      OpenSSLPutNetError(FROM_HERE, ERR_SSL_CLIENT_AUTH_CERT_BAD_FORMAT);
      return -1;
    }

    if (!SSL_use_certificate(ssl_.get(), leaf_x509.get()) ||
        !SSL_set1_chain(ssl_.get(), chain.get())) {
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

    SSL_set_private_key_method(ssl_.get(), &SSLContext::kPrivateKeyMethod);

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

    SSL_set_private_key_digest_prefs(ssl_.get(), digests.data(),
                                     digests.size());

    int cert_count = 1 + sk_X509_num(chain.get());
    net_log_.AddEvent(NetLogEventType::SSL_CLIENT_CERT_PROVIDED,
                      NetLog::IntCallback("cert_count", cert_count));
    return 1;
  }
#endif  // defined(OS_IOS)

  // Send no client certificate.
  net_log_.AddEvent(NetLogEventType::SSL_CLIENT_CERT_PROVIDED,
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

void SSLClientSocketImpl::MaybeCacheSession() {
  // Only cache the session once both a new session has been established and the
  // certificate has been verified. Due to False Start, these events may happen
  // in either order.
  if (!pending_session_ || !certificate_verified_)
    return;

  SSLContext::GetInstance()->session_cache()->Insert(GetSessionCacheKey(),
                                                     pending_session_.get());
  pending_session_ = nullptr;
}

int SSLClientSocketImpl::NewSessionCallback(SSL_SESSION* session) {
  // OpenSSL passes a reference to |session|.
  pending_session_.reset(session);
  MaybeCacheSession();
  return 1;
}

void SSLClientSocketImpl::AddCTInfoToSSLInfo(SSLInfo* ssl_info) const {
  ssl_info->UpdateCertificateTransparencyInfo(ct_verify_result_);
}

std::string SSLClientSocketImpl::GetSessionCacheKey() const {
  std::string result = host_and_port_.ToString();
  result.append("/");
  result.append(ssl_session_cache_shard_);

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

  if (negotiated_protocol_ == kProtoUnknown)
    return ssl_config_.renego_allowed_default;

  for (NextProto allowed : ssl_config_.renego_allowed_for_protos) {
    if (negotiated_protocol_ == allowed)
      return true;
  }
  return false;
}

int SSLClientSocketImpl::PrivateKeyTypeCallback() {
  switch (ssl_config_.client_private_key->GetType()) {
    case SSLPrivateKey::Type::RSA:
      return NID_rsaEncryption;
    case SSLPrivateKey::Type::ECDSA_P256:
      return NID_X9_62_prime256v1;
    case SSLPrivateKey::Type::ECDSA_P384:
      return NID_secp384r1;
    case SSLPrivateKey::Type::ECDSA_P521:
      return NID_secp521r1;
  }
  NOTREACHED();
  return NID_undef;
}

size_t SSLClientSocketImpl::PrivateKeyMaxSignatureLenCallback() {
  return ssl_config_.client_private_key->GetMaxSignatureLengthInBytes();
}

ssl_private_key_result_t SSLClientSocketImpl::PrivateKeySignDigestCallback(
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
      NetLogEventType::SSL_PRIVATE_KEY_OP,
      base::Bind(&NetLogPrivateKeyOperationCallback,
                 ssl_config_.client_private_key->GetType(), hash));

  signature_result_ = ERR_IO_PENDING;
  ssl_config_.client_private_key->SignDigest(
      hash, base::StringPiece(reinterpret_cast<const char*>(in), in_len),
      base::Bind(&SSLClientSocketImpl::OnPrivateKeyComplete,
                 weak_factory_.GetWeakPtr()));
  return ssl_private_key_retry;
}

ssl_private_key_result_t SSLClientSocketImpl::PrivateKeyCompleteCallback(
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

void SSLClientSocketImpl::OnPrivateKeyComplete(
    Error error,
    const std::vector<uint8_t>& signature) {
  DCHECK_EQ(ERR_IO_PENDING, signature_result_);
  DCHECK(signature_.empty());
  DCHECK(ssl_config_.client_private_key);

  net_log_.EndEventWithNetErrorCode(NetLogEventType::SSL_PRIVATE_KEY_OP, error);

  signature_result_ = error;
  if (signature_result_ == OK)
    signature_ = signature;

  // During a renegotiation, either Read or Write calls may be blocked on an
  // asynchronous private key operation.
  RetryAllOperations();
}

int SSLClientSocketImpl::TokenBindingAdd(const uint8_t** out,
                                         size_t* out_len,
                                         int* out_alert_value) {
  if (ssl_config_.token_binding_params.empty()) {
    return 0;
  }
  bssl::ScopedCBB output;
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
    net_log_.EndEventWithNetErrorCode(NetLogEventType::SSL_CONNECT, rv);
    return;
  }

  net_log_.EndEvent(NetLogEventType::SSL_CONNECT,
                    base::Bind(&NetLogSSLInfoCallback, base::Unretained(this)));
}

void SSLClientSocketImpl::RecordNegotiatedProtocol() const {
  UMA_HISTOGRAM_ENUMERATION("Net.SSLNegotiatedAlpnProtocol",
                            negotiated_protocol_, kProtoLast + 1);
}

void SSLClientSocketImpl::RecordChannelIDSupport() const {
  // Since this enum is used for a histogram, do not change or re-use values.
  enum {
    DISABLED = 0,
    CLIENT_ONLY = 1,
    CLIENT_AND_SERVER = 2,
    // CLIENT_NO_ECC is unused now.
    // CLIENT_BAD_SYSTEM_TIME is unused now.
    CLIENT_BAD_SYSTEM_TIME = 4,
    CLIENT_NO_CHANNEL_ID_SERVICE = 5,
    CHANNEL_ID_USAGE_MAX
  } supported = DISABLED;
  if (channel_id_sent_) {
    supported = CLIENT_AND_SERVER;
  } else if (ssl_config_.channel_id_enabled) {
    if (!channel_id_service_)
      supported = CLIENT_NO_CHANNEL_ID_SERVICE;
    else
      supported = CLIENT_ONLY;
  }
  UMA_HISTOGRAM_ENUMERATION("DomainBoundCerts.Support", supported,
                            CHANNEL_ID_USAGE_MAX);
}

bool SSLClientSocketImpl::IsChannelIDEnabled() const {
  return ssl_config_.channel_id_enabled && channel_id_service_;
}

int SSLClientSocketImpl::MapLastOpenSSLError(
    int ssl_error,
    const crypto::OpenSSLErrStackTracer& tracer,
    OpenSSLErrorInfo* info) {
  int net_error = MapOpenSSLErrorWithDetails(ssl_error, tracer, info);

  if (ssl_error == SSL_ERROR_SSL &&
      ERR_GET_LIB(info->error_code) == ERR_LIB_SSL) {
    // TLS does not provide an alert for missing client certificates, so most
    // servers send a generic handshake_failure alert. Detect this case by
    // checking if we have received a CertificateRequest but sent no
    // certificate. See https://crbug.com/646567.
    if (ERR_GET_REASON(info->error_code) ==
            SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE &&
        certificate_requested_ && ssl_config_.send_client_cert &&
        !ssl_config_.client_cert) {
      net_error = ERR_BAD_SSL_CLIENT_AUTH_CERT;
    }

    // Per spec, access_denied is only for client-certificate-based access
    // control, but some buggy firewalls use it when blocking a page. To avoid a
    // confusing error, map it to a generic protocol error if no
    // CertificateRequest was sent. See https://crbug.com/630883.
    if (ERR_GET_REASON(info->error_code) == SSL_R_TLSV1_ALERT_ACCESS_DENIED &&
        !certificate_requested_) {
      net_error = ERR_SSL_PROTOCOL_ERROR;
    }
  }

  return net_error;
}

}  // namespace net
