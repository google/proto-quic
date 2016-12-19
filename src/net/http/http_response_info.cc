// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_response_info.h"

#include "base/logging.h"
#include "base/pickle.h"
#include "base/time/time.h"
#include "net/base/auth.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/cert/sct_status_flags.h"
#include "net/cert/signed_certificate_timestamp.h"
#include "net/cert/x509_certificate.h"
#include "net/http/http_response_headers.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

using base::Time;

namespace net {

namespace {

X509Certificate::PickleType GetPickleTypeForVersion(int version) {
  switch (version) {
    case 1:
      return X509Certificate::PICKLETYPE_SINGLE_CERTIFICATE;
    case 2:
      return X509Certificate::PICKLETYPE_CERTIFICATE_CHAIN_V2;
    case 3:
    default:
      return X509Certificate::PICKLETYPE_CERTIFICATE_CHAIN_V3;
  }
}

bool KeyExchangeGroupIsValid(int ssl_connection_status) {
  // TLS 1.3 and later always treat the field correctly.
  if (SSLConnectionStatusToVersion(ssl_connection_status) >=
      SSL_CONNECTION_VERSION_TLS1_3) {
    return true;
  }

  // Prior to TLS 1.3, only ECDHE ciphers have groups.
  const SSL_CIPHER* cipher = SSL_get_cipher_by_value(
      SSLConnectionStatusToCipherSuite(ssl_connection_status));
  return cipher && SSL_CIPHER_is_ECDHE(cipher);
}

}  // namespace

// These values can be bit-wise combined to form the flags field of the
// serialized HttpResponseInfo.
enum {
  // The version of the response info used when persisting response info.
  RESPONSE_INFO_VERSION = 3,

  // The minimum version supported for deserializing response info.
  RESPONSE_INFO_MINIMUM_VERSION = 1,

  // We reserve up to 8 bits for the version number.
  RESPONSE_INFO_VERSION_MASK = 0xFF,

  // This bit is set if the response info has a cert at the end.
  // Version 1 serialized only the end-entity certificate, while subsequent
  // versions include the available certificate chain.
  RESPONSE_INFO_HAS_CERT = 1 << 8,

  // This bit is set if the response info has a security-bits field (security
  // strength, in bits, of the SSL connection) at the end.
  RESPONSE_INFO_HAS_SECURITY_BITS = 1 << 9,

  // This bit is set if the response info has a cert status at the end.
  RESPONSE_INFO_HAS_CERT_STATUS = 1 << 10,

  // This bit is set if the response info has vary header data.
  RESPONSE_INFO_HAS_VARY_DATA = 1 << 11,

  // This bit is set if the request was cancelled before completion.
  RESPONSE_INFO_TRUNCATED = 1 << 12,

  // This bit is set if the response was received via SPDY.
  RESPONSE_INFO_WAS_SPDY = 1 << 13,

  // This bit is set if the request has ALPN negotiated.
  RESPONSE_INFO_WAS_ALPN = 1 << 14,

  // This bit is set if the request was fetched via an explicit proxy.
  RESPONSE_INFO_WAS_PROXY = 1 << 15,

  // This bit is set if the response info has an SSL connection status field.
  // This contains the ciphersuite used to fetch the resource as well as the
  // protocol version, compression method and whether SSLv3 fallback was used.
  RESPONSE_INFO_HAS_SSL_CONNECTION_STATUS = 1 << 16,

  // This bit is set if the response info has protocol version.
  RESPONSE_INFO_HAS_ALPN_NEGOTIATED_PROTOCOL = 1 << 17,

  // This bit is set if the response info has connection info.
  RESPONSE_INFO_HAS_CONNECTION_INFO = 1 << 18,

  // This bit is set if the request has http authentication.
  RESPONSE_INFO_USE_HTTP_AUTHENTICATION = 1 << 19,

  // This bit is set if ssl_info has SCTs.
  RESPONSE_INFO_HAS_SIGNED_CERTIFICATE_TIMESTAMPS = 1 << 20,

  RESPONSE_INFO_UNUSED_SINCE_PREFETCH = 1 << 21,

  // This bit is set if the response has a key exchange group.
  RESPONSE_INFO_HAS_KEY_EXCHANGE_GROUP = 1 << 22,

  // This bit is set if ssl_info recorded that PKP was bypassed due to a local
  // trust anchor.
  RESPONSE_INFO_PKP_BYPASSED = 1 << 23,

  // TODO(darin): Add other bits to indicate alternate request methods.
  // For now, we don't support storing those.
};

HttpResponseInfo::HttpResponseInfo()
    : was_cached(false),
      cache_entry_status(CacheEntryStatus::ENTRY_UNDEFINED),
      server_data_unavailable(false),
      network_accessed(false),
      was_fetched_via_spdy(false),
      was_alpn_negotiated(false),
      was_fetched_via_proxy(false),
      did_use_http_auth(false),
      unused_since_prefetch(false),
      async_revalidation_required(false),
      connection_info(CONNECTION_INFO_UNKNOWN) {}

HttpResponseInfo::HttpResponseInfo(const HttpResponseInfo& rhs)
    : was_cached(rhs.was_cached),
      cache_entry_status(rhs.cache_entry_status),
      server_data_unavailable(rhs.server_data_unavailable),
      network_accessed(rhs.network_accessed),
      was_fetched_via_spdy(rhs.was_fetched_via_spdy),
      was_alpn_negotiated(rhs.was_alpn_negotiated),
      was_fetched_via_proxy(rhs.was_fetched_via_proxy),
      proxy_server(rhs.proxy_server),
      did_use_http_auth(rhs.did_use_http_auth),
      unused_since_prefetch(rhs.unused_since_prefetch),
      async_revalidation_required(rhs.async_revalidation_required),
      socket_address(rhs.socket_address),
      alpn_negotiated_protocol(rhs.alpn_negotiated_protocol),
      connection_info(rhs.connection_info),
      request_time(rhs.request_time),
      response_time(rhs.response_time),
      auth_challenge(rhs.auth_challenge),
      cert_request_info(rhs.cert_request_info),
      ssl_info(rhs.ssl_info),
      headers(rhs.headers),
      vary_data(rhs.vary_data),
      metadata(rhs.metadata) {}

HttpResponseInfo::~HttpResponseInfo() {
}

HttpResponseInfo& HttpResponseInfo::operator=(const HttpResponseInfo& rhs) {
  was_cached = rhs.was_cached;
  cache_entry_status = rhs.cache_entry_status;
  server_data_unavailable = rhs.server_data_unavailable;
  network_accessed = rhs.network_accessed;
  was_fetched_via_spdy = rhs.was_fetched_via_spdy;
  proxy_server = rhs.proxy_server;
  was_alpn_negotiated = rhs.was_alpn_negotiated;
  was_fetched_via_proxy = rhs.was_fetched_via_proxy;
  did_use_http_auth = rhs.did_use_http_auth;
  unused_since_prefetch = rhs.unused_since_prefetch;
  async_revalidation_required = rhs.async_revalidation_required;
  socket_address = rhs.socket_address;
  alpn_negotiated_protocol = rhs.alpn_negotiated_protocol;
  connection_info = rhs.connection_info;
  request_time = rhs.request_time;
  response_time = rhs.response_time;
  auth_challenge = rhs.auth_challenge;
  cert_request_info = rhs.cert_request_info;
  ssl_info = rhs.ssl_info;
  headers = rhs.headers;
  vary_data = rhs.vary_data;
  metadata = rhs.metadata;
  return *this;
}

bool HttpResponseInfo::InitFromPickle(const base::Pickle& pickle,
                                      bool* response_truncated) {
  base::PickleIterator iter(pickle);

  // Read flags and verify version
  int flags;
  if (!iter.ReadInt(&flags))
    return false;
  int version = flags & RESPONSE_INFO_VERSION_MASK;
  if (version < RESPONSE_INFO_MINIMUM_VERSION ||
      version > RESPONSE_INFO_VERSION) {
    DLOG(ERROR) << "unexpected response info version: " << version;
    return false;
  }

  // Read request-time
  int64_t time_val;
  if (!iter.ReadInt64(&time_val))
    return false;
  request_time = Time::FromInternalValue(time_val);
  was_cached = true;  // Set status to show cache resurrection.

  // Read response-time
  if (!iter.ReadInt64(&time_val))
    return false;
  response_time = Time::FromInternalValue(time_val);

  // Read response-headers
  headers = new HttpResponseHeaders(&iter);
  if (headers->response_code() == -1)
    return false;

  // Read ssl-info
  if (flags & RESPONSE_INFO_HAS_CERT) {
    X509Certificate::PickleType type = GetPickleTypeForVersion(version);
    ssl_info.cert = X509Certificate::CreateFromPickle(&iter, type);
    if (!ssl_info.cert.get())
      return false;
  }
  if (flags & RESPONSE_INFO_HAS_CERT_STATUS) {
    CertStatus cert_status;
    if (!iter.ReadUInt32(&cert_status))
      return false;
    ssl_info.cert_status = cert_status;
  }
  if (flags & RESPONSE_INFO_HAS_SECURITY_BITS) {
    int security_bits;
    if (!iter.ReadInt(&security_bits))
      return false;
    ssl_info.security_bits = security_bits;
  }

  if (flags & RESPONSE_INFO_HAS_SSL_CONNECTION_STATUS) {
    int connection_status;
    if (!iter.ReadInt(&connection_status))
      return false;
    ssl_info.connection_status = connection_status;
  }

  if (flags & RESPONSE_INFO_HAS_SIGNED_CERTIFICATE_TIMESTAMPS) {
    int num_scts;
    if (!iter.ReadInt(&num_scts))
      return false;
    for (int i = 0; i < num_scts; ++i) {
      scoped_refptr<ct::SignedCertificateTimestamp> sct(
          ct::SignedCertificateTimestamp::CreateFromPickle(&iter));
      uint16_t status;
      if (!sct.get() || !iter.ReadUInt16(&status))
        return false;
      if (!net::ct::IsValidSCTStatus(status))
        return false;
      ssl_info.signed_certificate_timestamps.push_back(
          SignedCertificateTimestampAndStatus(
              sct, static_cast<ct::SCTVerifyStatus>(status)));
    }
  }

  // Read vary-data
  if (flags & RESPONSE_INFO_HAS_VARY_DATA) {
    if (!vary_data.InitFromPickle(&iter))
      return false;
  }

  // Read socket_address.
  std::string socket_address_host;
  if (iter.ReadString(&socket_address_host)) {
    // If the host was written, we always expect the port to follow.
    uint16_t socket_address_port;
    if (!iter.ReadUInt16(&socket_address_port))
      return false;
    socket_address = HostPortPair(socket_address_host, socket_address_port);
  } else if (version > 1) {
    // socket_address was not always present in version 1 of the response
    // info, so we don't fail if it can't be read.
    return false;
  }

  // Read protocol-version.
  if (flags & RESPONSE_INFO_HAS_ALPN_NEGOTIATED_PROTOCOL) {
    if (!iter.ReadString(&alpn_negotiated_protocol))
      return false;
  }

  // Read connection info.
  if (flags & RESPONSE_INFO_HAS_CONNECTION_INFO) {
    int value;
    if (!iter.ReadInt(&value))
      return false;

    if (value > static_cast<int>(CONNECTION_INFO_UNKNOWN) &&
        value < static_cast<int>(NUM_OF_CONNECTION_INFOS)) {
      connection_info = static_cast<ConnectionInfo>(value);
    }
  }

  // Read key_exchange_group
  if (flags & RESPONSE_INFO_HAS_KEY_EXCHANGE_GROUP) {
    int key_exchange_group;
    if (!iter.ReadInt(&key_exchange_group))
      return false;

    // Historically, the key_exchange_group field was key_exchange_info which
    // conflated a number of different values based on the cipher suite, so some
    // values must be discarded. See https://crbug.com/639421.
    if (KeyExchangeGroupIsValid(ssl_info.connection_status))
      ssl_info.key_exchange_group = key_exchange_group;
  }

  was_fetched_via_spdy = (flags & RESPONSE_INFO_WAS_SPDY) != 0;

  was_alpn_negotiated = (flags & RESPONSE_INFO_WAS_ALPN) != 0;

  was_fetched_via_proxy = (flags & RESPONSE_INFO_WAS_PROXY) != 0;

  *response_truncated = (flags & RESPONSE_INFO_TRUNCATED) != 0;

  did_use_http_auth = (flags & RESPONSE_INFO_USE_HTTP_AUTHENTICATION) != 0;

  unused_since_prefetch = (flags & RESPONSE_INFO_UNUSED_SINCE_PREFETCH) != 0;

  ssl_info.pkp_bypassed = (flags & RESPONSE_INFO_PKP_BYPASSED) != 0;

  return true;
}

void HttpResponseInfo::Persist(base::Pickle* pickle,
                               bool skip_transient_headers,
                               bool response_truncated) const {
  int flags = RESPONSE_INFO_VERSION;
  if (ssl_info.is_valid()) {
    flags |= RESPONSE_INFO_HAS_CERT;
    flags |= RESPONSE_INFO_HAS_CERT_STATUS;
    if (ssl_info.security_bits != -1)
      flags |= RESPONSE_INFO_HAS_SECURITY_BITS;
    if (ssl_info.key_exchange_group != 0)
      flags |= RESPONSE_INFO_HAS_KEY_EXCHANGE_GROUP;
    if (ssl_info.connection_status != 0)
      flags |= RESPONSE_INFO_HAS_SSL_CONNECTION_STATUS;
  }
  if (vary_data.is_valid())
    flags |= RESPONSE_INFO_HAS_VARY_DATA;
  if (response_truncated)
    flags |= RESPONSE_INFO_TRUNCATED;
  if (was_fetched_via_spdy)
    flags |= RESPONSE_INFO_WAS_SPDY;
  if (was_alpn_negotiated) {
    flags |= RESPONSE_INFO_WAS_ALPN;
    flags |= RESPONSE_INFO_HAS_ALPN_NEGOTIATED_PROTOCOL;
  }
  if (was_fetched_via_proxy)
    flags |= RESPONSE_INFO_WAS_PROXY;
  if (connection_info != CONNECTION_INFO_UNKNOWN)
    flags |= RESPONSE_INFO_HAS_CONNECTION_INFO;
  if (did_use_http_auth)
    flags |= RESPONSE_INFO_USE_HTTP_AUTHENTICATION;
  if (unused_since_prefetch)
    flags |= RESPONSE_INFO_UNUSED_SINCE_PREFETCH;
  if (!ssl_info.signed_certificate_timestamps.empty())
    flags |= RESPONSE_INFO_HAS_SIGNED_CERTIFICATE_TIMESTAMPS;
  if (ssl_info.pkp_bypassed)
    flags |= RESPONSE_INFO_PKP_BYPASSED;

  pickle->WriteInt(flags);
  pickle->WriteInt64(request_time.ToInternalValue());
  pickle->WriteInt64(response_time.ToInternalValue());

  HttpResponseHeaders::PersistOptions persist_options =
      HttpResponseHeaders::PERSIST_RAW;

  if (skip_transient_headers) {
    persist_options = HttpResponseHeaders::PERSIST_SANS_COOKIES |
                      HttpResponseHeaders::PERSIST_SANS_CHALLENGES |
                      HttpResponseHeaders::PERSIST_SANS_HOP_BY_HOP |
                      HttpResponseHeaders::PERSIST_SANS_NON_CACHEABLE |
                      HttpResponseHeaders::PERSIST_SANS_RANGES |
                      HttpResponseHeaders::PERSIST_SANS_SECURITY_STATE;
  }

  headers->Persist(pickle, persist_options);

  if (ssl_info.is_valid()) {
    ssl_info.cert->Persist(pickle);
    pickle->WriteUInt32(ssl_info.cert_status);
    if (ssl_info.security_bits != -1)
      pickle->WriteInt(ssl_info.security_bits);
    if (ssl_info.connection_status != 0)
      pickle->WriteInt(ssl_info.connection_status);
    if (!ssl_info.signed_certificate_timestamps.empty()) {
      pickle->WriteInt(ssl_info.signed_certificate_timestamps.size());
      for (SignedCertificateTimestampAndStatusList::const_iterator it =
           ssl_info.signed_certificate_timestamps.begin(); it !=
           ssl_info.signed_certificate_timestamps.end(); ++it) {
        it->sct->Persist(pickle);
        pickle->WriteUInt16(static_cast<uint16_t>(it->status));
      }
    }
  }

  if (vary_data.is_valid())
    vary_data.Persist(pickle);

  pickle->WriteString(socket_address.host());
  pickle->WriteUInt16(socket_address.port());

  if (was_alpn_negotiated)
    pickle->WriteString(alpn_negotiated_protocol);

  if (connection_info != CONNECTION_INFO_UNKNOWN)
    pickle->WriteInt(static_cast<int>(connection_info));

  if (ssl_info.is_valid() && ssl_info.key_exchange_group != 0)
    pickle->WriteInt(ssl_info.key_exchange_group);
}

bool HttpResponseInfo::DidUseQuic() const {
  switch (connection_info) {
    case CONNECTION_INFO_UNKNOWN:
    case CONNECTION_INFO_HTTP1_1:
    case CONNECTION_INFO_DEPRECATED_SPDY2:
    case CONNECTION_INFO_DEPRECATED_SPDY3:
    case CONNECTION_INFO_HTTP2:
    case CONNECTION_INFO_DEPRECATED_HTTP2_14:
    case CONNECTION_INFO_DEPRECATED_HTTP2_15:
    case CONNECTION_INFO_HTTP0_9:
    case CONNECTION_INFO_HTTP1_0:
      return false;
    case CONNECTION_INFO_QUIC_UNKNOWN_VERSION:
    case CONNECTION_INFO_QUIC_32:
    case CONNECTION_INFO_QUIC_33:
    case CONNECTION_INFO_QUIC_34:
    case CONNECTION_INFO_QUIC_35:
    case CONNECTION_INFO_QUIC_36:
    case CONNECTION_INFO_QUIC_37:
      return true;
    case NUM_OF_CONNECTION_INFOS:
      NOTREACHED();
      return false;
  }
  NOTREACHED();
  return false;
}

// static
std::string HttpResponseInfo::ConnectionInfoToString(
    ConnectionInfo connection_info) {
  switch (connection_info) {
    case CONNECTION_INFO_UNKNOWN:
      return "unknown";
    case CONNECTION_INFO_HTTP1_1:
      return "http/1.1";
    case CONNECTION_INFO_DEPRECATED_SPDY2:
      NOTREACHED();
      return "";
    case CONNECTION_INFO_DEPRECATED_SPDY3:
      return "spdy/3";
    // Since ConnectionInfo is persisted to disk, deprecated values have to be
    // handled. Note that h2-14 and h2-15 are essentially wire compatible with
    // h2.
    // Intentional fallthrough.
    case CONNECTION_INFO_DEPRECATED_HTTP2_14:
    case CONNECTION_INFO_DEPRECATED_HTTP2_15:
    case CONNECTION_INFO_HTTP2:
      return "h2";
    case CONNECTION_INFO_QUIC_UNKNOWN_VERSION:
      return "http/2+quic";
    case CONNECTION_INFO_QUIC_32:
      return "http/2+quic/32";
    case CONNECTION_INFO_QUIC_33:
      return "http/2+quic/33";
    case CONNECTION_INFO_QUIC_34:
      return "http/2+quic/34";
    case CONNECTION_INFO_QUIC_35:
      return "http/2+quic/35";
    case CONNECTION_INFO_QUIC_36:
      return "http/2+quic/36";
    case CONNECTION_INFO_QUIC_37:
      return "http/2+quic/37";
    case CONNECTION_INFO_HTTP0_9:
      return "http/0.9";
    case CONNECTION_INFO_HTTP1_0:
      return "http/1.0";
    case NUM_OF_CONNECTION_INFOS:
      break;
  }
  NOTREACHED();
  return "";
}

}  // namespace net
