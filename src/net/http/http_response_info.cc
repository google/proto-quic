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
#include "net/cert/signed_certificate_timestamp.h"
#include "net/cert/x509_certificate.h"
#include "net/http/http_response_headers.h"
#include "net/ssl/ssl_cert_request_info.h"

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

  // This bit is set if the request has NPN negotiated.
  RESPONSE_INFO_WAS_NPN = 1 << 14,

  // This bit is set if the request was fetched via an explicit proxy.
  RESPONSE_INFO_WAS_PROXY = 1 << 15,

  // This bit is set if the response info has an SSL connection status field.
  // This contains the ciphersuite used to fetch the resource as well as the
  // protocol version, compression method and whether SSLv3 fallback was used.
  RESPONSE_INFO_HAS_SSL_CONNECTION_STATUS = 1 << 16,

  // This bit is set if the response info has protocol version.
  RESPONSE_INFO_HAS_NPN_NEGOTIATED_PROTOCOL = 1 << 17,

  // This bit is set if the response info has connection info.
  RESPONSE_INFO_HAS_CONNECTION_INFO = 1 << 18,

  // This bit is set if the request has http authentication.
  RESPONSE_INFO_USE_HTTP_AUTHENTICATION = 1 << 19,

  // This bit is set if ssl_info has SCTs.
  RESPONSE_INFO_HAS_SIGNED_CERTIFICATE_TIMESTAMPS = 1 << 20,

  RESPONSE_INFO_UNUSED_SINCE_PREFETCH = 1 << 21,

  // This bit is set if the response has a key-exchange-info field at the end.
  RESPONSE_INFO_HAS_KEY_EXCHANGE_INFO = 1 << 22,

  // TODO(darin): Add other bits to indicate alternate request methods.
  // For now, we don't support storing those.
};

HttpResponseInfo::HttpResponseInfo()
    : was_cached(false),
      server_data_unavailable(false),
      network_accessed(false),
      was_fetched_via_spdy(false),
      was_npn_negotiated(false),
      was_fetched_via_proxy(false),
      did_use_http_auth(false),
      unused_since_prefetch(false),
      async_revalidation_required(false),
      connection_info(CONNECTION_INFO_UNKNOWN) {}

HttpResponseInfo::HttpResponseInfo(const HttpResponseInfo& rhs)
    : was_cached(rhs.was_cached),
      server_data_unavailable(rhs.server_data_unavailable),
      network_accessed(rhs.network_accessed),
      was_fetched_via_spdy(rhs.was_fetched_via_spdy),
      was_npn_negotiated(rhs.was_npn_negotiated),
      was_fetched_via_proxy(rhs.was_fetched_via_proxy),
      proxy_server(rhs.proxy_server),
      did_use_http_auth(rhs.did_use_http_auth),
      unused_since_prefetch(rhs.unused_since_prefetch),
      async_revalidation_required(rhs.async_revalidation_required),
      socket_address(rhs.socket_address),
      npn_negotiated_protocol(rhs.npn_negotiated_protocol),
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
  server_data_unavailable = rhs.server_data_unavailable;
  network_accessed = rhs.network_accessed;
  was_fetched_via_spdy = rhs.was_fetched_via_spdy;
  proxy_server = rhs.proxy_server;
  was_npn_negotiated = rhs.was_npn_negotiated;
  was_fetched_via_proxy = rhs.was_fetched_via_proxy;
  did_use_http_auth = rhs.did_use_http_auth;
  unused_since_prefetch = rhs.unused_since_prefetch;
  async_revalidation_required = rhs.async_revalidation_required;
  socket_address = rhs.socket_address;
  npn_negotiated_protocol = rhs.npn_negotiated_protocol;
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
  if (flags & RESPONSE_INFO_HAS_NPN_NEGOTIATED_PROTOCOL) {
    if (!iter.ReadString(&npn_negotiated_protocol))
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

  // Read key_exchange_info
  if (flags & RESPONSE_INFO_HAS_KEY_EXCHANGE_INFO) {
    int key_exchange_info;
    if (!iter.ReadInt(&key_exchange_info))
      return false;
    ssl_info.key_exchange_info = key_exchange_info;
  }

  was_fetched_via_spdy = (flags & RESPONSE_INFO_WAS_SPDY) != 0;

  was_npn_negotiated = (flags & RESPONSE_INFO_WAS_NPN) != 0;

  was_fetched_via_proxy = (flags & RESPONSE_INFO_WAS_PROXY) != 0;

  *response_truncated = (flags & RESPONSE_INFO_TRUNCATED) != 0;

  did_use_http_auth = (flags & RESPONSE_INFO_USE_HTTP_AUTHENTICATION) != 0;

  unused_since_prefetch = (flags & RESPONSE_INFO_UNUSED_SINCE_PREFETCH) != 0;

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
    if (ssl_info.key_exchange_info != 0)
      flags |= RESPONSE_INFO_HAS_KEY_EXCHANGE_INFO;
    if (ssl_info.connection_status != 0)
      flags |= RESPONSE_INFO_HAS_SSL_CONNECTION_STATUS;
  }
  if (vary_data.is_valid())
    flags |= RESPONSE_INFO_HAS_VARY_DATA;
  if (response_truncated)
    flags |= RESPONSE_INFO_TRUNCATED;
  if (was_fetched_via_spdy)
    flags |= RESPONSE_INFO_WAS_SPDY;
  if (was_npn_negotiated) {
    flags |= RESPONSE_INFO_WAS_NPN;
    flags |= RESPONSE_INFO_HAS_NPN_NEGOTIATED_PROTOCOL;
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

  if (was_npn_negotiated)
    pickle->WriteString(npn_negotiated_protocol);

  if (connection_info != CONNECTION_INFO_UNKNOWN)
    pickle->WriteInt(static_cast<int>(connection_info));

  if (ssl_info.is_valid() && ssl_info.key_exchange_info != 0)
    pickle->WriteInt(ssl_info.key_exchange_info);
}

HttpResponseInfo::ConnectionInfo HttpResponseInfo::ConnectionInfoFromNextProto(
    NextProto next_proto) {
  switch (next_proto) {
    case kProtoSPDY31:
      return CONNECTION_INFO_SPDY3;
    case kProtoHTTP2:
      return CONNECTION_INFO_HTTP2;
    case kProtoQUIC1SPDY3:
      return CONNECTION_INFO_QUIC1_SPDY3;

    case kProtoUnknown:
    case kProtoHTTP11:
      break;
  }

  NOTREACHED();
  return CONNECTION_INFO_UNKNOWN;
}

// static
std::string HttpResponseInfo::ConnectionInfoToString(
    ConnectionInfo connection_info) {
  switch (connection_info) {
    case CONNECTION_INFO_UNKNOWN:
      return "unknown";
    case CONNECTION_INFO_HTTP1:
      return "http/1";
    case CONNECTION_INFO_DEPRECATED_SPDY2:
      NOTREACHED();
      return "";
    case CONNECTION_INFO_SPDY3:
      return "spdy/3";
    // Since ConnectionInfo is persisted to disk, deprecated values have to be
    // handled. Note that h2-14 and h2-15 are essentially wire compatible with
    // h2.
    // Intentional fallthrough.
    case CONNECTION_INFO_HTTP2_14:
    case CONNECTION_INFO_HTTP2_15:
    case CONNECTION_INFO_HTTP2:
      return "h2";
    case CONNECTION_INFO_QUIC1_SPDY3:
      return "quic/1+spdy/3";
    case NUM_OF_CONNECTION_INFOS:
      break;
  }
  NOTREACHED();
  return "";
}

}  // namespace net
