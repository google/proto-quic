// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/ssl_client_socket.h"

#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "base/strings/string_util.h"
#include "crypto/ec_private_key.h"
#include "net/base/connection_type_histograms.h"
#include "net/base/net_errors.h"
#include "net/ssl/channel_id_service.h"
#include "net/ssl/ssl_cipher_suite_names.h"
#include "net/ssl/ssl_config_service.h"
#include "net/ssl/ssl_connection_status_flags.h"

#if defined(USE_OPENSSL)
#include "net/socket/ssl_client_socket_openssl.h"
#endif

namespace net {

SSLClientSocket::SSLClientSocket()
    : signed_cert_timestamps_received_(false),
      stapled_ocsp_response_received_(false),
      negotiation_extension_(kExtensionUnknown) {
}

// static
NextProto SSLClientSocket::NextProtoFromString(
    const std::string& proto_string) {
  if (proto_string == "http1.1" || proto_string == "http/1.1") {
    return kProtoHTTP11;
  } else if (proto_string == "spdy/3.1") {
    return kProtoSPDY31;
  } else if (proto_string == "h2") {
    return kProtoHTTP2;
  } else if (proto_string == "quic/1+spdy/3") {
    return kProtoQUIC1SPDY3;
  } else {
    return kProtoUnknown;
  }
}

// static
const char* SSLClientSocket::NextProtoToString(NextProto next_proto) {
  switch (next_proto) {
    case kProtoHTTP11:
      return "http/1.1";
    case kProtoSPDY31:
      return "spdy/3.1";
    case kProtoHTTP2:
      return "h2";
    case kProtoQUIC1SPDY3:
      return "quic/1+spdy/3";
    case kProtoUnknown:
      break;
  }
  return "unknown";
}

// static
const char* SSLClientSocket::NextProtoStatusToString(
    const SSLClientSocket::NextProtoStatus status) {
  switch (status) {
    case kNextProtoUnsupported:
      return "unsupported";
    case kNextProtoNegotiated:
      return "negotiated";
    case kNextProtoNoOverlap:
      return "no-overlap";
  }
  return NULL;
}

// static
void SSLClientSocket::SetSSLKeyLogFile(
    const base::FilePath& path,
    const scoped_refptr<base::SequencedTaskRunner>& task_runner) {
#if defined(USE_OPENSSL) && !defined(OS_NACL)
  SSLClientSocketOpenSSL::SetSSLKeyLogFile(path, task_runner);
#else
  NOTIMPLEMENTED();
#endif
}

bool SSLClientSocket::WasNpnNegotiated() const {
  std::string unused_proto;
  return GetNextProto(&unused_proto) == kNextProtoNegotiated;
}

NextProto SSLClientSocket::GetNegotiatedProtocol() const {
  std::string proto;
  if (GetNextProto(&proto) != kNextProtoNegotiated)
    return kProtoUnknown;
  return NextProtoFromString(proto);
}

bool SSLClientSocket::IgnoreCertError(int error, int load_flags) {
  if (error == OK)
    return true;
  return (load_flags & LOAD_IGNORE_ALL_CERT_ERRORS) &&
         IsCertificateError(error);
}

void SSLClientSocket::RecordNegotiationExtension() {
  if (negotiation_extension_ == kExtensionUnknown)
    return;
  std::string proto;
  SSLClientSocket::NextProtoStatus status = GetNextProto(&proto);
  if (status == kNextProtoUnsupported)
    return;
  // Convert protocol into numerical value for histogram.
  NextProto protocol_negotiated = SSLClientSocket::NextProtoFromString(proto);
  base::HistogramBase::Sample sample =
      static_cast<base::HistogramBase::Sample>(protocol_negotiated);
  // In addition to the protocol negotiated, we want to record which TLS
  // extension was used, and in case of NPN, whether there was overlap between
  // server and client list of supported protocols.
  if (negotiation_extension_ == kExtensionNPN) {
    if (status == kNextProtoNoOverlap) {
      sample += 1000;
    } else {
      sample += 500;
    }
  } else {
    DCHECK_EQ(kExtensionALPN, negotiation_extension_);
  }
  UMA_HISTOGRAM_SPARSE_SLOWLY("Net.SSLProtocolNegotiation", sample);
}

// static
void SSLClientSocket::RecordChannelIDSupport(
    ChannelIDService* channel_id_service,
    bool negotiated_channel_id,
    bool channel_id_enabled) {
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
  if (negotiated_channel_id) {
    supported = CLIENT_AND_SERVER;
  } else if (channel_id_enabled) {
    if (!channel_id_service)
      supported = CLIENT_NO_CHANNEL_ID_SERVICE;
    else
      supported = CLIENT_ONLY;
  }
  UMA_HISTOGRAM_ENUMERATION("DomainBoundCerts.Support", supported,
                            CHANNEL_ID_USAGE_MAX);
}

// static
bool SSLClientSocket::IsChannelIDEnabled(
    const SSLConfig& ssl_config,
    ChannelIDService* channel_id_service) {
  if (!ssl_config.channel_id_enabled)
    return false;
  if (!channel_id_service) {
    DVLOG(1) << "NULL channel_id_service_, not enabling channel ID.";
    return false;
  }
  return true;
}

// static
bool SSLClientSocket::HasCipherAdequateForHTTP2(
    const std::vector<uint16_t>& cipher_suites) {
  for (uint16_t cipher : cipher_suites) {
    if (IsTLSCipherSuiteAllowedByHTTP2(cipher))
      return true;
  }
  return false;
}

// static
bool SSLClientSocket::IsTLSVersionAdequateForHTTP2(
    const SSLConfig& ssl_config) {
  return ssl_config.version_max >= SSL_PROTOCOL_VERSION_TLS1_2;
}

// static
std::vector<uint8_t> SSLClientSocket::SerializeNextProtos(
    const NextProtoVector& next_protos) {
  std::vector<uint8_t> wire_protos;
  for (const NextProto next_proto : next_protos) {
    const std::string proto = NextProtoToString(next_proto);
    if (proto.size() > 255) {
      LOG(WARNING) << "Ignoring overlong NPN/ALPN protocol: " << proto;
      continue;
    }
    if (proto.size() == 0) {
      LOG(WARNING) << "Ignoring empty NPN/ALPN protocol";
      continue;
    }
    wire_protos.push_back(proto.size());
    for (const char ch : proto) {
      wire_protos.push_back(static_cast<uint8_t>(ch));
    }
  }

  return wire_protos;
}

}  // namespace net
