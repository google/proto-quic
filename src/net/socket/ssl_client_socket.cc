// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/ssl_client_socket.h"

#include "base/feature_list.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "base/strings/string_util.h"
#include "build/build_config.h"
#include "crypto/ec_private_key.h"
#include "net/base/net_errors.h"
#include "net/socket/ssl_client_socket_impl.h"
#include "net/ssl/channel_id_service.h"
#include "net/ssl/ssl_config_service.h"

namespace net {

namespace {
#if !defined(OS_NACL)
const base::Feature kPostQuantumExperiment{"SSLPostQuantumExperiment",
                                           base::FEATURE_DISABLED_BY_DEFAULT};
#endif
}  // namespace

SSLClientSocket::SSLClientSocket()
    : signed_cert_timestamps_received_(false),
      stapled_ocsp_response_received_(false) {}

// static
NextProto SSLClientSocket::NextProtoFromString(base::StringPiece proto_string) {
  if (proto_string == "http1.1" || proto_string == "http/1.1") {
    return kProtoHTTP11;
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
void SSLClientSocket::SetSSLKeyLogFile(
    const base::FilePath& path,
    const scoped_refptr<base::SequencedTaskRunner>& task_runner) {
#if !defined(OS_NACL)
  SSLClientSocketImpl::SetSSLKeyLogFile(path, task_runner);
#else
  NOTIMPLEMENTED();
#endif
}

bool SSLClientSocket::IgnoreCertError(int error, int load_flags) {
  if (error == OK)
    return true;
  return (load_flags & LOAD_IGNORE_ALL_CERT_ERRORS) &&
         IsCertificateError(error);
}

// static
bool SSLClientSocket::IsPostQuantumExperimentEnabled() {
#if !defined(OS_NACL)
  return base::FeatureList::IsEnabled(kPostQuantumExperiment);
#else
  return false;
#endif
}

// static
std::vector<uint8_t> SSLClientSocket::SerializeNextProtos(
    const NextProtoVector& next_protos) {
  std::vector<uint8_t> wire_protos;
  for (const NextProto next_proto : next_protos) {
    const std::string proto = NextProtoToString(next_proto);
    if (proto.size() > 255) {
      LOG(WARNING) << "Ignoring overlong ALPN protocol: " << proto;
      continue;
    }
    if (proto.size() == 0) {
      LOG(WARNING) << "Ignoring empty ALPN protocol";
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
