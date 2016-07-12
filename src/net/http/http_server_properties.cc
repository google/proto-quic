// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_server_properties.h"

#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/stringprintf.h"
#include "net/socket/ssl_client_socket.h"
#include "net/ssl/ssl_config.h"

namespace net {

const char kAlternativeServiceHeader[] = "Alt-Svc";

void HistogramAlternateProtocolUsage(AlternateProtocolUsage usage) {
  UMA_HISTOGRAM_ENUMERATION("Net.AlternateProtocolUsage", usage,
                            ALTERNATE_PROTOCOL_USAGE_MAX);
}

void HistogramBrokenAlternateProtocolLocation(
    BrokenAlternateProtocolLocation location){
  UMA_HISTOGRAM_ENUMERATION("Net.AlternateProtocolBrokenLocation", location,
                            BROKEN_ALTERNATE_PROTOCOL_LOCATION_MAX);
}

bool IsAlternateProtocolValid(AlternateProtocol protocol) {
  return protocol >= ALTERNATE_PROTOCOL_MINIMUM_VALID_VERSION &&
      protocol <= ALTERNATE_PROTOCOL_MAXIMUM_VALID_VERSION;
}

const char* AlternateProtocolToString(AlternateProtocol protocol) {
  switch (protocol) {
    case QUIC:
      return "quic";
    case NPN_HTTP_2:
      return "h2";
    case NPN_SPDY_3_1:
      return "npn-spdy/3.1";
    case UNINITIALIZED_ALTERNATE_PROTOCOL:
      return "Uninitialized";
  }
  NOTREACHED();
  return "";
}

AlternateProtocol AlternateProtocolFromString(const std::string& str) {
  if (str == "quic")
    return QUIC;
  if (str == "h2")
    return NPN_HTTP_2;
  // "npn-h2" is accepted here so that persisted settings with the old string
  // can be loaded from disk.  TODO(bnc):  Remove around 2016 December.
  if (str == "npn-h2")
    return NPN_HTTP_2;
  if (str == "npn-spdy/3.1")
    return NPN_SPDY_3_1;

  return UNINITIALIZED_ALTERNATE_PROTOCOL;
}

AlternateProtocol AlternateProtocolFromNextProto(NextProto next_proto) {
  switch (next_proto) {
    case kProtoSPDY31:
      return NPN_SPDY_3_1;
    case kProtoHTTP2:
      return NPN_HTTP_2;
    case kProtoQUIC1SPDY3:
      return QUIC;

    case kProtoUnknown:
    case kProtoHTTP11:
      break;
  }

  NOTREACHED() << "Invalid NextProto: " << next_proto;
  return UNINITIALIZED_ALTERNATE_PROTOCOL;
}

std::string AlternativeService::ToString() const {
  return base::StringPrintf("%s %s:%d", AlternateProtocolToString(protocol),
                            host.c_str(), port);
}

std::string AlternativeServiceInfo::ToString() const {
  base::Time::Exploded exploded;
  expiration.LocalExplode(&exploded);
  return base::StringPrintf(
      "%s, expires %04d-%02d-%02d %02d:%02d:%02d",
      alternative_service.ToString().c_str(), exploded.year, exploded.month,
      exploded.day_of_month, exploded.hour, exploded.minute, exploded.second);
}

// static
void HttpServerProperties::ForceHTTP11(SSLConfig* ssl_config) {
  ssl_config->alpn_protos.clear();
  ssl_config->alpn_protos.push_back(kProtoHTTP11);
  ssl_config->npn_protos.clear();
  ssl_config->npn_protos.push_back(kProtoHTTP11);
}

}  // namespace net
