// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory.h"

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "net/base/host_mapping_rules.h"
#include "net/base/host_port_pair.h"
#include "net/base/parse_number.h"
#include "net/base/port_util.h"
#include "net/http/http_network_session.h"
#include "net/http/http_response_headers.h"
#include "net/quic/quic_protocol.h"
#include "net/spdy/spdy_alt_svc_wire_format.h"
#include "url/gurl.h"

namespace net {

// WARNING: If you modify or add any static flags, you must keep them in sync
// with |ResetStaticSettingsToInit|. This is critical for unit test isolation.

// static
bool HttpStreamFactory::spdy_enabled_ = true;

HttpStreamFactory::~HttpStreamFactory() {}

// static
void HttpStreamFactory::ResetStaticSettingsToInit() {
  spdy_enabled_ = true;
}

void HttpStreamFactory::ProcessAlternativeServices(
    HttpNetworkSession* session,
    const HttpResponseHeaders* headers,
    const url::SchemeHostPort& http_server) {
  if (session->params().parse_alternative_services) {
    if (headers->HasHeader(kAlternativeServiceHeader)) {
      std::string alternative_service_str;
      headers->GetNormalizedHeader(kAlternativeServiceHeader,
                                   &alternative_service_str);
      ProcessAlternativeService(session->http_server_properties(),
                                alternative_service_str, http_server, *session);
    }
    // If "Alt-Svc" is enabled, then ignore "Alternate-Protocol".
    return;
  }

  if (!headers->HasHeader(kAlternateProtocolHeader))
    return;

  std::vector<std::string> alternate_protocol_values;
  size_t iter = 0;
  std::string alternate_protocol_str;
  while (headers->EnumerateHeader(&iter, kAlternateProtocolHeader,
                                  &alternate_protocol_str)) {
    base::TrimWhitespaceASCII(alternate_protocol_str, base::TRIM_ALL,
                              &alternate_protocol_str);
    if (!alternate_protocol_str.empty()) {
      alternate_protocol_values.push_back(alternate_protocol_str);
    }
  }

  ProcessAlternateProtocol(session->http_server_properties(),
                           alternate_protocol_values, http_server, *session);
}

GURL HttpStreamFactory::ApplyHostMappingRules(const GURL& url,
                                              HostPortPair* endpoint) {
  const HostMappingRules* mapping_rules = GetHostMappingRules();
  if (mapping_rules && mapping_rules->RewriteHost(endpoint)) {
    url::Replacements<char> replacements;
    const std::string port_str = base::UintToString(endpoint->port());
    replacements.SetPort(port_str.c_str(), url::Component(0, port_str.size()));
    replacements.SetHost(endpoint->host().c_str(),
                         url::Component(0, endpoint->host().size()));
    return url.ReplaceComponents(replacements);
  }
  return url;
}

HttpStreamFactory::HttpStreamFactory() {}

void HttpStreamFactory::ProcessAlternativeService(
    const base::WeakPtr<HttpServerProperties>& http_server_properties,
    base::StringPiece alternative_service_str,
    const url::SchemeHostPort& http_server,
    const HttpNetworkSession& session) {
  SpdyAltSvcWireFormat::AlternativeServiceVector alternative_service_vector;
  if (!SpdyAltSvcWireFormat::ParseHeaderFieldValue(
          alternative_service_str, &alternative_service_vector)) {
    return;
  }

  // Convert SpdyAltSvcWireFormat::AlternativeService entries
  // to net::AlternativeServiceInfo.
  AlternativeServiceInfoVector alternative_service_info_vector;
  for (const SpdyAltSvcWireFormat::AlternativeService&
           alternative_service_entry : alternative_service_vector) {
    AlternateProtocol protocol =
        AlternateProtocolFromString(alternative_service_entry.protocol_id);
    if (!IsAlternateProtocolValid(protocol) ||
        !session.IsProtocolEnabled(protocol) ||
        !IsPortValid(alternative_service_entry.port)) {
      continue;
    }
    // Check if QUIC version is supported.
    if (protocol == QUIC && !alternative_service_entry.version.empty()) {
      bool match_found = false;
      for (QuicVersion supported : session.params().quic_supported_versions) {
        for (uint16_t advertised : alternative_service_entry.version) {
          if (supported == advertised) {
            match_found = true;
            break;
          }
        }
        if (match_found) {
          break;
        }
      }
      if (!match_found) {
        continue;
      }
    }
    AlternativeService alternative_service(protocol,
                                           alternative_service_entry.host,
                                           alternative_service_entry.port);
    base::Time expiration =
        base::Time::Now() +
        base::TimeDelta::FromSeconds(alternative_service_entry.max_age);
    AlternativeServiceInfo alternative_service_info(alternative_service,
                                                    expiration);
    alternative_service_info_vector.push_back(alternative_service_info);
  }

  http_server_properties->SetAlternativeServices(
      RewriteHost(http_server), alternative_service_info_vector);
}

void HttpStreamFactory::ProcessAlternateProtocol(
    const base::WeakPtr<HttpServerProperties>& http_server_properties,
    const std::vector<std::string>& alternate_protocol_values,
    const url::SchemeHostPort& http_server,
    const HttpNetworkSession& session) {
  AlternateProtocol protocol = UNINITIALIZED_ALTERNATE_PROTOCOL;
  int port = 0;
  bool is_valid = true;
  for (size_t i = 0; i < alternate_protocol_values.size(); ++i) {
    base::StringPiece alternate_protocol_str = alternate_protocol_values[i];
    if (base::StartsWith(alternate_protocol_str, "p=",
                         base::CompareCase::SENSITIVE)) {
      // Ignore deprecated probability.
      continue;
    }
    std::vector<base::StringPiece> port_protocol_vector =
        base::SplitStringPiece(alternate_protocol_str, ":",
                               base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
    if (port_protocol_vector.size() != 2) {
      DVLOG(1) << kAlternateProtocolHeader
               << " header has too many tokens: "
               << alternate_protocol_str;
      is_valid = false;
      break;
    }

    if (!ParseInt32(port_protocol_vector[0], ParseIntFormat::NON_NEGATIVE,
                    &port) ||
        port == 0 || !IsPortValid(port)) {
      DVLOG(1) << kAlternateProtocolHeader
               << " header has unrecognizable port: "
               << port_protocol_vector[0];
      is_valid = false;
      break;
    }

    protocol = AlternateProtocolFromString(port_protocol_vector[1].as_string());

    if (IsAlternateProtocolValid(protocol) &&
        !session.IsProtocolEnabled(protocol)) {
      DVLOG(1) << kAlternateProtocolHeader
               << " header has unrecognized protocol: "
               << port_protocol_vector[1];
      is_valid = false;
      break;
    }
  }

  if (!is_valid || protocol == UNINITIALIZED_ALTERNATE_PROTOCOL) {
    http_server_properties->ClearAlternativeServices(http_server);
    return;
  }

  http_server_properties->SetAlternativeService(
      RewriteHost(http_server),
      AlternativeService(protocol, "", static_cast<uint16_t>(port)),
      base::Time::Now() + base::TimeDelta::FromDays(30));
}

url::SchemeHostPort HttpStreamFactory::RewriteHost(
    const url::SchemeHostPort& server) {
  HostPortPair host_port_pair(server.host(), server.port());
  const HostMappingRules* mapping_rules = GetHostMappingRules();
  if (mapping_rules)
    mapping_rules->RewriteHost(&host_port_pair);
  return url::SchemeHostPort(server.scheme(), host_port_pair.host(),
                             host_port_pair.port());
}

}  // namespace net
