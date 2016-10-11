// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/mojo_proxy_struct_traits.h"

#include "base/logging.h"
#include "net/base/host_port_pair.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_server.h"

namespace mojo {

net::interfaces::ProxyScheme
EnumTraits<net::interfaces::ProxyScheme, net::ProxyServer::Scheme>::ToMojom(
    net::ProxyServer::Scheme scheme) {
  using net::ProxyServer;
  switch (scheme) {
    case ProxyServer::SCHEME_INVALID:
      return net::interfaces::ProxyScheme::INVALID;
    case ProxyServer::SCHEME_DIRECT:
      return net::interfaces::ProxyScheme::DIRECT;
    case ProxyServer::SCHEME_HTTP:
      return net::interfaces::ProxyScheme::HTTP;
    case ProxyServer::SCHEME_SOCKS4:
      return net::interfaces::ProxyScheme::SOCKS4;
    case ProxyServer::SCHEME_SOCKS5:
      return net::interfaces::ProxyScheme::SOCKS5;
    case ProxyServer::SCHEME_HTTPS:
      return net::interfaces::ProxyScheme::HTTPS;
    case ProxyServer::SCHEME_QUIC:
      return net::interfaces::ProxyScheme::QUIC;
  }
  NOTREACHED();
  return net::interfaces::ProxyScheme::INVALID;
}

bool EnumTraits<net::interfaces::ProxyScheme, net::ProxyServer::Scheme>::
    FromMojom(net::interfaces::ProxyScheme scheme,
              net::ProxyServer::Scheme* out) {
  using net::ProxyServer;
  switch (scheme) {
    case net::interfaces::ProxyScheme::INVALID:
      *out = ProxyServer::SCHEME_INVALID;
      return true;
    case net::interfaces::ProxyScheme::DIRECT:
      *out = ProxyServer::SCHEME_DIRECT;
      return true;
    case net::interfaces::ProxyScheme::HTTP:
      *out = ProxyServer::SCHEME_HTTP;
      return true;
    case net::interfaces::ProxyScheme::SOCKS4:
      *out = ProxyServer::SCHEME_SOCKS4;
      return true;
    case net::interfaces::ProxyScheme::SOCKS5:
      *out = ProxyServer::SCHEME_SOCKS5;
      return true;
    case net::interfaces::ProxyScheme::HTTPS:
      *out = ProxyServer::SCHEME_HTTPS;
      return true;
    case net::interfaces::ProxyScheme::QUIC:
      *out = ProxyServer::SCHEME_QUIC;
      return true;
  }
  return false;
}

base::StringPiece
StructTraits<net::interfaces::ProxyServerDataView, net::ProxyServer>::host(
    const net::ProxyServer& s) {
  if (s.scheme() == net::ProxyServer::SCHEME_DIRECT ||
      s.scheme() == net::ProxyServer::SCHEME_INVALID) {
    return base::StringPiece();
  }
  return s.host_port_pair().host();
}

uint16_t StructTraits<net::interfaces::ProxyServerDataView,
                      net::ProxyServer>::port(const net::ProxyServer& s) {
  if (s.scheme() == net::ProxyServer::SCHEME_DIRECT ||
      s.scheme() == net::ProxyServer::SCHEME_INVALID) {
    return 0;
  }
  return s.host_port_pair().port();
}

bool StructTraits<net::interfaces::ProxyServerDataView, net::ProxyServer>::Read(
    net::interfaces::ProxyServerDataView data,
    net::ProxyServer* out) {
  net::ProxyServer::Scheme scheme;
  if (!data.ReadScheme(&scheme))
    return false;

  base::StringPiece host;
  if (!data.ReadHost(&host))
    return false;

  if ((scheme == net::ProxyServer::SCHEME_DIRECT ||
       scheme == net::ProxyServer::SCHEME_INVALID) &&
      (!host.empty() || data.port())) {
    return false;
  }

  *out = net::ProxyServer(scheme,
                          net::HostPortPair(host.as_string(), data.port()));
  return true;
}

bool StructTraits<net::interfaces::ProxyInfoDataView, net::ProxyInfo>::Read(
    net::interfaces::ProxyInfoDataView data,
    net::ProxyInfo* out) {
  std::vector<net::ProxyServer> proxy_servers;
  if (!data.ReadProxyServers(&proxy_servers))
    return false;

  net::ProxyList proxy_list;
  for (const auto& server : proxy_servers)
    proxy_list.AddProxyServer(server);

  out->UseProxyList(proxy_list);
  return true;
}

}  // namespace mojo
