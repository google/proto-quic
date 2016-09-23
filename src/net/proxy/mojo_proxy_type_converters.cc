// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/mojo_proxy_type_converters.h"

#include "base/logging.h"
#include "net/base/host_port_pair.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_server.h"

namespace net {
namespace {

interfaces::ProxyScheme ProxySchemeToMojo(ProxyServer::Scheme scheme) {
  switch (scheme) {
    case ProxyServer::SCHEME_INVALID:
      return interfaces::ProxyScheme::INVALID;
    case ProxyServer::SCHEME_DIRECT:
      return interfaces::ProxyScheme::DIRECT;
    case ProxyServer::SCHEME_HTTP:
      return interfaces::ProxyScheme::HTTP;
    case ProxyServer::SCHEME_SOCKS4:
      return interfaces::ProxyScheme::SOCKS4;
    case ProxyServer::SCHEME_SOCKS5:
      return interfaces::ProxyScheme::SOCKS5;
    case ProxyServer::SCHEME_HTTPS:
      return interfaces::ProxyScheme::HTTPS;
    case ProxyServer::SCHEME_QUIC:
      return interfaces::ProxyScheme::QUIC;
  }
  NOTREACHED();
  return interfaces::ProxyScheme::INVALID;
}

ProxyServer::Scheme ProxySchemeFromMojo(interfaces::ProxyScheme scheme) {
  switch (scheme) {
    case interfaces::ProxyScheme::INVALID:
      return ProxyServer::SCHEME_INVALID;
    case interfaces::ProxyScheme::DIRECT:
      return ProxyServer::SCHEME_DIRECT;
    case interfaces::ProxyScheme::HTTP:
      return ProxyServer::SCHEME_HTTP;
    case interfaces::ProxyScheme::SOCKS4:
      return ProxyServer::SCHEME_SOCKS4;
    case interfaces::ProxyScheme::SOCKS5:
      return ProxyServer::SCHEME_SOCKS5;
    case interfaces::ProxyScheme::HTTPS:
      return ProxyServer::SCHEME_HTTPS;
    case interfaces::ProxyScheme::QUIC:
      return ProxyServer::SCHEME_QUIC;
  }
  NOTREACHED();
  return ProxyServer::SCHEME_INVALID;
}

}  // namespace
}  // namespace net

namespace mojo {

// static
net::interfaces::ProxyServerPtr
TypeConverter<net::interfaces::ProxyServerPtr, net::ProxyServer>::Convert(
    const net::ProxyServer& obj) {
  net::interfaces::ProxyServerPtr server(net::interfaces::ProxyServer::New());
  server->scheme = net::ProxySchemeToMojo(obj.scheme());
  if (server->scheme != net::interfaces::ProxyScheme::DIRECT &&
      server->scheme != net::interfaces::ProxyScheme::INVALID) {
    server->host = obj.host_port_pair().host();
    server->port = obj.host_port_pair().port();
  }
  return server;
}

// static
net::ProxyServer
TypeConverter<net::ProxyServer, net::interfaces::ProxyServerPtr>::Convert(
    const net::interfaces::ProxyServerPtr& obj) {
  return net::ProxyServer(net::ProxySchemeFromMojo(obj->scheme),
                          net::HostPortPair(obj->host, obj->port));
}

// static
net::ProxyInfo
TypeConverter<net::ProxyInfo, mojo::Array<net::interfaces::ProxyServerPtr>>::
    Convert(const mojo::Array<net::interfaces::ProxyServerPtr>& obj) {
  net::ProxyList proxy_list;
  for (size_t i = 0; i < obj.size(); i++) {
    proxy_list.AddProxyServer(obj[i].To<net::ProxyServer>());
  }
  net::ProxyInfo info;
  info.UseProxyList(proxy_list);
  return info;
}

}  // namespace mojo
