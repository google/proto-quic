// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_PROXY_MOJO_PROXY_STRUCT_TRAITS_H_
#define NET_PROXY_MOJO_PROXY_STRUCT_TRAITS_H_

#include "base/strings/string_piece.h"
#include "mojo/public/cpp/bindings/enum_traits.h"
#include "mojo/public/cpp/bindings/struct_traits.h"
#include "net/base/host_port_pair.h"
#include "net/interfaces/proxy_resolver_service.mojom.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_list.h"
#include "net/proxy/proxy_server.h"

namespace net {
class ProxyInfo;
class ProxyServer;
}

namespace mojo {

template <>
struct EnumTraits<net::interfaces::ProxyScheme, net::ProxyServer::Scheme> {
  static net::interfaces::ProxyScheme ToMojom(net::ProxyServer::Scheme scheme);
  static bool FromMojom(net::interfaces::ProxyScheme scheme,
                        net::ProxyServer::Scheme* out);
};

template <>
struct StructTraits<net::interfaces::ProxyServerDataView, net::ProxyServer> {
  static net::ProxyServer::Scheme scheme(const net::ProxyServer& s) {
    return s.scheme();
  }

  static base::StringPiece host(const net::ProxyServer& s);
  static uint16_t port(const net::ProxyServer& s);

  static bool Read(net::interfaces::ProxyServerDataView data,
                   net::ProxyServer* out);
};

template <>
struct StructTraits<net::interfaces::ProxyInfoDataView, net::ProxyInfo> {
  static const std::vector<net::ProxyServer>& proxy_servers(
      const net::ProxyInfo& info) {
    return info.proxy_list().GetAll();
  }

  static bool Read(net::interfaces::ProxyInfoDataView data,
                   net::ProxyInfo* out);
};

}  // namespace mojo

#endif  // NET_PROXY_MOJO_PROXY_STRUCT_TRAITS_H_
