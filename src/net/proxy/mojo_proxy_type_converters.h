// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_PROXY_MOJO_PROXY_TYPE_CONVERTERS_H_
#define NET_PROXY_MOJO_PROXY_TYPE_CONVERTERS_H_

#include "mojo/public/cpp/bindings/type_converter.h"
#include "net/interfaces/proxy_resolver_service.mojom.h"

namespace net {
class ProxyInfo;
class ProxyServer;
}

namespace mojo {

template <>
struct TypeConverter<net::interfaces::ProxyServerPtr, net::ProxyServer> {
  static net::interfaces::ProxyServerPtr Convert(const net::ProxyServer& obj);
};

template <>
struct TypeConverter<net::ProxyServer, net::interfaces::ProxyServerPtr> {
  static net::ProxyServer Convert(const net::interfaces::ProxyServerPtr& obj);
};

template <>
struct TypeConverter<net::ProxyInfo,
                     mojo::Array<net::interfaces::ProxyServerPtr>> {
  static net::ProxyInfo Convert(
      const mojo::Array<net::interfaces::ProxyServerPtr>& obj);
};

}  // namespace mojo

#endif  // NET_PROXY_MOJO_PROXY_TYPE_CONVERTERS_H_
