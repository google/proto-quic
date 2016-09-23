// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DNS_MOJO_HOST_TYPE_CONVERTERS_H_
#define NET_DNS_MOJO_HOST_TYPE_CONVERTERS_H_

#include "net/dns/host_resolver.h"
#include "net/interfaces/host_resolver_service.mojom.h"

namespace mojo {

template <>
struct TypeConverter<net::HostResolver::RequestInfo,
                     net::interfaces::HostResolverRequestInfo> {
  static net::HostResolver::RequestInfo Convert(
      const net::interfaces::HostResolverRequestInfo& obj);
};

template <>
struct TypeConverter<net::interfaces::HostResolverRequestInfoPtr,
                     net::HostResolver::RequestInfo> {
  static net::interfaces::HostResolverRequestInfoPtr Convert(
      const net::HostResolver::RequestInfo& obj);
};

template <>
struct TypeConverter<net::interfaces::AddressListPtr, net::AddressList> {
  static net::interfaces::AddressListPtr Convert(const net::AddressList& obj);
};

template <>
struct TypeConverter<net::AddressList, net::interfaces::AddressList> {
  static net::AddressList Convert(const net::interfaces::AddressList& obj);
};

}  // namespace mojo

#endif  // NET_DNS_MOJO_HOST_TYPE_CONVERTERS_H_
