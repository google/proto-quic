// Copyright (c) 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_NETWORK_INTERFACES_MAC_H_
#define NET_BASE_NETWORK_INTERFACES_MAC_H_

// This file is only used to expose some of the internals
// of network_interfaces_mac.cc to tests.

#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/base/network_interfaces.h"

struct ifaddrs;
struct sockaddr;

namespace net {
namespace internal {

class NET_EXPORT IPAttributesGetterMac {
 public:
  IPAttributesGetterMac() {}
  virtual ~IPAttributesGetterMac() {}
  virtual bool IsInitialized() const = 0;
  virtual bool GetIPAttributes(const char* ifname,
                               const sockaddr* sock_addr,
                               int* native_attributes) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(IPAttributesGetterMac);
};

NET_EXPORT bool GetNetworkListImpl(NetworkInterfaceList* networks,
                                   int policy,
                                   const ifaddrs* interfaces,
                                   IPAttributesGetterMac* ip_attributes_getter);

}  // namespace internal
}  // namespace net

#endif  // NET_BASE_NETWORK_INTERFACES_MAC_H_
