// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_IP_ADDRESS_NUMBER_H_
#define NET_BASE_IP_ADDRESS_NUMBER_H_

#include <vector>

namespace net {

// IPAddressNumber is used to represent an IP address's numeric value as an
// array of bytes, from most significant to least significant. This is the
// network byte ordering.
//
// IPv4 addresses will have length 4, whereas IPv6 address will have length 16.
//
// TODO(Martijnc): Remove the IPAddressNumber typedef. New code should use
// IPAddress instead and existing code should be switched over.
// https://crbug.com/496258
typedef std::vector<unsigned char> IPAddressNumber;

static const size_t kIPv4AddressSize = 4;
static const size_t kIPv6AddressSize = 16;

}  // namespace net

#endif  // NET_BASE_IP_ADDRESS_NUMBER_H_
