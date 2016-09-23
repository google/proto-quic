// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/server_socket.h"

#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"

namespace net {

ServerSocket::ServerSocket() {
}

ServerSocket::~ServerSocket() {
}

int ServerSocket::ListenWithAddressAndPort(const std::string& address_string,
                                           uint16_t port,
                                           int backlog) {
  IPAddress ip_address;
  if (!ip_address.AssignFromIPLiteral(address_string)) {
    return ERR_ADDRESS_INVALID;
  }

  return Listen(IPEndPoint(ip_address, port), backlog);
}

}  // namespace net
