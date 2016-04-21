// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/socket_net_log_params.h"

#include <utility>

#include "base/bind.h"
#include "base/values.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_endpoint.h"

namespace net {

namespace {

std::unique_ptr<base::Value> NetLogSocketErrorCallback(
    int net_error,
    int os_error,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("net_error", net_error);
  dict->SetInteger("os_error", os_error);
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogHostPortPairCallback(
    const HostPortPair* host_and_port,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("host_and_port", host_and_port->ToString());
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogIPEndPointCallback(
    const IPEndPoint* address,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("address", address->ToString());
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogSourceAddressCallback(
    const struct sockaddr* net_address,
    socklen_t address_len,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  IPEndPoint ipe;
  bool result = ipe.FromSockAddr(net_address, address_len);
  DCHECK(result);
  dict->SetString("source_address", ipe.ToString());
  return std::move(dict);
}

}  // namespace

NetLog::ParametersCallback CreateNetLogSocketErrorCallback(int net_error,
                                                           int os_error) {
  return base::Bind(&NetLogSocketErrorCallback, net_error, os_error);
}

NetLog::ParametersCallback CreateNetLogHostPortPairCallback(
    const HostPortPair* host_and_port) {
  return base::Bind(&NetLogHostPortPairCallback, host_and_port);
}

NetLog::ParametersCallback CreateNetLogIPEndPointCallback(
    const IPEndPoint* address) {
  return base::Bind(&NetLogIPEndPointCallback, address);
}

NetLog::ParametersCallback CreateNetLogSourceAddressCallback(
    const struct sockaddr* net_address,
    socklen_t address_len) {
  return base::Bind(&NetLogSourceAddressCallback, net_address, address_len);
}

}  // namespace net
