// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_proxy_client_socket.h"

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>

#include "base/logging.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/fuzzed_data_provider.h"
#include "net/base/address_list.h"
#include "net/base/auth.h"
#include "net/base/host_port_pair.h"
#include "net/base/test_completion_callback.h"
#include "net/http/http_auth_cache.h"
#include "net/http/http_auth_handler_basic.h"
#include "net/http/http_auth_handler_digest.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_auth_scheme.h"
#include "net/log/test_net_log.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/fuzzed_socket.h"
#include "net/socket/next_proto.h"

// Fuzzer for HttpProxyClientSocket only tests establishing a connection when
// using the proxy as a tunnel.
//
// |data| is used to create a FuzzedSocket to fuzz reads and writes, see that
// class for details.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Use a test NetLog, to exercise logging code.
  net::TestNetLog test_net_log;

  base::FuzzedDataProvider data_provider(data, size);

  net::TestCompletionCallback callback;
  std::unique_ptr<net::FuzzedSocket> fuzzed_socket(
      new net::FuzzedSocket(&data_provider, &test_net_log));
  CHECK_EQ(net::OK, fuzzed_socket->Connect(callback.callback()));

  std::unique_ptr<net::ClientSocketHandle> socket_handle(
      new net::ClientSocketHandle());
  socket_handle->SetSocket(std::move(fuzzed_socket));

  // Create auth handler supporting basic and digest schemes.  Other schemes can
  // make system calls, which doesn't seem like a great idea.
  net::HttpAuthCache auth_cache;
  net::HttpAuthHandlerRegistryFactory auth_handler_factory;
  auth_handler_factory.RegisterSchemeFactory(
      net::kBasicAuthScheme, new net::HttpAuthHandlerBasic::Factory());
  auth_handler_factory.RegisterSchemeFactory(
      net::kDigestAuthScheme, new net::HttpAuthHandlerDigest::Factory());

  scoped_refptr<net::HttpAuthController> auth_controller(
      new net::HttpAuthController(net::HttpAuth::AUTH_PROXY,
                                  GURL("http://proxy:42/"), &auth_cache,
                                  &auth_handler_factory));
  // Determine if the HttpProxyClientSocket should be told the underlying socket
  // is HTTPS.
  bool is_https_proxy = data_provider.ConsumeBool();
  net::HttpProxyClientSocket socket(
      socket_handle.release(), "Bond/007", net::HostPortPair("foo", 80),
      net::HostPortPair("proxy", 42), auth_controller.get(), true /* tunnel */,
      false /* using_spdy */, net::kProtoUnknown, nullptr /* proxy_delegate */,
      is_https_proxy);
  int result = socket.Connect(callback.callback());
  result = callback.GetResult(result);

  // Repeatedly try to log in with the same credentials.
  while (result == net::ERR_PROXY_AUTH_REQUESTED) {
    auth_controller->ResetAuth(net::AuthCredentials(
        base::ASCIIToUTF16("user"), base::ASCIIToUTF16("pass")));
    result = socket.RestartWithAuth(callback.callback());
    result = callback.GetResult(result);
  }

  return 0;
}
