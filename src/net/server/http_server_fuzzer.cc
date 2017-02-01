// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/test/fuzzed_data_provider.h"
#include "net/base/net_errors.h"
#include "net/log/test_net_log.h"
#include "net/server/http_server.h"
#include "net/socket/fuzzed_server_socket.h"

namespace {

class WaitTillHttpCloseDelegate : public net::HttpServer::Delegate {
 public:
  WaitTillHttpCloseDelegate(base::FuzzedDataProvider* data_provider,
                            const base::Closure& done_closure)
      : server_(nullptr),
        data_provider_(data_provider),
        done_closure_(done_closure),
        action_flags_(data_provider_->ConsumeUint8()) {}

  void set_server(net::HttpServer* server) { server_ = server; }

  void OnConnect(int connection_id) override {
    if (!(action_flags_ & ACCEPT_CONNECTION))
      server_->Close(connection_id);
  }

  void OnHttpRequest(int connection_id,
                     const net::HttpServerRequestInfo& info) override {
    if (!(action_flags_ & ACCEPT_MESSAGE)) {
      server_->Close(connection_id);
      return;
    }

    if (action_flags_ & REPLY_TO_MESSAGE) {
      server_->Send200(connection_id,
                       data_provider_->ConsumeRandomLengthString(64),
                       "text/html");
    }
  }

  void OnWebSocketRequest(int connection_id,
                          const net::HttpServerRequestInfo& info) override {
    if (action_flags_ & CLOSE_WEBSOCKET_RATHER_THAN_ACCEPT) {
      server_->Close(connection_id);
      return;
    }

    if (action_flags_ & ACCEPT_WEBSOCKET)
      server_->AcceptWebSocket(connection_id, info);
  }

  void OnWebSocketMessage(int connection_id, const std::string& data) override {
    if (!(action_flags_ & ACCEPT_MESSAGE)) {
      server_->Close(connection_id);
      return;
    }

    if (action_flags_ & REPLY_TO_MESSAGE) {
      server_->SendOverWebSocket(connection_id,
                                 data_provider_->ConsumeRandomLengthString(64));
    }
  }

  void OnClose(int connection_id) override { done_closure_.Run(); }

 private:
  enum {
    ACCEPT_CONNECTION = 1,
    ACCEPT_MESSAGE = 2,
    REPLY_TO_MESSAGE = 4,
    ACCEPT_WEBSOCKET = 8,
    CLOSE_WEBSOCKET_RATHER_THAN_ACCEPT = 16
  };

  net::HttpServer* server_;
  base::FuzzedDataProvider* const data_provider_;
  base::Closure done_closure_;
  const uint8_t action_flags_;

  DISALLOW_COPY_AND_ASSIGN(WaitTillHttpCloseDelegate);
};

}  // namespace

// Fuzzer for HttpServer
//
// |data| is used to create a FuzzedServerSocket.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  net::TestNetLog test_net_log;
  base::FuzzedDataProvider data_provider(data, size);

  std::unique_ptr<net::ServerSocket> server_socket(
      base::MakeUnique<net::FuzzedServerSocket>(&data_provider, &test_net_log));
  CHECK_EQ(net::OK,
           server_socket->ListenWithAddressAndPort("127.0.0.1", 80, 5));

  base::RunLoop run_loop;
  WaitTillHttpCloseDelegate delegate(&data_provider, run_loop.QuitClosure());
  net::HttpServer server(std::move(server_socket), &delegate);
  delegate.set_server(&server);
  run_loop.Run();
  return 0;
}
