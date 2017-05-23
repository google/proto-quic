// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/logging.h"
#include "base/macros.h"
#include "base/run_loop.h"
#include "base/test/fuzzed_data_provider.h"
#include "net/base/net_errors.h"
#include "net/base/request_priority.h"
#include "net/log/net_log_source.h"
#include "net/log/test_net_log.h"
#include "net/socket/fuzzed_socket_factory.h"
#include "net/spdy/chromium/spdy_test_util_common.h"

namespace {

class FuzzerDelegate : public net::SpdyStream::Delegate {
 public:
  explicit FuzzerDelegate(const base::Closure& done_closure)
      : done_closure_(done_closure) {}

  void OnHeadersSent() override {}
  void OnHeadersReceived(
      const net::SpdyHeaderBlock& response_headers) override {}
  void OnDataReceived(std::unique_ptr<net::SpdyBuffer> buffer) override {}
  void OnDataSent() override {}
  void OnTrailers(const net::SpdyHeaderBlock& trailers) override {}

  void OnClose(int status) override { done_closure_.Run(); }

  net::NetLogSource source_dependency() const override {
    return net::NetLogSource();
  }

 private:
  base::Closure done_closure_;
  DISALLOW_COPY_AND_ASSIGN(FuzzerDelegate);
};

}  // namespace

// Fuzzer for SpdySession
//
// |data| is used to create a FuzzedServerSocket.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  net::BoundTestNetLog bound_test_net_log;
  base::FuzzedDataProvider data_provider(data, size);
  net::FuzzedSocketFactory socket_factory(&data_provider);
  socket_factory.set_fuzz_connect_result(false);
  net::SpdySessionDependencies deps;
  std::unique_ptr<net::HttpNetworkSession> http_session(
      net::SpdySessionDependencies::SpdyCreateSessionWithSocketFactory(
          &deps, &socket_factory));

  net::ProxyServer direct_connect(net::ProxyServer::Direct());
  net::SpdySessionKey session_key(net::HostPortPair("127.0.0.1", 80),
                                  direct_connect, net::PRIVACY_MODE_DISABLED);
  base::WeakPtr<net::SpdySession> spdy_session(net::CreateInsecureSpdySession(
      http_session.get(), session_key, bound_test_net_log.bound()));

  net::SpdyStreamRequest stream_request;
  base::WeakPtr<net::SpdyStream> stream;

  net::TestCompletionCallback wait_for_start;
  int rv = stream_request.StartRequest(
      net::SPDY_REQUEST_RESPONSE_STREAM, spdy_session,
      GURL("http://www.example.invalid/"), net::DEFAULT_PRIORITY,
      bound_test_net_log.bound(), wait_for_start.callback());

  if (rv == net::ERR_IO_PENDING) {
    rv = wait_for_start.WaitForResult();
  }

  // Re-check the status after potential event loop.
  if (rv != net::OK) {
    LOG(WARNING) << "StartRequest failed with result=" << rv;
    return 0;
  }

  stream = stream_request.ReleaseStream();
  stream->SendRequestHeaders(
      net::SpdyTestUtil::ConstructGetHeaderBlock("http://www.example.invalid"),
      net::NO_MORE_DATA_TO_SEND);

  base::RunLoop run_loop;
  FuzzerDelegate delegate(run_loop.QuitClosure());
  stream->SetDelegate(&delegate);
  run_loop.Run();

  // Give a chance for GOING_AWAY sessions to wrap up.
  base::RunLoop().RunUntilIdle();

  return 0;
}
