// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/net_test_suite.h"

#include "base/message_loop/message_loop.h"
#include "net/base/network_change_notifier.h"
#include "net/http/http_stream_factory.h"
#include "net/spdy/spdy_session.h"
#include "testing/gtest/include/gtest/gtest.h"

#if defined(USE_NSS_CERTS)
#include "net/cert_net/nss_ocsp.h"
#endif

NetTestSuite::NetTestSuite(int argc, char** argv)
    : TestSuite(argc, argv) {
}

NetTestSuite::~NetTestSuite() {}

void NetTestSuite::Initialize() {
  TestSuite::Initialize();
  InitializeTestThread();
}

void NetTestSuite::Shutdown() {
#if defined(USE_NSS_CERTS)
  net::ShutdownNSSHttpIO();
#endif

  // We want to destroy this here before the TestSuite continues to tear down
  // the environment.
  message_loop_.reset();

  TestSuite::Shutdown();
}

void NetTestSuite::InitializeTestThread() {
  network_change_notifier_.reset(net::NetworkChangeNotifier::CreateMock());

  InitializeTestThreadNoNetworkChangeNotifier();
}

void NetTestSuite::InitializeTestThreadNoNetworkChangeNotifier() {
  host_resolver_proc_ = new net::RuleBasedHostResolverProc(NULL);
  scoped_host_resolver_proc_.Init(host_resolver_proc_.get());
  // In case any attempts are made to resolve host names, force them all to
  // be mapped to localhost.  This prevents DNS queries from being sent in
  // the process of running these unit tests.
  host_resolver_proc_->AddRule("*", "127.0.0.1");

  message_loop_.reset(new base::MessageLoopForIO());
}
