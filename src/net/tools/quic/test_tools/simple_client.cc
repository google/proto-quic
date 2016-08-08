// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/test_tools/simple_client.h"

#include "net/tools/balsa/balsa_headers.h"

namespace net {
namespace test {

void SimpleClient::WaitForResponse() {
  WaitForResponseForMs(-1);
}

// Waits for some data or response from the server.
void SimpleClient::WaitForInitialResponse() {
  WaitForInitialResponseForMs(-1);
}

void SimpleClient::WaitForResponseForMs(int timeout_ms) {
  WaitUntil(timeout_ms, [this]() { return response_complete(); });
  if (response_complete()) {
    VLOG(1) << "Client received response:" << response_headers()->DebugString()
            << response_body();
  }
}

void SimpleClient::WaitForInitialResponseForMs(int timeout_ms) {
  WaitUntil(timeout_ms, [this]() { return response_size() != 0; });
}

int SimpleClient::ResetSocket() {
  LOG(FATAL) << "SimpleClient::ResetSocket is not implemented";
  return 0;
}

int SimpleClient::HalfClose() {
  LOG(FATAL) << "SimpleClient::HalfClose is not implemented";
  return 0;
}

int SimpleClient::response_header_size() const {
  return 0;
}

int64_t SimpleClient::response_body_size() const {
  return 0;
}

}  // namespace net
}  // namespace test
