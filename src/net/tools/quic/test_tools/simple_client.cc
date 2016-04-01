// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/test_tools/simple_client.h"

namespace net {
namespace test {

void SimpleClient::WaitForResponse() {
  WaitForResponseForMs(-1);
}

// Waits for some data or response from the server.
void SimpleClient::WaitForInitialResponse() {
  WaitForInitialResponseForMs(-1);
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
