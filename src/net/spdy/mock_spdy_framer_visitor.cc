// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/mock_spdy_framer_visitor.h"

namespace net {

namespace test {

MockSpdyFramerVisitor::MockSpdyFramerVisitor() {
  DelegateNewHeaderHandling();
}

MockSpdyFramerVisitor::~MockSpdyFramerVisitor() {}

}  // namespace test

}  // namespace net
