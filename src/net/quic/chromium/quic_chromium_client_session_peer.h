// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_QUIC_CHROMIUM_CLIENT_SESSION_PEER_H_
#define NET_QUIC_TEST_TOOLS_QUIC_CHROMIUM_CLIENT_SESSION_PEER_H_

#include <stddef.h>

#include <string>

#include "base/macros.h"
#include "net/quic/core/quic_protocol.h"

namespace net {

class QuicChromiumClientSession;

namespace test {

class QuicChromiumClientSessionPeer {
 public:
  static void SetMaxOpenStreams(QuicChromiumClientSession* session,
                                size_t max_streams,
                                size_t default_streams);

  static void SetChannelIDSent(QuicChromiumClientSession* session,
                               bool channel_id_sent);

  static void SetHostname(QuicChromiumClientSession* session,
                          const std::string& hostname);

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicChromiumClientSessionPeer);
};

}  // namespace test
}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_QUIC_CHROMIUM_CLIENT_SESSION_PEER_H_
