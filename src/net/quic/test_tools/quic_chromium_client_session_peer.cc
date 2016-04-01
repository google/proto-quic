// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_chromium_client_session_peer.h"

#include "net/quic/quic_chromium_client_session.h"

namespace net {
namespace test {

// static
void QuicChromiumClientSessionPeer::SetMaxOpenStreams(
    QuicChromiumClientSession* session,
    size_t max_streams,
    size_t default_streams) {
  session->config()->SetMaxStreamsPerConnection(max_streams, default_streams);
}

// static
void QuicChromiumClientSessionPeer::SetChannelIDSent(
    QuicChromiumClientSession* session,
    bool channel_id_sent) {
  session->crypto_stream_->channel_id_sent_ = channel_id_sent;
}

// static
void QuicChromiumClientSessionPeer::SetHostname(
    QuicChromiumClientSession* session,
    const std::string& hostname) {
  QuicServerId server_id(hostname, session->server_id_.port(),
                         session->server_id_.privacy_mode());
  session->server_id_ = server_id;
}

}  // namespace test
}  // namespace net
