// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_MOCK_QUIC_SPDY_CLIENT_STREAM_H_
#define NET_QUIC_TEST_TOOLS_MOCK_QUIC_SPDY_CLIENT_STREAM_H_

#include "base/macros.h"
#include "net/quic/quic_protocol.h"
#include "net/tools/quic/quic_spdy_client_stream.h"
#include "testing/gmock/include/gmock/gmock.h"
// #include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

class MockQuicSpdyClientStream : public net::QuicSpdyClientStream {
 public:
  MockQuicSpdyClientStream(QuicStreamId id, net::QuicClientSession* session);
  ~MockQuicSpdyClientStream() override;

  MOCK_METHOD1(OnStreamFrame, void(const QuicStreamFrame& frame));
  MOCK_METHOD2(OnInitialHeadersComplete, void(bool fin, size_t frame_len));
  MOCK_METHOD3(OnTrailingHeadersComplete,
               void(bool fin,
                    size_t frame_len,
                    const QuicHeaderList& header_list));
  MOCK_METHOD1(OnPromiseHeaders, void(base::StringPiece headers_data));
  MOCK_METHOD2(OnPromiseHeadersComplete,
               void(QuicStreamId promised_stream_id, size_t frame_len));
  MOCK_METHOD0(OnDataAvailable, void());
};

}  // namespace test
}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_MOCK_QUIC_SPDY_CLIENT_STREAM_H_
