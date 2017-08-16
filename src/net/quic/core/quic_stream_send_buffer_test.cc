// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_stream_send_buffer.h"

#include "net/quic/core/quic_data_writer.h"
#include "net/quic/core/quic_simple_buffer_allocator.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_test.h"
#include "net/quic/test_tools/quic_test_utils.h"

using std::string;

namespace net {
namespace test {
namespace {

struct iovec MakeIovec(QuicStringPiece data) {
  struct iovec iov = {const_cast<char*>(data.data()),
                      static_cast<size_t>(data.size())};
  return iov;
}

class QuicStreamSendBufferTest : public QuicTest {
 public:
  QuicStreamSendBufferTest() : send_buffer_(&allocator_) {
    EXPECT_EQ(0u, send_buffer_.size());
    string data1(1536, 'a');
    string data2(256, 'b');
    string data3(2048, 'c');
    struct iovec iov[3];
    iov[0] = MakeIovec(QuicStringPiece(data1));
    iov[1] = MakeIovec(QuicStringPiece(data2));
    iov[2] = MakeIovec(QuicStringPiece(data3));
    QuicIOVector quic_iov(iov, 3, 3840);

    // Save all data.
    SetQuicFlag(&FLAGS_quic_send_buffer_max_data_slice_size, 1024);
    send_buffer_.SaveStreamData(quic_iov, 0, 3840);
    EXPECT_EQ(4u, send_buffer_.size());
  }

  SimpleBufferAllocator allocator_;
  QuicStreamSendBuffer send_buffer_;
};

TEST_F(QuicStreamSendBufferTest, CopyDataToBuffer) {
  char buf[4000];
  QuicDataWriter writer(4000, buf, Perspective::IS_CLIENT, HOST_BYTE_ORDER);
  string copy1(1024, 'a');
  string copy2 = string(512, 'a') + string(256, 'b') + string(256, 'c');
  string copy3(1024, 'c');
  string copy4(768, 'c');

  ASSERT_TRUE(send_buffer_.WriteStreamData(0, 1024, &writer));
  EXPECT_EQ(copy1, QuicStringPiece(buf, 1024));
  ASSERT_TRUE(send_buffer_.WriteStreamData(1024, 1024, &writer));
  EXPECT_EQ(copy2, QuicStringPiece(buf + 1024, 1024));
  ASSERT_TRUE(send_buffer_.WriteStreamData(2048, 1024, &writer));
  EXPECT_EQ(copy3, QuicStringPiece(buf + 2048, 1024));
  ASSERT_TRUE(send_buffer_.WriteStreamData(2048, 768, &writer));
  EXPECT_EQ(copy4, QuicStringPiece(buf + 3072, 768));

  // Test data piece across boundries.
  QuicDataWriter writer2(4000, buf, Perspective::IS_CLIENT, HOST_BYTE_ORDER);
  string copy5 = string(536, 'a') + string(256, 'b') + string(232, 'c');
  ASSERT_TRUE(send_buffer_.WriteStreamData(1000, 1024, &writer2));
  EXPECT_EQ(copy5, QuicStringPiece(buf, 1024));
  ASSERT_TRUE(send_buffer_.WriteStreamData(2500, 1024, &writer2));
  EXPECT_EQ(copy3, QuicStringPiece(buf + 1024, 1024));

  // Invalid data copy.
  QuicDataWriter writer3(4000, buf, Perspective::IS_CLIENT, HOST_BYTE_ORDER);
  EXPECT_FALSE(send_buffer_.WriteStreamData(3000, 1024, &writer3));
  EXPECT_FALSE(send_buffer_.WriteStreamData(0, 4000, &writer3));
}

TEST_F(QuicStreamSendBufferTest, RemoveStreamFrame) {
  send_buffer_.RemoveStreamFrame(1024, 1024);
  EXPECT_EQ(4u, send_buffer_.size());
  send_buffer_.RemoveStreamFrame(2048, 1024);
  EXPECT_EQ(4u, send_buffer_.size());
  send_buffer_.RemoveStreamFrame(0, 1024);
  // Send buffer is cleaned up in order.
  EXPECT_EQ(1u, send_buffer_.size());
  send_buffer_.RemoveStreamFrame(3072, 768);
  EXPECT_EQ(0u, send_buffer_.size());
}

TEST_F(QuicStreamSendBufferTest, RemoveStreamFrameAcrossBoundries) {
  send_buffer_.RemoveStreamFrame(2024, 576);
  EXPECT_EQ(4u, send_buffer_.size());
  send_buffer_.RemoveStreamFrame(0, 1000);
  EXPECT_EQ(4u, send_buffer_.size());
  send_buffer_.RemoveStreamFrame(1000, 1024);
  // Send buffer is cleaned up in order.
  EXPECT_EQ(2u, send_buffer_.size());
  send_buffer_.RemoveStreamFrame(2600, 1024);
  EXPECT_EQ(1u, send_buffer_.size());
  send_buffer_.RemoveStreamFrame(3624, 216);
  EXPECT_EQ(0u, send_buffer_.size());
}

}  // namespace
}  // namespace test
}  // namespace net
