// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_QUIC_TEST_TOOLS_PACKET_REORDERING_WRITER_H_
#define NET_TOOLS_QUIC_TEST_TOOLS_PACKET_REORDERING_WRITER_H_

#include "net/tools/quic/quic_packet_writer_wrapper.h"

namespace net {

namespace test {

// This packet writer allows delaying writing the next packet after
// SetDelay(num_packets_to_wait)
// is called and buffer this packet and write it after it writes next
// |num_packets_to_wait| packets. It doesn't support delaying a packet while
// there is already a packet delayed.
class PacketReorderingWriter : public QuicPacketWriterWrapper {
 public:
  PacketReorderingWriter();

  ~PacketReorderingWriter() override;

  WriteResult WritePacket(const char* buffer,
                          size_t buf_len,
                          const IPAddress& self_address,
                          const IPEndPoint& peer_address,
                          PerPacketOptions* options) override;

  void SetDelay(size_t num_packets_to_wait);

 private:
  bool delay_next_ = false;
  size_t num_packets_to_wait_ = 0;
  std::string delayed_data_;
  IPAddress delayed_self_address_;
  IPEndPoint delayed_peer_address_;
  std::unique_ptr<PerPacketOptions> delayed_options_;
};

}  // namespace test
}  // namespace net

#endif  // NET_TOOLS_QUIC_TEST_TOOLS_PACKET_REORDERING_WRITER_H_
