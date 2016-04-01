// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_default_packet_writer.h"

#include "net/tools/quic/quic_socket_utils.h"

namespace net {

QuicDefaultPacketWriter::QuicDefaultPacketWriter(int fd)
    : fd_(fd), write_blocked_(false) {}

QuicDefaultPacketWriter::~QuicDefaultPacketWriter() {}

WriteResult QuicDefaultPacketWriter::WritePacket(const char* buffer,
                                                 size_t buf_len,
                                                 const IPAddress& self_address,
                                                 const IPEndPoint& peer_address,
                                                 PerPacketOptions* options) {
  DCHECK(!IsWriteBlocked());
  DCHECK(nullptr == options)
      << "QuicDefaultPacketWriter does not accept any options.";
  WriteResult result = QuicSocketUtils::WritePacket(fd_, buffer, buf_len,
                                                    self_address, peer_address);
  if (result.status == WRITE_STATUS_BLOCKED) {
    write_blocked_ = true;
  }
  return result;
}

bool QuicDefaultPacketWriter::IsWriteBlockedDataBuffered() const {
  return false;
}

bool QuicDefaultPacketWriter::IsWriteBlocked() const {
  return write_blocked_;
}

void QuicDefaultPacketWriter::SetWritable() {
  write_blocked_ = false;
}

QuicByteCount QuicDefaultPacketWriter::GetMaxPacketSize(
    const IPEndPoint& peer_address) const {
  return kMaxPacketSize;
}

}  // namespace net
