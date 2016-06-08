// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_CHROMIUM_PACKET_WRITER_H_
#define NET_QUIC_QUIC_CHROMIUM_PACKET_WRITER_H_

#include <stddef.h>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_packet_writer.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_types.h"
#include "net/udp/datagram_client_socket.h"

namespace net {

// Chrome specific packet writer which uses a datagram Socket for writing data.
class NET_EXPORT_PRIVATE QuicChromiumPacketWriter : public QuicPacketWriter {
 public:
  QuicChromiumPacketWriter();
  explicit QuicChromiumPacketWriter(Socket* socket);
  ~QuicChromiumPacketWriter() override;

  // QuicPacketWriter
  WriteResult WritePacket(const char* buffer,
                          size_t buf_len,
                          const IPAddress& self_address,
                          const IPEndPoint& peer_address,
                          PerPacketOptions* options) override;
  bool IsWriteBlockedDataBuffered() const override;
  bool IsWriteBlocked() const override;
  void SetWritable() override;
  QuicByteCount GetMaxPacketSize(const IPEndPoint& peer_address) const override;

  void OnWriteComplete(int rv);
  void SetConnection(QuicConnection* connection) { connection_ = connection; }

 protected:
  void set_write_blocked(bool is_blocked) { write_blocked_ = is_blocked; }

 private:
  Socket* socket_;
  QuicConnection* connection_;

  // Whether a write is currently in flight.
  bool write_blocked_;

  base::WeakPtrFactory<QuicChromiumPacketWriter> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(QuicChromiumPacketWriter);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_CHROMIUM_PACKET_WRITER_H_
