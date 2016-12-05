// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//

#ifndef NET_QUIC_QUIC_CHROMIUM_PACKET_READER_H_
#define NET_QUIC_QUIC_CHROMIUM_PACKET_READER_H_

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "net/base/io_buffer.h"
#include "net/base/net_export.h"
#include "net/log/net_log_with_source.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_time.h"
#include "net/socket/datagram_client_socket.h"

namespace net {

class QuicClock;

// If more than this many packets have been read or more than that many
// milliseconds have passed, QuicChromiumPacketReader::StartReading() yields by
// doing a QuicChromiumPacketReader::PostTask().
const int kQuicYieldAfterPacketsRead = 32;
const int kQuicYieldAfterDurationMilliseconds = 20;

class NET_EXPORT_PRIVATE QuicChromiumPacketReader {
 public:
  class NET_EXPORT_PRIVATE Visitor {
   public:
    virtual ~Visitor() {}
    virtual void OnReadError(int result,
                             const DatagramClientSocket* socket) = 0;
    virtual bool OnPacket(const QuicReceivedPacket& packet,
                          IPEndPoint local_address,
                          IPEndPoint peer_address) = 0;
  };

  QuicChromiumPacketReader(DatagramClientSocket* socket,
                           QuicClock* clock,
                           Visitor* visitor,
                           int yield_after_packets,
                           QuicTime::Delta yield_after_duration,
                           const NetLogWithSource& net_log);
  virtual ~QuicChromiumPacketReader();

  // Causes the QuicConnectionHelper to start reading from the socket
  // and passing the data along to the QuicConnection.
  void StartReading();

 private:
  // A completion callback invoked when a read completes.
  void OnReadComplete(int result);

  // Called when a packet is read and it should be processed.
  // Returns false if the read was an error or the packet couldn't
  // be processed.
  bool OnPacketRead(int result);

  DatagramClientSocket* socket_;
  Visitor* visitor_;
  bool read_pending_;
  QuicClock* clock_;  // Owned by QuicStreamFactory
  int yield_after_packets_;
  QuicTime::Delta yield_after_duration_;
  scoped_refptr<IOBufferWithSize> read_buffer_;
  NetLogWithSource net_log_;

  base::WeakPtrFactory<QuicChromiumPacketReader> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(QuicChromiumPacketReader);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_CHROMIUM_PACKET_READER_H_
