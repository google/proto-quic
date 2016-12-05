// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/chromium/quic_chromium_packet_reader.h"

#include "base/location.h"
#include "base/metrics/histogram_macros.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/net_errors.h"
#include "net/quic/core/quic_clock.h"

namespace net {

QuicChromiumPacketReader::QuicChromiumPacketReader(
    DatagramClientSocket* socket,
    QuicClock* clock,
    Visitor* visitor,
    int yield_after_packets,
    QuicTime::Delta yield_after_duration,
    const NetLogWithSource& net_log)
    : socket_(socket),
      visitor_(visitor),
      read_pending_(false),
      clock_(clock),
      yield_after_packets_(yield_after_packets),
      yield_after_duration_(yield_after_duration),
      read_buffer_(new IOBufferWithSize(static_cast<size_t>(kMaxPacketSize))),
      net_log_(net_log),
      weak_factory_(this) {}

QuicChromiumPacketReader::~QuicChromiumPacketReader() {}

void QuicChromiumPacketReader::StartReading() {
  if (read_pending_)
    return;

  int num_packets_read = 0;
  QuicTime yield_after = clock_->Now() + yield_after_duration_;

  DCHECK(socket_);
  while (true) {
    read_pending_ = true;
    int rv = socket_->Read(read_buffer_.get(), read_buffer_->size(),
                           base::Bind(&QuicChromiumPacketReader::OnReadComplete,
                                      weak_factory_.GetWeakPtr()));
    UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.AsyncRead", rv == ERR_IO_PENDING);
    if (rv == ERR_IO_PENDING)
      return;
    if (!OnPacketRead(rv))
      return;
    if (++num_packets_read > yield_after_packets_ ||
        clock_->Now() > yield_after) {
      // Schedule the work through the message loop to avoid blocking the thread
      // for too long.
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(&QuicChromiumPacketReader::StartReading,
                                weak_factory_.GetWeakPtr()));
      return;
    }
  }
}

void QuicChromiumPacketReader::OnReadComplete(int result) {
  if (OnPacketRead(result))
    StartReading();
}

bool QuicChromiumPacketReader::OnPacketRead(int result) {
  read_pending_ = false;
  if (result == 0)
    result = ERR_CONNECTION_CLOSED;

  if (result < 0) {
    visitor_->OnReadError(result, socket_);
    return false;
  }

  QuicReceivedPacket packet(read_buffer_->data(), result, clock_->Now());
  IPEndPoint local_address;
  IPEndPoint peer_address;
  socket_->GetLocalAddress(&local_address);
  socket_->GetPeerAddress(&peer_address);
  return visitor_->OnPacket(packet, local_address, peer_address);
}

}  // namespace net
