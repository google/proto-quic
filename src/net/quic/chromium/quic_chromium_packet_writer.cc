// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/chromium/quic_chromium_packet_writer.h"

#include <string>

#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/quic/chromium/quic_chromium_client_session.h"

namespace net {

QuicChromiumPacketWriter::QuicChromiumPacketWriter() : weak_factory_(this) {}

QuicChromiumPacketWriter::QuicChromiumPacketWriter(Socket* socket)
    : socket_(socket),
      delegate_(nullptr),
      packet_(nullptr),
      write_blocked_(false),
      weak_factory_(this) {}

QuicChromiumPacketWriter::~QuicChromiumPacketWriter() {}

WriteResult QuicChromiumPacketWriter::WritePacket(
    const char* buffer,
    size_t buf_len,
    const QuicIpAddress& self_address,
    const QuicSocketAddress& peer_address,
    PerPacketOptions* /*options*/) {
  scoped_refptr<StringIOBuffer> buf(
      new StringIOBuffer(std::string(buffer, buf_len)));
  DCHECK(!IsWriteBlocked());
  return WritePacketToSocket(buf);
}

WriteResult QuicChromiumPacketWriter::WritePacketToSocket(
    scoped_refptr<StringIOBuffer> packet) {
  base::TimeTicks now = base::TimeTicks::Now();
  int rv = socket_->Write(packet.get(), packet.get()->size(),
                          base::Bind(&QuicChromiumPacketWriter::OnWriteComplete,
                                     weak_factory_.GetWeakPtr()));

  if (rv < 0 && rv != ERR_IO_PENDING && delegate_ != nullptr) {
    // If write error, then call delegate's HandleWriteError, which
    // may be able to migrate and rewrite packet on a new socket.
    // HandleWriteError returns the outcome of that rewrite attempt.
    rv = delegate_->HandleWriteError(rv, packet);
  }

  WriteStatus status = WRITE_STATUS_OK;
  if (rv < 0) {
    if (rv != ERR_IO_PENDING) {
      UMA_HISTOGRAM_SPARSE_SLOWLY("Net.QuicSession.WriteError", -rv);
      status = WRITE_STATUS_ERROR;
    } else {
      status = WRITE_STATUS_BLOCKED;
      write_blocked_ = true;
      packet_ = packet;
    }
  }

  base::TimeDelta delta = base::TimeTicks::Now() - now;
  if (status == WRITE_STATUS_OK) {
    UMA_HISTOGRAM_TIMES("Net.QuicSession.PacketWriteTime.Synchronous", delta);
  } else if (status == WRITE_STATUS_BLOCKED) {
    UMA_HISTOGRAM_TIMES("Net.QuicSession.PacketWriteTime.Asynchronous", delta);
  }

  return WriteResult(status, rv);
}

bool QuicChromiumPacketWriter::IsWriteBlockedDataBuffered() const {
  // Chrome sockets' Write() methods buffer the data until the Write is
  // permitted.
  return true;
}

bool QuicChromiumPacketWriter::IsWriteBlocked() const {
  return write_blocked_;
}

void QuicChromiumPacketWriter::SetWritable() {
  write_blocked_ = false;
}

void QuicChromiumPacketWriter::OnWriteComplete(int rv) {
  DCHECK_NE(rv, ERR_IO_PENDING);
  DCHECK(delegate_) << "Uninitialized delegate.";
  write_blocked_ = false;
  if (rv < 0) {
    // If write error, then call delegate's HandleWriteError, which
    // may be able to migrate and rewrite packet on a new socket.
    // HandleWriteError returns the outcome of that rewrite attempt.
    rv = delegate_->HandleWriteError(rv, packet_);
    packet_ = nullptr;
    if (rv == ERR_IO_PENDING)
      return;
  }

  if (rv < 0)
    delegate_->OnWriteError(rv);
  else
    delegate_->OnWriteUnblocked();
}

QuicByteCount QuicChromiumPacketWriter::GetMaxPacketSize(
    const QuicSocketAddress& peer_address) const {
  return kMaxPacketSize;
}

}  // namespace net
