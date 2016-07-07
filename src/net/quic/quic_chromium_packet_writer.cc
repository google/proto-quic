// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_chromium_packet_writer.h"

#include <string>

#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/quic/quic_chromium_client_session.h"

namespace net {

QuicChromiumPacketWriter::QuicChromiumPacketWriter() : weak_factory_(this) {}

QuicChromiumPacketWriter::QuicChromiumPacketWriter(Socket* socket)
    : socket_(socket),
      connection_(nullptr),
      observer_(nullptr),
      packet_(nullptr),
      write_blocked_(false),
      weak_factory_(this) {}

QuicChromiumPacketWriter::~QuicChromiumPacketWriter() {}

void QuicChromiumPacketWriter::Initialize(WriteErrorObserver* observer,
                                          QuicConnection* connection) {
  observer_ = observer;
  connection_ = connection;
}

int QuicChromiumPacketWriter::WritePacketToSocket(StringIOBuffer* packet) {
  return socket_->Write(packet, packet->size(),
                        base::Bind(&QuicChromiumPacketWriter::OnWriteComplete,
                                   weak_factory_.GetWeakPtr()));
}

WriteResult QuicChromiumPacketWriter::WritePacket(
    const char* buffer,
    size_t buf_len,
    const IPAddress& self_address,
    const IPEndPoint& peer_address,
    PerPacketOptions* /*options*/) {
  scoped_refptr<StringIOBuffer> buf(
      new StringIOBuffer(std::string(buffer, buf_len)));
  DCHECK(!IsWriteBlocked());
  base::TimeTicks now = base::TimeTicks::Now();

  int rv = WritePacketToSocket(buf.get());

  if (rv < 0 && rv != ERR_IO_PENDING && observer_ != nullptr) {
    // If write error, then call observer's OnWriteError, which may be
    // able to migrate and rewrite packet on a new socket.
    // OnWriteError returns the outcome of that attempt, which is returned
    // to the caller.
    rv = observer_->OnWriteError(rv, buf);
  }

  WriteStatus status = WRITE_STATUS_OK;
  if (rv < 0) {
    if (rv != ERR_IO_PENDING) {
      UMA_HISTOGRAM_SPARSE_SLOWLY("Net.QuicSession.WriteError", -rv);
      status = WRITE_STATUS_ERROR;
    } else {
      status = WRITE_STATUS_BLOCKED;
      write_blocked_ = true;
      packet_ = buf;
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
  write_blocked_ = false;
  if (rv < 0) {
    // If write error, then call into the observer's OnWriteError,
    // which may be able to rewrite the packet on a new
    // socket. OnWriteError returns the outcome of the attempt.
    rv = observer_->OnWriteError(rv, packet_);
    packet_ = nullptr;
    if (rv == ERR_IO_PENDING)
      return;
  }

  if (rv < 0) {
    connection_->OnWriteError(rv);
  }
  connection_->OnCanWrite();
}

QuicByteCount QuicChromiumPacketWriter::GetMaxPacketSize(
    const IPEndPoint& peer_address) const {
  return kMaxPacketSize;
}

}  // namespace net
