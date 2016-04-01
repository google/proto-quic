// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_simple_server_packet_writer.h"

#include "base/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/sparse_histogram.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/udp/udp_server_socket.h"

namespace net {

QuicSimpleServerPacketWriter::QuicSimpleServerPacketWriter(
    UDPServerSocket* socket,
    QuicBlockedWriterInterface* blocked_writer)
    : socket_(socket),
      blocked_writer_(blocked_writer),
      write_blocked_(false),
      weak_factory_(this) {}

QuicSimpleServerPacketWriter::~QuicSimpleServerPacketWriter() {}

WriteResult QuicSimpleServerPacketWriter::WritePacketWithCallback(
    const char* buffer,
    size_t buf_len,
    const IPAddress& self_address,
    const IPEndPoint& peer_address,
    PerPacketOptions* options,
    WriteCallback callback) {
  DCHECK(callback_.is_null());
  callback_ = callback;
  WriteResult result =
      WritePacket(buffer, buf_len, self_address, peer_address, options);
  if (result.status != WRITE_STATUS_BLOCKED) {
    callback_.Reset();
  }
  return result;
}

void QuicSimpleServerPacketWriter::OnWriteComplete(int rv) {
  DCHECK_NE(rv, ERR_IO_PENDING);
  write_blocked_ = false;
  WriteResult result(rv < 0 ? WRITE_STATUS_ERROR : WRITE_STATUS_OK, rv);
  base::ResetAndReturn(&callback_).Run(result);
  blocked_writer_->OnCanWrite();
}

bool QuicSimpleServerPacketWriter::IsWriteBlockedDataBuffered() const {
  // UDPServerSocket::SendTo buffers the data until the Write is permitted.
  return true;
}

bool QuicSimpleServerPacketWriter::IsWriteBlocked() const {
  return write_blocked_;
}

void QuicSimpleServerPacketWriter::SetWritable() {
  write_blocked_ = false;
}

WriteResult QuicSimpleServerPacketWriter::WritePacket(
    const char* buffer,
    size_t buf_len,
    const IPAddress& self_address,
    const IPEndPoint& peer_address,
    PerPacketOptions* options) {
  scoped_refptr<StringIOBuffer> buf(
      new StringIOBuffer(std::string(buffer, buf_len)));
  DCHECK(!IsWriteBlocked());
  DCHECK(!callback_.is_null());
  int rv;
  if (buf_len <= static_cast<size_t>(std::numeric_limits<int>::max())) {
    rv = socket_->SendTo(
        buf.get(), static_cast<int>(buf_len), peer_address,
        base::Bind(&QuicSimpleServerPacketWriter::OnWriteComplete,
                   weak_factory_.GetWeakPtr()));
  } else {
    rv = ERR_MSG_TOO_BIG;
  }
  WriteStatus status = WRITE_STATUS_OK;
  if (rv < 0) {
    if (rv != ERR_IO_PENDING) {
      UMA_HISTOGRAM_SPARSE_SLOWLY("Net.QuicSession.WriteError", -rv);
      status = WRITE_STATUS_ERROR;
    } else {
      status = WRITE_STATUS_BLOCKED;
      write_blocked_ = true;
    }
  }
  return WriteResult(status, rv);
}

QuicByteCount QuicSimpleServerPacketWriter::GetMaxPacketSize(
    const IPEndPoint& peer_address) const {
  return kMaxPacketSize;
}

}  // namespace net
