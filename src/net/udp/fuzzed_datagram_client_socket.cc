// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/udp/fuzzed_datagram_client_socket.h"

#include <algorithm>

#include "base/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "base/test/fuzzed_data_provider.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"

namespace net {

// Subset of network errors that can occur on each operation. Less clear cut
// than TCP errors, so some of these may not actually be possible.
const Error kConnectErrors[] = {ERR_FAILED, ERR_ADDRESS_UNREACHABLE,
                                ERR_ACCESS_DENIED};
const Error kReadErrors[] = {ERR_FAILED, ERR_ADDRESS_UNREACHABLE};
const Error kWriteErrors[] = {ERR_FAILED, ERR_ADDRESS_UNREACHABLE,
                              ERR_MSG_TOO_BIG};

FuzzedDatagramClientSocket::FuzzedDatagramClientSocket(
    base::FuzzedDataProvider* data_provider)
    : data_provider_(data_provider), weak_factory_(this) {}

FuzzedDatagramClientSocket::~FuzzedDatagramClientSocket() {}

int FuzzedDatagramClientSocket::Connect(const IPEndPoint& address) {
  CHECK(!connected_);

  // Decide if the connect attempt succeeds.
  if (data_provider_->ConsumeBool()) {
    connected_ = true;
    remote_address_ = address;
    return OK;
  }

  // On failure, return a random connect error.
  return data_provider_->PickValueInArray(kConnectErrors);
}

int FuzzedDatagramClientSocket::ConnectUsingNetwork(
    NetworkChangeNotifier::NetworkHandle network,
    const IPEndPoint& address) {
  CHECK(!connected_);
  return ERR_NOT_IMPLEMENTED;
}

int FuzzedDatagramClientSocket::FuzzedDatagramClientSocket::
    ConnectUsingDefaultNetwork(const IPEndPoint& address) {
  CHECK(!connected_);
  return ERR_NOT_IMPLEMENTED;
}

NetworkChangeNotifier::NetworkHandle
FuzzedDatagramClientSocket::GetBoundNetwork() const {
  return NetworkChangeNotifier::kInvalidNetworkHandle;
}

void FuzzedDatagramClientSocket::Close() {
  connected_ = false;
  read_pending_ = false;
  write_pending_ = false;
  remote_address_ = IPEndPoint();
  weak_factory_.InvalidateWeakPtrs();
}

int FuzzedDatagramClientSocket::GetPeerAddress(IPEndPoint* address) const {
  if (!connected_)
    return ERR_SOCKET_NOT_CONNECTED;
  *address = remote_address_;
  return OK;
}

int FuzzedDatagramClientSocket::GetLocalAddress(IPEndPoint* address) const {
  if (!connected_)
    return ERR_SOCKET_NOT_CONNECTED;
  *address = IPEndPoint(IPAddress(1, 2, 3, 4), 43210);
  return OK;
}

void FuzzedDatagramClientSocket::UseNonBlockingIO() {}

const NetLogWithSource& FuzzedDatagramClientSocket::NetLog() const {
  return net_log_;
}

int FuzzedDatagramClientSocket::Read(IOBuffer* buf,
                                     int buf_len,
                                     const CompletionCallback& callback) {
  CHECK(!callback.is_null());
  CHECK_GT(buf_len, 0);
  CHECK(!read_pending_);

  // Normally calling this on disconnected sockets is allowed, but code really
  // shouldn't be doing this.  If it is, it's best to figure out why, and fix
  // it. Note that |connected_| is only set to false on calls to Close(), not on
  // errors.
  CHECK(connected_);

  // Get contents of response.
  base::StringPiece data(data_provider_->ConsumeBytes(
      data_provider_->ConsumeUint32InRange(0, buf_len)));

  int result;
  if (data.length() > 0) {
    // If the response is not empty, consider it a successful read.
    result = data.length();
    std::copy(data.begin(), data.end(), buf->data());
  } else {
    // If the response is empty, pick a random read error.
    result = data_provider_->PickValueInArray(kReadErrors);
  }

  // Decide if result should be returned synchronously.
  if (data_provider_->ConsumeBool())
    return result;

  read_pending_ = true;
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&FuzzedDatagramClientSocket::OnReadComplete,
                            weak_factory_.GetWeakPtr(), callback, result));
  return ERR_IO_PENDING;
}

int FuzzedDatagramClientSocket::Write(IOBuffer* buf,
                                      int buf_len,
                                      const CompletionCallback& callback) {
  CHECK(!callback.is_null());
  CHECK(!write_pending_);

  // Normally this is allowed, but code really shouldn't be doing this - if it
  // is, it's best to figure out why, and fix it.
  CHECK(connected_);

  int result;
  // Decide if success or failure.
  if (data_provider_->ConsumeBool()) {
    // On success, everything is written.
    result = buf_len;
  } else {
    // On failure, pick a random write error.
    result = data_provider_->PickValueInArray(kWriteErrors);
  }

  // Decide if result should be returned synchronously.
  if (data_provider_->ConsumeBool())
    return result;

  write_pending_ = true;
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&FuzzedDatagramClientSocket::OnWriteComplete,
                            weak_factory_.GetWeakPtr(), callback, result));
  return ERR_IO_PENDING;
}

int FuzzedDatagramClientSocket::SetReceiveBufferSize(int32_t size) {
  return OK;
}

int FuzzedDatagramClientSocket::SetSendBufferSize(int32_t size) {
  return OK;
}

int FuzzedDatagramClientSocket::SetDoNotFragment() {
  return OK;
}

void FuzzedDatagramClientSocket::OnReadComplete(
    const net::CompletionCallback& callback,
    int result) {
  CHECK(connected_);
  CHECK(read_pending_);

  read_pending_ = false;
  callback.Run(result);
}

void FuzzedDatagramClientSocket::OnWriteComplete(
    const net::CompletionCallback& callback,
    int result) {
  CHECK(connected_);
  CHECK(write_pending_);

  write_pending_ = false;
  callback.Run(result);
}

}  // namespace net
