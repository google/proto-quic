// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/socks_client_socket.h"

#include <utility>

#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/compiler_specific.h"
#include "base/sys_byteorder.h"
#include "net/base/io_buffer.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/socket/client_socket_handle.h"

namespace net {

// Every SOCKS server requests a user-id from the client. It is optional
// and we send an empty string.
static const char kEmptyUserId[] = "";

// For SOCKS4, the client sends 8 bytes  plus the size of the user-id.
static const unsigned int kWriteHeaderSize = 8;

// For SOCKS4 the server sends 8 bytes for acknowledgement.
static const unsigned int kReadHeaderSize = 8;

// Server Response codes for SOCKS.
static const uint8_t kServerResponseOk = 0x5A;
static const uint8_t kServerResponseRejected = 0x5B;
static const uint8_t kServerResponseNotReachable = 0x5C;
static const uint8_t kServerResponseMismatchedUserId = 0x5D;

static const uint8_t kSOCKSVersion4 = 0x04;
static const uint8_t kSOCKSStreamRequest = 0x01;

// A struct holding the essential details of the SOCKS4 Server Request.
// The port in the header is stored in network byte order.
struct SOCKS4ServerRequest {
  uint8_t version;
  uint8_t command;
  uint16_t nw_port;
  uint8_t ip[4];
};
static_assert(sizeof(SOCKS4ServerRequest) == kWriteHeaderSize,
              "socks4 server request struct has incorrect size");

// A struct holding details of the SOCKS4 Server Response.
struct SOCKS4ServerResponse {
  uint8_t reserved_null;
  uint8_t code;
  uint16_t port;
  uint8_t ip[4];
};
static_assert(sizeof(SOCKS4ServerResponse) == kReadHeaderSize,
              "socks4 server response struct has incorrect size");

SOCKSClientSocket::SOCKSClientSocket(
    std::unique_ptr<ClientSocketHandle> transport_socket,
    const HostResolver::RequestInfo& req_info,
    RequestPriority priority,
    HostResolver* host_resolver)
    : transport_(std::move(transport_socket)),
      next_state_(STATE_NONE),
      completed_handshake_(false),
      bytes_sent_(0),
      bytes_received_(0),
      was_ever_used_(false),
      host_resolver_(host_resolver),
      host_request_info_(req_info),
      priority_(priority),
      net_log_(transport_->socket()->NetLog()) {}

SOCKSClientSocket::~SOCKSClientSocket() {
  Disconnect();
}

int SOCKSClientSocket::Connect(const CompletionCallback& callback) {
  DCHECK(transport_.get());
  DCHECK(transport_->socket());
  DCHECK_EQ(STATE_NONE, next_state_);
  DCHECK(user_callback_.is_null());

  // If already connected, then just return OK.
  if (completed_handshake_)
    return OK;

  next_state_ = STATE_RESOLVE_HOST;

  net_log_.BeginEvent(NetLogEventType::SOCKS_CONNECT);

  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING) {
    user_callback_ = callback;
  } else {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::SOCKS_CONNECT, rv);
  }
  return rv;
}

void SOCKSClientSocket::Disconnect() {
  completed_handshake_ = false;
  request_.reset();
  transport_->socket()->Disconnect();

  // Reset other states to make sure they aren't mistakenly used later.
  // These are the states initialized by Connect().
  next_state_ = STATE_NONE;
  user_callback_.Reset();
}

bool SOCKSClientSocket::IsConnected() const {
  return completed_handshake_ && transport_->socket()->IsConnected();
}

bool SOCKSClientSocket::IsConnectedAndIdle() const {
  return completed_handshake_ && transport_->socket()->IsConnectedAndIdle();
}

const NetLogWithSource& SOCKSClientSocket::NetLog() const {
  return net_log_;
}

void SOCKSClientSocket::SetSubresourceSpeculation() {
  if (transport_.get() && transport_->socket()) {
    transport_->socket()->SetSubresourceSpeculation();
  } else {
    NOTREACHED();
  }
}

void SOCKSClientSocket::SetOmniboxSpeculation() {
  if (transport_.get() && transport_->socket()) {
    transport_->socket()->SetOmniboxSpeculation();
  } else {
    NOTREACHED();
  }
}

bool SOCKSClientSocket::WasEverUsed() const {
  return was_ever_used_;
}

bool SOCKSClientSocket::WasAlpnNegotiated() const {
  if (transport_.get() && transport_->socket()) {
    return transport_->socket()->WasAlpnNegotiated();
  }
  NOTREACHED();
  return false;
}

NextProto SOCKSClientSocket::GetNegotiatedProtocol() const {
  if (transport_.get() && transport_->socket()) {
    return transport_->socket()->GetNegotiatedProtocol();
  }
  NOTREACHED();
  return kProtoUnknown;
}

bool SOCKSClientSocket::GetSSLInfo(SSLInfo* ssl_info) {
  if (transport_.get() && transport_->socket()) {
    return transport_->socket()->GetSSLInfo(ssl_info);
  }
  NOTREACHED();
  return false;
}

void SOCKSClientSocket::GetConnectionAttempts(ConnectionAttempts* out) const {
  out->clear();
}

int64_t SOCKSClientSocket::GetTotalReceivedBytes() const {
  return transport_->socket()->GetTotalReceivedBytes();
}

// Read is called by the transport layer above to read. This can only be done
// if the SOCKS handshake is complete.
int SOCKSClientSocket::Read(IOBuffer* buf, int buf_len,
                            const CompletionCallback& callback) {
  DCHECK(completed_handshake_);
  DCHECK_EQ(STATE_NONE, next_state_);
  DCHECK(user_callback_.is_null());
  DCHECK(!callback.is_null());

  int rv = transport_->socket()->Read(
      buf, buf_len,
      base::Bind(&SOCKSClientSocket::OnReadWriteComplete,
                 base::Unretained(this), callback));
  if (rv > 0)
    was_ever_used_ = true;
  return rv;
}

// Write is called by the transport layer. This can only be done if the
// SOCKS handshake is complete.
int SOCKSClientSocket::Write(IOBuffer* buf, int buf_len,
                             const CompletionCallback& callback) {
  DCHECK(completed_handshake_);
  DCHECK_EQ(STATE_NONE, next_state_);
  DCHECK(user_callback_.is_null());
  DCHECK(!callback.is_null());

  int rv = transport_->socket()->Write(
      buf, buf_len,
      base::Bind(&SOCKSClientSocket::OnReadWriteComplete,
                 base::Unretained(this), callback));
  if (rv > 0)
    was_ever_used_ = true;
  return rv;
}

int SOCKSClientSocket::SetReceiveBufferSize(int32_t size) {
  return transport_->socket()->SetReceiveBufferSize(size);
}

int SOCKSClientSocket::SetSendBufferSize(int32_t size) {
  return transport_->socket()->SetSendBufferSize(size);
}

void SOCKSClientSocket::DoCallback(int result) {
  DCHECK_NE(ERR_IO_PENDING, result);
  DCHECK(!user_callback_.is_null());

  // Since Run() may result in Read being called,
  // clear user_callback_ up front.
  DVLOG(1) << "Finished setting up SOCKS handshake";
  base::ResetAndReturn(&user_callback_).Run(result);
}

void SOCKSClientSocket::OnIOComplete(int result) {
  DCHECK_NE(STATE_NONE, next_state_);
  int rv = DoLoop(result);
  if (rv != ERR_IO_PENDING) {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::SOCKS_CONNECT, rv);
    DoCallback(rv);
  }
}

void SOCKSClientSocket::OnReadWriteComplete(const CompletionCallback& callback,
                                            int result) {
  DCHECK_NE(ERR_IO_PENDING, result);
  DCHECK(!callback.is_null());

  if (result > 0)
    was_ever_used_ = true;
  callback.Run(result);
}

int SOCKSClientSocket::DoLoop(int last_io_result) {
  DCHECK_NE(next_state_, STATE_NONE);
  int rv = last_io_result;
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_RESOLVE_HOST:
        DCHECK_EQ(OK, rv);
        rv = DoResolveHost();
        break;
      case STATE_RESOLVE_HOST_COMPLETE:
        rv = DoResolveHostComplete(rv);
        break;
      case STATE_HANDSHAKE_WRITE:
        DCHECK_EQ(OK, rv);
        rv = DoHandshakeWrite();
        break;
      case STATE_HANDSHAKE_WRITE_COMPLETE:
        rv = DoHandshakeWriteComplete(rv);
        break;
      case STATE_HANDSHAKE_READ:
        DCHECK_EQ(OK, rv);
        rv = DoHandshakeRead();
        break;
      case STATE_HANDSHAKE_READ_COMPLETE:
        rv = DoHandshakeReadComplete(rv);
        break;
      default:
        NOTREACHED() << "bad state";
        rv = ERR_UNEXPECTED;
        break;
    }
  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);
  return rv;
}

int SOCKSClientSocket::DoResolveHost() {
  next_state_ = STATE_RESOLVE_HOST_COMPLETE;
  // SOCKS4 only supports IPv4 addresses, so only try getting the IPv4
  // addresses for the target host.
  host_request_info_.set_address_family(ADDRESS_FAMILY_IPV4);
  return host_resolver_->Resolve(
      host_request_info_, priority_, &addresses_,
      base::Bind(&SOCKSClientSocket::OnIOComplete, base::Unretained(this)),
      &request_, net_log_);
}

int SOCKSClientSocket::DoResolveHostComplete(int result) {
  if (result != OK) {
    // Resolving the hostname failed; fail the request rather than automatically
    // falling back to SOCKS4a (since it can be confusing to see invalid IP
    // addresses being sent to the SOCKS4 server when it doesn't support 4A.)
    return result;
  }

  next_state_ = STATE_HANDSHAKE_WRITE;
  return OK;
}

// Builds the buffer that is to be sent to the server.
const std::string SOCKSClientSocket::BuildHandshakeWriteBuffer() const {
  SOCKS4ServerRequest request;
  request.version = kSOCKSVersion4;
  request.command = kSOCKSStreamRequest;
  request.nw_port = base::HostToNet16(host_request_info_.port());

  DCHECK(!addresses_.empty());
  const IPEndPoint& endpoint = addresses_.front();

  // We disabled IPv6 results when resolving the hostname, so none of the
  // results in the list will be IPv6.
  // TODO(eroman): we only ever use the first address in the list. It would be
  //               more robust to try all the IP addresses we have before
  //               failing the connect attempt.
  CHECK_EQ(ADDRESS_FAMILY_IPV4, endpoint.GetFamily());
  CHECK_LE(endpoint.address().size(), sizeof(request.ip));
  memcpy(&request.ip, &endpoint.address().bytes()[0],
         endpoint.address().size());

  DVLOG(1) << "Resolved Host is : " << endpoint.ToStringWithoutPort();

  std::string handshake_data(reinterpret_cast<char*>(&request),
                             sizeof(request));
  handshake_data.append(kEmptyUserId, arraysize(kEmptyUserId));

  return handshake_data;
}

// Writes the SOCKS handshake data to the underlying socket connection.
int SOCKSClientSocket::DoHandshakeWrite() {
  next_state_ = STATE_HANDSHAKE_WRITE_COMPLETE;

  if (buffer_.empty()) {
    buffer_ = BuildHandshakeWriteBuffer();
    bytes_sent_ = 0;
  }

  int handshake_buf_len = buffer_.size() - bytes_sent_;
  DCHECK_GT(handshake_buf_len, 0);
  handshake_buf_ = new IOBuffer(handshake_buf_len);
  memcpy(handshake_buf_->data(), &buffer_[bytes_sent_],
         handshake_buf_len);
  return transport_->socket()->Write(
      handshake_buf_.get(),
      handshake_buf_len,
      base::Bind(&SOCKSClientSocket::OnIOComplete, base::Unretained(this)));
}

int SOCKSClientSocket::DoHandshakeWriteComplete(int result) {
  if (result < 0)
    return result;

  // We ignore the case when result is 0, since the underlying Write
  // may return spurious writes while waiting on the socket.

  bytes_sent_ += result;
  if (bytes_sent_ == buffer_.size()) {
    next_state_ = STATE_HANDSHAKE_READ;
    buffer_.clear();
  } else if (bytes_sent_ < buffer_.size()) {
    next_state_ = STATE_HANDSHAKE_WRITE;
  } else {
    return ERR_UNEXPECTED;
  }

  return OK;
}

int SOCKSClientSocket::DoHandshakeRead() {
  next_state_ = STATE_HANDSHAKE_READ_COMPLETE;

  if (buffer_.empty()) {
    bytes_received_ = 0;
  }

  int handshake_buf_len = kReadHeaderSize - bytes_received_;
  handshake_buf_ = new IOBuffer(handshake_buf_len);
  return transport_->socket()->Read(
      handshake_buf_.get(),
      handshake_buf_len,
      base::Bind(&SOCKSClientSocket::OnIOComplete, base::Unretained(this)));
}

int SOCKSClientSocket::DoHandshakeReadComplete(int result) {
  if (result < 0)
    return result;

  // The underlying socket closed unexpectedly.
  if (result == 0)
    return ERR_CONNECTION_CLOSED;

  if (bytes_received_ + result > kReadHeaderSize) {
    // TODO(eroman): Describe failure in NetLog.
    return ERR_SOCKS_CONNECTION_FAILED;
  }

  buffer_.append(handshake_buf_->data(), result);
  bytes_received_ += result;
  if (bytes_received_ < kReadHeaderSize) {
    next_state_ = STATE_HANDSHAKE_READ;
    return OK;
  }

  const SOCKS4ServerResponse* response =
      reinterpret_cast<const SOCKS4ServerResponse*>(buffer_.data());

  if (response->reserved_null != 0x00) {
    DVLOG(1) << "Unknown response from SOCKS server.";
    return ERR_SOCKS_CONNECTION_FAILED;
  }

  switch (response->code) {
    case kServerResponseOk:
      completed_handshake_ = true;
      return OK;
    case kServerResponseRejected:
      DVLOG(1) << "SOCKS request rejected or failed";
      return ERR_SOCKS_CONNECTION_FAILED;
    case kServerResponseNotReachable:
      DVLOG(1) << "SOCKS request failed because client is not running "
               << "identd (or not reachable from the server)";
      return ERR_SOCKS_CONNECTION_HOST_UNREACHABLE;
    case kServerResponseMismatchedUserId:
      DVLOG(1) << "SOCKS request failed because client's identd could "
               << "not confirm the user ID string in the request";
      return ERR_SOCKS_CONNECTION_FAILED;
    default:
      DVLOG(1) << "SOCKS server sent unknown response";
      return ERR_SOCKS_CONNECTION_FAILED;
  }

  // Note: we ignore the last 6 bytes as specified by the SOCKS protocol
}

int SOCKSClientSocket::GetPeerAddress(IPEndPoint* address) const {
  return transport_->socket()->GetPeerAddress(address);
}

int SOCKSClientSocket::GetLocalAddress(IPEndPoint* address) const {
  return transport_->socket()->GetLocalAddress(address);
}

}  // namespace net
