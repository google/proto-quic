// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SOCKET_UNIX_DOMAIN_CLIENT_SOCKET_POSIX_H_
#define NET_SOCKET_UNIX_DOMAIN_CLIENT_SOCKET_POSIX_H_

#include <stdint.h>

#include <memory>
#include <string>

#include "base/macros.h"
#include "net/base/completion_callback.h"
#include "net/base/net_export.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/socket_descriptor.h"
#include "net/socket/stream_socket.h"

namespace net {

class SocketPosix;
struct SockaddrStorage;

// A client socket that uses unix domain socket as the transport layer.
class NET_EXPORT UnixDomainClientSocket : public StreamSocket {
 public:
  // Builds a client socket with |socket_path|. The caller should call Connect()
  // to connect to a server socket.
  UnixDomainClientSocket(const std::string& socket_path,
                         bool use_abstract_namespace);
  // Builds a client socket with SocketPosix which is already connected.
  // UnixDomainServerSocket uses this after it accepts a connection.
  explicit UnixDomainClientSocket(std::unique_ptr<SocketPosix> socket);

  ~UnixDomainClientSocket() override;

  // Fills |address| with |socket_path| and its length. For Android or Linux
  // platform, this supports abstract namespaces.
  static bool FillAddress(const std::string& socket_path,
                          bool use_abstract_namespace,
                          SockaddrStorage* address);

  // StreamSocket implementation.
  int Connect(const CompletionCallback& callback) override;
  void Disconnect() override;
  bool IsConnected() const override;
  bool IsConnectedAndIdle() const override;
  int GetPeerAddress(IPEndPoint* address) const override;
  int GetLocalAddress(IPEndPoint* address) const override;
  const NetLogWithSource& NetLog() const override;
  void SetSubresourceSpeculation() override;
  void SetOmniboxSpeculation() override;
  bool WasEverUsed() const override;
  bool WasAlpnNegotiated() const override;
  NextProto GetNegotiatedProtocol() const override;
  bool GetSSLInfo(SSLInfo* ssl_info) override;
  void GetConnectionAttempts(ConnectionAttempts* out) const override;
  void ClearConnectionAttempts() override {}
  void AddConnectionAttempts(const ConnectionAttempts& attempts) override {}
  int64_t GetTotalReceivedBytes() const override;

  // Socket implementation.
  int Read(IOBuffer* buf,
           int buf_len,
           const CompletionCallback& callback) override;
  int Write(IOBuffer* buf,
            int buf_len,
            const CompletionCallback& callback) override;
  int SetReceiveBufferSize(int32_t size) override;
  int SetSendBufferSize(int32_t size) override;

  // Releases ownership of underlying SocketDescriptor to caller.
  // Internal state is reset so that this object can be used again.
  // Socket must be connected in order to release it.
  SocketDescriptor ReleaseConnectedSocket();

 private:
  const std::string socket_path_;
  const bool use_abstract_namespace_;
  std::unique_ptr<SocketPosix> socket_;
  // This net log is just to comply StreamSocket::NetLog(). It throws away
  // everything.
  NetLogWithSource net_log_;

  DISALLOW_COPY_AND_ASSIGN(UnixDomainClientSocket);
};

}  // namespace net

#endif  // NET_SOCKET_UNIX_DOMAIN_CLIENT_SOCKET_POSIX_H_
