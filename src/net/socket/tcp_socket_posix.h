// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SOCKET_TCP_SOCKET_POSIX_H_
#define NET_SOCKET_TCP_SOCKET_POSIX_H_

#include <stdint.h>

#include <memory>

#include "base/callback.h"
#include "base/compiler_specific.h"
#include "base/macros.h"
#include "net/base/address_family.h"
#include "net/base/completion_callback.h"
#include "net/base/net_export.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/socket_performance_watcher.h"

namespace base {
class TimeDelta;
}

namespace net {

class AddressList;
class IOBuffer;
class IPEndPoint;
class SocketPosix;
class NetLog;
struct NetLogSource;

class NET_EXPORT TCPSocketPosix {
 public:
  // |socket_performance_watcher| is notified of the performance metrics related
  // to this socket. |socket_performance_watcher| may be null.
  TCPSocketPosix(
      std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
      NetLog* net_log,
      const NetLogSource& source);
  virtual ~TCPSocketPosix();

  int Open(AddressFamily family);
  // Takes ownership of |socket_fd|.
  int AdoptConnectedSocket(int socket_fd, const IPEndPoint& peer_address);

  int Bind(const IPEndPoint& address);

  int Listen(int backlog);
  int Accept(std::unique_ptr<TCPSocketPosix>* socket,
             IPEndPoint* address,
             const CompletionCallback& callback);

  int Connect(const IPEndPoint& address, const CompletionCallback& callback);
  bool IsConnected() const;
  bool IsConnectedAndIdle() const;

  // Multiple outstanding requests are not supported.
  // Full duplex mode (reading and writing at the same time) is supported.
  int Read(IOBuffer* buf, int buf_len, const CompletionCallback& callback);
  int Write(IOBuffer* buf, int buf_len, const CompletionCallback& callback);

  int GetLocalAddress(IPEndPoint* address) const;
  int GetPeerAddress(IPEndPoint* address) const;

  // Sets various socket options.
  // The commonly used options for server listening sockets:
  // - SetAddressReuse(true).
  int SetDefaultOptionsForServer();
  // The commonly used options for client sockets and accepted sockets:
  // - SetNoDelay(true);
  // - SetKeepAlive(true, 45).
  void SetDefaultOptionsForClient();
  int SetAddressReuse(bool allow);
  int SetReceiveBufferSize(int32_t size);
  int SetSendBufferSize(int32_t size);
  bool SetKeepAlive(bool enable, int delay);
  bool SetNoDelay(bool no_delay);

  // Gets the estimated RTT. Returns false if the RTT is
  // unavailable. May also return false when estimated RTT is 0.
  bool GetEstimatedRoundTripTime(base::TimeDelta* out_rtt) const
      WARN_UNUSED_RESULT;

  void Close();

  void EnableTCPFastOpenIfSupported();

  bool IsValid() const;

  // Detachs from the current thread, to allow the socket to be transferred to
  // a new thread. Should only be called when the object is no longer used by
  // the old thread.
  void DetachFromThread();

  // Marks the start/end of a series of connect attempts for logging purpose.
  //
  // TCPClientSocket may attempt to connect to multiple addresses until it
  // succeeds in establishing a connection. The corresponding log will have
  // multiple NetLogEventType::TCP_CONNECT_ATTEMPT entries nested within a
  // NetLogEventType::TCP_CONNECT. These methods set the start/end of
  // NetLogEventType::TCP_CONNECT.
  //
  // TODO(yzshen): Change logging format and let TCPClientSocket log the
  // start/end of a series of connect attempts itself.
  void StartLoggingMultipleConnectAttempts(const AddressList& addresses);
  void EndLoggingMultipleConnectAttempts(int net_error);

  const NetLogWithSource& net_log() const { return net_log_; }

 private:
  // States that using a socket with TCP FastOpen can lead to.
  enum TCPFastOpenStatus {
    TCP_FASTOPEN_STATUS_UNKNOWN,

    // The initial FastOpen connect attempted returned synchronously,
    // indicating that we had and sent a cookie along with the initial data.
    TCP_FASTOPEN_FAST_CONNECT_RETURN,

    // The initial FastOpen connect attempted returned asynchronously,
    // indicating that we did not have a cookie for the server.
    TCP_FASTOPEN_SLOW_CONNECT_RETURN,

    // Some other error occurred on connection, so we couldn't tell if
    // FastOpen would have worked.
    TCP_FASTOPEN_ERROR,

    // An attempt to do a FastOpen succeeded immediately
    // (TCP_FASTOPEN_FAST_CONNECT_RETURN) and we later confirmed that the server
    // had acked the data we sent.
    TCP_FASTOPEN_SYN_DATA_ACK,

    // An attempt to do a FastOpen succeeded immediately
    // (TCP_FASTOPEN_FAST_CONNECT_RETURN) and we later confirmed that the server
    // had nacked the data we sent.
    TCP_FASTOPEN_SYN_DATA_NACK,

    // An attempt to do a FastOpen succeeded immediately
    // (TCP_FASTOPEN_FAST_CONNECT_RETURN) and our probe to determine if the
    // socket was using FastOpen failed.
    TCP_FASTOPEN_SYN_DATA_GETSOCKOPT_FAILED,

    // An attempt to do a FastOpen failed (TCP_FASTOPEN_SLOW_CONNECT_RETURN)
    // and we later confirmed that the server had acked initial data.  This
    // should never happen (we didn't send data, so it shouldn't have
    // been acked).
    TCP_FASTOPEN_NO_SYN_DATA_ACK,

    // An attempt to do a FastOpen failed (TCP_FASTOPEN_SLOW_CONNECT_RETURN)
    // and we later discovered that the server had nacked initial data.  This
    // is the expected case results for TCP_FASTOPEN_SLOW_CONNECT_RETURN.
    TCP_FASTOPEN_NO_SYN_DATA_NACK,

    // An attempt to do a FastOpen failed (TCP_FASTOPEN_SLOW_CONNECT_RETURN)
    // and our later probe for ack/nack state failed.
    TCP_FASTOPEN_NO_SYN_DATA_GETSOCKOPT_FAILED,

    // The initial FastOpen connect+write succeeded immediately
    // (TCP_FASTOPEN_FAST_CONNECT_RETURN) and a subsequent attempt to read from
    // the connection failed.
    TCP_FASTOPEN_FAST_CONNECT_READ_FAILED,

    // The initial FastOpen connect+write failed
    // (TCP_FASTOPEN_SLOW_CONNECT_RETURN)
    // and a subsequent attempt to read from the connection failed.
    TCP_FASTOPEN_SLOW_CONNECT_READ_FAILED,

    // We didn't try FastOpen because it had failed in the past
    // (g_tcp_fastopen_has_failed was true.)
    // NOTE: This status is currently registered before a connect/write call
    // is attempted, and may capture some cases where the status is registered
    // but no connect is subsequently attempted.
    // TODO(jri): The expectation is that such cases are not the common case
    // with TCP FastOpen for SSL sockets however. Change code to be more
    // accurate when TCP FastOpen is used for more than just SSL sockets.
    TCP_FASTOPEN_PREVIOUSLY_FAILED,

    TCP_FASTOPEN_MAX_VALUE
  };

  void AcceptCompleted(std::unique_ptr<TCPSocketPosix>* tcp_socket,
                       IPEndPoint* address,
                       const CompletionCallback& callback,
                       int rv);
  int HandleAcceptCompleted(std::unique_ptr<TCPSocketPosix>* tcp_socket,
                            IPEndPoint* address,
                            int rv);
  int BuildTcpSocketPosix(std::unique_ptr<TCPSocketPosix>* tcp_socket,
                          IPEndPoint* address);

  void ConnectCompleted(const CompletionCallback& callback, int rv);
  int HandleConnectCompleted(int rv);
  void LogConnectBegin(const AddressList& addresses) const;
  void LogConnectEnd(int net_error) const;

  void ReadCompleted(const scoped_refptr<IOBuffer>& buf,
                     const CompletionCallback& callback,
                     int rv);
  int HandleReadCompleted(IOBuffer* buf, int rv);

  void WriteCompleted(const scoped_refptr<IOBuffer>& buf,
                      const CompletionCallback& callback,
                      int rv);
  int HandleWriteCompleted(IOBuffer* buf, int rv);
  int TcpFastOpenWrite(IOBuffer* buf,
                       int buf_len,
                       const CompletionCallback& callback);

  // Notifies |socket_performance_watcher_| of the latest RTT estimate available
  // from the tcp_info struct for this TCP socket.
  void NotifySocketPerformanceWatcher();

  // Called after the first read completes on a TCP FastOpen socket.
  void UpdateTCPFastOpenStatusAfterRead();

  std::unique_ptr<SocketPosix> socket_;
  std::unique_ptr<SocketPosix> accept_socket_;

  // Socket performance statistics (such as RTT) are reported to the
  // |socket_performance_watcher_|. May be nullptr.
  std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher_;

  // Enables experimental TCP FastOpen option.
  bool use_tcp_fastopen_;

  // True when TCP FastOpen is in use and we have attempted the
  // connect with write.
  bool tcp_fastopen_write_attempted_;

  // True when TCP FastOpen is in use and we have done the connect.
  bool tcp_fastopen_connected_;

  TCPFastOpenStatus tcp_fastopen_status_;

  bool logging_multiple_connect_attempts_;

  NetLogWithSource net_log_;

  DISALLOW_COPY_AND_ASSIGN(TCPSocketPosix);
};

}  // namespace net

#endif  // NET_SOCKET_TCP_SOCKET_POSIX_H_
