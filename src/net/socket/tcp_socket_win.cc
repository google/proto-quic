// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/tcp_socket.h"
#include "net/socket/tcp_socket_win.h"

#include <errno.h>
#include <mstcpip.h>

#include <utility>

#include "base/callback_helpers.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/profiler/scoped_tracker.h"
#include "net/base/address_list.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/network_activity_monitor.h"
#include "net/base/network_change_notifier.h"
#include "net/base/sockaddr_storage.h"
#include "net/base/winsock_init.h"
#include "net/base/winsock_util.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"
#include "net/socket/socket_descriptor.h"
#include "net/socket/socket_net_log_params.h"

namespace net {

namespace {

const int kTCPKeepAliveSeconds = 45;

int SetSocketReceiveBufferSize(SOCKET socket, int32_t size) {
  int rv = setsockopt(socket, SOL_SOCKET, SO_RCVBUF,
                      reinterpret_cast<const char*>(&size), sizeof(size));
  int net_error = (rv == 0) ? OK : MapSystemError(WSAGetLastError());
  DCHECK(!rv) << "Could not set socket receive buffer size: " << net_error;
  return net_error;
}

int SetSocketSendBufferSize(SOCKET socket, int32_t size) {
  int rv = setsockopt(socket, SOL_SOCKET, SO_SNDBUF,
                      reinterpret_cast<const char*>(&size), sizeof(size));
  int net_error = (rv == 0) ? OK : MapSystemError(WSAGetLastError());
  DCHECK(!rv) << "Could not set socket send buffer size: " << net_error;
  return net_error;
}

// Disable Nagle.
// Enable TCP Keep-Alive to prevent NAT routers from timing out TCP
// connections. See http://crbug.com/27400 for details.
bool SetTCPKeepAlive(SOCKET socket, BOOL enable, int delay_secs) {
  unsigned delay = delay_secs * 1000;
  struct tcp_keepalive keepalive_vals = {
      enable ? 1u : 0u,  // TCP keep-alive on.
      delay,  // Delay seconds before sending first TCP keep-alive packet.
      delay,  // Delay seconds between sending TCP keep-alive packets.
  };
  DWORD bytes_returned = 0xABAB;
  int rv = WSAIoctl(socket, SIO_KEEPALIVE_VALS, &keepalive_vals,
                    sizeof(keepalive_vals), NULL, 0,
                    &bytes_returned, NULL, NULL);
  DCHECK(!rv) << "Could not enable TCP Keep-Alive for socket: " << socket
              << " [error: " << WSAGetLastError() << "].";

  // Disregard any failure in disabling nagle or enabling TCP Keep-Alive.
  return rv == 0;
}

int MapConnectError(int os_error) {
  switch (os_error) {
    // connect fails with WSAEACCES when Windows Firewall blocks the
    // connection.
    case WSAEACCES:
      return ERR_NETWORK_ACCESS_DENIED;
    case WSAETIMEDOUT:
      return ERR_CONNECTION_TIMED_OUT;
    default: {
      int net_error = MapSystemError(os_error);
      if (net_error == ERR_FAILED)
        return ERR_CONNECTION_FAILED;  // More specific than ERR_FAILED.

      // Give a more specific error when the user is offline.
      if (net_error == ERR_ADDRESS_UNREACHABLE &&
          NetworkChangeNotifier::IsOffline()) {
        return ERR_INTERNET_DISCONNECTED;
      }

      return net_error;
    }
  }
}

}  // namespace

//-----------------------------------------------------------------------------

// Nothing to do for Windows since it doesn't support TCP FastOpen.
// TODO(jri): Remove these along with the corresponding global variables.
bool IsTCPFastOpenSupported() { return false; }
bool IsTCPFastOpenUserEnabled() { return false; }
void CheckSupportAndMaybeEnableTCPFastOpen(bool user_enabled) {}

// This class encapsulates all the state that has to be preserved as long as
// there is a network IO operation in progress. If the owner TCPSocketWin is
// destroyed while an operation is in progress, the Core is detached and it
// lives until the operation completes and the OS doesn't reference any resource
// declared on this class anymore.
class TCPSocketWin::Core : public base::RefCounted<Core> {
 public:
  explicit Core(TCPSocketWin* socket);

  // Start watching for the end of a read or write operation.
  void WatchForRead();
  void WatchForWrite();

  // The TCPSocketWin is going away.
  void Detach() { socket_ = NULL; }

  // The separate OVERLAPPED variables for asynchronous operation.
  // |read_overlapped_| is used for both Connect() and Read().
  // |write_overlapped_| is only used for Write();
  OVERLAPPED read_overlapped_;
  OVERLAPPED write_overlapped_;

  // The buffers used in Read() and Write().
  scoped_refptr<IOBuffer> read_iobuffer_;
  scoped_refptr<IOBuffer> write_iobuffer_;
  int read_buffer_length_;
  int write_buffer_length_;

  bool non_blocking_reads_initialized_;

 private:
  friend class base::RefCounted<Core>;

  class ReadDelegate : public base::win::ObjectWatcher::Delegate {
   public:
    explicit ReadDelegate(Core* core) : core_(core) {}
    ~ReadDelegate() override {}

    // base::ObjectWatcher::Delegate methods:
    void OnObjectSignaled(HANDLE object) override;

   private:
    Core* const core_;
  };

  class WriteDelegate : public base::win::ObjectWatcher::Delegate {
   public:
    explicit WriteDelegate(Core* core) : core_(core) {}
    ~WriteDelegate() override {}

    // base::ObjectWatcher::Delegate methods:
    void OnObjectSignaled(HANDLE object) override;

   private:
    Core* const core_;
  };

  ~Core();

  // The socket that created this object.
  TCPSocketWin* socket_;

  // |reader_| handles the signals from |read_watcher_|.
  ReadDelegate reader_;
  // |writer_| handles the signals from |write_watcher_|.
  WriteDelegate writer_;

  // |read_watcher_| watches for events from Connect() and Read().
  base::win::ObjectWatcher read_watcher_;
  // |write_watcher_| watches for events from Write();
  base::win::ObjectWatcher write_watcher_;

  DISALLOW_COPY_AND_ASSIGN(Core);
};

TCPSocketWin::Core::Core(TCPSocketWin* socket)
    : read_buffer_length_(0),
      write_buffer_length_(0),
      non_blocking_reads_initialized_(false),
      socket_(socket),
      reader_(this),
      writer_(this) {
  memset(&read_overlapped_, 0, sizeof(read_overlapped_));
  memset(&write_overlapped_, 0, sizeof(write_overlapped_));

  read_overlapped_.hEvent = WSACreateEvent();
  write_overlapped_.hEvent = WSACreateEvent();
}

TCPSocketWin::Core::~Core() {
  // Make sure the message loop is not watching this object anymore.
  read_watcher_.StopWatching();
  write_watcher_.StopWatching();

  WSACloseEvent(read_overlapped_.hEvent);
  memset(&read_overlapped_, 0xaf, sizeof(read_overlapped_));
  WSACloseEvent(write_overlapped_.hEvent);
  memset(&write_overlapped_, 0xaf, sizeof(write_overlapped_));
}

void TCPSocketWin::Core::WatchForRead() {
  // We grab an extra reference because there is an IO operation in progress.
  // Balanced in ReadDelegate::OnObjectSignaled().
  AddRef();
  read_watcher_.StartWatchingOnce(read_overlapped_.hEvent, &reader_);
}

void TCPSocketWin::Core::WatchForWrite() {
  // We grab an extra reference because there is an IO operation in progress.
  // Balanced in WriteDelegate::OnObjectSignaled().
  AddRef();
  write_watcher_.StartWatchingOnce(write_overlapped_.hEvent, &writer_);
}

void TCPSocketWin::Core::ReadDelegate::OnObjectSignaled(HANDLE object) {
  DCHECK_EQ(object, core_->read_overlapped_.hEvent);
  if (core_->socket_) {
    if (core_->socket_->waiting_connect_)
      core_->socket_->DidCompleteConnect();
    else
      core_->socket_->DidSignalRead();
  }

  core_->Release();
}

void TCPSocketWin::Core::WriteDelegate::OnObjectSignaled(
    HANDLE object) {
  DCHECK_EQ(object, core_->write_overlapped_.hEvent);
  if (core_->socket_)
    core_->socket_->DidCompleteWrite();

  core_->Release();
}

//-----------------------------------------------------------------------------

TCPSocketWin::TCPSocketWin(
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    net::NetLog* net_log,
    const net::NetLog::Source& source)
    : socket_(INVALID_SOCKET),
      socket_performance_watcher_(std::move(socket_performance_watcher)),
      accept_event_(WSA_INVALID_EVENT),
      accept_socket_(NULL),
      accept_address_(NULL),
      waiting_connect_(false),
      waiting_read_(false),
      waiting_write_(false),
      connect_os_error_(0),
      logging_multiple_connect_attempts_(false),
      net_log_(NetLogWithSource::Make(net_log, NetLogSourceType::SOCKET)) {
  net_log_.BeginEvent(NetLogEventType::SOCKET_ALIVE,
                      source.ToEventParametersCallback());
  EnsureWinsockInit();
}

TCPSocketWin::~TCPSocketWin() {
  Close();
  net_log_.EndEvent(NetLogEventType::SOCKET_ALIVE);
}

int TCPSocketWin::Open(AddressFamily family) {
  DCHECK(CalledOnValidThread());
  DCHECK_EQ(socket_, INVALID_SOCKET);

  socket_ = CreatePlatformSocket(ConvertAddressFamily(family), SOCK_STREAM,
                                 IPPROTO_TCP);
  if (socket_ == INVALID_SOCKET) {
    PLOG(ERROR) << "CreatePlatformSocket() returned an error";
    return MapSystemError(WSAGetLastError());
  }

  if (!base::SetNonBlocking(socket_)) {
    int result = MapSystemError(WSAGetLastError());
    Close();
    return result;
  }

  return OK;
}

int TCPSocketWin::AdoptConnectedSocket(SOCKET socket,
                                       const IPEndPoint& peer_address) {
  DCHECK(CalledOnValidThread());
  DCHECK_EQ(socket_, INVALID_SOCKET);
  DCHECK(!core_.get());

  socket_ = socket;

  if (!base::SetNonBlocking(socket_)) {
    int result = MapSystemError(WSAGetLastError());
    Close();
    return result;
  }

  core_ = new Core(this);
  peer_address_.reset(new IPEndPoint(peer_address));

  return OK;
}

int TCPSocketWin::AdoptListenSocket(SOCKET socket) {
  DCHECK(CalledOnValidThread());
  DCHECK_EQ(socket_, INVALID_SOCKET);

  socket_ = socket;

  if (!base::SetNonBlocking(socket_)) {
    int result = MapSystemError(WSAGetLastError());
    Close();
    return result;
  }

  // |core_| is not needed for sockets that are used to accept connections.
  // The operation here is more like Open but with an existing socket.

  return OK;
}

int TCPSocketWin::Bind(const IPEndPoint& address) {
  DCHECK(CalledOnValidThread());
  DCHECK_NE(socket_, INVALID_SOCKET);

  SockaddrStorage storage;
  if (!address.ToSockAddr(storage.addr, &storage.addr_len))
    return ERR_ADDRESS_INVALID;

  int result = bind(socket_, storage.addr, storage.addr_len);
  if (result < 0) {
    PLOG(ERROR) << "bind() returned an error";
    return MapSystemError(WSAGetLastError());
  }

  return OK;
}

int TCPSocketWin::Listen(int backlog) {
  DCHECK(CalledOnValidThread());
  DCHECK_GT(backlog, 0);
  DCHECK_NE(socket_, INVALID_SOCKET);
  DCHECK_EQ(accept_event_, WSA_INVALID_EVENT);

  accept_event_ = WSACreateEvent();
  if (accept_event_ == WSA_INVALID_EVENT) {
    PLOG(ERROR) << "WSACreateEvent()";
    return MapSystemError(WSAGetLastError());
  }

  int result = listen(socket_, backlog);
  if (result < 0) {
    PLOG(ERROR) << "listen() returned an error";
    return MapSystemError(WSAGetLastError());
  }

  return OK;
}

int TCPSocketWin::Accept(std::unique_ptr<TCPSocketWin>* socket,
                         IPEndPoint* address,
                         const CompletionCallback& callback) {
  DCHECK(CalledOnValidThread());
  DCHECK(socket);
  DCHECK(address);
  DCHECK(!callback.is_null());
  DCHECK(accept_callback_.is_null());

  net_log_.BeginEvent(NetLogEventType::TCP_ACCEPT);

  int result = AcceptInternal(socket, address);

  if (result == ERR_IO_PENDING) {
    // Start watching.
    WSAEventSelect(socket_, accept_event_, FD_ACCEPT);
    accept_watcher_.StartWatchingOnce(accept_event_, this);

    accept_socket_ = socket;
    accept_address_ = address;
    accept_callback_ = callback;
  }

  return result;
}

int TCPSocketWin::Connect(const IPEndPoint& address,
                          const CompletionCallback& callback) {
  DCHECK(CalledOnValidThread());
  DCHECK_NE(socket_, INVALID_SOCKET);
  DCHECK(!waiting_connect_);

  // |peer_address_| and |core_| will be non-NULL if Connect() has been called.
  // Unless Close() is called to reset the internal state, a second call to
  // Connect() is not allowed.
  // Please note that we enforce this even if the previous Connect() has
  // completed and failed. Although it is allowed to connect the same |socket_|
  // again after a connection attempt failed on Windows, it results in
  // unspecified behavior according to POSIX. Therefore, we make it behave in
  // the same way as TCPSocketPosix.
  DCHECK(!peer_address_ && !core_.get());

  if (!logging_multiple_connect_attempts_)
    LogConnectBegin(AddressList(address));

  peer_address_.reset(new IPEndPoint(address));

  int rv = DoConnect();
  if (rv == ERR_IO_PENDING) {
    // Synchronous operation not supported.
    DCHECK(!callback.is_null());
    read_callback_ = callback;
    waiting_connect_ = true;
  } else {
    DoConnectComplete(rv);
  }

  return rv;
}

bool TCPSocketWin::IsConnected() const {
  DCHECK(CalledOnValidThread());

  if (socket_ == INVALID_SOCKET || waiting_connect_)
    return false;

  if (waiting_read_)
    return true;

  // Check if connection is alive.
  char c;
  int rv = recv(socket_, &c, 1, MSG_PEEK);
  if (rv == 0)
    return false;
  if (rv == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
    return false;

  return true;
}

bool TCPSocketWin::IsConnectedAndIdle() const {
  DCHECK(CalledOnValidThread());

  if (socket_ == INVALID_SOCKET || waiting_connect_)
    return false;

  if (waiting_read_)
    return true;

  // Check if connection is alive and we haven't received any data
  // unexpectedly.
  char c;
  int rv = recv(socket_, &c, 1, MSG_PEEK);
  if (rv >= 0)
    return false;
  if (WSAGetLastError() != WSAEWOULDBLOCK)
    return false;

  return true;
}

int TCPSocketWin::Read(IOBuffer* buf,
                       int buf_len,
                       const CompletionCallback& callback) {
  DCHECK(CalledOnValidThread());
  DCHECK_NE(socket_, INVALID_SOCKET);
  DCHECK(!waiting_read_);
  CHECK(read_callback_.is_null());
  DCHECK(!core_->read_iobuffer_.get());

  return DoRead(buf, buf_len, callback);
}

int TCPSocketWin::Write(IOBuffer* buf,
                        int buf_len,
                        const CompletionCallback& callback) {
  DCHECK(CalledOnValidThread());
  DCHECK_NE(socket_, INVALID_SOCKET);
  DCHECK(!waiting_write_);
  CHECK(write_callback_.is_null());
  DCHECK_GT(buf_len, 0);
  DCHECK(!core_->write_iobuffer_.get());

  WSABUF write_buffer;
  write_buffer.len = buf_len;
  write_buffer.buf = buf->data();

  // TODO(wtc): Remove the assertion after enough testing.
  AssertEventNotSignaled(core_->write_overlapped_.hEvent);
  DWORD num;
  int rv = WSASend(socket_, &write_buffer, 1, &num, 0,
                   &core_->write_overlapped_, NULL);
  if (rv == 0) {
    if (ResetEventIfSignaled(core_->write_overlapped_.hEvent)) {
      rv = static_cast<int>(num);
      if (rv > buf_len || rv < 0) {
        // It seems that some winsock interceptors report that more was written
        // than was available. Treat this as an error.  http://crbug.com/27870
        LOG(ERROR) << "Detected broken LSP: Asked to write " << buf_len
                   << " bytes, but " << rv << " bytes reported.";
        return ERR_WINSOCK_UNEXPECTED_WRITTEN_BYTES;
      }
      net_log_.AddByteTransferEvent(NetLogEventType::SOCKET_BYTES_SENT, rv,
                                    buf->data());
      NetworkActivityMonitor::GetInstance()->IncrementBytesSent(rv);
      return rv;
    }
  } else {
    int os_error = WSAGetLastError();
    if (os_error != WSA_IO_PENDING) {
      int net_error = MapSystemError(os_error);
      net_log_.AddEvent(NetLogEventType::SOCKET_WRITE_ERROR,
                        CreateNetLogSocketErrorCallback(net_error, os_error));
      return net_error;
    }
  }
  waiting_write_ = true;
  write_callback_ = callback;
  core_->write_iobuffer_ = buf;
  core_->write_buffer_length_ = buf_len;
  core_->WatchForWrite();
  return ERR_IO_PENDING;
}

int TCPSocketWin::GetLocalAddress(IPEndPoint* address) const {
  DCHECK(CalledOnValidThread());
  DCHECK(address);

  SockaddrStorage storage;
  if (getsockname(socket_, storage.addr, &storage.addr_len))
    return MapSystemError(WSAGetLastError());
  if (!address->FromSockAddr(storage.addr, storage.addr_len))
    return ERR_ADDRESS_INVALID;

  return OK;
}

int TCPSocketWin::GetPeerAddress(IPEndPoint* address) const {
  DCHECK(CalledOnValidThread());
  DCHECK(address);
  if (!IsConnected())
    return ERR_SOCKET_NOT_CONNECTED;
  *address = *peer_address_;
  return OK;
}

int TCPSocketWin::SetDefaultOptionsForServer() {
  return SetExclusiveAddrUse();
}

void TCPSocketWin::SetDefaultOptionsForClient() {
  SetTCPNoDelay(socket_, /*no_delay=*/true);
  SetTCPKeepAlive(socket_, true, kTCPKeepAliveSeconds);
}

int TCPSocketWin::SetExclusiveAddrUse() {
  // On Windows, a bound end point can be hijacked by another process by
  // setting SO_REUSEADDR. Therefore a Windows-only option SO_EXCLUSIVEADDRUSE
  // was introduced in Windows NT 4.0 SP4. If the socket that is bound to the
  // end point has SO_EXCLUSIVEADDRUSE enabled, it is not possible for another
  // socket to forcibly bind to the end point until the end point is unbound.
  // It is recommend that all server applications must use SO_EXCLUSIVEADDRUSE.
  // MSDN: http://goo.gl/M6fjQ.
  //
  // Unlike on *nix, on Windows a TCP server socket can always bind to an end
  // point in TIME_WAIT state without setting SO_REUSEADDR, therefore it is not
  // needed here.
  //
  // SO_EXCLUSIVEADDRUSE will prevent a TCP client socket from binding to an end
  // point in TIME_WAIT status. It does not have this effect for a TCP server
  // socket.

  BOOL true_value = 1;
  int rv = setsockopt(socket_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                      reinterpret_cast<const char*>(&true_value),
                      sizeof(true_value));
  if (rv < 0)
    return MapSystemError(errno);
  return OK;
}

int TCPSocketWin::SetReceiveBufferSize(int32_t size) {
  DCHECK(CalledOnValidThread());
  return SetSocketReceiveBufferSize(socket_, size);
}

int TCPSocketWin::SetSendBufferSize(int32_t size) {
  DCHECK(CalledOnValidThread());
  return SetSocketSendBufferSize(socket_, size);
}

bool TCPSocketWin::SetKeepAlive(bool enable, int delay) {
  return SetTCPKeepAlive(socket_, enable, delay);
}

bool TCPSocketWin::SetNoDelay(bool no_delay) {
  return SetTCPNoDelay(socket_, no_delay);
}

void TCPSocketWin::Close() {
  DCHECK(CalledOnValidThread());

  if (socket_ != INVALID_SOCKET) {
    // Only log the close event if there's actually a socket to close.
    net_log_.AddEvent(NetLogEventType::SOCKET_CLOSED);

    // Note: don't use CancelIo to cancel pending IO because it doesn't work
    // when there is a Winsock layered service provider.

    // In most socket implementations, closing a socket results in a graceful
    // connection shutdown, but in Winsock we have to call shutdown explicitly.
    // See the MSDN page "Graceful Shutdown, Linger Options, and Socket Closure"
    // at http://msdn.microsoft.com/en-us/library/ms738547.aspx
    shutdown(socket_, SD_SEND);

    // This cancels any pending IO.
    if (closesocket(socket_) < 0)
      PLOG(ERROR) << "closesocket";
    socket_ = INVALID_SOCKET;
  }

  if (!accept_callback_.is_null()) {
    accept_watcher_.StopWatching();
    accept_socket_ = NULL;
    accept_address_ = NULL;
    accept_callback_.Reset();
  }

  if (accept_event_) {
    WSACloseEvent(accept_event_);
    accept_event_ = WSA_INVALID_EVENT;
  }

  if (core_.get()) {
    if (waiting_connect_) {
      // We closed the socket, so this notification will never come.
      // From MSDN' WSAEventSelect documentation:
      // "Closing a socket with closesocket also cancels the association and
      // selection of network events specified in WSAEventSelect for the
      // socket".
      core_->Release();
    }
    core_->Detach();
    core_ = NULL;
  }

  waiting_connect_ = false;
  waiting_read_ = false;
  waiting_write_ = false;

  read_callback_.Reset();
  write_callback_.Reset();
  peer_address_.reset();
  connect_os_error_ = 0;
}

void TCPSocketWin::DetachFromThread() {
  base::NonThreadSafe::DetachFromThread();
}

void TCPSocketWin::StartLoggingMultipleConnectAttempts(
    const AddressList& addresses) {
  if (!logging_multiple_connect_attempts_) {
    logging_multiple_connect_attempts_ = true;
    LogConnectBegin(addresses);
  } else {
    NOTREACHED();
  }
}

void TCPSocketWin::EndLoggingMultipleConnectAttempts(int net_error) {
  if (logging_multiple_connect_attempts_) {
    LogConnectEnd(net_error);
    logging_multiple_connect_attempts_ = false;
  } else {
    NOTREACHED();
  }
}

int TCPSocketWin::AcceptInternal(std::unique_ptr<TCPSocketWin>* socket,
                                 IPEndPoint* address) {
  SockaddrStorage storage;
  int new_socket = accept(socket_, storage.addr, &storage.addr_len);
  if (new_socket < 0) {
    int net_error = MapSystemError(WSAGetLastError());
    if (net_error != ERR_IO_PENDING)
      net_log_.EndEventWithNetErrorCode(NetLogEventType::TCP_ACCEPT, net_error);
    return net_error;
  }

  IPEndPoint ip_end_point;
  if (!ip_end_point.FromSockAddr(storage.addr, storage.addr_len)) {
    NOTREACHED();
    if (closesocket(new_socket) < 0)
      PLOG(ERROR) << "closesocket";
    int net_error = ERR_ADDRESS_INVALID;
    net_log_.EndEventWithNetErrorCode(NetLogEventType::TCP_ACCEPT, net_error);
    return net_error;
  }
  std::unique_ptr<TCPSocketWin> tcp_socket(
      new TCPSocketWin(NULL, net_log_.net_log(), net_log_.source()));
  int adopt_result = tcp_socket->AdoptConnectedSocket(new_socket, ip_end_point);
  if (adopt_result != OK) {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::TCP_ACCEPT,
                                      adopt_result);
    return adopt_result;
  }
  *socket = std::move(tcp_socket);
  *address = ip_end_point;
  net_log_.EndEvent(NetLogEventType::TCP_ACCEPT,
                    CreateNetLogIPEndPointCallback(&ip_end_point));
  return OK;
}

void TCPSocketWin::OnObjectSignaled(HANDLE object) {
  WSANETWORKEVENTS ev;
  if (WSAEnumNetworkEvents(socket_, accept_event_, &ev) == SOCKET_ERROR) {
    PLOG(ERROR) << "WSAEnumNetworkEvents()";
    return;
  }

  if (ev.lNetworkEvents & FD_ACCEPT) {
    int result = AcceptInternal(accept_socket_, accept_address_);
    if (result != ERR_IO_PENDING) {
      accept_socket_ = NULL;
      accept_address_ = NULL;
      base::ResetAndReturn(&accept_callback_).Run(result);
    }
  } else {
    // This happens when a client opens a connection and closes it before we
    // have a chance to accept it.
    DCHECK(ev.lNetworkEvents == 0);

    // Start watching the next FD_ACCEPT event.
    WSAEventSelect(socket_, accept_event_, FD_ACCEPT);
    accept_watcher_.StartWatchingOnce(accept_event_, this);
  }
}

int TCPSocketWin::DoConnect() {
  DCHECK_EQ(connect_os_error_, 0);
  DCHECK(!core_.get());

  net_log_.BeginEvent(NetLogEventType::TCP_CONNECT_ATTEMPT,
                      CreateNetLogIPEndPointCallback(peer_address_.get()));

  core_ = new Core(this);

  // WSAEventSelect sets the socket to non-blocking mode as a side effect.
  // Our connect() and recv() calls require that the socket be non-blocking.
  WSAEventSelect(socket_, core_->read_overlapped_.hEvent, FD_CONNECT);

  SockaddrStorage storage;
  if (!peer_address_->ToSockAddr(storage.addr, &storage.addr_len))
    return ERR_ADDRESS_INVALID;

  int result;
  {
    // TODO(ricea): Remove ScopedTracker below once crbug.com/436634 is fixed.
    tracked_objects::ScopedTracker tracking_profile(
        FROM_HERE_WITH_EXPLICIT_FUNCTION("436634 connect()"));
    result = connect(socket_, storage.addr, storage.addr_len);
  }

  if (!result) {
    // Connected without waiting!
    //
    // The MSDN page for connect says:
    //   With a nonblocking socket, the connection attempt cannot be completed
    //   immediately. In this case, connect will return SOCKET_ERROR, and
    //   WSAGetLastError will return WSAEWOULDBLOCK.
    // which implies that for a nonblocking socket, connect never returns 0.
    // It's not documented whether the event object will be signaled or not
    // if connect does return 0.  So the code below is essentially dead code
    // and we don't know if it's correct.
    NOTREACHED();

    if (ResetEventIfSignaled(core_->read_overlapped_.hEvent))
      return OK;
  } else {
    int os_error = WSAGetLastError();
    if (os_error != WSAEWOULDBLOCK) {
      LOG(ERROR) << "connect failed: " << os_error;
      connect_os_error_ = os_error;
      int rv = MapConnectError(os_error);
      CHECK_NE(ERR_IO_PENDING, rv);
      return rv;
    }
  }

  // TODO(ricea): Remove ScopedTracker below once crbug.com/436634 is fixed.
  tracked_objects::ScopedTracker tracking_profile(
      FROM_HERE_WITH_EXPLICIT_FUNCTION("436634 WatchForRead()"));

  core_->WatchForRead();
  return ERR_IO_PENDING;
}

void TCPSocketWin::DoConnectComplete(int result) {
  // Log the end of this attempt (and any OS error it threw).
  int os_error = connect_os_error_;
  connect_os_error_ = 0;
  if (result != OK) {
    net_log_.EndEvent(NetLogEventType::TCP_CONNECT_ATTEMPT,
                      NetLog::IntCallback("os_error", os_error));
  } else {
    net_log_.EndEvent(NetLogEventType::TCP_CONNECT_ATTEMPT);
  }

  if (!logging_multiple_connect_attempts_)
    LogConnectEnd(result);
}

void TCPSocketWin::LogConnectBegin(const AddressList& addresses) {
  net_log_.BeginEvent(NetLogEventType::TCP_CONNECT,
                      addresses.CreateNetLogCallback());
}

void TCPSocketWin::LogConnectEnd(int net_error) {
  if (net_error != OK) {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::TCP_CONNECT, net_error);
    return;
  }

  struct sockaddr_storage source_address;
  socklen_t addrlen = sizeof(source_address);
  int rv = getsockname(
      socket_, reinterpret_cast<struct sockaddr*>(&source_address), &addrlen);
  if (rv != 0) {
    LOG(ERROR) << "getsockname() [rv: " << rv
               << "] error: " << WSAGetLastError();
    NOTREACHED();
    net_log_.EndEventWithNetErrorCode(NetLogEventType::TCP_CONNECT, rv);
    return;
  }

  net_log_.EndEvent(
      NetLogEventType::TCP_CONNECT,
      CreateNetLogSourceAddressCallback(
          reinterpret_cast<const struct sockaddr*>(&source_address),
          sizeof(source_address)));
}

int TCPSocketWin::DoRead(IOBuffer* buf, int buf_len,
                         const CompletionCallback& callback) {
  if (!core_->non_blocking_reads_initialized_) {
    WSAEventSelect(socket_, core_->read_overlapped_.hEvent,
                   FD_READ | FD_CLOSE);
    core_->non_blocking_reads_initialized_ = true;
  }
  int rv = recv(socket_, buf->data(), buf_len, 0);
  if (rv == SOCKET_ERROR) {
    int os_error = WSAGetLastError();
    if (os_error != WSAEWOULDBLOCK) {
      int net_error = MapSystemError(os_error);
      net_log_.AddEvent(NetLogEventType::SOCKET_READ_ERROR,
                        CreateNetLogSocketErrorCallback(net_error, os_error));
      return net_error;
    }
  } else {
    net_log_.AddByteTransferEvent(NetLogEventType::SOCKET_BYTES_RECEIVED, rv,
                                  buf->data());
    NetworkActivityMonitor::GetInstance()->IncrementBytesReceived(rv);
    return rv;
  }

  waiting_read_ = true;
  read_callback_ = callback;
  core_->read_iobuffer_ = buf;
  core_->read_buffer_length_ = buf_len;
  core_->WatchForRead();
  return ERR_IO_PENDING;
}

void TCPSocketWin::DidCompleteConnect() {
  DCHECK(waiting_connect_);
  DCHECK(!read_callback_.is_null());
  int result;

  WSANETWORKEVENTS events;
  int rv;
  {
    // TODO(pkasting): Remove ScopedTracker below once crbug.com/462784 is
    // fixed.
    tracked_objects::ScopedTracker tracking_profile1(
        FROM_HERE_WITH_EXPLICIT_FUNCTION(
            "462784 TCPSocketWin::DidCompleteConnect -> WSAEnumNetworkEvents"));
    rv = WSAEnumNetworkEvents(socket_, core_->read_overlapped_.hEvent, &events);
  }
  int os_error = 0;
  if (rv == SOCKET_ERROR) {
    NOTREACHED();
    os_error = WSAGetLastError();
    result = MapSystemError(os_error);
  } else if (events.lNetworkEvents & FD_CONNECT) {
    os_error = events.iErrorCode[FD_CONNECT_BIT];
    result = MapConnectError(os_error);
  } else {
    NOTREACHED();
    result = ERR_UNEXPECTED;
  }

  connect_os_error_ = os_error;
  DoConnectComplete(result);
  waiting_connect_ = false;

  // TODO(pkasting): Remove ScopedTracker below once crbug.com/462784 is fixed.
  tracked_objects::ScopedTracker tracking_profile4(
      FROM_HERE_WITH_EXPLICIT_FUNCTION(
          "462784 TCPSocketWin::DidCompleteConnect -> read_callback_"));
  DCHECK_NE(result, ERR_IO_PENDING);
  base::ResetAndReturn(&read_callback_).Run(result);
}

void TCPSocketWin::DidCompleteWrite() {
  DCHECK(waiting_write_);
  DCHECK(!write_callback_.is_null());

  DWORD num_bytes, flags;
  BOOL ok = WSAGetOverlappedResult(socket_, &core_->write_overlapped_,
                                   &num_bytes, FALSE, &flags);
  WSAResetEvent(core_->write_overlapped_.hEvent);
  waiting_write_ = false;
  int rv;
  if (!ok) {
    int os_error = WSAGetLastError();
    rv = MapSystemError(os_error);
    net_log_.AddEvent(NetLogEventType::SOCKET_WRITE_ERROR,
                      CreateNetLogSocketErrorCallback(rv, os_error));
  } else {
    rv = static_cast<int>(num_bytes);
    if (rv > core_->write_buffer_length_ || rv < 0) {
      // It seems that some winsock interceptors report that more was written
      // than was available. Treat this as an error.  http://crbug.com/27870
      LOG(ERROR) << "Detected broken LSP: Asked to write "
                 << core_->write_buffer_length_ << " bytes, but " << rv
                 << " bytes reported.";
      rv = ERR_WINSOCK_UNEXPECTED_WRITTEN_BYTES;
    } else {
      net_log_.AddByteTransferEvent(NetLogEventType::SOCKET_BYTES_SENT,
                                    num_bytes, core_->write_iobuffer_->data());
      NetworkActivityMonitor::GetInstance()->IncrementBytesSent(num_bytes);
    }
  }

  core_->write_iobuffer_ = NULL;

  DCHECK_NE(rv, ERR_IO_PENDING);
  base::ResetAndReturn(&write_callback_).Run(rv);
}

void TCPSocketWin::DidSignalRead() {
  DCHECK(waiting_read_);
  DCHECK(!read_callback_.is_null());

  int os_error = 0;
  WSANETWORKEVENTS network_events;
  int rv = WSAEnumNetworkEvents(socket_, core_->read_overlapped_.hEvent,
                                &network_events);
  if (rv == SOCKET_ERROR) {
    os_error = WSAGetLastError();
    rv = MapSystemError(os_error);
  } else if (network_events.lNetworkEvents) {
    // TODO(pkasting): Remove ScopedTracker below once crbug.com/462778 is
    // fixed.
    tracked_objects::ScopedTracker tracking_profile2(
        FROM_HERE_WITH_EXPLICIT_FUNCTION(
            "462778 TCPSocketWin::DidSignalRead -> DoRead"));
    DCHECK_EQ(network_events.lNetworkEvents & ~(FD_READ | FD_CLOSE), 0);
    // If network_events.lNetworkEvents is FD_CLOSE and
    // network_events.iErrorCode[FD_CLOSE_BIT] is 0, it is a graceful
    // connection closure. It is tempting to directly set rv to 0 in
    // this case, but the MSDN pages for WSAEventSelect and
    // WSAAsyncSelect recommend we still call DoRead():
    //   FD_CLOSE should only be posted after all data is read from a
    //   socket, but an application should check for remaining data upon
    //   receipt of FD_CLOSE to avoid any possibility of losing data.
    //
    // If network_events.iErrorCode[FD_READ_BIT] or
    // network_events.iErrorCode[FD_CLOSE_BIT] is nonzero, still call
    // DoRead() because recv() reports a more accurate error code
    // (WSAECONNRESET vs. WSAECONNABORTED) when the connection was
    // reset.
    rv = DoRead(core_->read_iobuffer_.get(), core_->read_buffer_length_,
                read_callback_);
    if (rv == ERR_IO_PENDING)
      return;
  } else {
    // This may happen because Read() may succeed synchronously and
    // consume all the received data without resetting the event object.
    core_->WatchForRead();
    return;
  }

  waiting_read_ = false;
  core_->read_iobuffer_ = NULL;
  core_->read_buffer_length_ = 0;

  DCHECK_NE(rv, ERR_IO_PENDING);
  base::ResetAndReturn(&read_callback_).Run(rv);
}

bool TCPSocketWin::GetEstimatedRoundTripTime(base::TimeDelta* out_rtt) const {
  DCHECK(out_rtt);
  // TODO(bmcquade): Consider implementing using
  // GetPerTcpConnectionEStats/GetPerTcp6ConnectionEStats.
  return false;
}

}  // namespace net
