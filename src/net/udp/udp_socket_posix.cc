// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/udp/udp_socket_posix.h"

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "base/callback.h"
#include "base/debug/alias.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/metrics/sparse_histogram.h"
#include "base/posix/eintr_wrapper.h"
#include "base/rand_util.h"
#include "base/trace_event/trace_event.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/network_activity_monitor.h"
#include "net/base/sockaddr_storage.h"
#include "net/log/net_log.h"
#include "net/socket/socket_descriptor.h"
#include "net/udp/udp_net_log_parameters.h"

#if defined(OS_ANDROID)
#include <dlfcn.h>
// This was added in Lollipop to dlfcn.h
#define RTLD_NOLOAD 4
#include "base/android/build_info.h"
#include "base/native_library.h"
#include "base/strings/utf_string_conversions.h"
#endif

namespace net {

namespace {

const int kBindRetries = 10;
const int kPortStart = 1024;
const int kPortEnd = 65535;

#if defined(OS_MACOSX)

// Returns IPv4 address in network order.
int GetIPv4AddressFromIndex(int socket, uint32_t index, uint32_t* address) {
  if (!index) {
    *address = htonl(INADDR_ANY);
    return OK;
  }
  ifreq ifr;
  ifr.ifr_addr.sa_family = AF_INET;
  if (!if_indextoname(index, ifr.ifr_name))
    return MapSystemError(errno);
  int rv = ioctl(socket, SIOCGIFADDR, &ifr);
  if (rv == -1)
    return MapSystemError(errno);
  *address = reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr;
  return OK;
}

#endif  // OS_MACOSX

}  // namespace

UDPSocketPosix::UDPSocketPosix(DatagramSocket::BindType bind_type,
                               const RandIntCallback& rand_int_cb,
                               net::NetLog* net_log,
                               const net::NetLog::Source& source)
    : socket_(kInvalidSocket),
      addr_family_(0),
      is_connected_(false),
      socket_options_(SOCKET_OPTION_MULTICAST_LOOP),
      multicast_interface_(0),
      multicast_time_to_live_(1),
      bind_type_(bind_type),
      rand_int_cb_(rand_int_cb),
      read_watcher_(this),
      write_watcher_(this),
      read_buf_len_(0),
      recv_from_address_(NULL),
      write_buf_len_(0),
      net_log_(BoundNetLog::Make(net_log, NetLog::SOURCE_UDP_SOCKET)),
      bound_network_(NetworkChangeNotifier::kInvalidNetworkHandle) {
  net_log_.BeginEvent(NetLog::TYPE_SOCKET_ALIVE,
                      source.ToEventParametersCallback());
  if (bind_type == DatagramSocket::RANDOM_BIND)
    DCHECK(!rand_int_cb.is_null());
}

UDPSocketPosix::~UDPSocketPosix() {
  Close();
  net_log_.EndEvent(NetLog::TYPE_SOCKET_ALIVE);
}

int UDPSocketPosix::Open(AddressFamily address_family) {
  DCHECK(CalledOnValidThread());
  DCHECK_EQ(socket_, kInvalidSocket);

  addr_family_ = ConvertAddressFamily(address_family);
  socket_ = CreatePlatformSocket(addr_family_, SOCK_DGRAM, 0);
  if (socket_ == kInvalidSocket)
    return MapSystemError(errno);
  if (!base::SetNonBlocking(socket_)) {
    const int err = MapSystemError(errno);
    Close();
    return err;
  }
  return OK;
}

void UDPSocketPosix::Close() {
  DCHECK(CalledOnValidThread());

  if (socket_ == kInvalidSocket)
    return;

  // Zero out any pending read/write callback state.
  read_buf_ = NULL;
  read_buf_len_ = 0;
  read_callback_.Reset();
  recv_from_address_ = NULL;
  write_buf_ = NULL;
  write_buf_len_ = 0;
  write_callback_.Reset();
  send_to_address_.reset();

  bool ok = read_socket_watcher_.StopWatchingFileDescriptor();
  DCHECK(ok);
  ok = write_socket_watcher_.StopWatchingFileDescriptor();
  DCHECK(ok);

  PCHECK(IGNORE_EINTR(close(socket_)) == 0);

  socket_ = kInvalidSocket;
  addr_family_ = 0;
  is_connected_ = false;
}

int UDPSocketPosix::GetPeerAddress(IPEndPoint* address) const {
  DCHECK(CalledOnValidThread());
  DCHECK(address);
  if (!is_connected())
    return ERR_SOCKET_NOT_CONNECTED;

  if (!remote_address_.get()) {
    SockaddrStorage storage;
    if (getpeername(socket_, storage.addr, &storage.addr_len))
      return MapSystemError(errno);
    std::unique_ptr<IPEndPoint> address(new IPEndPoint());
    if (!address->FromSockAddr(storage.addr, storage.addr_len))
      return ERR_ADDRESS_INVALID;
    remote_address_.reset(address.release());
  }

  *address = *remote_address_;
  return OK;
}

int UDPSocketPosix::GetLocalAddress(IPEndPoint* address) const {
  DCHECK(CalledOnValidThread());
  DCHECK(address);
  if (!is_connected())
    return ERR_SOCKET_NOT_CONNECTED;

  if (!local_address_.get()) {
    SockaddrStorage storage;
    if (getsockname(socket_, storage.addr, &storage.addr_len))
      return MapSystemError(errno);
    std::unique_ptr<IPEndPoint> address(new IPEndPoint());
    if (!address->FromSockAddr(storage.addr, storage.addr_len))
      return ERR_ADDRESS_INVALID;
    local_address_.reset(address.release());
    net_log_.AddEvent(
        NetLog::TYPE_UDP_LOCAL_ADDRESS,
        CreateNetLogUDPConnectCallback(local_address_.get(), bound_network_));
  }

  *address = *local_address_;
  return OK;
}

int UDPSocketPosix::Read(IOBuffer* buf,
                         int buf_len,
                         const CompletionCallback& callback) {
  return RecvFrom(buf, buf_len, NULL, callback);
}

int UDPSocketPosix::RecvFrom(IOBuffer* buf,
                             int buf_len,
                             IPEndPoint* address,
                             const CompletionCallback& callback) {
  DCHECK(CalledOnValidThread());
  DCHECK_NE(kInvalidSocket, socket_);
  CHECK(read_callback_.is_null());
  DCHECK(!recv_from_address_);
  DCHECK(!callback.is_null());  // Synchronous operation not supported
  DCHECK_GT(buf_len, 0);

  int nread = InternalRecvFrom(buf, buf_len, address);
  if (nread != ERR_IO_PENDING)
    return nread;

  if (!base::MessageLoopForIO::current()->WatchFileDescriptor(
          socket_, true, base::MessageLoopForIO::WATCH_READ,
          &read_socket_watcher_, &read_watcher_)) {
    PLOG(ERROR) << "WatchFileDescriptor failed on read";
    int result = MapSystemError(errno);
    LogRead(result, NULL, 0, NULL);
    return result;
  }

  read_buf_ = buf;
  read_buf_len_ = buf_len;
  recv_from_address_ = address;
  read_callback_ = callback;
  return ERR_IO_PENDING;
}

int UDPSocketPosix::Write(IOBuffer* buf,
                          int buf_len,
                          const CompletionCallback& callback) {
  return SendToOrWrite(buf, buf_len, NULL, callback);
}

int UDPSocketPosix::SendTo(IOBuffer* buf,
                           int buf_len,
                           const IPEndPoint& address,
                           const CompletionCallback& callback) {
  return SendToOrWrite(buf, buf_len, &address, callback);
}

int UDPSocketPosix::SendToOrWrite(IOBuffer* buf,
                                  int buf_len,
                                  const IPEndPoint* address,
                                  const CompletionCallback& callback) {
  DCHECK(CalledOnValidThread());
  DCHECK_NE(kInvalidSocket, socket_);
  CHECK(write_callback_.is_null());
  DCHECK(!callback.is_null());  // Synchronous operation not supported
  DCHECK_GT(buf_len, 0);

  int result = InternalSendTo(buf, buf_len, address);
  if (result != ERR_IO_PENDING)
    return result;

  if (!base::MessageLoopForIO::current()->WatchFileDescriptor(
          socket_, true, base::MessageLoopForIO::WATCH_WRITE,
          &write_socket_watcher_, &write_watcher_)) {
    DVLOG(1) << "WatchFileDescriptor failed on write, errno " << errno;
    int result = MapSystemError(errno);
    LogWrite(result, NULL, NULL);
    return result;
  }

  write_buf_ = buf;
  write_buf_len_ = buf_len;
  DCHECK(!send_to_address_.get());
  if (address) {
    send_to_address_.reset(new IPEndPoint(*address));
  }
  write_callback_ = callback;
  return ERR_IO_PENDING;
}

int UDPSocketPosix::Connect(const IPEndPoint& address) {
  DCHECK_NE(socket_, kInvalidSocket);
  net_log_.BeginEvent(NetLog::TYPE_UDP_CONNECT,
                      CreateNetLogUDPConnectCallback(&address, bound_network_));
  int rv = InternalConnect(address);
  net_log_.EndEventWithNetErrorCode(NetLog::TYPE_UDP_CONNECT, rv);
  is_connected_ = (rv == OK);
  return rv;
}

int UDPSocketPosix::InternalConnect(const IPEndPoint& address) {
  DCHECK(CalledOnValidThread());
  DCHECK(!is_connected());
  DCHECK(!remote_address_.get());

  int rv = 0;
  if (bind_type_ == DatagramSocket::RANDOM_BIND) {
    // Construct IPAddress of appropriate size (IPv4 or IPv6) of 0s,
    // representing INADDR_ANY or in6addr_any.
    size_t addr_size = address.GetSockAddrFamily() == AF_INET
                           ? IPAddress::kIPv4AddressSize
                           : IPAddress::kIPv6AddressSize;
    rv = RandomBind(IPAddress::AllZeros(addr_size));
  }
  // else connect() does the DatagramSocket::DEFAULT_BIND

  if (rv < 0) {
    UMA_HISTOGRAM_SPARSE_SLOWLY("Net.UdpSocketRandomBindErrorCode", -rv);
    return rv;
  }

  SockaddrStorage storage;
  if (!address.ToSockAddr(storage.addr, &storage.addr_len))
    return ERR_ADDRESS_INVALID;

  rv = HANDLE_EINTR(connect(socket_, storage.addr, storage.addr_len));
  if (rv < 0)
    return MapSystemError(errno);

  remote_address_.reset(new IPEndPoint(address));
  return rv;
}

int UDPSocketPosix::Bind(const IPEndPoint& address) {
  DCHECK_NE(socket_, kInvalidSocket);
  DCHECK(CalledOnValidThread());
  DCHECK(!is_connected());

  int rv = SetMulticastOptions();
  if (rv < 0)
    return rv;

  rv = DoBind(address);
  if (rv < 0)
    return rv;

  is_connected_ = true;
  local_address_.reset();
  return rv;
}

int UDPSocketPosix::BindToNetwork(
    NetworkChangeNotifier::NetworkHandle network) {
  DCHECK_NE(socket_, kInvalidSocket);
  DCHECK(CalledOnValidThread());
  DCHECK(!is_connected());
  if (network == NetworkChangeNotifier::kInvalidNetworkHandle)
    return ERR_INVALID_ARGUMENT;
#if defined(OS_ANDROID)
  // Android prior to Lollipop didn't have support for binding sockets to
  // networks.
  if (base::android::BuildInfo::GetInstance()->sdk_int() <
      base::android::SDK_VERSION_LOLLIPOP) {
    return ERR_NOT_IMPLEMENTED;
  }
  // NOTE(pauljensen): This does rely on Android implementation details, but
  // these details are unlikely to change.
  typedef int (*SetNetworkForSocket)(unsigned netId, int socketFd);
  static SetNetworkForSocket setNetworkForSocket;
  // This is racy, but all racers should come out with the same answer so it
  // shouldn't matter.
  if (!setNetworkForSocket) {
    // Android's netd client library should always be loaded in our address
    // space as it shims socket() which was used to create |socket_|.
    base::FilePath file(base::GetNativeLibraryName("netd_client"));
    // Use RTLD_NOW to match Android's prior loading of the library:
    // http://androidxref.com/6.0.0_r5/xref/bionic/libc/bionic/NetdClient.cpp#37
    // Use RTLD_NOLOAD to assert that the library is already loaded and
    // avoid doing any disk IO.
    void* dl = dlopen(file.value().c_str(), RTLD_NOW | RTLD_NOLOAD);
    setNetworkForSocket =
        reinterpret_cast<SetNetworkForSocket>(dlsym(dl, "setNetworkForSocket"));
  }
  if (!setNetworkForSocket)
    return ERR_NOT_IMPLEMENTED;
  int rv = setNetworkForSocket(network, socket_);
  // If |network| has since disconnected, |rv| will be ENONET.  Surface this as
  // ERR_NETWORK_CHANGED, rather than MapSystemError(ENONET) which gives back
  // the less descriptive ERR_FAILED.
  if (rv == ENONET)
    return ERR_NETWORK_CHANGED;
  if (rv == 0)
    bound_network_ = network;
  return MapSystemError(rv);
#else
  NOTIMPLEMENTED();
  return ERR_NOT_IMPLEMENTED;
#endif
}

int UDPSocketPosix::SetReceiveBufferSize(int32_t size) {
  DCHECK_NE(socket_, kInvalidSocket);
  DCHECK(CalledOnValidThread());
  int rv = setsockopt(socket_, SOL_SOCKET, SO_RCVBUF,
                      reinterpret_cast<const char*>(&size), sizeof(size));
  return rv == 0 ? OK : MapSystemError(errno);
}

int UDPSocketPosix::SetSendBufferSize(int32_t size) {
  DCHECK_NE(socket_, kInvalidSocket);
  DCHECK(CalledOnValidThread());
  int rv = setsockopt(socket_, SOL_SOCKET, SO_SNDBUF,
                      reinterpret_cast<const char*>(&size), sizeof(size));
  return rv == 0 ? OK : MapSystemError(errno);
}

int UDPSocketPosix::AllowAddressReuse() {
  DCHECK_NE(socket_, kInvalidSocket);
  DCHECK(CalledOnValidThread());
  DCHECK(!is_connected());
  int true_value = 1;
  int rv = setsockopt(
      socket_, SOL_SOCKET, SO_REUSEADDR, &true_value, sizeof(true_value));
  return rv == 0 ? OK : MapSystemError(errno);
}

int UDPSocketPosix::SetBroadcast(bool broadcast) {
  DCHECK_NE(socket_, kInvalidSocket);
  DCHECK(CalledOnValidThread());
  int value = broadcast ? 1 : 0;
  int rv;
#if defined(OS_MACOSX)
  // SO_REUSEPORT on OSX permits multiple processes to each receive
  // UDP multicast or broadcast datagrams destined for the bound
  // port.
  rv = setsockopt(socket_, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value));
#else
  rv = setsockopt(socket_, SOL_SOCKET, SO_BROADCAST, &value, sizeof(value));
#endif  // defined(OS_MACOSX)
  return rv == 0 ? OK : MapSystemError(errno);
}

void UDPSocketPosix::ReadWatcher::OnFileCanReadWithoutBlocking(int) {
  TRACE_EVENT0("net",
               "UDPSocketPosix::ReadWatcher::OnFileCanReadWithoutBlocking");
  if (!socket_->read_callback_.is_null())
    socket_->DidCompleteRead();
}

void UDPSocketPosix::WriteWatcher::OnFileCanWriteWithoutBlocking(int) {
  if (!socket_->write_callback_.is_null())
    socket_->DidCompleteWrite();
}

void UDPSocketPosix::DoReadCallback(int rv) {
  DCHECK_NE(rv, ERR_IO_PENDING);
  DCHECK(!read_callback_.is_null());

  // since Run may result in Read being called, clear read_callback_ up front.
  CompletionCallback c = read_callback_;
  read_callback_.Reset();
  c.Run(rv);
}

void UDPSocketPosix::DoWriteCallback(int rv) {
  DCHECK_NE(rv, ERR_IO_PENDING);
  DCHECK(!write_callback_.is_null());

  // since Run may result in Write being called, clear write_callback_ up front.
  CompletionCallback c = write_callback_;
  write_callback_.Reset();
  c.Run(rv);
}

void UDPSocketPosix::DidCompleteRead() {
  int result =
      InternalRecvFrom(read_buf_.get(), read_buf_len_, recv_from_address_);
  if (result != ERR_IO_PENDING) {
    read_buf_ = NULL;
    read_buf_len_ = 0;
    recv_from_address_ = NULL;
    bool ok = read_socket_watcher_.StopWatchingFileDescriptor();
    DCHECK(ok);
    DoReadCallback(result);
  }
}

void UDPSocketPosix::LogRead(int result,
                             const char* bytes,
                             socklen_t addr_len,
                             const sockaddr* addr) const {
  if (result < 0) {
    net_log_.AddEventWithNetErrorCode(NetLog::TYPE_UDP_RECEIVE_ERROR, result);
    return;
  }

  if (net_log_.IsCapturing()) {
    DCHECK(addr_len > 0);
    DCHECK(addr);

    IPEndPoint address;
    bool is_address_valid = address.FromSockAddr(addr, addr_len);
    net_log_.AddEvent(
        NetLog::TYPE_UDP_BYTES_RECEIVED,
        CreateNetLogUDPDataTranferCallback(
            result, bytes,
            is_address_valid ? &address : NULL));
  }

  NetworkActivityMonitor::GetInstance()->IncrementBytesReceived(result);
}

void UDPSocketPosix::DidCompleteWrite() {
  int result =
      InternalSendTo(write_buf_.get(), write_buf_len_, send_to_address_.get());

  if (result != ERR_IO_PENDING) {
    write_buf_ = NULL;
    write_buf_len_ = 0;
    send_to_address_.reset();
    write_socket_watcher_.StopWatchingFileDescriptor();
    DoWriteCallback(result);
  }
}

void UDPSocketPosix::LogWrite(int result,
                              const char* bytes,
                              const IPEndPoint* address) const {
  if (result < 0) {
    net_log_.AddEventWithNetErrorCode(NetLog::TYPE_UDP_SEND_ERROR, result);
    return;
  }

  if (net_log_.IsCapturing()) {
    net_log_.AddEvent(
        NetLog::TYPE_UDP_BYTES_SENT,
        CreateNetLogUDPDataTranferCallback(result, bytes, address));
  }

  NetworkActivityMonitor::GetInstance()->IncrementBytesSent(result);
}

int UDPSocketPosix::InternalRecvFrom(IOBuffer* buf,
                                     int buf_len,
                                     IPEndPoint* address) {
  int bytes_transferred;
  int flags = 0;

  SockaddrStorage storage;

  bytes_transferred =
      HANDLE_EINTR(recvfrom(socket_,
                            buf->data(),
                            buf_len,
                            flags,
                            storage.addr,
                            &storage.addr_len));
  int result;
  if (bytes_transferred >= 0) {
    result = bytes_transferred;
    if (address && !address->FromSockAddr(storage.addr, storage.addr_len))
      result = ERR_ADDRESS_INVALID;
  } else {
    result = MapSystemError(errno);
  }
  if (result != ERR_IO_PENDING)
    LogRead(result, buf->data(), storage.addr_len, storage.addr);
  return result;
}

int UDPSocketPosix::InternalSendTo(IOBuffer* buf,
                                   int buf_len,
                                   const IPEndPoint* address) {
  SockaddrStorage storage;
  struct sockaddr* addr = storage.addr;
  if (!address) {
    addr = NULL;
    storage.addr_len = 0;
  } else {
    if (!address->ToSockAddr(storage.addr, &storage.addr_len)) {
      int result = ERR_ADDRESS_INVALID;
      LogWrite(result, NULL, NULL);
      return result;
    }
  }

  int result = HANDLE_EINTR(sendto(socket_,
                            buf->data(),
                            buf_len,
                            0,
                            addr,
                            storage.addr_len));
  if (result < 0)
    result = MapSystemError(errno);
  if (result != ERR_IO_PENDING)
    LogWrite(result, buf->data(), address);
  return result;
}

int UDPSocketPosix::SetMulticastOptions() {
  if (!(socket_options_ & SOCKET_OPTION_MULTICAST_LOOP)) {
    int rv;
    if (addr_family_ == AF_INET) {
      u_char loop = 0;
      rv = setsockopt(socket_, IPPROTO_IP, IP_MULTICAST_LOOP,
                      &loop, sizeof(loop));
    } else {
      u_int loop = 0;
      rv = setsockopt(socket_, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                      &loop, sizeof(loop));
    }
    if (rv < 0)
      return MapSystemError(errno);
  }
  if (multicast_time_to_live_ != IP_DEFAULT_MULTICAST_TTL) {
    int rv;
    if (addr_family_ == AF_INET) {
      u_char ttl = multicast_time_to_live_;
      rv = setsockopt(socket_, IPPROTO_IP, IP_MULTICAST_TTL,
                      &ttl, sizeof(ttl));
    } else {
      // Signed integer. -1 to use route default.
      int ttl = multicast_time_to_live_;
      rv = setsockopt(socket_, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                      &ttl, sizeof(ttl));
    }
    if (rv < 0)
      return MapSystemError(errno);
  }
  if (multicast_interface_ != 0) {
    switch (addr_family_) {
      case AF_INET: {
#if !defined(OS_MACOSX)
        ip_mreqn mreq;
        mreq.imr_ifindex = multicast_interface_;
        mreq.imr_address.s_addr = htonl(INADDR_ANY);
#else
        ip_mreq mreq;
        int error = GetIPv4AddressFromIndex(socket_, multicast_interface_,
                                            &mreq.imr_interface.s_addr);
        if (error != OK)
          return error;
#endif
        int rv = setsockopt(socket_, IPPROTO_IP, IP_MULTICAST_IF,
                            reinterpret_cast<const char*>(&mreq), sizeof(mreq));
        if (rv)
          return MapSystemError(errno);
        break;
      }
      case AF_INET6: {
        uint32_t interface_index = multicast_interface_;
        int rv = setsockopt(socket_, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                            reinterpret_cast<const char*>(&interface_index),
                            sizeof(interface_index));
        if (rv)
          return MapSystemError(errno);
        break;
      }
      default:
        NOTREACHED() << "Invalid address family";
        return ERR_ADDRESS_INVALID;
    }
  }
  return OK;
}

int UDPSocketPosix::DoBind(const IPEndPoint& address) {
  SockaddrStorage storage;
  if (!address.ToSockAddr(storage.addr, &storage.addr_len))
    return ERR_ADDRESS_INVALID;
  int rv = bind(socket_, storage.addr, storage.addr_len);
  if (rv == 0)
    return OK;
  int last_error = errno;
  UMA_HISTOGRAM_SPARSE_SLOWLY("Net.UdpSocketBindErrorFromPosix", last_error);
#if defined(OS_CHROMEOS)
  if (last_error == EINVAL)
    return ERR_ADDRESS_IN_USE;
#elif defined(OS_MACOSX)
  if (last_error == EADDRNOTAVAIL)
    return ERR_ADDRESS_IN_USE;
#endif
  return MapSystemError(last_error);
}

int UDPSocketPosix::RandomBind(const IPAddress& address) {
  DCHECK(bind_type_ == DatagramSocket::RANDOM_BIND && !rand_int_cb_.is_null());

  for (int i = 0; i < kBindRetries; ++i) {
    int rv = DoBind(IPEndPoint(address,
                               rand_int_cb_.Run(kPortStart, kPortEnd)));
    if (rv == OK || rv != ERR_ADDRESS_IN_USE)
      return rv;
  }
  return DoBind(IPEndPoint(address, 0));
}

int UDPSocketPosix::JoinGroup(const IPAddress& group_address) const {
  DCHECK(CalledOnValidThread());
  if (!is_connected())
    return ERR_SOCKET_NOT_CONNECTED;

  switch (group_address.size()) {
    case IPAddress::kIPv4AddressSize: {
      if (addr_family_ != AF_INET)
        return ERR_ADDRESS_INVALID;

#if !defined(OS_MACOSX)
      ip_mreqn mreq;
      mreq.imr_ifindex = multicast_interface_;
      mreq.imr_address.s_addr = htonl(INADDR_ANY);
#else
      ip_mreq mreq;
      int error = GetIPv4AddressFromIndex(socket_, multicast_interface_,
                                          &mreq.imr_interface.s_addr);
      if (error != OK)
        return error;
#endif
      memcpy(&mreq.imr_multiaddr, group_address.bytes().data(),
             IPAddress::kIPv4AddressSize);
      int rv = setsockopt(socket_, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                          &mreq, sizeof(mreq));
      if (rv < 0)
        return MapSystemError(errno);
      return OK;
    }
    case IPAddress::kIPv6AddressSize: {
      if (addr_family_ != AF_INET6)
        return ERR_ADDRESS_INVALID;
      ipv6_mreq mreq;
      mreq.ipv6mr_interface = multicast_interface_;
      memcpy(&mreq.ipv6mr_multiaddr, group_address.bytes().data(),
             IPAddress::kIPv6AddressSize);
      int rv = setsockopt(socket_, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                          &mreq, sizeof(mreq));
      if (rv < 0)
        return MapSystemError(errno);
      return OK;
    }
    default:
      NOTREACHED() << "Invalid address family";
      return ERR_ADDRESS_INVALID;
  }
}

int UDPSocketPosix::LeaveGroup(const IPAddress& group_address) const {
  DCHECK(CalledOnValidThread());

  if (!is_connected())
    return ERR_SOCKET_NOT_CONNECTED;

  switch (group_address.size()) {
    case IPAddress::kIPv4AddressSize: {
      if (addr_family_ != AF_INET)
        return ERR_ADDRESS_INVALID;
      ip_mreq mreq;
      mreq.imr_interface.s_addr = INADDR_ANY;
      memcpy(&mreq.imr_multiaddr, group_address.bytes().data(),
             IPAddress::kIPv4AddressSize);
      int rv = setsockopt(socket_, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                          &mreq, sizeof(mreq));
      if (rv < 0)
        return MapSystemError(errno);
      return OK;
    }
    case IPAddress::kIPv6AddressSize: {
      if (addr_family_ != AF_INET6)
        return ERR_ADDRESS_INVALID;
      ipv6_mreq mreq;
      mreq.ipv6mr_interface = 0;  // 0 indicates default multicast interface.
      memcpy(&mreq.ipv6mr_multiaddr, group_address.bytes().data(),
             IPAddress::kIPv6AddressSize);
      int rv = setsockopt(socket_, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
                          &mreq, sizeof(mreq));
      if (rv < 0)
        return MapSystemError(errno);
      return OK;
    }
    default:
      NOTREACHED() << "Invalid address family";
      return ERR_ADDRESS_INVALID;
  }
}

int UDPSocketPosix::SetMulticastInterface(uint32_t interface_index) {
  DCHECK(CalledOnValidThread());
  if (is_connected())
    return ERR_SOCKET_IS_CONNECTED;
  multicast_interface_ = interface_index;
  return OK;
}

int UDPSocketPosix::SetMulticastTimeToLive(int time_to_live) {
  DCHECK(CalledOnValidThread());
  if (is_connected())
    return ERR_SOCKET_IS_CONNECTED;

  if (time_to_live < 0 || time_to_live > 255)
    return ERR_INVALID_ARGUMENT;
  multicast_time_to_live_ = time_to_live;
  return OK;
}

int UDPSocketPosix::SetMulticastLoopbackMode(bool loopback) {
  DCHECK(CalledOnValidThread());
  if (is_connected())
    return ERR_SOCKET_IS_CONNECTED;

  if (loopback)
    socket_options_ |= SOCKET_OPTION_MULTICAST_LOOP;
  else
    socket_options_ &= ~SOCKET_OPTION_MULTICAST_LOOP;
  return OK;
}

int UDPSocketPosix::SetDiffServCodePoint(DiffServCodePoint dscp) {
  if (dscp == DSCP_NO_CHANGE) {
    return OK;
  }
  int rv;
  int dscp_and_ecn = dscp << 2;
  if (addr_family_ == AF_INET) {
    rv = setsockopt(socket_, IPPROTO_IP, IP_TOS,
                    &dscp_and_ecn, sizeof(dscp_and_ecn));
  } else {
    rv = setsockopt(socket_, IPPROTO_IPV6, IPV6_TCLASS,
                    &dscp_and_ecn, sizeof(dscp_and_ecn));
  }
  if (rv < 0)
    return MapSystemError(errno);

  return OK;
}

void UDPSocketPosix::DetachFromThread() {
  base::NonThreadSafe::DetachFromThread();
}

}  // namespace net
