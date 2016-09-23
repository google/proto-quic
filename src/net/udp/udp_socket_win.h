// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_UDP_UDP_SOCKET_WIN_H_
#define NET_UDP_UDP_SOCKET_WIN_H_

#include <qos2.h>
#include <stdint.h>
#include <winsock2.h>

#include <memory>

#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/threading/non_thread_safe.h"
#include "base/win/object_watcher.h"
#include "base/win/scoped_handle.h"
#include "net/base/address_family.h"
#include "net/base/completion_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_export.h"
#include "net/base/network_change_notifier.h"
#include "net/base/rand_callback.h"
#include "net/log/net_log.h"
#include "net/udp/datagram_socket.h"
#include "net/udp/diff_serv_code_point.h"

namespace net {

class IPAddress;

class NET_EXPORT UDPSocketWin
    : NON_EXPORTED_BASE(public base::NonThreadSafe),
      NON_EXPORTED_BASE(public base::win::ObjectWatcher::Delegate) {
 public:
  UDPSocketWin(DatagramSocket::BindType bind_type,
               const RandIntCallback& rand_int_cb,
               net::NetLog* net_log,
               const net::NetLog::Source& source);
  ~UDPSocketWin() override;

  // Opens the socket.
  // Returns a net error code.
  int Open(AddressFamily address_family);

  // Binds this socket to |network|. All data traffic on the socket will be sent
  // and received via |network|. Must be called before Connect(). This call will
  // fail if |network| has disconnected. Communication using this socket will
  // fail if |network| disconnects.
  // Returns a net error code.
  int BindToNetwork(NetworkChangeNotifier::NetworkHandle network);

  // Connects the socket to connect with a certain |address|.
  // Should be called after Open().
  // Returns a net error code.
  int Connect(const IPEndPoint& address);

  // Binds the address/port for this socket to |address|.  This is generally
  // only used on a server. Should be called after Open().
  // Returns a net error code.
  int Bind(const IPEndPoint& address);

  // Closes the socket.
  // TODO(rvargas, hidehiko): Disallow re-Open() after Close().
  void Close();

  // Copies the remote udp address into |address| and returns a net error code.
  int GetPeerAddress(IPEndPoint* address) const;

  // Copies the local udp address into |address| and returns a net error code.
  // (similar to getsockname)
  int GetLocalAddress(IPEndPoint* address) const;

  // IO:
  // Multiple outstanding read requests are not supported.
  // Full duplex mode (reading and writing at the same time) is supported

  // Reads from the socket.
  // Only usable from the client-side of a UDP socket, after the socket
  // has been connected.
  int Read(IOBuffer* buf, int buf_len, const CompletionCallback& callback);

  // Writes to the socket.
  // Only usable from the client-side of a UDP socket, after the socket
  // has been connected.
  int Write(IOBuffer* buf, int buf_len, const CompletionCallback& callback);

  // Reads from a socket and receive sender address information.
  // |buf| is the buffer to read data into.
  // |buf_len| is the maximum amount of data to read.
  // |address| is a buffer provided by the caller for receiving the sender
  //   address information about the received data.  This buffer must be kept
  //   alive by the caller until the callback is placed.
  // |callback| is the callback on completion of the RecvFrom.
  // Returns a net error code, or ERR_IO_PENDING if the IO is in progress.
  // If ERR_IO_PENDING is returned, the caller must keep |buf| and |address|,
  // alive until the callback is called.
  int RecvFrom(IOBuffer* buf,
               int buf_len,
               IPEndPoint* address,
               const CompletionCallback& callback);

  // Sends to a socket with a particular destination.
  // |buf| is the buffer to send.
  // |buf_len| is the number of bytes to send.
  // |address| is the recipient address.
  // |callback| is the user callback function to call on complete.
  // Returns a net error code, or ERR_IO_PENDING if the IO is in progress.
  // If ERR_IO_PENDING is returned, the caller must keep |buf| and |address|
  // alive until the callback is called.
  int SendTo(IOBuffer* buf,
             int buf_len,
             const IPEndPoint& address,
             const CompletionCallback& callback);

  // Sets the receive buffer size (in bytes) for the socket.
  // Returns a net error code.
  int SetReceiveBufferSize(int32_t size);

  // Sets the send buffer size (in bytes) for the socket.
  // Returns a net error code.
  int SetSendBufferSize(int32_t size);

  // Requests that packets sent by this socket not be fragment, either locally
  // by the host, or by routers (via the DF bit in the IPv4 packet header).
  // May not be supported by all platforms. Returns a return a network error
  // code if there was a problem, but the socket will still be usable. Can not
  // return ERR_IO_PENDING.
  int SetDoNotFragment();

  // Returns true if the socket is already connected or bound.
  bool is_connected() const { return is_connected_; }

  const NetLogWithSource& NetLog() const { return net_log_; }

  // Sets corresponding flags in |socket_options_| to allow the socket
  // to share the local address to which the socket will be bound with
  // other processes. Should be called between Open() and Bind().
  // Returns a net error code.
  int AllowAddressReuse();

  // Sets corresponding flags in |socket_options_| to allow sending
  // and receiving packets to and from broadcast addresses.
  int SetBroadcast(bool broadcast);

  // Joins the multicast group.
  // |group_address| is the group address to join, could be either
  // an IPv4 or IPv6 address.
  // Returns a net error code.
  int JoinGroup(const IPAddress& group_address) const;

  // Leaves the multicast group.
  // |group_address| is the group address to leave, could be either
  // an IPv4 or IPv6 address. If the socket hasn't joined the group,
  // it will be ignored.
  // It's optional to leave the multicast group before destroying
  // the socket. It will be done by the OS.
  // Return a net error code.
  int LeaveGroup(const IPAddress& group_address) const;

  // Sets interface to use for multicast. If |interface_index| set to 0,
  // default interface is used.
  // Should be called before Bind().
  // Returns a net error code.
  int SetMulticastInterface(uint32_t interface_index);

  // Sets the time-to-live option for UDP packets sent to the multicast
  // group address. The default value of this option is 1.
  // Cannot be negative or more than 255.
  // Should be called before Bind().
  int SetMulticastTimeToLive(int time_to_live);

  // Sets the loopback flag for UDP socket. If this flag is true, the host
  // will receive packets sent to the joined group from itself.
  // The default value of this option is true.
  // Should be called before Bind().
  //
  // Note: the behavior of |SetMulticastLoopbackMode| is slightly
  // different between Windows and Unix-like systems. The inconsistency only
  // happens when there are more than one applications on the same host
  // joined to the same multicast group while having different settings on
  // multicast loopback mode. On Windows, the applications with loopback off
  // will not RECEIVE the loopback packets; while on Unix-like systems, the
  // applications with loopback off will not SEND the loopback packets to
  // other applications on the same host. See MSDN: http://goo.gl/6vqbj
  int SetMulticastLoopbackMode(bool loopback);

  // Sets the differentiated services flags on outgoing packets. May not
  // do anything on some platforms.
  int SetDiffServCodePoint(DiffServCodePoint dscp);

  // Resets the thread to be used for thread-safety checks.
  void DetachFromThread();

  // This class by default uses overlapped IO. Call this method before Open()
  // to switch to non-blocking IO.
  void UseNonBlockingIO();

 private:
  enum SocketOptions {
    SOCKET_OPTION_MULTICAST_LOOP = 1 << 0
  };

  class Core;

  void DoReadCallback(int rv);
  void DoWriteCallback(int rv);

  void DidCompleteRead();
  void DidCompleteWrite();

  // base::ObjectWatcher::Delegate implementation.
  void OnObjectSignaled(HANDLE object) override;
  void OnReadSignaled();
  void OnWriteSignaled();

  void WatchForReadWrite();

  // Handles stats and logging. |result| is the number of bytes transferred, on
  // success, or the net error code on failure.
  void LogRead(int result, const char* bytes, const IPEndPoint* address) const;
  void LogWrite(int result, const char* bytes, const IPEndPoint* address) const;

  // Same as SendTo(), except that address is passed by pointer
  // instead of by reference. It is called from Write() with |address|
  // set to NULL.
  int SendToOrWrite(IOBuffer* buf,
                    int buf_len,
                    const IPEndPoint* address,
                    const CompletionCallback& callback);

  int InternalConnect(const IPEndPoint& address);

  // Version for using overlapped IO.
  int InternalRecvFromOverlapped(IOBuffer* buf,
                                 int buf_len,
                                 IPEndPoint* address);
  int InternalSendToOverlapped(IOBuffer* buf,
                               int buf_len,
                               const IPEndPoint* address);

  // Version for using non-blocking IO.
  int InternalRecvFromNonBlocking(IOBuffer* buf,
                                  int buf_len,
                                  IPEndPoint* address);
  int InternalSendToNonBlocking(IOBuffer* buf,
                                int buf_len,
                                const IPEndPoint* address);

  // Applies |socket_options_| to |socket_|. Should be called before
  // Bind().
  int SetMulticastOptions();
  int DoBind(const IPEndPoint& address);
  // Binds to a random port on |address|.
  int RandomBind(const IPAddress& address);

  SOCKET socket_;
  int addr_family_;
  bool is_connected_;

  // Bitwise-or'd combination of SocketOptions. Specifies the set of
  // options that should be applied to |socket_| before Bind().
  int socket_options_;

  // Multicast interface.
  uint32_t multicast_interface_;

  // Multicast socket options cached for SetMulticastOption.
  // Cannot be used after Bind().
  int multicast_time_to_live_;

  // How to do source port binding, used only when UDPSocket is part of
  // UDPClientSocket, since UDPServerSocket provides Bind.
  DatagramSocket::BindType bind_type_;

  // PRNG function for generating port numbers.
  RandIntCallback rand_int_cb_;

  // These are mutable since they're just cached copies to make
  // GetPeerAddress/GetLocalAddress smarter.
  mutable std::unique_ptr<IPEndPoint> local_address_;
  mutable std::unique_ptr<IPEndPoint> remote_address_;

  // The core of the socket that can live longer than the socket itself. We pass
  // resources to the Windows async IO functions and we have to make sure that
  // they are not destroyed while the OS still references them.
  scoped_refptr<Core> core_;

  // True if non-blocking IO is used.
  bool use_non_blocking_io_;

  // Watches |read_write_event_|.
  base::win::ObjectWatcher read_write_watcher_;

  // Events for read and write.
  base::win::ScopedHandle read_write_event_;

  // The buffers used in Read() and Write().
  scoped_refptr<IOBuffer> read_iobuffer_;
  scoped_refptr<IOBuffer> write_iobuffer_;

  int read_iobuffer_len_;
  int write_iobuffer_len_;

  IPEndPoint* recv_from_address_;

  // Cached copy of the current address we're sending to, if any.  Used for
  // logging.
  std::unique_ptr<IPEndPoint> send_to_address_;

  // External callback; called when read is complete.
  CompletionCallback read_callback_;

  // External callback; called when write is complete.
  CompletionCallback write_callback_;

  NetLogWithSource net_log_;

  // QWAVE data. Used to set DSCP bits on outgoing packets.
  HANDLE qos_handle_;
  QOS_FLOWID qos_flow_id_;

  DISALLOW_COPY_AND_ASSIGN(UDPSocketWin);
};

//-----------------------------------------------------------------------------

// QWAVE (Quality Windows Audio/Video Experience) is the latest windows
// library for setting packet priorities (and other things). Unfortunately,
// Microsoft has decided that setting the DSCP bits with setsockopt() no
// longer works, so we have to use this API instead.
// This class is meant to be used as a singleton. It exposes a few dynamically
// loaded functions and a bool called "qwave_supported".
class NET_EXPORT QwaveAPI {
  typedef BOOL (WINAPI *CreateHandleFn)(PQOS_VERSION, PHANDLE);
  typedef BOOL (WINAPI *CloseHandleFn)(HANDLE);
  typedef BOOL (WINAPI *AddSocketToFlowFn)(
      HANDLE, SOCKET, PSOCKADDR, QOS_TRAFFIC_TYPE, DWORD, PQOS_FLOWID);
  typedef BOOL (WINAPI *RemoveSocketFromFlowFn)(
      HANDLE, SOCKET, QOS_FLOWID, DWORD);
  typedef BOOL (WINAPI *SetFlowFn)(
      HANDLE, QOS_FLOWID, QOS_SET_FLOW, ULONG, PVOID, DWORD, LPOVERLAPPED);

 public:
  QwaveAPI();

  static QwaveAPI& Get();

  bool qwave_supported() const;
  BOOL CreateHandle(PQOS_VERSION version, PHANDLE handle);
  BOOL CloseHandle(HANDLE handle);
  BOOL AddSocketToFlow(HANDLE handle,
                       SOCKET socket,
                       PSOCKADDR addr,
                       QOS_TRAFFIC_TYPE traffic_type,
                       DWORD flags,
                       PQOS_FLOWID flow_id);
  BOOL RemoveSocketFromFlow(HANDLE handle,
                            SOCKET socket,
                            QOS_FLOWID flow_id,
                            DWORD reserved);
  BOOL SetFlow(HANDLE handle,
               QOS_FLOWID flow_id,
               QOS_SET_FLOW op,
               ULONG size,
               PVOID data,
               DWORD reserved,
               LPOVERLAPPED overlapped);

 private:
  bool qwave_supported_;
  CreateHandleFn create_handle_func_;
  CloseHandleFn close_handle_func_;
  AddSocketToFlowFn add_socket_to_flow_func_;
  RemoveSocketFromFlowFn remove_socket_from_flow_func_;
  SetFlowFn set_flow_func_;

  FRIEND_TEST_ALL_PREFIXES(UDPSocketTest, SetDSCPFake);
  DISALLOW_COPY_AND_ASSIGN(QwaveAPI);
};


}  // namespace net

#endif  // NET_UDP_UDP_SOCKET_WIN_H_
