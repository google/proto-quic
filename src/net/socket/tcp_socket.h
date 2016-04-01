// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SOCKET_TCP_SOCKET_H_
#define NET_SOCKET_TCP_SOCKET_H_

#include "build/build_config.h"
#include "net/base/net_export.h"
#include "net/socket/socket_descriptor.h"

#if defined(OS_WIN)
#include "net/socket/tcp_socket_win.h"
#elif defined(OS_POSIX)
#include "net/socket/tcp_socket_posix.h"
#endif

namespace net {

// TCPSocket provides a platform-independent interface for TCP sockets.
//
// It is recommended to use TCPClientSocket/TCPServerSocket instead of this
// class, unless a clear separation of client and server socket functionality is
// not suitable for your use case (e.g., a socket needs to be created and bound
// before you know whether it is a client or server socket).
#if defined(OS_WIN)
typedef TCPSocketWin TCPSocket;
#elif defined(OS_POSIX)
typedef TCPSocketPosix TCPSocket;
#endif

// Check if TCP FastOpen is supported by the OS.
bool IsTCPFastOpenSupported();

// Check if TCP FastOpen is enabled by the user.
bool IsTCPFastOpenUserEnabled();

// Checks if TCP FastOpen is supported by the kernel. Also enables TFO for all
// connections if indicated by user.
// Not thread safe.  Must be called during initialization/startup only.
NET_EXPORT void CheckSupportAndMaybeEnableTCPFastOpen(bool user_enabled);

// This function enables/disables buffering in the kernel. By default, on Linux,
// TCP sockets will wait up to 200ms for more data to complete a packet before
// transmitting. After calling this function, the kernel will not wait. See
// TCP_NODELAY in `man 7 tcp`.
//
// For Windows:
//
// The Nagle implementation on Windows is governed by RFC 896.  The idea
// behind Nagle is to reduce small packets on the network.  When Nagle is
// enabled, if a partial packet has been sent, the TCP stack will disallow
// further *partial* packets until an ACK has been received from the other
// side.  Good applications should always strive to send as much data as
// possible and avoid partial-packet sends.  However, in most real world
// applications, there are edge cases where this does not happen, and two
// partial packets may be sent back to back.  For a browser, it is NEVER
// a benefit to delay for an RTT before the second packet is sent.
//
// As a practical example in Chromium today, consider the case of a small
// POST.  I have verified this:
//     Client writes 649 bytes of header  (partial packet #1)
//     Client writes 50 bytes of POST data (partial packet #2)
// In the above example, with Nagle, a RTT delay is inserted between these
// two sends due to nagle.  RTTs can easily be 100ms or more.  The best
// fix is to make sure that for POSTing data, we write as much data as
// possible and minimize partial packets.  We will fix that.  But disabling
// Nagle also ensure we don't run into this delay in other edge cases.
// See also:
//    http://technet.microsoft.com/en-us/library/bb726981.aspx
//
// This function returns true if it succeeds to set the TCP_NODELAY option,
// otherwise returns false.
NET_EXPORT_PRIVATE bool SetTCPNoDelay(SocketDescriptor socket, bool no_delay);

}  // namespace net

#endif  // NET_SOCKET_TCP_SOCKET_H_
