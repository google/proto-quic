// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/tcp_socket.h"

#include "build/build_config.h"

#if defined(OS_POSIX)
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#elif defined(OS_WIN)
#include <winsock2.h>
#endif

namespace net {

bool SetTCPNoDelay(SocketDescriptor socket, bool no_delay) {
#if defined(OS_POSIX)
  int on = no_delay ? 1 : 0;
#elif defined(OS_WIN)
  BOOL on = no_delay ? TRUE : FALSE;
#endif
  return setsockopt(socket, IPPROTO_TCP, TCP_NODELAY,
                    reinterpret_cast<const char*>(&on), sizeof(on)) == 0;
}

}  // namespace net
