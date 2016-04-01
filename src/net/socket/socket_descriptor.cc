// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/socket_descriptor.h"

#if defined(OS_POSIX)
#include <sys/types.h>
#include <sys/socket.h>
#endif

#if defined(OS_WIN)
#include <ws2tcpip.h>
#include "base/win/windows_version.h"
#include "net/base/winsock_init.h"
#endif

namespace net {

SocketDescriptor CreatePlatformSocket(int family, int type, int protocol) {
#if defined(OS_WIN)
  EnsureWinsockInit();
  SocketDescriptor result = ::WSASocket(family, type, protocol, nullptr, 0,
                                        WSA_FLAG_OVERLAPPED);
  if (result != kInvalidSocket && family == AF_INET6 &&
      base::win::OSInfo::GetInstance()->version() >= base::win::VERSION_VISTA) {
    DWORD value = 0;
    if (setsockopt(result, IPPROTO_IPV6, IPV6_V6ONLY,
                   reinterpret_cast<const char*>(&value), sizeof(value))) {
      closesocket(result);
      return kInvalidSocket;
    }
  }
  return result;
#else  // OS_WIN
  return ::socket(family, type, protocol);
#endif  // OS_WIN

}

}  // namespace net
