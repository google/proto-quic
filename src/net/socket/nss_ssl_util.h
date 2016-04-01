// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is only included in ssl_client_socket_nss.cc and
// ssl_server_socket_nss.cc to share common functions of NSS.

#ifndef NET_SOCKET_NSS_SSL_UTIL_H_
#define NET_SOCKET_NSS_SSL_UTIL_H_

#include <prerror.h>
#include <prio.h>

#include "net/base/net_export.h"
#include "net/log/net_log.h"

namespace net {

class BoundNetLog;

// Initalize NSS SSL library.
NET_EXPORT void EnsureNSSSSLInit();

// Log a failed NSS funcion call.
void LogFailedNSSFunction(const BoundNetLog& net_log,
                          const char* function,
                          const char* param);

// Map network error code to NSS error code.
PRErrorCode MapErrorToNSS(int result);

// GetNSSModelSocket returns either NULL, or an NSS socket that can be passed
// to |SSL_ImportFD| in order to inherit some default options.
PRFileDesc* GetNSSModelSocket();

// Map NSS error code to network error code.
int MapNSSError(PRErrorCode err);

// Creates a NetLog callback for an SSL error.
NetLog::ParametersCallback CreateNetLogSSLErrorCallback(int net_error,
                                                        int ssl_lib_error);


}  // namespace net

#endif  // NET_SOCKET_NSS_SSL_UTIL_H_
