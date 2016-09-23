// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// NOTE: This class is provided to support existing Chromium consumers; it is
// NOT intended for use in NEW code. Configuring a TLS server correctly is a
// security-sensitive activity with many subtle nuances, and thus care should be
// taken to discuss with //net/OWNERS before any new usages.
//
// As such, this header should be treated as an internal implementation detail
// of //net (where it's used for some unit test infrastructure), not as
// appropriate for general use.
//
// See https://crbug.com/621176 for more details.

#ifndef NET_SOCKET_SSL_SERVER_SOCKET_H_
#define NET_SOCKET_SSL_SERVER_SOCKET_H_

#include <memory>

#include "net/base/completion_callback.h"
#include "net/base/net_export.h"
#include "net/socket/ssl_socket.h"
#include "net/socket/stream_socket.h"

namespace crypto {
class RSAPrivateKey;
}  // namespace crypto

namespace net {

struct SSLServerConfig;
class X509Certificate;

class SSLServerSocket : public SSLSocket {
 public:
  ~SSLServerSocket() override {}

  // Perform the SSL server handshake, and notify the supplied callback
  // if the process completes asynchronously.  If Disconnect is called before
  // completion then the callback will be silently, as for other StreamSocket
  // calls.
  virtual int Handshake(const CompletionCallback& callback) = 0;
};

class SSLServerContext {
 public:
  virtual ~SSLServerContext(){};

  // Creates an SSL server socket over an already-connected transport socket.
  // The caller must ensure the returned socket does not outlive the server
  // context.
  //
  // The caller starts the SSL server handshake by calling Handshake on the
  // returned socket.
  virtual std::unique_ptr<SSLServerSocket> CreateSSLServerSocket(
      std::unique_ptr<StreamSocket> socket) = 0;
};

// Configures the underlying SSL library for the use of SSL server sockets.
//
// Due to the requirements of the underlying libraries, this should be called
// early in process initialization, before any SSL socket, client or server,
// has been used.
//
// Note: If a process does not use SSL server sockets, this call may be
// omitted.
NET_EXPORT void EnableSSLServerSockets();

// Creates an SSL server socket context where all sockets spawned using this
// context will share the same session cache.
//
// The caller must provide the server certificate and private key to use.
// It takes a reference to |certificate|.
// The |key| and |ssl_config| parameters are copied.
//
NET_EXPORT std::unique_ptr<SSLServerContext> CreateSSLServerContext(
    X509Certificate* certificate,
    const crypto::RSAPrivateKey& key,
    const SSLServerConfig& ssl_config);

}  // namespace net

#endif  // NET_SOCKET_SSL_SERVER_SOCKET_H_
