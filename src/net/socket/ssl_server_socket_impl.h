// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SOCKET_SSL_SERVER_SOCKET_IMPL_H_
#define NET_SOCKET_SSL_SERVER_SOCKET_IMPL_H_

#include <stdint.h>

#include <memory>

#include "base/macros.h"
#include "net/base/completion_callback.h"
#include "net/base/io_buffer.h"
#include "net/log/net_log.h"
#include "net/socket/ssl_server_socket.h"
#include "net/ssl/scoped_openssl_types.h"
#include "net/ssl/ssl_server_config.h"

// Avoid including misc OpenSSL headers, i.e.:
// <openssl/bio.h>
typedef struct bio_st BIO;
// <openssl/ssl.h>
typedef struct ssl_st SSL;
typedef struct x509_store_ctx_st X509_STORE_CTX;

namespace net {

class SSLInfo;

class SSLServerContextImpl : public SSLServerContext {
 public:
  SSLServerContextImpl(X509Certificate* certificate,
                       const crypto::RSAPrivateKey& key,
                       const SSLServerConfig& ssl_server_config);
  ~SSLServerContextImpl() override;

  std::unique_ptr<SSLServerSocket> CreateSSLServerSocket(
      std::unique_ptr<StreamSocket> socket) override;

 private:
  ScopedSSL_CTX ssl_ctx_;

  // Options for the SSL socket.
  SSLServerConfig ssl_server_config_;

  // Certificate for the server.
  scoped_refptr<X509Certificate> cert_;

  // Private key used by the server.
  std::unique_ptr<crypto::RSAPrivateKey> key_;
};

}  // namespace net

#endif  // NET_SOCKET_SSL_SERVER_SOCKET_IMPL_H_
