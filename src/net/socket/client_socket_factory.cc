// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/client_socket_factory.h"

#include <utility>

#include "base/lazy_instance.h"
#include "build/build_config.h"
#include "net/cert/cert_database.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/tcp_client_socket.h"
#include "net/udp/udp_client_socket.h"

#if defined(USE_OPENSSL)
#include "net/socket/ssl_client_socket_openssl.h"
#else
#include "net/socket/ssl_client_socket_nss.h"
#endif

namespace net {

class X509Certificate;

namespace {

class DefaultClientSocketFactory : public ClientSocketFactory,
                                   public CertDatabase::Observer {
 public:
  DefaultClientSocketFactory() {
    CertDatabase::GetInstance()->AddObserver(this);
  }

  ~DefaultClientSocketFactory() override {
    // Note: This code never runs, as the factory is defined as a Leaky
    // singleton.
    CertDatabase::GetInstance()->RemoveObserver(this);
  }

  void OnCertAdded(const X509Certificate* cert) override {
    ClearSSLSessionCache();
  }

  void OnCACertChanged(const X509Certificate* cert) override {
    // Per wtc, we actually only need to flush when trust is reduced.
    // Always flush now because OnCACertChanged does not tell us this.
    // See comments in ClientSocketPoolManager::OnCACertChanged.
    ClearSSLSessionCache();
  }

  scoped_ptr<DatagramClientSocket> CreateDatagramClientSocket(
      DatagramSocket::BindType bind_type,
      const RandIntCallback& rand_int_cb,
      NetLog* net_log,
      const NetLog::Source& source) override {
    return scoped_ptr<DatagramClientSocket>(
        new UDPClientSocket(bind_type, rand_int_cb, net_log, source));
  }

  scoped_ptr<StreamSocket> CreateTransportClientSocket(
      const AddressList& addresses,
      NetLog* net_log,
      const NetLog::Source& source) override {
    return scoped_ptr<StreamSocket>(
        new TCPClientSocket(addresses, net_log, source));
  }

  scoped_ptr<SSLClientSocket> CreateSSLClientSocket(
      scoped_ptr<ClientSocketHandle> transport_socket,
      const HostPortPair& host_and_port,
      const SSLConfig& ssl_config,
      const SSLClientSocketContext& context) override {
#if defined(USE_OPENSSL)
    return scoped_ptr<SSLClientSocket>(new SSLClientSocketOpenSSL(
        std::move(transport_socket), host_and_port, ssl_config, context));
#else
    return scoped_ptr<SSLClientSocket>(new SSLClientSocketNSS(
        std::move(transport_socket), host_and_port, ssl_config, context));
#endif
  }

  void ClearSSLSessionCache() override { SSLClientSocket::ClearSessionCache(); }
};

static base::LazyInstance<DefaultClientSocketFactory>::Leaky
    g_default_client_socket_factory = LAZY_INSTANCE_INITIALIZER;

}  // namespace

// static
ClientSocketFactory* ClientSocketFactory::GetDefaultFactory() {
  return g_default_client_socket_factory.Pointer();
}

}  // namespace net
