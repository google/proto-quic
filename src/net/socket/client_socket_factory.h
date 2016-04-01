// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SOCKET_CLIENT_SOCKET_FACTORY_H_
#define NET_SOCKET_CLIENT_SOCKET_FACTORY_H_

#include <string>

#include "base/memory/scoped_ptr.h"
#include "net/base/net_export.h"
#include "net/base/rand_callback.h"
#include "net/log/net_log.h"
#include "net/udp/datagram_socket.h"

namespace net {

class AddressList;
class ClientSocketHandle;
class DatagramClientSocket;
class HostPortPair;
class SSLClientSocket;
struct SSLClientSocketContext;
struct SSLConfig;
class StreamSocket;

// An interface used to instantiate StreamSocket objects.  Used to facilitate
// testing code with mock socket implementations.
class NET_EXPORT ClientSocketFactory {
 public:
  virtual ~ClientSocketFactory() {}

  // |source| is the NetLog::Source for the entity trying to create the socket,
  // if it has one.
  virtual scoped_ptr<DatagramClientSocket> CreateDatagramClientSocket(
      DatagramSocket::BindType bind_type,
      const RandIntCallback& rand_int_cb,
      NetLog* net_log,
      const NetLog::Source& source) = 0;

  virtual scoped_ptr<StreamSocket> CreateTransportClientSocket(
      const AddressList& addresses,
      NetLog* net_log,
      const NetLog::Source& source) = 0;

  // It is allowed to pass in a |transport_socket| that is not obtained from a
  // socket pool. The caller could create a ClientSocketHandle directly and call
  // set_socket() on it to set a valid StreamSocket instance.
  virtual scoped_ptr<SSLClientSocket> CreateSSLClientSocket(
      scoped_ptr<ClientSocketHandle> transport_socket,
      const HostPortPair& host_and_port,
      const SSLConfig& ssl_config,
      const SSLClientSocketContext& context) = 0;

  // Clears cache used for SSL session resumption.
  virtual void ClearSSLSessionCache() = 0;

  // Returns the default ClientSocketFactory.
  static ClientSocketFactory* GetDefaultFactory();
};

}  // namespace net

#endif  // NET_SOCKET_CLIENT_SOCKET_FACTORY_H_
