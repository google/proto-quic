// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_socket_pool.h"

#include "base/logging.h"
#include "base/macros.h"
#include "base/rand_util.h"
#include "base/stl_util.h"
#include "net/base/address_list.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/rand_callback.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/stream_socket.h"
#include "net/udp/datagram_client_socket.h"

namespace net {

namespace {

// When we initialize the SocketPool, we allocate kInitialPoolSize sockets.
// When we allocate a socket, we ensure we have at least kAllocateMinSize
// sockets to choose from.  Freed sockets are not retained.

// On Windows, we can't request specific (random) ports, since that will
// trigger firewall prompts, so request default ones, but keep a pile of
// them.  Everywhere else, request fresh, random ports each time.
#if defined(OS_WIN)
const DatagramSocket::BindType kBindType = DatagramSocket::DEFAULT_BIND;
const unsigned kInitialPoolSize = 256;
const unsigned kAllocateMinSize = 256;
#else
const DatagramSocket::BindType kBindType = DatagramSocket::RANDOM_BIND;
const unsigned kInitialPoolSize = 0;
const unsigned kAllocateMinSize = 1;
#endif

} // namespace

DnsSocketPool::DnsSocketPool(ClientSocketFactory* socket_factory)
    : socket_factory_(socket_factory),
      net_log_(NULL),
      nameservers_(NULL),
      initialized_(false) {
}

void DnsSocketPool::InitializeInternal(
    const std::vector<IPEndPoint>* nameservers,
    NetLog* net_log) {
  DCHECK(nameservers);
  DCHECK(!initialized_);

  net_log_ = net_log;
  nameservers_ = nameservers;
  initialized_ = true;
}

scoped_ptr<StreamSocket> DnsSocketPool::CreateTCPSocket(
    unsigned server_index,
    const NetLog::Source& source) {
  DCHECK_LT(server_index, nameservers_->size());

  return scoped_ptr<StreamSocket>(
      socket_factory_->CreateTransportClientSocket(
          AddressList((*nameservers_)[server_index]), net_log_, source));
}

scoped_ptr<DatagramClientSocket> DnsSocketPool::CreateConnectedSocket(
    unsigned server_index) {
  DCHECK_LT(server_index, nameservers_->size());

  scoped_ptr<DatagramClientSocket> socket;

  NetLog::Source no_source;
  socket = socket_factory_->CreateDatagramClientSocket(
      kBindType, base::Bind(&base::RandInt), net_log_, no_source);

  if (socket.get()) {
    int rv = socket->Connect((*nameservers_)[server_index]);
    if (rv != OK) {
      VLOG(1) << "Failed to connect socket: " << rv;
      socket.reset();
    }
  } else {
    LOG(WARNING) << "Failed to create socket.";
  }

  return socket;
}

class NullDnsSocketPool : public DnsSocketPool {
 public:
  NullDnsSocketPool(ClientSocketFactory* factory)
     : DnsSocketPool(factory) {
  }

  void Initialize(const std::vector<IPEndPoint>* nameservers,
                  NetLog* net_log) override {
    InitializeInternal(nameservers, net_log);
  }

  scoped_ptr<DatagramClientSocket> AllocateSocket(
      unsigned server_index) override {
    return CreateConnectedSocket(server_index);
  }

  void FreeSocket(unsigned server_index,
                  scoped_ptr<DatagramClientSocket> socket) override {}

 private:
  DISALLOW_COPY_AND_ASSIGN(NullDnsSocketPool);
};

// static
scoped_ptr<DnsSocketPool> DnsSocketPool::CreateNull(
    ClientSocketFactory* factory) {
  return scoped_ptr<DnsSocketPool>(new NullDnsSocketPool(factory));
}

class DefaultDnsSocketPool : public DnsSocketPool {
 public:
  DefaultDnsSocketPool(ClientSocketFactory* factory)
     : DnsSocketPool(factory) {
  };

  ~DefaultDnsSocketPool() override;

  void Initialize(const std::vector<IPEndPoint>* nameservers,
                  NetLog* net_log) override;

  scoped_ptr<DatagramClientSocket> AllocateSocket(
      unsigned server_index) override;

  void FreeSocket(unsigned server_index,
                  scoped_ptr<DatagramClientSocket> socket) override;

 private:
  void FillPool(unsigned server_index, unsigned size);

  typedef std::vector<DatagramClientSocket*> SocketVector;

  std::vector<SocketVector> pools_;

  DISALLOW_COPY_AND_ASSIGN(DefaultDnsSocketPool);
};

// static
scoped_ptr<DnsSocketPool> DnsSocketPool::CreateDefault(
    ClientSocketFactory* factory) {
  return scoped_ptr<DnsSocketPool>(new DefaultDnsSocketPool(factory));
}

void DefaultDnsSocketPool::Initialize(
    const std::vector<IPEndPoint>* nameservers,
    NetLog* net_log) {
  InitializeInternal(nameservers, net_log);

  DCHECK(pools_.empty());
  const unsigned num_servers = nameservers->size();
  pools_.resize(num_servers);
  for (unsigned server_index = 0; server_index < num_servers; ++server_index)
    FillPool(server_index, kInitialPoolSize);
}

DefaultDnsSocketPool::~DefaultDnsSocketPool() {
  unsigned num_servers = pools_.size();
  for (unsigned server_index = 0; server_index < num_servers; ++server_index) {
    SocketVector& pool = pools_[server_index];
    STLDeleteElements(&pool);
  }
}

scoped_ptr<DatagramClientSocket> DefaultDnsSocketPool::AllocateSocket(
    unsigned server_index) {
  DCHECK_LT(server_index, pools_.size());
  SocketVector& pool = pools_[server_index];

  FillPool(server_index, kAllocateMinSize);
  if (pool.size() == 0) {
    LOG(WARNING) << "No DNS sockets available in pool " << server_index << "!";
    return scoped_ptr<DatagramClientSocket>();
  }

  if (pool.size() < kAllocateMinSize) {
    LOG(WARNING) << "Low DNS port entropy: wanted " << kAllocateMinSize
                 << " sockets to choose from, but only have " << pool.size()
                 << " in pool " << server_index << ".";
  }

  unsigned socket_index = base::RandInt(0, pool.size() - 1);
  DatagramClientSocket* socket = pool[socket_index];
  pool[socket_index] = pool.back();
  pool.pop_back();

  return scoped_ptr<DatagramClientSocket>(socket);
}

void DefaultDnsSocketPool::FreeSocket(
    unsigned server_index,
    scoped_ptr<DatagramClientSocket> socket) {
  DCHECK_LT(server_index, pools_.size());
}

void DefaultDnsSocketPool::FillPool(unsigned server_index, unsigned size) {
  SocketVector& pool = pools_[server_index];

  for (unsigned pool_index = pool.size(); pool_index < size; ++pool_index) {
    DatagramClientSocket* socket =
        CreateConnectedSocket(server_index).release();
    if (!socket)
      break;
    pool.push_back(socket);
  }
}

} // namespace net
