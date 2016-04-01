// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_client.h"

#include <utility>

#include "base/bind.h"
#include "base/rand_util.h"
#include "net/dns/address_sorter.h"
#include "net/dns/dns_config_service.h"
#include "net/dns/dns_session.h"
#include "net/dns/dns_socket_pool.h"
#include "net/dns/dns_transaction.h"
#include "net/log/net_log.h"
#include "net/socket/client_socket_factory.h"

namespace net {

namespace {

class DnsClientImpl : public DnsClient {
 public:
  explicit DnsClientImpl(NetLog* net_log)
      : address_sorter_(AddressSorter::CreateAddressSorter()),
        net_log_(net_log) {}

  void SetConfig(const DnsConfig& config) override {
    factory_.reset();
    session_ = NULL;
    if (config.IsValid() && !config.unhandled_options) {
      ClientSocketFactory* factory = ClientSocketFactory::GetDefaultFactory();
      scoped_ptr<DnsSocketPool> socket_pool(
          config.randomize_ports ? DnsSocketPool::CreateDefault(factory)
                                 : DnsSocketPool::CreateNull(factory));
      session_ = new DnsSession(config, std::move(socket_pool),
                                base::Bind(&base::RandInt), net_log_);
      factory_ = DnsTransactionFactory::CreateFactory(session_.get());
    }
  }

  const DnsConfig* GetConfig() const override {
    return session_.get() ? &session_->config() : NULL;
  }

  DnsTransactionFactory* GetTransactionFactory() override {
    return session_.get() ? factory_.get() : NULL;
  }

  AddressSorter* GetAddressSorter() override { return address_sorter_.get(); }

 private:
  scoped_refptr<DnsSession> session_;
  scoped_ptr<DnsTransactionFactory> factory_;
  scoped_ptr<AddressSorter> address_sorter_;

  NetLog* net_log_;
};

}  // namespace

// static
scoped_ptr<DnsClient> DnsClient::CreateClient(NetLog* net_log) {
  return scoped_ptr<DnsClient>(new DnsClientImpl(net_log));
}

}  // namespace net

