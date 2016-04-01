// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DNS_DNS_CLIENT_H_
#define NET_DNS_DNS_CLIENT_H_

#include "base/memory/scoped_ptr.h"
#include "net/base/net_export.h"

namespace net {

class AddressSorter;
struct DnsConfig;
class DnsTransactionFactory;
class NetLog;

// Convenience wrapper which allows easy injection of DnsTransaction into
// HostResolverImpl. Pointers returned by the Get* methods are only guaranteed
// to remain valid until next time SetConfig is called.
class NET_EXPORT DnsClient {
 public:
  virtual ~DnsClient() {}

  // Destroys the current DnsTransactionFactory and creates a new one
  // according to |config|, unless it is invalid or has |unhandled_options|.
  virtual void SetConfig(const DnsConfig& config) = 0;

  // Returns NULL if the current config is not valid.
  virtual const DnsConfig* GetConfig() const = 0;

  // Returns NULL if the current config is not valid.
  virtual DnsTransactionFactory* GetTransactionFactory() = 0;

  // Returns NULL if the current config is not valid.
  virtual AddressSorter* GetAddressSorter() = 0;

  // Creates default client.
  static scoped_ptr<DnsClient> CreateClient(NetLog* net_log);
};

}  // namespace net

#endif  // NET_DNS_DNS_CLIENT_H_

