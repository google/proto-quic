// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_config_watcher_mac.h"

#include <dlfcn.h>

#include "base/lazy_instance.h"
#include "third_party/apple_apsl/dnsinfo.h"

namespace {

// dnsinfo symbols are available via libSystem.dylib, but can also be present in
// SystemConfiguration.framework. To avoid confusion, load them explicitly from
// libSystem.dylib.
class DnsInfoApi {
 public:
  typedef const char* (*dns_configuration_notify_key_t)();
  typedef dns_config_t* (*dns_configuration_copy_t)();
  typedef void (*dns_configuration_free_t)(dns_config_t*);

  DnsInfoApi()
      : dns_configuration_notify_key(NULL),
        dns_configuration_copy(NULL),
        dns_configuration_free(NULL) {
    handle_ = dlopen("/usr/lib/libSystem.dylib",
                     RTLD_LAZY | RTLD_NOLOAD);
    if (!handle_)
      return;
    dns_configuration_notify_key =
        reinterpret_cast<dns_configuration_notify_key_t>(
            dlsym(handle_, "dns_configuration_notify_key"));
    dns_configuration_copy =
        reinterpret_cast<dns_configuration_copy_t>(
            dlsym(handle_, "dns_configuration_copy"));
    dns_configuration_free =
        reinterpret_cast<dns_configuration_free_t>(
            dlsym(handle_, "dns_configuration_free"));
  }

  ~DnsInfoApi() {
    if (handle_)
      dlclose(handle_);
  }

  dns_configuration_notify_key_t dns_configuration_notify_key;
  dns_configuration_copy_t dns_configuration_copy;
  dns_configuration_free_t dns_configuration_free;

 private:
  void* handle_;
};

const DnsInfoApi& GetDnsInfoApi() {
  static base::LazyInstance<DnsInfoApi>::Leaky api = LAZY_INSTANCE_INITIALIZER;
  return api.Get();
}

struct DnsConfigTDeleter {
  inline void operator()(dns_config_t* ptr) const {
    if (GetDnsInfoApi().dns_configuration_free)
      GetDnsInfoApi().dns_configuration_free(ptr);
  }
};

}  // namespace

namespace net {
namespace internal {

bool DnsConfigWatcher::Watch(
    const base::Callback<void(bool succeeded)>& callback) {
  if (!GetDnsInfoApi().dns_configuration_notify_key)
    return false;
  return watcher_.Watch(GetDnsInfoApi().dns_configuration_notify_key(),
                        callback);
}

// static
ConfigParsePosixResult DnsConfigWatcher::CheckDnsConfig() {
  if (!GetDnsInfoApi().dns_configuration_copy)
    return CONFIG_PARSE_POSIX_NO_DNSINFO;
  std::unique_ptr<dns_config_t, DnsConfigTDeleter> dns_config(
      GetDnsInfoApi().dns_configuration_copy());
  if (!dns_config)
    return CONFIG_PARSE_POSIX_NO_DNSINFO;

  // TODO(szym): Parse dns_config_t for resolvers rather than res_state.
  // DnsClient can't handle domain-specific unscoped resolvers.
  unsigned num_resolvers = 0;
  for (int i = 0; i < dns_config->n_resolver; ++i) {
    dns_resolver_t* resolver = dns_config->resolver[i];
    if (!resolver->n_nameserver)
      continue;
    if (resolver->options && !strcmp(resolver->options, "mdns"))
      continue;
    ++num_resolvers;
  }
  if (num_resolvers > 1)
    return CONFIG_PARSE_POSIX_UNHANDLED_OPTIONS;
  return CONFIG_PARSE_POSIX_OK;
}

}  // namespace internal
}  // namespace net
