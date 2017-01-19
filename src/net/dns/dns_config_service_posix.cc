// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_config_service_posix.h"

#include <memory>
#include <string>

#include "base/bind.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_path_watcher.h"
#include "base/lazy_instance.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/metrics/histogram_macros.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/dns/dns_hosts.h"
#include "net/dns/dns_protocol.h"
#include "net/dns/notify_watcher_mac.h"
#include "net/dns/serial_worker.h"

#if defined(OS_MACOSX) && !defined(OS_IOS)
#include "net/dns/dns_config_watcher_mac.h"
#endif

#if defined(OS_ANDROID)
#include <sys/system_properties.h>
#include "base/android/build_info.h"
#include "net/android/network_library.h"
#include "net/base/network_change_notifier.h"
#endif

namespace net {

namespace internal {

namespace {

#if defined(OS_ANDROID)
const base::FilePath::CharType kFilePathHosts[] =
    FILE_PATH_LITERAL("/system/etc/hosts");
#else
const base::FilePath::CharType kFilePathHosts[] =
    FILE_PATH_LITERAL("/etc/hosts");
#endif

#if defined(OS_IOS)
// There is no public API to watch the DNS configuration on iOS.
class DnsConfigWatcher {
 public:
  using CallbackType = base::Callback<void(bool succeeded)>;

  bool Watch(const CallbackType& callback) {
    return false;
  }
};

#elif defined(OS_ANDROID)

// On Android, assume DNS config may have changed on every network change.
class DnsConfigWatcher {
 public:
  using CallbackType = base::Callback<void(bool succeeded)>;

  bool Watch(const CallbackType& callback) {
    callback_ = callback;
    return true;
  }

  void OnNetworkChanged(NetworkChangeNotifier::ConnectionType type) {
    if (!callback_.is_null() && type != NetworkChangeNotifier::CONNECTION_NONE)
      callback_.Run(true);
  }

 private:
  CallbackType callback_;
};

#elif defined(OS_MACOSX)

// DnsConfigWatcher for OS_MACOSX is in dns_config_watcher_mac.{hh,cc}.

#else  // !defined(OS_IOS) && !defined(OS_ANDROID) && !defined(OS_MACOSX)

#ifndef _PATH_RESCONF  // Normally defined in <resolv.h>
#define _PATH_RESCONF "/etc/resolv.conf"
#endif

const base::FilePath::CharType kFilePathConfig[] =
    FILE_PATH_LITERAL(_PATH_RESCONF);

class DnsConfigWatcher {
 public:
  using CallbackType = base::Callback<void(bool succeeded)>;

  bool Watch(const CallbackType& callback) {
    callback_ = callback;
    return watcher_.Watch(base::FilePath(kFilePathConfig), false,
                          base::Bind(&DnsConfigWatcher::OnCallback,
                                     base::Unretained(this)));
  }

 private:
  void OnCallback(const base::FilePath& path, bool error) {
    callback_.Run(!error);
  }

  base::FilePathWatcher watcher_;
  CallbackType callback_;
};
#endif  // defined(OS_IOS)

#if !defined(OS_ANDROID)
ConfigParsePosixResult ReadDnsConfig(DnsConfig* config) {
  ConfigParsePosixResult result;
  config->unhandled_options = false;
#if defined(OS_OPENBSD)
  // Note: res_ninit in glibc always returns 0 and sets RES_INIT.
  // res_init behaves the same way.
  memset(&_res, 0, sizeof(_res));
  if (res_init() == 0) {
    result = ConvertResStateToDnsConfig(_res, config);
  } else {
    result = CONFIG_PARSE_POSIX_RES_INIT_FAILED;
  }
#else  // all other OS_POSIX
  struct __res_state res;
  memset(&res, 0, sizeof(res));
  if (res_ninit(&res) == 0) {
    result = ConvertResStateToDnsConfig(res, config);
  } else {
    result = CONFIG_PARSE_POSIX_RES_INIT_FAILED;
  }
  // Prefer res_ndestroy where available.
#if defined(OS_MACOSX) || defined(OS_FREEBSD)
  res_ndestroy(&res);
#else
  res_nclose(&res);
#endif  // defined(OS_MACOSX) || defined(OS_FREEBSD)
#endif  // defined(OS_OPENBSD)

#if defined(OS_MACOSX) && !defined(OS_IOS)
  ConfigParsePosixResult error = DnsConfigWatcher::CheckDnsConfig();
  switch (error) {
    case CONFIG_PARSE_POSIX_OK:
      break;
    case CONFIG_PARSE_POSIX_UNHANDLED_OPTIONS:
      LOG(WARNING) << "dns_config has unhandled options!";
      config->unhandled_options = true;
    default:
      return error;
  }
#endif  // defined(OS_MACOSX) && !defined(OS_IOS)
  // Override timeout value to match default setting on Windows.
  config->timeout = base::TimeDelta::FromMilliseconds(kDnsDefaultTimeoutMs);
  return result;
}
#else  // defined(OS_ANDROID)
// Theoretically, this is bad. __system_property_get is not a supported API
// (but it's currently visible to anyone using Bionic), and the properties
// are implementation details that may disappear in future Android releases.
// Practically, libcutils provides property_get, which is a public API, and the
// DNS code (and its clients) are already robust against failing to get the DNS
// config for whatever reason, so the properties can disappear and the world
// won't end.
// TODO(juliatuttle): Depend on libcutils, then switch this (and other uses of
//                    __system_property_get) to property_get.
ConfigParsePosixResult ReadDnsConfig(DnsConfig* dns_config) {
  if (base::android::BuildInfo::GetInstance()->sdk_int() >=
      base::android::SDK_VERSION_MARSHMALLOW) {
    dns_config->nameservers.clear();
    net::android::GetDnsServers(&dns_config->nameservers);
    if (dns_config->nameservers.empty())
      return CONFIG_PARSE_POSIX_NO_NAMESERVERS;
    return CONFIG_PARSE_POSIX_OK;
  }
  char property_value[PROP_VALUE_MAX];
  __system_property_get("net.dns1", property_value);
  std::string dns1_string = property_value;
  __system_property_get("net.dns2", property_value);
  std::string dns2_string = property_value;
  if (dns1_string.empty() && dns2_string.empty())
    return CONFIG_PARSE_POSIX_NO_NAMESERVERS;

  IPAddress dns1_address;
  IPAddress dns2_address;
  bool parsed1 = dns1_address.AssignFromIPLiteral(dns1_string);
  bool parsed2 = dns2_address.AssignFromIPLiteral(dns2_string);
  if (!parsed1 && !parsed2)
    return CONFIG_PARSE_POSIX_BAD_ADDRESS;

  if (parsed1) {
    IPEndPoint dns1(dns1_address, dns_protocol::kDefaultPort);
    dns_config->nameservers.push_back(dns1);
  }
  if (parsed2) {
    IPEndPoint dns2(dns2_address, dns_protocol::kDefaultPort);
    dns_config->nameservers.push_back(dns2);
  }

  return CONFIG_PARSE_POSIX_OK;
}
#endif  // !defined(OS_ANDROID)

}  // namespace

class DnsConfigServicePosix::Watcher {
 public:
  explicit Watcher(DnsConfigServicePosix* service)
      : service_(service), weak_factory_(this) {}
  ~Watcher() {}

  bool Watch() {
    bool success = true;
    if (!config_watcher_.Watch(base::Bind(&Watcher::OnConfigChanged,
                                          base::Unretained(this)))) {
      LOG(ERROR) << "DNS config watch failed to start.";
      success = false;
      UMA_HISTOGRAM_ENUMERATION("AsyncDNS.WatchStatus",
                                DNS_CONFIG_WATCH_FAILED_TO_START_CONFIG,
                                DNS_CONFIG_WATCH_MAX);
    }
// Hosts file should never change on Android or iOS (and watching it on Android
// is problematic; see http://crbug.com/600442), so don't watch it there.
#if !defined(OS_ANDROID) && !defined(OS_IOS)
    if (!hosts_watcher_.Watch(
            base::FilePath(service_->file_path_hosts_), false,
            base::Bind(&Watcher::OnHostsChanged, base::Unretained(this)))) {
      LOG(ERROR) << "DNS hosts watch failed to start.";
      success = false;
      UMA_HISTOGRAM_ENUMERATION("AsyncDNS.WatchStatus",
                                DNS_CONFIG_WATCH_FAILED_TO_START_HOSTS,
                                DNS_CONFIG_WATCH_MAX);
    }
#endif  // !defined(OS_ANDROID) && !defined(OS_IOS)
    return success;
  }

#if defined(OS_ANDROID)
  void OnNetworkChanged(NetworkChangeNotifier::ConnectionType type) {
    config_watcher_.OnNetworkChanged(type);
  }
#endif  // defined(OS_ANDROID)

 private:
  void OnConfigChanged(bool succeeded) {
#if defined(OS_ANDROID)
    service_->seen_config_change_ = true;
#endif  // defined(OS_ANDROID)
    // Ignore transient flutter of resolv.conf by delaying the signal a bit.
    const base::TimeDelta kDelay = base::TimeDelta::FromMilliseconds(50);
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE, base::Bind(&Watcher::OnConfigChangedDelayed,
                              weak_factory_.GetWeakPtr(), succeeded),
        kDelay);
  }

  void OnConfigChangedDelayed(bool succeeded) {
    service_->OnConfigChanged(succeeded);
  }

  void OnHostsChanged(const base::FilePath& path, bool error) {
    service_->OnHostsChanged(!error);
  }

  DnsConfigServicePosix* const service_;
  DnsConfigWatcher config_watcher_;
#if !defined(OS_ANDROID) && !defined(OS_IOS)
  base::FilePathWatcher hosts_watcher_;
#endif  // !defined(OS_ANDROID) && !defined(OS_IOS)

  base::WeakPtrFactory<Watcher> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(Watcher);
};

// A SerialWorker that uses libresolv to initialize res_state and converts
// it to DnsConfig (except on Android, where it reads system properties
// net.dns1 and net.dns2; see #if around ReadDnsConfig above.)
class DnsConfigServicePosix::ConfigReader : public SerialWorker {
 public:
  explicit ConfigReader(DnsConfigServicePosix* service)
      : service_(service), success_(false) {
    const DnsConfig* test_config = service->dns_config_for_testing_;
    if (test_config)
      dns_config_for_testing_.reset(new DnsConfig(*test_config));
  }

  void DoWork() override {
    base::TimeTicks start_time = base::TimeTicks::Now();
    ConfigParsePosixResult result = ReadDnsConfig(&dns_config_);
    if (dns_config_for_testing_) {
      dns_config_ = *dns_config_for_testing_;
      result = CONFIG_PARSE_POSIX_OK;
    }
    switch (result) {
      case CONFIG_PARSE_POSIX_MISSING_OPTIONS:
      case CONFIG_PARSE_POSIX_UNHANDLED_OPTIONS:
        DCHECK(dns_config_.unhandled_options);
        // Fall through.
      case CONFIG_PARSE_POSIX_OK:
        success_ = true;
        break;
      default:
        success_ = false;
        break;
    }
    UMA_HISTOGRAM_ENUMERATION("AsyncDNS.ConfigParsePosix",
                              result, CONFIG_PARSE_POSIX_MAX);
    UMA_HISTOGRAM_BOOLEAN("AsyncDNS.ConfigParseResult", success_);
    UMA_HISTOGRAM_TIMES("AsyncDNS.ConfigParseDuration",
                        base::TimeTicks::Now() - start_time);
  }

  void OnWorkFinished() override {
    DCHECK(!IsCancelled());
    if (success_) {
      service_->OnConfigRead(dns_config_);
    } else {
      LOG(WARNING) << "Failed to read DnsConfig.";
    }
  }

 private:
  ~ConfigReader() override {}

  // Raw pointer to owning DnsConfigService. This must never be accessed inside
  // DoWork(), since service may be destroyed while SerialWorker is running
  // on worker thread.
  DnsConfigServicePosix* const service_;
  // Dns config value to always return for testing.
  std::unique_ptr<const DnsConfig> dns_config_for_testing_;
  // Written in DoWork, read in OnWorkFinished, no locking necessary.
  DnsConfig dns_config_;
  bool success_;

  DISALLOW_COPY_AND_ASSIGN(ConfigReader);
};

// A SerialWorker that reads the HOSTS file and runs Callback.
class DnsConfigServicePosix::HostsReader : public SerialWorker {
 public:
  explicit HostsReader(DnsConfigServicePosix* service)
      : service_(service),
        file_path_hosts_(service->file_path_hosts_),
        success_(false) {}

 private:
  ~HostsReader() override {}

  void DoWork() override {
    base::TimeTicks start_time = base::TimeTicks::Now();
    success_ = ParseHostsFile(file_path_hosts_, &hosts_);
    UMA_HISTOGRAM_BOOLEAN("AsyncDNS.HostParseResult", success_);
    UMA_HISTOGRAM_TIMES("AsyncDNS.HostsParseDuration",
                        base::TimeTicks::Now() - start_time);
  }

  void OnWorkFinished() override {
    if (success_) {
      service_->OnHostsRead(hosts_);
    } else {
      LOG(WARNING) << "Failed to read DnsHosts.";
    }
  }

  // Raw pointer to owning DnsConfigService. This must never be accessed inside
  // DoWork(), since service may be destroyed while SerialWorker is running
  // on worker thread.
  DnsConfigServicePosix* const service_;
  // Hosts file path to parse.
  const base::FilePath file_path_hosts_;
  // Written in DoWork, read in OnWorkFinished, no locking necessary.
  DnsHosts hosts_;
  bool success_;

  DISALLOW_COPY_AND_ASSIGN(HostsReader);
};

DnsConfigServicePosix::DnsConfigServicePosix()
    : file_path_hosts_(kFilePathHosts),  // Must set before |hosts_reader_|
      dns_config_for_testing_(nullptr),  // Must set before |config_reader_|
      config_reader_(new ConfigReader(this)),
      hosts_reader_(new HostsReader(this))
#if defined(OS_ANDROID)
      ,
      seen_config_change_(false)
#endif  // defined(OS_ANDROID)
{
}

DnsConfigServicePosix::~DnsConfigServicePosix() {
  config_reader_->Cancel();
  hosts_reader_->Cancel();
}

void DnsConfigServicePosix::ReadNow() {
  config_reader_->WorkNow();
  hosts_reader_->WorkNow();
}

bool DnsConfigServicePosix::StartWatching() {
  // TODO(szym): re-start watcher if that makes sense. http://crbug.com/116139
  watcher_.reset(new Watcher(this));
  UMA_HISTOGRAM_ENUMERATION("AsyncDNS.WatchStatus", DNS_CONFIG_WATCH_STARTED,
                            DNS_CONFIG_WATCH_MAX);
  return watcher_->Watch();
}

void DnsConfigServicePosix::OnConfigChanged(bool succeeded) {
  InvalidateConfig();
  if (succeeded) {
    config_reader_->WorkNow();
  } else {
    LOG(ERROR) << "DNS config watch failed.";
    set_watch_failed(true);
    UMA_HISTOGRAM_ENUMERATION("AsyncDNS.WatchStatus",
                              DNS_CONFIG_WATCH_FAILED_CONFIG,
                              DNS_CONFIG_WATCH_MAX);
  }
}

void DnsConfigServicePosix::OnHostsChanged(bool succeeded) {
  InvalidateHosts();
  if (succeeded) {
    hosts_reader_->WorkNow();
  } else {
    LOG(ERROR) << "DNS hosts watch failed.";
    set_watch_failed(true);
    UMA_HISTOGRAM_ENUMERATION("AsyncDNS.WatchStatus",
                              DNS_CONFIG_WATCH_FAILED_HOSTS,
                              DNS_CONFIG_WATCH_MAX);
  }
}

void DnsConfigServicePosix::SetDnsConfigForTesting(
    const DnsConfig* dns_config) {
  DCHECK(CalledOnValidThread());
  dns_config_for_testing_ = dns_config;
  // Reset ConfigReader to bind new DnsConfig for testing.
  config_reader_->Cancel();
  config_reader_ = make_scoped_refptr(new ConfigReader(this));
}

void DnsConfigServicePosix::SetHostsFilePathForTesting(
    const base::FilePath::CharType* file_path) {
  DCHECK(CalledOnValidThread());
  file_path_hosts_ = file_path;
  // Reset HostsReader to bind new hosts file path.
  hosts_reader_->Cancel();
  hosts_reader_ = make_scoped_refptr(new HostsReader(this));
  // If watching, reset to bind new hosts file path and resume watching.
  if (watcher_) {
    watcher_.reset(new Watcher(this));
    watcher_->Watch();
  }
}

#if !defined(OS_ANDROID)
ConfigParsePosixResult ConvertResStateToDnsConfig(const struct __res_state& res,
                                                  DnsConfig* dns_config) {
  DCHECK(dns_config);

  if (!(res.options & RES_INIT))
    return CONFIG_PARSE_POSIX_RES_INIT_UNSET;

  dns_config->nameservers.clear();

#if defined(OS_MACOSX) || defined(OS_FREEBSD)
  union res_sockaddr_union addresses[MAXNS];
  int nscount = res_getservers(const_cast<res_state>(&res), addresses, MAXNS);
  DCHECK_GE(nscount, 0);
  DCHECK_LE(nscount, MAXNS);
  for (int i = 0; i < nscount; ++i) {
    IPEndPoint ipe;
    if (!ipe.FromSockAddr(
            reinterpret_cast<const struct sockaddr*>(&addresses[i]),
            sizeof addresses[i])) {
      return CONFIG_PARSE_POSIX_BAD_ADDRESS;
    }
    dns_config->nameservers.push_back(ipe);
  }
#elif defined(OS_LINUX)
  static_assert(arraysize(res.nsaddr_list) >= MAXNS &&
                    arraysize(res._u._ext.nsaddrs) >= MAXNS,
                "incompatible libresolv res_state");
  DCHECK_LE(res.nscount, MAXNS);
  // Initially, glibc stores IPv6 in |_ext.nsaddrs| and IPv4 in |nsaddr_list|.
  // In res_send.c:res_nsend, it merges |nsaddr_list| into |nsaddrs|,
  // but we have to combine the two arrays ourselves.
  for (int i = 0; i < res.nscount; ++i) {
    IPEndPoint ipe;
    const struct sockaddr* addr = nullptr;
    size_t addr_len = 0;
    if (res.nsaddr_list[i].sin_family) {  // The indicator used by res_nsend.
      addr = reinterpret_cast<const struct sockaddr*>(&res.nsaddr_list[i]);
      addr_len = sizeof res.nsaddr_list[i];
    } else if (res._u._ext.nsaddrs[i]) {
      addr = reinterpret_cast<const struct sockaddr*>(res._u._ext.nsaddrs[i]);
      addr_len = sizeof *res._u._ext.nsaddrs[i];
    } else {
      return CONFIG_PARSE_POSIX_BAD_EXT_STRUCT;
    }
    if (!ipe.FromSockAddr(addr, addr_len))
      return CONFIG_PARSE_POSIX_BAD_ADDRESS;
    dns_config->nameservers.push_back(ipe);
  }
#else  // !(defined(OS_LINUX) || defined(OS_MACOSX) || defined(OS_FREEBSD))
  DCHECK_LE(res.nscount, MAXNS);
  for (int i = 0; i < res.nscount; ++i) {
    IPEndPoint ipe;
    if (!ipe.FromSockAddr(
            reinterpret_cast<const struct sockaddr*>(&res.nsaddr_list[i]),
            sizeof res.nsaddr_list[i])) {
      return CONFIG_PARSE_POSIX_BAD_ADDRESS;
    }
    dns_config->nameservers.push_back(ipe);
  }
#endif  // defined(OS_MACOSX) || defined(OS_FREEBSD)

  dns_config->search.clear();
  for (int i = 0; (i < MAXDNSRCH) && res.dnsrch[i]; ++i) {
    dns_config->search.push_back(std::string(res.dnsrch[i]));
  }

  dns_config->ndots = res.ndots;
  dns_config->timeout = base::TimeDelta::FromSeconds(res.retrans);
  dns_config->attempts = res.retry;
#if defined(RES_ROTATE)
  dns_config->rotate = res.options & RES_ROTATE;
#endif
#if defined(RES_USE_EDNS0)
  dns_config->edns0 = res.options & RES_USE_EDNS0;
#endif
#if !defined(RES_USE_DNSSEC)
  // Some versions of libresolv don't have support for the DO bit. In this
  // case, we proceed without it.
  static const int RES_USE_DNSSEC = 0;
#endif

  // The current implementation assumes these options are set. They normally
  // cannot be overwritten by /etc/resolv.conf
  const unsigned kRequiredOptions = RES_RECURSE | RES_DEFNAMES | RES_DNSRCH;
  if ((res.options & kRequiredOptions) != kRequiredOptions) {
    dns_config->unhandled_options = true;
    return CONFIG_PARSE_POSIX_MISSING_OPTIONS;
  }

  const unsigned kUnhandledOptions = RES_USEVC | RES_IGNTC | RES_USE_DNSSEC;
  if (res.options & kUnhandledOptions) {
    dns_config->unhandled_options = true;
    return CONFIG_PARSE_POSIX_UNHANDLED_OPTIONS;
  }

  if (dns_config->nameservers.empty())
    return CONFIG_PARSE_POSIX_NO_NAMESERVERS;

  // If any name server is 0.0.0.0, assume the configuration is invalid.
  // TODO(szym): Measure how often this happens. http://crbug.com/125599
  for (unsigned i = 0; i < dns_config->nameservers.size(); ++i) {
    if (dns_config->nameservers[i].address().IsZero())
      return CONFIG_PARSE_POSIX_NULL_ADDRESS;
  }
  return CONFIG_PARSE_POSIX_OK;
}

#else   // defined(OS_ANDROID)

bool DnsConfigServicePosix::SeenChangeSince(
    const base::Time& since_time) const {
  DCHECK(CalledOnValidThread());
  return seen_config_change_;
}

void DnsConfigServicePosix::OnNetworkChanged(
    NetworkChangeNotifier::ConnectionType type) {
  DCHECK(CalledOnValidThread());
  DCHECK(watcher_);
  watcher_->OnNetworkChanged(type);
}
#endif  // !defined(OS_ANDROID)

}  // namespace internal

// static
std::unique_ptr<DnsConfigService> DnsConfigService::CreateSystemService() {
  return std::unique_ptr<DnsConfigService>(
      new internal::DnsConfigServicePosix());
}

}  // namespace net
