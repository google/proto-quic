// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_config_service.h"

#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/values.h"
#include "net/base/ip_endpoint.h"
#include "net/base/ip_pattern.h"

namespace net {

NameServerClassifier::NameServerClassifier() {
  // Google Public DNS addresses from:
  // https://developers.google.com/speed/public-dns/docs/using
  AddRule("8.8.8.8", NAME_SERVERS_TYPE_GOOGLE_PUBLIC_DNS);
  AddRule("8.8.4.4", NAME_SERVERS_TYPE_GOOGLE_PUBLIC_DNS);
  AddRule("2001:4860:4860:0:0:0:0:8888", NAME_SERVERS_TYPE_GOOGLE_PUBLIC_DNS),
  AddRule("2001:4860:4860:0:0:0:0:8844", NAME_SERVERS_TYPE_GOOGLE_PUBLIC_DNS),

  // Count localhost as private, since we don't know what upstream it uses:
  AddRule("127.*.*.*", NAME_SERVERS_TYPE_PRIVATE);
  AddRule("0:0:0:0:0:0:0:1", NAME_SERVERS_TYPE_PRIVATE);

  // RFC 1918 private addresses:
  AddRule("10.*.*.*", NAME_SERVERS_TYPE_PRIVATE);
  AddRule("172.[16-31].*.*", NAME_SERVERS_TYPE_PRIVATE);
  AddRule("192.168.*.*", NAME_SERVERS_TYPE_PRIVATE);

  // IPv4 link-local addresses:
  AddRule("169.254.*.*", NAME_SERVERS_TYPE_PRIVATE);

  // IPv6 link-local addresses:
  AddRule("fe80:*:*:*:*:*:*:*", NAME_SERVERS_TYPE_PRIVATE);

  // Anything else counts as public:
  AddRule("*.*.*.*", NAME_SERVERS_TYPE_PUBLIC);
  AddRule("*:*:*:*:*:*:*:*", NAME_SERVERS_TYPE_PUBLIC);
}

NameServerClassifier::~NameServerClassifier() {}

NameServerClassifier::NameServersType NameServerClassifier::GetNameServersType(
    const std::vector<IPEndPoint>& nameservers) const {
  NameServersType type = NAME_SERVERS_TYPE_NONE;
  for (std::vector<IPEndPoint>::const_iterator it = nameservers.begin();
       it != nameservers.end();
       ++it) {
    type = MergeNameServersTypes(type, GetNameServerType(it->address()));
  }
  return type;
}

struct NameServerClassifier::NameServerTypeRule {
  NameServerTypeRule(const char* pattern_string, NameServersType type)
      : type(type) {
    bool parsed = pattern.ParsePattern(pattern_string);
    DCHECK(parsed);
  }

  IPPattern pattern;
  NameServersType type;
};

void NameServerClassifier::AddRule(const char* pattern_string,
                                   NameServersType address_type) {
  rules_.push_back(new NameServerTypeRule(pattern_string, address_type));
}

NameServerClassifier::NameServersType NameServerClassifier::GetNameServerType(
    const IPAddress& address) const {
  for (ScopedVector<NameServerTypeRule>::const_iterator it = rules_.begin();
       it != rules_.end();
       ++it) {
    if ((*it)->pattern.Match(address))
      return (*it)->type;
  }
  NOTREACHED();
  return NAME_SERVERS_TYPE_NONE;
}

NameServerClassifier::NameServersType
NameServerClassifier::MergeNameServersTypes(NameServersType a,
                                            NameServersType b) {
  if (a == NAME_SERVERS_TYPE_NONE)
    return b;
  if (b == NAME_SERVERS_TYPE_NONE)
    return a;
  if (a == b)
    return a;
  return NAME_SERVERS_TYPE_MIXED;
}

// Default values are taken from glibc resolv.h except timeout which is set to
// |kDnsDefaultTimeoutMs|.
DnsConfig::DnsConfig()
    : unhandled_options(false),
      append_to_multi_label_name(true),
      randomize_ports(false),
      ndots(1),
      timeout(base::TimeDelta::FromMilliseconds(kDnsDefaultTimeoutMs)),
      attempts(2),
      rotate(false),
      edns0(false),
      use_local_ipv6(false) {}

DnsConfig::DnsConfig(const DnsConfig& other) = default;

DnsConfig::~DnsConfig() {}

bool DnsConfig::Equals(const DnsConfig& d) const {
  return EqualsIgnoreHosts(d) && (hosts == d.hosts);
}

bool DnsConfig::EqualsIgnoreHosts(const DnsConfig& d) const {
  return (nameservers == d.nameservers) &&
         (search == d.search) &&
         (unhandled_options == d.unhandled_options) &&
         (append_to_multi_label_name == d.append_to_multi_label_name) &&
         (ndots == d.ndots) &&
         (timeout == d.timeout) &&
         (attempts == d.attempts) &&
         (rotate == d.rotate) &&
         (edns0 == d.edns0) &&
         (use_local_ipv6 == d.use_local_ipv6);
}

void DnsConfig::CopyIgnoreHosts(const DnsConfig& d) {
  nameservers = d.nameservers;
  search = d.search;
  unhandled_options = d.unhandled_options;
  append_to_multi_label_name = d.append_to_multi_label_name;
  ndots = d.ndots;
  timeout = d.timeout;
  attempts = d.attempts;
  rotate = d.rotate;
  edns0 = d.edns0;
  use_local_ipv6 = d.use_local_ipv6;
}

scoped_ptr<base::Value> DnsConfig::ToValue() const {
  scoped_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

  base::ListValue* list = new base::ListValue();
  for (size_t i = 0; i < nameservers.size(); ++i)
    list->Append(new base::StringValue(nameservers[i].ToString()));
  dict->Set("nameservers", list);

  list = new base::ListValue();
  for (size_t i = 0; i < search.size(); ++i)
    list->Append(new base::StringValue(search[i]));
  dict->Set("search", list);

  dict->SetBoolean("unhandled_options", unhandled_options);
  dict->SetBoolean("append_to_multi_label_name", append_to_multi_label_name);
  dict->SetInteger("ndots", ndots);
  dict->SetDouble("timeout", timeout.InSecondsF());
  dict->SetInteger("attempts", attempts);
  dict->SetBoolean("rotate", rotate);
  dict->SetBoolean("edns0", edns0);
  dict->SetBoolean("use_local_ipv6", use_local_ipv6);
  dict->SetInteger("num_hosts", hosts.size());

  return std::move(dict);
}

DnsConfigService::DnsConfigService()
    : watch_failed_(false),
      have_config_(false),
      have_hosts_(false),
      need_update_(false),
      last_sent_empty_(true) {}

DnsConfigService::~DnsConfigService() {
}

void DnsConfigService::ReadConfig(const CallbackType& callback) {
  DCHECK(CalledOnValidThread());
  DCHECK(!callback.is_null());
  DCHECK(callback_.is_null());
  callback_ = callback;
  ReadNow();
}

void DnsConfigService::WatchConfig(const CallbackType& callback) {
  DCHECK(CalledOnValidThread());
  DCHECK(!callback.is_null());
  DCHECK(callback_.is_null());
  callback_ = callback;
  watch_failed_ = !StartWatching();
  ReadNow();
}

void DnsConfigService::InvalidateConfig() {
  DCHECK(CalledOnValidThread());
  base::TimeTicks now = base::TimeTicks::Now();
  if (!last_invalidate_config_time_.is_null()) {
    UMA_HISTOGRAM_LONG_TIMES("AsyncDNS.ConfigNotifyInterval",
                             now - last_invalidate_config_time_);
  }
  last_invalidate_config_time_ = now;
  if (!have_config_)
    return;
  have_config_ = false;
  StartTimer();
}

void DnsConfigService::InvalidateHosts() {
  DCHECK(CalledOnValidThread());
  base::TimeTicks now = base::TimeTicks::Now();
  if (!last_invalidate_hosts_time_.is_null()) {
    UMA_HISTOGRAM_LONG_TIMES("AsyncDNS.HostsNotifyInterval",
                             now - last_invalidate_hosts_time_);
  }
  last_invalidate_hosts_time_ = now;
  if (!have_hosts_)
    return;
  have_hosts_ = false;
  StartTimer();
}

void DnsConfigService::OnConfigRead(const DnsConfig& config) {
  DCHECK(CalledOnValidThread());
  DCHECK(config.IsValid());

  bool changed = false;
  if (!config.EqualsIgnoreHosts(dns_config_)) {
    dns_config_.CopyIgnoreHosts(config);
    need_update_ = true;
    changed = true;
  }
  if (!changed && !last_sent_empty_time_.is_null()) {
    UMA_HISTOGRAM_LONG_TIMES("AsyncDNS.UnchangedConfigInterval",
                             base::TimeTicks::Now() - last_sent_empty_time_);
  }
  UMA_HISTOGRAM_BOOLEAN("AsyncDNS.ConfigChange", changed);
  UMA_HISTOGRAM_ENUMERATION(
      "AsyncDNS.NameServersType",
      classifier_.GetNameServersType(dns_config_.nameservers),
      NameServerClassifier::NAME_SERVERS_TYPE_MAX_VALUE);

  have_config_ = true;
  if (have_hosts_ || watch_failed_)
    OnCompleteConfig();
}

void DnsConfigService::OnHostsRead(const DnsHosts& hosts) {
  DCHECK(CalledOnValidThread());

  bool changed = false;
  if (hosts != dns_config_.hosts) {
    dns_config_.hosts = hosts;
    need_update_ = true;
    changed = true;
  }
  if (!changed && !last_sent_empty_time_.is_null()) {
    UMA_HISTOGRAM_LONG_TIMES("AsyncDNS.UnchangedHostsInterval",
                             base::TimeTicks::Now() - last_sent_empty_time_);
  }
  UMA_HISTOGRAM_BOOLEAN("AsyncDNS.HostsChange", changed);

  have_hosts_ = true;
  if (have_config_ || watch_failed_)
    OnCompleteConfig();
}

void DnsConfigService::StartTimer() {
  DCHECK(CalledOnValidThread());
  if (last_sent_empty_) {
    DCHECK(!timer_.IsRunning());
    return;  // No need to withdraw again.
  }
  timer_.Stop();

  // Give it a short timeout to come up with a valid config. Otherwise withdraw
  // the config from the receiver. The goal is to avoid perceivable network
  // outage (when using the wrong config) but at the same time avoid
  // unnecessary Job aborts in HostResolverImpl. The signals come from multiple
  // sources so it might receive multiple events during a config change.

  // DHCP and user-induced changes are on the order of seconds, so 150ms should
  // not add perceivable delay. On the other hand, config readers should finish
  // within 150ms with the rare exception of I/O block or extra large HOSTS.
  const base::TimeDelta kTimeout = base::TimeDelta::FromMilliseconds(150);

  timer_.Start(FROM_HERE,
               kTimeout,
               this,
               &DnsConfigService::OnTimeout);
}

void DnsConfigService::OnTimeout() {
  DCHECK(CalledOnValidThread());
  DCHECK(!last_sent_empty_);
  // Indicate that even if there is no change in On*Read, we will need to
  // update the receiver when the config becomes complete.
  need_update_ = true;
  // Empty config is considered invalid.
  last_sent_empty_ = true;
  last_sent_empty_time_ = base::TimeTicks::Now();
  callback_.Run(DnsConfig());
}

void DnsConfigService::OnCompleteConfig() {
  timer_.Stop();
  if (!need_update_)
    return;
  need_update_ = false;
  last_sent_empty_ = false;
  if (watch_failed_) {
    // If a watch failed, the config may not be accurate, so report empty.
    callback_.Run(DnsConfig());
  } else {
    callback_.Run(dns_config_);
  }
}

}  // namespace net

