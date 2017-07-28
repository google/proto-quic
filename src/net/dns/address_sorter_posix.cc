// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/address_sorter_posix.h"

#include <netinet/in.h>

#include <memory>
#include <utility>

#if defined(OS_MACOSX) || defined(OS_BSD)
#include <sys/socket.h>  // Must be included before ifaddrs.h.
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in_var.h>
#include <string.h>
#include <sys/ioctl.h>
#endif

#include <algorithm>
#include <vector>

#include "base/logging.h"
#include "net/base/net_errors.h"
#include "net/log/net_log_source.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/datagram_client_socket.h"

#if defined(OS_LINUX)
#include "net/base/address_tracker_linux.h"
#endif

namespace net {

namespace {

// Address sorting is performed according to RFC3484 with revisions.
// http://tools.ietf.org/html/draft-ietf-6man-rfc3484bis-06
// Precedence and label are separate to support override through /etc/gai.conf.

// Returns true if |p1| should precede |p2| in the table.
// Sorts table by decreasing prefix size to allow longest prefix matching.
bool ComparePolicy(const AddressSorterPosix::PolicyEntry& p1,
                   const AddressSorterPosix::PolicyEntry& p2) {
  return p1.prefix_length > p2.prefix_length;
}

// Creates sorted PolicyTable from |table| with |size| entries.
AddressSorterPosix::PolicyTable LoadPolicy(
    const AddressSorterPosix::PolicyEntry* table,
    size_t size) {
  AddressSorterPosix::PolicyTable result(table, table + size);
  std::sort(result.begin(), result.end(), ComparePolicy);
  return result;
}

// Search |table| for matching prefix of |address|. |table| must be sorted by
// descending prefix (prefix of another prefix must be later in table).
unsigned GetPolicyValue(const AddressSorterPosix::PolicyTable& table,
                        const IPAddress& address) {
  if (address.IsIPv4())
    return GetPolicyValue(table, ConvertIPv4ToIPv4MappedIPv6(address));
  for (unsigned i = 0; i < table.size(); ++i) {
    const AddressSorterPosix::PolicyEntry& entry = table[i];
    IPAddress prefix(entry.prefix);
    if (IPAddressMatchesPrefix(address, prefix, entry.prefix_length))
      return entry.value;
  }
  NOTREACHED();
  // The last entry is the least restrictive, so assume it's default.
  return table.back().value;
}

bool IsIPv6Multicast(const IPAddress& address) {
  DCHECK(address.IsIPv6());
  return address.bytes()[0] == 0xFF;
}

AddressSorterPosix::AddressScope GetIPv6MulticastScope(
    const IPAddress& address) {
  DCHECK(address.IsIPv6());
  return static_cast<AddressSorterPosix::AddressScope>(address.bytes()[1] &
                                                       0x0F);
}

bool IsIPv6Loopback(const IPAddress& address) {
  DCHECK(address.IsIPv6());
  return address == IPAddress::IPv6Localhost();
}

bool IsIPv6LinkLocal(const IPAddress& address) {
  DCHECK(address.IsIPv6());
  // IN6_IS_ADDR_LINKLOCAL
  return (address.bytes()[0] == 0xFE) && ((address.bytes()[1] & 0xC0) == 0x80);
}

bool IsIPv6SiteLocal(const IPAddress& address) {
  DCHECK(address.IsIPv6());
  // IN6_IS_ADDR_SITELOCAL
  return (address.bytes()[0] == 0xFE) && ((address.bytes()[1] & 0xC0) == 0xC0);
}

AddressSorterPosix::AddressScope GetScope(
    const AddressSorterPosix::PolicyTable& ipv4_scope_table,
    const IPAddress& address) {
  if (address.IsIPv6()) {
    if (IsIPv6Multicast(address)) {
      return GetIPv6MulticastScope(address);
    } else if (IsIPv6Loopback(address) || IsIPv6LinkLocal(address)) {
      return AddressSorterPosix::SCOPE_LINKLOCAL;
    } else if (IsIPv6SiteLocal(address)) {
      return AddressSorterPosix::SCOPE_SITELOCAL;
    } else {
      return AddressSorterPosix::SCOPE_GLOBAL;
    }
  } else if (address.IsIPv4()) {
    return static_cast<AddressSorterPosix::AddressScope>(
        GetPolicyValue(ipv4_scope_table, address));
  } else {
    NOTREACHED();
    return AddressSorterPosix::SCOPE_NODELOCAL;
  }
}

// Default policy table. RFC 3484, Section 2.1.
const AddressSorterPosix::PolicyEntry kDefaultPrecedenceTable[] = {
    // ::1/128 -- loopback
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 128, 50},
    // ::/0 -- any
    {{}, 0, 40},
    // ::ffff:0:0/96 -- IPv4 mapped
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF}, 96, 35},
    // 2002::/16 -- 6to4
    {{
         0x20, 0x02,
     },
     16,
     30},
    // 2001::/32 -- Teredo
    {{0x20, 0x01, 0, 0}, 32, 5},
    // fc00::/7 -- unique local address
    {{0xFC}, 7, 3},
    // ::/96 -- IPv4 compatible
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 96, 1},
    // fec0::/10 -- site-local expanded scope
    {{0xFE, 0xC0}, 10, 1},
    // 3ffe::/16 -- 6bone
    {{0x3F, 0xFE}, 16, 1},
};

const AddressSorterPosix::PolicyEntry kDefaultLabelTable[] = {
    // ::1/128 -- loopback
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 128, 0},
    // ::/0 -- any
    {{}, 0, 1},
    // ::ffff:0:0/96 -- IPv4 mapped
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF}, 96, 4},
    // 2002::/16 -- 6to4
    {{
         0x20, 0x02,
     },
     16,
     2},
    // 2001::/32 -- Teredo
    {{0x20, 0x01, 0, 0}, 32, 5},
    // fc00::/7 -- unique local address
    {{0xFC}, 7, 13},
    // ::/96 -- IPv4 compatible
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 96, 3},
    // fec0::/10 -- site-local expanded scope
    {{0xFE, 0xC0}, 10, 11},
    // 3ffe::/16 -- 6bone
    {{0x3F, 0xFE}, 16, 12},
};

// Default mapping of IPv4 addresses to scope.
const AddressSorterPosix::PolicyEntry kDefaultIPv4ScopeTable[] = {
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0x7F},
     104,
     AddressSorterPosix::SCOPE_LINKLOCAL},
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xA9, 0xFE},
     112,
     AddressSorterPosix::SCOPE_LINKLOCAL},
    {{}, 0, AddressSorterPosix::SCOPE_GLOBAL},
};

struct DestinationInfo {
  IPAddress address;
  AddressSorterPosix::AddressScope scope;
  unsigned precedence;
  unsigned label;
  const AddressSorterPosix::SourceAddressInfo* src;
  unsigned common_prefix_length;
};

// Returns true iff |dst_a| should precede |dst_b| in the address list.
// RFC 3484, section 6.
bool CompareDestinations(const std::unique_ptr<DestinationInfo>& dst_a,
                         const std::unique_ptr<DestinationInfo>& dst_b) {
  // Rule 1: Avoid unusable destinations.
  // Unusable destinations are already filtered out.
  DCHECK(dst_a->src);
  DCHECK(dst_b->src);

  // Rule 2: Prefer matching scope.
  bool scope_match1 = (dst_a->src->scope == dst_a->scope);
  bool scope_match2 = (dst_b->src->scope == dst_b->scope);
  if (scope_match1 != scope_match2)
    return scope_match1;

  // Rule 3: Avoid deprecated addresses.
  if (dst_a->src->deprecated != dst_b->src->deprecated)
    return !dst_a->src->deprecated;

  // Rule 4: Prefer home addresses.
  if (dst_a->src->home != dst_b->src->home)
    return dst_a->src->home;

  // Rule 5: Prefer matching label.
  bool label_match1 = (dst_a->src->label == dst_a->label);
  bool label_match2 = (dst_b->src->label == dst_b->label);
  if (label_match1 != label_match2)
    return label_match1;

  // Rule 6: Prefer higher precedence.
  if (dst_a->precedence != dst_b->precedence)
    return dst_a->precedence > dst_b->precedence;

  // Rule 7: Prefer native transport.
  if (dst_a->src->native != dst_b->src->native)
    return dst_a->src->native;

  // Rule 8: Prefer smaller scope.
  if (dst_a->scope != dst_b->scope)
    return dst_a->scope < dst_b->scope;

  // Rule 9: Use longest matching prefix. Only for matching address families.
  if (dst_a->address.size() == dst_b->address.size()) {
    if (dst_a->common_prefix_length != dst_b->common_prefix_length)
      return dst_a->common_prefix_length > dst_b->common_prefix_length;
  }

  // Rule 10: Leave the order unchanged.
  // stable_sort takes care of that.
  return false;
}

}  // namespace

AddressSorterPosix::AddressSorterPosix(ClientSocketFactory* socket_factory)
    : socket_factory_(socket_factory),
      precedence_table_(LoadPolicy(kDefaultPrecedenceTable,
                                   arraysize(kDefaultPrecedenceTable))),
      label_table_(LoadPolicy(kDefaultLabelTable,
                              arraysize(kDefaultLabelTable))),
      ipv4_scope_table_(LoadPolicy(kDefaultIPv4ScopeTable,
                              arraysize(kDefaultIPv4ScopeTable))) {
  NetworkChangeNotifier::AddIPAddressObserver(this);
  OnIPAddressChanged();
}

AddressSorterPosix::~AddressSorterPosix() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  NetworkChangeNotifier::RemoveIPAddressObserver(this);
}

void AddressSorterPosix::Sort(const AddressList& list,
                              const CallbackType& callback) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  std::vector<std::unique_ptr<DestinationInfo>> sort_list;

  for (size_t i = 0; i < list.size(); ++i) {
    std::unique_ptr<DestinationInfo> info(new DestinationInfo());
    info->address = list[i].address();
    info->scope = GetScope(ipv4_scope_table_, info->address);
    info->precedence = GetPolicyValue(precedence_table_, info->address);
    info->label = GetPolicyValue(label_table_, info->address);

    // Each socket can only be bound once.
    std::unique_ptr<DatagramClientSocket> socket(
        socket_factory_->CreateDatagramClientSocket(
            DatagramSocket::DEFAULT_BIND, RandIntCallback(), NULL /* NetLog */,
            NetLogSource()));

    // Even though no packets are sent, cannot use port 0 in Connect.
    IPEndPoint dest(info->address, 80 /* port */);
    int rv = socket->Connect(dest);
    if (rv != OK) {
      VLOG(1) << "Could not connect to " << dest.ToStringWithoutPort()
              << " reason " << rv;
      continue;
    }
    // Filter out unusable destinations.
    IPEndPoint src;
    rv = socket->GetLocalAddress(&src);
    if (rv != OK) {
      LOG(WARNING) << "Could not get local address for "
                   << dest.ToStringWithoutPort() << " reason " << rv;
      continue;
    }

    SourceAddressInfo& src_info = source_map_[src.address()];
    if (src_info.scope == SCOPE_UNDEFINED) {
      // If |source_info_| is out of date, |src| might be missing, but we still
      // want to sort, even though the HostCache will be cleared soon.
      FillPolicy(src.address(), &src_info);
    }
    info->src = &src_info;

    if (info->address.size() == src.address().size()) {
      info->common_prefix_length =
          std::min(CommonPrefixLength(info->address, src.address()),
                   info->src->prefix_length);
    }
    sort_list.push_back(std::move(info));
  }

  std::stable_sort(sort_list.begin(), sort_list.end(), CompareDestinations);

  AddressList result;
  for (size_t i = 0; i < sort_list.size(); ++i)
    result.push_back(IPEndPoint(sort_list[i]->address, 0 /* port */));

  callback.Run(true, result);
}

void AddressSorterPosix::OnIPAddressChanged() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  source_map_.clear();
#if defined(OS_LINUX)
  const internal::AddressTrackerLinux* tracker =
      NetworkChangeNotifier::GetAddressTracker();
  if (!tracker)
    return;
  typedef internal::AddressTrackerLinux::AddressMap AddressMap;
  AddressMap map = tracker->GetAddressMap();
  for (AddressMap::const_iterator it = map.begin(); it != map.end(); ++it) {
    const IPAddress& address = it->first;
    const struct ifaddrmsg& msg = it->second;
    SourceAddressInfo& info = source_map_[address];
    info.native = false;  // TODO(szym): obtain this via netlink.
    info.deprecated = msg.ifa_flags & IFA_F_DEPRECATED;
    info.home = msg.ifa_flags & IFA_F_HOMEADDRESS;
    info.prefix_length = msg.ifa_prefixlen;
    FillPolicy(address, &info);
  }
#elif defined(OS_MACOSX) || defined(OS_BSD)
  // It's not clear we will receive notification when deprecated flag changes.
  // Socket for ioctl.
  int ioctl_socket = socket(AF_INET6, SOCK_DGRAM, 0);
  if (ioctl_socket < 0)
    return;

  struct ifaddrs* addrs;
  int rv = getifaddrs(&addrs);
  if (rv < 0) {
    LOG(WARNING) << "getifaddrs failed " << rv;
    close(ioctl_socket);
    return;
  }

  for (struct ifaddrs* ifa = addrs; ifa != NULL; ifa = ifa->ifa_next) {
    IPEndPoint src;
    if (!src.FromSockAddr(ifa->ifa_addr, ifa->ifa_addr->sa_len))
      continue;
    SourceAddressInfo& info = source_map_[src.address()];
    // Note: no known way to fill in |native| and |home|.
    info.native = info.home = info.deprecated = false;
    if (ifa->ifa_addr->sa_family == AF_INET6) {
      struct in6_ifreq ifr = {};
      strncpy(ifr.ifr_name, ifa->ifa_name, sizeof(ifr.ifr_name) - 1);
      DCHECK_LE(ifa->ifa_addr->sa_len, sizeof(ifr.ifr_ifru.ifru_addr));
      memcpy(&ifr.ifr_ifru.ifru_addr, ifa->ifa_addr, ifa->ifa_addr->sa_len);
      int rv = ioctl(ioctl_socket, SIOCGIFAFLAG_IN6, &ifr);
      if (rv >= 0) {
        info.deprecated = ifr.ifr_ifru.ifru_flags & IN6_IFF_DEPRECATED;
      } else {
        LOG(WARNING) << "SIOCGIFAFLAG_IN6 failed " << rv;
      }
    }
    if (ifa->ifa_netmask) {
      IPEndPoint netmask;
      if (netmask.FromSockAddr(ifa->ifa_netmask, ifa->ifa_addr->sa_len)) {
        info.prefix_length = MaskPrefixLength(netmask.address());
      } else {
        LOG(WARNING) << "FromSockAddr failed on netmask";
      }
    }
    FillPolicy(src.address(), &info);
  }
  freeifaddrs(addrs);
  close(ioctl_socket);
#endif
}

void AddressSorterPosix::FillPolicy(const IPAddress& address,
                                    SourceAddressInfo* info) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  info->scope = GetScope(ipv4_scope_table_, address);
  info->label = GetPolicyValue(label_table_, address);
}

// static
std::unique_ptr<AddressSorter> AddressSorter::CreateAddressSorter() {
  return std::unique_ptr<AddressSorter>(
      new AddressSorterPosix(ClientSocketFactory::GetDefaultFactory()));
}

}  // namespace net
