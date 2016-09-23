// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/network_interfaces.h"

#include <ostream>
#include <string>
#include <unordered_set>

// TODO(eroman): Remove unneeeded headers.
#include "base/files/file_path.h"
#include "base/format_macros.h"
#include "base/scoped_native_library.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/sys_byteorder.h"
#include "base/time/time.h"
#include "net/base/ip_endpoint.h"

#if !defined(OS_NACL) && !defined(OS_WIN)
#include <net/if.h>
#include <netinet/in.h>
#if defined(OS_MACOSX)
#include <ifaddrs.h>
#if !defined(OS_IOS)
#include <netinet/in_var.h>
#endif  // !OS_IOS
#endif  // OS_MACOSX
#endif  // !OS_NACL && !OS_WIN
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

#if defined(OS_WIN)
#include <iphlpapi.h>
#include <objbase.h>
#endif  // OS_WIN

#if !defined(OS_MACOSX) && !defined(OS_NACL) && !defined(OS_WIN)
#include "net/base/address_tracker_linux.h"
#endif  // !OS_MACOSX && !OS_NACL && !OS_WIN

#if defined(OS_WIN)
#include "net/base/network_interfaces_win.h"
#else  // OS_WIN
#include "net/base/network_interfaces_posix.h"
#if defined(OS_MACOSX)
#include "net/base/network_interfaces_mac.h"
#else  // OS_MACOSX
#include "net/base/network_interfaces_linux.h"
#endif  // OS_MACOSX
#endif  // OS_WIN

namespace net {

namespace {

#if defined(OS_LINUX) || defined(OS_ANDROID) || defined(OS_CHROMEOS)
const char kWiFiSSID[] = "TestWiFi";
const char kInterfaceWithDifferentSSID[] = "wlan999";

std::string TestGetInterfaceSSID(const std::string& ifname) {
  return (ifname == kInterfaceWithDifferentSSID) ? "AnotherSSID" : kWiFiSSID;
}
#endif

#if defined(OS_MACOSX)
class IPAttributesGetterTest : public internal::IPAttributesGetterMac {
 public:
  IPAttributesGetterTest() : native_attributes_(0) {}
  bool IsInitialized() const override { return true; }
  bool GetIPAttributes(const char* ifname,
                       const sockaddr* sock_addr,
                       int* native_attributes) override {
    *native_attributes = native_attributes_;
    return true;
  }
  void set_native_attributes(int native_attributes) {
    native_attributes_ = native_attributes;
  }

 private:
  int native_attributes_;
};

// Helper function to create a single valid ifaddrs
bool FillIfaddrs(ifaddrs* interfaces,
                 const char* ifname,
                 uint flags,
                 const IPAddress& ip_address,
                 const IPAddress& ip_netmask,
                 sockaddr_storage sock_addrs[2]) {
  interfaces->ifa_next = NULL;
  interfaces->ifa_name = const_cast<char*>(ifname);
  interfaces->ifa_flags = flags;

  socklen_t sock_len = sizeof(sockaddr_storage);

  // Convert to sockaddr for next check.
  if (!IPEndPoint(ip_address, 0)
           .ToSockAddr(reinterpret_cast<sockaddr*>(&sock_addrs[0]),
                       &sock_len)) {
    return false;
  }
  interfaces->ifa_addr = reinterpret_cast<sockaddr*>(&sock_addrs[0]);

  sock_len = sizeof(sockaddr_storage);
  if (!IPEndPoint(ip_netmask, 0)
           .ToSockAddr(reinterpret_cast<sockaddr*>(&sock_addrs[1]),
                       &sock_len)) {
    return false;
  }
  interfaces->ifa_netmask = reinterpret_cast<sockaddr*>(&sock_addrs[1]);

  return true;
}
#endif  // OS_MACOSX

// Verify GetNetworkList().
TEST(NetworkInterfacesTest, GetNetworkList) {
  NetworkInterfaceList list;
  ASSERT_TRUE(GetNetworkList(&list, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES));
  for (NetworkInterfaceList::iterator it = list.begin();
       it != list.end(); ++it) {
    // Verify that the names are not empty.
    EXPECT_FALSE(it->name.empty());
    EXPECT_FALSE(it->friendly_name.empty());

    // Verify that the address is correct.
    EXPECT_TRUE(it->address.IsValid()) << "Invalid address of size "
                                       << it->address.size();
    EXPECT_FALSE(it->address.IsZero());
    EXPECT_GT(it->prefix_length, 1u);
    EXPECT_LE(it->prefix_length, it->address.size() * 8);

#if defined(OS_WIN)
    // On Windows |name| is NET_LUID.
    NET_LUID luid;
    EXPECT_EQ(static_cast<DWORD>(NO_ERROR),
              ConvertInterfaceIndexToLuid(it->interface_index, &luid));
    GUID guid;
    EXPECT_EQ(static_cast<DWORD>(NO_ERROR),
              ConvertInterfaceLuidToGuid(&luid, &guid));
    LPOLESTR name;
    StringFromCLSID(guid, &name);
    EXPECT_STREQ(base::UTF8ToWide(it->name).c_str(), name);
    CoTaskMemFree(name);

    if (it->type == NetworkChangeNotifier::CONNECTION_WIFI) {
      EXPECT_NE(WIFI_PHY_LAYER_PROTOCOL_NONE, GetWifiPHYLayerProtocol());
    }
#elif !defined(OS_ANDROID)
    char name[IF_NAMESIZE];
    EXPECT_TRUE(if_indextoname(it->interface_index, name));
    EXPECT_STREQ(it->name.c_str(), name);
#endif
  }
}

static const char ifname_em1[] = "em1";
#if defined(OS_WIN)
static const char ifname_vm[] = "VMnet";
#else
static const char ifname_vm[] = "vmnet";
#endif  // OS_WIN

static const unsigned char kIPv6LocalAddr[] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

// The following 3 addresses need to be changed together. IPv6Addr is the IPv6
// address. IPv6Netmask is the mask address with as many leading bits set to 1
// as the prefix length. IPv6AddrPrefix needs to match IPv6Addr with the same
// number of bits as the prefix length.
static const unsigned char kIPv6Addr[] =
  {0x24, 0x01, 0xfa, 0x00, 0x00, 0x04, 0x10, 0x00, 0xbe, 0x30, 0x5b, 0xff,
   0xfe, 0xe5, 0x00, 0xc3};
#if defined(OS_WIN)
static const unsigned char kIPv6AddrPrefix[] =
  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00};
#endif  // OS_WIN
#if defined(OS_MACOSX)
static const unsigned char kIPv6Netmask[] =
  {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00};
#endif  // OS_MACOSX

#if !defined(OS_MACOSX) && !defined(OS_WIN) && !defined(OS_NACL)

char* CopyInterfaceName(const char* ifname, int ifname_size, char* output) {
  EXPECT_LT(ifname_size, IF_NAMESIZE);
  memcpy(output, ifname, ifname_size);
  return output;
}

char* GetInterfaceName(int interface_index, char* ifname) {
  return CopyInterfaceName(ifname_em1, arraysize(ifname_em1), ifname);
}

char* GetInterfaceNameVM(int interface_index, char* ifname) {
  return CopyInterfaceName(ifname_vm, arraysize(ifname_vm), ifname);
}

TEST(NetworkInterfacesTest, GetNetworkListTrimming) {
  IPAddress ipv6_local_address(kIPv6LocalAddr);
  IPAddress ipv6_address(kIPv6Addr);

  NetworkInterfaceList results;
  std::unordered_set<int> online_links;
  internal::AddressTrackerLinux::AddressMap address_map;

  // Interface 1 is offline.
  struct ifaddrmsg msg = {
      AF_INET6,
      1,               /* prefix length */
      IFA_F_TEMPORARY, /* address flags */
      0,               /* link scope */
      1                /* link index */
  };

  // Address of offline links should be ignored.
  ASSERT_TRUE(address_map.insert(std::make_pair(ipv6_address, msg)).second);
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, online_links,
      address_map, GetInterfaceName));
  EXPECT_EQ(results.size(), 0ul);

  // Mark interface 1 online.
  online_links.insert(1);

  // Local address should be trimmed out.
  address_map.clear();
  ASSERT_TRUE(
      address_map.insert(std::make_pair(ipv6_local_address, msg)).second);
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, online_links,
      address_map, GetInterfaceName));
  EXPECT_EQ(results.size(), 0ul);

  // vmware address should return by default.
  address_map.clear();
  ASSERT_TRUE(address_map.insert(std::make_pair(ipv6_address, msg)).second);
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, online_links,
      address_map, GetInterfaceNameVM));
  EXPECT_EQ(results.size(), 1ul);
  EXPECT_EQ(results[0].name, ifname_vm);
  EXPECT_EQ(results[0].prefix_length, 1ul);
  EXPECT_EQ(results[0].address, ipv6_address);
  results.clear();

  // vmware address should be trimmed out if policy specified so.
  address_map.clear();
  ASSERT_TRUE(address_map.insert(std::make_pair(ipv6_address, msg)).second);
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, EXCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, online_links,
      address_map, GetInterfaceNameVM));
  EXPECT_EQ(results.size(), 0ul);
  results.clear();

  // Addresses with banned attributes should be ignored.
  address_map.clear();
  msg.ifa_flags = IFA_F_TENTATIVE;
  ASSERT_TRUE(address_map.insert(std::make_pair(ipv6_address, msg)).second);
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, online_links,
      address_map, GetInterfaceName));
  EXPECT_EQ(results.size(), 0ul);
  results.clear();

  // Addresses with allowed attribute IFA_F_TEMPORARY should be returned and
  // attributes should be translated correctly.
  address_map.clear();
  msg.ifa_flags = IFA_F_TEMPORARY;
  ASSERT_TRUE(address_map.insert(std::make_pair(ipv6_address, msg)).second);
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, online_links,
      address_map, GetInterfaceName));
  EXPECT_EQ(results.size(), 1ul);
  EXPECT_EQ(results[0].name, ifname_em1);
  EXPECT_EQ(results[0].prefix_length, 1ul);
  EXPECT_EQ(results[0].address, ipv6_address);
  EXPECT_EQ(results[0].ip_address_attributes, IP_ADDRESS_ATTRIBUTE_TEMPORARY);
  results.clear();

  // Addresses with allowed attribute IFA_F_DEPRECATED should be returned and
  // attributes should be translated correctly.
  address_map.clear();
  msg.ifa_flags = IFA_F_DEPRECATED;
  ASSERT_TRUE(address_map.insert(std::make_pair(ipv6_address, msg)).second);
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, online_links,
      address_map, GetInterfaceName));
  EXPECT_EQ(results.size(), 1ul);
  EXPECT_EQ(results[0].name, ifname_em1);
  EXPECT_EQ(results[0].prefix_length, 1ul);
  EXPECT_EQ(results[0].address, ipv6_address);
  EXPECT_EQ(results[0].ip_address_attributes, IP_ADDRESS_ATTRIBUTE_DEPRECATED);
  results.clear();
}

#elif defined(OS_MACOSX)

TEST(NetworkInterfacesTest, GetNetworkListTrimming) {
  IPAddress ipv6_local_address(kIPv6LocalAddr);
  IPAddress ipv6_address(kIPv6Addr);
  IPAddress ipv6_netmask(kIPv6Netmask);

  NetworkInterfaceList results;
  IPAttributesGetterTest ip_attributes_getter;
  sockaddr_storage addresses[2];
  ifaddrs interface;

  // Address of offline links should be ignored.
  ASSERT_TRUE(FillIfaddrs(&interface, ifname_em1, IFF_UP, ipv6_address,
                          ipv6_netmask, addresses));
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &interface,
      &ip_attributes_getter));
  EXPECT_EQ(results.size(), 0ul);

  // Local address should be trimmed out.
  ASSERT_TRUE(FillIfaddrs(&interface, ifname_em1, IFF_RUNNING,
                          ipv6_local_address, ipv6_netmask, addresses));
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &interface,
      &ip_attributes_getter));
  EXPECT_EQ(results.size(), 0ul);

  // vmware address should return by default.
  ASSERT_TRUE(FillIfaddrs(&interface, ifname_vm, IFF_RUNNING, ipv6_address,
                          ipv6_netmask, addresses));
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &interface,
      &ip_attributes_getter));
  EXPECT_EQ(results.size(), 1ul);
  EXPECT_EQ(results[0].name, ifname_vm);
  EXPECT_EQ(results[0].prefix_length, 1ul);
  EXPECT_EQ(results[0].address, ipv6_address);
  results.clear();

  // vmware address should be trimmed out if policy specified so.
  ASSERT_TRUE(FillIfaddrs(&interface, ifname_vm, IFF_RUNNING, ipv6_address,
                          ipv6_netmask, addresses));
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, EXCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &interface,
      &ip_attributes_getter));
  EXPECT_EQ(results.size(), 0ul);
  results.clear();

#if !defined(OS_IOS)
  // Addresses with banned attributes should be ignored.
  ip_attributes_getter.set_native_attributes(IN6_IFF_ANYCAST);
  ASSERT_TRUE(FillIfaddrs(&interface, ifname_em1, IFF_RUNNING, ipv6_address,
                          ipv6_netmask, addresses));
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &interface,
      &ip_attributes_getter));
  EXPECT_EQ(results.size(), 0ul);
  results.clear();

  // Addresses with allowed attribute IFA_F_TEMPORARY should be returned and
  // attributes should be translated correctly.
  ip_attributes_getter.set_native_attributes(IN6_IFF_TEMPORARY);
  ASSERT_TRUE(FillIfaddrs(&interface, ifname_em1, IFF_RUNNING, ipv6_address,
                          ipv6_netmask, addresses));
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &interface,
      &ip_attributes_getter));
  EXPECT_EQ(results.size(), 1ul);
  EXPECT_EQ(results[0].name, ifname_em1);
  EXPECT_EQ(results[0].prefix_length, 1ul);
  EXPECT_EQ(results[0].address, ipv6_address);
  EXPECT_EQ(results[0].ip_address_attributes, IP_ADDRESS_ATTRIBUTE_TEMPORARY);
  results.clear();

  // Addresses with allowed attribute IFA_F_DEPRECATED should be returned and
  // attributes should be translated correctly.
  ip_attributes_getter.set_native_attributes(IN6_IFF_DEPRECATED);
  ASSERT_TRUE(FillIfaddrs(&interface, ifname_em1, IFF_RUNNING, ipv6_address,
                          ipv6_netmask, addresses));
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &interface,
      &ip_attributes_getter));
  EXPECT_EQ(results.size(), 1ul);
  EXPECT_EQ(results[0].name, ifname_em1);
  EXPECT_EQ(results[0].prefix_length, 1ul);
  EXPECT_EQ(results[0].address, ipv6_address);
  EXPECT_EQ(results[0].ip_address_attributes, IP_ADDRESS_ATTRIBUTE_DEPRECATED);
  results.clear();
#endif  // !OS_IOS
}
#elif defined(OS_WIN)  // !OS_MACOSX && !OS_WIN && !OS_NACL

// Helper function to create a valid IP_ADAPTER_ADDRESSES with reasonable
// default value. The output is the |adapter_address|. All the rests are input
// to fill the |adapter_address|. |sock_addrs| are temporary storage used by
// |adapter_address| once the function is returned.
bool FillAdapterAddress(IP_ADAPTER_ADDRESSES* adapter_address,
                        const char* ifname,
                        const IPAddress& ip_address,
                        const IPAddress& ip_netmask,
                        sockaddr_storage sock_addrs[2]) {
  adapter_address->AdapterName = const_cast<char*>(ifname);
  adapter_address->FriendlyName = const_cast<PWCHAR>(L"interface");
  adapter_address->IfType = IF_TYPE_ETHERNET_CSMACD;
  adapter_address->OperStatus = IfOperStatusUp;
  adapter_address->FirstUnicastAddress->DadState = IpDadStatePreferred;
  adapter_address->FirstUnicastAddress->PrefixOrigin = IpPrefixOriginOther;
  adapter_address->FirstUnicastAddress->SuffixOrigin = IpSuffixOriginOther;
  adapter_address->FirstUnicastAddress->PreferredLifetime = 100;
  adapter_address->FirstUnicastAddress->ValidLifetime = 1000;

  socklen_t sock_len = sizeof(sockaddr_storage);

  // Convert to sockaddr for next check.
  if (!IPEndPoint(ip_address, 0)
           .ToSockAddr(reinterpret_cast<sockaddr*>(&sock_addrs[0]),
                       &sock_len)) {
    return false;
  }
  adapter_address->FirstUnicastAddress->Address.lpSockaddr =
      reinterpret_cast<sockaddr*>(&sock_addrs[0]);
  adapter_address->FirstUnicastAddress->Address.iSockaddrLength = sock_len;
  adapter_address->FirstUnicastAddress->OnLinkPrefixLength = 1;

  sock_len = sizeof(sockaddr_storage);
  if (!IPEndPoint(ip_netmask, 0)
           .ToSockAddr(reinterpret_cast<sockaddr*>(&sock_addrs[1]),
                       &sock_len)) {
    return false;
  }
  adapter_address->FirstPrefix->Address.lpSockaddr =
      reinterpret_cast<sockaddr*>(&sock_addrs[1]);
  adapter_address->FirstPrefix->Address.iSockaddrLength = sock_len;
  adapter_address->FirstPrefix->PrefixLength = 1;

  DCHECK_EQ(sock_addrs[0].ss_family, sock_addrs[1].ss_family);
  if (sock_addrs[0].ss_family == AF_INET6) {
    adapter_address->Ipv6IfIndex = 0;
  } else {
    DCHECK_EQ(sock_addrs[0].ss_family, AF_INET);
    adapter_address->IfIndex = 0;
  }

  return true;
}

TEST(NetworkInterfacesTest, GetNetworkListTrimming) {
  IPAddress ipv6_local_address(kIPv6LocalAddr);
  IPAddress ipv6_address(kIPv6Addr);
  IPAddress ipv6_prefix(kIPv6AddrPrefix);

  NetworkInterfaceList results;
  sockaddr_storage addresses[2];
  IP_ADAPTER_ADDRESSES adapter_address = {};
  IP_ADAPTER_UNICAST_ADDRESS address = {};
  IP_ADAPTER_PREFIX adapter_prefix = {};
  adapter_address.FirstUnicastAddress = &address;
  adapter_address.FirstPrefix = &adapter_prefix;

  // Address of offline links should be ignored.
  ASSERT_TRUE(FillAdapterAddress(
      &adapter_address /* adapter_address */, ifname_em1 /* ifname */,
      ipv6_address /* ip_address */, ipv6_prefix /* ip_netmask */,
      addresses /* sock_addrs */));
  adapter_address.OperStatus = IfOperStatusDown;

  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));

  EXPECT_EQ(results.size(), 0ul);

  // Address on loopback interface should be trimmed out.
  ASSERT_TRUE(FillAdapterAddress(
      &adapter_address /* adapter_address */, ifname_em1 /* ifname */,
      ipv6_local_address /* ip_address */, ipv6_prefix /* ip_netmask */,
      addresses /* sock_addrs */));
  adapter_address.IfType = IF_TYPE_SOFTWARE_LOOPBACK;

  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));
  EXPECT_EQ(results.size(), 0ul);

  // vmware address should return by default.
  ASSERT_TRUE(FillAdapterAddress(
      &adapter_address /* adapter_address */, ifname_vm /* ifname */,
      ipv6_address /* ip_address */, ipv6_prefix /* ip_netmask */,
      addresses /* sock_addrs */));
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));
  EXPECT_EQ(results.size(), 1ul);
  EXPECT_EQ(results[0].name, ifname_vm);
  EXPECT_EQ(results[0].prefix_length, 1ul);
  EXPECT_EQ(results[0].address, ipv6_address);
  EXPECT_EQ(results[0].ip_address_attributes, IP_ADDRESS_ATTRIBUTE_NONE);
  results.clear();

  // vmware address should be trimmed out if policy specified so.
  ASSERT_TRUE(FillAdapterAddress(
      &adapter_address /* adapter_address */, ifname_vm /* ifname */,
      ipv6_address /* ip_address */, ipv6_prefix /* ip_netmask */,
      addresses /* sock_addrs */));
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, EXCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));
  EXPECT_EQ(results.size(), 0ul);
  results.clear();

  // Addresses with incompleted DAD should be ignored.
  ASSERT_TRUE(FillAdapterAddress(
      &adapter_address /* adapter_address */, ifname_em1 /* ifname */,
      ipv6_address /* ip_address */, ipv6_prefix /* ip_netmask */,
      addresses /* sock_addrs */));
  adapter_address.FirstUnicastAddress->DadState = IpDadStateTentative;

  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));
  EXPECT_EQ(results.size(), 0ul);
  results.clear();

  // Addresses with allowed attribute IpSuffixOriginRandom should be returned
  // and attributes should be translated correctly to
  // IP_ADDRESS_ATTRIBUTE_TEMPORARY.
  ASSERT_TRUE(FillAdapterAddress(
      &adapter_address /* adapter_address */, ifname_em1 /* ifname */,
      ipv6_address /* ip_address */, ipv6_prefix /* ip_netmask */,
      addresses /* sock_addrs */));
  adapter_address.FirstUnicastAddress->PrefixOrigin =
      IpPrefixOriginRouterAdvertisement;
  adapter_address.FirstUnicastAddress->SuffixOrigin = IpSuffixOriginRandom;

  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));
  EXPECT_EQ(results.size(), 1ul);
  EXPECT_EQ(results[0].name, ifname_em1);
  EXPECT_EQ(results[0].prefix_length, 1ul);
  EXPECT_EQ(results[0].address, ipv6_address);
  EXPECT_EQ(results[0].ip_address_attributes, IP_ADDRESS_ATTRIBUTE_TEMPORARY);
  results.clear();

  // Addresses with preferred lifetime 0 should be returned and
  // attributes should be translated correctly to
  // IP_ADDRESS_ATTRIBUTE_DEPRECATED.
  ASSERT_TRUE(FillAdapterAddress(
      &adapter_address /* adapter_address */, ifname_em1 /* ifname */,
      ipv6_address /* ip_address */, ipv6_prefix /* ip_netmask */,
      addresses /* sock_addrs */));
  adapter_address.FirstUnicastAddress->PreferredLifetime = 0;
  adapter_address.FriendlyName = const_cast<PWCHAR>(L"FriendlyInterfaceName");
  EXPECT_TRUE(internal::GetNetworkListImpl(
      &results, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES, &adapter_address));
  EXPECT_EQ(results.size(), 1ul);
  EXPECT_EQ(results[0].friendly_name, "FriendlyInterfaceName");
  EXPECT_EQ(results[0].name, ifname_em1);
  EXPECT_EQ(results[0].prefix_length, 1ul);
  EXPECT_EQ(results[0].address, ipv6_address);
  EXPECT_EQ(results[0].ip_address_attributes, IP_ADDRESS_ATTRIBUTE_DEPRECATED);
  results.clear();
}

#endif  // !OS_MACOSX && !OS_WIN && !OS_NACL

TEST(NetworkInterfacesTest, GetWifiSSID) {
  // We can't check the result of GetWifiSSID() directly, since the result
  // will differ across machines. Simply exercise the code path and hope that it
  // doesn't crash.
  EXPECT_NE((const char*)NULL, GetWifiSSID().c_str());
}

#if defined(OS_LINUX) || defined(OS_ANDROID) || defined(OS_CHROMEOS)
TEST(NetworkInterfacesTest, GetWifiSSIDFromInterfaceList) {
  NetworkInterfaceList list;
  EXPECT_EQ(std::string(), internal::GetWifiSSIDFromInterfaceListInternal(
                               list, TestGetInterfaceSSID));

  NetworkInterface interface1;
  interface1.name = "wlan0";
  interface1.type = NetworkChangeNotifier::CONNECTION_WIFI;
  list.push_back(interface1);
  ASSERT_EQ(1u, list.size());
  EXPECT_EQ(std::string(kWiFiSSID),
            internal::GetWifiSSIDFromInterfaceListInternal(
                list, TestGetInterfaceSSID));

  NetworkInterface interface2;
  interface2.name = "wlan1";
  interface2.type = NetworkChangeNotifier::CONNECTION_WIFI;
  list.push_back(interface2);
  ASSERT_EQ(2u, list.size());
  EXPECT_EQ(std::string(kWiFiSSID),
            internal::GetWifiSSIDFromInterfaceListInternal(
                list, TestGetInterfaceSSID));

  NetworkInterface interface3;
  interface3.name = kInterfaceWithDifferentSSID;
  interface3.type = NetworkChangeNotifier::CONNECTION_WIFI;
  list.push_back(interface3);
  ASSERT_EQ(3u, list.size());
  EXPECT_EQ(std::string(), internal::GetWifiSSIDFromInterfaceListInternal(
                               list, TestGetInterfaceSSID));

  list.pop_back();
  NetworkInterface interface4;
  interface4.name = "eth0";
  interface4.type = NetworkChangeNotifier::CONNECTION_ETHERNET;
  list.push_back(interface4);
  ASSERT_EQ(3u, list.size());
  EXPECT_EQ(std::string(), internal::GetWifiSSIDFromInterfaceListInternal(
                               list, TestGetInterfaceSSID));
}
#endif  // OS_LINUX

#if defined(OS_WIN)
bool read_int_or_bool(DWORD data_size,
                      PVOID data) {
  switch (data_size) {
    case 1:
      return !!*reinterpret_cast<uint8_t*>(data);
    case 4:
      return !!*reinterpret_cast<uint32_t*>(data);
    default:
      LOG(FATAL) << "That is not a type I know!";
      return false;
  }
}

int GetWifiOptions() {
  const internal::WlanApi& wlanapi = internal::WlanApi::GetInstance();
  if (!wlanapi.initialized)
    return -1;

  internal::WlanHandle client;
  DWORD cur_version = 0;
  const DWORD kMaxClientVersion = 2;
  DWORD result = wlanapi.OpenHandle(
      kMaxClientVersion, &cur_version, &client);
  if (result != ERROR_SUCCESS)
    return -1;

  WLAN_INTERFACE_INFO_LIST* interface_list_ptr = NULL;
  result = wlanapi.enum_interfaces_func(client.Get(), NULL,
                                        &interface_list_ptr);
  if (result != ERROR_SUCCESS)
    return -1;
  std::unique_ptr<WLAN_INTERFACE_INFO_LIST, internal::WlanApiDeleter>
      interface_list(interface_list_ptr);

  for (unsigned i = 0; i < interface_list->dwNumberOfItems; ++i) {
    WLAN_INTERFACE_INFO* info = &interface_list->InterfaceInfo[i];
    DWORD data_size;
    PVOID data;
    int options = 0;
    result = wlanapi.query_interface_func(
        client.Get(),
        &info->InterfaceGuid,
        wlan_intf_opcode_background_scan_enabled,
        NULL,
        &data_size,
        &data,
        NULL);
    if (result != ERROR_SUCCESS)
      continue;
    if (!read_int_or_bool(data_size, data)) {
      options |= WIFI_OPTIONS_DISABLE_SCAN;
    }
    internal::WlanApi::GetInstance().free_memory_func(data);

    result = wlanapi.query_interface_func(
        client.Get(),
        &info->InterfaceGuid,
        wlan_intf_opcode_media_streaming_mode,
        NULL,
        &data_size,
        &data,
        NULL);
    if (result != ERROR_SUCCESS)
      continue;
    if (read_int_or_bool(data_size, data)) {
      options |= WIFI_OPTIONS_MEDIA_STREAMING_MODE;
    }
    internal::WlanApi::GetInstance().free_memory_func(data);

    // Just the the options from the first succesful
    // interface.
    return options;
  }

  // No wifi interface found.
  return -1;
}

#else  // OS_WIN

int GetWifiOptions() {
  // Not supported.
  return -1;
}

#endif  // OS_WIN

void TryChangeWifiOptions(int options) {
  int previous_options = GetWifiOptions();
  std::unique_ptr<ScopedWifiOptions> scoped_options = SetWifiOptions(options);
  EXPECT_EQ(previous_options | options, GetWifiOptions());
  scoped_options.reset();
  EXPECT_EQ(previous_options, GetWifiOptions());
}

// Test SetWifiOptions().
TEST(NetworkInterfacesTest, SetWifiOptionsTest) {
  TryChangeWifiOptions(0);
  TryChangeWifiOptions(WIFI_OPTIONS_DISABLE_SCAN);
  TryChangeWifiOptions(WIFI_OPTIONS_MEDIA_STREAMING_MODE);
  TryChangeWifiOptions(WIFI_OPTIONS_DISABLE_SCAN |
                       WIFI_OPTIONS_MEDIA_STREAMING_MODE);
}

TEST(NetworkInterfacesTest, GetHostName) {
  // We can't check the result of GetHostName() directly, since the result
  // will differ across machines. Our goal here is to simply exercise the
  // code path, and check that things "look about right".
  std::string hostname = GetHostName();
  EXPECT_FALSE(hostname.empty());
}

}  // namespace

}  // namespace net
