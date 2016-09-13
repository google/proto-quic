// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DNS_DNS_UTIL_H_
#define NET_DNS_DNS_UTIL_H_

#include <string>

#include "base/strings/string_piece.h"
#include "base/time/time.h"
#include "net/base/net_export.h"
#include "net/base/network_change_notifier.h"

namespace net {

class AddressList;

// DNSDomainFromDot - convert a domain string to DNS format. From DJB's
// public domain DNS library.
//
//   dotted: a string in dotted form: "www.google.com"
//   out: a result in DNS form: "\x03www\x06google\x03com\x00"
NET_EXPORT_PRIVATE bool DNSDomainFromDot(const base::StringPiece& dotted,
                                         std::string* out);

// Checks that a hostname is valid. Simple wrapper around DNSDomainFromDot.
NET_EXPORT_PRIVATE bool IsValidDNSDomain(const base::StringPiece& dotted);

// DNSDomainToString converts a domain in DNS format to a dotted string.
// Excludes the dot at the end.
NET_EXPORT_PRIVATE std::string DNSDomainToString(
    const base::StringPiece& domain);

// Returns true if it can determine that only loopback addresses are configured.
// i.e. if only 127.0.0.1 and ::1 are routable.
// Also returns false if it cannot determine this.
NET_EXPORT_PRIVATE bool HaveOnlyLoopbackAddresses();

#if !defined(OS_NACL)
NET_EXPORT_PRIVATE
base::TimeDelta GetTimeDeltaForConnectionTypeFromFieldTrialOrDefault(
    const char* field_trial_name,
    base::TimeDelta default_delta,
    NetworkChangeNotifier::ConnectionType connection_type);
#endif  // !defined(OS_NACL)

// How similar or different two AddressLists are (see values for details).
// Used in histograms; do not modify existing values.
enum AddressListDeltaType {
  // Both lists contain the same addresses in the same order.
  DELTA_IDENTICAL = 0,
  // Both lists contain the same addresses in a different order.
  DELTA_REORDERED = 1,
  // The two lists have at least one address in common, but not all of them.
  DELTA_OVERLAP = 2,
  // The two lists have no addresses in common.
  DELTA_DISJOINT = 3,
  MAX_DELTA_TYPE
};

// Compares two AddressLists to see how similar or different their addresses
// are. (See |AddressListDeltaType| for details of exactly what's checked.)
AddressListDeltaType FindAddressListDeltaType(const AddressList& a,
                                              const AddressList& b);

}  // namespace net

#endif  // NET_DNS_DNS_UTIL_H_
