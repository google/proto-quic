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

// DNSDomainFromDot - convert a domain string to DNS format. From DJB's
// public domain DNS library.
//
//   dotted: a string in dotted form: "www.google.com"
//   out: a result in DNS form: "\x03www\x06google\x03com\x00"
NET_EXPORT_PRIVATE bool DNSDomainFromDot(const base::StringPiece& dotted,
                                         std::string* out);

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

}  // namespace net

#endif  // NET_DNS_DNS_UTIL_H_
