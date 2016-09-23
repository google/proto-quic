// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_EFFECTIVE_CONNECTION_TYPE_H_
#define NET_NQE_EFFECTIVE_CONNECTION_TYPE_H_

#include <string>

#include "net/base/net_export.h"

namespace net {

// EffectiveConnectionType is the connection type whose typical performance is
// most similar to the measured performance of the network in use. In many
// cases, the "effective" connection type and the actual type of connection in
// use are the same, but often a network connection performs significantly
// differently, usually worse, from its expected capabilities.
// EffectiveConnectionType of a network is independent of if the current
// connection is metered or not. For example, an unmetered slow connection may
// have EFFECTIVE_CONNECTION_TYPE_SLOW_2G as its effective connection type. The
// effective connection type enums are be in increasing order of quality.
// GENERATED_JAVA_ENUM_PACKAGE: org.chromium.net
// GENERATED_JAVA_PREFIX_TO_STRIP: EFFECTIVE_CONNECTION_
enum EffectiveConnectionType {
  // Effective connection type reported when the network quality is unknown.
  EFFECTIVE_CONNECTION_TYPE_UNKNOWN = 0,

  // Effective connection type reported when the Internet is unreachable, either
  // because the device does not have a connection or because the
  // connection is too slow to be usable.
  EFFECTIVE_CONNECTION_TYPE_OFFLINE,

  // Effective connection type reported when the network has the quality of a
  // poor 2G connection.
  EFFECTIVE_CONNECTION_TYPE_SLOW_2G,

  // Effective connection type reported when the network has the quality of a
  // faster 2G connection.
  EFFECTIVE_CONNECTION_TYPE_2G,

  // Effective connection type reported when the network has the quality of a 3G
  // connection.
  EFFECTIVE_CONNECTION_TYPE_3G,

  // Effective connection type reported when the network has the quality of a 4G
  // connection.
  EFFECTIVE_CONNECTION_TYPE_4G,

  // Last value of the effective connection type. This value is unused.
  EFFECTIVE_CONNECTION_TYPE_LAST,
};

// Returns the string equivalent of |type|.
NET_EXPORT const char* GetNameForEffectiveConnectionType(
    EffectiveConnectionType type);

// Returns true if the EffectiveConnectionType that corresponds to
// |connection_type_name| is available, and sets |effective_connection_type| to
// that value. If the effective connection type is unavailable, false is
// returned, and |effective_connection_type| is set to
// EFFECTIVE_CONNECTION_TYPE_UNKNOWN. |effective_connection_type| must be
// non-null.
NET_EXPORT bool GetEffectiveConnectionTypeForName(
    const std::string& connection_type_name,
    EffectiveConnectionType* effective_connection_type);

}  // namespace net

#endif  // NET_NQE_EFFECTIVE_CONNECTION_TYPE_H_
