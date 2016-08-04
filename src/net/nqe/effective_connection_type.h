// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_EFFECTIVE_CONNECTION_TYPE_H_
#define NET_NQE_EFFECTIVE_CONNECTION_TYPE_H_

namespace net {

// EffectiveConnectionType is the connection type whose typical performance is
// most similar to the measured performance of the network in use. In many
// cases, the "effective" connection type and the actual type of connection in
// use are the same, but often a network connection performs significantly
// differently, usually worse, from its expected capabilities.
// EffectiveConnectionType of a network is independent of if the current
// connection is metered or not. For example, an unmetered slow connection may
// have EFFECTIVE_CONNECTION_TYPE_SLOW_2G as its effective connection type.
enum EffectiveConnectionType {
  // The connection types should be in increasing order of quality.
  EFFECTIVE_CONNECTION_TYPE_UNKNOWN = 0,
  EFFECTIVE_CONNECTION_TYPE_OFFLINE,
  EFFECTIVE_CONNECTION_TYPE_SLOW_2G,
  EFFECTIVE_CONNECTION_TYPE_2G,
  EFFECTIVE_CONNECTION_TYPE_3G,
  EFFECTIVE_CONNECTION_TYPE_4G,
  EFFECTIVE_CONNECTION_TYPE_BROADBAND,
  EFFECTIVE_CONNECTION_TYPE_LAST,
};

}  // namespace net

#endif  // NET_NQE_EFFECTIVE_CONNECTION_TYPE_H_
