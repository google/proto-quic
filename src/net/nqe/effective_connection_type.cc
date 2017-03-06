// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/effective_connection_type.h"

#include "base/logging.h"

namespace {

const char kEffectiveConnectionTypeUnknown[] = "Unknown";
const char kEffectiveConnectionTypeOffline[] = "Offline";
const char kEffectiveConnectionTypeSlow2G[] = "Slow-2G";
const char kEffectiveConnectionType2G[] = "2G";
const char kEffectiveConnectionType3G[] = "3G";
const char kEffectiveConnectionType4G[] = "4G";
const char kDeprectedEffectiveConnectionTypeSlow2G[] = "Slow2G";

}  // namespace

namespace net {

const char* GetNameForEffectiveConnectionType(EffectiveConnectionType type) {
  switch (type) {
    case EFFECTIVE_CONNECTION_TYPE_UNKNOWN:
      return kEffectiveConnectionTypeUnknown;
    case EFFECTIVE_CONNECTION_TYPE_OFFLINE:
      return kEffectiveConnectionTypeOffline;
    case EFFECTIVE_CONNECTION_TYPE_SLOW_2G:
      return kEffectiveConnectionTypeSlow2G;
    case EFFECTIVE_CONNECTION_TYPE_2G:
      return kEffectiveConnectionType2G;
    case EFFECTIVE_CONNECTION_TYPE_3G:
      return kEffectiveConnectionType3G;
    case EFFECTIVE_CONNECTION_TYPE_4G:
      return kEffectiveConnectionType4G;
    case EFFECTIVE_CONNECTION_TYPE_LAST:
      NOTREACHED();
      return "";
  }
  NOTREACHED();
  return "";
}

bool GetEffectiveConnectionTypeForName(
    base::StringPiece connection_type_name,
    EffectiveConnectionType* effective_connection_type) {
  if (connection_type_name == kEffectiveConnectionTypeUnknown) {
    *effective_connection_type = EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
    return true;
  }
  if (connection_type_name == kEffectiveConnectionTypeOffline) {
    *effective_connection_type = EFFECTIVE_CONNECTION_TYPE_OFFLINE;
    return true;
  }
  if (connection_type_name == kEffectiveConnectionTypeSlow2G) {
    *effective_connection_type = EFFECTIVE_CONNECTION_TYPE_SLOW_2G;
    return true;
  }
  // Return EFFECTIVE_CONNECTION_TYPE_SLOW_2G if the deprecated string
  // representation is in use.
  if (connection_type_name == kDeprectedEffectiveConnectionTypeSlow2G) {
    *effective_connection_type = EFFECTIVE_CONNECTION_TYPE_SLOW_2G;
    return true;
  }
  if (connection_type_name == kEffectiveConnectionType2G) {
    *effective_connection_type = EFFECTIVE_CONNECTION_TYPE_2G;
    return true;
  }
  if (connection_type_name == kEffectiveConnectionType3G) {
    *effective_connection_type = EFFECTIVE_CONNECTION_TYPE_3G;
    return true;
  }
  if (connection_type_name == kEffectiveConnectionType4G) {
    *effective_connection_type = EFFECTIVE_CONNECTION_TYPE_4G;
    return true;
  }
  *effective_connection_type = EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
  return false;
}

const char* DeprecatedGetNameForEffectiveConnectionType(
    EffectiveConnectionType type) {
  switch (type) {
    case EFFECTIVE_CONNECTION_TYPE_SLOW_2G:
      return kDeprectedEffectiveConnectionTypeSlow2G;
    default:
      return GetNameForEffectiveConnectionType(type);
  }
}

}  // namespace net
