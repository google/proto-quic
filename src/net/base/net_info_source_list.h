// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file intentionally does not have header guards, it's included
// inside a macro to generate enum values.

// Flags used to request different types of information about the current state
// of a URLRequestContext.
//
// The strings don't match the enums for historical reasons.

NET_INFO_SOURCE(PROXY_SETTINGS, "proxySettings",                         1 << 0)
NET_INFO_SOURCE(BAD_PROXIES, "badProxies",                               1 << 1)
NET_INFO_SOURCE(HOST_RESOLVER, "hostResolverInfo",                       1 << 2)
NET_INFO_SOURCE(SOCKET_POOL, "socketPoolInfo",                           1 << 3)
NET_INFO_SOURCE(QUIC, "quicInfo",                                        1 << 4)
NET_INFO_SOURCE(SPDY_SESSIONS, "spdySessionInfo",                        1 << 5)
NET_INFO_SOURCE(SPDY_STATUS, "spdyStatus",                               1 << 6)
NET_INFO_SOURCE(ALT_SVC_MAPPINGS, "altSvcMappings", 1 << 7)
NET_INFO_SOURCE(HTTP_CACHE, "httpCacheInfo",                             1 << 8)
NET_INFO_SOURCE(SDCH, "sdchInfo",                                        1 << 9)
