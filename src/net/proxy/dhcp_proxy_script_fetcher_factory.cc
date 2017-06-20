// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/dhcp_proxy_script_fetcher_factory.h"

#include "base/memory/ptr_util.h"
#include "net/base/net_errors.h"
#include "net/proxy/dhcp_proxy_script_fetcher.h"

#if defined(OS_WIN)
#include "net/proxy/dhcp_proxy_script_fetcher_win.h"
#endif

namespace net {

DhcpProxyScriptFetcherFactory::DhcpProxyScriptFetcherFactory() {}

DhcpProxyScriptFetcherFactory::~DhcpProxyScriptFetcherFactory() {}

std::unique_ptr<DhcpProxyScriptFetcher> DhcpProxyScriptFetcherFactory::Create(
    URLRequestContext* context) {
#if defined(OS_WIN)
  return base::MakeUnique<DhcpProxyScriptFetcherWin>(context);
#else
  return base::MakeUnique<DoNothingDhcpProxyScriptFetcher>();
#endif
}

}  // namespace net
