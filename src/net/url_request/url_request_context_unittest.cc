// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_context.h"

#include <memory>

#include "base/memory/ptr_util.h"
#include "base/trace_event/process_memory_dump.h"
#include "net/proxy/proxy_config_service_fixed.h"
#include "net/url_request/url_request_context_builder.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

// Checks if the dump provider runs without crashing and dumps root objects.
TEST(URLRequestContextTest, MemoryDumpProvider) {
  base::trace_event::MemoryDumpArgs dump_args = {
      base::trace_event::MemoryDumpLevelOfDetail::DETAILED};
  std::unique_ptr<base::trace_event::ProcessMemoryDump> process_memory_dump(
      new base::trace_event::ProcessMemoryDump(nullptr, dump_args));
  URLRequestContextBuilder builder;
#if defined(OS_LINUX) || defined(OS_ANDROID)
  builder.set_proxy_config_service(
      base::MakeUnique<ProxyConfigServiceFixed>(ProxyConfig::CreateDirect()));
#endif  // defined(OS_LINUX) || defined(OS_ANDROID)
  std::unique_ptr<URLRequestContext> context(builder.Build());
  context->OnMemoryDump(dump_args, process_memory_dump.get());
  const base::trace_event::ProcessMemoryDump::AllocatorDumpsMap&
      allocator_dumps = process_memory_dump->allocator_dumps();

  bool did_dump_http_network_session = false;
  bool did_dump_ssl_client_session_cache = false;
  bool did_dump_url_request_context = false;
  bool did_dump_url_request_context_http_network_session = false;
  for (const auto& it : allocator_dumps) {
    const std::string& dump_name = it.first;
    if (dump_name.find("net/http_network_session") != std::string::npos)
      did_dump_http_network_session = true;
    if (dump_name.find("net/ssl_session_cache") != std::string::npos)
      did_dump_ssl_client_session_cache = true;
    if (dump_name.find("net/url_request_context") != std::string::npos) {
      // A sub allocator dump to take into account of the sharing relationship.
      if (dump_name.find("http_network_session") != std::string::npos) {
        did_dump_url_request_context_http_network_session = true;
      } else {
        did_dump_url_request_context = true;
      }
    }
  }
  ASSERT_TRUE(did_dump_http_network_session);
  ASSERT_TRUE(did_dump_ssl_client_session_cache);
  ASSERT_TRUE(did_dump_url_request_context);
  ASSERT_TRUE(did_dump_url_request_context_http_network_session);
}

// TODO(xunjieli): Add more granular tests on the MemoryDumpProvider.
}  // namespace net
