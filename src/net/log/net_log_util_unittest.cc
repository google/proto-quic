// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/log/net_log_util.h"

#include <memory>
#include <set>
#include <vector>

#include "base/files/file_path.h"
#include "base/memory/ptr_util.h"
#include "base/values.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/http/http_cache.h"
#include "net/http/http_transaction.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// Make sure GetNetConstants doesn't crash.
TEST(NetLogUtil, GetNetConstants) {
  std::unique_ptr<base::Value> constants(GetNetConstants());
}

// Make sure GetNetInfo doesn't crash when called on contexts with and without
// caches, and they have the same number of elements.
TEST(NetLogUtil, GetNetInfo) {
  TestURLRequestContext context;
  HttpCache* http_cache = context.http_transaction_factory()->GetCache();

  // Get NetInfo when there's no cache backend (It's only created on first use).
  EXPECT_FALSE(http_cache->GetCurrentBackend());
  std::unique_ptr<base::DictionaryValue> net_info_without_cache(
      GetNetInfo(&context, NET_INFO_ALL_SOURCES));
  EXPECT_FALSE(http_cache->GetCurrentBackend());
  EXPECT_GT(net_info_without_cache->size(), 0u);

  // Fore creation of a cache backend, and get NetInfo again.
  disk_cache::Backend* backend = NULL;
  EXPECT_EQ(OK, context.http_transaction_factory()->GetCache()->GetBackend(
                    &backend, TestCompletionCallback().callback()));
  EXPECT_TRUE(http_cache->GetCurrentBackend());
  std::unique_ptr<base::DictionaryValue> net_info_with_cache(
      GetNetInfo(&context, NET_INFO_ALL_SOURCES));
  EXPECT_GT(net_info_with_cache->size(), 0u);

  EXPECT_EQ(net_info_without_cache->size(), net_info_with_cache->size());
}

// Make sure CreateNetLogEntriesForActiveObjects works for requests from a
// single URLRequestContext.
TEST(NetLogUtil, CreateNetLogEntriesForActiveObjectsOneContext) {
  // Using same context for each iteration makes sure deleted requests don't
  // appear in the list, or result in crashes.
  TestURLRequestContext context(true);
  NetLog net_log;
  context.set_net_log(&net_log);
  context.Init();
  TestDelegate delegate;
  for (size_t num_requests = 0; num_requests < 5; ++num_requests) {
    std::vector<std::unique_ptr<URLRequest>> requests;
    for (size_t i = 0; i < num_requests; ++i) {
      requests.push_back(context.CreateRequest(GURL("about:life"),
                                               DEFAULT_PRIORITY, &delegate));
    }
    std::set<URLRequestContext*> contexts;
    contexts.insert(&context);
    TestNetLog test_net_log;
    CreateNetLogEntriesForActiveObjects(contexts, test_net_log.GetObserver());
    TestNetLogEntry::List entry_list;
    test_net_log.GetEntries(&entry_list);
    ASSERT_EQ(num_requests, entry_list.size());

    for (size_t i = 0; i < num_requests; ++i) {
      EXPECT_EQ(entry_list[i].source.id, requests[i]->net_log().source().id);
    }
  }
}

// Make sure CreateNetLogEntriesForActiveObjects works with multiple
// URLRequestContexts.
TEST(NetLogUtil, CreateNetLogEntriesForActiveObjectsMultipleContexts) {
  TestDelegate delegate;
  for (size_t num_requests = 0; num_requests < 5; ++num_requests) {
    NetLog net_log;
    std::vector<std::unique_ptr<TestURLRequestContext>> contexts;
    std::vector<std::unique_ptr<URLRequest>> requests;
    std::set<URLRequestContext*> context_set;
    for (size_t i = 0; i < num_requests; ++i) {
      contexts.push_back(base::WrapUnique(new TestURLRequestContext(true)));
      contexts[i]->set_net_log(&net_log);
      contexts[i]->Init();
      context_set.insert(contexts[i].get());
      requests.push_back(contexts[i]->CreateRequest(
          GURL("about:hats"), DEFAULT_PRIORITY, &delegate));
    }
    TestNetLog test_net_log;
    CreateNetLogEntriesForActiveObjects(context_set,
                                        test_net_log.GetObserver());
    TestNetLogEntry::List entry_list;
    test_net_log.GetEntries(&entry_list);
    ASSERT_EQ(num_requests, entry_list.size());

    for (size_t i = 0; i < num_requests; ++i) {
      EXPECT_EQ(entry_list[i].source.id, requests[i]->net_log().source().id);
    }
  }
}

}  // namespace

}  // namespace net
