// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_cache_lookup_manager.h"

#include "net/base/load_flags.h"

namespace net {

HttpCacheLookupManager::LookupTransaction::LookupTransaction(
    std::unique_ptr<ServerPushHelper> server_push_helper)
    : push_helper_(std::move(server_push_helper)),
      request_(new HttpRequestInfo()),
      transaction_(nullptr) {}

HttpCacheLookupManager::LookupTransaction::~LookupTransaction() {}

int HttpCacheLookupManager::LookupTransaction::StartLookup(
    HttpCache* cache,
    const CompletionCallback& callback,
    const NetLogWithSource& net_log) {
  request_->url = push_helper_->GetURL();
  request_->method = "GET";
  request_->load_flags = LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;
  cache->CreateTransaction(DEFAULT_PRIORITY, &transaction_);
  return transaction_->Start(request_.get(), callback, net_log);
}

void HttpCacheLookupManager::LookupTransaction::CancelPush() {
  DCHECK(push_helper_.get());
  push_helper_->Cancel();
}

HttpCacheLookupManager::HttpCacheLookupManager(HttpCache* http_cache,
                                               const NetLogWithSource& net_log)
    : net_log_(net_log), http_cache_(http_cache), weak_factory_(this) {}

HttpCacheLookupManager::~HttpCacheLookupManager() {}

void HttpCacheLookupManager::OnPush(
    std::unique_ptr<ServerPushHelper> push_helper) {
  GURL pushed_url = push_helper->GetURL();

  // There's a pending lookup transaction sent over already.
  if (base::ContainsKey(lookup_transactions_, pushed_url))
    return;

  auto lookup = base::MakeUnique<LookupTransaction>(std::move(push_helper));

  int rv = lookup->StartLookup(
      http_cache_, base::Bind(&HttpCacheLookupManager::OnLookupComplete,
                              weak_factory_.GetWeakPtr(), pushed_url),
      net_log_);

  if (rv == ERR_IO_PENDING)
    lookup_transactions_[pushed_url] = std::move(lookup);
}

void HttpCacheLookupManager::OnLookupComplete(const GURL& url, int rv) {
  auto it = lookup_transactions_.find(url);
  DCHECK(it != lookup_transactions_.end());

  if (rv == OK)
    it->second->CancelPush();

  lookup_transactions_.erase(it);
}

}  // namespace net
