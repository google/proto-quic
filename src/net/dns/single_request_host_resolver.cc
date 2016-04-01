// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/single_request_host_resolver.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/compiler_specific.h"
#include "base/logging.h"
#include "net/base/net_errors.h"

namespace net {

SingleRequestHostResolver::SingleRequestHostResolver(HostResolver* resolver)
    : resolver_(resolver),
      cur_request_(NULL),
      callback_(
          base::Bind(&SingleRequestHostResolver::OnResolveCompletion,
                     base::Unretained(this))) {
  DCHECK(resolver_ != NULL);
}

SingleRequestHostResolver::~SingleRequestHostResolver() {
  Cancel();
}

int SingleRequestHostResolver::Resolve(const HostResolver::RequestInfo& info,
                                       RequestPriority priority,
                                       AddressList* addresses,
                                       const CompletionCallback& callback,
                                       const BoundNetLog& net_log) {
  DCHECK(addresses);
  DCHECK_EQ(false, callback.is_null());
  DCHECK(cur_request_callback_.is_null()) << "resolver already in use";

  HostResolver::RequestHandle request = NULL;

  // We need to be notified of completion before |callback| is called, so that
  // we can clear out |cur_request_*|.
  CompletionCallback transient_callback =
      callback.is_null() ? CompletionCallback() : callback_;

  int rv = resolver_->Resolve(
      info, priority, addresses, transient_callback, &request, net_log);

  if (rv == ERR_IO_PENDING) {
    DCHECK_EQ(false, callback.is_null());
    // Cleared in OnResolveCompletion().
    cur_request_ = request;
    cur_request_callback_ = callback;
  }

  return rv;
}

void SingleRequestHostResolver::Cancel() {
  if (!cur_request_callback_.is_null()) {
    resolver_->CancelRequest(cur_request_);
    cur_request_ = NULL;
    cur_request_callback_.Reset();
  }
}

void SingleRequestHostResolver::OnResolveCompletion(int result) {
  DCHECK(cur_request_);
  DCHECK_EQ(false, cur_request_callback_.is_null());

  CompletionCallback callback = cur_request_callback_;

  // Clear the outstanding request information.
  cur_request_ = NULL;
  cur_request_callback_.Reset();

  // Call the user's original callback.
  callback.Run(result);
}

}  // namespace net
