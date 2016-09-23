// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_URL_REQUEST_URL_REQUEST_CONTEXT_GETTER_OBSERVER_H_
#define NET_URL_REQUEST_URL_REQUEST_CONTEXT_GETTER_OBSERVER_H_

#include "base/macros.h"
#include "net/base/net_export.h"

namespace net {
class URLRequestContextGetter;

// Interface for watching when a URLRequestContext associated with a
// URLRequestContextGetter is shutting down.
class NET_EXPORT URLRequestContextGetterObserver {
 public:
  URLRequestContextGetterObserver() {}

  // Called before the URLRequestContext shuts down. When called, the Getter's
  // GetURLRequestContext method must return NULL to protected against
  // re-entrancy, but the Context must still be valid and GetNetworkTaskRunner()
  // must return the thread it lives on. Called on the network thread.
  virtual void OnContextShuttingDown() = 0;

 protected:
  virtual ~URLRequestContextGetterObserver() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(URLRequestContextGetterObserver);
};

}  // namespace net

#endif  // NET_URL_REQUEST_URL_REQUEST_CONTEXT_GETTER_OBSERVER_H_
