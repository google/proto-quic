// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_SDCH_NET_LOG_PARAMS_H_
#define NET_BASE_SDCH_NET_LOG_PARAMS_H_

#include <memory>
#include <string>

#include "net/base/net_export.h"
#include "net/base/sdch_problem_codes.h"

class GURL;

namespace base {
class Value;
}

namespace net {

class NetLogCaptureMode;

NET_EXPORT std::unique_ptr<base::Value> NetLogSdchResourceProblemCallback(
    SdchProblemCode problem,
    NetLogCaptureMode capture_mode);

// If |is_error| is false, "net_error" field won't be added to the JSON and the
// event won't be painted red in the netlog.
NET_EXPORT std::unique_ptr<base::Value>
NetLogSdchDictionaryFetchProblemCallback(SdchProblemCode problem,
                                         const GURL& url,
                                         bool is_error,
                                         NetLogCaptureMode capture_mode);

}  // namespace net

#endif  // NET_BASE_SDCH_NET_LOG_PARAMS_H_
