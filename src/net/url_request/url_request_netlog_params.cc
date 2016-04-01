// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_netlog_params.h"

#include <utility>

#include "base/strings/string_number_conversions.h"
#include "base/values.h"
#include "url/gurl.h"

namespace net {

scoped_ptr<base::Value> NetLogURLRequestStartCallback(
    const GURL* url,
    const std::string* method,
    int load_flags,
    RequestPriority priority,
    int64_t upload_id,
    NetLogCaptureMode /* capture_mode */) {
  scoped_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("url", url->possibly_invalid_spec());
  dict->SetString("method", *method);
  dict->SetInteger("load_flags", load_flags);
  dict->SetString("priority", RequestPriorityToString(priority));
  if (upload_id > -1)
    dict->SetString("upload_id", base::Int64ToString(upload_id));
  return std::move(dict);
}

}  // namespace net
