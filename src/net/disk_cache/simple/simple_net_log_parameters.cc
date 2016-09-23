// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/simple/simple_net_log_parameters.h"

#include <utility>

#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/format_macros.h"
#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "base/values.h"
#include "net/base/net_errors.h"
#include "net/disk_cache/simple/simple_entry_impl.h"

namespace {

std::unique_ptr<base::Value> NetLogSimpleEntryConstructionCallback(
    const disk_cache::SimpleEntryImpl* entry,
    net::NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("entry_hash",
                  base::StringPrintf("%#016" PRIx64, entry->entry_hash()));
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogSimpleEntryCreationCallback(
    const disk_cache::SimpleEntryImpl* entry,
    int net_error,
    net::NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("net_error", net_error);
  if (net_error == net::OK)
    dict->SetString("key", entry->key());
  return std::move(dict);
}

}  // namespace

namespace disk_cache {

net::NetLog::ParametersCallback CreateNetLogSimpleEntryConstructionCallback(
    const SimpleEntryImpl* entry) {
  DCHECK(entry);
  return base::Bind(&NetLogSimpleEntryConstructionCallback, entry);
}

net::NetLog::ParametersCallback CreateNetLogSimpleEntryCreationCallback(
    const SimpleEntryImpl* entry,
    int net_error) {
  DCHECK(entry);
  return base::Bind(&NetLogSimpleEntryCreationCallback, entry, net_error);
}

}  // namespace disk_cache
