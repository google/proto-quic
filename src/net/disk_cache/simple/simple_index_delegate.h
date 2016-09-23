// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DISK_CACHE_SIMPLE_SIMPLE_INDEX_DELEGATE_H_
#define NET_DISK_CACHE_SIMPLE_SIMPLE_INDEX_DELEGATE_H_

#include <stdint.h>

#include <vector>

#include "net/base/completion_callback.h"
#include "net/base/net_export.h"

namespace disk_cache {

class NET_EXPORT_PRIVATE SimpleIndexDelegate {
 public:
  virtual ~SimpleIndexDelegate() {}

  // Dooms all entries in |entries|, calling |callback| with the result
  // asynchronously. |entries| is mutated in an undefined way by this call,
  // for efficiency.
  virtual void DoomEntries(std::vector<uint64_t>* entry_hashes,
                           const net::CompletionCallback& callback) = 0;
};

}  // namespace disk_cache

#endif  // NET_DISK_CACHE_SIMPLE_SIMPLE_INDEX_DELEGATE_H_
