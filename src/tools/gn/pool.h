// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_GN_POOL_H_
#define TOOLS_GN_POOL_H_

#include <string>

#include "tools/gn/item.h"

// Represents a named pool in the dependency graph.
//
// A pool is used to limit the parallelism of task invocation in the
// generated ninja build. Pools are referenced by toolchains.
class Pool : public Item {
 public:
  using Item::Item;
  ~Pool() override;

  Pool(const Pool&) = delete;
  Pool& operator=(const Pool&) = delete;

  // Item implementation.
  Pool* AsPool() override;
  const Pool* AsPool() const override;

  // The pool depth (number of task to run simultaneously).
  int64_t depth() const { return depth_; }
  void set_depth(int64_t depth) { depth_ = depth; }

  // The pool name in generated ninja files.
  std::string GetNinjaName(const Label& default_toolchain) const;

 private:
  std::string GetNinjaName(bool include_toolchain) const;

  int64_t depth_ = 0;
};

#endif  // TOOLS_GN_POOL_H_
