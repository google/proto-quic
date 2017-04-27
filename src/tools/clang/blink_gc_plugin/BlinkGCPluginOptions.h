// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_BLINK_GC_PLUGIN_BLINK_GC_PLUGIN_OPTIONS_H_
#define TOOLS_BLINK_GC_PLUGIN_BLINK_GC_PLUGIN_OPTIONS_H_

#include <set>
#include <string>
#include <vector>

struct BlinkGCPluginOptions {
  bool dump_graph = false;

  // If |true|, emit warning for class types which derive from from
  // GarbageCollectedFinalized<> when just GarbageCollected<> will do.
  bool warn_unneeded_finalizer = false;

  std::set<std::string> ignored_classes;
  std::set<std::string> checked_namespaces;
  std::vector<std::string> ignored_directories;
};

#endif  // TOOLS_BLINK_GC_PLUGIN_BLINK_GC_PLUGIN_OPTIONS_H_
