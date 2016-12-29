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
  bool warn_unneeded_finalizer = false;
  // TODO(https://crbug.com/675879): Clean up after the Blink rename.
  bool use_chromium_style_naming = false;
  std::set<std::string> ignored_classes;
  std::set<std::string> checked_namespaces;
  std::vector<std::string> ignored_directories;
};

#endif  // TOOLS_BLINK_GC_PLUGIN_BLINK_GC_PLUGIN_OPTIONS_H_
