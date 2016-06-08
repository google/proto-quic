// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/memory_infra_background_whitelist.h"

#include <ctype.h>
#include <string.h>

#include <string>

namespace base {
namespace trace_event {
namespace {

// The names of dump providers whitelisted for background tracing. Dump
// providers can be added here only if the background mode dump has very
// less performance and memory overhead.
const char* const kDumpProviderWhitelist[] = {
    // TODO(ssid): Fill this list with dump provider names which support
    // background mode, crbug.com/613198.
    nullptr  // End of list marker.
};

// A list of string names that are allowed for the memory allocator dumps in
// background mode.
const char* const kAllocatorDumpNameWhitelist[] = {
    // TODO(ssid): Fill this list with dump names, crbug.com/613198.
    nullptr  // End of list marker.
};

const char* const* g_dump_provider_whitelist = kDumpProviderWhitelist;
const char* const* g_allocator_dump_name_whitelist =
    kAllocatorDumpNameWhitelist;

}  // namespace

bool IsMemoryDumpProviderWhitelisted(const char* mdp_name) {
  for (size_t i = 0; g_dump_provider_whitelist[i] != nullptr; ++i) {
    if (strcmp(mdp_name, g_dump_provider_whitelist[i]) == 0)
      return true;
  }
  return false;
}

bool IsMemoryAllocatorDumpNameWhitelisted(const std::string& name) {
  // Remove special characters, numbers (including hexadecimal which are marked
  // by '0x') from the given string.
  const size_t length = name.size();
  std::string stripped_str;
  stripped_str.reserve(length);
  bool parsing_hex = false;
  for (size_t i = 0; i < length; ++i) {
    if (parsing_hex) {
      if (isxdigit(name[i])) {
        continue;
      } else {
        parsing_hex = false;
      }
    }
    if (i + 1 < length && name[i] == '0' && name[i + 1] == 'x') {
      parsing_hex = true;
      ++i;
    } else if (isalpha(name[i]) ||
               (name[i] == '/' && stripped_str.back() != '/')) {
      // Do not add successive '/'(s) in |stripped_str|.
      stripped_str.push_back(name[i]);
    }
  }

  for (size_t i = 0; g_allocator_dump_name_whitelist[i] != nullptr; ++i) {
    if (stripped_str == g_allocator_dump_name_whitelist[i]) {
      return true;
    }
  }
  return false;
}

void SetDumpProviderWhitelistForTesting(const char* const* list) {
  g_dump_provider_whitelist = list;
}

void SetAllocatorDumpNameWhitelistForTesting(const char* const* list) {
  g_allocator_dump_name_whitelist = list;
}

}  // namespace trace_event
}  // namespace base
