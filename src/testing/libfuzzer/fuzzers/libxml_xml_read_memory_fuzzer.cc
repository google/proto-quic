// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cassert>
#include <cstddef>
#include <cstdint>

#include <functional>
#include <limits>
#include <string>

#include "libxml/parser.h"
#include "libxml/xmlsave.h"

void ignore (void* ctx, const char* msg, ...) {
  // Error handler to avoid spam of error messages from libxml parser.
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  xmlSetGenericErrorFunc(NULL, &ignore);

  // Test default empty options value and one random combination of flags.
  const std::string data_string(reinterpret_cast<const char*>(data), size);
  const std::size_t data_hash = std::hash<std::string>()(data_string);
  const int max_option_value = std::numeric_limits<int>::max();
  const int random_option = data_hash & max_option_value;
  const int options[] = {0, random_option};

  for (const auto option_value : options) {
    if (auto doc = xmlReadMemory(data_string.c_str(), data_string.length(),
                                 "noname.xml", NULL, option_value)) {
      auto buffer = xmlBufferCreate();
      assert(buffer);

      auto context = xmlSaveToBuffer(buffer, NULL, 0);
      xmlSaveDoc(context, doc);
      xmlSaveClose(context);
      xmlFreeDoc(doc);
      xmlBufferFree(buffer);
    }
  }

  return 0;
}
