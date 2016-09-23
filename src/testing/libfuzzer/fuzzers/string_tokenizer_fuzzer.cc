// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "base/strings/string_tokenizer.h"

void GetAllTokens(base::StringTokenizer& t) {
  while (t.GetNext()) {
    (void)t.token();
  }
}

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) {
    return 0;
  }

  // Allow quote_chars and options to be set. Otherwise full coverage
  // won't be possible since IsQuote, FullGetNext and other functions
  // won't be called.
  size_t pattern_size = data[0];

  if (pattern_size > size - 1) {
    return 0;
  }

  std::string pattern(reinterpret_cast<const char*>(data + 1),
                      pattern_size);

  std::string input(
      reinterpret_cast<const char*>(data + 1 + pattern_size),
      size - pattern_size - 1);


  base::StringTokenizer t(input, pattern);
  GetAllTokens(t);

  base::StringTokenizer t_quote(input, pattern);
  t_quote.set_quote_chars("\"");
  GetAllTokens(t_quote);

  base::StringTokenizer t_options(input, pattern);
  t_options.set_options(base::StringTokenizer::RETURN_DELIMS);
  GetAllTokens(t_options);


  base::StringTokenizer t_quote_and_options(input, pattern);
  t_quote_and_options.set_quote_chars("\"");
  t_quote_and_options.set_options(base::StringTokenizer::RETURN_DELIMS);
  GetAllTokens(t_quote_and_options);

  return 0;
}
