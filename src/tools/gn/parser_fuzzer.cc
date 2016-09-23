// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include "tools/gn/input_file.h"
#include "tools/gn/parser.h"
#include "tools/gn/source_file.h"
#include "tools/gn/tokenizer.h"

extern "C" int LLVMFuzzerTestOneInput(const unsigned char* data, size_t size) {
  SourceFile source;
  InputFile input(source);
  input.SetContents(std::string(reinterpret_cast<const char*>(data), size));

  Err err;
  std::vector<Token> tokens = Tokenizer::Tokenize(&input, &err);

  if (!err.has_error())
    Parser::Parse(tokens, &err);

  return 0;
}
