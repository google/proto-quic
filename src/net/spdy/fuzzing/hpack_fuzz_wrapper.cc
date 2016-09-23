// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/files/file_util.h"
#include "net/spdy/fuzzing/hpack_fuzz_util.h"

namespace {

// Specifies a file having HPACK header sets.
const char kFileToParse[] = "file-to-parse";

}  // namespace

using base::StringPiece;
using net::HpackFuzzUtil;
using std::string;

// Sequentially runs each given length-prefixed header block through
// decoding and encoding fuzzing stages (using HpackFuzzUtil).
int main(int argc, char** argv) {
  base::AtExitManager exit_manager;

  base::CommandLine::Init(argc, argv);
  const base::CommandLine& command_line =
      *base::CommandLine::ForCurrentProcess();

  if (!command_line.HasSwitch(kFileToParse)) {
    LOG(ERROR) << "Usage: " << argv[0]
               << " --" << kFileToParse << "=/path/to/file.in";
    return -1;
  }
  string file_to_parse = command_line.GetSwitchValueASCII(kFileToParse);

  // ClusterFuzz may invoke as --file-to-parse="". Don't crash in this case.
  if (file_to_parse.empty()) {
    LOG(WARNING) << "Empty file to parse given. Doing nothing.";
    return 0;
  }

  DVLOG(1) << "Reading input from " << file_to_parse;
  HpackFuzzUtil::Input input;
  CHECK(base::ReadFileToString(base::FilePath::FromUTF8Unsafe(file_to_parse),
                               &input.input));

  HpackFuzzUtil::FuzzerContext context;
  HpackFuzzUtil::InitializeFuzzerContext(&context);

  size_t block_count = 0;
  StringPiece block;
  while (HpackFuzzUtil::NextHeaderBlock(&input, &block)) {
    HpackFuzzUtil::RunHeaderBlockThroughFuzzerStages(&context, block);
    ++block_count;
  }
  DVLOG(1) << "Fuzzed " << block_count << " blocks.";
  return 0;
}
