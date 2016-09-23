// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/command_line.h"
#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/strings/string_number_conversions.h"
#include "net/spdy/fuzzing/hpack_fuzz_util.h"

namespace {

// Specifies a file having HPACK header sets.
const char kFileToParse[] = "file-to-parse";

// Target file for mutated HPACK header sets.
const char kFileToWrite[] = "file-to-write";

// Number of bits to flip per 1,024 bytes of input.
const char kFlipsPerThousand[] = "flips-per-thousand-bytes";

}  // namespace

using base::StringPiece;
using net::HpackFuzzUtil;
using std::string;

// Reads length-prefixed input blocks, applies a bit-flipping mutation to each
// block, and writes length-prefixed blocks to the output file. While blocks
// themselves are mutated, the length-prefixes of written blocks are not.
int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  const base::CommandLine& command_line =
      *base::CommandLine::ForCurrentProcess();

  if (!command_line.HasSwitch(kFileToParse) ||
      !command_line.HasSwitch(kFileToWrite) ||
      !command_line.HasSwitch(kFlipsPerThousand)) {
    LOG(ERROR) << "Usage: " << argv[0]
               << " --" << kFileToParse << "=/path/to/file.in"
               << " --" << kFileToWrite << "=/path/to/file.out"
               << " --" << kFlipsPerThousand << "=10";
    return -1;
  }
  string file_to_parse = command_line.GetSwitchValueASCII(kFileToParse);
  string file_to_write = command_line.GetSwitchValueASCII(kFileToWrite);

  int flip_ratio = 0;
  CHECK(base::StringToInt(command_line.GetSwitchValueASCII(kFlipsPerThousand),
                    &flip_ratio));

  DVLOG(1) << "Reading input from " << file_to_parse;
  HpackFuzzUtil::Input input;
  CHECK(base::ReadFileToString(base::FilePath::FromUTF8Unsafe(file_to_parse),
                               &input.input));

  DVLOG(1) << "Writing output to " << file_to_write;
  base::File file_out(base::FilePath::FromUTF8Unsafe(file_to_write),
                      base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  CHECK(file_out.IsValid()) << file_out.error_details();

  DVLOG(1) << "Flipping " << flip_ratio << " bits per 1024 input bytes";

  size_t block_count = 0;
  StringPiece block;
  while (HpackFuzzUtil::NextHeaderBlock(&input, &block)) {
    HpackFuzzUtil::FlipBits(
        reinterpret_cast<uint8_t*>(const_cast<char*>(block.data())),
        block.size(), flip_ratio);

    string prefix = HpackFuzzUtil::HeaderBlockPrefix(block.size());

    CHECK_LT(0, file_out.WriteAtCurrentPos(prefix.data(), prefix.size()));
    CHECK_LT(0, file_out.WriteAtCurrentPos(block.data(), block.size()));
    ++block_count;
  }
  CHECK(file_out.Flush());
  DVLOG(1) << "Mutated " << block_count << " blocks.";
  return 0;
}
