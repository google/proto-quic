// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_FUZZING_HPACK_FUZZ_UTIL_H_
#define NET_SPDY_FUZZING_HPACK_FUZZ_UTIL_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/spdy/hpack/hpack_decoder.h"
#include "net/spdy/hpack/hpack_encoder.h"

namespace net {

class NET_EXPORT_PRIVATE HpackFuzzUtil {
 public:
  // A GeneratorContext holds ordered header names & values which are
  // initially seeded and then expanded with dynamically generated data.
  struct NET_EXPORT_PRIVATE GeneratorContext {
    GeneratorContext();
    ~GeneratorContext();
    std::vector<std::string> names;
    std::vector<std::string> values;
  };

  // Initializes a GeneratorContext with a random seed and name/value fixtures.
  static void InitializeGeneratorContext(GeneratorContext* context);

  // Generates a header set from the generator context.
  static SpdyHeaderBlock NextGeneratedHeaderSet(GeneratorContext* context);

  // Samples a size from the exponential distribution with mean |mean|,
  // upper-bounded by |sanity_bound|.
  static size_t SampleExponential(size_t mean, size_t sanity_bound);

  // Holds an input string, and manages an offset into that string.
  struct NET_EXPORT_PRIVATE Input {
    Input();  // Initializes |offset| to zero.
    ~Input();

    size_t remaining() {
      return input.size() - offset;
    }
    const char* ptr() {
      return input.data() + offset;
    }

    std::string input;
    size_t offset;
  };

  // Returns true if the next header block was set at |out|. Returns
  // false if no input header blocks remain.
  static bool NextHeaderBlock(Input* input, base::StringPiece* out);

  // Returns the serialized header block length prefix for a block of
  // |block_size| bytes.
  static std::string HeaderBlockPrefix(size_t block_size);

  // A FuzzerContext holds fuzzer input, as well as each of the decoder and
  // encoder stages which fuzzed header blocks are processed through.
  struct NET_EXPORT_PRIVATE FuzzerContext {
    FuzzerContext();
    ~FuzzerContext();
    std::unique_ptr<HpackDecoder> first_stage;
    std::unique_ptr<HpackEncoder> second_stage;
    std::unique_ptr<HpackDecoder> third_stage;
  };

  static void InitializeFuzzerContext(FuzzerContext* context);

  // Runs |input_block| through |first_stage| and, iff that succeeds,
  // |second_stage| and |third_stage| as well. Returns whether all stages
  // processed the input without error.
  static bool RunHeaderBlockThroughFuzzerStages(FuzzerContext* context,
                                                base::StringPiece input_block);

  // Flips random bits within |buffer|. The total number of flips is
  // |flip_per_thousand| bits for every 1,024 bytes of |buffer_length|,
  // rounding up.
  static void FlipBits(uint8_t* buffer,
                       size_t buffer_length,
                       size_t flip_per_thousand);
};

}  // namespace net

#endif  // NET_SPDY_FUZZING_HPACK_FUZZ_UTIL_H_
