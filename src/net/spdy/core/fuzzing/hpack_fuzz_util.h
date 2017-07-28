// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_CORE_FUZZING_HPACK_FUZZ_UTIL_H_
#define NET_SPDY_CORE_FUZZING_HPACK_FUZZ_UTIL_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <vector>

#include "net/spdy/core/hpack/hpack_decoder_adapter.h"
#include "net/spdy/core/hpack/hpack_encoder.h"
#include "net/spdy/platform/api/spdy_export.h"
#include "net/spdy/platform/api/spdy_string.h"
#include "net/spdy/platform/api/spdy_string_piece.h"

namespace net {

class SPDY_EXPORT_PRIVATE HpackFuzzUtil {
 public:
  // A GeneratorContext holds ordered header names & values which are
  // initially seeded and then expanded with dynamically generated data.
  struct SPDY_EXPORT_PRIVATE GeneratorContext {
    GeneratorContext();
    ~GeneratorContext();
    std::vector<SpdyString> names;
    std::vector<SpdyString> values;
  };

  // Initializes a GeneratorContext with a random seed and name/value fixtures.
  static void InitializeGeneratorContext(GeneratorContext* context);

  // Generates a header set from the generator context.
  static SpdyHeaderBlock NextGeneratedHeaderSet(GeneratorContext* context);

  // Samples a size from the exponential distribution with mean |mean|,
  // upper-bounded by |sanity_bound|.
  static size_t SampleExponential(size_t mean, size_t sanity_bound);

  // Holds an input SpdyString, and manages an offset into that SpdyString.
  struct SPDY_EXPORT_PRIVATE Input {
    Input();  // Initializes |offset| to zero.
    ~Input();

    size_t remaining() {
      return input.size() - offset;
    }
    const char* ptr() {
      return input.data() + offset;
    }

    SpdyString input;
    size_t offset;
  };

  // Returns true if the next header block was set at |out|. Returns
  // false if no input header blocks remain.
  static bool NextHeaderBlock(Input* input, SpdyStringPiece* out);

  // Returns the serialized header block length prefix for a block of
  // |block_size| bytes.
  static SpdyString HeaderBlockPrefix(size_t block_size);

  // A FuzzerContext holds fuzzer input, as well as each of the decoder and
  // encoder stages which fuzzed header blocks are processed through.
  struct SPDY_EXPORT_PRIVATE FuzzerContext {
    FuzzerContext();
    ~FuzzerContext();
    std::unique_ptr<HpackDecoderAdapter> first_stage;
    std::unique_ptr<HpackEncoder> second_stage;
    std::unique_ptr<HpackDecoderAdapter> third_stage;
  };

  static void InitializeFuzzerContext(FuzzerContext* context);

  // Runs |input_block| through |first_stage| and, iff that succeeds,
  // |second_stage| and |third_stage| as well. Returns whether all stages
  // processed the input without error.
  static bool RunHeaderBlockThroughFuzzerStages(FuzzerContext* context,
                                                SpdyStringPiece input_block);

  // Flips random bits within |buffer|. The total number of flips is
  // |flip_per_thousand| bits for every 1,024 bytes of |buffer_length|,
  // rounding up.
  static void FlipBits(uint8_t* buffer,
                       size_t buffer_length,
                       size_t flip_per_thousand);
};

}  // namespace net

#endif  // NET_SPDY_CORE_FUZZING_HPACK_FUZZ_UTIL_H_
