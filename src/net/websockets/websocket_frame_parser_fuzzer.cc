// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "base/test/fuzzed_data_provider.h"
#include "net/websockets/websocket_frame_parser.h"

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  base::FuzzedDataProvider fuzzed_data_provider(data, size);
  net::WebSocketFrameParser parser;
  std::vector<std::unique_ptr<net::WebSocketFrameChunk>> frame_chunks;
  while (fuzzed_data_provider.remaining_bytes() > 0) {
    size_t chunk_size = fuzzed_data_provider.ConsumeUint32InRange(1, 32);
    base::StringPiece chunk = fuzzed_data_provider.ConsumeBytes(chunk_size);
    parser.Decode(chunk.data(), chunk.size(), &frame_chunks);
  }
  return 0;
}
