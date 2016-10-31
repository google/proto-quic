// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string_piece.h"
#include "base/test/fuzzed_data_provider.h"
#include "net/base/completion_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/websockets/websocket_deflate_parameters.h"
#include "net/websockets/websocket_deflate_predictor.h"
#include "net/websockets/websocket_deflate_predictor_impl.h"
#include "net/websockets/websocket_deflate_stream.h"
#include "net/websockets/websocket_extension.h"
#include "net/websockets/websocket_frame.h"
#include "net/websockets/websocket_stream.h"

namespace net {

namespace {

class WebSocketFuzzedStream final : public WebSocketStream {
 public:
  WebSocketFuzzedStream(const uint8_t* data, size_t size)
      : fuzzed_data_provider_(data, size) {}

  int ReadFrames(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
                 const CompletionCallback& callback) override {
    if (fuzzed_data_provider_.remaining_bytes() == 0)
      return ERR_CONNECTION_CLOSED;
    while (fuzzed_data_provider_.remaining_bytes() > 0)
      frames->push_back(CreateFrame());
    return OK;
  }

  int WriteFrames(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
                  const CompletionCallback& callback) override {
    return ERR_FILE_NOT_FOUND;
  }

  void Close() override {}
  std::string GetSubProtocol() const override { return std::string(); }
  std::string GetExtensions() const override { return std::string(); }

 private:
  std::unique_ptr<WebSocketFrame> CreateFrame() {
    WebSocketFrameHeader::OpCode opcode =
        fuzzed_data_provider_.ConsumeInt32InRange(
            WebSocketFrameHeader::kOpCodeContinuation,
            WebSocketFrameHeader::kOpCodeControlUnused);
    auto frame = base::MakeUnique<WebSocketFrame>(opcode);
    // Bad news: ConsumeBool actually consumes a whole byte per call, so do
    // something hacky to conserve precious bits.
    uint8_t flags = fuzzed_data_provider_.ConsumeUint8();
    frame->header.final = flags & 0x1;
    frame->header.reserved1 = (flags >> 1) & 0x1;
    frame->header.reserved2 = (flags >> 2) & 0x1;
    frame->header.reserved3 = (flags >> 3) & 0x1;
    frame->header.masked = (flags >> 4) & 0x1;
    uint64_t payload_length = fuzzed_data_provider_.ConsumeInt32InRange(0, 64);
    std::string payload = fuzzed_data_provider_.ConsumeBytes(payload_length);
    frame->data = new StringIOBuffer(payload);
    frame->header.payload_length = payload.size();
    return frame;
  }

  base::FuzzedDataProvider fuzzed_data_provider_;
};

void WebSocketDeflateStreamFuzz(const uint8_t* data, size_t size) {
  // WebSocketDeflateStream needs to be constructed on each call because it
  // has state.
  std::string failure_message;
  WebSocketDeflateParameters parameters;
  parameters.Initialize(WebSocketExtension("permessage-deflate"),
                        &failure_message);
  WebSocketDeflateStream deflate_stream(
      base::MakeUnique<WebSocketFuzzedStream>(data, size), parameters,
      base::MakeUnique<WebSocketDeflatePredictorImpl>());
  std::vector<std::unique_ptr<net::WebSocketFrame>> frames;
  deflate_stream.ReadFrames(&frames, CompletionCallback());
}

}  // namespace

}  // namespace net

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  net::WebSocketDeflateStreamFuzz(data, size);

  return 0;
}
