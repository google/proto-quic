// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_deflate_predictor_impl.h"

#include <vector>

#include "base/memory/ptr_util.h"
#include "net/websockets/websocket_frame.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

typedef WebSocketDeflatePredictor::Result Result;

TEST(WebSocketDeflatePredictorImpl, Predict) {
  WebSocketDeflatePredictorImpl predictor;
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  frames.push_back(
      base::MakeUnique<WebSocketFrame>(WebSocketFrameHeader::kOpCodeText));
  Result result = predictor.Predict(frames, 0);

  EXPECT_EQ(WebSocketDeflatePredictor::DEFLATE, result);
}

}  // namespace

}  // namespace net
