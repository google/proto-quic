// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP2_DECODER_FRAME_PARTS_H_
#define NET_HTTP2_DECODER_FRAME_PARTS_H_

// FrameParts implements Http2FrameDecoderListener, recording the callbacks
// during the decoding of a single frame. It is also used for comparing the
// info that a test expects to be recorded during the decoding of a frame
// with the actual recorded value (i.e. by providing a comparator).

// TODO(jamessynge): Convert FrameParts to a class, hide the members, add
// getters/setters.

#include <stddef.h>

#include <string>
#include <vector>

#include "base/logging.h"
#include "base/optional.h"
#include "base/strings/string_piece.h"
#include "net/http2/decoder/http2_frame_decoder_listener.h"
#include "net/http2/http2_constants.h"
#include "net/http2/http2_structures.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

// Forward declarations.
struct FrameParts;
std::ostream& operator<<(std::ostream& out, const FrameParts& v);

struct FrameParts : public Http2FrameDecoderListener {
  // The first callback for every type of frame includes the frame header; this
  // is the only constructor used during decoding of a frame.
  explicit FrameParts(const Http2FrameHeader& header);

  // For use in tests where the expected frame has a variable size payload.
  FrameParts(const Http2FrameHeader& header, base::StringPiece payload);

  // For use in tests where the expected frame has a variable size payload
  // and may be padded.
  FrameParts(const Http2FrameHeader& header,
             base::StringPiece payload,
             size_t total_pad_length);

  // Copy constructor.
  FrameParts(const FrameParts& header);

  ~FrameParts() override;

  // Returns AssertionSuccess() if they're equal, else AssertionFailure()
  // with info about the difference.
  ::testing::AssertionResult VerifyEquals(const FrameParts& other) const;

  // Format this FrameParts object.
  void OutputTo(std::ostream& out) const;

  // Set the total padding length (0 to 256).
  void SetTotalPadLength(size_t total_pad_length);

  // Set the origin and value expected in an ALTSVC frame.
  void SetAltSvcExpected(base::StringPiece origin, base::StringPiece value);

  // Http2FrameDecoderListener methods:
  bool OnFrameHeader(const Http2FrameHeader& header) override;
  void OnDataStart(const Http2FrameHeader& header) override;
  void OnDataPayload(const char* data, size_t len) override;
  void OnDataEnd() override;
  void OnHeadersStart(const Http2FrameHeader& header) override;
  void OnHeadersPriority(const Http2PriorityFields& priority) override;
  void OnHpackFragment(const char* data, size_t len) override;
  void OnHeadersEnd() override;
  void OnPriorityFrame(const Http2FrameHeader& header,
                       const Http2PriorityFields& priority) override;
  void OnContinuationStart(const Http2FrameHeader& header) override;
  void OnContinuationEnd() override;
  void OnPadLength(size_t trailing_length) override;
  void OnPadding(const char* pad, size_t skipped_length) override;
  void OnRstStream(const Http2FrameHeader& header,
                   Http2ErrorCode error_code) override;
  void OnSettingsStart(const Http2FrameHeader& header) override;
  void OnSetting(const Http2SettingFields& setting_fields) override;
  void OnSettingsEnd() override;
  void OnSettingsAck(const Http2FrameHeader& header) override;
  void OnPushPromiseStart(const Http2FrameHeader& header,
                          const Http2PushPromiseFields& promise,
                          size_t total_padding_length) override;
  void OnPushPromiseEnd() override;
  void OnPing(const Http2FrameHeader& header,
              const Http2PingFields& ping) override;
  void OnPingAck(const Http2FrameHeader& header,
                 const Http2PingFields& ping) override;
  void OnGoAwayStart(const Http2FrameHeader& header,
                     const Http2GoAwayFields& goaway) override;
  void OnGoAwayOpaqueData(const char* data, size_t len) override;
  void OnGoAwayEnd() override;
  void OnWindowUpdate(const Http2FrameHeader& header,
                      uint32_t increment) override;
  void OnAltSvcStart(const Http2FrameHeader& header,
                     size_t origin_length,
                     size_t value_length) override;
  void OnAltSvcOriginData(const char* data, size_t len) override;
  void OnAltSvcValueData(const char* data, size_t len) override;
  void OnAltSvcEnd() override;
  void OnUnknownStart(const Http2FrameHeader& header) override;
  void OnUnknownPayload(const char* data, size_t len) override;
  void OnUnknownEnd() override;
  void OnPaddingTooLong(const Http2FrameHeader& header,
                        size_t missing_length) override;
  void OnFrameSizeError(const Http2FrameHeader& header) override;

  // The fields are public for access by tests.

  const Http2FrameHeader frame_header;

  std::string payload;
  std::string padding;
  std::string altsvc_origin;
  std::string altsvc_value;

  base::Optional<Http2PriorityFields> opt_priority;
  base::Optional<Http2ErrorCode> opt_rst_stream_error_code;
  base::Optional<Http2PushPromiseFields> opt_push_promise;
  base::Optional<Http2PingFields> opt_ping;
  base::Optional<Http2GoAwayFields> opt_goaway;

  base::Optional<size_t> opt_pad_length;
  base::Optional<size_t> opt_payload_length;
  base::Optional<size_t> opt_missing_length;
  base::Optional<size_t> opt_altsvc_origin_length;
  base::Optional<size_t> opt_altsvc_value_length;

  base::Optional<size_t> opt_window_update_increment;

  bool has_frame_size_error = false;

  std::vector<Http2SettingFields> settings;

  // These booleans are not checked by CompareCollectedFrames.
  bool got_start_callback = false;
  bool got_end_callback = false;

 private:
  // ASSERT during an On* method that we're handling a frame of type
  // expected_frame_type, and have not already received other On* methods
  // (i.e. got_start_callback is false).
  ::testing::AssertionResult StartFrameOfType(
      const Http2FrameHeader& header,
      Http2FrameType expected_frame_type);

  // ASSERT that StartFrameOfType has already been called with
  // expected_frame_type (i.e. got_start_callback has been called), and that
  // EndFrameOfType has not yet been called (i.e. got_end_callback is false).
  ::testing::AssertionResult InFrameOfType(Http2FrameType expected_frame_type);

  // ASSERT that we're InFrameOfType, and then sets got_end_callback=true.
  ::testing::AssertionResult EndFrameOfType(Http2FrameType expected_frame_type);

  // ASSERT that we're in the middle of processing a frame that is padded.
  ::testing::AssertionResult InPaddedFrame();

  // Append source to target. If opt_length is not nullptr, then verifies that
  // the optional has a value (i.e. that the necessary On*Start method has been
  // called), and that target is not longer than opt_length->value().
  ::testing::AssertionResult AppendString(base::StringPiece source,
                                          std::string* target,
                                          base::Optional<size_t>* opt_length);
};

}  // namespace test
}  // namespace net

#endif  // NET_HTTP2_DECODER_FRAME_PARTS_H_
