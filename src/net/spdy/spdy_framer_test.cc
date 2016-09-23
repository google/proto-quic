// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_framer.h"

#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include "base/compiler_specific.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string_number_conversions.h"
#include "net/quic/core/quic_flags.h"
#include "net/spdy/hpack/hpack_constants.h"
#include "net/spdy/mock_spdy_framer_visitor.h"
#include "net/spdy/spdy_flags.h"
#include "net/spdy/spdy_frame_builder.h"
#include "net/spdy/spdy_frame_reader.h"
#include "net/spdy/spdy_protocol.h"
#include "net/spdy/spdy_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/platform_test.h"

using base::StringPiece;
using std::string;
using testing::_;

namespace net {

namespace test {

static const size_t kMaxDecompressedSize = 1024;

class MockDebugVisitor : public SpdyFramerDebugVisitorInterface {
 public:
  MOCK_METHOD4(OnSendCompressedFrame,
               void(SpdyStreamId stream_id,
                    SpdyFrameType type,
                    size_t payload_len,
                    size_t frame_len));

  MOCK_METHOD3(OnReceiveCompressedFrame,
               void(SpdyStreamId stream_id,
                    SpdyFrameType type,
                    size_t frame_len));
};

class SpdyFramerTestUtil {
 public:
  // Decompress a single frame using the decompression context held by
  // the SpdyFramer.  The implemention is meant for use only in tests
  // and will CHECK fail if the input is anything other than a single,
  // well-formed compressed frame.
  //
  // Returns a new decompressed SpdySerializedFrame.
  template <class SpdyFrameType>
  static SpdySerializedFrame DecompressFrame(SpdyFramer* framer,
                                             const SpdyFrameType& frame) {
    NewDecompressionVisitor visitor;
    framer->set_visitor(&visitor);
    CHECK_EQ(frame.size(), framer->ProcessInput(frame.data(), frame.size()));
    CHECK_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer->state());
    framer->set_visitor(nullptr);
    SpdyFramer serializer(framer->protocol_version());
    serializer.set_enable_compression(false);
    return serializer.SerializeFrame(visitor.GetFrame());
  }

  class NewDecompressionVisitor : public SpdyFramerVisitorInterface {
   public:
    NewDecompressionVisitor() : finished_(false) {}

    const SpdyFrameIR& GetFrame() const {
      CHECK(finished_);
      return *frame_;
    }

    SpdyHeadersHandlerInterface* OnHeaderFrameStart(
        SpdyStreamId stream_id) override {
      if (headers_handler_ == nullptr) {
        headers_handler_.reset(new TestHeadersHandler);
      }
      return headers_handler_.get();
    }

    void OnHeaderFrameEnd(SpdyStreamId stream_id, bool end_headers) override {
      CHECK(!finished_);
      frame_->set_header_block(headers_handler_->decoded_block().Clone());
      finished_ = true;
      if (end_headers) {
        headers_handler_.reset();
      }
    }

    void OnSynStream(SpdyStreamId stream_id,
                     SpdyStreamId associated_stream_id,
                     SpdyPriority priority,
                     bool fin,
                     bool unidirectional) override {
      SpdySynStreamIR* syn_stream = new SpdySynStreamIR(stream_id);
      syn_stream->set_associated_to_stream_id(associated_stream_id);
      syn_stream->set_priority(priority);
      syn_stream->set_fin(fin);
      syn_stream->set_unidirectional(unidirectional);
      frame_.reset(syn_stream);
    }

    void OnSynReply(SpdyStreamId stream_id, bool fin) override {
      SpdyHeadersIR* headers = new SpdyHeadersIR(stream_id);
      headers->set_fin(fin);
      frame_.reset(headers);
    }

    void OnHeaders(SpdyStreamId stream_id,
                   bool has_priority,
                   int weight,
                   SpdyStreamId parent_stream_id,
                   bool exclusive,
                   bool fin,
                   bool end) override {
      SpdyHeadersIR* headers = new SpdyHeadersIR(stream_id);
      headers->set_has_priority(has_priority);
      headers->set_weight(weight);
      headers->set_parent_stream_id(parent_stream_id);
      headers->set_exclusive(exclusive);
      headers->set_fin(fin);
      frame_.reset(headers);
    }

    void OnPushPromise(SpdyStreamId stream_id,
                       SpdyStreamId promised_stream_id,
                       bool end) override {
      SpdyPushPromiseIR* push_promise =
          new SpdyPushPromiseIR(stream_id, promised_stream_id);
      frame_.reset(push_promise);
    }

    // TODO(birenroy): Add support for CONTINUATION.
    void OnContinuation(SpdyStreamId stream_id, bool end) override {
      LOG(FATAL);
    }

    // All other methods just LOG(FATAL).
    void OnError(SpdyFramer* framer) override { LOG(FATAL); }
    void OnDataFrameHeader(SpdyStreamId stream_id,
                           size_t length,
                           bool fin) override {
      LOG(FATAL) << "Unexpected data frame header";
    }
    void OnStreamFrameData(SpdyStreamId stream_id,
                           const char* data,
                           size_t len) override {
      LOG(FATAL);
    }

    void OnStreamEnd(SpdyStreamId stream_id) override { LOG(FATAL); }

    void OnStreamPadding(SpdyStreamId stream_id, size_t len) override {
      LOG(FATAL);
    }

    bool OnControlFrameHeaderData(SpdyStreamId stream_id,
                                  const char* header_data,
                                  size_t len) override {
      LOG(FATAL);
      return true;
    }

    void OnRstStream(SpdyStreamId stream_id,
                     SpdyRstStreamStatus status) override {
      LOG(FATAL);
    }
    void OnSetting(SpdySettingsIds id, uint8_t flags, uint32_t value) override {
      LOG(FATAL);
    }
    void OnPing(SpdyPingId unique_id, bool is_ack) override { LOG(FATAL); }
    void OnSettingsEnd() override { LOG(FATAL); }
    void OnGoAway(SpdyStreamId last_accepted_stream_id,
                  SpdyGoAwayStatus status) override {
      LOG(FATAL);
    }

    void OnWindowUpdate(SpdyStreamId stream_id,
                        int delta_window_size) override {
      LOG(FATAL);
    }

    void OnPriority(SpdyStreamId stream_id,
                    SpdyStreamId parent_stream_id,
                    int weight,
                    bool exclusive) override {
      // Do nothing.
    }

    bool OnUnknownFrame(SpdyStreamId stream_id, int frame_type) override {
      LOG(FATAL);
      return false;
    }

   private:
    std::unique_ptr<TestHeadersHandler> headers_handler_;
    std::unique_ptr<SpdyFrameWithHeaderBlockIR> frame_;
    bool finished_;

    DISALLOW_COPY_AND_ASSIGN(NewDecompressionVisitor);
  };

  class DecompressionVisitor : public SpdyFramerVisitorInterface {
   public:
    explicit DecompressionVisitor(SpdyMajorVersion version)
        : version_(version), size_(0), finished_(false) {}

    void ResetBuffer() {
      CHECK(buffer_.get() == NULL);
      CHECK_EQ(0u, size_);
      CHECK(!finished_);
      buffer_.reset(new char[kMaxDecompressedSize]);
    }

    void OnError(SpdyFramer* framer) override { LOG(FATAL); }
    void OnDataFrameHeader(SpdyStreamId stream_id,
                           size_t length,
                           bool fin) override {
      LOG(FATAL) << "Unexpected data frame header";
    }
    void OnStreamFrameData(SpdyStreamId stream_id,
                           const char* data,
                           size_t len) override {
      LOG(FATAL);
    }

    void OnStreamEnd(SpdyStreamId stream_id) override { LOG(FATAL); }

    void OnStreamPadding(SpdyStreamId stream_id, size_t len) override {
      LOG(FATAL);
    }

    SpdyHeadersHandlerInterface* OnHeaderFrameStart(
        SpdyStreamId stream_id) override {
      LOG(FATAL) << "Not implemented.";
      return nullptr;
    }

    void OnHeaderFrameEnd(SpdyStreamId stream_id, bool end_headers) override {
      LOG(FATAL) << "Not implemented.";
    }

    bool OnControlFrameHeaderData(SpdyStreamId stream_id,
                                  const char* header_data,
                                  size_t len) override {
      CHECK(buffer_.get() != NULL);
      CHECK_GE(kMaxDecompressedSize, size_ + len);
      CHECK(!finished_);
      if (len != 0) {
        memcpy(buffer_.get() + size_, header_data, len);
        size_ += len;
      } else {
        // Done.
        finished_ = true;
      }
      return true;
    }

    void OnSynStream(SpdyStreamId stream_id,
                     SpdyStreamId associated_stream_id,
                     SpdyPriority priority,
                     bool fin,
                     bool unidirectional) override {
      SpdyFramer framer(version_);
      framer.set_enable_compression(false);
      SpdySynStreamIR syn_stream(stream_id);
      syn_stream.set_associated_to_stream_id(associated_stream_id);
      syn_stream.set_priority(priority);
      syn_stream.set_fin(fin);
      syn_stream.set_unidirectional(unidirectional);
      SpdySerializedFrame frame(framer.SerializeSynStream(syn_stream));
      ResetBuffer();
      memcpy(buffer_.get(), frame.data(), framer.GetSynStreamMinimumSize());
      size_ += framer.GetSynStreamMinimumSize();
    }

    void OnSynReply(SpdyStreamId stream_id, bool fin) override {
      SpdyFramer framer(version_);
      framer.set_enable_compression(false);
      SpdyHeadersIR headers(stream_id);
      headers.set_fin(fin);
      SpdySerializedFrame frame(framer.SerializeHeaders(headers));
      ResetBuffer();
      memcpy(buffer_.get(), frame.data(), framer.GetHeadersMinimumSize());
      size_ += framer.GetSynStreamMinimumSize();
    }

    void OnRstStream(SpdyStreamId stream_id,
                     SpdyRstStreamStatus status) override {
      LOG(FATAL);
    }
    void OnSetting(SpdySettingsIds id, uint8_t flags, uint32_t value) override {
      LOG(FATAL);
    }
    void OnPing(SpdyPingId unique_id, bool is_ack) override { LOG(FATAL); }
    void OnSettingsEnd() override { LOG(FATAL); }
    void OnGoAway(SpdyStreamId last_accepted_stream_id,
                  SpdyGoAwayStatus status) override {
      LOG(FATAL);
    }

    void OnHeaders(SpdyStreamId stream_id,
                   bool has_priority,
                   int weight,
                   SpdyStreamId parent_stream_id,
                   bool exclusive,
                   bool fin,
                   bool end) override {
      SpdyFramer framer(version_);
      framer.set_enable_compression(false);
      SpdyHeadersIR headers(stream_id);
      headers.set_has_priority(has_priority);
      headers.set_weight(weight);
      headers.set_parent_stream_id(parent_stream_id);
      headers.set_exclusive(exclusive);
      headers.set_fin(fin);
      SpdySerializedFrame frame(framer.SerializeHeaders(headers));
      ResetBuffer();
      memcpy(buffer_.get(), frame.data(), framer.GetHeadersMinimumSize());
      size_ += framer.GetHeadersMinimumSize();
    }

    void OnWindowUpdate(SpdyStreamId stream_id,
                        int delta_window_size) override {
      LOG(FATAL);
    }

    void OnPushPromise(SpdyStreamId stream_id,
                       SpdyStreamId promised_stream_id,
                       bool end) override {
      SpdyFramer framer(version_);
      framer.set_enable_compression(false);
      SpdyPushPromiseIR push_promise(stream_id, promised_stream_id);
      SpdySerializedFrame frame(framer.SerializePushPromise(push_promise));
      ResetBuffer();
      memcpy(buffer_.get(), frame.data(), framer.GetPushPromiseMinimumSize());
      size_ += framer.GetPushPromiseMinimumSize();
    }

    void OnContinuation(SpdyStreamId stream_id, bool end) override {
      LOG(FATAL);
    }

    void OnPriority(SpdyStreamId stream_id,
                    SpdyStreamId parent_stream_id,
                    int weight,
                    bool exclusive) override {
      // Do nothing.
    }

    bool OnUnknownFrame(SpdyStreamId stream_id, int frame_type) override {
      LOG(FATAL);
      return false;
    }

    char* ReleaseBuffer() {
      CHECK(finished_);
      return buffer_.release();
    }

    size_t size() const {
      CHECK(finished_);
      return size_;
    }

   private:
    SpdyMajorVersion version_;
    std::unique_ptr<char[]> buffer_;
    size_t size_;
    bool finished_;

    DISALLOW_COPY_AND_ASSIGN(DecompressionVisitor);
  };

 private:
  DISALLOW_COPY_AND_ASSIGN(SpdyFramerTestUtil);
};

MATCHER_P(IsFrameUnionOf, frame_list, "") {
  size_t size_verified = 0;
  for (const auto& frame : *frame_list) {
    if (arg.size() >= size_verified + frame.size()) {
      if (!memcmp(arg.data() + size_verified, frame.data(), frame.size())) {
        size_verified += frame.size();
      } else {
        CompareCharArraysWithHexError(
            "Header serialization methods should be equivalent: ",
            reinterpret_cast<unsigned char*>(arg.data() + size_verified),
            frame.size(), reinterpret_cast<unsigned char*>(frame.data()),
            frame.size());
        return false;
      }
    } else {
      LOG(FATAL) << "Incremental header serialization should not lead to a "
                 << "higher total frame length than non-incremental method.";
      return false;
    }
  }
  return size_verified == arg.size();
}

class SpdyFramerPeer {
 public:
  static size_t ControlFrameBufferSize() {
    return SpdyFramer::kControlFrameBufferSize;
  }
  static size_t GetNumberRequiredContinuationFrames(SpdyFramer* framer,
                                                    size_t size) {
    return framer->GetNumberRequiredContinuationFrames(size);
  }
  static void SetError(SpdyFramer* framer, SpdyFramer::SpdyError error) {
    framer->set_error(error);
  }

  // TODO(dahollings): Remove these methods when deprecating non-incremental
  // header serialization path.
  static std::unique_ptr<SpdyHeadersIR> CloneSpdyHeadersIR(
      const SpdyHeadersIR& headers) {
    auto newHeaders = base::MakeUnique<SpdyHeadersIR>(
        headers.stream_id(), headers.header_block().Clone());
    newHeaders->set_fin(headers.fin());
    newHeaders->set_has_priority(headers.has_priority());
    newHeaders->set_weight(headers.weight());
    newHeaders->set_parent_stream_id(headers.parent_stream_id());
    newHeaders->set_exclusive(headers.exclusive());
    if (headers.padded()) {
      newHeaders->set_padding_len(headers.padding_payload_len() + 1);
    }
    newHeaders->set_end_headers(headers.end_headers());
    return newHeaders;
  }

  static SpdySerializedFrame SerializeHeaders(SpdyFramer* framer,
                                              const SpdyHeadersIR& headers) {
    SpdySerializedFrame serialized_headers_old_version =
        framer->SerializeHeaders(headers);
    if (framer->protocol_version() == HTTP2) {
      framer->hpack_encoder_.reset(nullptr);
      auto saved_debug_visitor = framer->debug_visitor_;
      framer->debug_visitor_ = nullptr;

      std::vector<SpdySerializedFrame> frame_list;
      SpdyFramer::SpdyHeaderFrameIterator it(framer,
                                             CloneSpdyHeadersIR(headers));
      while (it.HasNextFrame()) {
        frame_list.push_back(it.NextFrame());
      }
      framer->debug_visitor_ = saved_debug_visitor;

      EXPECT_THAT(serialized_headers_old_version, IsFrameUnionOf(&frame_list));
    }
    return serialized_headers_old_version;
  }
};

class TestSpdyVisitor : public SpdyFramerVisitorInterface,
                        public SpdyFramerDebugVisitorInterface {
 public:
  // This is larger than our max frame size because header blocks that
  // are too long can spill over into CONTINUATION frames.
  static const size_t kDefaultHeaderBufferSize = 16 * 1024 * 1024;

  explicit TestSpdyVisitor(SpdyMajorVersion version)
      : framer_(version),
        use_compression_(false),
        error_count_(0),
        syn_frame_count_(0),
        syn_reply_frame_count_(0),
        headers_frame_count_(0),
        push_promise_frame_count_(0),
        goaway_count_(0),
        setting_count_(0),
        settings_ack_sent_(0),
        settings_ack_received_(0),
        continuation_count_(0),
        altsvc_count_(0),
        priority_count_(0),
        test_altsvc_ir_(0),
        on_unknown_frame_result_(false),
        last_window_update_stream_(0),
        last_window_update_delta_(0),
        last_push_promise_stream_(0),
        last_push_promise_promised_stream_(0),
        data_bytes_(0),
        fin_frame_count_(0),
        fin_opaque_data_(),
        fin_flag_count_(0),
        end_of_stream_count_(0),
        control_frame_header_data_count_(0),
        zero_length_control_frame_header_data_count_(0),
        data_frame_count_(0),
        last_payload_len_(0),
        last_frame_len_(0),
        header_buffer_(new char[kDefaultHeaderBufferSize]),
        header_buffer_length_(0),
        header_buffer_size_(kDefaultHeaderBufferSize),
        header_stream_id_(static_cast<SpdyStreamId>(-1)),
        header_control_type_(DATA),
        header_buffer_valid_(false) {}

  void OnError(SpdyFramer* f) override {
    VLOG(1) << "SpdyFramer Error: "
            << SpdyFramer::ErrorCodeToString(f->error_code());
    ++error_count_;
  }

  void OnDataFrameHeader(SpdyStreamId stream_id,
                         size_t length,
                         bool fin) override {
    VLOG(1) << "OnDataFrameHeader(" << stream_id << ", " << length << ", "
            << fin << ")";
    ++data_frame_count_;
    header_stream_id_ = stream_id;
  }

  void OnStreamFrameData(SpdyStreamId stream_id,
                         const char* data,
                         size_t len) override {
    VLOG(1) << "OnStreamFrameData(" << stream_id << ", data, " << len << ", "
            << ")   data:\n"
            << base::HexEncode(data, len);
    EXPECT_EQ(header_stream_id_, stream_id);
    data_bytes_ += len;
  }

  void OnStreamEnd(SpdyStreamId stream_id) override {
    VLOG(1) << "OnStreamEnd(" << stream_id << ")";
    EXPECT_EQ(header_stream_id_, stream_id);
    ++end_of_stream_count_;
  }

  void OnStreamPadding(SpdyStreamId stream_id, size_t len) override {
    VLOG(1) << "OnStreamPadding(" << stream_id << ", " << len << ")\n";
    EXPECT_EQ(header_stream_id_, stream_id);
    data_bytes_ += len;
  }

  SpdyHeadersHandlerInterface* OnHeaderFrameStart(
      SpdyStreamId stream_id) override {
    if (headers_handler_ == nullptr) {
      headers_handler_.reset(new TestHeadersHandler);
    }
    return headers_handler_.get();
  }

  void OnHeaderFrameEnd(SpdyStreamId stream_id, bool end_headers) override {
    CHECK(headers_handler_ != nullptr);
    headers_ = headers_handler_->decoded_block().Clone();
    header_bytes_received_ = headers_handler_->header_bytes_parsed();
    if (end_headers) {
      headers_handler_.reset();
    }
  }

  bool OnControlFrameHeaderData(SpdyStreamId stream_id,
                                const char* header_data,
                                size_t len) override {
    VLOG(1) << "OnControlFrameHeaderData(" << stream_id << ", data, " << len
            << ")";
    ++control_frame_header_data_count_;
    CHECK_EQ(header_stream_id_, stream_id);
    if (len == 0) {
      ++zero_length_control_frame_header_data_count_;
      // Indicates end-of-header-block.
      headers_.clear();
      CHECK(header_buffer_valid_);
      return framer_.ParseHeaderBlockInBuffer(header_buffer_.get(),
                                              header_buffer_length_, &headers_);
    }
    const size_t available = header_buffer_size_ - header_buffer_length_;
    if (len > available) {
      header_buffer_valid_ = false;
      return false;
    }
    memcpy(header_buffer_.get() + header_buffer_length_, header_data, len);
    header_buffer_length_ += len;
    return true;
  }

  void OnSynStream(SpdyStreamId stream_id,
                   SpdyStreamId associated_stream_id,
                   SpdyPriority priority,
                   bool fin,
                   bool unidirectional) override {
    VLOG(1) << "OnSynStream(" << stream_id << ", " << associated_stream_id
            << ", " << priority << ", " << (fin ? 1 : 0) << ", "
            << (unidirectional ? 1 : 0) << ")";
    ++syn_frame_count_;
    if (framer_.protocol_version() == SPDY3) {
      InitHeaderStreaming(SYN_STREAM, stream_id);
    } else {
      InitHeaderStreaming(HEADERS, stream_id);
    }
    if (fin) {
      ++fin_flag_count_;
    }
  }

  void OnSynReply(SpdyStreamId stream_id, bool fin) override {
    ++syn_reply_frame_count_;
    if (framer_.protocol_version() == SPDY3) {
      InitHeaderStreaming(SYN_REPLY, stream_id);
    } else {
      InitHeaderStreaming(HEADERS, stream_id);
    }
    if (fin) {
      ++fin_flag_count_;
    }
  }

  void OnRstStream(SpdyStreamId stream_id,
                   SpdyRstStreamStatus status) override {
    VLOG(1) << "OnRstStream(" << stream_id << ", " << status << ")";
    ++fin_frame_count_;
  }

  bool OnRstStreamFrameData(const char* rst_stream_data, size_t len) override {
    if ((rst_stream_data != NULL) && (len > 0)) {
      fin_opaque_data_ += string(rst_stream_data, len);
    }
    return true;
  }

  void OnSetting(SpdySettingsIds id, uint8_t flags, uint32_t value) override {
    VLOG(1) << "OnSetting(" << id << ", " << std::hex << flags << ", " << value
            << ")";
    ++setting_count_;
  }

  void OnSettingsAck() override {
    VLOG(1) << "OnSettingsAck";
    DCHECK_EQ(HTTP2, framer_.protocol_version());
    ++settings_ack_received_;
  }

  void OnSettingsEnd() override {
    VLOG(1) << "OnSettingsEnd";
    if (framer_.protocol_version() == HTTP2) {
      ++settings_ack_sent_;
    }
  }

  void OnPing(SpdyPingId unique_id, bool is_ack) override {
    LOG(DFATAL) << "OnPing(" << unique_id << ", " << (is_ack ? 1 : 0) << ")";
  }

  void OnGoAway(SpdyStreamId last_accepted_stream_id,
                SpdyGoAwayStatus status) override {
    VLOG(1) << "OnGoAway(" << last_accepted_stream_id << ", " << status << ")";
    ++goaway_count_;
  }

  void OnHeaders(SpdyStreamId stream_id,
                 bool has_priority,
                 int weight,
                 SpdyStreamId parent_stream_id,
                 bool exclusive,
                 bool fin,
                 bool end) override {
    VLOG(1) << "OnHeaders(" << stream_id << ", " << has_priority << ", "
            << weight << ", " << parent_stream_id << ", " << exclusive << ", "
            << fin << ", " << end << ")";
    ++headers_frame_count_;
    InitHeaderStreaming(HEADERS, stream_id);
    if (fin) {
      ++fin_flag_count_;
    }
    header_has_priority_ = has_priority;
    header_parent_stream_id_ = parent_stream_id;
    header_exclusive_ = exclusive;
  }

  void OnWindowUpdate(SpdyStreamId stream_id, int delta_window_size) override {
    VLOG(1) << "OnWindowUpdate(" << stream_id << ", " << delta_window_size
            << ")";
    last_window_update_stream_ = stream_id;
    last_window_update_delta_ = delta_window_size;
  }

  void OnPushPromise(SpdyStreamId stream_id,
                     SpdyStreamId promised_stream_id,
                     bool end) override {
    VLOG(1) << "OnPushPromise(" << stream_id << ", " << promised_stream_id
            << ", " << end << ")";
    ++push_promise_frame_count_;
    InitHeaderStreaming(PUSH_PROMISE, stream_id);
    last_push_promise_stream_ = stream_id;
    last_push_promise_promised_stream_ = promised_stream_id;
  }

  void OnContinuation(SpdyStreamId stream_id, bool end) override {
    VLOG(1) << "OnContinuation(" << stream_id << ", " << end << ")";
    ++continuation_count_;
  }

  void OnAltSvc(SpdyStreamId stream_id,
                StringPiece origin,
                const SpdyAltSvcWireFormat::AlternativeServiceVector&
                    altsvc_vector) override {
    VLOG(1) << "OnAltSvc(" << stream_id << ", \"" << origin
            << "\", altsvc_vector)";
    test_altsvc_ir_.set_stream_id(stream_id);
    if (origin.length() > 0) {
      test_altsvc_ir_.set_origin(origin.as_string());
    }
    for (const SpdyAltSvcWireFormat::AlternativeService& altsvc :
         altsvc_vector) {
      test_altsvc_ir_.add_altsvc(altsvc);
    }
    ++altsvc_count_;
  }

  void OnPriority(SpdyStreamId stream_id,
                  SpdyStreamId parent_stream_id,
                  int weight,
                  bool exclusive) override {
    VLOG(1) << "OnPriority(" << stream_id << ", " << parent_stream_id << ", "
            << weight << ", " << (exclusive ? 1 : 0) << ")";
    ++priority_count_;
  }

  bool OnUnknownFrame(SpdyStreamId stream_id, int frame_type) override {
    VLOG(1) << "OnUnknownFrame(" << stream_id << ", " << frame_type << ")";
    return on_unknown_frame_result_;
  }

  void OnSendCompressedFrame(SpdyStreamId stream_id,
                             SpdyFrameType type,
                             size_t payload_len,
                             size_t frame_len) override {
    VLOG(1) << "OnSendCompressedFrame(" << stream_id << ", " << type << ", "
            << payload_len << ", " << frame_len << ")";
    last_payload_len_ = payload_len;
    last_frame_len_ = frame_len;
  }

  void OnReceiveCompressedFrame(SpdyStreamId stream_id,
                                SpdyFrameType type,
                                size_t frame_len) override {
    VLOG(1) << "OnReceiveCompressedFrame(" << stream_id << ", " << type << ", "
            << frame_len << ")";
    last_frame_len_ = frame_len;
  }

  // Convenience function which runs a framer simulation with particular input.
  void SimulateInFramer(const unsigned char* input, size_t size) {
    framer_.set_enable_compression(use_compression_);
    framer_.set_visitor(this);
    size_t input_remaining = size;
    const char* input_ptr = reinterpret_cast<const char*>(input);
    while (input_remaining > 0 &&
           framer_.error_code() == SpdyFramer::SPDY_NO_ERROR) {
      // To make the tests more interesting, we feed random (and small) chunks
      // into the framer.  This simulates getting strange-sized reads from
      // the socket.
      const size_t kMaxReadSize = 32;
      size_t bytes_read =
          (rand() % std::min(input_remaining, kMaxReadSize)) + 1;
      size_t bytes_processed = framer_.ProcessInput(input_ptr, bytes_read);
      input_remaining -= bytes_processed;
      input_ptr += bytes_processed;
    }
  }

  void InitHeaderStreaming(SpdyFrameType header_control_type,
                           SpdyStreamId stream_id) {
    if (!SpdyConstants::IsValidFrameType(
            framer_.protocol_version(),
            SpdyConstants::SerializeFrameType(framer_.protocol_version(),
                                              header_control_type))) {
      DLOG(FATAL) << "Attempted to init header streaming with "
                  << "invalid control frame type: " << header_control_type;
    }
    memset(header_buffer_.get(), 0, header_buffer_size_);
    header_buffer_length_ = 0;
    header_stream_id_ = stream_id;
    header_control_type_ = header_control_type;
    header_buffer_valid_ = true;
    DCHECK_NE(header_stream_id_, SpdyFramer::kInvalidStream);
  }

  // Override the default buffer size (16K). Call before using the framer!
  void set_header_buffer_size(size_t header_buffer_size) {
    header_buffer_size_ = header_buffer_size;
    header_buffer_.reset(new char[header_buffer_size]);
  }

  // Largest control frame that the SPDY implementation sends, including the
  // size of the header.
  static size_t sent_control_frame_max_size() {
    return SpdyFramer::kMaxControlFrameSize;
  }

  // Largest control frame that the SPDY implementation is willing to receive,
  // excluding the size of the header.
  static size_t received_control_frame_max_size() {
    return kSpdyInitialFrameSizeLimit;
  }

  static size_t header_data_chunk_max_size() {
    return SpdyFramer::kHeaderDataChunkMaxSize;
  }

  SpdyFramer framer_;
  bool use_compression_;

  // Counters from the visitor callbacks.
  int error_count_;
  int syn_frame_count_;
  int syn_reply_frame_count_;
  int headers_frame_count_;
  int push_promise_frame_count_;
  int goaway_count_;
  int setting_count_;
  int settings_ack_sent_;
  int settings_ack_received_;
  int continuation_count_;
  int altsvc_count_;
  int priority_count_;
  SpdyAltSvcIR test_altsvc_ir_;
  bool on_unknown_frame_result_;
  SpdyStreamId last_window_update_stream_;
  int last_window_update_delta_;
  SpdyStreamId last_push_promise_stream_;
  SpdyStreamId last_push_promise_promised_stream_;
  int data_bytes_;
  int fin_frame_count_;  // The count of RST_STREAM type frames received.
  string fin_opaque_data_;
  int fin_flag_count_;       // The count of frames with the FIN flag set.
  int end_of_stream_count_;  // The count of zero-length data frames.
  int control_frame_header_data_count_;  // The count of chunks received.
  // The count of zero-length control frame header data chunks received.
  int zero_length_control_frame_header_data_count_;
  int data_frame_count_;
  size_t last_payload_len_;
  size_t last_frame_len_;

  // Header block streaming state:
  std::unique_ptr<char[]> header_buffer_;
  size_t header_buffer_length_;
  size_t header_buffer_size_;
  size_t header_bytes_received_;
  SpdyStreamId header_stream_id_;
  SpdyFrameType header_control_type_;
  bool header_buffer_valid_;
  std::unique_ptr<TestHeadersHandler> headers_handler_;
  SpdyHeaderBlock headers_;
  bool header_has_priority_;
  SpdyStreamId header_parent_stream_id_;
  bool header_exclusive_;
};

// Retrieves serialized headers from a HEADERS or SYN_STREAM frame.
StringPiece GetSerializedHeaders(const SpdySerializedFrame& frame,
                                 const SpdyFramer& framer) {
  SpdyFrameReader reader(frame.data(), frame.size());
  if (framer.protocol_version() == SPDY3) {
    reader.Seek(2);  // Seek past the frame length.
  } else {
    reader.Seek(3);  // Seek past the frame length.
  }
  SpdyFrameType frame_type;
  if (framer.protocol_version() == SPDY3) {
    uint16_t serialized_type;
    reader.ReadUInt16(&serialized_type);
    frame_type = SpdyConstants::ParseFrameType(framer.protocol_version(),
                                               serialized_type);
    DCHECK(frame_type == HEADERS || frame_type == SYN_STREAM) << frame_type;
  } else {
    uint8_t serialized_type;
    reader.ReadUInt8(&serialized_type);
    frame_type = SpdyConstants::ParseFrameType(framer.protocol_version(),
                                               serialized_type);
    DCHECK_EQ(HEADERS, frame_type);
    uint8_t flags;
    reader.ReadUInt8(&flags);
    if (flags & HEADERS_FLAG_PRIORITY) {
      frame_type = SYN_STREAM;
    }
  }

  if (frame_type == SYN_STREAM) {
    return StringPiece(frame.data() + framer.GetSynStreamMinimumSize(),
                       frame.size() - framer.GetSynStreamMinimumSize());
  } else {
    return StringPiece(frame.data() + framer.GetHeadersMinimumSize(),
                       frame.size() - framer.GetHeadersMinimumSize());
  }
}

class SpdyFramerTest : public ::testing::TestWithParam<SpdyMajorVersion> {
 protected:
  void SetUp() override { spdy_version_ = GetParam(); }

  void CompareFrame(const string& description,
                    const SpdySerializedFrame& actual_frame,
                    const unsigned char* expected,
                    const int expected_len) {
    const unsigned char* actual =
        reinterpret_cast<const unsigned char*>(actual_frame.data());
    CompareCharArraysWithHexError(description, actual, actual_frame.size(),
                                  expected, expected_len);
  }

  void CompareFrames(const string& description,
                     const SpdySerializedFrame& expected_frame,
                     const SpdySerializedFrame& actual_frame) {
    CompareCharArraysWithHexError(
        description,
        reinterpret_cast<const unsigned char*>(expected_frame.data()),
        expected_frame.size(),
        reinterpret_cast<const unsigned char*>(actual_frame.data()),
        actual_frame.size());
  }

  bool IsSpdy3() { return spdy_version_ == SPDY3; }
  bool IsHttp2() { return spdy_version_ == HTTP2; }

  // Version of SPDY protocol to be used.
  SpdyMajorVersion spdy_version_;
};

// All tests are run with SPDY/3 and HTTP/2.
INSTANTIATE_TEST_CASE_P(SpdyFramerTests,
                        SpdyFramerTest,
                        ::testing::Values(SPDY3, HTTP2));

// Test that we ignore cookie where both name and value are empty.
TEST_P(SpdyFramerTest, HeaderBlockWithEmptyCookie) {
  if (!IsSpdy3()) {
    // Not implemented for hpack.
    return;
  }

  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(true);
  SpdyHeadersIR headers(1);
  headers.SetHeader("cookie",
                    "=; key=value; ;  = ; foo; bar=;  ;  =   ; k2=v2 ; =");
  SpdySerializedFrame frame(SpdyFramerPeer::SerializeHeaders(&framer, headers));

  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = true;
  visitor.SimulateInFramer(reinterpret_cast<unsigned char*>(frame.data()),
                           frame.size());

  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
  EXPECT_NE(headers.header_block(), visitor.headers_);
  EXPECT_EQ(1u, visitor.headers_.size());
  EXPECT_EQ("key=value; foo; bar=; k2=v2 ", visitor.headers_["cookie"]);
}

// Test that we can encode and decode a SpdyHeaderBlock in serialized form.
TEST_P(SpdyFramerTest, HeaderBlockInBuffer) {
  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(false);

  // Encode the header block into a Headers frame.
  SpdyHeadersIR headers(1);
  headers.SetHeader("alpha", "beta");
  headers.SetHeader("gamma", "charlie");
  headers.SetHeader("cookie", "key1=value1; key2=value2");
  SpdySerializedFrame frame(SpdyFramerPeer::SerializeHeaders(&framer, headers));

  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = false;
  visitor.SimulateInFramer(reinterpret_cast<unsigned char*>(frame.data()),
                           frame.size());

  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
  EXPECT_EQ(headers.header_block(), visitor.headers_);
}

// Test that if there's not a full frame, we fail to parse it.
TEST_P(SpdyFramerTest, UndersizedHeaderBlockInBuffer) {
  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(false);

  // Encode the header block into a Headers frame.
  SpdyHeadersIR headers(1);
  headers.SetHeader("alpha", "beta");
  headers.SetHeader("gamma", "charlie");
  SpdySerializedFrame frame(SpdyFramerPeer::SerializeHeaders(&framer, headers));

  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = false;
  visitor.SimulateInFramer(reinterpret_cast<unsigned char*>(frame.data()),
                           frame.size() - 2);

  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
  EXPECT_EQ(0u, visitor.headers_.size());
}

// Test that we can encode and decode stream dependency values in a header
// frame.
TEST_P(SpdyFramerTest, HeaderStreamDependencyValues) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(false);

  const SpdyStreamId parent_stream_id_test_array[] = {0, 3};
  for (SpdyStreamId parent_stream_id : parent_stream_id_test_array) {
    const bool exclusive_test_array[] = {true, false};
    for (bool exclusive : exclusive_test_array) {
      SpdyHeadersIR headers(1);
      headers.set_has_priority(true);
      headers.set_parent_stream_id(parent_stream_id);
      headers.set_exclusive(exclusive);
      SpdySerializedFrame frame(
          SpdyFramerPeer::SerializeHeaders(&framer, headers));

      TestSpdyVisitor visitor(spdy_version_);
      visitor.use_compression_ = false;
      visitor.SimulateInFramer(reinterpret_cast<unsigned char*>(frame.data()),
                               frame.size());

      EXPECT_TRUE(visitor.header_has_priority_);
      EXPECT_EQ(parent_stream_id, visitor.header_parent_stream_id_);
      EXPECT_EQ(exclusive, visitor.header_exclusive_);
    }
  }
}

// Test that if we receive a frame with payload length field at the
// advertised max size, we do not set an error in ProcessInput.
TEST_P(SpdyFramerTest, AcceptMaxFrameSizeSetting) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  // DATA frame with maximum allowed payload length.
  unsigned char kH2FrameData[] = {
      0x00, 0x40, 0x00,        // Length: 2^14
      0x00,                    //   Type: HEADERS
      0x00,                    //  Flags: None
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  // Junk payload
  };

  SpdySerializedFrame frame(reinterpret_cast<char*>(kH2FrameData),
                            sizeof(kH2FrameData), false);

  EXPECT_CALL(visitor, OnDataFrameHeader(1, 1 << 14, false));
  EXPECT_CALL(visitor, OnStreamFrameData(1, _, 4));
  framer.ProcessInput(frame.data(), frame.size());
  EXPECT_FALSE(framer.HasError());
}

// Test that if we receive a frame with payload length larger than the
// advertised max size, we set an error of SPDY_INVALID_CONTROL_FRAME_SIZE.
TEST_P(SpdyFramerTest, ExceedMaxFrameSizeSetting) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  // DATA frame with too large payload length.
  unsigned char kH2FrameData[] = {
      0x00, 0x40, 0x01,        // Length: 2^14 + 1
      0x00,                    //   Type: HEADERS
      0x00,                    //  Flags: None
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  // Junk payload
  };

  SpdySerializedFrame frame(reinterpret_cast<char*>(kH2FrameData),
                            sizeof(kH2FrameData), false);

  EXPECT_CALL(visitor, OnError(testing::Eq(&framer)));
  framer.ProcessInput(frame.data(), frame.size());
  EXPECT_TRUE(framer.HasError());
  EXPECT_EQ(SpdyFramer::SPDY_OVERSIZED_PAYLOAD, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Test that if we receive a DATA frame with padding length larger than the
// payload length, we set an error of SPDY_INVALID_PADDING
TEST_P(SpdyFramerTest, OversizedDataPaddingError) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  // DATA frame with invalid padding length.
  // |kH2FrameData| has to be |unsigned char|, because Chromium on Windows uses
  // MSVC, where |char| is signed by default, which would not compile because of
  // the element exceeding 127.
  unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x00,                    //   Type: DATA
      0x09,                    //  Flags: END_STREAM|PADDED
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0xff,                    // PadLen: 255 trailing bytes (Too Long)
      0x00, 0x00, 0x00, 0x00,  // Padding
  };

  SpdySerializedFrame frame(reinterpret_cast<char*>(kH2FrameData),
                            sizeof(kH2FrameData), false);

  {
    testing::InSequence seq;
    EXPECT_CALL(visitor, OnDataFrameHeader(1, 5, 1));
    EXPECT_CALL(visitor, OnStreamPadding(1, 1));
    EXPECT_CALL(visitor, OnError(testing::Eq(&framer)));
  }
  EXPECT_GT(frame.size(), framer.ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(framer.HasError());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_PADDING, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Test that if we receive a DATA frame with padding length not larger than the
// payload length, we do not set an error of SPDY_INVALID_PADDING
TEST_P(SpdyFramerTest, CorrectlySizedDataPaddingNoError) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  // DATA frame with valid Padding length
  char kH2FrameData[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x00,                    //   Type: DATA
      0x08,                    //  Flags: PADDED
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x04,                    // PadLen: 4 trailing bytes
      0x00, 0x00, 0x00, 0x00,  // Padding
  };

  SpdySerializedFrame frame(kH2FrameData, sizeof(kH2FrameData), false);

  {
    testing::InSequence seq;
    EXPECT_CALL(visitor, OnDataFrameHeader(1, 5, false));
    EXPECT_CALL(visitor, OnStreamPadding(1, 1));
    EXPECT_CALL(visitor, OnError(testing::Eq(&framer))).Times(0);
    // Note that OnStreamFrameData(1, _, 1)) is never called
    // since there is no data, only padding
    EXPECT_CALL(visitor, OnStreamPadding(1, 4));
  }

  EXPECT_EQ(frame.size(), framer.ProcessInput(frame.data(), frame.size()));
  EXPECT_FALSE(framer.HasError());
  EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Test that if we receive a HEADERS frame with padding length larger than the
// payload length, we set an error of SPDY_INVALID_PADDING
TEST_P(SpdyFramerTest, OversizedHeadersPaddingError) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  // HEADERS frame with invalid padding length.
  // |kH2FrameData| has to be |unsigned char|, because Chromium on Windows uses
  // MSVC, where |char| is signed by default, which would not compile because of
  // the element exceeding 127.
  unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x01,                    //   Type: HEADERS
      0x08,                    //  Flags: PADDED
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0xff,                    // PadLen: 255 trailing bytes (Too Long)
      0x00, 0x00, 0x00, 0x00,  // Padding
  };

  SpdySerializedFrame frame(reinterpret_cast<char*>(kH2FrameData),
                            sizeof(kH2FrameData), false);

  EXPECT_CALL(visitor, OnHeaders(1, false, 0, 0, false, false, false));
  EXPECT_CALL(visitor, OnHeaderFrameStart(1)).Times(1);
  EXPECT_CALL(visitor, OnError(testing::Eq(&framer)));
  EXPECT_EQ(frame.size(), framer.ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(framer.HasError());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_PADDING, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Test that if we receive a HEADERS frame with padding length not larger
// than the payload length, we do not set an error of SPDY_INVALID_PADDING
TEST_P(SpdyFramerTest, CorrectlySizedHeadersPaddingNoError) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  // HEADERS frame with invalid Padding length
  char kH2FrameData[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x01,                    //   Type: HEADERS
      0x08,                    //  Flags: PADDED
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x04,                    // PadLen: 4 trailing bytes
      0x00, 0x00, 0x00, 0x00,  // Padding
  };

  SpdySerializedFrame frame(kH2FrameData, sizeof(kH2FrameData), false);

  EXPECT_CALL(visitor, OnHeaders(1, false, 0, 0, false, false, false));
  EXPECT_CALL(visitor, OnHeaderFrameStart(1)).Times(1);
  EXPECT_EQ(frame.size(), framer.ProcessInput(frame.data(), frame.size()));
  EXPECT_FALSE(framer.HasError());
  EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Test that if we receive a SYN_REPLY with stream ID zero, we signal an error
// (but don't crash).
TEST_P(SpdyFramerTest, SynReplyWithStreamIdZero) {
  if (!IsSpdy3()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  SpdySynReplyIR syn_reply(0);
  syn_reply.SetHeader("alpha", "beta");
  SpdySerializedFrame frame(framer.SerializeSynReply(syn_reply));

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnError(testing::Eq(&framer)));
  EXPECT_GT(frame.size(), framer.ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(framer.HasError());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_CONTROL_FRAME, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Test that if we receive a DATA with stream ID zero, we signal an error
// (but don't crash).
TEST_P(SpdyFramerTest, DataWithStreamIdZero) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  const char bytes[] = "hello";
  SpdyDataIR data_ir(0, bytes);
  SpdySerializedFrame frame(framer.SerializeData(data_ir));

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnError(testing::Eq(&framer)));
  EXPECT_GT(frame.size(), framer.ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(framer.HasError());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_STREAM_ID, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Test that if we receive a HEADERS with stream ID zero, we signal an error
// (but don't crash).
TEST_P(SpdyFramerTest, HeadersWithStreamIdZero) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  SpdyHeadersIR headers(0);
  headers.SetHeader("alpha", "beta");
  SpdySerializedFrame frame(SpdyFramerPeer::SerializeHeaders(&framer, headers));

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnError(testing::Eq(&framer)));
  EXPECT_GT(frame.size(), framer.ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(framer.HasError());
  if (IsHttp2()) {
    EXPECT_EQ(SpdyFramer::SPDY_INVALID_STREAM_ID, framer.error_code())
        << SpdyFramer::ErrorCodeToString(framer.error_code());
  } else {
    EXPECT_EQ(SpdyFramer::SPDY_INVALID_CONTROL_FRAME, framer.error_code())
        << SpdyFramer::ErrorCodeToString(framer.error_code());
  }
}

// Test that if we receive a PRIORITY with stream ID zero, we signal an error
// (but don't crash).
TEST_P(SpdyFramerTest, PriorityWithStreamIdZero) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  SpdyPriorityIR priority_ir(0, 1, 16, true);
  SpdySerializedFrame frame(framer.SerializeFrame(priority_ir));

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnError(testing::Eq(&framer)));
  EXPECT_GT(frame.size(), framer.ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(framer.HasError());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_STREAM_ID, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Test that if we receive a RST_STREAM with stream ID zero, we signal an error
// (but don't crash).
TEST_P(SpdyFramerTest, RstStreamWithStreamIdZero) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  SpdyRstStreamIR rst_stream_ir(0, RST_STREAM_PROTOCOL_ERROR);
  SpdySerializedFrame frame(framer.SerializeRstStream(rst_stream_ir));

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnError(testing::Eq(&framer)));
  EXPECT_GT(frame.size(), framer.ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(framer.HasError());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_STREAM_ID, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Test that if we receive a SETTINGS with stream ID other than zero,
// we signal an error (but don't crash).
TEST_P(SpdyFramerTest, SettingsWithStreamIdNotZero) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  // Settings frame with invalid StreamID of 0x01
  char kH2FrameData[] = {
      0x00, 0x00, 0x06,        // Length: 6
      0x04,                    //   Type: SETTINGS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x04,              //  Param: INITIAL_WINDOW_SIZE
      0x0a, 0x0b, 0x0c, 0x0d,  //  Value: 168496141
  };

  SpdySerializedFrame frame(kH2FrameData, sizeof(kH2FrameData), false);

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnError(testing::Eq(&framer)));
  EXPECT_GT(frame.size(), framer.ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(framer.HasError());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_STREAM_ID, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Test that if we receive a GOAWAY with stream ID other than zero,
// we signal an error (but don't crash).
TEST_P(SpdyFramerTest, GoawayWithStreamIdNotZero) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  // GOAWAY frame with invalid StreamID of 0x01
  char kH2FrameData[] = {
      0x00, 0x00, 0x0a,        // Length: 10
      0x07,                    //   Type: GOAWAY
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  //   Last: 0
      0x00, 0x00, 0x00, 0x00,  //  Error: NO_ERROR
      0x47, 0x41,              // Description
  };

  SpdySerializedFrame frame(kH2FrameData, sizeof(kH2FrameData), false);

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnError(testing::Eq(&framer)));
  EXPECT_GT(frame.size(), framer.ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(framer.HasError());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_STREAM_ID, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Test that if we receive a CONTINUATION with stream ID zero, we signal an
// SPDY_INVALID_STREAM_ID.
TEST_P(SpdyFramerTest, ContinuationWithStreamIdZero) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  SpdyContinuationIR continuation(0);
  auto some_nonsense_encoding =
      base::MakeUnique<string>("some nonsense encoding");
  continuation.take_encoding(std::move(some_nonsense_encoding));
  continuation.set_end_headers(true);
  SpdySerializedFrame frame(framer.SerializeContinuation(continuation));

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnError(testing::Eq(&framer)));
  EXPECT_GT(frame.size(), framer.ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(framer.HasError());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_STREAM_ID, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Test that if we receive a PUSH_PROMISE with stream ID zero, we signal an
// SPDY_INVALID_STREAM_ID.
TEST_P(SpdyFramerTest, PushPromiseWithStreamIdZero) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  SpdyPushPromiseIR push_promise(0, 4);
  push_promise.SetHeader("alpha", "beta");
  SpdySerializedFrame frame(framer.SerializePushPromise(push_promise));

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnError(testing::Eq(&framer)));
  EXPECT_GT(frame.size(), framer.ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(framer.HasError());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_STREAM_ID, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Test that if we receive a PUSH_PROMISE with promised stream ID zero, we
// signal SPDY_INVALID_STREAM_ID.
TEST_P(SpdyFramerTest, PushPromiseWithPromisedStreamIdZero) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  SpdyPushPromiseIR push_promise(3, 0);
  push_promise.SetHeader("alpha", "beta");
  SpdySerializedFrame frame(framer.SerializePushPromise(push_promise));

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnError(testing::Eq(&framer)));
  EXPECT_GT(frame.size(), framer.ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(framer.HasError());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_CONTROL_FRAME, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

TEST_P(SpdyFramerTest, DuplicateHeader) {
  if (!IsSpdy3()) {
    // TODO(jgraettinger): Punting on this because we haven't determined
    // whether duplicate HPACK headers other than Cookie are an error.
    // If they are, this will need to be updated to use HpackOutputStream.
    return;
  }
  SpdyFramer framer(spdy_version_);
  // Frame builder with plentiful buffer size.
  SpdyFrameBuilder frame(1024, spdy_version_);
  if (spdy_version_ <= SPDY3) {
    frame.WriteControlFrameHeader(framer, SYN_STREAM, CONTROL_FLAG_NONE);
    frame.WriteUInt32(3);  // stream_id
    frame.WriteUInt32(0);  // associated stream id
    frame.WriteUInt16(0);  // Priority.
  } else {
    frame.BeginNewFrame(framer, HEADERS, HEADERS_FLAG_PRIORITY, 3);
    frame.WriteUInt32(framer.GetHighestPriority());
  }

  frame.WriteUInt32(2);  // Number of headers.
  frame.WriteStringPiece32("name");
  frame.WriteStringPiece32("value1");
  frame.WriteStringPiece32("name");
  frame.WriteStringPiece32("value2");
  // write the length
  frame.RewriteLength(framer);

  SpdyHeaderBlock new_headers;
  framer.set_enable_compression(false);
  SpdySerializedFrame control_frame(frame.take());
  StringPiece serialized_headers = GetSerializedHeaders(control_frame, framer);
  // This should fail because duplicate headers are verboten by the spec.
  EXPECT_FALSE(framer.ParseHeaderBlockInBuffer(
      serialized_headers.data(), serialized_headers.size(), &new_headers));
}

TEST_P(SpdyFramerTest, MultiValueHeader) {
  SpdyFramer framer(spdy_version_);
  // Frame builder with plentiful buffer size.
  SpdyFrameBuilder frame(1024, spdy_version_);
  if (IsSpdy3()) {
    frame.WriteControlFrameHeader(framer, SYN_STREAM, CONTROL_FLAG_NONE);
    frame.WriteUInt32(3);  // stream_id
    frame.WriteUInt32(0);  // associated stream id
    frame.WriteUInt16(0);  // Priority.
  } else {
    frame.BeginNewFrame(framer, HEADERS,
                        HEADERS_FLAG_PRIORITY | HEADERS_FLAG_END_HEADERS, 3);
    frame.WriteUInt32(0);   // Priority exclusivity and dependent stream.
    frame.WriteUInt8(255);  // Priority weight.
  }

  string value("value1\0value2", 13);
  if (IsSpdy3()) {
    frame.WriteUInt32(1);  // Number of headers.
    frame.WriteStringPiece32("name");
    frame.WriteStringPiece32(value);
  } else {
    // TODO(jgraettinger): If this pattern appears again, move to test class.
    SpdyHeaderBlock header_set;
    header_set["name"] = value;
    string buffer;
    HpackEncoder encoder(ObtainHpackHuffmanTable());
    encoder.EncodeHeaderSetWithoutCompression(header_set, &buffer);
    frame.WriteBytes(&buffer[0], buffer.size());
  }
  // write the length
  frame.RewriteLength(framer);

  framer.set_enable_compression(false);
  SpdySerializedFrame control_frame(frame.take());

  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = false;
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());

  EXPECT_THAT(visitor.headers_,
              testing::ElementsAre(testing::Pair("name", StringPiece(value))));
}

TEST_P(SpdyFramerTest, BasicCompression) {
  if (!IsSpdy3()) {
    // Deflate compression doesn't apply to HPACK.
    return;
  }

  std::unique_ptr<TestSpdyVisitor> visitor(new TestSpdyVisitor(spdy_version_));
  SpdyFramer framer(spdy_version_);
  framer.set_debug_visitor(visitor.get());
  SpdySynStreamIR syn_stream(1);
  syn_stream.set_priority(1);
  syn_stream.SetHeader("server", "SpdyServer 1.0");
  syn_stream.SetHeader("date", "Mon 12 Jan 2009 12:12:12 PST");
  syn_stream.SetHeader("status", "200");
  syn_stream.SetHeader("version", "HTTP/1.1");
  syn_stream.SetHeader("content-type", "text/html");
  syn_stream.SetHeader("content-length", "12");
  SpdySerializedFrame frame1(framer.SerializeSynStream(syn_stream));
  size_t uncompressed_size1 = visitor->last_payload_len_;
  size_t compressed_size1 =
      visitor->last_frame_len_ - framer.GetSynStreamMinimumSize();
  EXPECT_EQ(165u, uncompressed_size1);
#if defined(USE_SYSTEM_ZLIB)
  EXPECT_EQ(181u, compressed_size1);
#else   // !defined(USE_SYSTEM_ZLIB)
  EXPECT_EQ(116u, compressed_size1);
#endif  // !defined(USE_SYSTEM_ZLIB)
  SpdySerializedFrame frame2(framer.SerializeSynStream(syn_stream));
  size_t uncompressed_size2 = visitor->last_payload_len_;
  size_t compressed_size2 =
      visitor->last_frame_len_ - framer.GetSynStreamMinimumSize();

  // Expect the second frame to be more compact than the first.
  EXPECT_LE(frame2.size(), frame1.size());

  // Decompress the first frame
  SpdySerializedFrame frame3(
      SpdyFramerTestUtil::DecompressFrame(&framer, frame1));

  // Decompress the second frame
  visitor.reset(new TestSpdyVisitor(spdy_version_));
  framer.set_debug_visitor(visitor.get());
  SpdySerializedFrame frame4(
      SpdyFramerTestUtil::DecompressFrame(&framer, frame2));
  size_t uncompressed_size4 = frame4.size() - framer.GetSynStreamMinimumSize();
  size_t compressed_size4 =
      visitor->last_frame_len_ - framer.GetSynStreamMinimumSize();
  EXPECT_EQ(165u, uncompressed_size4);
#if defined(USE_SYSTEM_ZLIB)
  EXPECT_EQ(175u, compressed_size4);
#else   // !defined(USE_SYSTEM_ZLIB)
  EXPECT_EQ(98u, compressed_size4);
#endif  // !defined(USE_SYSTEM_ZLIB)

  EXPECT_EQ(uncompressed_size1, uncompressed_size2);
  EXPECT_EQ(uncompressed_size1, uncompressed_size4);
  EXPECT_EQ(compressed_size2, compressed_size4);

  // Expect frames 3 & 4 to be the same.
  CompareFrames("Uncompressed SYN_STREAM", frame3, frame4);

  // Expect frames 3 to be the same as a uncompressed frame created
  // from scratch.
  framer.set_enable_compression(false);
  SpdySerializedFrame uncompressed_frame(framer.SerializeSynStream(syn_stream));
  CompareFrames("Uncompressed SYN_STREAM", frame3, uncompressed_frame);
}

TEST_P(SpdyFramerTest, CompressEmptyHeaders) {
  // See crbug.com/172383
  SpdyHeadersIR headers(1);
  headers.SetHeader("server", "SpdyServer 1.0");
  headers.SetHeader("date", "Mon 12 Jan 2009 12:12:12 PST");
  headers.SetHeader("status", "200");
  headers.SetHeader("version", "HTTP/1.1");
  headers.SetHeader("content-type", "text/html");
  headers.SetHeader("content-length", "12");
  headers.SetHeader("x-empty-header", "");

  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(true);
  SpdySerializedFrame frame1(
      SpdyFramerPeer::SerializeHeaders(&framer, headers));
}

TEST_P(SpdyFramerTest, Basic) {
  // clang-format off
  const unsigned char kV3Input[] = {
    0x80, 0x03, 0x00, 0x01,  // SYN Stream #1
    0x00, 0x00, 0x00, 0x1a,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00,
    0x00, 0x02, 'h', 'h',
    0x00, 0x00, 0x00, 0x02,
    'v', 'v',

    0x80, 0x03, 0x00, 0x08,  // HEADERS on Stream #1
    0x00, 0x00, 0x00, 0x20,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x02,
    'h', '2',
    0x00, 0x00, 0x00, 0x02,
    'v', '2', 0x00, 0x00,
    0x00, 0x02, 'h', '3',
    0x00, 0x00, 0x00, 0x02,
    'v', '3',

    0x00, 0x00, 0x00, 0x01,  // DATA on Stream #1
    0x00, 0x00, 0x00, 0x0c,
    0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef,

    0x80, 0x03, 0x00, 0x01,  // SYN Stream #3
    0x00, 0x00, 0x00, 0x0e,
    0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,

    0x00, 0x00, 0x00, 0x03,  // DATA on Stream #3
    0x00, 0x00, 0x00, 0x08,
    0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef,

    0x00, 0x00, 0x00, 0x01,  // DATA on Stream #1
    0x00, 0x00, 0x00, 0x04,
    0xde, 0xad, 0xbe, 0xef,

    0x80, 0x03, 0x00, 0x03,  // RST_STREAM on Stream #1
    0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x05,  // RST_STREAM_CANCEL

    0x00, 0x00, 0x00, 0x03,  // DATA on Stream #3
    0x00, 0x00, 0x00, 0x00,

    0x80, 0x03, 0x00, 0x03,  // RST_STREAM on Stream #3
    0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x05,  // RST_STREAM_CANCEL
  };
  // clang-format on

  // SYN_STREAM doesn't exist in HTTP/2, so instead we send
  // HEADERS frames with PRIORITY and END_HEADERS set.
  // frame-format off
  const unsigned char kH2Input[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x01,                    //   Type: HEADERS
      0x24,                    //  Flags: END_HEADERS|PRIORITY
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  // Parent: 0
      0x82,                    // Weight: 131

      0x00, 0x00, 0x01,        // Length: 1
      0x01,                    //   Type: HEADERS
      0x04,                    //  Flags: END_HEADERS
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x8c,                    // :status: 200

      0x00, 0x00, 0x0c,        // Length: 12
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0xde, 0xad, 0xbe, 0xef,  // Payload
      0xde, 0xad, 0xbe, 0xef,  //
      0xde, 0xad, 0xbe, 0xef,  //

      0x00, 0x00, 0x05,        // Length: 5
      0x01,                    //   Type: HEADERS
      0x24,                    //  Flags: END_HEADERS|PRIORITY
      0x00, 0x00, 0x00, 0x03,  // Stream: 3
      0x00, 0x00, 0x00, 0x00,  // Parent: 0
      0x82,                    // Weight: 131

      0x00, 0x00, 0x08,        // Length: 8
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x03,  // Stream: 3
      0xde, 0xad, 0xbe, 0xef,  // Payload
      0xde, 0xad, 0xbe, 0xef,  //

      0x00, 0x00, 0x04,        // Length: 4
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0xde, 0xad, 0xbe, 0xef,  // Payload

      0x00, 0x00, 0x04,        // Length: 4
      0x03,                    //   Type: RST_STREAM
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x08,  //  Error: CANCEL

      0x00, 0x00, 0x00,        // Length: 0
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x03,  // Stream: 3

      0x00, 0x00, 0x04,        // Length: 4
      0x03,                    //   Type: RST_STREAM
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x03,  // Stream: 3
      0x00, 0x00, 0x00, 0x08,  //  Error: CANCEL
  };
  // frame-format on

  TestSpdyVisitor visitor(spdy_version_);
  if (IsSpdy3()) {
    visitor.SimulateInFramer(kV3Input, sizeof(kV3Input));
  } else {
    visitor.SimulateInFramer(kH2Input, sizeof(kH2Input));
  }

  EXPECT_EQ(0, visitor.syn_reply_frame_count_);
  EXPECT_EQ(24, visitor.data_bytes_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(2, visitor.fin_frame_count_);

  if (IsSpdy3()) {
    EXPECT_EQ(1, visitor.headers_frame_count_);
    EXPECT_EQ(2, visitor.syn_frame_count_);
    EXPECT_TRUE(visitor.fin_opaque_data_.empty());
  } else {
    EXPECT_EQ(3, visitor.headers_frame_count_);
    EXPECT_EQ(0, visitor.syn_frame_count_);
    EXPECT_TRUE(visitor.fin_opaque_data_.empty());
  }

  EXPECT_EQ(0, visitor.fin_flag_count_);
  EXPECT_EQ(0, visitor.end_of_stream_count_);
  EXPECT_EQ(4, visitor.data_frame_count_);
  visitor.fin_opaque_data_.clear();
}

// Test that the FIN flag on a data frame signifies EOF.
TEST_P(SpdyFramerTest, FinOnDataFrame) {
  // clang-format off
  const unsigned char kV3Input[] = {
    0x80, 0x03, 0x00, 0x01,  // SYN Stream #1
    0x00, 0x00, 0x00, 0x1a,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00,
    0x00, 0x02, 'h', 'h',
    0x00, 0x00, 0x00, 0x02,
    'v',  'v',

    0x80, 0x03, 0x00, 0x02,  // SYN REPLY Stream #1
    0x00, 0x00, 0x00, 0x14,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x02,
    'a',  'a',  0x00, 0x00,
    0x00, 0x02, 'b', 'b',

    0x00, 0x00, 0x00, 0x01,  // DATA on Stream #1
    0x00, 0x00, 0x00, 0x0c,
    0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef,

    0x00, 0x00, 0x00, 0x01,  // DATA on Stream #1, with EOF
    0x01, 0x00, 0x00, 0x04,
    0xde, 0xad, 0xbe, 0xef,
  };
  // clang-format on

  // SYN_STREAM and SYN_REPLY don't exist in HTTP2, so instead we send
  // HEADERS frames with PRIORITY(SYN_STREAM only) and END_HEADERS set.
  // frame-format off
  const unsigned char kH2Input[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x01,                    //   Type: HEADERS
      0x24,                    //  Flags: END_HEADERS|PRIORITY
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  // Parent: 0
      0x82,                    // Weight: 131

      0x00, 0x00, 0x01,        // Length: 1
      0x01,                    //   Type: HEADERS
      0x04,                    //  Flags: END_HEADERS
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x8c,                    // :status: 200

      0x00, 0x00, 0x0c,        // Length: 12
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0xde, 0xad, 0xbe, 0xef,  // Payload
      0xde, 0xad, 0xbe, 0xef,  //
      0xde, 0xad, 0xbe, 0xef,  //

      0x00, 0x00, 0x04,        // Length: 4
      0x00,                    //   Type: DATA
      0x01,                    //  Flags: END_STREAM
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0xde, 0xad, 0xbe, 0xef,  // Payload
  };
  // frame-format on

  TestSpdyVisitor visitor(spdy_version_);
  if (IsSpdy3()) {
    visitor.SimulateInFramer(kV3Input, sizeof(kV3Input));
  } else {
    visitor.SimulateInFramer(kH2Input, sizeof(kH2Input));
  }

  EXPECT_EQ(0, visitor.error_count_);
  if (IsSpdy3()) {
    EXPECT_EQ(1, visitor.syn_frame_count_);
    EXPECT_EQ(1, visitor.syn_reply_frame_count_);
    EXPECT_EQ(0, visitor.headers_frame_count_);
  } else {
    EXPECT_EQ(0, visitor.syn_frame_count_);
    EXPECT_EQ(0, visitor.syn_reply_frame_count_);
    EXPECT_EQ(2, visitor.headers_frame_count_);
  }
  EXPECT_EQ(16, visitor.data_bytes_);
  EXPECT_EQ(0, visitor.fin_frame_count_);
  EXPECT_EQ(0, visitor.fin_flag_count_);
  EXPECT_EQ(1, visitor.end_of_stream_count_);
  EXPECT_EQ(2, visitor.data_frame_count_);
}

// Test that the FIN flag on a SYN reply frame signifies EOF.
TEST_P(SpdyFramerTest, FinOnSynReplyFrame) {
  // clang-format off
  const unsigned char kV3Input[] = {
    0x80, 0x03, 0x00,  // SYN Stream #1
    0x01, 0x00, 0x00, 0x00,
    0x1a, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x02, 'h',
    'h',  0x00, 0x00, 0x00,
    0x02, 'v', 'v',

    0x80, 0x03, 0x00, 0x02,  // SYN REPLY Stream #1
    0x01, 0x00, 0x00, 0x14,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x02,
    'a',  'a',  0x00, 0x00,
    0x00, 0x02, 'b',  'b',
  };
  // clang-format on

  // SYN_STREAM and SYN_REPLY don't exist in HTTP2, so instead we send
  // HEADERS frames with PRIORITY(SYN_STREAM only) and END_HEADERS set.
  // frame-format off
  const unsigned char kH2Input[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x01,                    //   Type: HEADERS
      0x24,                    //  Flags: END_HEADERS|PRIORITY
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  // Parent: 0
      0x82,                    // Weight: 131

      0x00, 0x00, 0x01,        // Length: 1
      0x01,                    //   Type: HEADERS
      0x05,                    //  Flags: END_STREAM|END_HEADERS
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x8c,                    // :status: 200
  };
  // frame-format on

  TestSpdyVisitor visitor(spdy_version_);
  if (IsSpdy3()) {
    visitor.SimulateInFramer(kV3Input, sizeof(kV3Input));
  } else {
    visitor.SimulateInFramer(kH2Input, sizeof(kH2Input));
  }

  EXPECT_EQ(0, visitor.error_count_);
  if (IsSpdy3()) {
    EXPECT_EQ(1, visitor.syn_frame_count_);
    EXPECT_EQ(1, visitor.syn_reply_frame_count_);
    EXPECT_EQ(0, visitor.headers_frame_count_);
  } else {
    EXPECT_EQ(0, visitor.syn_frame_count_);
    EXPECT_EQ(0, visitor.syn_reply_frame_count_);
    EXPECT_EQ(2, visitor.headers_frame_count_);
  }
  EXPECT_EQ(0, visitor.data_bytes_);
  EXPECT_EQ(0, visitor.fin_frame_count_);
  EXPECT_EQ(1, visitor.fin_flag_count_);
  EXPECT_EQ(1, visitor.end_of_stream_count_);
  EXPECT_EQ(0, visitor.data_frame_count_);
}

TEST_P(SpdyFramerTest, HeaderCompression) {
  if (!IsSpdy3()) {
    // Deflate compression doesn't apply to HPACK.
    return;
  }

  SpdyFramer send_framer(spdy_version_);
  SpdyFramer recv_framer(spdy_version_);

  send_framer.set_enable_compression(true);
  recv_framer.set_enable_compression(true);

  const char kHeader1[] = "header1";
  const char kHeader2[] = "header2";
  const char kHeader3[] = "header3";
  const char kValue1[] = "value1";
  const char kValue2[] = "value2";
  const char kValue3[] = "value3";

  // SYN_STREAM #1
  SpdyHeaderBlock block;
  block[kHeader1] = kValue1;
  block[kHeader2] = kValue2;
  SpdySynStreamIR syn_ir_1(1, block.Clone());
  SpdySerializedFrame syn_frame_1(send_framer.SerializeFrame(syn_ir_1));

  // SYN_STREAM #2
  block[kHeader3] = kValue3;
  SpdySynStreamIR syn_stream(3, std::move(block));
  SpdySerializedFrame syn_frame_2(send_framer.SerializeSynStream(syn_stream));

  // Decompress SYN_STREAM #1
  SpdySerializedFrame decompressed(
      SpdyFramerTestUtil::DecompressFrame(&recv_framer, syn_frame_1));
  StringPiece serialized_headers =
      GetSerializedHeaders(decompressed, send_framer);
  SpdyHeaderBlock decompressed_headers;
  EXPECT_TRUE(recv_framer.ParseHeaderBlockInBuffer(serialized_headers.data(),
                                                   serialized_headers.size(),
                                                   &decompressed_headers));
  EXPECT_EQ(2u, decompressed_headers.size());
  EXPECT_EQ(kValue1, decompressed_headers[kHeader1]);
  EXPECT_EQ(kValue2, decompressed_headers[kHeader2]);

  // Decompress SYN_STREAM #2
  decompressed = SpdyFramerTestUtil::DecompressFrame(&recv_framer, syn_frame_2);
  serialized_headers = GetSerializedHeaders(decompressed, send_framer);
  decompressed_headers.clear();
  EXPECT_TRUE(recv_framer.ParseHeaderBlockInBuffer(serialized_headers.data(),
                                                   serialized_headers.size(),
                                                   &decompressed_headers));
  EXPECT_EQ(3u, decompressed_headers.size());
  EXPECT_EQ(kValue1, decompressed_headers[kHeader1]);
  EXPECT_EQ(kValue2, decompressed_headers[kHeader2]);
  EXPECT_EQ(kValue3, decompressed_headers[kHeader3]);
}

// Verify we can decompress the stream even if handed over to the
// framer 1 byte at a time.
TEST_P(SpdyFramerTest, UnclosedStreamDataCompressorsOneByteAtATime) {
  SpdyFramer framer(spdy_version_);

  framer.set_enable_compression(true);

  const char kHeader1[] = "header1";
  const char kHeader2[] = "header2";
  const char kValue1[] = "value1";
  const char kValue2[] = "value2";

  SpdyHeadersIR headers(1);
  headers.SetHeader(kHeader1, kValue1);
  headers.SetHeader(kHeader2, kValue2);
  SpdySerializedFrame headers_frame(
      SpdyFramerPeer::SerializeHeaders(&framer, headers));

  const char bytes[] = "this is a test test test test test!";
  SpdyDataIR data_ir(1, StringPiece(bytes, arraysize(bytes)));
  data_ir.set_fin(true);
  SpdySerializedFrame send_frame(framer.SerializeData(data_ir));

  // Run the inputs through the framer.
  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = true;
  const unsigned char* data;
  data = reinterpret_cast<const unsigned char*>(headers_frame.data());
  for (size_t idx = 0; idx < headers_frame.size(); ++idx) {
    visitor.SimulateInFramer(data + idx, 1);
    ASSERT_EQ(0, visitor.error_count_);
  }
  data = reinterpret_cast<const unsigned char*>(send_frame.data());
  for (size_t idx = 0; idx < send_frame.size(); ++idx) {
    visitor.SimulateInFramer(data + idx, 1);
    ASSERT_EQ(0, visitor.error_count_);
  }

  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(0, visitor.syn_frame_count_);
  EXPECT_EQ(0, visitor.syn_reply_frame_count_);
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(arraysize(bytes), static_cast<unsigned>(visitor.data_bytes_));
  EXPECT_EQ(0, visitor.fin_frame_count_);
  EXPECT_EQ(0, visitor.fin_flag_count_);
  EXPECT_EQ(1, visitor.end_of_stream_count_);
  EXPECT_EQ(1, visitor.data_frame_count_);
}

TEST_P(SpdyFramerTest, WindowUpdateFrame) {
  SpdyFramer framer(spdy_version_);
  SpdySerializedFrame frame(
      framer.SerializeWindowUpdate(SpdyWindowUpdateIR(1, 0x12345678)));

  const char kDescription[] = "WINDOW_UPDATE frame, stream 1, delta 0x12345678";
  // clang-format off
  const unsigned char kV3FrameData[] = {
    0x80, 0x03, 0x00, 0x09,
    0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x01,
    0x12, 0x34, 0x56, 0x78
  };
  // clang-format on
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x04,        // Length: 4
      0x08,                    //   Type: WINDOW_UPDATE
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x12, 0x34, 0x56, 0x78,  // Increment: 305419896
  };

  if (IsSpdy3()) {
    CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
  } else {
    CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
  }
}

TEST_P(SpdyFramerTest, CreateDataFrame) {
  SpdyFramer framer(spdy_version_);

  {
    const char kDescription[] = "'hello' data frame, no FIN";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x05,
      'h',  'e',  'l',  'l',
      'o'
    };
    // clang-format on
    // frame-format off
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x05,        // Length: 5
        0x00,                    //   Type: DATA
        0x00,                    //  Flags: none
        0x00, 0x00, 0x00, 0x01,  // Stream: 1
        'h',  'e',  'l',  'l',   // Payload
        'o',                     //
    };
    // frame-format on
    const char bytes[] = "hello";

    SpdyDataIR data_ir(1, bytes);
    SpdySerializedFrame frame(framer.SerializeData(data_ir));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }

    SpdyDataIR data_header_ir(1);
    data_header_ir.SetDataShallow(bytes);
    frame =
        framer.SerializeDataFrameHeaderWithPaddingLengthField(data_header_ir);
    CompareCharArraysWithHexError(
        kDescription, reinterpret_cast<const unsigned char*>(frame.data()),
        framer.GetDataFrameMinimumSize(),
        IsSpdy3() ? kV3FrameData : kH2FrameData,
        framer.GetDataFrameMinimumSize());
  }

  {
    const char kDescription[] = "'hello' data frame with more padding, no FIN";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x05,
      'h',  'e',  'l',  'l',
      'o'
    };
    // frame-format off
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0xfd,        // Length: 253
        0x00,                    //   Type: DATA
        0x08,                    //  Flags: PADDED
        0x00, 0x00, 0x00, 0x01,  // Stream: 1
        0xf7,                    // PadLen: 247 trailing bytes
        'h',  'e',  'l',  'l',   // Payload
        'o',                     //
        // Padding of 247 0x00(s).
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    // frame-format on
    // clang-format on
    const char bytes[] = "hello";

    SpdyDataIR data_ir(1, bytes);
    // 247 zeros and the pad length field make the overall padding to be 248
    // bytes.
    data_ir.set_padding_len(248);
    SpdySerializedFrame frame(framer.SerializeData(data_ir));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }

    frame = framer.SerializeDataFrameHeaderWithPaddingLengthField(data_ir);
    CompareCharArraysWithHexError(
        kDescription, reinterpret_cast<const unsigned char*>(frame.data()),
        framer.GetDataFrameMinimumSize(),
        IsSpdy3() ? kV3FrameData : kH2FrameData,
        framer.GetDataFrameMinimumSize());
  }

  {
    const char kDescription[] = "'hello' data frame with few padding, no FIN";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x05,
      'h',  'e',  'l',  'l',
      'o'
    };
    // clang-format on
    // frame-format off
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x0d,        // Length: 13
        0x00,                    //   Type: DATA
        0x08,                    //  Flags: PADDED
        0x00, 0x00, 0x00, 0x01,  // Stream: 1
        0x07,                    // PadLen: 7 trailing bytes
        'h',  'e',  'l',  'l',   // Payload
        'o',                     //
        0x00, 0x00, 0x00, 0x00,  // Padding
        0x00, 0x00, 0x00,        // Padding
    };
    // frame-format on
    const char bytes[] = "hello";

    SpdyDataIR data_ir(1, bytes);
    // 7 zeros and the pad length field make the overall padding to be 8 bytes.
    data_ir.set_padding_len(8);
    SpdySerializedFrame frame(framer.SerializeData(data_ir));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }

  {
    const char kDescription[] =
        "'hello' data frame with 1 byte padding, no FIN";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x05,
      'h',  'e',  'l',  'l',
      'o'
    };
    // clang-format on

    // frame-format off
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x06,        // Length: 6
        0x00,                    //   Type: DATA
        0x08,                    //  Flags: PADDED
        0x00, 0x00, 0x00, 0x01,  // Stream: 1
        0x00,                    // PadLen: 0 trailing bytes
        'h',  'e',  'l',  'l',   // Payload
        'o',                     //
    };
    // frame-format on
    const char bytes[] = "hello";

    SpdyDataIR data_ir(1, bytes);
    // The pad length field itself is used for the 1-byte padding and no padding
    // payload is needed.
    data_ir.set_padding_len(1);
    SpdySerializedFrame frame(framer.SerializeData(data_ir));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }

    frame = framer.SerializeDataFrameHeaderWithPaddingLengthField(data_ir);
    CompareCharArraysWithHexError(
        kDescription, reinterpret_cast<const unsigned char*>(frame.data()),
        framer.GetDataFrameMinimumSize(),
        IsSpdy3() ? kV3FrameData : kH2FrameData,
        framer.GetDataFrameMinimumSize());
  }

  {
    const char kDescription[] = "Data frame with negative data byte, no FIN";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x01,
      0xff
    };
    // clang-format on
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x01,        // Length: 1
        0x00,                    //   Type: DATA
        0x00,                    //  Flags: none
        0x00, 0x00, 0x00, 0x01,  // Stream: 1
        0xff,                    // Payload
    };
    SpdyDataIR data_ir(1, "\xff");
    SpdySerializedFrame frame(framer.SerializeData(data_ir));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }

  {
    const char kDescription[] = "'hello' data frame, with FIN";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x00, 0x00, 0x00, 0x01,
      0x01, 0x00, 0x00, 0x05,
      'h', 'e', 'l', 'l',
      'o'
    };
    // clang-format on
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x05,        // Length: 5
        0x00,                    //   Type: DATA
        0x01,                    //  Flags: END_STREAM
        0x00, 0x00, 0x00, 0x01,  // Stream: 1
        0x68, 0x65, 0x6c, 0x6c,  // Payload
        0x6f,                    //
    };
    SpdyDataIR data_ir(1, "hello");
    data_ir.set_fin(true);
    SpdySerializedFrame frame(framer.SerializeData(data_ir));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }

  {
    const char kDescription[] = "Empty data frame";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x00,
    };
    // clang-format on
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x00,        // Length: 0
        0x00,                    //   Type: DATA
        0x00,                    //  Flags: none
        0x00, 0x00, 0x00, 0x01,  // Stream: 1
    };
    SpdyDataIR data_ir(1, "");
    SpdySerializedFrame frame(framer.SerializeData(data_ir));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }

    frame = framer.SerializeDataFrameHeaderWithPaddingLengthField(data_ir);
    CompareCharArraysWithHexError(
        kDescription, reinterpret_cast<const unsigned char*>(frame.data()),
        framer.GetDataFrameMinimumSize(),
        IsSpdy3() ? kV3FrameData : kH2FrameData,
        framer.GetDataFrameMinimumSize());
  }

  {
    const char kDescription[] = "Data frame with max stream ID";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x7f, 0xff, 0xff, 0xff,
      0x01, 0x00, 0x00, 0x05,
      'h',  'e',  'l',  'l',
      'o'
    };
    // clang-format on
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x05,        // Length: 5
        0x00,                    //   Type: DATA
        0x01,                    //  Flags: END_STREAM
        0x7f, 0xff, 0xff, 0xff,  // Stream: 0x7fffffff
        0x68, 0x65, 0x6c, 0x6c,  // Payload
        0x6f,                    //
    };
    SpdyDataIR data_ir(0x7fffffff, "hello");
    data_ir.set_fin(true);
    SpdySerializedFrame frame(framer.SerializeData(data_ir));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }

  if (!IsHttp2()) {
    // This test does not apply to HTTP/2 because the max frame size is smaller
    // than 4MB.
    const char kDescription[] = "Large data frame";
    const int kDataSize = 4 * 1024 * 1024;  // 4 MB
    const string kData(kDataSize, 'A');
    // clang-format off
    const unsigned char kFrameHeader[] = {
      0x00, 0x00, 0x00, 0x01,
      0x01, 0x40, 0x00, 0x00,
    };
    // clang-format on

    const int kFrameSize = arraysize(kFrameHeader) + kDataSize;
    std::unique_ptr<unsigned char[]> expected_frame_data(
        new unsigned char[kFrameSize]);
    memcpy(expected_frame_data.get(), kFrameHeader, arraysize(kFrameHeader));
    memset(expected_frame_data.get() + arraysize(kFrameHeader), 'A', kDataSize);

    SpdyDataIR data_ir(1, kData);
    data_ir.set_fin(true);
    SpdySerializedFrame frame(framer.SerializeData(data_ir));
    CompareFrame(kDescription, frame, expected_frame_data.get(), kFrameSize);
  }
}

TEST_P(SpdyFramerTest, CreateSynStreamUncompressed) {
  if (!IsSpdy3()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(false);

  {
    const char kDescription[] = "SYN_STREAM frame, lowest pri, no FIN";

    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x2a,
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x00,
      0xE0, 0x00, 0x00, 0x00,
      0x00, 0x02, 0x00, 0x00,
      0x00, 0x03, 'b',  'a',
      'r',  0x00, 0x00, 0x00,
      0x03, 'f',  'o',  'o',
      0x00, 0x00, 0x00, 0x03,
      'f',  'o',  'o',  0x00,
      0x00, 0x00, 0x03, 'b',
      'a',  'r'
    };
    // clang-format on
    SpdySynStreamIR syn_stream(1);
    syn_stream.set_priority(framer.GetLowestPriority());
    syn_stream.SetHeader("bar", "foo");
    syn_stream.SetHeader("foo", "bar");
    SpdySerializedFrame frame(framer.SerializeSynStream(syn_stream));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      LOG(FATAL) << "Unsupported version in test.";
    }
  }

  {
    const char kDescription[] =
        "SYN_STREAM frame with a 0-length header name, highest pri, FIN, "
        "max stream ID";

    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x01,
      0x01, 0x00, 0x00, 0x27,
      0x7f, 0xff, 0xff, 0xff,
      0x7f, 0xff, 0xff, 0xff,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x02, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x03, 'f',  'o',
      'o',  0x00, 0x00, 0x00,
      0x03, 'f',  'o',  'o',
      0x00, 0x00, 0x00, 0x03,
      'b',  'a',  'r'
    };
    // clang-format on
    SpdySynStreamIR syn_stream(0x7fffffff);
    syn_stream.set_associated_to_stream_id(0x7fffffff);
    syn_stream.set_priority(framer.GetHighestPriority());
    syn_stream.set_fin(true);
    syn_stream.SetHeader("", "foo");
    syn_stream.SetHeader("foo", "bar");
    SpdySerializedFrame frame(framer.SerializeSynStream(syn_stream));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      LOG(FATAL) << "Unsupported version in test.";
    }
  }

  {
    const char kDescription[] =
        "SYN_STREAM frame with a 0-length header val, high pri, FIN, "
        "max stream ID";

    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x01,
      0x01, 0x00, 0x00, 0x27,
      0x7f, 0xff, 0xff, 0xff,
      0x7f, 0xff, 0xff, 0xff,
      0x20, 0x00, 0x00, 0x00,
      0x00, 0x02, 0x00, 0x00,
      0x00, 0x03, 'b',  'a',
      'r',  0x00, 0x00, 0x00,
      0x03, 'f',  'o',  'o',
      0x00, 0x00, 0x00, 0x03,
      'f',  'o',  'o',  0x00,
      0x00, 0x00, 0x00
    };
    // clang-format on
    SpdySynStreamIR syn_stream(0x7fffffff);
    syn_stream.set_associated_to_stream_id(0x7fffffff);
    syn_stream.set_priority(1);
    syn_stream.set_fin(true);
    syn_stream.SetHeader("bar", "foo");
    syn_stream.SetHeader("foo", "");
    SpdySerializedFrame frame(framer.SerializeSynStream(syn_stream));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      LOG(FATAL) << "Unsupported version in test.";
    }
  }
}

// TODO(phajdan.jr): Clean up after we no longer need
// to workaround http://crbug.com/139744.
#if !defined(USE_SYSTEM_ZLIB)
TEST_P(SpdyFramerTest, CreateSynStreamCompressed) {
  if (!IsSpdy3()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(true);

  {
    const char kDescription[] = "SYN_STREAM frame, low pri, no FIN";

    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x36,
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x00,
      0x80, 0x00, 0x38, 0xEA,
      0xE3, 0xC6, 0xA7, 0xC2,
      0x02, 0xE5, 0x0E, 0x50,
      0xC2, 0x4B, 0x4A, 0x04,
      0xE5, 0x0B, 0x66, 0x80,
      0x00, 0x4A, 0xCB, 0xCF,
      0x07, 0x08, 0x20, 0x10,
      0x95, 0x96, 0x9F, 0x0F,
      0xA2, 0x00, 0x02, 0x28,
      0x29, 0xB1, 0x08, 0x20,
      0x00, 0x00, 0x00, 0x00,
      0xFF, 0xFF,
    };
    const unsigned char kV3SIMDFrameData[] = {
      0x80, 0x03, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x31,
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x00,
      0x80, 0x00, 0x38, 0xea,
      0xe3, 0xc6, 0xa7, 0xc2,
      0x02, 0xe5, 0x0e, 0x50,
      0xc2, 0x4b, 0x4a, 0x04,
      0xe5, 0x0b, 0x66, 0x80,
      0x00, 0x4a, 0xcb, 0xcf,
      0x07, 0x08, 0x20, 0x24,
      0x0a, 0x20, 0x80, 0x92,
      0x12, 0x8b, 0x00, 0x02,
      0x00, 0x00, 0x00, 0xff,
      0xff,
    };
    // clang-format on

    SpdySynStreamIR syn_stream(1);
    syn_stream.set_priority(4);
    syn_stream.SetHeader("bar", "foo");
    syn_stream.SetHeader("foo", "bar");
    SpdySerializedFrame frame(framer.SerializeSynStream(syn_stream));
    const unsigned char* frame_data =
        reinterpret_cast<const unsigned char*>(frame.data());
    if (IsSpdy3()) {
      if (memcmp(frame_data, kV3SIMDFrameData,
                 std::min(arraysize(kV3SIMDFrameData), frame.size())) != 0) {
        CompareCharArraysWithHexError(kDescription, frame_data, frame.size(),
                                      kV3FrameData, arraysize(kV3FrameData));
      }
    } else {
      LOG(FATAL) << "Unsupported version in test.";
    }
  }
}
#endif  // !defined(USE_SYSTEM_ZLIB)

TEST_P(SpdyFramerTest, CreateSynReplyUncompressed) {
  if (!IsSpdy3()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(false);

  {
    const char kDescription[] = "SYN_REPLY frame, no FIN";

    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x02,
      0x00, 0x00, 0x00, 0x24,
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x02,
      0x00, 0x00, 0x00, 0x03,
      'b',  'a',  'r',  0x00,
      0x00, 0x00, 0x03, 'f',
      'o',  'o',  0x00, 0x00,
      0x00, 0x03, 'f',  'o',
      'o',  0x00, 0x00, 0x00,
      0x03, 'b',  'a',  'r'
    };
    // clang-format on
    SpdySynReplyIR syn_reply(1);
    syn_reply.SetHeader("bar", "foo");
    syn_reply.SetHeader("foo", "bar");
    SpdySerializedFrame frame(framer.SerializeSynReply(syn_reply));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      LOG(FATAL) << "Unsupported version in test.";
    }
  }

  {
    const char kDescription[] =
        "SYN_REPLY frame with a 0-length header name, FIN, max stream ID";

    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x02,
      0x01, 0x00, 0x00, 0x21,
      0x7f, 0xff, 0xff, 0xff,
      0x00, 0x00, 0x00, 0x02,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x03,
      'f',  'o',  'o',  0x00,
      0x00, 0x00, 0x03, 'f',
      'o',  'o',  0x00, 0x00,
      0x00, 0x03, 'b',  'a',
      'r'
    };
    // clang-format on
    SpdySynReplyIR syn_reply(0x7fffffff);
    syn_reply.set_fin(true);
    syn_reply.SetHeader("", "foo");
    syn_reply.SetHeader("foo", "bar");
    SpdySerializedFrame frame(framer.SerializeSynReply(syn_reply));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      LOG(FATAL) << "Unsupported version in test.";
    }
  }

  {
    const char kDescription[] =
        "SYN_REPLY frame with a 0-length header val, FIN, max stream ID";

    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x02,
      0x01, 0x00, 0x00, 0x21,
      0x7f, 0xff, 0xff, 0xff,
      0x00, 0x00, 0x00, 0x02,
      0x00, 0x00, 0x00, 0x03,
      'b',  'a',  'r',  0x00,
      0x00, 0x00, 0x03, 'f',
      'o',  'o',  0x00, 0x00,
      0x00, 0x03, 'f',  'o',
      'o',  0x00, 0x00, 0x00,
      0x00
    };
    // clang-format on
    SpdySynReplyIR syn_reply(0x7fffffff);
    syn_reply.set_fin(true);
    syn_reply.SetHeader("bar", "foo");
    syn_reply.SetHeader("foo", "");
    SpdySerializedFrame frame(framer.SerializeSynReply(syn_reply));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      LOG(FATAL) << "Unsupported version in test.";
    }
  }
}

// TODO(phajdan.jr): Clean up after we no longer need
// to workaround http://crbug.com/139744.
#if !defined(USE_SYSTEM_ZLIB)
TEST_P(SpdyFramerTest, CreateSynReplyCompressed) {
  if (!IsSpdy3()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(true);

  {
    const char kDescription[] = "SYN_REPLY frame, no FIN";

    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x02,
      0x00, 0x00, 0x00, 0x30,
      0x00, 0x00, 0x00, 0x01,
      0x38, 0xea, 0xe3, 0xc6,
      0xa7, 0xc2, 0x02, 0xe5,
      0x0e, 0x50, 0xc2, 0x4b,
      0x4a, 0x04, 0xe5, 0x0b,
      0x66, 0x80, 0x00, 0x4a,
      0xcb, 0xcf, 0x07, 0x08,
      0x20, 0x10, 0x95, 0x96,
      0x9f, 0x0f, 0xa2, 0x00,
      0x02, 0x28, 0x29, 0xb1,
      0x08, 0x20, 0x00, 0x00,
      0x00, 0x00, 0xff, 0xff,
    };

    const unsigned char kV3SIMDFrameData[] = {
      0x80, 0x03, 0x00, 0x02,
      0x00, 0x00, 0x00, 0x2b,
      0x00, 0x00, 0x00, 0x01,
      0x38, 0xea, 0xe3, 0xc6,
      0xa7, 0xc2, 0x02, 0xe5,
      0x0e, 0x50, 0xc2, 0x4b,
      0x4a, 0x04, 0xe5, 0x0b,
      0x66, 0x80, 0x00, 0x4a,
      0xcb, 0xcf, 0x07, 0x08,
      0x20, 0x24, 0x0a, 0x20,
      0x80, 0x92, 0x12, 0x8b,
      0x00, 0x02, 0x00, 0x00,
      0x00, 0xff, 0xff,
    };
    // clang-format on

    SpdySynReplyIR syn_reply(1);
    syn_reply.SetHeader("bar", "foo");
    syn_reply.SetHeader("foo", "bar");
    SpdySerializedFrame frame(framer.SerializeSynReply(syn_reply));
    const unsigned char* frame_data =
        reinterpret_cast<const unsigned char*>(frame.data());
    if (IsSpdy3()) {
      if (memcmp(frame_data, kV3SIMDFrameData,
                 std::min(arraysize(kV3SIMDFrameData), frame.size())) != 0) {
        CompareCharArraysWithHexError(kDescription, frame_data, frame.size(),
                                      kV3FrameData, arraysize(kV3FrameData));
      }
    } else {
      LOG(FATAL) << "Unsupported version in test.";
    }
  }
}
#endif  // !defined(USE_SYSTEM_ZLIB)

TEST_P(SpdyFramerTest, CreateRstStream) {
  SpdyFramer framer(spdy_version_);

  {
    const char kDescription[] = "RST_STREAM frame";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x03,
      0x00, 0x00, 0x00, 0x08,
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x01,
    };
    // clang-format on
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x04,        // Length: 4
        0x03,                    //   Type: RST_STREAM
        0x00,                    //  Flags: none
        0x00, 0x00, 0x00, 0x01,  // Stream: 1
        0x00, 0x00, 0x00, 0x01,  //  Error: PROTOCOL_ERROR
    };
    SpdyRstStreamIR rst_stream(1, RST_STREAM_PROTOCOL_ERROR);
    SpdySerializedFrame frame(framer.SerializeRstStream(rst_stream));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }

  {
    const char kDescription[] = "RST_STREAM frame with max stream ID";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x03,
      0x00, 0x00, 0x00, 0x08,
      0x7f, 0xff, 0xff, 0xff,
      0x00, 0x00, 0x00, 0x01,
    };
    // clang-format on
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x04,        // Length: 4
        0x03,                    //   Type: RST_STREAM
        0x00,                    //  Flags: none
        0x7f, 0xff, 0xff, 0xff,  // Stream: 0x7fffffff
        0x00, 0x00, 0x00, 0x01,  //  Error: PROTOCOL_ERROR
    };
    SpdyRstStreamIR rst_stream(0x7FFFFFFF, RST_STREAM_PROTOCOL_ERROR);
    SpdySerializedFrame frame(framer.SerializeRstStream(rst_stream));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }

  {
    const char kDescription[] = "RST_STREAM frame with max status code";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x03,
      0x00, 0x00, 0x00, 0x08,
      0x7f, 0xff, 0xff, 0xff,
      0x00, 0x00, 0x00, 0x06,
    };
    // clang-format on
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x04,        // Length: 4
        0x03,                    //   Type: RST_STREAM
        0x00,                    //  Flags: none
        0x7f, 0xff, 0xff, 0xff,  // Stream: 0x7fffffff
        0x00, 0x00, 0x00, 0x02,  //  Error: INTERNAL_ERROR
    };
    SpdyRstStreamIR rst_stream(0x7FFFFFFF, RST_STREAM_INTERNAL_ERROR);
    SpdySerializedFrame frame(framer.SerializeRstStream(rst_stream));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }
}

TEST_P(SpdyFramerTest, CreateSettings) {
  SpdyFramer framer(spdy_version_);

  {
    const char kDescription[] = "Network byte order SETTINGS frame";

    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x04,
      0x00, 0x00, 0x00, 0x0c,
      0x00, 0x00, 0x00, 0x01,
      0x01, 0x00, 0x00, 0x07,
      0x0a, 0x0b, 0x0c, 0x0d,
    };
    // clang-format on
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x06,        // Length: 6
        0x04,                    //   Type: SETTINGS
        0x00,                    //  Flags: none
        0x00, 0x00, 0x00, 0x00,  // Stream: 0
        0x00, 0x04,              //  Param: INITIAL_WINDOW_SIZE
        0x0a, 0x0b, 0x0c, 0x0d,  //  Value: 168496141
    };

    uint32_t kValue = 0x0a0b0c0d;
    SpdySettingsIR settings_ir;

    SpdySettingsFlags kFlags = static_cast<SpdySettingsFlags>(0x01);
    SpdySettingsIds kId = SETTINGS_INITIAL_WINDOW_SIZE;
    settings_ir.AddSetting(kId, kFlags & SETTINGS_FLAG_PLEASE_PERSIST,
                           kFlags & SETTINGS_FLAG_PERSISTED, kValue);

    SpdySerializedFrame frame(framer.SerializeSettings(settings_ir));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }

  {
    const char kDescription[] = "Basic SETTINGS frame";

    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x04,
      0x00, 0x00, 0x00, 0x24,
      0x00, 0x00, 0x00, 0x04,
      0x00, 0x00, 0x00, 0x01,  // 1st Setting
      0x00, 0x00, 0x00, 0x05,
      0x00, 0x00, 0x00, 0x02,  // 2nd Setting
      0x00, 0x00, 0x00, 0x06,
      0x00, 0x00, 0x00, 0x03,  // 3rd Setting
      0x00, 0x00, 0x00, 0x07,
      0x00, 0x00, 0x00, 0x04,  // 4th Setting
      0x00, 0x00, 0x00, 0x08,
    };
    // clang-format on
    // These end up seemingly out of order because of the way that our internal
    // ordering for settings_ir works. HTTP2 has no requirement on ordering on
    // the wire.
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x18,        // Length: 24
        0x04,                    //   Type: SETTINGS
        0x00,                    //  Flags: none
        0x00, 0x00, 0x00, 0x00,  // Stream: 0
        0x00, 0x03,              //  Param: MAX_CONCURRENT_STREAMS
        0x00, 0x00, 0x00, 0x07,  //  Value: 7
        0x00, 0x04,              //  Param: INITIAL_WINDOW_SIZE
        0x00, 0x00, 0x00, 0x08,  //  Value: 8
        0x00, 0x01,              //  Param: HEADER_TABLE_SIZE
        0x00, 0x00, 0x00, 0x05,  //  Value: 5
        0x00, 0x02,              //  Param: ENABLE_PUSH
        0x00, 0x00, 0x00, 0x06,  //  Value: 6
    };

    SpdySettingsIR settings_ir;
    settings_ir.AddSetting(SpdyConstants::ParseSettingId(spdy_version_, 1),
                           false,  // persist
                           false,  // persisted
                           5);
    settings_ir.AddSetting(SpdyConstants::ParseSettingId(spdy_version_, 2),
                           false,  // persist
                           false,  // persisted
                           6);
    settings_ir.AddSetting(SpdyConstants::ParseSettingId(spdy_version_, 3),
                           false,  // persist
                           false,  // persisted
                           7);
    settings_ir.AddSetting(SpdyConstants::ParseSettingId(spdy_version_, 4),
                           false,  // persist
                           false,  // persisted
                           8);
    SpdySerializedFrame frame(framer.SerializeSettings(settings_ir));

    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }

  {
    const char kDescription[] = "Empty SETTINGS frame";

    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x04,
      0x00, 0x00, 0x00, 0x04,
      0x00, 0x00, 0x00, 0x00,
    };
    // clang-format on
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x00,        // Length: 0
        0x04,                    //   Type: SETTINGS
        0x00,                    //  Flags: none
        0x00, 0x00, 0x00, 0x00,  // Stream: 0
    };
    SpdySettingsIR settings_ir;
    SpdySerializedFrame frame(framer.SerializeSettings(settings_ir));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }
}

TEST_P(SpdyFramerTest, CreatePingFrame) {
  SpdyFramer framer(spdy_version_);

  {
    const char kDescription[] = "PING frame";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x06,
      0x00, 0x00, 0x00, 0x04,
      0x12, 0x34, 0x56, 0x78,
    };
    // clang-format on
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x08,        // Length: 8
        0x06,                    //   Type: PING
        0x00,                    //  Flags: none
        0x00, 0x00, 0x00, 0x00,  // Stream: 0
        0x12, 0x34, 0x56, 0x78,  // Opaque
        0x9a, 0xbc, 0xde, 0xff,  //     Data
    };
    const unsigned char kH2FrameDataWithAck[] = {
        0x00, 0x00, 0x08,        // Length: 8
        0x06,                    //   Type: PING
        0x01,                    //  Flags: ACK
        0x00, 0x00, 0x00, 0x00,  // Stream: 0
        0x12, 0x34, 0x56, 0x78,  // Opaque
        0x9a, 0xbc, 0xde, 0xff,  //     Data
    };
    SpdySerializedFrame frame;
    if (IsSpdy3()) {
      frame = framer.SerializePing(SpdyPingIR(0x12345678ull));
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      const SpdyPingId kPingId = 0x123456789abcdeffULL;
      SpdyPingIR ping_ir(kPingId);
      // Tests SpdyPingIR when the ping is not an ack.
      ASSERT_FALSE(ping_ir.is_ack());
      frame = framer.SerializePing(ping_ir);
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));

      // Tests SpdyPingIR when the ping is an ack.
      ping_ir.set_is_ack(true);
      frame = framer.SerializePing(ping_ir);
      CompareFrame(kDescription, frame, kH2FrameDataWithAck,
                   arraysize(kH2FrameDataWithAck));
    }
  }
}

TEST_P(SpdyFramerTest, CreateGoAway) {
  SpdyFramer framer(spdy_version_);

  {
    const char kDescription[] = "GOAWAY frame";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x07,
      0x00, 0x00, 0x00, 0x08,
      0x00, 0x00, 0x00, 0x00,  // Stream Id
      0x00, 0x00, 0x00, 0x00,  // Status
    };
    // clang-format on
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x0a,        // Length: 10
        0x07,                    //   Type: GOAWAY
        0x00,                    //  Flags: none
        0x00, 0x00, 0x00, 0x00,  // Stream: 0
        0x00, 0x00, 0x00, 0x00,  //   Last: 0
        0x00, 0x00, 0x00, 0x00,  //  Error: NO_ERROR
        0x47, 0x41,              // Description
    };
    SpdyGoAwayIR goaway_ir(0, GOAWAY_OK, "GA");
    SpdySerializedFrame frame(framer.SerializeGoAway(goaway_ir));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }

  {
    const char kDescription[] = "GOAWAY frame with max stream ID, status";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x07,
      0x00, 0x00, 0x00, 0x08,
      0x7f, 0xff, 0xff, 0xff,  // Stream Id
      0x00, 0x00, 0x00, 0x01,  // Status: PROTOCOL_ERROR.
    };
    // clang-format on
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x0a,        // Length: 10
        0x07,                    //   Type: GOAWAY
        0x00,                    //  Flags: none
        0x00, 0x00, 0x00, 0x00,  // Stream: 0
        0x7f, 0xff, 0xff, 0xff,  //   Last: 0x7fffffff
        0x00, 0x00, 0x00, 0x02,  //  Error: INTERNAL_ERROR
        0x47, 0x41,              // Description
    };
    SpdyGoAwayIR goaway_ir(0x7FFFFFFF, GOAWAY_INTERNAL_ERROR, "GA");
    SpdySerializedFrame frame(framer.SerializeGoAway(goaway_ir));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }
}

TEST_P(SpdyFramerTest, CreateHeadersUncompressed) {
  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(false);

  {
    const char kDescription[] = "HEADERS frame, no FIN";

    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x08,
      0x00, 0x00, 0x00, 0x24,
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x02,
      0x00, 0x00, 0x00, 0x03,
      'b',  'a',  'r',  0x00,
      0x00, 0x00, 0x03, 'f',
      'o',  'o',  0x00, 0x00,
      0x00, 0x03, 'f',  'o',
      'o',  0x00, 0x00, 0x00,
      0x03, 'b',  'a',  'r'
    };
    // clang-format on
    // frame-format off
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x12,        // Length: 18
        0x01,                    //   Type: HEADERS
        0x04,                    //  Flags: END_HEADERS
        0x00, 0x00, 0x00, 0x01,  // Stream: 1

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x62, 0x61, 0x72,  // bar
        0x03,              // Value Len: 3
        0x66, 0x6f, 0x6f,  // foo

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x66, 0x6f, 0x6f,  // foo
        0x03,              // Value Len: 3
        0x62, 0x61, 0x72,  // bar
    };
    // frame-format on

    SpdyHeadersIR headers(1);
    headers.SetHeader("bar", "foo");
    headers.SetHeader("foo", "bar");
    SpdySerializedFrame frame(
        SpdyFramerPeer::SerializeHeaders(&framer, headers));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }

  {
    const char kDescription[] =
        "HEADERS frame with a 0-length header name, FIN, max stream ID";

    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x08,
      0x01, 0x00, 0x00, 0x21,
      0x7f, 0xff, 0xff, 0xff,
      0x00, 0x00, 0x00, 0x02,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x03,
      'f',  'o',  'o',  0x00,
      0x00, 0x00, 0x03, 'f',
      'o',  'o',  0x00, 0x00,
      0x00, 0x03, 'b',  'a',
      'r'
    };
    // clang-format on
    // frame-format off
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x0f,        // Length: 15
        0x01,                    //   Type: HEADERS
        0x05,                    //  Flags: END_STREAM|END_HEADERS
        0x7f, 0xff, 0xff, 0xff,  // Stream: 2147483647

        0x00,              // Unindexed Entry
        0x00,              // Name Len: 0
        0x03,              // Value Len: 3
        0x66, 0x6f, 0x6f,  // foo

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x66, 0x6f, 0x6f,  // foo
        0x03,              // Value Len: 3
        0x62, 0x61, 0x72,  // bar
    };
    // frame-format on
    SpdyHeadersIR headers(0x7fffffff);
    headers.set_fin(true);
    headers.SetHeader("", "foo");
    headers.SetHeader("foo", "bar");
    SpdySerializedFrame frame(
        SpdyFramerPeer::SerializeHeaders(&framer, headers));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }

  {
    const char kDescription[] =
        "HEADERS frame with a 0-length header val, FIN, max stream ID";

    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x08,
      0x01, 0x00, 0x00, 0x21,
      0x7f, 0xff, 0xff, 0xff,
      0x00, 0x00, 0x00, 0x02,
      0x00, 0x00, 0x00, 0x03,
      'b',  'a',  'r',  0x00,
      0x00, 0x00, 0x03, 'f',
      'o',  'o',  0x00, 0x00,
      0x00, 0x03, 'f',  'o',
      'o',  0x00, 0x00, 0x00,
      0x00
    };
    // clang-format on
    // frame-format off
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x0f,        // Length: 15
        0x01,                    //   Type: HEADERS
        0x05,                    //  Flags: END_STREAM|END_HEADERS
        0x7f, 0xff, 0xff, 0xff,  // Stream: 2147483647

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x62, 0x61, 0x72,  // bar
        0x03,              // Value Len: 3
        0x66, 0x6f, 0x6f,  // foo

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x66, 0x6f, 0x6f,  // foo
        0x00,              // Value Len: 0
    };
    // frame-format on
    SpdyHeadersIR headers_ir(0x7fffffff);
    headers_ir.set_fin(true);
    headers_ir.SetHeader("bar", "foo");
    headers_ir.SetHeader("foo", "");
    SpdySerializedFrame frame(
        SpdyFramerPeer::SerializeHeaders(&framer, headers_ir));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }

  {
    const char kDescription[] =
        "HEADERS frame with a 0-length header val, FIN, max stream ID, pri";

    // frame-format off
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x14,        // Length: 20
        0x01,                    //   Type: HEADERS
        0x25,                    //  Flags: END_STREAM|END_HEADERS|PRIORITY
        0x7f, 0xff, 0xff, 0xff,  // Stream: 2147483647
        0x00, 0x00, 0x00, 0x00,  // Parent: 0
        0xdb,                    // Weight: 220

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x62, 0x61, 0x72,  // bar
        0x03,              // Value Len: 3
        0x66, 0x6f, 0x6f,  // foo

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x66, 0x6f, 0x6f,  // foo
        0x00,              // Value Len: 0
    };
    // frame-format on
    SpdyHeadersIR headers_ir(0x7fffffff);
    headers_ir.set_fin(true);
    headers_ir.set_has_priority(true);
    headers_ir.set_weight(220);
    headers_ir.SetHeader("bar", "foo");
    headers_ir.SetHeader("foo", "");
    SpdySerializedFrame frame(
        SpdyFramerPeer::SerializeHeaders(&framer, headers_ir));
    if (IsSpdy3()) {
      // HEADERS with priority not supported.
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }

  {
    const char kDescription[] =
        "HEADERS frame with a 0-length header val, FIN, max stream ID, pri, "
        "exclusive=true, parent_stream=0";

    // frame-format off
    const unsigned char kV4FrameData[] = {
        0x00, 0x00, 0x14,        // Length: 20
        0x01,                    //   Type: HEADERS
        0x25,                    //  Flags: END_STREAM|END_HEADERS|PRIORITY
        0x7f, 0xff, 0xff, 0xff,  // Stream: 2147483647
        0x80, 0x00, 0x00, 0x00,  // Parent: 0 (Exclusive)
        0xdb,                    // Weight: 220

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x62, 0x61, 0x72,  // bar
        0x03,              // Value Len: 3
        0x66, 0x6f, 0x6f,  // foo

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x66, 0x6f, 0x6f,  // foo
        0x00,              // Value Len: 0
    };
    // frame-format on
    SpdyHeadersIR headers_ir(0x7fffffff);
    headers_ir.set_fin(true);
    headers_ir.set_has_priority(true);
    headers_ir.set_weight(220);
    headers_ir.set_exclusive(true);
    headers_ir.set_parent_stream_id(0);
    headers_ir.SetHeader("bar", "foo");
    headers_ir.SetHeader("foo", "");
    SpdySerializedFrame frame(
        SpdyFramerPeer::SerializeHeaders(&framer, headers_ir));
    if (IsSpdy3()) {
      // HEADERS with priority not supported.
    } else {
      CompareFrame(kDescription, frame, kV4FrameData, arraysize(kV4FrameData));
    }
  }

  {
    const char kDescription[] =
        "HEADERS frame with a 0-length header val, FIN, max stream ID, pri, "
        "exclusive=false, parent_stream=max stream ID";

    // frame-format off
    const unsigned char kV4FrameData[] = {
        0x00, 0x00, 0x14,        // Length: 20
        0x01,                    //   Type: HEADERS
        0x25,                    //  Flags: END_STREAM|END_HEADERS|PRIORITY
        0x7f, 0xff, 0xff, 0xff,  // Stream: 2147483647
        0x7f, 0xff, 0xff, 0xff,  // Parent: 2147483647
        0xdb,                    // Weight: 220

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x62, 0x61, 0x72,  // bar
        0x03,              // Value Len: 3
        0x66, 0x6f, 0x6f,  // foo

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x66, 0x6f, 0x6f,  // foo
        0x00,              // Value Len: 0
    };
    // frame-format on
    SpdyHeadersIR headers_ir(0x7fffffff);
    headers_ir.set_fin(true);
    headers_ir.set_has_priority(true);
    headers_ir.set_weight(220);
    headers_ir.set_exclusive(false);
    headers_ir.set_parent_stream_id(0x7fffffff);
    headers_ir.SetHeader("bar", "foo");
    headers_ir.SetHeader("foo", "");
    SpdySerializedFrame frame(
        SpdyFramerPeer::SerializeHeaders(&framer, headers_ir));
    if (IsSpdy3()) {
      // HEADERS with priority not supported.
    } else {
      CompareFrame(kDescription, frame, kV4FrameData, arraysize(kV4FrameData));
    }
  }

  {
    const char kDescription[] =
        "HEADERS frame with a 0-length header name, FIN, max stream ID, padded";

    // frame-format off
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x15,        // Length: 21
        0x01,                    //   Type: HEADERS
        0x0d,                    //  Flags: END_STREAM|END_HEADERS|PADDED
        0x7f, 0xff, 0xff, 0xff,  // Stream: 2147483647
        0x05,                    // PadLen: 5 trailing bytes

        0x00,              // Unindexed Entry
        0x00,              // Name Len: 0
        0x03,              // Value Len: 3
        0x66, 0x6f, 0x6f,  // foo

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x66, 0x6f, 0x6f,  // foo
        0x03,              // Value Len: 3
        0x62, 0x61, 0x72,  // bar

        0x00, 0x00, 0x00, 0x00,  // Padding
        0x00,                    // Padding
    };
    // frame-format on
    SpdyHeadersIR headers_ir(0x7fffffff);
    headers_ir.set_fin(true);
    headers_ir.SetHeader("", "foo");
    headers_ir.SetHeader("foo", "bar");
    headers_ir.set_padding_len(6);
    SpdySerializedFrame frame(
        SpdyFramerPeer::SerializeHeaders(&framer, headers_ir));
    if (IsSpdy3()) {
      // Padding is not supported.
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }
}

// TODO(phajdan.jr): Clean up after we no longer need
// to workaround http://crbug.com/139744.
#if !defined(USE_SYSTEM_ZLIB)
TEST_P(SpdyFramerTest, CreateHeadersCompressed) {
  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(true);

  {
    const char kDescription[] = "HEADERS frame, no FIN";

    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x08,
      0x00, 0x00, 0x00, 0x30,
      0x00, 0x00, 0x00, 0x01,
      0x38, 0xea, 0xe3, 0xc6,
      0xa7, 0xc2, 0x02, 0xe5,
      0x0e, 0x50, 0xc2, 0x4b,
      0x4a, 0x04, 0xe5, 0x0b,
      0x66, 0x80, 0x00, 0x4a,
      0xcb, 0xcf, 0x07, 0x08,
      0x20, 0x10, 0x95, 0x96,
      0x9f, 0x0f, 0xa2, 0x00,
      0x02, 0x28, 0x29, 0xb1,
      0x08, 0x20, 0x00, 0x00,
      0x00, 0x00, 0xff, 0xff,
    };
    const unsigned char kV3SIMDFrameData[] = {
      0x80, 0x03, 0x00, 0x08,
      0x00, 0x00, 0x00, 0x2b,
      0x00, 0x00, 0x00, 0x01,
      0x38, 0xea, 0xe3, 0xc6,
      0xa7, 0xc2, 0x02, 0xe5,
      0x0e, 0x50, 0xc2, 0x4b,
      0x4a, 0x04, 0xe5, 0x0b,
      0x66, 0x80, 0x00, 0x4a,
      0xcb, 0xcf, 0x07, 0x08,
      0x20, 0x24, 0x0a, 0x20,
      0x80, 0x92, 0x12, 0x8b,
      0x00, 0x02, 0x00, 0x00,
      0x00, 0xff, 0xff,
    };
    // clang-format on

    SpdyHeadersIR headers_ir(1);
    headers_ir.SetHeader("bar", "foo");
    headers_ir.SetHeader("foo", "bar");
    SpdySerializedFrame frame(
        SpdyFramerPeer::SerializeHeaders(&framer, headers_ir));
    const unsigned char* frame_data =
        reinterpret_cast<const unsigned char*>(frame.data());
    if (IsSpdy3()) {
      if (memcmp(frame_data, kV3SIMDFrameData,
                 std::min(arraysize(kV3SIMDFrameData), frame.size())) != 0) {
        CompareCharArraysWithHexError(kDescription, frame_data, frame.size(),
                                      kV3FrameData, arraysize(kV3FrameData));
      }
    } else {
      // Deflate compression doesn't apply to HPACK.
    }
  }
}
#endif  // !defined(USE_SYSTEM_ZLIB)

TEST_P(SpdyFramerTest, CreateWindowUpdate) {
  SpdyFramer framer(spdy_version_);

  {
    const char kDescription[] = "WINDOW_UPDATE frame";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x09,
      0x00, 0x00, 0x00, 0x08,
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x01,
    };
    // clang-format on
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x04,        // Length: 4
        0x08,                    //   Type: WINDOW_UPDATE
        0x00,                    //  Flags: none
        0x00, 0x00, 0x00, 0x01,  // Stream: 1
        0x00, 0x00, 0x00, 0x01,  // Increment: 1
    };
    SpdySerializedFrame frame(
        framer.SerializeWindowUpdate(SpdyWindowUpdateIR(1, 1)));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }

  {
    const char kDescription[] = "WINDOW_UPDATE frame with max stream ID";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x09,
      0x00, 0x00, 0x00, 0x08,
      0x7f, 0xff, 0xff, 0xff,
      0x00, 0x00, 0x00, 0x01,
    };
    // clang-format on
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x04,        // Length: 4
        0x08,                    //   Type: WINDOW_UPDATE
        0x00,                    //  Flags: none
        0x7f, 0xff, 0xff, 0xff,  // Stream: 0x7fffffff
        0x00, 0x00, 0x00, 0x01,  // Increment: 1
    };
    SpdySerializedFrame frame(
        framer.SerializeWindowUpdate(SpdyWindowUpdateIR(0x7FFFFFFF, 1)));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }

  {
    const char kDescription[] = "WINDOW_UPDATE frame with max window delta";
    // clang-format off
    const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x09,
      0x00, 0x00, 0x00, 0x08,
      0x00, 0x00, 0x00, 0x01,
      0x7f, 0xff, 0xff, 0xff,
    };
    // clang-format on
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x04,        // Length: 4
        0x08,                    //   Type: WINDOW_UPDATE
        0x00,                    //  Flags: none
        0x00, 0x00, 0x00, 0x01,  // Stream: 1
        0x7f, 0xff, 0xff, 0xff,  // Increment: 0x7fffffff
    };
    SpdySerializedFrame frame(
        framer.SerializeWindowUpdate(SpdyWindowUpdateIR(1, 0x7FFFFFFF)));
    if (IsSpdy3()) {
      CompareFrame(kDescription, frame, kV3FrameData, arraysize(kV3FrameData));
    } else {
      CompareFrame(kDescription, frame, kH2FrameData, arraysize(kH2FrameData));
    }
  }
}

TEST_P(SpdyFramerTest, SerializeBlocked) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);

  const char kDescription[] = "BLOCKED frame";
  const unsigned char kType = static_cast<unsigned char>(
      SpdyConstants::SerializeFrameType(spdy_version_, BLOCKED));
  const unsigned char kFrameData[] = {
      0x00,  0x00, 0x00,        // Length: 0
      kType,                    //   Type: BLOCKED
      0x00,                     //  Flags: none
      0x00,  0x00, 0x00, 0x00,  // Stream: 0
  };
  SpdyBlockedIR blocked_ir(0);
  SpdySerializedFrame frame(framer.SerializeFrame(blocked_ir));
  CompareFrame(kDescription, frame, kFrameData, arraysize(kFrameData));
}

TEST_P(SpdyFramerTest, CreateBlocked) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);

  const char kDescription[] = "BLOCKED frame";
  const SpdyStreamId kStreamId = 3;

  SpdySerializedFrame frame_serialized(
      framer.SerializeBlocked(SpdyBlockedIR(kStreamId)));
  SpdyBlockedIR blocked_ir(kStreamId);
  SpdySerializedFrame frame_created(framer.SerializeFrame(blocked_ir));

  CompareFrames(kDescription, frame_serialized, frame_created);
}

TEST_P(SpdyFramerTest, CreatePushPromiseUncompressed) {
  if (!IsHttp2()) {
    return;
  }

  {
    // Test framing PUSH_PROMISE without padding.
    SpdyFramer framer(spdy_version_);
    framer.set_enable_compression(false);
    const char kDescription[] = "PUSH_PROMISE frame without padding";

    // frame-format off
    const unsigned char kFrameData[] = {
        0x00, 0x00, 0x16,        // Length: 22
        0x05,                    //   Type: PUSH_PROMISE
        0x04,                    //  Flags: END_HEADERS
        0x00, 0x00, 0x00, 0x29,  // Stream: 41
        0x00, 0x00, 0x00, 0x3a,  // Promise: 58

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x62, 0x61, 0x72,  // bar
        0x03,              // Value Len: 3
        0x66, 0x6f, 0x6f,  // foo

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x66, 0x6f, 0x6f,  // foo
        0x03,              // Value Len: 3
        0x62, 0x61, 0x72,  // bar
    };
    // frame-format on

    SpdyPushPromiseIR push_promise(41, 58);
    push_promise.SetHeader("bar", "foo");
    push_promise.SetHeader("foo", "bar");
    SpdySerializedFrame frame(framer.SerializePushPromise(push_promise));
    CompareFrame(kDescription, frame, kFrameData, arraysize(kFrameData));
  }

  {
    // Test framing PUSH_PROMISE with one byte of padding.
    SpdyFramer framer(spdy_version_);
    framer.set_enable_compression(false);
    const char kDescription[] = "PUSH_PROMISE frame with one byte of padding";

    // frame-format off
    const unsigned char kFrameData[] = {
        0x00, 0x00, 0x17,        // Length: 23
        0x05,                    //   Type: PUSH_PROMISE
        0x0c,                    //  Flags: END_HEADERS|PADDED
        0x00, 0x00, 0x00, 0x29,  // Stream: 41
        0x00,                    // PadLen: 0 trailing bytes
        0x00, 0x00, 0x00, 0x3a,  // Promise: 58

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x62, 0x61, 0x72,  // bar
        0x03,              // Value Len: 3
        0x66, 0x6f, 0x6f,  // foo

        0x00,              // Unindexed Entry
        0x03,              // Name Len: 3
        0x66, 0x6f, 0x6f,  // foo
        0x03,              // Value Len: 3
        0x62, 0x61, 0x72,  // bar
    };
    // frame-format on

    SpdyPushPromiseIR push_promise(41, 58);
    push_promise.set_padding_len(1);
    push_promise.SetHeader("bar", "foo");
    push_promise.SetHeader("foo", "bar");
    SpdySerializedFrame frame(framer.SerializePushPromise(push_promise));
    CompareFrame(kDescription, frame, kFrameData, arraysize(kFrameData));
  }

  {
    // Test framing PUSH_PROMISE with 177 bytes of padding.
    SpdyFramer framer(spdy_version_);
    framer.set_enable_compression(false);
    const char kDescription[] = "PUSH_PROMISE frame with 177 bytes of padding";

    // frame-format off
    // clang-format off
    const unsigned char kFrameData[] = {
        0x00, 0x00, 0xc7,        // Length: 199
        0x05,                    //   Type: PUSH_PROMISE
        0x0c,                    //  Flags: END_HEADERS|PADDED
        0x00, 0x00, 0x00, 0x2a,  // Stream: 42
        0xb0,                    // PadLen: 176 trailing bytes
        0x00, 0x00, 0x00, 0x39,  // Promise: 57

        0x00,                    // Unindexed Entry
        0x03,                    // Name Len: 3
        0x62, 0x61, 0x72,        // bar
        0x03,                    // Value Len: 3
        0x66, 0x6f, 0x6f,        // foo

        0x00,                    // Unindexed Entry
        0x03,                    // Name Len: 3
        0x66, 0x6f, 0x6f,        // foo
        0x03,                    // Value Len: 3
        0x62, 0x61, 0x72,        // bar

      // Padding of 176 0x00(s).
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 0x00,  0x00,  0x00,
    };
    // clang-format on
    // frame-format on

    SpdyPushPromiseIR push_promise(42, 57);
    push_promise.set_padding_len(177);
    push_promise.SetHeader("bar", "foo");
    push_promise.SetHeader("foo", "bar");
    SpdySerializedFrame frame(framer.SerializePushPromise(push_promise));
    CompareFrame(kDescription, frame, kFrameData, arraysize(kFrameData));
  }
}

// Regression test for https://crbug.com/464748.
TEST_P(SpdyFramerTest, GetNumberRequiredContinuationFrames) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  EXPECT_EQ(1u, SpdyFramerPeer::GetNumberRequiredContinuationFrames(
                    &framer, 16383 + 16374));
  EXPECT_EQ(2u, SpdyFramerPeer::GetNumberRequiredContinuationFrames(
                    &framer, 16383 + 16374 + 1));
  EXPECT_EQ(2u, SpdyFramerPeer::GetNumberRequiredContinuationFrames(
                    &framer, 16383 + 2 * 16374));
  EXPECT_EQ(3u, SpdyFramerPeer::GetNumberRequiredContinuationFrames(
                    &framer, 16383 + 2 * 16374 + 1));
}

TEST_P(SpdyFramerTest, CreateContinuationUncompressed) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(false);
  const char kDescription[] = "CONTINUATION frame";

  // frame-format off
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x12,        // Length: 18
      0x09,                    //   Type: CONTINUATION
      0x04,                    //  Flags: END_HEADERS
      0x00, 0x00, 0x00, 0x2a,  // Stream: 42

      0x00,              // Unindexed Entry
      0x03,              // Name Len: 3
      0x62, 0x61, 0x72,  // bar
      0x03,              // Value Len: 3
      0x66, 0x6f, 0x6f,  // foo

      0x00,              // Unindexed Entry
      0x03,              // Name Len: 3
      0x66, 0x6f, 0x6f,  // foo
      0x03,              // Value Len: 3
      0x62, 0x61, 0x72,  // bar
  };
  // frame-format on

  SpdyHeaderBlock header_block;
  header_block["bar"] = "foo";
  header_block["foo"] = "bar";
  auto buffer = base::MakeUnique<string>();
  HpackEncoder encoder(ObtainHpackHuffmanTable());
  encoder.EncodeHeaderSetWithoutCompression(header_block, buffer.get());

  SpdyContinuationIR continuation(42);
  continuation.take_encoding(std::move(buffer));
  continuation.set_end_headers(true);

  SpdySerializedFrame frame(framer.SerializeContinuation(continuation));
  CompareFrame(kDescription, frame, kFrameData, arraysize(kFrameData));
}

// Test that if we send an unexpected CONTINUATION
// we signal an error (but don't crash).
TEST_P(SpdyFramerTest, SendUnexpectedContinuation) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  // frame-format off
  char kH2FrameData[] = {
      0x00, 0x00, 0x12,        // Length: 18
      0x09,                    //   Type: CONTINUATION
      0x04,                    //  Flags: END_HEADERS
      0x00, 0x00, 0x00, 0x2a,  // Stream: 42

      0x00,              // Unindexed Entry
      0x03,              // Name Len: 3
      0x62, 0x61, 0x72,  // bar
      0x03,              // Value Len: 3
      0x66, 0x6f, 0x6f,  // foo

      0x00,              // Unindexed Entry
      0x03,              // Name Len: 3
      0x66, 0x6f, 0x6f,  // foo
      0x03,              // Value Len: 3
      0x62, 0x61, 0x72,  // bar
  };
  // frame-format on

  SpdySerializedFrame frame(kH2FrameData, sizeof(kH2FrameData), false);

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnError(testing::Eq(&framer)));
  EXPECT_GT(frame.size(), framer.ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(framer.HasError());
  EXPECT_EQ(SpdyFramer::SPDY_UNEXPECTED_FRAME, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

TEST_P(SpdyFramerTest, CreatePushPromiseThenContinuationUncompressed) {
  if (!IsHttp2()) {
    return;
  }

  {
    // Test framing in a case such that a PUSH_PROMISE frame, with one byte of
    // padding, cannot hold all the data payload, which is overflowed to the
    // consecutive CONTINUATION frame.
    SpdyFramer framer(spdy_version_);
    framer.set_enable_compression(false);
    const char kDescription[] =
        "PUSH_PROMISE and CONTINUATION frames with one byte of padding";

    // frame-format off
    const unsigned char kPartialPushPromiseFrameData[] = {
        0x00, 0x3f, 0xf6,        // Length: 16374
        0x05,                    //   Type: PUSH_PROMISE
        0x08,                    //  Flags: PADDED
        0x00, 0x00, 0x00, 0x2a,  // Stream: 42
        0x00,                    // PadLen: 0 trailing bytes
        0x00, 0x00, 0x00, 0x39,  // Promise: 57

        0x00,                    // Unindexed Entry
        0x03,                    // Name Len: 3
        0x78, 0x78, 0x78,        // xxx
        0x7f, 0x80, 0x7f,        // Value Len: 16361
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
    };
    const unsigned char kContinuationFrameData[] = {
        0x00, 0x00, 0x16,        // Length: 22
        0x09,                    //   Type: CONTINUATION
        0x04,                    //  Flags: END_HEADERS
        0x00, 0x00, 0x00, 0x2a,  // Stream: 42
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78,                    // x
    };
    // frame-format on

    SpdyPushPromiseIR push_promise(42, 57);
    push_promise.set_padding_len(1);
    string big_value(TestSpdyVisitor::sent_control_frame_max_size(), 'x');
    push_promise.SetHeader("xxx", big_value);
    SpdySerializedFrame frame(framer.SerializePushPromise(push_promise));

    // The entire frame should look like below:
    // Name                     Length in Byte
    // ------------------------------------------- Begin of PUSH_PROMISE frame
    // PUSH_PROMISE header      9
    // Pad length field         1
    // Promised stream          4
    // Length field of key      2
    // Content of key           3
    // Length field of value    3
    // Part of big_value        16361
    // ------------------------------------------- Begin of CONTINUATION frame
    // CONTINUATION header      9
    // Remaining of big_value   22
    // ------------------------------------------- End

    // Length of everything listed above except big_value.
    int len_non_data_payload = 31;
    EXPECT_EQ(
        TestSpdyVisitor::sent_control_frame_max_size() + len_non_data_payload,
        frame.size());

    // Partially compare the PUSH_PROMISE frame against the template.
    const unsigned char* frame_data =
        reinterpret_cast<const unsigned char*>(frame.data());
    CompareCharArraysWithHexError(
        kDescription, frame_data, arraysize(kPartialPushPromiseFrameData),
        kPartialPushPromiseFrameData, arraysize(kPartialPushPromiseFrameData));

    // Compare the CONTINUATION frame against the template.
    frame_data += TestSpdyVisitor::sent_control_frame_max_size();
    CompareCharArraysWithHexError(
        kDescription, frame_data, arraysize(kContinuationFrameData),
        kContinuationFrameData, arraysize(kContinuationFrameData));
  }
}

TEST_P(SpdyFramerTest, CreateAltSvc) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);

  const char kDescription[] = "ALTSVC frame";
  const char kType = static_cast<unsigned char>(
      SpdyConstants::SerializeFrameType(spdy_version_, ALTSVC));
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x49, kType, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x06, 'o',
      'r',  'i',  'g',  'i',   'n',  'p',  'i',  'd',  '1',  '=',  '"',  'h',
      'o',  's',  't',  ':',   '4',  '4',  '3',  '"',  ';',  ' ',  'm',  'a',
      '=',  '5',  ',',  'p',   '%',  '2',  '2',  '%',  '3',  'D',  'i',  '%',
      '3',  'A',  'd',  '=',   '"',  'h',  '_',  '\\', '\\', 'o',  '\\', '"',
      's',  't',  ':',  '1',   '2',  '3',  '"',  ';',  ' ',  'm',  'a',  '=',
      '4',  '2',  ';',  ' ',   'v',  '=',  '"',  '2',  '4',  '"'};
  SpdyAltSvcIR altsvc_ir(3);
  altsvc_ir.set_origin("origin");
  altsvc_ir.add_altsvc(SpdyAltSvcWireFormat::AlternativeService(
      "pid1", "host", 443, 5, SpdyAltSvcWireFormat::VersionVector()));
  altsvc_ir.add_altsvc(SpdyAltSvcWireFormat::AlternativeService(
      "p\"=i:d", "h_\\o\"st", 123, 42,
      SpdyAltSvcWireFormat::VersionVector{24}));
  SpdySerializedFrame frame(framer.SerializeFrame(altsvc_ir));
  CompareFrame(kDescription, frame, kFrameData, arraysize(kFrameData));
}

TEST_P(SpdyFramerTest, CreatePriority) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);

  const char kDescription[] = "PRIORITY frame";
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x02,                    //   Type: PRIORITY
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x02,  // Stream: 2
      0x80, 0x00, 0x00, 0x01,  // Parent: 1 (Exclusive)
      0x10,                    // Weight: 17
  };
  SpdyPriorityIR priority_ir(2, 1, 17, true);
  SpdySerializedFrame frame(framer.SerializeFrame(priority_ir));
  CompareFrame(kDescription, frame, kFrameData, arraysize(kFrameData));
  SpdyPriorityIR priority2(2);
  priority2.set_parent_stream_id(1);
  priority2.set_weight(17);
  priority2.set_exclusive(true);
  frame = framer.SerializeFrame(priority2);
  CompareFrame(kDescription, frame, kFrameData, arraysize(kFrameData));
}

TEST_P(SpdyFramerTest, ReadCompressedSynStreamHeaderBlock) {
  if (!IsSpdy3()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  SpdySynStreamIR syn_stream(1);
  syn_stream.set_priority(1);
  syn_stream.SetHeader("aa", "vv");
  syn_stream.SetHeader("bb", "ww");
  SpdySerializedFrame control_frame(framer.SerializeSynStream(syn_stream));
  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = true;
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_EQ(1, visitor.syn_frame_count_);
  EXPECT_EQ(syn_stream.header_block(), visitor.headers_);
}

TEST_P(SpdyFramerTest, ReadCompressedSynReplyHeaderBlock) {
  if (!IsSpdy3()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  SpdySynReplyIR syn_reply(1);
  syn_reply.SetHeader("alpha", "beta");
  syn_reply.SetHeader("gamma", "delta");
  SpdySerializedFrame control_frame(framer.SerializeSynReply(syn_reply));
  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = true;
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_EQ(1, visitor.syn_reply_frame_count_);
  EXPECT_EQ(0, visitor.headers_frame_count_);
  EXPECT_EQ(syn_reply.header_block(), visitor.headers_);
}

TEST_P(SpdyFramerTest, ReadCompressedHeadersHeaderBlock) {
  SpdyFramer framer(spdy_version_);
  SpdyHeadersIR headers_ir(1);
  headers_ir.SetHeader("alpha", "beta");
  headers_ir.SetHeader("gamma", "delta");
  SpdySerializedFrame control_frame(
      SpdyFramerPeer::SerializeHeaders(&framer, headers_ir));
  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = true;
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.control_frame_header_data_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
  EXPECT_EQ(0, visitor.end_of_stream_count_);
  EXPECT_EQ(headers_ir.header_block(), visitor.headers_);
}

TEST_P(SpdyFramerTest, ReadCompressedHeadersHeaderBlockWithHalfClose) {
  SpdyFramer framer(spdy_version_);
  SpdyHeadersIR headers_ir(1);
  headers_ir.set_fin(true);
  headers_ir.SetHeader("alpha", "beta");
  headers_ir.SetHeader("gamma", "delta");
  SpdySerializedFrame control_frame(
      SpdyFramerPeer::SerializeHeaders(&framer, headers_ir));
  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = true;
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.control_frame_header_data_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
  EXPECT_EQ(1, visitor.end_of_stream_count_);
  EXPECT_EQ(headers_ir.header_block(), visitor.headers_);
}

TEST_P(SpdyFramerTest, ControlFrameAtMaxSizeLimit) {
  if (!IsSpdy3()) {
    // TODO(jgraettinger): This test setup doesn't work with HPACK.
    return;
  }

  // First find the size of the header value in order to just reach the control
  // frame max size.
  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(false);
  SpdySynStreamIR syn_stream(1);
  syn_stream.set_priority(1);
  syn_stream.SetHeader("aa", "");
  SpdySerializedFrame control_frame(framer.SerializeSynStream(syn_stream));
  const size_t kBigValueSize =
      TestSpdyVisitor::sent_control_frame_max_size() - control_frame.size();

  // Create a frame at exactly that size.
  string big_value(kBigValueSize, 'x');
  syn_stream.SetHeader("aa", big_value);
  control_frame = framer.SerializeSynStream(syn_stream);
  EXPECT_EQ(TestSpdyVisitor::sent_control_frame_max_size(),
            control_frame.size());

  TestSpdyVisitor visitor(spdy_version_);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_TRUE(visitor.header_buffer_valid_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.syn_frame_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
  EXPECT_EQ(0, visitor.end_of_stream_count_);
}

TEST_P(SpdyFramerTest, ControlFrameTooLarge) {
  if (!IsSpdy3()) {
    // TODO(jgraettinger): This test setup doesn't work with HPACK.
    return;
  }

  // First find the size of the header value in order to just reach the control
  // frame max size.
  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(false);
  SpdySynStreamIR syn_stream(1);
  syn_stream.SetHeader("aa", "");
  syn_stream.set_priority(1);
  SpdySerializedFrame control_frame(framer.SerializeSynStream(syn_stream));
  const size_t kBigValueSize =
      TestSpdyVisitor::received_control_frame_max_size() +
      SpdyConstants::GetFrameHeaderSize(spdy_version_) - control_frame.size() +
      1;

  // Create a frame at exatly that size.
  string big_value(kBigValueSize, 'x');
  syn_stream.SetHeader("aa", big_value);
  if (IsSpdy3()) {
    control_frame = framer.SerializeSynStream(syn_stream);
  } else {
    EXPECT_SPDY_BUG({ control_frame = framer.SerializeSynStream(syn_stream); },
                    "Serializing frame over-capacity.");
  }
  EXPECT_EQ(TestSpdyVisitor::received_control_frame_max_size() +
                SpdyConstants::GetFrameHeaderSize(spdy_version_) + 1,
            control_frame.size());

  TestSpdyVisitor visitor(spdy_version_);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_FALSE(visitor.header_buffer_valid_);
  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(SpdyFramer::SPDY_CONTROL_PAYLOAD_TOO_LARGE,
            visitor.framer_.error_code())
      << SpdyFramer::ErrorCodeToString(visitor.framer_.error_code());
  EXPECT_EQ(0, visitor.syn_frame_count_);
  EXPECT_EQ(0u, visitor.header_buffer_length_);
}

TEST_P(SpdyFramerTest, TooLargeHeadersFrameUsesContinuation) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(false);
  SpdyHeadersIR headers(1);
  headers.set_padding_len(256);

  // Exact payload length will change with HPACK, but this should be long
  // enough to cause an overflow.
  const size_t kBigValueSize = TestSpdyVisitor::sent_control_frame_max_size();
  string big_value(kBigValueSize, 'x');
  headers.SetHeader("aa", big_value);
  SpdySerializedFrame control_frame(
      SpdyFramerPeer::SerializeHeaders(&framer, headers));
  EXPECT_GT(control_frame.size(),
            TestSpdyVisitor::sent_control_frame_max_size());

  TestSpdyVisitor visitor(spdy_version_);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_TRUE(visitor.header_buffer_valid_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(1, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
}

TEST_P(SpdyFramerTest, MultipleContinuationFramesWithIterator) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(false);
  auto headers = base::MakeUnique<SpdyHeadersIR>(1);
  headers->set_padding_len(256);

  // Exact payload length will change with HPACK, but this should be long
  // enough to cause an overflow.
  const size_t kBigValueSize = TestSpdyVisitor::sent_control_frame_max_size();
  string big_valuex(kBigValueSize, 'x');
  headers->SetHeader("aa", big_valuex);
  string big_valuez(kBigValueSize, 'z');
  headers->SetHeader("bb", big_valuez);

  SpdyFramer::SpdyHeaderFrameIterator frame_it(&framer, std::move(headers));

  EXPECT_TRUE(frame_it.HasNextFrame());
  SpdySerializedFrame headers_frame(frame_it.NextFrame());
  EXPECT_EQ(headers_frame.size(),
            TestSpdyVisitor::sent_control_frame_max_size());

  TestSpdyVisitor visitor(spdy_version_);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(headers_frame.data()),
      headers_frame.size());
  EXPECT_TRUE(visitor.header_buffer_valid_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);

  EXPECT_TRUE(frame_it.HasNextFrame());
  SpdySerializedFrame first_cont_frame(frame_it.NextFrame());
  EXPECT_EQ(first_cont_frame.size(),
            TestSpdyVisitor::sent_control_frame_max_size());

  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(first_cont_frame.data()),
      first_cont_frame.size());
  EXPECT_TRUE(visitor.header_buffer_valid_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(1, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);

  EXPECT_TRUE(frame_it.HasNextFrame());
  SpdySerializedFrame second_cont_frame(frame_it.NextFrame());
  EXPECT_LT(second_cont_frame.size(),
            TestSpdyVisitor::sent_control_frame_max_size());

  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(second_cont_frame.data()),
      second_cont_frame.size());
  EXPECT_TRUE(visitor.header_buffer_valid_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(2, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);

  EXPECT_FALSE(frame_it.HasNextFrame());
}

TEST_P(SpdyFramerTest, TooLargePushPromiseFrameUsesContinuation) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(false);
  SpdyPushPromiseIR push_promise(1, 2);
  push_promise.set_padding_len(256);

  // Exact payload length will change with HPACK, but this should be long
  // enough to cause an overflow.
  const size_t kBigValueSize = TestSpdyVisitor::sent_control_frame_max_size();
  string big_value(kBigValueSize, 'x');
  push_promise.SetHeader("aa", big_value);
  SpdySerializedFrame control_frame(framer.SerializePushPromise(push_promise));
  EXPECT_GT(control_frame.size(),
            TestSpdyVisitor::sent_control_frame_max_size());

  TestSpdyVisitor visitor(spdy_version_);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_TRUE(visitor.header_buffer_valid_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.push_promise_frame_count_);
  EXPECT_EQ(1, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
}

// Check that the framer stops delivering header data chunks once the visitor
// declares it doesn't want any more. This is important to guard against
// "zip bomb" types of attacks.
TEST_P(SpdyFramerTest, ControlFrameMuchTooLarge) {
  const size_t kHeaderBufferChunks = 4;
  const size_t kHeaderBufferSize =
      TestSpdyVisitor::header_data_chunk_max_size() * kHeaderBufferChunks;
  const size_t kBigValueSize = kHeaderBufferSize * 2;
  string big_value(kBigValueSize, 'x');
  SpdyFramer framer(spdy_version_);
  SpdyHeadersIR headers(1);
  headers.set_fin(true);
  headers.SetHeader("aa", big_value);
  SpdySerializedFrame control_frame(
      SpdyFramerPeer::SerializeHeaders(&framer, headers));
  TestSpdyVisitor visitor(spdy_version_);
  visitor.set_header_buffer_size(kHeaderBufferSize);
  visitor.use_compression_ = true;
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  // It's up to the visitor to ignore extraneous header data; the framer
  // won't throw an error.
  EXPECT_GT(visitor.header_bytes_received_, visitor.header_buffer_size_);
  EXPECT_EQ(1, visitor.end_of_stream_count_);
}

TEST_P(SpdyFramerTest, DecompressCorruptHeaderBlock) {
  if (!IsSpdy3()) {
    // Deflate compression doesn't apply to HPACK.
    return;
  }

  SpdyFramer framer(spdy_version_);
  framer.set_enable_compression(false);
  // Construct a SYN_STREAM control frame without compressing the header block,
  // and have the framer try to decompress it. This will cause the framer to
  // deal with a decompression error.
  SpdySynStreamIR syn_stream(1);
  syn_stream.set_priority(1);
  syn_stream.SetHeader("aa", "alpha beta gamma delta");
  SpdySerializedFrame control_frame(framer.SerializeSynStream(syn_stream));
  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = true;
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(SpdyFramer::SPDY_DECOMPRESS_FAILURE, visitor.framer_.error_code())
      << SpdyFramer::ErrorCodeToString(visitor.framer_.error_code());
  EXPECT_EQ(0u, visitor.header_buffer_length_);
}

TEST_P(SpdyFramerTest, ControlFrameSizesAreValidated) {
  SpdyFramer framer(spdy_version_);
  // Create a GoAway frame that has a few extra bytes at the end.
  // We create enough overhead to overflow the framer's control frame buffer.
  ASSERT_LE(SpdyFramerPeer::ControlFrameBufferSize(), 250u);
  const size_t length = SpdyFramerPeer::ControlFrameBufferSize() + 1;
  const unsigned char kV3FrameData[] = {
      0x80, 0x03, 0x00, 0x07,
      0x00, 0x00, 0x00, static_cast<unsigned char>(length),
      0x00, 0x00, 0x00, 0x00,  // Stream ID
      0x00, 0x00, 0x00, 0x00,  // Status
  };

  // HTTP/2 GOAWAY frames are only bound by a minimal length, since they may
  // carry opaque data. Verify that minimal length is tested.
  ASSERT_GT(framer.GetGoAwayMinimumSize(), framer.GetFrameHeaderSize());
  const size_t less_than_min_length =
      framer.GetGoAwayMinimumSize() - framer.GetFrameHeaderSize() - 1;
  ASSERT_LE(less_than_min_length, std::numeric_limits<unsigned char>::max());
  const unsigned char kH2Len = static_cast<unsigned char>(less_than_min_length);
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, kH2Len,        // Length: min length - 1
      0x07,                      //   Type: GOAWAY
      0x00,                      //  Flags: none
      0x00, 0x00, 0x00,   0x00,  // Stream: 0
      0x00, 0x00, 0x00,   0x00,  //   Last: 0
      0x00, 0x00, 0x00,          // Truncated Status Field
  };
  const size_t pad_length =
      length + framer.GetFrameHeaderSize() -
      (IsSpdy3() ? sizeof(kV3FrameData) : sizeof(kH2FrameData));
  string pad(pad_length, 'A');
  TestSpdyVisitor visitor(spdy_version_);

  if (IsSpdy3()) {
    visitor.SimulateInFramer(kV3FrameData, sizeof(kV3FrameData));
  } else {
    visitor.SimulateInFramer(kH2FrameData, sizeof(kH2FrameData));
  }
  visitor.SimulateInFramer(reinterpret_cast<const unsigned char*>(pad.c_str()),
                           pad.length());

  EXPECT_EQ(1, visitor.error_count_);  // This generated an error.
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_CONTROL_FRAME,
            visitor.framer_.error_code())
      << SpdyFramer::ErrorCodeToString(visitor.framer_.error_code());
  EXPECT_EQ(0, visitor.goaway_count_);  // Frame not parsed.
}

TEST_P(SpdyFramerTest, ReadZeroLenSettingsFrame) {
  SpdyFramer framer(spdy_version_);
  SpdySettingsIR settings_ir;
  SpdySerializedFrame control_frame(framer.SerializeSettings(settings_ir));
  SetFrameLength(&control_frame, 0, spdy_version_);
  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = false;
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      framer.GetFrameHeaderSize());
  if (IsSpdy3()) {
    // Should generate an error, since zero-len settings frames are unsupported.
    EXPECT_EQ(1, visitor.error_count_);
  } else {
    // Zero-len settings frames are permitted as of HTTP/2.
    EXPECT_EQ(0, visitor.error_count_);
  }
}

// Tests handling of SETTINGS frames with invalid length.
TEST_P(SpdyFramerTest, ReadBogusLenSettingsFrame) {
  SpdyFramer framer(spdy_version_);
  SpdySettingsIR settings_ir;

  // Add a setting to pad the frame so that we don't get a buffer overflow when
  // calling SimulateInFramer() below.
  settings_ir.AddSetting(SETTINGS_INITIAL_WINDOW_SIZE, false, false,
                         0x00000002);
  SpdySerializedFrame control_frame(framer.SerializeSettings(settings_ir));
  const size_t kNewLength = 14;
  SetFrameLength(&control_frame, kNewLength, spdy_version_);
  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = false;
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      framer.GetFrameHeaderSize() + kNewLength);
  // Should generate an error, since its not possible to have a
  // settings frame of length kNewLength.
  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_CONTROL_FRAME_SIZE,
            visitor.framer_.error_code())
      << SpdyFramer::ErrorCodeToString(visitor.framer_.error_code());
}

// Tests handling of SETTINGS frames larger than the frame buffer size.
TEST_P(SpdyFramerTest, ReadLargeSettingsFrame) {
  SpdyFramer framer(spdy_version_);
  SpdySettingsIR settings_ir;
  settings_ir.AddSetting(SpdyConstants::ParseSettingId(spdy_version_, 1),
                         false,  // persist
                         false,  // persisted
                         5);
  settings_ir.AddSetting(SpdyConstants::ParseSettingId(spdy_version_, 2),
                         false,  // persist
                         false,  // persisted
                         6);
  settings_ir.AddSetting(SpdyConstants::ParseSettingId(spdy_version_, 3),
                         false,  // persist
                         false,  // persisted
                         7);

  SpdySerializedFrame control_frame(framer.SerializeSettings(settings_ir));
  EXPECT_LT(SpdyFramerPeer::ControlFrameBufferSize(), control_frame.size());
  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = false;

  // Read all at once.
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(3, visitor.setting_count_);
  if (IsHttp2()) {
    EXPECT_EQ(1, visitor.settings_ack_sent_);
  }

  // Read data in small chunks.
  size_t framed_data = 0;
  size_t unframed_data = control_frame.size();
  size_t kReadChunkSize = 5;  // Read five bytes at a time.
  while (unframed_data > 0) {
    size_t to_read = std::min(kReadChunkSize, unframed_data);
    visitor.SimulateInFramer(
        reinterpret_cast<unsigned char*>(control_frame.data() + framed_data),
        to_read);
    unframed_data -= to_read;
    framed_data += to_read;
  }
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(3 * 2, visitor.setting_count_);
  if (IsHttp2()) {
    EXPECT_EQ(2, visitor.settings_ack_sent_);
  }
}

// Tests handling of SETTINGS frame with duplicate entries.
TEST_P(SpdyFramerTest, ReadDuplicateSettings) {
  SpdyFramer framer(spdy_version_);

  // clang-format off
  const unsigned char kV3FrameData[] = {
    0x80, 0x03, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x1C,
    0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x01,  // 1st Setting
    0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x01,  // 2nd (duplicate) Setting
    0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x03,  // 3rd (unprocessed) Setting
    0x00, 0x00, 0x00, 0x03,
  };
  // clang-format on
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x12,        // Length: 18
      0x04,                    //   Type: SETTINGS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
      0x00, 0x01,              //  Param: HEADER_TABLE_SIZE
      0x00, 0x00, 0x00, 0x02,  //  Value: 2
      0x00, 0x01,              //  Param: HEADER_TABLE_SIZE
      0x00, 0x00, 0x00, 0x03,  //  Value: 3
      0x00, 0x03,              //  Param: MAX_CONCURRENT_STREAMS
      0x00, 0x00, 0x00, 0x03,  //  Value: 3
  };

  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = false;
  if (IsSpdy3()) {
    visitor.SimulateInFramer(kV3FrameData, sizeof(kV3FrameData));
  } else {
    visitor.SimulateInFramer(kH2FrameData, sizeof(kH2FrameData));
  }

  if (IsSpdy3()) {
    EXPECT_EQ(1, visitor.setting_count_);
    EXPECT_EQ(1, visitor.error_count_);
  } else {
    // In HTTP/2, duplicate settings are allowed;
    // each setting replaces the previous value for that setting.
    EXPECT_EQ(3, visitor.setting_count_);
    EXPECT_EQ(0, visitor.error_count_);
    EXPECT_EQ(1, visitor.settings_ack_sent_);
  }
}

// Tests handling of SETTINGS frame with a setting we don't recognize.
TEST_P(SpdyFramerTest, ReadUnknownSettingsId) {
  SpdyFramer framer(spdy_version_);

  // clang-format off
  const unsigned char kV3FrameData[] = {
    0x80, 0x03, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x1C,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x10,  // 1st Setting
    0x00, 0x00, 0x00, 0x02,
  };
  // clang-format on
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x06,        // Length: 6
      0x04,                    //   Type: SETTINGS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
      0x00, 0x10,              //  Param: 16
      0x00, 0x00, 0x00, 0x02,  //  Value: 2
  };

  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = false;
  if (IsSpdy3()) {
    visitor.SimulateInFramer(kV3FrameData, sizeof(kV3FrameData));
  } else {
    visitor.SimulateInFramer(kH2FrameData, sizeof(kH2FrameData));
  }

  if (IsSpdy3()) {
    EXPECT_EQ(0, visitor.setting_count_);
    EXPECT_EQ(1, visitor.error_count_);
  } else {
    // In HTTP/2, we ignore unknown settings because of extensions.
    EXPECT_EQ(0, visitor.setting_count_);
    EXPECT_EQ(0, visitor.error_count_);
  }
}

// Tests handling of SETTINGS frame with entries out of order.
TEST_P(SpdyFramerTest, ReadOutOfOrderSettings) {
  SpdyFramer framer(spdy_version_);

  // clang-format off
  const unsigned char kV3FrameData[] = {
    0x80, 0x03, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x1C,
    0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x02,  // 1st Setting
    0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x01,  // 2nd (out of order) Setting
    0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x01, 0x03,  // 3rd (unprocessed) Setting
    0x00, 0x00, 0x00, 0x03,
  };
  // clang-format on
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x12,        // Length: 18
      0x04,                    //   Type: SETTINGS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
      0x00, 0x02,              //  Param: ENABLE_PUSH
      0x00, 0x00, 0x00, 0x02,  //  Value: 2
      0x00, 0x01,              //  Param: HEADER_TABLE_SIZE
      0x00, 0x00, 0x00, 0x03,  //  Value: 3
      0x00, 0x03,              //  Param: MAX_CONCURRENT_STREAMS
      0x00, 0x00, 0x00, 0x03,  //  Value: 3
  };

  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = false;
  if (IsSpdy3()) {
    visitor.SimulateInFramer(kV3FrameData, sizeof(kV3FrameData));
  } else {
    visitor.SimulateInFramer(kH2FrameData, sizeof(kH2FrameData));
  }

  if (IsSpdy3()) {
    EXPECT_EQ(1, visitor.setting_count_);
    EXPECT_EQ(1, visitor.error_count_);
  } else {
    // In HTTP/2, settings are allowed in any order.
    EXPECT_EQ(3, visitor.setting_count_);
    EXPECT_EQ(0, visitor.error_count_);
  }
}

TEST_P(SpdyFramerTest, ProcessSettingsAckFrame) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);

  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x00,        // Length: 0
      0x04,                    //   Type: SETTINGS
      0x01,                    //  Flags: ACK
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
  };

  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = false;
  visitor.SimulateInFramer(kFrameData, sizeof(kFrameData));

  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(0, visitor.setting_count_);
  EXPECT_EQ(1, visitor.settings_ack_received_);
}

TEST_P(SpdyFramerTest, ProcessDataFrameWithPadding) {
  if (!IsHttp2()) {
    return;
  }

  const int kPaddingLen = 119;
  const char data_payload[] = "hello";

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  SpdyDataIR data_ir(1, data_payload);
  data_ir.set_padding_len(kPaddingLen);
  SpdySerializedFrame frame(framer.SerializeData(data_ir));

  int bytes_consumed = 0;

  // Send the frame header.
  EXPECT_CALL(visitor,
              OnDataFrameHeader(1, kPaddingLen + strlen(data_payload), false));
  CHECK_EQ(framer.GetDataFrameMinimumSize(),
           framer.ProcessInput(frame.data(), framer.GetDataFrameMinimumSize()));
  CHECK_EQ(framer.state(), SpdyFramer::SPDY_READ_DATA_FRAME_PADDING_LENGTH);
  CHECK_EQ(framer.error_code(), SpdyFramer::SPDY_NO_ERROR);
  bytes_consumed += framer.GetDataFrameMinimumSize();

  // Send the padding length field.
  EXPECT_CALL(visitor, OnStreamPadding(1, 1));
  CHECK_EQ(1u, framer.ProcessInput(frame.data() + bytes_consumed, 1));
  CHECK_EQ(framer.state(), SpdyFramer::SPDY_FORWARD_STREAM_FRAME);
  CHECK_EQ(framer.error_code(), SpdyFramer::SPDY_NO_ERROR);
  bytes_consumed += 1;

  // Send the first two bytes of the data payload, i.e., "he".
  EXPECT_CALL(visitor, OnStreamFrameData(1, _, 2));
  CHECK_EQ(2u, framer.ProcessInput(frame.data() + bytes_consumed, 2));
  CHECK_EQ(framer.state(), SpdyFramer::SPDY_FORWARD_STREAM_FRAME);
  CHECK_EQ(framer.error_code(), SpdyFramer::SPDY_NO_ERROR);
  bytes_consumed += 2;

  // Send the rest three bytes of the data payload, i.e., "llo".
  EXPECT_CALL(visitor, OnStreamFrameData(1, _, 3));
  CHECK_EQ(3u, framer.ProcessInput(frame.data() + bytes_consumed, 3));
  CHECK_EQ(framer.state(), SpdyFramer::SPDY_CONSUME_PADDING);
  CHECK_EQ(framer.error_code(), SpdyFramer::SPDY_NO_ERROR);
  bytes_consumed += 3;

  // Send the first 100 bytes of the padding payload.
  EXPECT_CALL(visitor, OnStreamPadding(1, 100));
  CHECK_EQ(100u, framer.ProcessInput(frame.data() + bytes_consumed, 100));
  CHECK_EQ(framer.state(), SpdyFramer::SPDY_CONSUME_PADDING);
  CHECK_EQ(framer.error_code(), SpdyFramer::SPDY_NO_ERROR);
  bytes_consumed += 100;

  // Send rest of the padding payload.
  EXPECT_CALL(visitor, OnStreamPadding(1, 18));
  CHECK_EQ(18u, framer.ProcessInput(frame.data() + bytes_consumed, 18));
  CHECK_EQ(framer.state(), SpdyFramer::SPDY_READY_FOR_FRAME);
  CHECK_EQ(framer.error_code(), SpdyFramer::SPDY_NO_ERROR);
}

TEST_P(SpdyFramerTest, ReadWindowUpdate) {
  SpdyFramer framer(spdy_version_);
  SpdySerializedFrame control_frame(
      framer.SerializeWindowUpdate(SpdyWindowUpdateIR(1, 2)));
  TestSpdyVisitor visitor(spdy_version_);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_EQ(1u, visitor.last_window_update_stream_);
  EXPECT_EQ(2, visitor.last_window_update_delta_);
}

TEST_P(SpdyFramerTest, ReadCompressedPushPromise) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  SpdyPushPromiseIR push_promise(42, 57);
  push_promise.SetHeader("foo", "bar");
  push_promise.SetHeader("bar", "foofoo");
  SpdySerializedFrame frame(framer.SerializePushPromise(push_promise));
  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = true;
  visitor.SimulateInFramer(reinterpret_cast<unsigned char*>(frame.data()),
                           frame.size());
  EXPECT_EQ(42u, visitor.last_push_promise_stream_);
  EXPECT_EQ(57u, visitor.last_push_promise_promised_stream_);
  EXPECT_EQ(push_promise.header_block(), visitor.headers_);
}

TEST_P(SpdyFramerTest, ReadHeadersWithContinuation) {
  if (!IsHttp2()) {
    return;
  }

  // frame-format off
  const unsigned char kInput[] = {
      0x00, 0x00, 0x14,                       // Length: 20
      0x01,                                   //   Type: HEADERS
      0x09,                                   //  Flags: FIN, PADDED
      0x00, 0x00, 0x00, 0x01,                 // Stream: 1
      0x03,                                   // PadLen: 3 trailing bytes
      0x00,                                   // Unindexed Entry
      0x06,                                   // Name Len: 6
      'c',  'o',  'o',  'k',  'i', 'e',       // Name
      0x07,                                   // Value Len: 7
      'f',  'o',  'o',  '=',  'b', 'a', 'r',  // Value
      0x00, 0x00, 0x00,                       // Padding

      0x00, 0x00, 0x14,                            // Length: 20
      0x09,                                        //   Type: CONTINUATION
      0x00,                                        //  Flags: none
      0x00, 0x00, 0x00, 0x01,                      // Stream: 1
      0x00,                                        // Unindexed Entry
      0x06,                                        // Name Len: 6
      'c',  'o',  'o',  'k',  'i', 'e',            // Name
      0x08,                                        // Value Len: 7
      'b',  'a',  'z',  '=',  'b', 'i', 'n', 'g',  // Value
      0x00,                                        // Unindexed Entry
      0x06,                                        // Name Len: 6
      'c',                                         // Name (split)

      0x00, 0x00, 0x12,             // Length: 18
      0x09,                         //   Type: CONTINUATION
      0x04,                         //  Flags: END_HEADERS
      0x00, 0x00, 0x00, 0x01,       // Stream: 1
      'o',  'o',  'k',  'i',  'e',  // Name (continued)
      0x00,                         // Value Len: 0
      0x00,                         // Unindexed Entry
      0x04,                         // Name Len: 4
      'n',  'a',  'm',  'e',        // Name
      0x05,                         // Value Len: 5
      'v',  'a',  'l',  'u',  'e',  // Value
  };
  // frame-format on

  SpdyFramer framer(spdy_version_);
  TestSpdyVisitor visitor(spdy_version_);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(2, visitor.continuation_count_);
  EXPECT_EQ(1, visitor.fin_flag_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
  EXPECT_EQ(1, visitor.end_of_stream_count_);

  EXPECT_THAT(
      visitor.headers_,
      testing::ElementsAre(testing::Pair("cookie", "foo=bar; baz=bing; "),
                           testing::Pair("name", "value")));
}

TEST_P(SpdyFramerTest, ReadPushPromiseWithContinuation) {
  if (!IsHttp2()) {
    return;
  }

  // frame-format off
  const unsigned char kInput[] = {
    0x00, 0x00, 0x17, 0x05,  // PUSH_PROMISE
    0x08, 0x00, 0x00, 0x00,  // PADDED
    0x01, 0x02, 0x00, 0x00,  // Stream 1, Pad length field
    0x00, 0x2A, 0x00, 0x06,  // Promised stream 42
    'c',  'o',  'o',  'k',
    'i',  'e',  0x07, 'f',
    'o',  'o',  '=',  'b',
    'a',  'r',  0x00, 0x00,

    0x00, 0x00, 0x14, 0x09,  // CONTINUATION
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x06, 'c',   // Stream 1
    'o',  'o',  'k',  'i',
    'e',  0x08, 'b',  'a',
    'z',  '=',  'b',  'i',
    'n',  'g',  0x00, 0x06,
    'c',

    0x00, 0x00, 0x12, 0x09,  // CONTINUATION
    0x04, 0x00, 0x00, 0x00,  // END_HEADERS
    0x01, 'o',  'o',  'k',   // Stream 1
    'i',  'e',  0x00, 0x00,
    0x04, 'n',  'a',  'm',
    'e',  0x05, 'v',  'a',
    'l',  'u',  'e',
  };
  // frame-format on

  SpdyFramer framer(spdy_version_);
  TestSpdyVisitor visitor(spdy_version_);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1u, visitor.last_push_promise_stream_);
  EXPECT_EQ(42u, visitor.last_push_promise_promised_stream_);
  EXPECT_EQ(2, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
  EXPECT_EQ(0, visitor.end_of_stream_count_);

  EXPECT_THAT(
      visitor.headers_,
      testing::ElementsAre(testing::Pair("cookie", "foo=bar; baz=bing; "),
                           testing::Pair("name", "value")));
}

// Receiving an unknown frame when a continuation is expected should
// result in a SPDY_UNEXPECTED_FRAME error
TEST_P(SpdyFramerTest, ReceiveUnknownMidContinuation) {
  if (!IsHttp2()) {
    return;
  }

  const unsigned char kInput[] = {
      0x00, 0x00, 0x10,        // Length: 16
      0x01,                    //   Type: HEADERS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // HPACK
      0x6f, 0x6b, 0x69, 0x65,  //
      0x07, 0x66, 0x6f, 0x6f,  //
      0x3d, 0x62, 0x61, 0x72,  //

      0x00, 0x00, 0x14,        // Length: 20
      0xa9,                    //   Type: UnknownFrameType(169)
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // Payload
      0x6f, 0x6b, 0x69, 0x65,  //
      0x08, 0x62, 0x61, 0x7a,  //
      0x3d, 0x62, 0x69, 0x6e,  //
      0x67, 0x00, 0x06, 0x63,  //
  };

  SpdyFramer framer(spdy_version_);
  TestSpdyVisitor visitor(spdy_version_);
  // Assume the unknown frame is allowed
  visitor.on_unknown_frame_result_ = true;
  framer.set_visitor(&visitor);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(SpdyFramer::SPDY_UNEXPECTED_FRAME, visitor.framer_.error_code())
      << SpdyFramer::ErrorCodeToString(visitor.framer_.error_code());
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.continuation_count_);
  EXPECT_EQ(0u, visitor.header_buffer_length_);
}

TEST_P(SpdyFramerTest, ReceiveContinuationOnWrongStream) {
  if (!IsHttp2()) {
    return;
  }

  const unsigned char kInput[] = {
      0x00, 0x00, 0x10,        // Length: 16
      0x01,                    //   Type: HEADERS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // HPACK
      0x6f, 0x6b, 0x69, 0x65,  //
      0x07, 0x66, 0x6f, 0x6f,  //
      0x3d, 0x62, 0x61, 0x72,  //

      0x00, 0x00, 0x14,        // Length: 20
      0x09,                    //   Type: CONTINUATION
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x02,  // Stream: 2
      0x00, 0x06, 0x63, 0x6f,  // HPACK
      0x6f, 0x6b, 0x69, 0x65,  //
      0x08, 0x62, 0x61, 0x7a,  //
      0x3d, 0x62, 0x69, 0x6e,  //
      0x67, 0x00, 0x06, 0x63,  //
  };

  SpdyFramer framer(spdy_version_);
  TestSpdyVisitor visitor(spdy_version_);
  framer.set_visitor(&visitor);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(SpdyFramer::SPDY_UNEXPECTED_FRAME, visitor.framer_.error_code())
      << SpdyFramer::ErrorCodeToString(visitor.framer_.error_code());
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.continuation_count_);
  EXPECT_EQ(0u, visitor.header_buffer_length_);
}

TEST_P(SpdyFramerTest, ReadContinuationOutOfOrder) {
  if (!IsHttp2()) {
    return;
  }

  const unsigned char kInput[] = {
      0x00, 0x00, 0x18,        // Length: 24
      0x09,                    //   Type: CONTINUATION
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // HPACK
      0x6f, 0x6b, 0x69, 0x65,  //
      0x07, 0x66, 0x6f, 0x6f,  //
      0x3d, 0x62, 0x61, 0x72,  //
  };

  SpdyFramer framer(spdy_version_);
  TestSpdyVisitor visitor(spdy_version_);
  framer.set_visitor(&visitor);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(SpdyFramer::SPDY_UNEXPECTED_FRAME, visitor.framer_.error_code())
      << SpdyFramer::ErrorCodeToString(visitor.framer_.error_code());
  EXPECT_EQ(0, visitor.continuation_count_);
  EXPECT_EQ(0u, visitor.header_buffer_length_);
}

TEST_P(SpdyFramerTest, ExpectContinuationReceiveData) {
  if (!IsHttp2()) {
    return;
  }

  const unsigned char kInput[] = {
      0x00, 0x00, 0x10,        // Length: 16
      0x01,                    //   Type: HEADERS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // HPACK
      0x6f, 0x6b, 0x69, 0x65,  //
      0x07, 0x66, 0x6f, 0x6f,  //
      0x3d, 0x62, 0x61, 0x72,  //

      0x00, 0x00, 0x00,        // Length: 0
      0x00,                    //   Type: DATA
      0x01,                    //  Flags: END_STREAM
      0x00, 0x00, 0x00, 0x04,  // Stream: 4

      0xde, 0xad, 0xbe, 0xef,  // Truncated Frame Header
  };

  SpdyFramer framer(spdy_version_);
  TestSpdyVisitor visitor(spdy_version_);
  framer.set_visitor(&visitor);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(SpdyFramer::SPDY_UNEXPECTED_FRAME, visitor.framer_.error_code())
      << SpdyFramer::ErrorCodeToString(visitor.framer_.error_code());
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.continuation_count_);
  EXPECT_EQ(0u, visitor.header_buffer_length_);
  EXPECT_EQ(0, visitor.data_frame_count_);
}

TEST_P(SpdyFramerTest, ExpectContinuationReceiveControlFrame) {
  if (!IsHttp2()) {
    return;
  }

  const unsigned char kInput[] = {
      0x00, 0x00, 0x10,        // Length: 16
      0x01,                    //   Type: HEADERS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // HPACK
      0x6f, 0x6b, 0x69, 0x65,  //
      0x07, 0x66, 0x6f, 0x6f,  //
      0x3d, 0x62, 0x61, 0x72,  //

      0x00, 0x00, 0x10,        // Length: 16
      0x01,                    //   Type: HEADERS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // HPACK
      0x6f, 0x6b, 0x69, 0x65,  //
      0x07, 0x66, 0x6f, 0x6f,  //
      0x3d, 0x62, 0x61, 0x72,  //
  };

  SpdyFramer framer(spdy_version_);
  TestSpdyVisitor visitor(spdy_version_);
  framer.set_visitor(&visitor);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(SpdyFramer::SPDY_UNEXPECTED_FRAME, visitor.framer_.error_code())
      << SpdyFramer::ErrorCodeToString(visitor.framer_.error_code());
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.continuation_count_);
  EXPECT_EQ(0u, visitor.header_buffer_length_);
  EXPECT_EQ(0, visitor.data_frame_count_);
}

TEST_P(SpdyFramerTest, ReadGarbage) {
  SpdyFramer framer(spdy_version_);
  unsigned char garbage_frame[256];
  memset(garbage_frame, ~0, sizeof(garbage_frame));
  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = false;
  visitor.SimulateInFramer(garbage_frame, sizeof(garbage_frame));
  EXPECT_EQ(1, visitor.error_count_);
}

TEST_P(SpdyFramerTest, ReadUnknownExtensionFrame) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);

  // The unrecognized frame type should still have a valid length.
  const unsigned char unknown_frame[] = {
      0x00, 0x00, 0x08,        // Length: 8
      0xff,                    //   Type: UnknownFrameType(255)
      0xff,                    //  Flags: 0xff
      0xff, 0xff, 0xff, 0xff,  // Stream: 0x7fffffff (R-bit set)
      0xff, 0xff, 0xff, 0xff,  // Payload
      0xff, 0xff, 0xff, 0xff,  //
  };
  TestSpdyVisitor visitor(spdy_version_);

  // Simulate the case where the stream id validation checks out.
  visitor.on_unknown_frame_result_ = true;
  visitor.use_compression_ = false;
  visitor.SimulateInFramer(unknown_frame, arraysize(unknown_frame));
  EXPECT_EQ(0, visitor.error_count_);

  // Follow it up with a valid control frame to make sure we handle
  // subsequent frames correctly.
  SpdySettingsIR settings_ir;
  settings_ir.AddSetting(SpdyConstants::ParseSettingId(spdy_version_, 1),
                         false,  // persist
                         false,  // persisted
                         10);
  SpdySerializedFrame control_frame(framer.SerializeSettings(settings_ir));
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1u, static_cast<unsigned>(visitor.setting_count_));
  EXPECT_EQ(1u, static_cast<unsigned>(visitor.settings_ack_sent_));
}

TEST_P(SpdyFramerTest, ReadGarbageWithValidLength) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x08,        // Length: 8
      0xff,                    //   Type: UnknownFrameType(255)
      0xff,                    //  Flags: 0xff
      0xff, 0xff, 0xff, 0xff,  // Stream: 0x7fffffff (R-bit set)
      0xff, 0xff, 0xff, 0xff,  // Payload
      0xff, 0xff, 0xff, 0xff,  //
  };
  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = false;
  visitor.SimulateInFramer(kFrameData, arraysize(kFrameData));
  EXPECT_EQ(1, visitor.error_count_);
}

TEST_P(SpdyFramerTest, ReadGarbageWithValidVersion) {
  if (!IsSpdy3()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  // clang-format off
  const unsigned char kFrameData[] = {
    0x80, 0x03, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
  };
  // clang-format on
  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = false;
  visitor.SimulateInFramer(kFrameData, arraysize(kFrameData));
  EXPECT_EQ(1, visitor.error_count_);
}

TEST_P(SpdyFramerTest, ReadGarbageHPACKEncoding) {
  if (!IsHttp2()) {
    return;
  }

  const unsigned char kInput[] = {
      0x00, 0x12, 0x01,        // Length: 4609
      0x04,                    //   Type: SETTINGS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x01, 0xef,  // Stream: 495
      0xef, 0xff,              //  Param: 61439
      0xff, 0xff, 0xff, 0xff,  //  Value: 4294967295
      0xff, 0xff,              //  Param: 0xffff
      0xff, 0xff, 0xff, 0xff,  //  Value: 4294967295
      0xff, 0xff, 0xff, 0xff,  // Settings (Truncated)
      0xff,                    //
  };

  TestSpdyVisitor visitor(spdy_version_);
  visitor.SimulateInFramer(kInput, arraysize(kInput));
  EXPECT_EQ(1, visitor.error_count_);
}

TEST_P(SpdyFramerTest, SizesTest) {
  SpdyFramer framer(spdy_version_);
  if (IsSpdy3()) {
    EXPECT_EQ(8u, framer.GetDataFrameMinimumSize());
    EXPECT_EQ(8u, framer.GetFrameHeaderSize());
    EXPECT_EQ(18u, framer.GetSynStreamMinimumSize());
    EXPECT_EQ(12u, framer.GetSynReplyMinimumSize());
    EXPECT_EQ(16u, framer.GetRstStreamMinimumSize());
    EXPECT_EQ(12u, framer.GetSettingsMinimumSize());
    EXPECT_EQ(12u, framer.GetPingSize());
    EXPECT_EQ(16u, framer.GetGoAwayMinimumSize());
    EXPECT_EQ(12u, framer.GetHeadersMinimumSize());
    EXPECT_EQ(16u, framer.GetWindowUpdateSize());
    EXPECT_EQ(8u, framer.GetFrameMinimumSize());
    EXPECT_EQ(16777223u, framer.GetFrameMaximumSize());
    EXPECT_EQ(16777215u, framer.GetDataFrameMaximumPayload());
  } else {
    EXPECT_EQ(9u, framer.GetDataFrameMinimumSize());
    EXPECT_EQ(9u, framer.GetFrameHeaderSize());
    EXPECT_EQ(14u, framer.GetSynStreamMinimumSize());
    EXPECT_EQ(9u, framer.GetSynReplyMinimumSize());
    EXPECT_EQ(13u, framer.GetRstStreamMinimumSize());
    EXPECT_EQ(9u, framer.GetSettingsMinimumSize());
    EXPECT_EQ(17u, framer.GetPingSize());
    EXPECT_EQ(17u, framer.GetGoAwayMinimumSize());
    EXPECT_EQ(9u, framer.GetHeadersMinimumSize());
    EXPECT_EQ(13u, framer.GetWindowUpdateSize());
    EXPECT_EQ(9u, framer.GetBlockedSize());
    EXPECT_EQ(13u, framer.GetPushPromiseMinimumSize());
    EXPECT_EQ(11u, framer.GetAltSvcMinimumSize());
    EXPECT_EQ(9u, framer.GetFrameMinimumSize());
    EXPECT_EQ(16393u, framer.GetFrameMaximumSize());
    EXPECT_EQ(16384u, framer.GetDataFrameMaximumPayload());
  }
}

TEST_P(SpdyFramerTest, StateToStringTest) {
  EXPECT_STREQ("ERROR", SpdyFramer::StateToString(SpdyFramer::SPDY_ERROR));
  EXPECT_STREQ("FRAME_COMPLETE",
               SpdyFramer::StateToString(SpdyFramer::SPDY_FRAME_COMPLETE));
  EXPECT_STREQ("READY_FOR_FRAME",
               SpdyFramer::StateToString(SpdyFramer::SPDY_READY_FOR_FRAME));
  EXPECT_STREQ(
      "READING_COMMON_HEADER",
      SpdyFramer::StateToString(SpdyFramer::SPDY_READING_COMMON_HEADER));
  EXPECT_STREQ(
      "CONTROL_FRAME_PAYLOAD",
      SpdyFramer::StateToString(SpdyFramer::SPDY_CONTROL_FRAME_PAYLOAD));
  EXPECT_STREQ(
      "IGNORE_REMAINING_PAYLOAD",
      SpdyFramer::StateToString(SpdyFramer::SPDY_IGNORE_REMAINING_PAYLOAD));
  EXPECT_STREQ(
      "FORWARD_STREAM_FRAME",
      SpdyFramer::StateToString(SpdyFramer::SPDY_FORWARD_STREAM_FRAME));
  EXPECT_STREQ("SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK",
               SpdyFramer::StateToString(
                   SpdyFramer::SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK));
  EXPECT_STREQ(
      "SPDY_CONTROL_FRAME_HEADER_BLOCK",
      SpdyFramer::StateToString(SpdyFramer::SPDY_CONTROL_FRAME_HEADER_BLOCK));
  EXPECT_STREQ(
      "SPDY_SETTINGS_FRAME_PAYLOAD",
      SpdyFramer::StateToString(SpdyFramer::SPDY_SETTINGS_FRAME_PAYLOAD));
  EXPECT_STREQ(
      "SPDY_ALTSVC_FRAME_PAYLOAD",
      SpdyFramer::StateToString(SpdyFramer::SPDY_ALTSVC_FRAME_PAYLOAD));
  EXPECT_STREQ("UNKNOWN_STATE", SpdyFramer::StateToString(
                                    SpdyFramer::SPDY_ALTSVC_FRAME_PAYLOAD + 1));
}

TEST_P(SpdyFramerTest, ErrorCodeToStringTest) {
  EXPECT_STREQ("NO_ERROR",
               SpdyFramer::ErrorCodeToString(SpdyFramer::SPDY_NO_ERROR));
  EXPECT_STREQ("INVALID_STREAM_ID", SpdyFramer::ErrorCodeToString(
                                        SpdyFramer::SPDY_INVALID_STREAM_ID));
  EXPECT_STREQ(
      "INVALID_CONTROL_FRAME",
      SpdyFramer::ErrorCodeToString(SpdyFramer::SPDY_INVALID_CONTROL_FRAME));
  EXPECT_STREQ("CONTROL_PAYLOAD_TOO_LARGE",
               SpdyFramer::ErrorCodeToString(
                   SpdyFramer::SPDY_CONTROL_PAYLOAD_TOO_LARGE));
  EXPECT_STREQ("INVALID_CONTROL_FRAME_SIZE",
               SpdyFramer::ErrorCodeToString(
                   SpdyFramer::SPDY_INVALID_CONTROL_FRAME_SIZE));
  EXPECT_STREQ("ZLIB_INIT_FAILURE", SpdyFramer::ErrorCodeToString(
                                        SpdyFramer::SPDY_ZLIB_INIT_FAILURE));
  EXPECT_STREQ(
      "UNSUPPORTED_VERSION",
      SpdyFramer::ErrorCodeToString(SpdyFramer::SPDY_UNSUPPORTED_VERSION));
  EXPECT_STREQ("DECOMPRESS_FAILURE", SpdyFramer::ErrorCodeToString(
                                         SpdyFramer::SPDY_DECOMPRESS_FAILURE));
  EXPECT_STREQ("COMPRESS_FAILURE", SpdyFramer::ErrorCodeToString(
                                       SpdyFramer::SPDY_COMPRESS_FAILURE));
  EXPECT_STREQ("SPDY_INVALID_PADDING",
               SpdyFramer::ErrorCodeToString(SpdyFramer::SPDY_INVALID_PADDING));
  EXPECT_STREQ(
      "SPDY_INVALID_DATA_FRAME_FLAGS",
      SpdyFramer::ErrorCodeToString(SpdyFramer::SPDY_INVALID_DATA_FRAME_FLAGS));
  EXPECT_STREQ("SPDY_INVALID_CONTROL_FRAME_FLAGS",
               SpdyFramer::ErrorCodeToString(
                   SpdyFramer::SPDY_INVALID_CONTROL_FRAME_FLAGS));
  EXPECT_STREQ("UNKNOWN_ERROR",
               SpdyFramer::ErrorCodeToString(SpdyFramer::LAST_ERROR));
}

TEST_P(SpdyFramerTest, StatusCodeToStringTest) {
  EXPECT_STREQ("INVALID", SpdyFramer::StatusCodeToString(RST_STREAM_INVALID));
  EXPECT_STREQ("PROTOCOL_ERROR",
               SpdyFramer::StatusCodeToString(RST_STREAM_PROTOCOL_ERROR));
  EXPECT_STREQ("INVALID_STREAM",
               SpdyFramer::StatusCodeToString(RST_STREAM_INVALID_STREAM));
  EXPECT_STREQ("REFUSED_STREAM",
               SpdyFramer::StatusCodeToString(RST_STREAM_REFUSED_STREAM));
  EXPECT_STREQ("UNSUPPORTED_VERSION",
               SpdyFramer::StatusCodeToString(RST_STREAM_UNSUPPORTED_VERSION));
  EXPECT_STREQ("CANCEL", SpdyFramer::StatusCodeToString(RST_STREAM_CANCEL));
  EXPECT_STREQ("INTERNAL_ERROR",
               SpdyFramer::StatusCodeToString(RST_STREAM_INTERNAL_ERROR));
  EXPECT_STREQ("FLOW_CONTROL_ERROR",
               SpdyFramer::StatusCodeToString(RST_STREAM_FLOW_CONTROL_ERROR));
  EXPECT_STREQ("UNKNOWN_STATUS", SpdyFramer::StatusCodeToString(-1));
}

TEST_P(SpdyFramerTest, FrameTypeToStringTest) {
  EXPECT_STREQ("DATA", SpdyFramer::FrameTypeToString(DATA));
  EXPECT_STREQ("SYN_STREAM", SpdyFramer::FrameTypeToString(SYN_STREAM));
  EXPECT_STREQ("SYN_REPLY", SpdyFramer::FrameTypeToString(SYN_REPLY));
  EXPECT_STREQ("RST_STREAM", SpdyFramer::FrameTypeToString(RST_STREAM));
  EXPECT_STREQ("SETTINGS", SpdyFramer::FrameTypeToString(SETTINGS));
  EXPECT_STREQ("PING", SpdyFramer::FrameTypeToString(PING));
  EXPECT_STREQ("GOAWAY", SpdyFramer::FrameTypeToString(GOAWAY));
  EXPECT_STREQ("HEADERS", SpdyFramer::FrameTypeToString(HEADERS));
  EXPECT_STREQ("WINDOW_UPDATE", SpdyFramer::FrameTypeToString(WINDOW_UPDATE));
  EXPECT_STREQ("PUSH_PROMISE", SpdyFramer::FrameTypeToString(PUSH_PROMISE));
  EXPECT_STREQ("CONTINUATION", SpdyFramer::FrameTypeToString(CONTINUATION));
}

TEST_P(SpdyFramerTest, CatchProbableHttpResponse) {
  if (!IsSpdy3()) {
    // TODO(hkhalil): catch probable HTTP response in HTTP/2?
    return;
  }

  {
    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    SpdyFramer framer(spdy_version_);
    framer.set_visitor(&visitor);

    EXPECT_CALL(visitor, OnError(_));
    framer.ProcessInput("HTTP/1.1", 8);
    EXPECT_TRUE(framer.probable_http_response());
    EXPECT_EQ(SpdyFramer::SPDY_ERROR, framer.state());
    EXPECT_EQ(SpdyFramer::SPDY_INVALID_DATA_FRAME_FLAGS, framer.error_code())
        << SpdyFramer::ErrorCodeToString(framer.error_code());
  }
  {
    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    SpdyFramer framer(spdy_version_);
    framer.set_visitor(&visitor);

    EXPECT_CALL(visitor, OnError(_));
    framer.ProcessInput("HTTP/1.0", 8);
    EXPECT_TRUE(framer.probable_http_response());
    EXPECT_EQ(SpdyFramer::SPDY_ERROR, framer.state());
    EXPECT_EQ(SpdyFramer::SPDY_INVALID_DATA_FRAME_FLAGS, framer.error_code())
        << SpdyFramer::ErrorCodeToString(framer.error_code());
  }
}

TEST_P(SpdyFramerTest, DataFrameFlagsV2V3) {
  if (!IsSpdy3()) {
    return;
  }

  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message() << "Flags " << flags << std::hex
                                    << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    SpdyFramer framer(spdy_version_);
    framer.set_visitor(&visitor);

    SpdyDataIR data_ir(1, "hello");
    SpdySerializedFrame frame(framer.SerializeData(data_ir));
    SetFrameFlags(&frame, flags, spdy_version_);

    if (flags & ~DATA_FLAG_FIN) {
      EXPECT_CALL(visitor, OnError(_));
    } else {
      EXPECT_CALL(visitor, OnDataFrameHeader(1, 5, flags & DATA_FLAG_FIN));
      EXPECT_CALL(visitor, OnStreamFrameData(_, _, 5));
      if (flags & DATA_FLAG_FIN) {
        EXPECT_CALL(visitor, OnStreamEnd(_));
      }
    }

    framer.ProcessInput(frame.data(), frame.size());
    if (flags & ~DATA_FLAG_FIN) {
      EXPECT_EQ(SpdyFramer::SPDY_ERROR, framer.state());
      EXPECT_EQ(SpdyFramer::SPDY_INVALID_DATA_FRAME_FLAGS, framer.error_code())
          << SpdyFramer::ErrorCodeToString(framer.error_code());
    } else {
      EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
      EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
          << SpdyFramer::ErrorCodeToString(framer.error_code());
    }
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, DataFrameFlagsV4) {
  if (!IsHttp2()) {
    return;
  }

  uint8_t valid_data_flags = DATA_FLAG_FIN | DATA_FLAG_PADDED;

  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message() << "Flags " << flags << std::hex
                                    << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    SpdyFramer framer(spdy_version_);
    framer.set_visitor(&visitor);

    SpdyDataIR data_ir(1, "hello");
    SpdySerializedFrame frame(framer.SerializeData(data_ir));
    SetFrameFlags(&frame, flags, spdy_version_);

    if (flags & ~valid_data_flags) {
      EXPECT_CALL(visitor, OnError(_));
    } else {
      EXPECT_CALL(visitor, OnDataFrameHeader(1, 5, flags & DATA_FLAG_FIN));
      if (flags & DATA_FLAG_PADDED) {
        // The first byte of payload is parsed as padding length, but 'h'
        // (0x68) is too large a padding length for a 5 byte payload.
        EXPECT_CALL(visitor, OnStreamPadding(_, 1));
        // Expect Error since the frame ends prematurely.
        EXPECT_CALL(visitor, OnError(_));
      } else {
        EXPECT_CALL(visitor, OnStreamFrameData(_, _, 5));
        if (flags & DATA_FLAG_FIN) {
          EXPECT_CALL(visitor, OnStreamEnd(_));
        }
      }
    }

    framer.ProcessInput(frame.data(), frame.size());
    if (flags & ~valid_data_flags) {
      EXPECT_EQ(SpdyFramer::SPDY_ERROR, framer.state());
      EXPECT_EQ(SpdyFramer::SPDY_INVALID_DATA_FRAME_FLAGS, framer.error_code())
          << SpdyFramer::ErrorCodeToString(framer.error_code());
    } else if (flags & DATA_FLAG_PADDED) {
      EXPECT_EQ(SpdyFramer::SPDY_ERROR, framer.state());
      EXPECT_EQ(SpdyFramer::SPDY_INVALID_PADDING, framer.error_code())
          << SpdyFramer::ErrorCodeToString(framer.error_code());
    } else {
      EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
      EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
          << SpdyFramer::ErrorCodeToString(framer.error_code());
    }
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, SynStreamFrameFlags) {
  if (!IsSpdy3()) {
    return;
  }

  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message() << "Flags " << flags << std::hex
                                    << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    testing::StrictMock<test::MockDebugVisitor> debug_visitor;
    SpdyFramer framer(spdy_version_);
    framer.set_visitor(&visitor);
    framer.set_debug_visitor(&debug_visitor);

    EXPECT_CALL(debug_visitor, OnSendCompressedFrame(8, SYN_STREAM, _, _));

    SpdySynStreamIR syn_stream(8);
    syn_stream.set_associated_to_stream_id(3);
    syn_stream.set_priority(1);
    syn_stream.SetHeader("foo", "bar");
    SpdySerializedFrame frame(framer.SerializeSynStream(syn_stream));
    SetFrameFlags(&frame, flags, spdy_version_);

    if (flags & ~(CONTROL_FLAG_FIN | CONTROL_FLAG_UNIDIRECTIONAL)) {
      EXPECT_CALL(visitor, OnError(_));
    } else {
      EXPECT_CALL(debug_visitor, OnReceiveCompressedFrame(8, SYN_STREAM, _));
      EXPECT_CALL(visitor, OnSynStream(8, 3, 1, flags & CONTROL_FLAG_FIN,
                                       flags & CONTROL_FLAG_UNIDIRECTIONAL));
      EXPECT_CALL(visitor, OnHeaderFrameStart(8)).Times(1);
      EXPECT_CALL(visitor, OnHeaderFrameEnd(8, _)).Times(1);
      if (flags & DATA_FLAG_FIN) {
        EXPECT_CALL(visitor, OnStreamEnd(_));
      } else {
        // Do not close the stream if we are expecting a CONTINUATION frame.
        EXPECT_CALL(visitor, OnStreamEnd(_)).Times(0);
      }
    }

    framer.ProcessInput(frame.data(), frame.size());
    if (flags & ~(CONTROL_FLAG_FIN | CONTROL_FLAG_UNIDIRECTIONAL)) {
      EXPECT_EQ(SpdyFramer::SPDY_ERROR, framer.state());
      EXPECT_EQ(SpdyFramer::SPDY_INVALID_CONTROL_FRAME_FLAGS,
                framer.error_code())
          << SpdyFramer::ErrorCodeToString(framer.error_code());
    } else {
      EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
      EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
          << SpdyFramer::ErrorCodeToString(framer.error_code());
    }
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, SynReplyFrameFlags) {
  if (!IsSpdy3()) {
    return;
  }

  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message() << "Flags " << flags << std::hex
                                    << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    SpdyFramer framer(spdy_version_);
    framer.set_visitor(&visitor);

    SpdySynReplyIR syn_reply(37);
    syn_reply.SetHeader("foo", "bar");
    SpdySerializedFrame frame(framer.SerializeSynReply(syn_reply));
    SetFrameFlags(&frame, flags, spdy_version_);

    if (flags & ~CONTROL_FLAG_FIN) {
      EXPECT_CALL(visitor, OnError(_));
    } else {
      EXPECT_CALL(visitor, OnSynReply(37, flags & CONTROL_FLAG_FIN));
      EXPECT_CALL(visitor, OnHeaderFrameStart(37)).Times(1);
      EXPECT_CALL(visitor, OnHeaderFrameEnd(37, _)).Times(1);
      if (flags & DATA_FLAG_FIN) {
        EXPECT_CALL(visitor, OnStreamEnd(_));
      }
    }

    framer.ProcessInput(frame.data(), frame.size());
    if (flags & ~CONTROL_FLAG_FIN) {
      EXPECT_EQ(SpdyFramer::SPDY_ERROR, framer.state());
      EXPECT_EQ(SpdyFramer::SPDY_INVALID_CONTROL_FRAME_FLAGS,
                framer.error_code())
          << SpdyFramer::ErrorCodeToString(framer.error_code());
    } else {
      EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
      EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
          << SpdyFramer::ErrorCodeToString(framer.error_code());
    }
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, RstStreamFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message() << "Flags " << flags << std::hex
                                    << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    SpdyFramer framer(spdy_version_);
    framer.set_visitor(&visitor);

    SpdyRstStreamIR rst_stream(13, RST_STREAM_CANCEL);
    SpdySerializedFrame frame(framer.SerializeRstStream(rst_stream));
    SetFrameFlags(&frame, flags, spdy_version_);

    EXPECT_CALL(visitor, OnRstStream(13, RST_STREAM_CANCEL));

    framer.ProcessInput(frame.data(), frame.size());

    EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
    EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
        << SpdyFramer::ErrorCodeToString(framer.error_code());
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, SettingsFrameFlagsOldFormat) {
  if (!IsSpdy3()) {
    return;
  }

  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message() << "Flags " << flags << std::hex
                                    << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    SpdyFramer framer(spdy_version_);
    framer.set_visitor(&visitor);

    SpdySettingsIR settings_ir;
    settings_ir.AddSetting(SETTINGS_UPLOAD_BANDWIDTH, false, false, 54321);
    SpdySerializedFrame frame(framer.SerializeSettings(settings_ir));
    SetFrameFlags(&frame, flags, spdy_version_);

    if (flags & ~SETTINGS_FLAG_CLEAR_PREVIOUSLY_PERSISTED_SETTINGS) {
      EXPECT_CALL(visitor, OnError(_));
    } else {
      EXPECT_CALL(
          visitor,
          OnSettings(flags &
                     SETTINGS_FLAG_CLEAR_PREVIOUSLY_PERSISTED_SETTINGS));
      EXPECT_CALL(visitor, OnSetting(SETTINGS_UPLOAD_BANDWIDTH,
                                     SETTINGS_FLAG_NONE, 54321));
      EXPECT_CALL(visitor, OnSettingsEnd());
    }

    framer.ProcessInput(frame.data(), frame.size());
    if (flags & ~SETTINGS_FLAG_CLEAR_PREVIOUSLY_PERSISTED_SETTINGS) {
      EXPECT_EQ(SpdyFramer::SPDY_ERROR, framer.state());
      EXPECT_EQ(SpdyFramer::SPDY_INVALID_CONTROL_FRAME_FLAGS,
                framer.error_code())
          << SpdyFramer::ErrorCodeToString(framer.error_code());
    } else {
      EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
      EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
          << SpdyFramer::ErrorCodeToString(framer.error_code());
    }
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, SettingsFrameFlags) {
  if (!IsHttp2()) {
    return;
  }

  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message() << "Flags " << flags << std::hex
                                    << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    SpdyFramer framer(spdy_version_);
    framer.set_visitor(&visitor);

    SpdySettingsIR settings_ir;
    settings_ir.AddSetting(SETTINGS_INITIAL_WINDOW_SIZE, 0, 0, 16);
    SpdySerializedFrame frame(framer.SerializeSettings(settings_ir));
    SetFrameFlags(&frame, flags, spdy_version_);

    if (flags & SETTINGS_FLAG_ACK) {
      EXPECT_CALL(visitor, OnError(_));
    } else {
      EXPECT_CALL(visitor, OnSettings(flags & SETTINGS_FLAG_ACK));
      EXPECT_CALL(visitor, OnSetting(SETTINGS_INITIAL_WINDOW_SIZE, 0, 16));
      EXPECT_CALL(visitor, OnSettingsEnd());
    }

    framer.ProcessInput(frame.data(), frame.size());
    if (flags & SETTINGS_FLAG_ACK) {
      // The frame is invalid because ACK frames should have no payload.
      EXPECT_EQ(SpdyFramer::SPDY_ERROR, framer.state());
      EXPECT_EQ(SpdyFramer::SPDY_INVALID_CONTROL_FRAME_SIZE,
                framer.error_code())
          << SpdyFramer::ErrorCodeToString(framer.error_code());
    } else {
      EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
      EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
          << SpdyFramer::ErrorCodeToString(framer.error_code());
    }
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, GoawayFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message() << "Flags " << flags << std::hex
                                    << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    SpdyFramer framer(spdy_version_);
    framer.set_visitor(&visitor);

    SpdyGoAwayIR goaway_ir(97, GOAWAY_OK, "test");
    SpdySerializedFrame frame(framer.SerializeGoAway(goaway_ir));
    SetFrameFlags(&frame, flags, spdy_version_);

    EXPECT_CALL(visitor, OnGoAway(97, GOAWAY_OK));

    framer.ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
    EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
        << SpdyFramer::ErrorCodeToString(framer.error_code());
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, HeadersFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message() << "Flags " << flags << std::hex
                                    << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    SpdyFramer framer(spdy_version_);
    framer.set_visitor(&visitor);

    SpdyHeadersIR headers_ir(57);
    if (IsHttp2() && (flags & HEADERS_FLAG_PRIORITY)) {
      headers_ir.set_weight(3);
      headers_ir.set_has_priority(true);
      headers_ir.set_parent_stream_id(5);
      headers_ir.set_exclusive(true);
    }
    headers_ir.SetHeader("foo", "bar");
    SpdySerializedFrame frame(
        SpdyFramerPeer::SerializeHeaders(&framer, headers_ir));
    uint8_t set_flags = flags;
    if (IsHttp2()) {
      // TODO(jgraettinger): Add padding to SpdyHeadersIR,
      // and implement framing.
      set_flags &= ~HEADERS_FLAG_PADDED;
    }
    SetFrameFlags(&frame, set_flags, spdy_version_);

    // Expected callback values
    SpdyStreamId stream_id = 57;
    bool has_priority = false;
    SpdyPriority priority = 0;
    SpdyStreamId parent_stream_id = 0;
    bool exclusive = false;
    bool fin = flags & CONTROL_FLAG_FIN;
    bool end = IsSpdy3() || (flags & HEADERS_FLAG_END_HEADERS);
    if (IsHttp2() && flags & HEADERS_FLAG_PRIORITY) {
      has_priority = true;
      priority = 3;
      parent_stream_id = 5;
      exclusive = true;
    }
    EXPECT_CALL(visitor, OnHeaders(stream_id, has_priority, priority,
                                   parent_stream_id, exclusive, fin, end));
    EXPECT_CALL(visitor, OnHeaderFrameStart(57)).Times(1);
    if (end) {
      EXPECT_CALL(visitor, OnHeaderFrameEnd(57, _)).Times(1);
    }
    if (flags & DATA_FLAG_FIN &&
        (IsSpdy3() || flags & HEADERS_FLAG_END_HEADERS)) {
      EXPECT_CALL(visitor, OnStreamEnd(_));
    } else {
      // Do not close the stream if we are expecting a CONTINUATION frame.
      EXPECT_CALL(visitor, OnStreamEnd(_)).Times(0);
    }

    framer.ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
    EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
        << SpdyFramer::ErrorCodeToString(framer.error_code());
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, PingFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message() << "Flags " << flags << std::hex
                                    << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    SpdyFramer framer(spdy_version_);
    framer.set_visitor(&visitor);

    SpdySerializedFrame frame(framer.SerializePing(SpdyPingIR(42)));
    SetFrameFlags(&frame, flags, spdy_version_);

    if (IsHttp2() && (flags & PING_FLAG_ACK)) {
      EXPECT_CALL(visitor, OnPing(42, true));
    } else {
      EXPECT_CALL(visitor, OnPing(42, false));
    }

    framer.ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
    EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
        << SpdyFramer::ErrorCodeToString(framer.error_code());
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, WindowUpdateFrameFlags) {
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message() << "Flags " << flags << std::hex
                                    << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    SpdyFramer framer(spdy_version_);
    framer.set_visitor(&visitor);

    SpdySerializedFrame frame(
        framer.SerializeWindowUpdate(SpdyWindowUpdateIR(4, 1024)));
    SetFrameFlags(&frame, flags, spdy_version_);

    EXPECT_CALL(visitor, OnWindowUpdate(4, 1024));

    framer.ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
    EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
        << SpdyFramer::ErrorCodeToString(framer.error_code());
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, PushPromiseFrameFlags) {
  if (!IsHttp2()) {
    return;
  }

  const SpdyStreamId client_id = 123;   // Must be odd.
  const SpdyStreamId promised_id = 22;  // Must be even.
  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message() << "Flags " << flags << std::hex
                                    << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    testing::StrictMock<test::MockDebugVisitor> debug_visitor;
    SpdyFramer framer(spdy_version_);
    framer.set_visitor(&visitor);
    framer.set_debug_visitor(&debug_visitor);

    EXPECT_CALL(debug_visitor,
                OnSendCompressedFrame(client_id, PUSH_PROMISE, _, _));

    SpdyPushPromiseIR push_promise(client_id, promised_id);
    push_promise.SetHeader("foo", "bar");
    SpdySerializedFrame frame(framer.SerializePushPromise(push_promise));
    // TODO(jgraettinger): Add padding to SpdyPushPromiseIR,
    // and implement framing.
    SetFrameFlags(&frame, flags & ~HEADERS_FLAG_PADDED, spdy_version_);

    bool end = flags & PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
    EXPECT_CALL(debug_visitor,
                OnReceiveCompressedFrame(client_id, PUSH_PROMISE, _));
    EXPECT_CALL(visitor,
                OnPushPromise(client_id, promised_id,
                              flags & PUSH_PROMISE_FLAG_END_PUSH_PROMISE));
    EXPECT_CALL(visitor, OnHeaderFrameStart(client_id)).Times(1);
    if (end) {
      EXPECT_CALL(visitor, OnHeaderFrameEnd(client_id, _)).Times(1);
    }

    framer.ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
    EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
        << SpdyFramer::ErrorCodeToString(framer.error_code());
  } while (++flags != 0);
}

TEST_P(SpdyFramerTest, ContinuationFrameFlags) {
  if (!IsHttp2()) {
    return;
  }

  uint8_t flags = 0;
  do {
    SCOPED_TRACE(testing::Message() << "Flags " << flags << std::hex
                                    << static_cast<int>(flags));

    testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
    testing::StrictMock<test::MockDebugVisitor> debug_visitor;
    SpdyFramer framer(spdy_version_);
    framer.set_visitor(&visitor);
    framer.set_debug_visitor(&debug_visitor);

    EXPECT_CALL(debug_visitor, OnSendCompressedFrame(42, HEADERS, _, _));
    EXPECT_CALL(debug_visitor, OnReceiveCompressedFrame(42, HEADERS, _));
    EXPECT_CALL(visitor, OnHeaders(42, false, 0, 0, false, false, false));
    EXPECT_CALL(visitor, OnHeaderFrameStart(42)).Times(1);

    SpdyHeadersIR headers_ir(42);
    headers_ir.SetHeader("foo", "bar");
    SpdySerializedFrame frame0(
        SpdyFramerPeer::SerializeHeaders(&framer, headers_ir));
    SetFrameFlags(&frame0, 0, spdy_version_);

    SpdyContinuationIR continuation(42);
    SpdySerializedFrame frame(framer.SerializeContinuation(continuation));
    SetFrameFlags(&frame, flags, spdy_version_);

    EXPECT_CALL(debug_visitor, OnReceiveCompressedFrame(42, CONTINUATION, _));
    EXPECT_CALL(visitor, OnContinuation(42, flags & HEADERS_FLAG_END_HEADERS));
    bool end = flags & HEADERS_FLAG_END_HEADERS;
    if (end) {
      EXPECT_CALL(visitor, OnHeaderFrameEnd(42, _)).Times(1);
    }

    framer.ProcessInput(frame0.data(), frame0.size());
    framer.ProcessInput(frame.data(), frame.size());
    EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
    EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
        << SpdyFramer::ErrorCodeToString(framer.error_code());
  } while (++flags != 0);
}

// TODO(mlavan): Add TEST_P(SpdyFramerTest, AltSvcFrameFlags)

// TODO(hkhalil): Add TEST_P(SpdyFramerTest, BlockedFrameFlags)

TEST_P(SpdyFramerTest, EmptySynStream) {
  if (!IsSpdy3()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  testing::StrictMock<test::MockDebugVisitor> debug_visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);
  framer.set_debug_visitor(&debug_visitor);

  EXPECT_CALL(debug_visitor, OnSendCompressedFrame(1, SYN_STREAM, _, _));

  SpdySynStreamIR syn_stream(1);
  syn_stream.set_priority(1);
  SpdySerializedFrame frame(framer.SerializeSynStream(syn_stream));
  // Adjust size to remove the header block.
  SetFrameLength(&frame,
                 framer.GetSynStreamMinimumSize() - framer.GetFrameHeaderSize(),
                 spdy_version_);

  EXPECT_CALL(debug_visitor, OnReceiveCompressedFrame(1, SYN_STREAM, _));
  EXPECT_CALL(visitor, OnSynStream(1, 0, 1, false, false));
  EXPECT_CALL(visitor, OnHeaderFrameStart(1)).Times(1);
  EXPECT_CALL(visitor, OnHeaderFrameEnd(1, _)).Times(1);

  framer.ProcessInput(frame.data(), framer.GetSynStreamMinimumSize());
  EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
  EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

TEST_P(SpdyFramerTest, SettingsFlagsAndId) {
  const uint32_t kId = 0x020304;
  const uint32_t kFlags = 0x01;
  const uint32_t kWireFormat = base::HostToNet32(0x01020304);

  SettingsFlagsAndId id_and_flags =
      SettingsFlagsAndId::FromWireFormat(spdy_version_, kWireFormat);
  EXPECT_EQ(kId, id_and_flags.id());
  EXPECT_EQ(kFlags, id_and_flags.flags());
  EXPECT_EQ(kWireFormat, id_and_flags.GetWireFormat(spdy_version_));
}

// Test handling of a RST_STREAM with out-of-bounds status codes.
TEST_P(SpdyFramerTest, RstStreamStatusBounds) {
  const unsigned char kRstStreamStatusTooLow = 0x00;
  const unsigned char kRstStreamStatusTooHigh = 0xff;
  // clang-format off
  const unsigned char kV3RstStreamInvalid[] = {
    0x80, 0x03, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, kRstStreamStatusTooLow
  };
  // clang-format on
  const unsigned char kH2RstStreamInvalid[] = {
      0x00, 0x00, 0x04,        // Length: 4
      0x03,                    //   Type: RST_STREAM
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  //  Error: NO_ERROR
  };

  // clang-format off
  const unsigned char kV3RstStreamNumStatusCodes[] = {
    0x80, 0x03, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, kRstStreamStatusTooHigh
  };
  // clang-format on
  const unsigned char kH2RstStreamNumStatusCodes[] = {
      0x00, 0x00, 0x04,        // Length: 4
      0x03,                    //   Type: RST_STREAM
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0xff,  //  Error: 255
  };

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  if (IsSpdy3()) {
    EXPECT_CALL(visitor, OnRstStream(1, RST_STREAM_INVALID));
    framer.ProcessInput(reinterpret_cast<const char*>(kV3RstStreamInvalid),
                        arraysize(kV3RstStreamInvalid));
  } else {
    EXPECT_CALL(visitor, OnRstStream(1, RST_STREAM_INTERNAL_ERROR));
    framer.ProcessInput(reinterpret_cast<const char*>(kH2RstStreamInvalid),
                        arraysize(kH2RstStreamInvalid));
  }
  EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
  EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());

  framer.Reset();

  if (IsSpdy3()) {
    EXPECT_CALL(visitor, OnRstStream(1, RST_STREAM_INVALID));
    framer.ProcessInput(
        reinterpret_cast<const char*>(kV3RstStreamNumStatusCodes),
        arraysize(kV3RstStreamNumStatusCodes));
  } else {
    EXPECT_CALL(visitor, OnRstStream(1, RST_STREAM_INTERNAL_ERROR));
    framer.ProcessInput(
        reinterpret_cast<const char*>(kH2RstStreamNumStatusCodes),
        arraysize(kH2RstStreamNumStatusCodes));
  }
  EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
  EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Test handling of GOAWAY frames with out-of-bounds status code.
TEST_P(SpdyFramerTest, GoAwayStatusBounds) {
  SpdyFramer framer(spdy_version_);

  // clang-format off
  const unsigned char kV3FrameData[] = {
    0x80, 0x03, 0x00, 0x07,
    0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x01,  // Stream Id
    0xff, 0xff, 0xff, 0xff,  // Status
  };
  // clang-format on
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x0a,        // Length: 10
      0x07,                    //   Type: GOAWAY
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
      0x00, 0x00, 0x00, 0x01,  //   Last: 1
      0xff, 0xff, 0xff, 0xff,  //  Error: 0xffffffff
      0x47, 0x41,              // Description
  };
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  framer.set_visitor(&visitor);

  if (IsSpdy3()) {
    EXPECT_CALL(visitor, OnGoAway(1, GOAWAY_OK));
    framer.ProcessInput(reinterpret_cast<const char*>(kV3FrameData),
                        arraysize(kV3FrameData));
  } else {
    EXPECT_CALL(visitor, OnGoAway(1, GOAWAY_INTERNAL_ERROR));
    framer.ProcessInput(reinterpret_cast<const char*>(kH2FrameData),
                        arraysize(kH2FrameData));
  }
  EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
  EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Tests handling of a GOAWAY frame with out-of-bounds stream ID.
TEST_P(SpdyFramerTest, GoAwayStreamIdBounds) {
  // clang-format off
  const unsigned char kV3FrameData[] = {
    0x80, 0x03, 0x00, 0x07,
    0x00, 0x00, 0x00, 0x08,
    0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00,
  };
  // clang-format on
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x08,        // Length: 8
      0x07,                    //   Type: GOAWAY
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
      0xff, 0xff, 0xff, 0xff,  //   Last: 0x7fffffff (R-bit set)
      0x00, 0x00, 0x00, 0x00,  //  Error: NO_ERROR
  };

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  EXPECT_CALL(visitor, OnGoAway(0x7fffffff, GOAWAY_OK));
  if (IsSpdy3()) {
    framer.ProcessInput(reinterpret_cast<const char*>(kV3FrameData),
                        arraysize(kV3FrameData));
  } else {
    framer.ProcessInput(reinterpret_cast<const char*>(kH2FrameData),
                        arraysize(kH2FrameData));
  }
  EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
  EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

TEST_P(SpdyFramerTest, OnBlocked) {
  if (!IsHttp2()) {
    return;
  }

  const SpdyStreamId kStreamId = 0;

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  EXPECT_CALL(visitor, OnBlocked(kStreamId));

  SpdyBlockedIR blocked_ir(0);
  SpdySerializedFrame frame(framer.SerializeFrame(blocked_ir));
  framer.ProcessInput(frame.data(), framer.GetBlockedSize());

  EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
  EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

TEST_P(SpdyFramerTest, OnAltSvc) {
  if (!IsHttp2()) {
    return;
  }

  const SpdyStreamId kStreamId = 1;

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  SpdyAltSvcWireFormat::AlternativeService altsvc1(
      "pid1", "host", 443, 5, SpdyAltSvcWireFormat::VersionVector());
  SpdyAltSvcWireFormat::AlternativeService altsvc2(
      "p\"=i:d", "h_\\o\"st", 123, 42, SpdyAltSvcWireFormat::VersionVector{24});
  SpdyAltSvcWireFormat::AlternativeServiceVector altsvc_vector;
  altsvc_vector.push_back(altsvc1);
  altsvc_vector.push_back(altsvc2);
  EXPECT_CALL(visitor,
              OnAltSvc(kStreamId, StringPiece("o_r|g!n"), altsvc_vector));

  SpdyAltSvcIR altsvc_ir(1);
  altsvc_ir.set_origin("o_r|g!n");
  altsvc_ir.add_altsvc(altsvc1);
  altsvc_ir.add_altsvc(altsvc2);
  SpdySerializedFrame frame(framer.SerializeFrame(altsvc_ir));
  framer.ProcessInput(frame.data(), frame.size());

  EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
  EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

TEST_P(SpdyFramerTest, OnAltSvcNoOrigin) {
  if (!IsHttp2()) {
    return;
  }

  const SpdyStreamId kStreamId = 1;

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  SpdyAltSvcWireFormat::AlternativeService altsvc1(
      "pid1", "host", 443, 5, SpdyAltSvcWireFormat::VersionVector());
  SpdyAltSvcWireFormat::AlternativeService altsvc2(
      "p\"=i:d", "h_\\o\"st", 123, 42, SpdyAltSvcWireFormat::VersionVector{24});
  SpdyAltSvcWireFormat::AlternativeServiceVector altsvc_vector;
  altsvc_vector.push_back(altsvc1);
  altsvc_vector.push_back(altsvc2);
  EXPECT_CALL(visitor, OnAltSvc(kStreamId, StringPiece(""), altsvc_vector));

  SpdyAltSvcIR altsvc_ir(1);
  altsvc_ir.add_altsvc(altsvc1);
  altsvc_ir.add_altsvc(altsvc2);
  SpdySerializedFrame frame(framer.SerializeFrame(altsvc_ir));
  framer.ProcessInput(frame.data(), frame.size());

  EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
  EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

TEST_P(SpdyFramerTest, OnAltSvcEmptyProtocolId) {
  if (!IsHttp2()) {
    return;
  }

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  EXPECT_CALL(visitor, OnError(testing::Eq(&framer)));

  SpdyAltSvcIR altsvc_ir(1);
  altsvc_ir.set_origin("o1");
  altsvc_ir.add_altsvc(SpdyAltSvcWireFormat::AlternativeService(
      "pid1", "host", 443, 5, SpdyAltSvcWireFormat::VersionVector()));
  altsvc_ir.add_altsvc(SpdyAltSvcWireFormat::AlternativeService(
      "", "h1", 443, 10, SpdyAltSvcWireFormat::VersionVector()));
  SpdySerializedFrame frame(framer.SerializeFrame(altsvc_ir));
  framer.ProcessInput(frame.data(), frame.size());

  EXPECT_EQ(SpdyFramer::SPDY_ERROR, framer.state());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_CONTROL_FRAME, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

TEST_P(SpdyFramerTest, OnAltSvcBadLengths) {
  if (!IsHttp2()) {
    return;
  }

  const SpdyStreamId kStreamId = 1;

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  SpdyFramer framer(spdy_version_);
  framer.set_visitor(&visitor);

  SpdyAltSvcWireFormat::AlternativeService altsvc(
      "pid", "h1", 443, 10, SpdyAltSvcWireFormat::VersionVector());
  SpdyAltSvcWireFormat::AlternativeServiceVector altsvc_vector;
  altsvc_vector.push_back(altsvc);
  EXPECT_CALL(visitor, OnAltSvc(kStreamId, StringPiece("o1"), altsvc_vector));

  SpdyAltSvcIR altsvc_ir(1);
  altsvc_ir.set_origin("o1");
  altsvc_ir.add_altsvc(altsvc);
  SpdySerializedFrame frame(framer.SerializeFrame(altsvc_ir));
  framer.ProcessInput(frame.data(), frame.size());

  EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
  EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
}

// Tests handling of ALTSVC frames delivered in small chunks.
TEST_P(SpdyFramerTest, ReadChunkedAltSvcFrame) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  SpdyAltSvcIR altsvc_ir(1);
  SpdyAltSvcWireFormat::AlternativeService altsvc1(
      "pid1", "host", 443, 5, SpdyAltSvcWireFormat::VersionVector());
  SpdyAltSvcWireFormat::AlternativeService altsvc2(
      "p\"=i:d", "h_\\o\"st", 123, 42, SpdyAltSvcWireFormat::VersionVector{24});
  altsvc_ir.add_altsvc(altsvc1);
  altsvc_ir.add_altsvc(altsvc2);

  SpdySerializedFrame control_frame(framer.SerializeAltSvc(altsvc_ir));
  TestSpdyVisitor visitor(spdy_version_);
  visitor.use_compression_ = false;

  // Read data in small chunks.
  size_t framed_data = 0;
  size_t unframed_data = control_frame.size();
  size_t kReadChunkSize = 5;  // Read five bytes at a time.
  while (unframed_data > 0) {
    size_t to_read = std::min(kReadChunkSize, unframed_data);
    visitor.SimulateInFramer(
        reinterpret_cast<unsigned char*>(control_frame.data() + framed_data),
        to_read);
    unframed_data -= to_read;
    framed_data += to_read;
  }
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.altsvc_count_);
  ASSERT_EQ(2u, visitor.test_altsvc_ir_.altsvc_vector().size());
  EXPECT_TRUE(visitor.test_altsvc_ir_.altsvc_vector()[0] == altsvc1);
  EXPECT_TRUE(visitor.test_altsvc_ir_.altsvc_vector()[1] == altsvc2);
}

// Tests handling of PRIORITY frames.
TEST_P(SpdyFramerTest, ReadPriority) {
  if (!IsHttp2()) {
    return;
  }

  SpdyFramer framer(spdy_version_);
  SpdyPriorityIR priority(3, 1, 256, false);
  SpdySerializedFrame frame(framer.SerializePriority(priority));
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  framer.set_visitor(&visitor);
  EXPECT_CALL(visitor, OnPriority(3, 1, 256, false));
  framer.ProcessInput(frame.data(), frame.size());

  EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
  EXPECT_EQ(SpdyFramer::SPDY_NO_ERROR, framer.error_code())
      << SpdyFramer::ErrorCodeToString(framer.error_code());
  // TODO(mlavan): once we actually maintain a priority tree,
  // check that state is adjusted correctly.
}

// Tests handling of PRIORITY frame with incorrect size.
TEST_P(SpdyFramerTest, ReadIncorrectlySizedPriority) {
  if (!IsHttp2()) {
    return;
  }

  // PRIORITY frame of size 4, which isn't correct.
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x04,        // Length: 4
      0x02,                    //   Type: PRIORITY
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x03,  // Stream: 3
      0x00, 0x00, 0x00, 0x01,  // Priority (Truncated)
  };

  TestSpdyVisitor visitor(spdy_version_);
  visitor.SimulateInFramer(kFrameData, sizeof(kFrameData));

  EXPECT_EQ(SpdyFramer::SPDY_ERROR, visitor.framer_.state());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_CONTROL_FRAME_SIZE,
            visitor.framer_.error_code())
      << SpdyFramer::ErrorCodeToString(visitor.framer_.error_code());
}

// Tests handling of PING frame with incorrect size.
TEST_P(SpdyFramerTest, ReadIncorrectlySizedPing) {
  if (!IsHttp2()) {
    return;
  }

  // PING frame of size 4, which isn't correct.
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x04,        // Length: 4
      0x06,                    //   Type: PING
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
      0x00, 0x00, 0x00, 0x01,  // Ping (Truncated)
  };

  TestSpdyVisitor visitor(spdy_version_);
  visitor.SimulateInFramer(kFrameData, sizeof(kFrameData));

  EXPECT_EQ(SpdyFramer::SPDY_ERROR, visitor.framer_.state());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_CONTROL_FRAME_SIZE,
            visitor.framer_.error_code())
      << SpdyFramer::ErrorCodeToString(visitor.framer_.error_code());
}

// Tests handling of WINDOW_UPDATE frame with incorrect size.
TEST_P(SpdyFramerTest, ReadIncorrectlySizedWindowUpdate) {
  if (!IsHttp2()) {
    return;
  }

  // WINDOW_UPDATE frame of size 3, which isn't correct.
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x03,        // Length: 3
      0x08,                    //   Type: WINDOW_UPDATE
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x03,  // Stream: 3
      0x00, 0x00, 0x01,        // WindowUpdate (Truncated)
  };

  TestSpdyVisitor visitor(spdy_version_);
  visitor.SimulateInFramer(kFrameData, sizeof(kFrameData));

  EXPECT_EQ(SpdyFramer::SPDY_ERROR, visitor.framer_.state());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_CONTROL_FRAME_SIZE,
            visitor.framer_.error_code())
      << SpdyFramer::ErrorCodeToString(visitor.framer_.error_code());
}

// Tests handling of RST_STREAM frame with incorrect size.
TEST_P(SpdyFramerTest, ReadIncorrectlySizedRstStream) {
  if (!IsHttp2()) {
    return;
  }

  // RST_STREAM frame of size 3, which isn't correct.
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x03,        // Length: 3
      0x03,                    //   Type: RST_STREAM
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x03,  // Stream: 3
      0x00, 0x00, 0x01,        // RstStream (Truncated)
  };

  TestSpdyVisitor visitor(spdy_version_);
  visitor.SimulateInFramer(kFrameData, sizeof(kFrameData));

  EXPECT_EQ(SpdyFramer::SPDY_ERROR, visitor.framer_.state());
  EXPECT_EQ(SpdyFramer::SPDY_INVALID_CONTROL_FRAME_SIZE,
            visitor.framer_.error_code())
      << SpdyFramer::ErrorCodeToString(visitor.framer_.error_code());
}

// Test that SpdyFramer processes, by default, all passed input in one call
// to ProcessInput (i.e. will not be calling set_process_single_input_frame()).
TEST_P(SpdyFramerTest, ProcessAllInput) {
  SpdyFramer framer(spdy_version_);
  std::unique_ptr<TestSpdyVisitor> visitor(new TestSpdyVisitor(spdy_version_));
  framer.set_visitor(visitor.get());

  // Create two input frames.
  SpdyHeadersIR headers(1);
  headers.SetHeader("alpha", "beta");
  headers.SetHeader("gamma", "charlie");
  headers.SetHeader("cookie", "key1=value1; key2=value2");
  SpdySerializedFrame headers_frame(
      SpdyFramerPeer::SerializeHeaders(&framer, headers));

  const char four_score[] = "Four score and seven years ago";
  SpdyDataIR four_score_ir(1, four_score);
  SpdySerializedFrame four_score_frame(framer.SerializeData(four_score_ir));

  // Put them in a single buffer (new variables here to make it easy to
  // change the order and type of frames).
  SpdySerializedFrame frame1 = std::move(headers_frame);
  SpdySerializedFrame frame2 = std::move(four_score_frame);

  const size_t frame1_size = frame1.size();
  const size_t frame2_size = frame2.size();

  VLOG(1) << "frame1_size = " << frame1_size;
  VLOG(1) << "frame2_size = " << frame2_size;

  string input_buffer;
  input_buffer.append(frame1.data(), frame1_size);
  input_buffer.append(frame2.data(), frame2_size);

  const char* buf = input_buffer.data();
  const size_t buf_size = input_buffer.size();

  VLOG(1) << "buf_size = " << buf_size;

  size_t processed = framer.ProcessInput(buf, buf_size);
  EXPECT_EQ(buf_size, processed);
  EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
  EXPECT_EQ(1, visitor->headers_frame_count_);
  EXPECT_EQ(1, visitor->data_frame_count_);
  EXPECT_EQ(strlen(four_score), static_cast<unsigned>(visitor->data_bytes_));
}

// Test that SpdyFramer stops after processing a full frame if
// process_single_input_frame is set. Input to ProcessInput has two frames, but
// only processes the first when we give it the first frame split at any point,
// or give it more than one frame in the input buffer.
TEST_P(SpdyFramerTest, ProcessAtMostOneFrame) {
  SpdyFramer framer(spdy_version_);
  framer.set_process_single_input_frame(true);
  std::unique_ptr<TestSpdyVisitor> visitor;

  // Create two input frames.
  const char four_score[] = "Four score and ...";
  SpdyDataIR four_score_ir(1, four_score);
  SpdySerializedFrame four_score_frame(framer.SerializeData(four_score_ir));

  SpdyHeadersIR headers(2);
  headers.SetHeader("alpha", "beta");
  headers.SetHeader("gamma", "charlie");
  headers.SetHeader("cookie", "key1=value1; key2=value2");
  SpdySerializedFrame headers_frame(
      SpdyFramerPeer::SerializeHeaders(&framer, headers));

  // Put them in a single buffer (new variables here to make it easy to
  // change the order and type of frames).
  SpdySerializedFrame frame1 = std::move(four_score_frame);
  SpdySerializedFrame frame2 = std::move(headers_frame);

  const size_t frame1_size = frame1.size();
  const size_t frame2_size = frame2.size();

  VLOG(1) << "frame1_size = " << frame1_size;
  VLOG(1) << "frame2_size = " << frame2_size;

  string input_buffer;
  input_buffer.append(frame1.data(), frame1_size);
  input_buffer.append(frame2.data(), frame2_size);

  const char* buf = input_buffer.data();
  const size_t buf_size = input_buffer.size();

  VLOG(1) << "buf_size = " << buf_size;

  for (size_t first_size = 0; first_size <= buf_size; ++first_size) {
    VLOG(1) << "first_size = " << first_size;
    visitor.reset(new TestSpdyVisitor(spdy_version_));
    framer.set_visitor(visitor.get());

    EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());

    size_t processed_first = framer.ProcessInput(buf, first_size);
    if (first_size < frame1_size) {
      EXPECT_EQ(first_size, processed_first);

      if (first_size == 0) {
        EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
      } else {
        EXPECT_NE(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());
      }

      const char* rest = buf + processed_first;
      const size_t remaining = buf_size - processed_first;
      VLOG(1) << "remaining = " << remaining;

      size_t processed_second = framer.ProcessInput(rest, remaining);

      // Redundant tests just to make it easier to think about.
      EXPECT_EQ(frame1_size - processed_first, processed_second);
      size_t processed_total = processed_first + processed_second;
      EXPECT_EQ(frame1_size, processed_total);
    } else {
      EXPECT_EQ(frame1_size, processed_first);
    }

    EXPECT_EQ(SpdyFramer::SPDY_READY_FOR_FRAME, framer.state());

    // At this point should have processed the entirety of the first frame,
    // and none of the second frame.

    EXPECT_EQ(1, visitor->data_frame_count_);
    EXPECT_EQ(strlen(four_score), static_cast<unsigned>(visitor->data_bytes_));
    EXPECT_EQ(0, visitor->headers_frame_count_);
  }
}

}  // namespace test

}  // namespace net
