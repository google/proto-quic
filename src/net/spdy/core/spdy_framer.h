// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_CORE_SPDY_FRAMER_H_
#define NET_SPDY_CORE_SPDY_FRAMER_H_

#include <stddef.h>

#include <cstdint>
#include <map>
#include <memory>
#include <utility>

#include "base/sys_byteorder.h"
#include "net/spdy/chromium/spdy_flags.h"
#include "net/spdy/core/hpack/hpack_decoder_interface.h"
#include "net/spdy/core/hpack/hpack_encoder.h"
#include "net/spdy/core/spdy_alt_svc_wire_format.h"
#include "net/spdy/core/spdy_header_block.h"
#include "net/spdy/core/spdy_headers_handler_interface.h"
#include "net/spdy/core/spdy_protocol.h"
#include "net/spdy/core/zero_copy_output_buffer.h"
#include "net/spdy/platform/api/spdy_export.h"
#include "net/spdy/platform/api/spdy_string.h"
#include "net/spdy/platform/api/spdy_string_piece.h"

namespace net {

class HttpProxyClientSocketPoolTest;
class HttpNetworkLayer;
class HttpNetworkTransactionTest;
class SpdyHttpStreamTest;
class SpdyNetworkTransactionTest;
class SpdyProxyClientSocketTest;
class SpdySessionTest;
class SpdyStreamTest;

class SpdyFramer;
class SpdyFrameBuilder;
class SpdyFramerDecoderAdapter;

namespace test {

class TestSpdyVisitor;
class SpdyFramerPeer;
class SpdyFramerTest_MultipleContinuationFramesWithIterator_Test;
class SpdyFramerTest_PushPromiseFramesWithIterator_Test;

}  // namespace test

// SpdyFramerVisitorInterface is a set of callbacks for the SpdyFramer.
// Implement this interface to receive event callbacks as frames are
// decoded from the framer.
//
// Control frames that contain HTTP2 header blocks (HEADER, and PUSH_PROMISE)
// are processed in fashion that allows the decompressed header block to be
// delivered in chunks to the visitor.
// The following steps are followed:
//   1. OnHeaders, or OnPushPromise is called.
//   2. OnHeaderFrameStart is called; visitor is expected to return an instance
//      of SpdyHeadersHandlerInterface that will receive the header key-value
//      pairs.
//   3. OnHeaderFrameEnd is called, indicating that the full header block has
//      been delivered for the control frame.
// During step 2, if the visitor is not interested in accepting the header data,
// it should return a no-op implementation of SpdyHeadersHandlerInterface.
class SPDY_EXPORT_PRIVATE SpdyFramerVisitorInterface {
 public:
  virtual ~SpdyFramerVisitorInterface() {}

  // Called if an error is detected in the SpdySerializedFrame protocol.
  virtual void OnError(SpdyFramer* framer) = 0;

  // Called when the common header for a frame is received. Validating the
  // common header occurs in later processing.
  virtual void OnCommonHeader(SpdyStreamId stream_id,
                              size_t length,
                              uint8_t type,
                              uint8_t flags) {}

  // Called when a data frame header is received. The frame's data
  // payload will be provided via subsequent calls to
  // OnStreamFrameData().
  virtual void OnDataFrameHeader(SpdyStreamId stream_id,
                                 size_t length,
                                 bool fin) = 0;

  // Called when data is received.
  // |stream_id| The stream receiving data.
  // |data| A buffer containing the data received.
  // |len| The length of the data buffer.
  virtual void OnStreamFrameData(SpdyStreamId stream_id,
                                 const char* data,
                                 size_t len) = 0;

  // Called when the other side has finished sending data on this stream.
  // |stream_id| The stream that was receivin data.
  virtual void OnStreamEnd(SpdyStreamId stream_id) = 0;

  // Called when padding is received (padding length field or padding octets).
  // |stream_id| The stream receiving data.
  // |len| The number of padding octets.
  virtual void OnStreamPadding(SpdyStreamId stream_id, size_t len) = 0;

  // Called just before processing the payload of a frame containing header
  // data. Should return an implementation of SpdyHeadersHandlerInterface that
  // will receive headers for stream |stream_id|. The caller will not take
  // ownership of the headers handler. The same instance should remain live
  // and be returned for all header frames comprising a logical header block
  // (i.e. until OnHeaderFrameEnd() is called with end_headers == true).
  virtual SpdyHeadersHandlerInterface* OnHeaderFrameStart(
      SpdyStreamId stream_id) = 0;

  // Called after processing the payload of a frame containing header data.
  // |end_headers| is true if there will not be any subsequent CONTINUATION
  // frames.
  virtual void OnHeaderFrameEnd(SpdyStreamId stream_id, bool end_headers) = 0;

  // Called when a RST_STREAM frame has been parsed.
  virtual void OnRstStream(SpdyStreamId stream_id,
                           SpdyErrorCode error_code) = 0;

  // Called when a SETTINGS frame is received.
  // |clear_persisted| True if the respective flag is set on the SETTINGS frame.
  virtual void OnSettings(bool clear_persisted) {}

  // Called when a complete setting within a SETTINGS frame has been parsed and
  // validated.
  virtual void OnSetting(SpdySettingsIds id, uint32_t value) = 0;

  // Called when a SETTINGS frame is received with the ACK flag set.
  virtual void OnSettingsAck() {}

  // Called before and after parsing SETTINGS id and value tuples.
  virtual void OnSettingsEnd() = 0;

  // Called when a PING frame has been parsed.
  virtual void OnPing(SpdyPingId unique_id, bool is_ack) = 0;

  // Called when a GOAWAY frame has been parsed.
  virtual void OnGoAway(SpdyStreamId last_accepted_stream_id,
                        SpdyErrorCode error_code) = 0;

  // Called when a HEADERS frame is received.
  // Note that header block data is not included. See OnHeaderFrameStart().
  // |stream_id| The stream receiving the header.
  // |has_priority| Whether or not the headers frame included a priority value,
  //     and stream dependency info.
  // |weight| If |has_priority| is true, then weight (in the range [1, 256])
  //     for the receiving stream, otherwise 0.
  // |parent_stream_id| If |has_priority| is true the parent stream of the
  //     receiving stream, else 0.
  // |exclusive| If |has_priority| is true the exclusivity of dependence on the
  //     parent stream, else false.
  // |fin| Whether FIN flag is set in frame headers.
  // |end| False if HEADERs frame is to be followed by a CONTINUATION frame,
  //     or true if not.
  virtual void OnHeaders(SpdyStreamId stream_id,
                         bool has_priority,
                         int weight,
                         SpdyStreamId parent_stream_id,
                         bool exclusive,
                         bool fin,
                         bool end) = 0;

  // Called when a WINDOW_UPDATE frame has been parsed.
  virtual void OnWindowUpdate(SpdyStreamId stream_id,
                              int delta_window_size) = 0;

  // Called when a goaway frame opaque data is available.
  // |goaway_data| A buffer containing the opaque GOAWAY data chunk received.
  // |len| The length of the header data buffer. A length of zero indicates
  //       that the header data block has been completely sent.
  // When this function returns true the visitor indicates that it accepted
  // all of the data. Returning false indicates that that an error has
  // occurred while processing the data. Default implementation returns true.
  virtual bool OnGoAwayFrameData(const char* goaway_data, size_t len);

  // Called when a PUSH_PROMISE frame is received.
  // Note that header block data is not included. See OnHeaderFrameStart().
  virtual void OnPushPromise(SpdyStreamId stream_id,
                             SpdyStreamId promised_stream_id,
                             bool end) = 0;

  // Called when a CONTINUATION frame is received.
  // Note that header block data is not included. See OnHeaderFrameStart().
  virtual void OnContinuation(SpdyStreamId stream_id, bool end) = 0;

  // Called when an ALTSVC frame has been parsed.
  virtual void OnAltSvc(
      SpdyStreamId stream_id,
      SpdyStringPiece origin,
      const SpdyAltSvcWireFormat::AlternativeServiceVector& altsvc_vector) {}

  // Called when a PRIORITY frame is received.
  // |stream_id| The stream to update the priority of.
  // |parent_stream_id| The parent stream of |stream_id|.
  // |weight| Stream weight, in the range [1, 256].
  // |exclusive| Whether |stream_id| should be an only child of
  //     |parent_stream_id|.
  virtual void OnPriority(SpdyStreamId stream_id,
                          SpdyStreamId parent_stream_id,
                          int weight,
                          bool exclusive) {}

  // Called when a frame type we don't recognize is received.
  // Return true if this appears to be a valid extension frame, false otherwise.
  // We distinguish between extension frames and nonsense by checking
  // whether the stream id is valid.
  virtual bool OnUnknownFrame(SpdyStreamId stream_id, uint8_t frame_type) = 0;
};

class SPDY_EXPORT_PRIVATE SpdyFrameSequence {
 public:
  virtual ~SpdyFrameSequence() {}

  // Serializes the next frame in the sequence to |output|. Returns the number
  // of bytes written to |output|.
  virtual size_t NextFrame(ZeroCopyOutputBuffer* output) = 0;

  // Returns true iff there is at least one more frame in the sequence.
  virtual bool HasNextFrame() const = 0;

  // Get SpdyFrameIR of the frame to be serialized.
  // TODO(yasong): return const SpdyFrameIR& instead.
  virtual const SpdyFrameIR* GetIR() const = 0;
};

class ExtensionVisitorInterface {
 public:
  virtual ~ExtensionVisitorInterface() {}

  // Called when non-standard SETTINGS are received.
  virtual void OnSetting(uint16_t id, uint32_t value) = 0;

  // Called when non-standard frames are received.
  virtual bool OnFrameHeader(SpdyStreamId stream_id,
                             size_t length,
                             uint8_t type,
                             uint8_t flags) = 0;

  // The payload for a single frame may be delivered as multiple calls to
  // OnFramePayload. Since the length field is passed in OnFrameHeader, there is
  // no explicit indication of the end of the frame payload.
  virtual void OnFramePayload(const char* data, size_t len) = 0;
};

// Optionally, and in addition to SpdyFramerVisitorInterface, a class supporting
// SpdyFramerDebugVisitorInterface may be used in conjunction with SpdyFramer in
// order to extract debug/internal information about the SpdyFramer as it
// operates.
//
// Most HTTP2 implementations need not bother with this interface at all.
class SPDY_EXPORT_PRIVATE SpdyFramerDebugVisitorInterface {
 public:
  virtual ~SpdyFramerDebugVisitorInterface() {}

  // Called after compressing a frame with a payload of
  // a list of name-value pairs.
  // |payload_len| is the uncompressed payload size.
  // |frame_len| is the compressed frame size.
  virtual void OnSendCompressedFrame(SpdyStreamId stream_id,
                                     SpdyFrameType type,
                                     size_t payload_len,
                                     size_t frame_len) {}

  // Called when a frame containing a compressed payload of
  // name-value pairs is received.
  // |frame_len| is the compressed frame size.
  virtual void OnReceiveCompressedFrame(SpdyStreamId stream_id,
                                        SpdyFrameType type,
                                        size_t frame_len) {}
};

class SPDY_EXPORT_PRIVATE SpdyFramer {
 public:
  // HTTP2 states.
  enum SpdyState {
    SPDY_ERROR,
    SPDY_READY_FOR_FRAME,  // Framer is ready for reading the next frame.
    SPDY_FRAME_COMPLETE,  // Framer has finished reading a frame, need to reset.
    SPDY_READING_COMMON_HEADER,
    SPDY_CONTROL_FRAME_PAYLOAD,
    SPDY_READ_DATA_FRAME_PADDING_LENGTH,
    SPDY_CONSUME_PADDING,
    SPDY_IGNORE_REMAINING_PAYLOAD,
    SPDY_FORWARD_STREAM_FRAME,
    SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK,
    SPDY_CONTROL_FRAME_HEADER_BLOCK,
    SPDY_GOAWAY_FRAME_PAYLOAD,
    SPDY_SETTINGS_FRAME_HEADER,
    SPDY_SETTINGS_FRAME_PAYLOAD,
    SPDY_ALTSVC_FRAME_PAYLOAD,
    SPDY_EXTENSION_FRAME_PAYLOAD,
  };

  // Framer error codes.
  enum SpdyFramerError {
    SPDY_NO_ERROR,
    SPDY_INVALID_STREAM_ID,            // Stream ID is invalid
    SPDY_INVALID_CONTROL_FRAME,        // Control frame is mal-formatted.
    SPDY_CONTROL_PAYLOAD_TOO_LARGE,    // Control frame payload was too large.
    SPDY_ZLIB_INIT_FAILURE,            // The Zlib library could not initialize.
    SPDY_UNSUPPORTED_VERSION,          // Control frame has unsupported version.
    SPDY_DECOMPRESS_FAILURE,           // There was an error decompressing.
    SPDY_COMPRESS_FAILURE,             // There was an error compressing.
    SPDY_GOAWAY_FRAME_CORRUPT,         // GOAWAY frame could not be parsed.
    SPDY_RST_STREAM_FRAME_CORRUPT,     // RST_STREAM frame could not be parsed.
    SPDY_INVALID_PADDING,              // HEADERS or DATA frame padding invalid
    SPDY_INVALID_DATA_FRAME_FLAGS,     // Data frame has invalid flags.
    SPDY_INVALID_CONTROL_FRAME_FLAGS,  // Control frame has invalid flags.
    SPDY_UNEXPECTED_FRAME,             // Frame received out of order.
    SPDY_INTERNAL_FRAMER_ERROR,        // SpdyFramer was used incorrectly.
    SPDY_INVALID_CONTROL_FRAME_SIZE,   // Control frame not sized to spec
    SPDY_OVERSIZED_PAYLOAD,            // Payload size was too large

    LAST_ERROR,  // Must be the last entry in the enum.
  };

  enum CompressionOption {
    ENABLE_COMPRESSION,
    DISABLE_COMPRESSION,
  };

  // Typedef for a function used to create SpdyFramerDecoderAdapter's.
  // Defined in support of evaluating an alternate HTTP/2 decoder.
  typedef std::unique_ptr<SpdyFramerDecoderAdapter> (*DecoderAdapterFactoryFn)(
      SpdyFramer* outer);

  // Constant for invalid (or unknown) stream IDs.
  static const SpdyStreamId kInvalidStream;

  // The maximum size of header data decompressed/delivered at once to the
  // header block parser. (Exposed here for unit test purposes.)
  static const size_t kHeaderDataChunkMaxSize;

  void SerializeHeaderBlockWithoutCompression(
      SpdyFrameBuilder* builder,
      const SpdyHeaderBlock& header_block) const;

  // Retrieve serialized length of SpdyHeaderBlock.
  static size_t GetSerializedLength(const SpdyHeaderBlock* headers);

  // Gets the serialized flags for the given |frame|.
  static uint8_t GetSerializedFlags(const SpdyFrameIR& frame);

  explicit SpdyFramer(CompressionOption option);

  // Used recursively from the above constructor in order to support
  // instantiating a SpdyFramerDecoderAdapter selected via flags or some other
  // means.
  SpdyFramer(DecoderAdapterFactoryFn adapter_factory, CompressionOption option);

  virtual ~SpdyFramer();

  // Set callbacks to be called from the framer.  A visitor must be set, or
  // else the framer will likely crash.  It is acceptable for the visitor
  // to do nothing.  If this is called multiple times, only the last visitor
  // will be used.
  void set_visitor(SpdyFramerVisitorInterface* visitor);

  // Set extension callbacks to be called from the framer. (Optional.)
  void set_extension_visitor(ExtensionVisitorInterface* extension);

  // Set debug callbacks to be called from the framer. The debug visitor is
  // completely optional and need not be set in order for normal operation.
  // If this is called multiple times, only the last visitor will be used.
  void set_debug_visitor(SpdyFramerDebugVisitorInterface* debug_visitor);

  // Sets whether or not ProcessInput returns after finishing a frame, or
  // continues processing additional frames. Normally ProcessInput processes
  // all input, but this method enables the caller (and visitor) to work with
  // a single frame at a time (or that portion of the frame which is provided
  // as input). Reset() does not change the value of this flag.
  void set_process_single_input_frame(bool v);

  // Pass data into the framer for parsing.
  // Returns the number of bytes consumed. It is safe to pass more bytes in
  // than may be consumed.
  size_t ProcessInput(const char* data, size_t len);

  // Resets the framer state after a frame has been successfully decoded.
  // TODO(mbelshe): can we make this private?
  void Reset();

  // Check the state of the framer.
  SpdyFramerError spdy_framer_error() const;
  SpdyState state() const;
  bool HasError() const { return state() == SPDY_ERROR; }

  // Create a SpdyFrameSequence to serialize |frame_ir|.
  static std::unique_ptr<SpdyFrameSequence> CreateIterator(
      SpdyFramer* framer,
      std::unique_ptr<const SpdyFrameIR> frame_ir);

  // Serialize a data frame.
  SpdySerializedFrame SerializeData(const SpdyDataIR& data) const;
  // Serializes the data frame header and optionally padding length fields,
  // excluding actual data payload and padding.
  SpdySerializedFrame SerializeDataFrameHeaderWithPaddingLengthField(
      const SpdyDataIR& data) const;

  SpdySerializedFrame SerializeRstStream(
      const SpdyRstStreamIR& rst_stream) const;

  // Serializes a SETTINGS frame. The SETTINGS frame is
  // used to communicate name/value pairs relevant to the communication channel.
  SpdySerializedFrame SerializeSettings(const SpdySettingsIR& settings) const;

  // Serializes a PING frame. The unique_id is used to
  // identify the ping request/response.
  SpdySerializedFrame SerializePing(const SpdyPingIR& ping) const;

  // Serializes a GOAWAY frame. The GOAWAY frame is used
  // prior to the shutting down of the TCP connection, and includes the
  // stream_id of the last stream the sender of the frame is willing to process
  // to completion.
  SpdySerializedFrame SerializeGoAway(const SpdyGoAwayIR& goaway) const;

  // Serializes a HEADERS frame. The HEADERS frame is used
  // for sending headers.
  SpdySerializedFrame SerializeHeaders(const SpdyHeadersIR& headers);

  // Serializes a WINDOW_UPDATE frame. The WINDOW_UPDATE
  // frame is used to implement per stream flow control.
  SpdySerializedFrame SerializeWindowUpdate(
      const SpdyWindowUpdateIR& window_update) const;

  // Serializes a PUSH_PROMISE frame. The PUSH_PROMISE frame is used
  // to inform the client that it will be receiving an additional stream
  // in response to the original request. The frame includes synthesized
  // headers to explain the upcoming data.
  SpdySerializedFrame SerializePushPromise(
      const SpdyPushPromiseIR& push_promise);

  // Serializes a CONTINUATION frame. The CONTINUATION frame is used
  // to continue a sequence of header block fragments.
  SpdySerializedFrame SerializeContinuation(
      const SpdyContinuationIR& continuation) const;

  // Serializes an ALTSVC frame. The ALTSVC frame advertises the
  // availability of an alternative service to the client.
  SpdySerializedFrame SerializeAltSvc(const SpdyAltSvcIR& altsvc);

  // Serializes a PRIORITY frame. The PRIORITY frame advises a change in
  // the relative priority of the given stream.
  SpdySerializedFrame SerializePriority(const SpdyPriorityIR& priority) const;

  // Serialize a frame of unknown type.
  SpdySerializedFrame SerializeFrame(const SpdyFrameIR& frame);

  // Serialize a data frame.
  bool SerializeData(const SpdyDataIR& data,
                     ZeroCopyOutputBuffer* output) const;

  // Serializes the data frame header and optionally padding length fields,
  // excluding actual data payload and padding.
  bool SerializeDataFrameHeaderWithPaddingLengthField(
      const SpdyDataIR& data,
      ZeroCopyOutputBuffer* output) const;

  bool SerializeRstStream(const SpdyRstStreamIR& rst_stream,
                          ZeroCopyOutputBuffer* output) const;

  // Serializes a SETTINGS frame. The SETTINGS frame is
  // used to communicate name/value pairs relevant to the communication channel.
  bool SerializeSettings(const SpdySettingsIR& settings,
                         ZeroCopyOutputBuffer* output) const;

  // Serializes a PING frame. The unique_id is used to
  // identify the ping request/response.
  bool SerializePing(const SpdyPingIR& ping,
                     ZeroCopyOutputBuffer* output) const;

  // Serializes a GOAWAY frame. The GOAWAY frame is used
  // prior to the shutting down of the TCP connection, and includes the
  // stream_id of the last stream the sender of the frame is willing to process
  // to completion.
  bool SerializeGoAway(const SpdyGoAwayIR& goaway,
                       ZeroCopyOutputBuffer* output) const;

  // Serializes a HEADERS frame. The HEADERS frame is used
  // for sending headers.
  bool SerializeHeaders(const SpdyHeadersIR& headers,
                        ZeroCopyOutputBuffer* output);

  // Serializes a WINDOW_UPDATE frame. The WINDOW_UPDATE
  // frame is used to implement per stream flow control.
  bool SerializeWindowUpdate(const SpdyWindowUpdateIR& window_update,
                             ZeroCopyOutputBuffer* output) const;

  // Serializes a PUSH_PROMISE frame. The PUSH_PROMISE frame is used
  // to inform the client that it will be receiving an additional stream
  // in response to the original request. The frame includes synthesized
  // headers to explain the upcoming data.
  bool SerializePushPromise(const SpdyPushPromiseIR& push_promise,
                            ZeroCopyOutputBuffer* output);

  // Serializes a CONTINUATION frame. The CONTINUATION frame is used
  // to continue a sequence of header block fragments.
  bool SerializeContinuation(const SpdyContinuationIR& continuation,
                             ZeroCopyOutputBuffer* output) const;

  // Serializes an ALTSVC frame. The ALTSVC frame advertises the
  // availability of an alternative service to the client.
  bool SerializeAltSvc(const SpdyAltSvcIR& altsvc,
                       ZeroCopyOutputBuffer* output);

  // Serializes a PRIORITY frame. The PRIORITY frame advises a change in
  // the relative priority of the given stream.
  bool SerializePriority(const SpdyPriorityIR& priority,
                         ZeroCopyOutputBuffer* output) const;

  // Serialize a frame of unknown type.
  size_t SerializeFrame(const SpdyFrameIR& frame, ZeroCopyOutputBuffer* output);

  // Returns whether this SpdyFramer will compress header blocks using HPACK.
  bool compression_enabled() const {
    return compression_option_ == ENABLE_COMPRESSION;
  }

  void SetHpackIndexingPolicy(HpackEncoder::IndexingPolicy policy) {
    GetHpackEncoder()->SetIndexingPolicy(std::move(policy));
  }

  // Returns the (minimum) size of frames (sans variable-length portions).
  size_t GetDataFrameMinimumSize() const;
  size_t GetFrameHeaderSize() const;
  size_t GetRstStreamSize() const;
  size_t GetSettingsMinimumSize() const;
  size_t GetPingSize() const;
  size_t GetGoAwayMinimumSize() const;
  size_t GetHeadersMinimumSize() const;
  size_t GetWindowUpdateSize() const;
  size_t GetPushPromiseMinimumSize() const;
  size_t GetContinuationMinimumSize() const;
  size_t GetAltSvcMinimumSize() const;
  size_t GetPrioritySize() const;

  // Returns the minimum size a frame can be (data or control).
  size_t GetFrameMinimumSize() const;

  // Returns the maximum size a frame can be (data or control).
  size_t GetFrameMaximumSize() const;

  // Returns the maximum payload size of a DATA frame.
  size_t GetDataFrameMaximumPayload() const;

  // For debugging.
  static const char* StateToString(int state);
  static const char* SpdyFramerErrorToString(SpdyFramerError spdy_framer_error);

  // Did the most recent frame header appear to be an HTTP/1.x (or earlier)
  // response (i.e. start with "HTTP/")?
  bool probable_http_response() const;

  SpdyPriority GetLowestPriority() const { return kV3LowestPriority; }

  SpdyPriority GetHighestPriority() const { return kV3HighestPriority; }

  // Updates the maximum size of the header encoder compression table.
  void UpdateHeaderEncoderTableSize(uint32_t value);

  // Updates the maximum size of the header decoder compression table.
  void UpdateHeaderDecoderTableSize(uint32_t value);

  // Returns the maximum size of the header encoder compression table.
  size_t header_encoder_table_size() const;

  void set_max_decode_buffer_size_bytes(size_t max_decode_buffer_size_bytes) {
    GetHpackDecoder()->set_max_decode_buffer_size_bytes(
        max_decode_buffer_size_bytes);
  }

  size_t send_frame_size_limit() const { return send_frame_size_limit_; }
  void set_send_frame_size_limit(size_t send_frame_size_limit) {
    send_frame_size_limit_ = send_frame_size_limit;
  }

  size_t recv_frame_size_limit() const { return recv_frame_size_limit_; }
  void set_recv_frame_size_limit(size_t recv_frame_size_limit) {
    recv_frame_size_limit_ = recv_frame_size_limit;
  }

  void SetDecoderHeaderTableDebugVisitor(
      std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor);

  void SetEncoderHeaderTableDebugVisitor(
      std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor);

  // For use in SpdyFramerDecoderAdapter implementations; returns the HPACK
  // decoder to be used.
  HpackDecoderInterface* GetHpackDecoderForAdapter() {
    return GetHpackDecoder();
  }

  void SetOverwriteLastFrame(bool value) { overwrite_last_frame_ = value; }
  void SetIsLastFrame(bool value) { is_last_frame_ = value; }
  bool ShouldOverwriteLastFrame() const { return overwrite_last_frame_; }

  // Returns the estimate of dynamically allocated memory in bytes.
  size_t EstimateMemoryUsage() const;

 protected:
  friend class BufferedSpdyFramer;
  friend class HttpNetworkLayer;  // This is temporary for the server.
  friend class HttpNetworkTransactionTest;
  friend class HttpProxyClientSocketPoolTest;
  friend class SpdyHttpStreamTest;
  friend class SpdyNetworkTransactionTest;
  friend class SpdyProxyClientSocketTest;
  friend class SpdySessionTest;
  friend class SpdyStreamTest;
  friend class test::TestSpdyVisitor;
  friend class test::SpdyFramerPeer;
  friend class test::SpdyFramerTest_MultipleContinuationFramesWithIterator_Test;
  friend class test::SpdyFramerTest_PushPromiseFramesWithIterator_Test;

  // Iteratively converts a SpdyFrameIR into an appropriate sequence of Spdy
  // frames.
  // Example usage:
  // std::unique_ptr<SpdyFrameSequence> it = CreateIterator(framer, frame_ir);
  // while (it->HasNextFrame()) {
  //   if(it->NextFrame(output) == 0) {
  //     // Write failed;
  //   }
  // }
  class SPDY_EXPORT_PRIVATE SpdyFrameIterator : public SpdyFrameSequence {
   public:
    // Creates an iterator with the provided framer.
    // Does not take ownership of |framer|.
    // |framer| must outlive this instance.
    explicit SpdyFrameIterator(SpdyFramer* framer);
    ~SpdyFrameIterator() override;

    // Serializes the next frame in the sequence to |output|. Returns the number
    // of bytes written to |output|.
    size_t NextFrame(ZeroCopyOutputBuffer* output) override;

    // Returns true iff there is at least one more frame in the sequence.
    bool HasNextFrame() const override;

    // SpdyFrameIterator is neither copyable nor movable.
    SpdyFrameIterator(const SpdyFrameIterator&) = delete;
    SpdyFrameIterator& operator=(const SpdyFrameIterator&) = delete;

   protected:
    virtual size_t GetFrameSizeSansBlock() const = 0;
    virtual bool SerializeGivenEncoding(const SpdyString& encoding,
                                        ZeroCopyOutputBuffer* output) const = 0;

    SpdyFramer* GetFramer() const { return framer_; }
    void SetEncoder(const SpdyFrameWithHeaderBlockIR* ir) {
      encoder_ =
          framer_->GetHpackEncoder()->EncodeHeaderSet(ir->header_block());
    }

   private:
    SpdyFramer* const framer_;
    std::unique_ptr<HpackEncoder::ProgressiveEncoder> encoder_;
    bool is_first_frame_;
    bool has_next_frame_;

    // Field for debug reporting.
    size_t debug_total_size_;
  };

  // Iteratively converts a SpdyHeadersIR (with a possibly huge
  // SpdyHeaderBlock) into an appropriate sequence of SpdySerializedFrames, and
  // write to the output.
  class SPDY_EXPORT_PRIVATE SpdyHeaderFrameIterator : public SpdyFrameIterator {
   public:
    // Does not take ownership of |framer|. Take ownership of |headers_ir|.
    SpdyHeaderFrameIterator(SpdyFramer* framer,
                            std::unique_ptr<const SpdyHeadersIR> headers_ir);

    ~SpdyHeaderFrameIterator() override;

   private:
    const SpdyFrameIR* GetIR() const override;
    size_t GetFrameSizeSansBlock() const override;
    bool SerializeGivenEncoding(const SpdyString& encoding,
                                ZeroCopyOutputBuffer* output) const override;

    const std::unique_ptr<const SpdyHeadersIR> headers_ir_;
  };

  // Iteratively converts a SpdyPushPromiseIR (with a possibly huge
  // SpdyHeaderBlock) into an appropriate sequence of SpdySerializedFrames, and
  // write to the output.
  class SPDY_EXPORT_PRIVATE SpdyPushPromiseFrameIterator
      : public SpdyFrameIterator {
   public:
    // Does not take ownership of |framer|. Take ownership of |push_promise_ir|.
    SpdyPushPromiseFrameIterator(
        SpdyFramer* framer,
        std::unique_ptr<const SpdyPushPromiseIR> push_promise_ir);

    ~SpdyPushPromiseFrameIterator() override;

   private:
    const SpdyFrameIR* GetIR() const override;
    size_t GetFrameSizeSansBlock() const override;
    bool SerializeGivenEncoding(const SpdyString& encoding,
                                ZeroCopyOutputBuffer* output) const override;

    const std::unique_ptr<const SpdyPushPromiseIR> push_promise_ir_;
  };

  // Converts a SpdyFrameIR into one Spdy frame (a sequence of length 1), and
  // write it to the output.
  class SpdyControlFrameIterator : public SpdyFrameSequence {
   public:
    SpdyControlFrameIterator(SpdyFramer* framer,
                             std::unique_ptr<const SpdyFrameIR> frame_ir);
    ~SpdyControlFrameIterator() override;

    size_t NextFrame(ZeroCopyOutputBuffer* output) override;

    bool HasNextFrame() const override;

    const SpdyFrameIR* GetIR() const override;

   private:
    SpdyFramer* const framer_;
    bool has_next_frame_ = true;
    std::unique_ptr<const SpdyFrameIR> frame_ir_;
  };

 private:
  class CharBuffer {
   public:
    explicit CharBuffer(size_t capacity);
    ~CharBuffer();

    void CopyFrom(const char* data, size_t size);
    void Rewind();

    const char* data() const { return buffer_.get(); }
    size_t len() const { return len_; }

    size_t EstimateMemoryUsage() const;

   private:
    std::unique_ptr<char[]> buffer_;
    size_t capacity_;
    size_t len_;
  };

  // Scratch space necessary for processing SETTINGS frames.
  struct SpdySettingsScratch {
    SpdySettingsScratch();
    void Reset();
    size_t EstimateMemoryUsage() const;

    // Buffer contains up to one complete key/value pair.
    CharBuffer buffer;

    // The ID of the last setting that was processed in the current SETTINGS
    // frame. Used for detecting out-of-order or duplicate keys within a
    // settings frame. Set to -1 before first key/value pair is processed.
    int last_setting_id;
  };

  // Internal breakouts from ProcessInput. Each returns the number of bytes
  // consumed from the data.
  size_t ProcessCommonHeader(const char* data, size_t len);
  size_t ProcessControlFramePayload(const char* data, size_t len);
  size_t ProcessControlFrameBeforeHeaderBlock(const char* data, size_t len);
  // HPACK data is re-encoded as SPDY3 and re-entrantly delivered through
  // |ProcessControlFrameHeaderBlock()|. |is_hpack_header_block| controls
  // whether data is treated as HPACK- vs SPDY3-encoded.
  size_t ProcessControlFrameHeaderBlock(const char* data, size_t len);
  size_t ProcessDataFramePaddingLength(const char* data, size_t len);
  size_t ProcessFramePadding(const char* data, size_t len);
  size_t ProcessDataFramePayload(const char* data, size_t len);
  size_t ProcessGoAwayFramePayload(const char* data, size_t len);
  size_t ProcessSettingsFrameHeader(const char* data, size_t len);
  size_t ProcessSettingsFramePayload(const char* data, size_t len);
  size_t ProcessAltSvcFramePayload(const char* data, size_t len);
  size_t ProcessIgnoredControlFramePayload(/*const char* data,*/ size_t len);
  size_t ProcessExtensionFramePayload(const char* data, size_t len);

  // Validates the frame header against the current protocol, e.g.
  // Frame type must be known, must specify a non-zero stream id.
  //
  // is_control_frame    : the control bit
  // frame_type_field    : the unparsed frame type octet(s)
  // payload_length_field: the stated length in octets of the frame payload
  //
  // For valid frames, returns the correct SpdyFrameType.
  // Otherwise returns a best guess at invalid frame type,
  // after setting the appropriate SpdyFramerError.
  SpdyFrameType ValidateFrameHeader(bool is_control_frame,
                                    uint8_t frame_type_field,
                                    size_t payload_length_field);

  // Helpers for above internal breakouts from ProcessInput.
  void ProcessControlFrameHeader();
  // Always passed exactly 1 setting's worth of data.
  bool ProcessSetting(const char* data);

  // Get (and lazily initialize) the HPACK state.
  HpackEncoder* GetHpackEncoder();
  HpackDecoderInterface* GetHpackDecoder();

  size_t GetNumberRequiredContinuationFrames(size_t size);

  bool WritePayloadWithContinuation(SpdyFrameBuilder* builder,
                                    const SpdyString& hpack_encoding,
                                    SpdyStreamId stream_id,
                                    SpdyFrameType type,
                                    int padding_payload_len);

  // Utility to copy the given data block to the current frame buffer, up
  // to the given maximum number of bytes, and update the buffer
  // data (pointer and length). Returns the number of bytes
  // read, and:
  //   *data is advanced the number of bytes read.
  //   *len is reduced by the number of bytes read.
  size_t UpdateCurrentFrameBuffer(const char** data, size_t* len,
                                  size_t max_bytes);

  // Serializes a HEADERS frame from the given SpdyHeadersIR and encoded header
  // block. Does not need or use the SpdyHeaderBlock inside SpdyHeadersIR.
  // Return false if the serialization fails. |encoding| should not be empty.
  bool SerializeHeadersGivenEncoding(const SpdyHeadersIR& headers,
                                     const SpdyString& encoding,
                                     ZeroCopyOutputBuffer* output) const;

  // Serializes a PUSH_PROMISE frame from the given SpdyPushPromiseIR and
  // encoded header block. Does not need or use the SpdyHeaderBlock inside
  // SpdyHeadersIR.
  bool SerializePushPromiseGivenEncoding(const SpdyPushPromiseIR& push_promise,
                                         const SpdyString& encoding,
                                         ZeroCopyOutputBuffer* output) const;

  // Calculates the number of bytes required to serialize a SpdyHeadersIR, not
  // including the bytes to be used for the encoded header set.
  size_t GetHeaderFrameSizeSansBlock(const SpdyHeadersIR& header_ir) const;

  // Calculates the number of bytes required to serialize a SpdyPushPromiseIR,
  // not including the bytes to be used for the encoded header set.
  size_t GetPushPromiseFrameSizeSansBlock(
      const SpdyPushPromiseIR& push_promise_ir) const;

  // Serializes the flags octet for a given SpdyHeadersIR.
  uint8_t SerializeHeaderFrameFlags(const SpdyHeadersIR& header_ir) const;

  // Serializes the flags octet for a given SpdyPushPromiseIR.
  uint8_t SerializePushPromiseFrameFlags(
      const SpdyPushPromiseIR& push_promise_ir) const;

  // Set the error code and moves the framer into the error state.
  void set_error(SpdyFramerError error);

  // Helper functions to prepare the input for SpdyFrameBuilder.
  void SerializeDataBuilderHelper(const SpdyDataIR& data_ir,
                                  uint8_t* flags,
                                  int* num_padding_fields,
                                  size_t* size_with_padding) const;
  void SerializeDataFrameHeaderWithPaddingLengthFieldBuilderHelper(
      const SpdyDataIR& data_ir,
      uint8_t* flags,
      size_t* frame_size,
      size_t* num_padding_fields) const;
  void SerializeSettingsBuilderHelper(const SpdySettingsIR& settings,
                                      uint8_t* flags,
                                      const SettingsMap* values,
                                      size_t* size) const;
  void SerializeAltSvcBuilderHelper(const SpdyAltSvcIR& altsvc_ir,
                                    SpdyString* value,
                                    size_t* size) const;
  void SerializeHeadersBuilderHelper(const SpdyHeadersIR& headers,
                                     uint8_t* flags,
                                     size_t* size,
                                     SpdyString* hpack_encoding,
                                     int* weight,
                                     size_t* length_field);
  void SerializePushPromiseBuilderHelper(const SpdyPushPromiseIR& push_promise,
                                         uint8_t* flags,
                                         SpdyString* hpack_encoding,
                                         size_t* size);

  // The size of the control frame buffer.
  // Since this is only used for control frame headers, the maximum control
  // frame header size is sufficient; all remaining control
  // frame data is streamed to the visitor.
  static const size_t kControlFrameBufferSize;

  // The maximum size of the control frames that we send, including the size of
  // the header. This limit is arbitrary. We can enforce it here or at the
  // application layer. We chose the framing layer, but this can be changed (or
  // removed) if necessary later down the line.
  // TODO(diannahu): Rename to make it clear that this limit is for sending.
  static const size_t kMaxControlFrameSize;
  // The maximum size for the payload of DATA frames to send.
  static const size_t kMaxDataPayloadSendSize;
  // The size of one parameter in SETTINGS frame.
  static const size_t kOneSettingParameterSize;

  SpdyState state_;
  SpdyState previous_state_;
  SpdyFramerError spdy_framer_error_;

  // Note that for DATA frame, remaining_data_length_ is sum of lengths of
  // frame header, padding length field (optional), data payload (optional) and
  // padding payload (optional).
  size_t remaining_data_length_;

  // The length (in bytes) of the padding payload to be processed.
  size_t remaining_padding_payload_length_;

  // The number of bytes remaining to read from the current control frame's
  // headers. Note that header data blocks (for control types that have them)
  // are part of the frame's payload, and not the frame's headers.
  size_t remaining_control_header_;

  // The limit on the size of sent HTTP/2 payloads as specified in the
  // SETTINGS_MAX_FRAME_SIZE received from peer.
  size_t send_frame_size_limit_ = kSpdyInitialFrameSizeLimit;

  // The limit on the size of received HTTP/2 payloads as specified in the
  // SETTINGS_MAX_FRAME_SIZE advertised to peer.
  size_t recv_frame_size_limit_ = kSpdyInitialFrameSizeLimit;

  CharBuffer current_frame_buffer_;

  // The type of the frame currently being read.
  SpdyFrameType current_frame_type_;

  // The total length of the frame currently being read, including frame header.
  uint32_t current_frame_length_;

  // The stream ID field of the frame currently being read, if applicable.
  SpdyStreamId current_frame_stream_id_;

  // Set this to the current stream when we receive a HEADERS, PUSH_PROMISE, or
  // CONTINUATION frame without the END_HEADERS(0x4) bit set. These frames must
  // be followed by a CONTINUATION frame, or else we throw a PROTOCOL_ERROR.
  // A value of 0 indicates that we are not expecting a CONTINUATION frame.
  SpdyStreamId expect_continuation_;

  // Scratch space for handling SETTINGS frames.
  // TODO(hkhalil): Unify memory for this scratch space with
  // current_frame_buffer_.
  SpdySettingsScratch settings_scratch_;

  std::unique_ptr<CharBuffer> altsvc_scratch_;

  std::unique_ptr<HpackEncoder> hpack_encoder_;
  std::unique_ptr<HpackDecoderInterface> hpack_decoder_;

  SpdyFramerVisitorInterface* visitor_;
  ExtensionVisitorInterface* extension_;
  SpdyFramerDebugVisitorInterface* debug_visitor_;

  SpdyHeadersHandlerInterface* header_handler_;

  // Optional decoder to use instead of this instance.
  std::unique_ptr<SpdyFramerDecoderAdapter> decoder_adapter_;

  // The flags field of the frame currently being read.
  uint8_t current_frame_flags_;

  // Determines whether HPACK compression is used.
  const CompressionOption compression_option_;

  // On the first read, we check to see if the data starts with HTTP.
  // If it does, we likely have an HTTP response.   This isn't guaranteed
  // though: we could have gotten a settings frame and then corrupt data that
  // just looks like HTTP, but deterministic checking requires a lot more state.
  bool probable_http_response_;

  // If a HEADERS frame is followed by a CONTINUATION frame, the FIN/END_STREAM
  // flag is still carried in the HEADERS frame. If it's set, flip this so that
  // we know to terminate the stream when the entire header block has been
  // processed.
  bool end_stream_when_done_;

  // If true, then ProcessInput returns after processing a full frame,
  // rather than reading all available input.
  bool process_single_input_frame_ = false;

  // TODO(yasong): Remove overwrite_last_frame_ and is_last_frame_ when we make
  // Serialize<FrameType>() functions static and independent of SpdyFramer. And
  // pass the last frame info in the arguments.
  bool overwrite_last_frame_ = false;
  // If the current frame to be serialized is the last frame. Will be valid iff
  // overwrite_last_frame_ is true.
  bool is_last_frame_ = false;
};

}  // namespace net

#endif  // NET_SPDY_CORE_SPDY_FRAMER_H_
