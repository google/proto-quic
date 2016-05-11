// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_BUFFERED_SPDY_FRAMER_H_
#define NET_SPDY_BUFFERED_SPDY_FRAMER_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>

#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/socket/next_proto.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_protocol.h"

namespace net {

// Returns the SPDY major version corresponding to the given NextProto
// value, which must represent a SPDY-like protocol.
NET_EXPORT_PRIVATE SpdyMajorVersion NextProtoToSpdyMajorVersion(
    NextProto next_proto);

class NET_EXPORT_PRIVATE BufferedSpdyFramerVisitorInterface {
 public:
  BufferedSpdyFramerVisitorInterface() {}

  // Called if an error is detected in the SpdySerializedFrame protocol.
  virtual void OnError(SpdyFramer::SpdyError error_code) = 0;

  // Called if an error is detected in a SPDY stream.
  virtual void OnStreamError(SpdyStreamId stream_id,
                             const std::string& description) = 0;

  // Called after all the header data for SYN_STREAM control frame is received.
  virtual void OnSynStream(SpdyStreamId stream_id,
                           SpdyStreamId associated_stream_id,
                           SpdyPriority priority,
                           bool fin,
                           bool unidirectional,
                           const SpdyHeaderBlock& headers) = 0;

  // Called after all the header data for SYN_REPLY control frame is received.
  virtual void OnSynReply(SpdyStreamId stream_id,
                          bool fin,
                          const SpdyHeaderBlock& headers) = 0;

  // Called after all the header data for HEADERS control frame is received.
  virtual void OnHeaders(SpdyStreamId stream_id,
                         bool has_priority,
                         SpdyPriority priority,
                         SpdyStreamId parent_stream_id,
                         bool exclusive,
                         bool fin,
                         const SpdyHeaderBlock& headers) = 0;

  // Called when a data frame header is received.
  virtual void OnDataFrameHeader(SpdyStreamId stream_id,
                                 size_t length,
                                 bool fin) = 0;

  // Called when data is received.
  // |stream_id| The stream receiving data.
  // |data| A buffer containing the data received.
  // |len| The length of the data buffer (at most 2^24 - 1 for SPDY/3,
  // but 2^16 - 1 - 8 for SPDY/4).
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
  // ownership of the headers handler. The same instance should be returned
  // for all header frames comprising a logical header block (i.e. until
  // OnHeaderFrameEnd() is called with end_headers == true).
  virtual SpdyHeadersHandlerInterface* OnHeaderFrameStart(
      SpdyStreamId stream_id) = 0;

  // Called after processing the payload of a frame containing header data.
  // |end_headers| is true if there will not be any subsequent CONTINUATION
  // frames.
  virtual void OnHeaderFrameEnd(SpdyStreamId stream_id, bool end_headers) = 0;

  // Called when a SETTINGS frame is received.
  // |clear_persisted| True if the respective flag is set on the SETTINGS frame.
  virtual void OnSettings(bool clear_persisted) = 0;

  // Called when an individual setting within a SETTINGS frame has been parsed
  // and validated.
  virtual void OnSetting(SpdySettingsIds id, uint8_t flags, uint32_t value) = 0;

  // Called when a SETTINGS frame is received with the ACK flag set.
  virtual void OnSettingsAck() {}

  // Called at the completion of parsing SETTINGS id and value tuples.
  virtual void OnSettingsEnd() {}

  // Called when a PING frame has been parsed.
  virtual void OnPing(SpdyPingId unique_id, bool is_ack) = 0;

  // Called when a RST_STREAM frame has been parsed.
  virtual void OnRstStream(SpdyStreamId stream_id,
                           SpdyRstStreamStatus status) = 0;

  // Called when a GOAWAY frame has been parsed.
  virtual void OnGoAway(SpdyStreamId last_accepted_stream_id,
                        SpdyGoAwayStatus status,
                        base::StringPiece debug_data) = 0;

  // Called when a WINDOW_UPDATE frame has been parsed.
  virtual void OnWindowUpdate(SpdyStreamId stream_id,
                              int delta_window_size) = 0;

  // Called when a PUSH_PROMISE frame has been parsed.
  virtual void OnPushPromise(SpdyStreamId stream_id,
                             SpdyStreamId promised_stream_id,
                             const SpdyHeaderBlock& headers) = 0;

  // Called when a frame type we don't recognize is received.
  // Return true if this appears to be a valid extension frame, false otherwise.
  // We distinguish between extension frames and nonsense by checking
  // whether the stream id is valid.
  virtual bool OnUnknownFrame(SpdyStreamId stream_id, int frame_type) = 0;

 protected:
  virtual ~BufferedSpdyFramerVisitorInterface() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(BufferedSpdyFramerVisitorInterface);
};

class NET_EXPORT_PRIVATE BufferedSpdyFramer
    : public SpdyFramerVisitorInterface {
 public:
  explicit BufferedSpdyFramer(SpdyMajorVersion version);
  ~BufferedSpdyFramer() override;

  // Sets callbacks to be called from the buffered spdy framer.  A visitor must
  // be set, or else the framer will likely crash.  It is acceptable for the
  // visitor to do nothing.  If this is called multiple times, only the last
  // visitor will be used.
  void set_visitor(BufferedSpdyFramerVisitorInterface* visitor);

  // Set debug callbacks to be called from the framer. The debug visitor is
  // completely optional and need not be set in order for normal operation.
  // If this is called multiple times, only the last visitor will be used.
  void set_debug_visitor(SpdyFramerDebugVisitorInterface* debug_visitor);

  // SpdyFramerVisitorInterface
  void OnError(SpdyFramer* spdy_framer) override;
  void OnSynStream(SpdyStreamId stream_id,
                   SpdyStreamId associated_stream_id,
                   SpdyPriority priority,
                   bool fin,
                   bool unidirectional) override;
  void OnSynReply(SpdyStreamId stream_id, bool fin) override;
  void OnHeaders(SpdyStreamId stream_id,
                 bool has_priority,
                 SpdyPriority priority,
                 SpdyStreamId parent_stream_id,
                 bool exclusive,
                 bool fin,
                 bool end) override;
  bool OnControlFrameHeaderData(SpdyStreamId stream_id,
                                const char* header_data,
                                size_t len) override;
  void OnStreamFrameData(SpdyStreamId stream_id,
                         const char* data,
                         size_t len) override;
  void OnStreamEnd(SpdyStreamId stream_id) override;
  void OnStreamPadding(SpdyStreamId stream_id, size_t len) override;
  SpdyHeadersHandlerInterface* OnHeaderFrameStart(
      SpdyStreamId stream_id) override;
  void OnHeaderFrameEnd(SpdyStreamId stream_id, bool end_headers) override;
  void OnSettings(bool clear_persisted) override;
  void OnSetting(SpdySettingsIds id, uint8_t flags, uint32_t value) override;
  void OnSettingsAck() override;
  void OnSettingsEnd() override;
  void OnPing(SpdyPingId unique_id, bool is_ack) override;
  void OnRstStream(SpdyStreamId stream_id, SpdyRstStreamStatus status) override;
  void OnGoAway(SpdyStreamId last_accepted_stream_id,
                SpdyGoAwayStatus status) override;
  bool OnGoAwayFrameData(const char* goaway_data, size_t len) override;
  void OnWindowUpdate(SpdyStreamId stream_id, int delta_window_size) override;
  void OnPushPromise(SpdyStreamId stream_id,
                     SpdyStreamId promised_stream_id,
                     bool end) override;
  void OnDataFrameHeader(SpdyStreamId stream_id,
                         size_t length,
                         bool fin) override;
  void OnContinuation(SpdyStreamId stream_id, bool end) override;
  bool OnUnknownFrame(SpdyStreamId stream_id, int frame_type) override;

  // SpdyFramer methods.
  size_t ProcessInput(const char* data, size_t len);
  SpdyMajorVersion protocol_version();
  void Reset();
  SpdyFramer::SpdyError error_code() const;
  SpdyFramer::SpdyState state() const;
  bool MessageFullyRead();
  bool HasError();
  SpdySerializedFrame* CreateSynStream(SpdyStreamId stream_id,
                                       SpdyStreamId associated_stream_id,
                                       SpdyPriority priority,
                                       SpdyControlFlags flags,
                                       const SpdyHeaderBlock* headers);
  SpdySerializedFrame* CreateSynReply(SpdyStreamId stream_id,
                                      SpdyControlFlags flags,
                                      const SpdyHeaderBlock* headers);
  SpdySerializedFrame* CreateRstStream(SpdyStreamId stream_id,
                                       SpdyRstStreamStatus status) const;
  SpdySerializedFrame* CreateSettings(const SettingsMap& values) const;
  SpdySerializedFrame* CreatePingFrame(SpdyPingId unique_id, bool is_ack) const;
  SpdySerializedFrame* CreateGoAway(SpdyStreamId last_accepted_stream_id,
                                    SpdyGoAwayStatus status,
                                    base::StringPiece debug_data) const;
  SpdySerializedFrame* CreateHeaders(SpdyStreamId stream_id,
                                     SpdyControlFlags flags,
                                     SpdyPriority priority,
                                     const SpdyHeaderBlock* headers);
  SpdySerializedFrame* CreateWindowUpdate(SpdyStreamId stream_id,
                                          uint32_t delta_window_size) const;
  SpdySerializedFrame* CreateDataFrame(SpdyStreamId stream_id,
                                       const char* data,
                                       uint32_t len,
                                       SpdyDataFlags flags);
  SpdySerializedFrame* CreatePushPromise(SpdyStreamId stream_id,
                                         SpdyStreamId promised_stream_id,
                                         const SpdyHeaderBlock* headers);

  // Serialize a frame of unknown type.
  SpdySerializedFrame SerializeFrame(const SpdyFrameIR& frame) {
    return spdy_framer_.SerializeFrame(frame);
  }

  SpdyPriority GetHighestPriority() const;

  size_t GetDataFrameMinimumSize() const {
    return spdy_framer_.GetDataFrameMinimumSize();
  }

  size_t GetControlFrameHeaderSize() const {
    return spdy_framer_.GetControlFrameHeaderSize();
  }

  size_t GetSynStreamMinimumSize() const {
    return spdy_framer_.GetSynStreamMinimumSize();
  }

  size_t GetFrameMinimumSize() const {
    return spdy_framer_.GetFrameMinimumSize();
  }

  size_t GetFrameMaximumSize() const {
    return spdy_framer_.GetFrameMaximumSize();
  }

  size_t GetDataFrameMaximumPayload() const {
    return spdy_framer_.GetDataFrameMaximumPayload();
  }

  int frames_received() const { return frames_received_; }

 private:
  void InitHeaderStreaming(SpdyStreamId stream_id);

  SpdyFramer spdy_framer_;
  BufferedSpdyFramerVisitorInterface* visitor_;

  // Header block streaming state:
  std::string header_buffer_;
  bool header_buffer_valid_;
  SpdyStreamId header_stream_id_;
  int frames_received_;

  // Collection of fields from control frames that we need to
  // buffer up from the spdy framer.
  struct ControlFrameFields {
    SpdyFrameType type;
    SpdyStreamId stream_id;
    SpdyStreamId associated_stream_id;
    SpdyStreamId promised_stream_id;
    bool has_priority;
    SpdyPriority priority;
    SpdyStreamId parent_stream_id;
    bool exclusive;
    bool fin;
    bool unidirectional;
  };
  std::unique_ptr<ControlFrameFields> control_frame_fields_;

  // Collection of fields of a GOAWAY frame that this class needs to buffer.
  struct GoAwayFields {
    SpdyStreamId last_accepted_stream_id;
    SpdyGoAwayStatus status;
    std::string debug_data;
  };
  std::unique_ptr<GoAwayFields> goaway_fields_;

  DISALLOW_COPY_AND_ASSIGN(BufferedSpdyFramer);
};

}  // namespace net

#endif  // NET_SPDY_BUFFERED_SPDY_FRAMER_H_
