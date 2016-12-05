// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file contains some protocol structures for use with SPDY 3 and HTTP 2
// The SPDY 3 spec can be found at:
// http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft3

#ifndef NET_SPDY_SPDY_PROTOCOL_H_
#define NET_SPDY_SPDY_PROTOCOL_H_

#include <stddef.h>
#include <stdint.h>

#include <limits>
#include <map>
#include <memory>
#include <string>
#include <utility>

#include "base/compiler_specific.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "base/sys_byteorder.h"
#include "net/base/net_export.h"
#include "net/spdy/spdy_alt_svc_wire_format.h"
#include "net/spdy/spdy_bitmasks.h"
#include "net/spdy/spdy_bug_tracker.h"
#include "net/spdy/spdy_header_block.h"

namespace net {

// A stream id is a 31 bit entity.
typedef uint32_t SpdyStreamId;

// Specifies the stream ID used to denote the current session (for
// flow control).
const SpdyStreamId kSessionFlowControlStreamId = 0;

// The maximum possible frame payload size allowed by the spec.
const uint32_t kSpdyMaxFrameSizeLimit = (1 << 24) - 1;

// The initial value for the maximum frame payload size as per the spec. This is
// the maximum control frame size we accept.
const uint32_t kSpdyInitialFrameSizeLimit = 1 << 14;

// The initial value for the maximum size of the header list, "unlimited" (max
// unsigned 32-bit int) as per the spec.
const uint32_t kSpdyInitialHeaderListSizeLimit = 0xFFFFFFFF;

// Maximum window size for a Spdy stream or session.
const int32_t kSpdyMaximumWindowSize = 0x7FFFFFFF;  // Max signed 32bit int

// Maximum padding size in octets for one DATA or HEADERS or PUSH_PROMISE frame.
const int32_t kPaddingSizePerFrame = 256;

// The HTTP/2 connection header prefix, which must be the first bytes
// sent by the client upon starting an HTTP/2 connection, and which
// must be followed by a SETTINGS frame.
//
// Equivalent to the string "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
// (without the null terminator).
const char kHttp2ConnectionHeaderPrefix[] = {
  0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54,  // PRI * HT
  0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,  // TP/2.0..
  0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a   // ..SM....
};
const int kHttp2ConnectionHeaderPrefixSize =
    arraysize(kHttp2ConnectionHeaderPrefix);

const char kHttp2VersionString[] = "HTTP/1.1";

// Types of HTTP2 frames.
enum SpdyFrameType {
  DATA,
  RST_STREAM,
  SETTINGS,
  PING,
  GOAWAY,
  HEADERS,
  WINDOW_UPDATE,
  PUSH_PROMISE,
  CONTINUATION,
  PRIORITY,
  // BLOCKED and ALTSVC are recognized extensions.
  BLOCKED,
  ALTSVC,
};

// Flags on data packets.
enum SpdyDataFlags {
  DATA_FLAG_NONE = 0x00,
  DATA_FLAG_FIN = 0x01,
  DATA_FLAG_PADDED = 0x08,
};

// Flags on control packets
enum SpdyControlFlags {
  CONTROL_FLAG_NONE = 0x00,
  CONTROL_FLAG_FIN = 0x01,
  CONTROL_FLAG_UNIDIRECTIONAL = 0x02,
};

enum SpdyPingFlags {
  PING_FLAG_ACK = 0x01,
};

// Used by HEADERS, PUSH_PROMISE, and CONTINUATION.
enum SpdyHeadersFlags {
  HEADERS_FLAG_END_HEADERS = 0x04,
  HEADERS_FLAG_PADDED = 0x08,
  HEADERS_FLAG_PRIORITY = 0x20,
};

enum SpdyPushPromiseFlags {
  PUSH_PROMISE_FLAG_END_PUSH_PROMISE = 0x04,
  PUSH_PROMISE_FLAG_PADDED = 0x08,
};

// Flags on the SETTINGS control frame.
enum SpdySettingsControlFlags {
  SETTINGS_FLAG_CLEAR_PREVIOUSLY_PERSISTED_SETTINGS = 0x01,
};

enum Http2SettingsControlFlags {
  SETTINGS_FLAG_ACK = 0x01,
};

// Flags for settings within a SETTINGS frame.
enum SpdySettingsFlags {
  SETTINGS_FLAG_NONE = 0x00,
  SETTINGS_FLAG_PLEASE_PERSIST = 0x01,
  SETTINGS_FLAG_PERSISTED = 0x02,
};

// List of known settings. Avoid changing these enum values, as persisted
// settings are keyed on them, and they are also exposed in net-internals.
enum SpdySettingsIds {
  SETTINGS_UPLOAD_BANDWIDTH = 0x1,
  SETTINGS_DOWNLOAD_BANDWIDTH = 0x2,
  // Network round trip time in milliseconds.
  SETTINGS_ROUND_TRIP_TIME = 0x3,
  // The maximum number of simultaneous live streams in each direction.
  SETTINGS_MAX_CONCURRENT_STREAMS = 0x4,
  // TCP congestion window in packets.
  SETTINGS_CURRENT_CWND = 0x5,
  // Downstream byte retransmission rate in percentage.
  SETTINGS_DOWNLOAD_RETRANS_RATE = 0x6,
  // Initial window size in bytes
  SETTINGS_INITIAL_WINDOW_SIZE = 0x7,
  // HPACK header table maximum size.
  SETTINGS_HEADER_TABLE_SIZE = 0x8,
  // Whether or not server push (PUSH_PROMISE) is enabled.
  SETTINGS_ENABLE_PUSH = 0x9,
  // The size of the largest frame payload that a receiver is willing to accept.
  SETTINGS_MAX_FRAME_SIZE = 0xa,
  // The maximum size of header list that the sender is prepared to accept.
  SETTINGS_MAX_HEADER_LIST_SIZE = 0xb,
};

// Status codes for RST_STREAM frames.
enum SpdyRstStreamStatus {
  RST_STREAM_NO_ERROR = 0,
  RST_STREAM_PROTOCOL_ERROR = 1,
  RST_STREAM_INVALID_STREAM = 2,
  RST_STREAM_STREAM_CLOSED = 2,  // Equivalent to INVALID_STREAM
  RST_STREAM_REFUSED_STREAM = 3,
  RST_STREAM_UNSUPPORTED_VERSION = 4,
  RST_STREAM_CANCEL = 5,
  RST_STREAM_INTERNAL_ERROR = 6,
  RST_STREAM_FLOW_CONTROL_ERROR = 7,
  RST_STREAM_STREAM_IN_USE = 8,
  RST_STREAM_STREAM_ALREADY_CLOSED = 9,
  // FRAME_TOO_LARGE (defined by SPDY versions 3.1 and below), and
  // FRAME_SIZE_ERROR (defined by HTTP/2) are mapped to the same internal
  // reset status.
  RST_STREAM_FRAME_TOO_LARGE = 11,
  RST_STREAM_FRAME_SIZE_ERROR = 11,
  RST_STREAM_SETTINGS_TIMEOUT = 12,
  RST_STREAM_CONNECT_ERROR = 13,
  RST_STREAM_ENHANCE_YOUR_CALM = 14,
  RST_STREAM_INADEQUATE_SECURITY = 15,
  RST_STREAM_HTTP_1_1_REQUIRED = 16,
  RST_STREAM_NUM_STATUS_CODES = 17
};

// Status codes for GOAWAY frames.
enum SpdyGoAwayStatus {
  GOAWAY_OK = 0,
  GOAWAY_NO_ERROR = GOAWAY_OK,
  GOAWAY_PROTOCOL_ERROR = 1,
  GOAWAY_INTERNAL_ERROR = 2,
  GOAWAY_FLOW_CONTROL_ERROR = 3,
  GOAWAY_SETTINGS_TIMEOUT = 4,
  GOAWAY_STREAM_CLOSED = 5,
  GOAWAY_FRAME_SIZE_ERROR = 6,
  GOAWAY_REFUSED_STREAM = 7,
  GOAWAY_CANCEL = 8,
  GOAWAY_COMPRESSION_ERROR = 9,
  GOAWAY_CONNECT_ERROR = 10,
  GOAWAY_ENHANCE_YOUR_CALM = 11,
  GOAWAY_INADEQUATE_SECURITY = 12,
  GOAWAY_HTTP_1_1_REQUIRED = 13
};

// A SPDY priority is a number between 0 and 7 (inclusive).
typedef uint8_t SpdyPriority;

// Lowest and Highest here refer to SPDY priorities as described in

// https://www.chromium.org/spdy/spdy-protocol/spdy-protocol-draft3-1#TOC-2.3.3-Stream-priority
const SpdyPriority kV3HighestPriority = 0;
const SpdyPriority kV3LowestPriority = 7;

// Returns SPDY 3.x priority value clamped to the valid range of [0, 7].
NET_EXPORT_PRIVATE SpdyPriority ClampSpdy3Priority(SpdyPriority priority);

// HTTP/2 stream weights are integers in range [1, 256], as specified in RFC
// 7540 section 5.3.2. Default stream weight is defined in section 5.3.5.
const int kHttp2MinStreamWeight = 1;
const int kHttp2MaxStreamWeight = 256;
const int kHttp2DefaultStreamWeight = 16;

// Returns HTTP/2 weight clamped to the valid range of [1, 256].
NET_EXPORT_PRIVATE int ClampHttp2Weight(int weight);

// Maps SPDY 3.x priority value in range [0, 7] to HTTP/2 weight value in range
// [1, 256], where priority 0 (i.e. highest precedence) corresponds to maximum
// weight 256 and priority 7 (lowest precedence) corresponds to minimum weight
// 1.
NET_EXPORT_PRIVATE int Spdy3PriorityToHttp2Weight(SpdyPriority priority);

// Maps HTTP/2 weight value in range [1, 256] to SPDY 3.x priority value in
// range [0, 7], where minimum weight 1 corresponds to priority 7 (lowest
// precedence) and maximum weight 256 corresponds to priority 0 (highest
// precedence).
NET_EXPORT_PRIVATE SpdyPriority Http2WeightToSpdy3Priority(int weight);

// Reserved ID for root stream of HTTP/2 stream dependency tree, as specified
// in RFC 7540 section 5.3.1.
const unsigned int kHttp2RootStreamId = 0;

typedef uint64_t SpdyPingId;

typedef std::string SpdyProtocolId;

// TODO(hkhalil): Add direct testing for this? It won't increase coverage any,
// but is good to do anyway.
class NET_EXPORT_PRIVATE SpdyConstants {
 public:
  // Returns true if a given on-the-wire enumeration of a frame type is valid
  // for a given protocol version, false otherwise.
  static bool IsValidFrameType(int frame_type_field);

  // Parses a frame type from an on-the-wire enumeration.
  // Behavior is undefined for invalid frame type fields; consumers should first
  // use IsValidFrameType() to verify validity of frame type fields.
  static SpdyFrameType ParseFrameType(int frame_type_field);

  // Serializes a given frame type to the on-the-wire enumeration value.
  // Returns -1 on failure (I.E. Invalid frame type).
  static int SerializeFrameType(SpdyFrameType frame_type);

  // (HTTP/2) All standard frame types except WINDOW_UPDATE are
  // (stream-specific xor connection-level). Returns false iff we know
  // the given frame type does not align with the given streamID.
  static bool IsValidHTTP2FrameStreamId(SpdyStreamId current_frame_stream_id,
                                        SpdyFrameType frame_type_field);

  // Returns true if a given on-the-wire enumeration of a setting id is valid
  // false otherwise.
  static bool IsValidSettingId(int setting_id_field);

  // Parses a setting id from an on-the-wire enumeration
  // Behavior is undefined for invalid setting id fields; consumers should first
  // use IsValidSettingId() to verify validity of setting id fields.
  static SpdySettingsIds ParseSettingId(int setting_id_field);

  // Serializes a given setting id to the on-the-wire enumeration value.
  // Returns -1 on failure (I.E. Invalid setting id).
  static int SerializeSettingId(SpdySettingsIds id);

  // Returns true if a given on-the-wire enumeration of a RST_STREAM status code
  // is valid, false otherwise.
  static bool IsValidRstStreamStatus(int rst_stream_status_field);

  // Parses a RST_STREAM status code from an on-the-wire enumeration.
  // Behavior is undefined for invalid RST_STREAM status code fields; consumers
  // should first use IsValidRstStreamStatus() to verify validity of RST_STREAM
  // status code fields..
  static SpdyRstStreamStatus ParseRstStreamStatus(int rst_stream_status_field);

  // Serializes a given RST_STREAM status code to the on-the-wire enumeration
  // value.
  // Returns -1 on failure (I.E. Invalid RST_STREAM status code for the given
  // version).
  static int SerializeRstStreamStatus(SpdyRstStreamStatus rst_stream_status);

  // Returns true if a given on-the-wire enumeration of a GOAWAY status code is
  // valid, false otherwise.
  static bool IsValidGoAwayStatus(int goaway_status_field);

  // Parses a GOAWAY status from an on-the-wire enumeration.
  // Behavior is undefined for invalid GOAWAY status fields; consumers should
  // first use IsValidGoAwayStatus() to verify validity of GOAWAY status fields.
  static SpdyGoAwayStatus ParseGoAwayStatus(int goaway_status_field);

  // Serializes a given GOAWAY status to the on-the-wire enumeration value.
  // Returns -1 on failure (I.E. Invalid GOAWAY status for the given version).
  static int SerializeGoAwayStatus(SpdyGoAwayStatus status);

  // Frame type for non-control (i.e. data) frames.
  static const int kDataFrameType;
  // Size, in bytes, of the data frame header.
  static const size_t kDataFrameMinimumSize;
  // Number of octets in the frame header.
  static const size_t kFrameHeaderSize;
  // Maximum possible configurable size of a frame in octets.
  static const size_t kMaxFrameSizeLimit;
  // Size of a header block size field. Valid only for SPDY 3.
  static const size_t kSizeOfSizeField;
  // Per-header overhead for block size accounting in bytes.
  static const size_t kPerHeaderOverhead;
  // Initial window size for a stream in bytes.
  static const int32_t kInitialStreamWindowSize;
  // Initial window size for a session in bytes.
  static const int32_t kInitialSessionWindowSize;
  // The NPN string for HTTP2, "h2".
  static const char kHttp2Npn[];
};

// Variant type (i.e. tagged union) that is either a SPDY 3.x priority value,
// or else an HTTP/2 stream dependency tuple {parent stream ID, weight,
// exclusive bit}. Templated to allow for use by QUIC code; SPDY and HTTP/2
// code should use the concrete type instantiation SpdyStreamPrecedence.
template <typename StreamIdType>
class StreamPrecedence {
 public:
  // Constructs instance that is a SPDY 3.x priority. Clamps priority value to
  // the valid range [0, 7].
  explicit StreamPrecedence(SpdyPriority priority)
      : is_spdy3_priority_(true),
        spdy3_priority_(ClampSpdy3Priority(priority)) {}

  // Constructs instance that is an HTTP/2 stream weight, parent stream ID, and
  // exclusive bit. Clamps stream weight to the valid range [1, 256].
  StreamPrecedence(StreamIdType parent_id, int weight, bool is_exclusive)
      : is_spdy3_priority_(false),
        http2_stream_dependency_{parent_id, ClampHttp2Weight(weight),
                                 is_exclusive} {}

  // Intentionally copyable, to support pass by value.
  StreamPrecedence(const StreamPrecedence& other) = default;
  StreamPrecedence& operator=(const StreamPrecedence& other) = default;

  // Returns true if this instance is a SPDY 3.x priority, or false if this
  // instance is an HTTP/2 stream dependency.
  bool is_spdy3_priority() const { return is_spdy3_priority_; }

  // Returns SPDY 3.x priority value. If |is_spdy3_priority()| is true, this is
  // the value provided at construction, clamped to the legal priority
  // range. Otherwise, it is the HTTP/2 stream weight mapped to a SPDY 3.x
  // priority value, where minimum weight 1 corresponds to priority 7 (lowest
  // precedence) and maximum weight 256 corresponds to priority 0 (highest
  // precedence).
  SpdyPriority spdy3_priority() const {
    return is_spdy3_priority_
               ? spdy3_priority_
               : Http2WeightToSpdy3Priority(http2_stream_dependency_.weight);
  }

  // Returns HTTP/2 parent stream ID. If |is_spdy3_priority()| is false, this is
  // the value provided at construction, otherwise it is |kHttp2RootStreamId|.
  StreamIdType parent_id() const {
    return is_spdy3_priority_ ? kHttp2RootStreamId
                              : http2_stream_dependency_.parent_id;
  }

  // Returns HTTP/2 stream weight. If |is_spdy3_priority()| is false, this is
  // the value provided at construction, clamped to the legal weight
  // range. Otherwise, it is the SPDY 3.x priority value mapped to an HTTP/2
  // stream weight, where priority 0 (i.e. highest precedence) corresponds to
  // maximum weight 256 and priority 7 (lowest precedence) corresponds to
  // minimum weight 1.
  int weight() const {
    return is_spdy3_priority_ ? Spdy3PriorityToHttp2Weight(spdy3_priority_)
                              : http2_stream_dependency_.weight;
  }

  // Returns HTTP/2 parent stream exclusivity. If |is_spdy3_priority()| is
  // false, this is the value provided at construction, otherwise it is false.
  bool is_exclusive() const {
    return !is_spdy3_priority_ && http2_stream_dependency_.is_exclusive;
  }

  // Facilitates test assertions.
  bool operator==(const StreamPrecedence& other) const {
    if (is_spdy3_priority()) {
      return other.is_spdy3_priority() &&
             (spdy3_priority() == other.spdy3_priority());
    } else {
      return !other.is_spdy3_priority() && (parent_id() == other.parent_id()) &&
             (weight() == other.weight()) &&
             (is_exclusive() == other.is_exclusive());
    }
  }

  bool operator!=(const StreamPrecedence& other) const {
    return !(*this == other);
  }

 private:
  struct Http2StreamDependency {
    StreamIdType parent_id;
    int weight;
    bool is_exclusive;
  };

  bool is_spdy3_priority_;
  union {
    SpdyPriority spdy3_priority_;
    Http2StreamDependency http2_stream_dependency_;
  };
};

typedef StreamPrecedence<SpdyStreamId> SpdyStreamPrecedence;

class SpdyFrameVisitor;

// Intermediate representation for HTTP2 frames.
class NET_EXPORT_PRIVATE SpdyFrameIR {
 public:
  virtual ~SpdyFrameIR() {}

  virtual void Visit(SpdyFrameVisitor* visitor) const = 0;

 protected:
  SpdyFrameIR() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(SpdyFrameIR);
};

// Abstract class intended to be inherited by IRs that have a stream associated
// to them.
class NET_EXPORT_PRIVATE SpdyFrameWithStreamIdIR : public SpdyFrameIR {
 public:
  ~SpdyFrameWithStreamIdIR() override {}
  SpdyStreamId stream_id() const { return stream_id_; }
  void set_stream_id(SpdyStreamId stream_id) {
    DCHECK_EQ(0u, stream_id & ~kStreamIdMask);
    stream_id_ = stream_id;
  }

 protected:
  explicit SpdyFrameWithStreamIdIR(SpdyStreamId stream_id) {
    set_stream_id(stream_id);
  }

 private:
  SpdyStreamId stream_id_;

  DISALLOW_COPY_AND_ASSIGN(SpdyFrameWithStreamIdIR);
};

// Abstract class intended to be inherited by IRs that have the option of a FIN
// flag. Implies SpdyFrameWithStreamIdIR.
class NET_EXPORT_PRIVATE SpdyFrameWithFinIR : public SpdyFrameWithStreamIdIR {
 public:
  ~SpdyFrameWithFinIR() override {}
  bool fin() const { return fin_; }
  void set_fin(bool fin) { fin_ = fin; }

 protected:
  explicit SpdyFrameWithFinIR(SpdyStreamId stream_id)
      : SpdyFrameWithStreamIdIR(stream_id),
        fin_(false) {}

 private:
  bool fin_;

  DISALLOW_COPY_AND_ASSIGN(SpdyFrameWithFinIR);
};

// Abstract class intended to be inherited by IRs that contain a header
// block. Implies SpdyFrameWithFinIR.
class NET_EXPORT_PRIVATE SpdyFrameWithHeaderBlockIR
    : public NON_EXPORTED_BASE(SpdyFrameWithFinIR) {
 public:
  ~SpdyFrameWithHeaderBlockIR() override;

  const SpdyHeaderBlock& header_block() const { return header_block_; }
  void set_header_block(SpdyHeaderBlock header_block) {
    // Deep copy.
    header_block_ = std::move(header_block);
  }
  void SetHeader(base::StringPiece name, base::StringPiece value) {
    header_block_[name] = value;
  }

 protected:
  SpdyFrameWithHeaderBlockIR(SpdyStreamId stream_id,
                             SpdyHeaderBlock header_block);

 private:
  SpdyHeaderBlock header_block_;

  DISALLOW_COPY_AND_ASSIGN(SpdyFrameWithHeaderBlockIR);
};

class NET_EXPORT_PRIVATE SpdyDataIR
    : public NON_EXPORTED_BASE(SpdyFrameWithFinIR) {
 public:
  // Performs a deep copy on data.
  SpdyDataIR(SpdyStreamId stream_id, base::StringPiece data);

  // Performs a deep copy on data.
  SpdyDataIR(SpdyStreamId stream_id, const char* data);

  // Moves data into data_store_. Makes a copy if passed a non-movable string.
  SpdyDataIR(SpdyStreamId stream_id, std::string data);

  // Use in conjunction with SetDataShallow() for shallow-copy on data.
  explicit SpdyDataIR(SpdyStreamId stream_id);

  ~SpdyDataIR() override;

  const char* data() const { return data_; }
  size_t data_len() const { return data_len_; }

  bool padded() const { return padded_; }

  int padding_payload_len() const { return padding_payload_len_; }

  void set_padding_len(int padding_len) {
    DCHECK_GT(padding_len, 0);
    DCHECK_LE(padding_len, kPaddingSizePerFrame);
    padded_ = true;
    // The pad field takes one octet on the wire.
    padding_payload_len_ = padding_len - 1;
  }

  // Deep-copy of data (keep private copy).
  void SetDataDeep(base::StringPiece data) {
    data_store_.reset(new std::string(data.data(), data.size()));
    data_ = data_store_->data();
    data_len_ = data.size();
  }

  // Shallow-copy of data (do not keep private copy).
  void SetDataShallow(base::StringPiece data) {
    data_store_.reset();
    data_ = data.data();
    data_len_ = data.size();
  }

  // Use this method if we don't have a contiguous buffer and only
  // need a length.
  void SetDataShallow(size_t len) {
    data_store_.reset();
    data_ = nullptr;
    data_len_ = len;
  }

  void Visit(SpdyFrameVisitor* visitor) const override;

 private:
  // Used to store data that this SpdyDataIR should own.
  std::unique_ptr<std::string> data_store_;
  const char* data_;
  size_t data_len_;

  bool padded_;
  // padding_payload_len_ = desired padding length - len(padding length field).
  int padding_payload_len_;

  DISALLOW_COPY_AND_ASSIGN(SpdyDataIR);
};

class NET_EXPORT_PRIVATE SpdyRstStreamIR : public SpdyFrameWithStreamIdIR {
 public:
  SpdyRstStreamIR(SpdyStreamId stream_id, SpdyRstStreamStatus status);

  ~SpdyRstStreamIR() override;

  SpdyRstStreamStatus status() const {
    return status_;
  }
  void set_status(SpdyRstStreamStatus status) {
    status_ = status;
  }

  void Visit(SpdyFrameVisitor* visitor) const override;

 private:
  SpdyRstStreamStatus status_;

  DISALLOW_COPY_AND_ASSIGN(SpdyRstStreamIR);
};

class NET_EXPORT_PRIVATE SpdySettingsIR : public SpdyFrameIR {
 public:
  // Associates flags with a value.
  struct Value {
    Value() : persist_value(false),
              persisted(false),
              value(0) {}
    bool persist_value;
    bool persisted;
    int32_t value;
  };
  typedef std::map<SpdySettingsIds, Value> ValueMap;

  SpdySettingsIR();

  ~SpdySettingsIR() override;

  // Overwrites as appropriate.
  const ValueMap& values() const { return values_; }
  void AddSetting(SpdySettingsIds id,
                  bool persist_value,
                  bool persisted,
                  int32_t value) {
    values_[id].persist_value = persist_value;
    values_[id].persisted = persisted;
    values_[id].value = value;
  }

  bool clear_settings() const { return clear_settings_; }
  bool is_ack() const { return is_ack_; }
  void set_is_ack(bool is_ack) {
    is_ack_ = is_ack;
  }

  void Visit(SpdyFrameVisitor* visitor) const override;

 private:
  ValueMap values_;
  bool clear_settings_;
  bool is_ack_;

  DISALLOW_COPY_AND_ASSIGN(SpdySettingsIR);
};

class NET_EXPORT_PRIVATE SpdyPingIR : public SpdyFrameIR {
 public:
  explicit SpdyPingIR(SpdyPingId id) : id_(id), is_ack_(false) {}
  SpdyPingId id() const { return id_; }

  bool is_ack() const { return is_ack_; }
  void set_is_ack(bool is_ack) { is_ack_ = is_ack; }

  void Visit(SpdyFrameVisitor* visitor) const override;

 private:
  SpdyPingId id_;
  bool is_ack_;

  DISALLOW_COPY_AND_ASSIGN(SpdyPingIR);
};

class NET_EXPORT_PRIVATE SpdyGoAwayIR : public SpdyFrameIR {
 public:
  // References description, doesn't copy it, so description must outlast
  // this SpdyGoAwayIR.
  SpdyGoAwayIR(SpdyStreamId last_good_stream_id,
               SpdyGoAwayStatus status,
               base::StringPiece description);

  // References description, doesn't copy it, so description must outlast
  // this SpdyGoAwayIR.
  SpdyGoAwayIR(SpdyStreamId last_good_stream_id,
               SpdyGoAwayStatus status,
               const char* description);

  // Moves description into description_store_, so caller doesn't need to
  // keep description live after constructing this SpdyGoAwayIR.
  SpdyGoAwayIR(SpdyStreamId last_good_stream_id,
               SpdyGoAwayStatus status,
               std::string description);

  ~SpdyGoAwayIR() override;
  SpdyStreamId last_good_stream_id() const { return last_good_stream_id_; }
  void set_last_good_stream_id(SpdyStreamId last_good_stream_id) {
    DCHECK_LE(0u, last_good_stream_id);
    DCHECK_EQ(0u, last_good_stream_id & ~kStreamIdMask);
    last_good_stream_id_ = last_good_stream_id;
  }
  SpdyGoAwayStatus status() const { return status_; }
  void set_status(SpdyGoAwayStatus status) {
    // TODO(hkhalil): Check valid ranges of status?
    status_ = status;
  }

  const base::StringPiece& description() const { return description_; }

  void Visit(SpdyFrameVisitor* visitor) const override;

 private:
  SpdyStreamId last_good_stream_id_;
  SpdyGoAwayStatus status_;
  const std::string description_store_;
  const base::StringPiece description_;

  DISALLOW_COPY_AND_ASSIGN(SpdyGoAwayIR);
};

class NET_EXPORT_PRIVATE SpdyHeadersIR : public SpdyFrameWithHeaderBlockIR {
 public:
  explicit SpdyHeadersIR(SpdyStreamId stream_id)
      : SpdyHeadersIR(stream_id, SpdyHeaderBlock()) {}
  SpdyHeadersIR(SpdyStreamId stream_id, SpdyHeaderBlock header_block)
      : SpdyFrameWithHeaderBlockIR(stream_id, std::move(header_block)) {}

  void Visit(SpdyFrameVisitor* visitor) const override;

  bool has_priority() const { return has_priority_; }
  void set_has_priority(bool has_priority) { has_priority_ = has_priority; }
  int weight() const { return weight_; }
  void set_weight(int weight) { weight_ = weight; }
  SpdyStreamId parent_stream_id() const { return parent_stream_id_; }
  void set_parent_stream_id(SpdyStreamId id) { parent_stream_id_ = id; }
  bool exclusive() const { return exclusive_; }
  void set_exclusive(bool exclusive) { exclusive_ = exclusive; }
  bool padded() const { return padded_; }
  int padding_payload_len() const { return padding_payload_len_; }
  void set_padding_len(int padding_len) {
    DCHECK_GT(padding_len, 0);
    DCHECK_LE(padding_len, kPaddingSizePerFrame);
    padded_ = true;
    // The pad field takes one octet on the wire.
    padding_payload_len_ = padding_len - 1;
  }
  bool end_headers() const { return end_headers_; }
  void set_end_headers(bool end_headers) { end_headers_ = end_headers; }

 private:
  bool has_priority_ = false;
  int weight_ = kHttp2DefaultStreamWeight;
  SpdyStreamId parent_stream_id_ = 0;
  bool exclusive_ = false;
  bool padded_ = false;
  int padding_payload_len_ = 0;
  bool end_headers_ = false;

  DISALLOW_COPY_AND_ASSIGN(SpdyHeadersIR);
};

class NET_EXPORT_PRIVATE SpdyWindowUpdateIR : public SpdyFrameWithStreamIdIR {
 public:
  SpdyWindowUpdateIR(SpdyStreamId stream_id, int32_t delta)
      : SpdyFrameWithStreamIdIR(stream_id) {
    set_delta(delta);
  }
  int32_t delta() const { return delta_; }
  void set_delta(int32_t delta) {
    DCHECK_LE(0, delta);
    DCHECK_LE(delta, kSpdyMaximumWindowSize);
    delta_ = delta;
  }

  void Visit(SpdyFrameVisitor* visitor) const override;

 private:
  int32_t delta_;

  DISALLOW_COPY_AND_ASSIGN(SpdyWindowUpdateIR);
};

class NET_EXPORT_PRIVATE SpdyBlockedIR
    : public NON_EXPORTED_BASE(SpdyFrameWithStreamIdIR) {
 public:
  explicit SpdyBlockedIR(SpdyStreamId stream_id)
      : SpdyFrameWithStreamIdIR(stream_id) {}

  void Visit(SpdyFrameVisitor* visitor) const override;

 private:
  DISALLOW_COPY_AND_ASSIGN(SpdyBlockedIR);
};

class NET_EXPORT_PRIVATE SpdyPushPromiseIR : public SpdyFrameWithHeaderBlockIR {
 public:
  SpdyPushPromiseIR(SpdyStreamId stream_id, SpdyStreamId promised_stream_id)
      : SpdyPushPromiseIR(stream_id, promised_stream_id, SpdyHeaderBlock()) {}
  SpdyPushPromiseIR(SpdyStreamId stream_id,
                    SpdyStreamId promised_stream_id,
                    SpdyHeaderBlock header_block)
      : SpdyFrameWithHeaderBlockIR(stream_id, std::move(header_block)),
        promised_stream_id_(promised_stream_id),
        padded_(false),
        padding_payload_len_(0) {}
  SpdyStreamId promised_stream_id() const { return promised_stream_id_; }

  void Visit(SpdyFrameVisitor* visitor) const override;

  bool padded() const { return padded_; }
  int padding_payload_len() const { return padding_payload_len_; }
  void set_padding_len(int padding_len) {
    DCHECK_GT(padding_len, 0);
    DCHECK_LE(padding_len, kPaddingSizePerFrame);
    padded_ = true;
    // The pad field takes one octet on the wire.
    padding_payload_len_ = padding_len - 1;
  }

 private:
  SpdyStreamId promised_stream_id_;

  bool padded_;
  int padding_payload_len_;

  DISALLOW_COPY_AND_ASSIGN(SpdyPushPromiseIR);
};

class NET_EXPORT_PRIVATE SpdyContinuationIR : public SpdyFrameWithStreamIdIR {
 public:
  explicit SpdyContinuationIR(SpdyStreamId stream_id);
  ~SpdyContinuationIR() override;

  void Visit(SpdyFrameVisitor* visitor) const override;

  bool end_headers() const { return end_headers_; }
  void set_end_headers(bool end_headers) {end_headers_ = end_headers;}
  const std::string& encoding() const { return *encoding_; }
  void take_encoding(std::unique_ptr<std::string> encoding) {
    encoding_ = std::move(encoding);
  }

 private:
  std::unique_ptr<std::string> encoding_;
  bool end_headers_;
  DISALLOW_COPY_AND_ASSIGN(SpdyContinuationIR);
};

class NET_EXPORT_PRIVATE SpdyAltSvcIR : public SpdyFrameWithStreamIdIR {
 public:
  explicit SpdyAltSvcIR(SpdyStreamId stream_id);
  ~SpdyAltSvcIR() override;

  std::string origin() const { return origin_; }
  const SpdyAltSvcWireFormat::AlternativeServiceVector& altsvc_vector() const {
    return altsvc_vector_;
  }

  void set_origin(std::string origin) { origin_ = std::move(origin); }
  void add_altsvc(const SpdyAltSvcWireFormat::AlternativeService& altsvc) {
    altsvc_vector_.push_back(altsvc);
  }

  void Visit(SpdyFrameVisitor* visitor) const override;

 private:
  std::string origin_;
  SpdyAltSvcWireFormat::AlternativeServiceVector altsvc_vector_;
  DISALLOW_COPY_AND_ASSIGN(SpdyAltSvcIR);
};

class NET_EXPORT_PRIVATE SpdyPriorityIR : public SpdyFrameWithStreamIdIR {
 public:
  explicit SpdyPriorityIR(SpdyStreamId stream_id)
      : SpdyFrameWithStreamIdIR(stream_id),
        parent_stream_id_(0),
        weight_(1),
        exclusive_(false) {}
  SpdyPriorityIR(SpdyStreamId stream_id,
                 SpdyStreamId parent_stream_id,
                 int weight,
                 bool exclusive)
      : SpdyFrameWithStreamIdIR(stream_id),
        parent_stream_id_(parent_stream_id),
        weight_(weight),
        exclusive_(exclusive) {}
  SpdyStreamId parent_stream_id() const { return parent_stream_id_; }
  void set_parent_stream_id(SpdyStreamId id) { parent_stream_id_ = id; }
  int weight() const { return weight_; }
  void set_weight(uint8_t weight) { weight_ = weight; }
  bool exclusive() const { return exclusive_; }
  void set_exclusive(bool exclusive) { exclusive_ = exclusive; }

  void Visit(SpdyFrameVisitor* visitor) const override;

 private:
  SpdyStreamId parent_stream_id_;
  int weight_;
  bool exclusive_;
  DISALLOW_COPY_AND_ASSIGN(SpdyPriorityIR);
};

class SpdySerializedFrame {
 public:
  SpdySerializedFrame()
      : frame_(const_cast<char*>("")), size_(0), owns_buffer_(false) {}

  // Create a valid SpdySerializedFrame using a pre-created buffer.
  // If |owns_buffer| is true, this class takes ownership of the buffer and will
  // delete it on cleanup.  The buffer must have been created using new char[].
  // If |owns_buffer| is false, the caller retains ownership of the buffer and
  // is responsible for making sure the buffer outlives this frame.  In other
  // words, this class does NOT create a copy of the buffer.
  SpdySerializedFrame(char* data, size_t size, bool owns_buffer)
      : frame_(data), size_(size), owns_buffer_(owns_buffer) {}

  SpdySerializedFrame(SpdySerializedFrame&& other)
      : frame_(other.frame_),
        size_(other.size_),
        owns_buffer_(other.owns_buffer_) {
    // |other| is no longer responsible for the buffer.
    other.owns_buffer_ = false;
  }

  SpdySerializedFrame& operator=(SpdySerializedFrame&& other) {
    // Free buffer if necessary.
    if (owns_buffer_) {
      delete[] frame_;
    }
    // Take over |other|.
    frame_ = other.frame_;
    size_ = other.size_;
    owns_buffer_ = other.owns_buffer_;
    // |other| is no longer responsible for the buffer.
    other.owns_buffer_ = false;
    return *this;
  }

  ~SpdySerializedFrame() {
    if (owns_buffer_) {
      delete[] frame_;
    }
  }

  // Provides access to the frame bytes, which is a buffer containing the frame
  // packed as expected for sending over the wire.
  char* data() const { return frame_; }

  // Returns the actual size of the underlying buffer.
  size_t size() const { return size_; }

  // Returns a buffer containing the contents of the frame, of which the caller
  // takes ownership, and clears this SpdySerializedFrame.
  char* ReleaseBuffer() {
    char* buffer;
    if (owns_buffer_) {
      // If the buffer is owned, relinquish ownership to the caller.
      buffer = frame_;
      owns_buffer_ = false;
    } else {
      // Otherwise, we need to make a copy to give to the caller.
      buffer = new char[size_];
      memcpy(buffer, frame_, size_);
    }
    *this = SpdySerializedFrame();
    return buffer;
  }

 protected:
  char* frame_;

 private:
  size_t size_;
  bool owns_buffer_;
  DISALLOW_COPY_AND_ASSIGN(SpdySerializedFrame);
};

// This interface is for classes that want to process SpdyFrameIRs without
// having to know what type they are.  An instance of this interface can be
// passed to a SpdyFrameIR's Visit method, and the appropriate type-specific
// method of this class will be called.
class SpdyFrameVisitor {
 public:
  virtual void VisitRstStream(const SpdyRstStreamIR& rst_stream) = 0;
  virtual void VisitSettings(const SpdySettingsIR& settings) = 0;
  virtual void VisitPing(const SpdyPingIR& ping) = 0;
  virtual void VisitGoAway(const SpdyGoAwayIR& goaway) = 0;
  virtual void VisitHeaders(const SpdyHeadersIR& headers) = 0;
  virtual void VisitWindowUpdate(const SpdyWindowUpdateIR& window_update) = 0;
  virtual void VisitBlocked(const SpdyBlockedIR& blocked) = 0;
  virtual void VisitPushPromise(const SpdyPushPromiseIR& push_promise) = 0;
  virtual void VisitContinuation(const SpdyContinuationIR& continuation) = 0;
  virtual void VisitAltSvc(const SpdyAltSvcIR& altsvc) = 0;
  virtual void VisitPriority(const SpdyPriorityIR& priority) = 0;
  virtual void VisitData(const SpdyDataIR& data) = 0;

 protected:
  SpdyFrameVisitor() {}
  virtual ~SpdyFrameVisitor() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(SpdyFrameVisitor);
};

}  // namespace net

#endif  // NET_SPDY_SPDY_PROTOCOL_H_
