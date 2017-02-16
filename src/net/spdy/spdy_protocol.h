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

#include <iosfwd>
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

// Max stream id.
const SpdyStreamId kMaxStreamId = 0x7fffffff;

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

// The HTTP/2 connection preface, which must be the first bytes sent by the
// client upon starting an HTTP/2 connection, and which must be followed by a
// SETTINGS frame.  Note that even though |kHttp2ConnectionHeaderPrefix| is
// defined as a string literal with a null terminator, the actual connection
// preface is only the first |kHttp2ConnectionHeaderPrefixSize| bytes, which
// excludes the null terminator.
NET_EXPORT_PRIVATE extern const char* const kHttp2ConnectionHeaderPrefix;
const int kHttp2ConnectionHeaderPrefixSize = 24;

// Wire values for HTTP2 frame types.
enum SpdyFrameType : uint8_t {
  DATA = 0x00,
  HEADERS = 0x01,
  PRIORITY = 0x02,
  RST_STREAM = 0x03,
  SETTINGS = 0x04,
  PUSH_PROMISE = 0x05,
  PING = 0x06,
  GOAWAY = 0x07,
  WINDOW_UPDATE = 0x08,
  CONTINUATION = 0x09,
  // ALTSVC is a public extension.
  ALTSVC = 0x0a,
  // BLOCKED was never standardized, and should be deleted.
  BLOCKED = 0x0b,
  MAX_FRAME_TYPE = BLOCKED,
  // The specific value of EXTENSION is meaningless; it is a placeholder used
  // within SpdyFramer's state machine when handling unknown frames via an
  // extension API.
  EXTENSION = 0xff
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

// Wire values of HTTP/2 setting identifiers.
enum SpdySettingsIds : uint16_t {
  // HPACK header table maximum size.
  SETTINGS_HEADER_TABLE_SIZE = 0x1,
  SETTINGS_MIN = SETTINGS_HEADER_TABLE_SIZE,
  // Whether or not server push (PUSH_PROMISE) is enabled.
  SETTINGS_ENABLE_PUSH = 0x2,
  // The maximum number of simultaneous live streams in each direction.
  SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
  // Initial window size in bytes
  SETTINGS_INITIAL_WINDOW_SIZE = 0x4,
  // The size of the largest frame payload that a receiver is willing to accept.
  SETTINGS_MAX_FRAME_SIZE = 0x5,
  // The maximum size of header list that the sender is prepared to accept.
  SETTINGS_MAX_HEADER_LIST_SIZE = 0x6,
  SETTINGS_MAX = SETTINGS_MAX_HEADER_LIST_SIZE
};

// This explicit operator is needed, otherwise compiler finds
// overloaded operator to be ambiguous.
NET_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& out,
                                            SpdySettingsIds id);

using SettingsMap = std::map<SpdySettingsIds, uint32_t>;

// HTTP/2 error codes, RFC 7540 Section 7.
enum SpdyErrorCode : uint32_t {
  ERROR_CODE_NO_ERROR = 0x0,
  ERROR_CODE_PROTOCOL_ERROR = 0x1,
  ERROR_CODE_INTERNAL_ERROR = 0x2,
  ERROR_CODE_FLOW_CONTROL_ERROR = 0x3,
  ERROR_CODE_SETTINGS_TIMEOUT = 0x4,
  ERROR_CODE_STREAM_CLOSED = 0x5,
  ERROR_CODE_FRAME_SIZE_ERROR = 0x6,
  ERROR_CODE_REFUSED_STREAM = 0x7,
  ERROR_CODE_CANCEL = 0x8,
  ERROR_CODE_COMPRESSION_ERROR = 0x9,
  ERROR_CODE_CONNECT_ERROR = 0xa,
  ERROR_CODE_ENHANCE_YOUR_CALM = 0xb,
  ERROR_CODE_INADEQUATE_SECURITY = 0xc,
  ERROR_CODE_HTTP_1_1_REQUIRED = 0xd,
  ERROR_CODE_MAX = ERROR_CODE_HTTP_1_1_REQUIRED
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

// Returns true if a given on-the-wire enumeration of a frame type is defined
// in a standardized HTTP/2 specification, false otherwise.
NET_EXPORT_PRIVATE bool IsDefinedFrameType(uint8_t frame_type_field);

// Parses a frame type from an on-the-wire enumeration.
// Behavior is undefined for invalid frame type fields; consumers should first
// use IsValidFrameType() to verify validity of frame type fields.
NET_EXPORT_PRIVATE SpdyFrameType ParseFrameType(uint8_t frame_type_field);

// (HTTP/2) All standard frame types except WINDOW_UPDATE are
// (stream-specific xor connection-level). Returns false iff we know
// the given frame type does not align with the given streamID.
NET_EXPORT_PRIVATE bool IsValidHTTP2FrameStreamId(
    SpdyStreamId current_frame_stream_id,
    SpdyFrameType frame_type_field);

// Serialize |frame_type| to string for logging/debugging.
const char* FrameTypeToString(SpdyFrameType frame_type);

// If |wire_setting_id| is the on-the-wire representation of a defined SETTINGS
// parameter, parse it to |*setting_id| and return true.
NET_EXPORT_PRIVATE bool ParseSettingsId(uint16_t wire_setting_id,
                                        SpdySettingsIds* setting_id);

// Return if |id| corresponds to a defined setting;
// stringify |id| to |*settings_id_string| regardless.
NET_EXPORT_PRIVATE bool SettingsIdToString(SpdySettingsIds id,
                                           const char** settings_id_string);

// Parse |wire_error_code| to a SpdyErrorCode.
// Treat unrecognized error codes as INTERNAL_ERROR
// as recommended by the HTTP/2 specification.
NET_EXPORT_PRIVATE SpdyErrorCode ParseErrorCode(uint32_t wire_error_code);

// Serialize RST_STREAM or GOAWAY frame error code to string
// for logging/debugging.
const char* ErrorCodeToString(SpdyErrorCode error_code);

// Number of octets in the frame header.
const size_t kFrameHeaderSize = 9;
// Size, in bytes, of the data frame header.
const size_t kDataFrameMinimumSize = kFrameHeaderSize;
// Maximum possible configurable size of a frame in octets.
const size_t kMaxFrameSizeLimit = kSpdyMaxFrameSizeLimit + kFrameHeaderSize;
// Size of a header block size field. Valid only for SPDY 3.
const size_t kSizeOfSizeField = sizeof(uint32_t);
// Per-header overhead for block size accounting in bytes.
const size_t kPerHeaderOverhead = 32;
// Initial window size for a stream in bytes.
const int32_t kInitialStreamWindowSize = 64 * 1024 - 1;
// Initial window size for a session in bytes.
const int32_t kInitialSessionWindowSize = 64 * 1024 - 1;
// The NPN string for HTTP2, "h2".
extern const char* const kHttp2Npn;

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
  SpdyRstStreamIR(SpdyStreamId stream_id, SpdyErrorCode error_code);

  ~SpdyRstStreamIR() override;

  SpdyErrorCode error_code() const { return error_code_; }
  void set_error_code(SpdyErrorCode error_code) { error_code_ = error_code; }

  void Visit(SpdyFrameVisitor* visitor) const override;

 private:
  SpdyErrorCode error_code_;

  DISALLOW_COPY_AND_ASSIGN(SpdyRstStreamIR);
};

class NET_EXPORT_PRIVATE SpdySettingsIR : public SpdyFrameIR {
 public:
  SpdySettingsIR();
  ~SpdySettingsIR() override;

  // Overwrites as appropriate.
  const SettingsMap& values() const { return values_; }
  void AddSetting(SpdySettingsIds id, int32_t value) { values_[id] = value; }

  bool is_ack() const { return is_ack_; }
  void set_is_ack(bool is_ack) {
    is_ack_ = is_ack;
  }

  void Visit(SpdyFrameVisitor* visitor) const override;

 private:
  SettingsMap values_;
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
               SpdyErrorCode error_code,
               base::StringPiece description);

  // References description, doesn't copy it, so description must outlast
  // this SpdyGoAwayIR.
  SpdyGoAwayIR(SpdyStreamId last_good_stream_id,
               SpdyErrorCode error_code,
               const char* description);

  // Moves description into description_store_, so caller doesn't need to
  // keep description live after constructing this SpdyGoAwayIR.
  SpdyGoAwayIR(SpdyStreamId last_good_stream_id,
               SpdyErrorCode error_code,
               std::string description);

  ~SpdyGoAwayIR() override;
  SpdyStreamId last_good_stream_id() const { return last_good_stream_id_; }
  void set_last_good_stream_id(SpdyStreamId last_good_stream_id) {
    DCHECK_LE(0u, last_good_stream_id);
    DCHECK_EQ(0u, last_good_stream_id & ~kStreamIdMask);
    last_good_stream_id_ = last_good_stream_id;
  }
  SpdyErrorCode error_code() const { return error_code_; }
  void set_error_code(SpdyErrorCode error_code) {
    // TODO(hkhalil): Check valid ranges of error_code?
    error_code_ = error_code;
  }

  const base::StringPiece& description() const { return description_; }

  void Visit(SpdyFrameVisitor* visitor) const override;

 private:
  SpdyStreamId last_good_stream_id_;
  SpdyErrorCode error_code_;
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

  // Returns the estimate of dynamically allocated memory in bytes.
  size_t EstimateMemoryUsage() const { return owns_buffer_ ? size_ : 0; }

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
