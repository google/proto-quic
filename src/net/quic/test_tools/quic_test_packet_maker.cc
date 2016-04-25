// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_test_packet_maker.h"

#include <list>

#include "net/quic/quic_framer.h"
#include "net/quic/quic_http_utils.h"
#include "net/quic/quic_utils.h"
#include "net/quic/test_tools/quic_test_utils.h"

using std::make_pair;

namespace net {
namespace test {

QuicTestPacketMaker::QuicTestPacketMaker(QuicVersion version,
                                         QuicConnectionId connection_id,
                                         MockClock* clock,
                                         const std::string& host)
    : version_(version),
      connection_id_(connection_id),
      clock_(clock),
      host_(host),
      spdy_request_framer_(HTTP2),
      spdy_response_framer_(HTTP2) {}

QuicTestPacketMaker::~QuicTestPacketMaker() {}

void QuicTestPacketMaker::set_hostname(const std::string& host) {
  host_.assign(host);
}

std::unique_ptr<QuicReceivedPacket> QuicTestPacketMaker::MakePingPacket(
    QuicPacketNumber num,
    bool include_version) {
  QuicPacketHeader header;
  header.public_header.connection_id = connection_id_;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = include_version;
  header.public_header.packet_number_length = PACKET_1BYTE_PACKET_NUMBER;
  header.packet_number = num;
  header.entropy_flag = false;
  header.fec_flag = false;
  header.fec_group = 0;

  QuicPingFrame ping;
  return std::unique_ptr<QuicReceivedPacket>(
      MakePacket(header, QuicFrame(ping)));
}

std::unique_ptr<QuicReceivedPacket> QuicTestPacketMaker::MakeRstPacket(
    QuicPacketNumber num,
    bool include_version,
    QuicStreamId stream_id,
    QuicRstStreamErrorCode error_code) {
  return MakeRstPacket(num, include_version, stream_id, error_code, 0);
}

std::unique_ptr<QuicReceivedPacket> QuicTestPacketMaker::MakeRstPacket(
    QuicPacketNumber num,
    bool include_version,
    QuicStreamId stream_id,
    QuicRstStreamErrorCode error_code,
    size_t bytes_written) {
  QuicPacketHeader header;
  header.public_header.connection_id = connection_id_;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = include_version;
  header.public_header.packet_number_length = PACKET_1BYTE_PACKET_NUMBER;
  header.packet_number = num;
  header.entropy_flag = false;
  header.fec_flag = false;
  header.fec_group = 0;

  QuicRstStreamFrame rst(stream_id, error_code, bytes_written);
  DVLOG(1) << "Adding frame: " << QuicFrame(&rst);
  return std::unique_ptr<QuicReceivedPacket>(
      MakePacket(header, QuicFrame(&rst)));
}

std::unique_ptr<QuicReceivedPacket> QuicTestPacketMaker::MakeAckAndRstPacket(
    QuicPacketNumber num,
    bool include_version,
    QuicStreamId stream_id,
    QuicRstStreamErrorCode error_code,
    QuicPacketNumber largest_received,
    QuicPacketNumber ack_least_unacked,
    QuicPacketNumber stop_least_unacked,
    bool send_feedback) {
  QuicPacketHeader header;
  header.public_header.connection_id = connection_id_;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = include_version;
  header.public_header.packet_number_length = PACKET_1BYTE_PACKET_NUMBER;
  header.packet_number = num;
  header.entropy_flag = false;
  header.fec_flag = false;
  header.fec_group = 0;

  QuicAckFrame ack(MakeAckFrame(largest_received));
  ack.ack_delay_time = QuicTime::Delta::Zero();
  for (QuicPacketNumber i = ack_least_unacked; i <= largest_received; ++i) {
    ack.received_packet_times.push_back(make_pair(i, clock_->Now()));
  }
  QuicFrames frames;
  frames.push_back(QuicFrame(&ack));
  DVLOG(1) << "Adding frame: " << frames[0];

  QuicStopWaitingFrame stop_waiting;
  stop_waiting.least_unacked = stop_least_unacked;
  frames.push_back(QuicFrame(&stop_waiting));
  DVLOG(1) << "Adding frame: " << frames[1];

  QuicRstStreamFrame rst(stream_id, error_code, 0);
  frames.push_back(QuicFrame(&rst));
  DVLOG(1) << "Adding frame: " << frames[2];

  QuicFramer framer(SupportedVersions(version_), clock_->Now(),
                    Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> packet(
      BuildUnsizedDataPacket(&framer, header, frames));
  char buffer[kMaxPacketSize];
  size_t encrypted_size = framer.EncryptPayload(ENCRYPTION_NONE, /*path_id=*/0u,
                                                header.packet_number, *packet,
                                                buffer, kMaxPacketSize);
  EXPECT_NE(0u, encrypted_size);
  QuicReceivedPacket encrypted(buffer, encrypted_size, QuicTime::Zero(), false);
  return std::unique_ptr<QuicReceivedPacket>(encrypted.Clone());
}

std::unique_ptr<QuicReceivedPacket>
QuicTestPacketMaker::MakeAckAndConnectionClosePacket(
    QuicPacketNumber num,
    bool include_version,
    QuicTime::Delta ack_delay_time,
    QuicPacketNumber largest_received,
    QuicPacketNumber least_unacked,
    QuicErrorCode quic_error,
    const std::string& quic_error_details) {
  QuicPacketHeader header;
  header.public_header.connection_id = connection_id_;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = include_version;
  header.public_header.packet_number_length = PACKET_1BYTE_PACKET_NUMBER;
  header.packet_number = num;
  header.entropy_flag = false;
  header.fec_flag = false;
  header.fec_group = 0;

  QuicAckFrame ack(MakeAckFrame(largest_received));
  ack.ack_delay_time = ack_delay_time;
  for (QuicPacketNumber i = least_unacked; i <= largest_received; ++i) {
    ack.received_packet_times.push_back(make_pair(i, clock_->Now()));
  }
  QuicFrames frames;
  frames.push_back(QuicFrame(&ack));
  DVLOG(1) << "Adding frame: " << frames[0];

  QuicStopWaitingFrame stop_waiting;
  stop_waiting.least_unacked = least_unacked;
  frames.push_back(QuicFrame(&stop_waiting));
  DVLOG(1) << "Adding frame: " << frames[1];

  QuicConnectionCloseFrame close;
  close.error_code = quic_error;
  close.error_details = quic_error_details;

  frames.push_back(QuicFrame(&close));
  DVLOG(1) << "Adding frame: " << frames[2];

  QuicFramer framer(SupportedVersions(version_), clock_->Now(),
                    Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> packet(
      BuildUnsizedDataPacket(&framer, header, frames));
  char buffer[kMaxPacketSize];
  size_t encrypted_size = framer.EncryptPayload(ENCRYPTION_NONE, /*path_id=*/0u,
                                                header.packet_number, *packet,
                                                buffer, kMaxPacketSize);
  EXPECT_NE(0u, encrypted_size);
  QuicReceivedPacket encrypted(buffer, encrypted_size, clock_->Now(), false);
  return std::unique_ptr<QuicReceivedPacket>(encrypted.Clone());
}

std::unique_ptr<QuicReceivedPacket>
QuicTestPacketMaker::MakeConnectionClosePacket(QuicPacketNumber num) {
  QuicPacketHeader header;
  header.public_header.connection_id = connection_id_;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.public_header.packet_number_length = PACKET_1BYTE_PACKET_NUMBER;
  header.packet_number = num;
  header.entropy_flag = false;
  header.fec_flag = false;
  header.fec_group = 0;

  QuicConnectionCloseFrame close;
  close.error_code = QUIC_CRYPTO_VERSION_NOT_SUPPORTED;
  close.error_details = "Time to panic!";
  return std::unique_ptr<QuicReceivedPacket>(
      MakePacket(header, QuicFrame(&close)));
}

std::unique_ptr<QuicReceivedPacket> QuicTestPacketMaker::MakeGoAwayPacket(
    QuicPacketNumber num,
    QuicErrorCode error_code,
    std::string reason_phrase) {
  QuicPacketHeader header;
  header.public_header.connection_id = connection_id_;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.public_header.packet_number_length = PACKET_1BYTE_PACKET_NUMBER;
  header.packet_number = num;
  header.entropy_flag = false;
  header.fec_flag = false;
  header.fec_group = 0;

  QuicGoAwayFrame goaway;
  goaway.error_code = error_code;
  goaway.last_good_stream_id = 0;
  goaway.reason_phrase = reason_phrase;
  return std::unique_ptr<QuicReceivedPacket>(
      MakePacket(header, QuicFrame(&goaway)));
}

// Sets both least_unacked fields in stop waiting frame and ack frame
// to be |least_unacked|.
std::unique_ptr<QuicReceivedPacket> QuicTestPacketMaker::MakeAckPacket(
    QuicPacketNumber packet_number,
    QuicPacketNumber largest_received,
    QuicPacketNumber least_unacked,
    bool send_feedback) {
  return MakeAckPacket(packet_number, largest_received, least_unacked,
                       least_unacked, send_feedback);
}

std::unique_ptr<QuicReceivedPacket> QuicTestPacketMaker::MakeAckPacket(
    QuicPacketNumber packet_number,
    QuicPacketNumber largest_received,
    QuicPacketNumber ack_least_unacked,
    QuicPacketNumber stop_least_unacked,
    bool send_feedback) {
  QuicPacketHeader header;
  header.public_header.connection_id = connection_id_;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.public_header.packet_number_length = PACKET_1BYTE_PACKET_NUMBER;
  header.packet_number = packet_number;
  header.entropy_flag = false;
  header.fec_flag = false;
  header.fec_group = 0;

  QuicAckFrame ack(MakeAckFrame(largest_received));
  ack.ack_delay_time = QuicTime::Delta::Zero();
  for (QuicPacketNumber i = ack_least_unacked; i <= largest_received; ++i) {
    ack.received_packet_times.push_back(make_pair(i, clock_->Now()));
  }

  QuicFramer framer(SupportedVersions(version_), clock_->Now(),
                    Perspective::IS_CLIENT);
  QuicFrames frames;
  frames.push_back(QuicFrame(&ack));

  QuicStopWaitingFrame stop_waiting;
  stop_waiting.least_unacked = stop_least_unacked;
  frames.push_back(QuicFrame(&stop_waiting));

  std::unique_ptr<QuicPacket> packet(
      BuildUnsizedDataPacket(&framer, header, frames));
  char buffer[kMaxPacketSize];
  size_t encrypted_size = framer.EncryptPayload(ENCRYPTION_NONE, /*path_id=*/0u,
                                                header.packet_number, *packet,
                                                buffer, kMaxPacketSize);
  EXPECT_NE(0u, encrypted_size);
  QuicReceivedPacket encrypted(buffer, encrypted_size, clock_->Now(), false);
  return std::unique_ptr<QuicReceivedPacket>(encrypted.Clone());
}

// Returns a newly created packet to send kData on stream 1.
std::unique_ptr<QuicReceivedPacket> QuicTestPacketMaker::MakeDataPacket(
    QuicPacketNumber packet_number,
    QuicStreamId stream_id,
    bool should_include_version,
    bool fin,
    QuicStreamOffset offset,
    base::StringPiece data) {
  InitializeHeader(packet_number, should_include_version);
  QuicStreamFrame frame(stream_id, fin, offset, data);
  return MakePacket(header_, QuicFrame(&frame));
}

std::unique_ptr<QuicReceivedPacket> QuicTestPacketMaker::MakeAckAndDataPacket(
    QuicPacketNumber packet_number,
    bool include_version,
    QuicStreamId stream_id,
    QuicPacketNumber largest_received,
    QuicPacketNumber least_unacked,
    bool fin,
    QuicStreamOffset offset,
    base::StringPiece data) {
  InitializeHeader(packet_number, include_version);

  QuicAckFrame ack(MakeAckFrame(largest_received));
  ack.ack_delay_time = QuicTime::Delta::Zero();
  for (QuicPacketNumber i = least_unacked; i <= largest_received; ++i) {
    ack.received_packet_times.push_back(make_pair(i, clock_->Now()));
  }
  QuicFrames frames;
  frames.push_back(QuicFrame(&ack));

  QuicStopWaitingFrame stop_waiting;
  stop_waiting.least_unacked = least_unacked;
  frames.push_back(QuicFrame(&stop_waiting));

  QuicStreamFrame stream_frame(stream_id, fin, offset, data);
  frames.push_back(QuicFrame(&stream_frame));

  return MakeMultipleFramesPacket(header_, frames);
}

std::unique_ptr<QuicReceivedPacket>
QuicTestPacketMaker::MakeRequestHeadersPacket(
    QuicPacketNumber packet_number,
    QuicStreamId stream_id,
    bool should_include_version,
    bool fin,
    SpdyPriority priority,
    const SpdyHeaderBlock& headers,
    size_t* spdy_headers_frame_length) {
  return MakeRequestHeadersPacket(packet_number, stream_id,
                                  should_include_version, fin, priority,
                                  headers, spdy_headers_frame_length, nullptr);
}

// If |offset| is provided, will use the value when creating the packet.
// Will also update the value after packet creation.
std::unique_ptr<QuicReceivedPacket>
QuicTestPacketMaker::MakeRequestHeadersPacket(QuicPacketNumber packet_number,
                                              QuicStreamId stream_id,
                                              bool should_include_version,
                                              bool fin,
                                              SpdyPriority priority,
                                              const SpdyHeaderBlock& headers,
                                              size_t* spdy_headers_frame_length,
                                              QuicStreamOffset* offset) {
  InitializeHeader(packet_number, should_include_version);
  SpdySerializedFrame spdy_frame;
  if (spdy_request_framer_.protocol_version() == SPDY3) {
    SpdySynStreamIR syn_stream(stream_id);
    syn_stream.set_header_block(headers);
    syn_stream.set_fin(fin);
    syn_stream.set_priority(priority);
    spdy_frame = spdy_request_framer_.SerializeSynStream(syn_stream);
  } else {
    SpdyHeadersIR headers_frame(stream_id);
    headers_frame.set_header_block(headers);
    headers_frame.set_fin(fin);
    headers_frame.set_priority(priority);
    headers_frame.set_has_priority(true);
    spdy_frame = spdy_request_framer_.SerializeFrame(headers_frame);
  }
  if (spdy_headers_frame_length) {
    *spdy_headers_frame_length = spdy_frame.size();
  }
  if (offset != nullptr) {
    QuicStreamFrame frame(
        kHeadersStreamId, false, *offset,
        base::StringPiece(spdy_frame.data(), spdy_frame.size()));
    *offset += spdy_frame.size();
    return MakePacket(header_, QuicFrame(&frame));
  } else {
    QuicStreamFrame frame(
        kHeadersStreamId, false, 0,
        base::StringPiece(spdy_frame.data(), spdy_frame.size()));

    return MakePacket(header_, QuicFrame(&frame));
  }
}

// Convenience method for calling MakeRequestHeadersPacket with nullptr for
// |spdy_headers_frame_length|.
std::unique_ptr<QuicReceivedPacket>
QuicTestPacketMaker::MakeRequestHeadersPacketWithOffsetTracking(
    QuicPacketNumber packet_number,
    QuicStreamId stream_id,
    bool should_include_version,
    bool fin,
    SpdyPriority priority,
    const SpdyHeaderBlock& headers,
    QuicStreamOffset* offset) {
  return MakeRequestHeadersPacket(packet_number, stream_id,
                                  should_include_version, fin, priority,
                                  headers, nullptr, offset);
}

// If |offset| is provided, will use the value when creating the packet.
// Will also update the value after packet creation.
std::unique_ptr<QuicReceivedPacket>
QuicTestPacketMaker::MakeResponseHeadersPacket(
    QuicPacketNumber packet_number,
    QuicStreamId stream_id,
    bool should_include_version,
    bool fin,
    const SpdyHeaderBlock& headers,
    size_t* spdy_headers_frame_length,
    QuicStreamOffset* offset) {
  InitializeHeader(packet_number, should_include_version);
  SpdySerializedFrame spdy_frame;
  if (spdy_response_framer_.protocol_version() == SPDY3) {
    SpdySynReplyIR syn_reply(stream_id);
    syn_reply.set_header_block(headers);
    syn_reply.set_fin(fin);
    spdy_frame = spdy_response_framer_.SerializeSynReply(syn_reply);
  } else {
    SpdyHeadersIR headers_frame(stream_id);
    headers_frame.set_header_block(headers);
    headers_frame.set_fin(fin);
    spdy_frame = spdy_response_framer_.SerializeFrame(headers_frame);
  }
  if (spdy_headers_frame_length) {
    *spdy_headers_frame_length = spdy_frame.size();
  }
  if (offset != nullptr) {
    QuicStreamFrame frame(
        kHeadersStreamId, false, *offset,
        base::StringPiece(spdy_frame.data(), spdy_frame.size()));
    *offset += spdy_frame.size();
    return MakePacket(header_, QuicFrame(&frame));
  } else {
    QuicStreamFrame frame(
        kHeadersStreamId, false, 0,
        base::StringPiece(spdy_frame.data(), spdy_frame.size()));
    return MakePacket(header_, QuicFrame(&frame));
  }
}

std::unique_ptr<QuicReceivedPacket>
QuicTestPacketMaker::MakeResponseHeadersPacket(
    QuicPacketNumber packet_number,
    QuicStreamId stream_id,
    bool should_include_version,
    bool fin,
    const SpdyHeaderBlock& headers,
    size_t* spdy_headers_frame_length) {
  return MakeResponseHeadersPacket(packet_number, stream_id,
                                   should_include_version, fin, headers,
                                   spdy_headers_frame_length, nullptr);
}

// Convenience method for calling MakeResponseHeadersPacket with nullptr for
// |spdy_headers_frame_length|.
std::unique_ptr<QuicReceivedPacket>
QuicTestPacketMaker::MakeResponseHeadersPacketWithOffsetTracking(
    QuicPacketNumber packet_number,
    QuicStreamId stream_id,
    bool should_include_version,
    bool fin,
    const SpdyHeaderBlock& headers,
    QuicStreamOffset* offset) {
  return MakeResponseHeadersPacket(packet_number, stream_id,
                                   should_include_version, fin, headers,
                                   nullptr, offset);
}

SpdyHeaderBlock QuicTestPacketMaker::GetRequestHeaders(
    const std::string& method,
    const std::string& scheme,
    const std::string& path) {
  SpdyHeaderBlock headers;
  headers[":method"] = method;
  headers[":authority"] = host_;
  headers[":scheme"] = scheme;
  headers[":path"] = path;
  return headers;
}

SpdyHeaderBlock QuicTestPacketMaker::GetResponseHeaders(
    const std::string& status) {
  SpdyHeaderBlock headers;
  headers[":status"] = status;
  headers["content-type"] = "text/plain";
  return headers;
}

SpdyHeaderBlock QuicTestPacketMaker::GetResponseHeaders(
    const std::string& status,
    const std::string& alt_svc) {
  SpdyHeaderBlock headers;
  headers[":status"] = status;
  headers["Alt-Svc"] = alt_svc;
  headers["content-type"] = "text/plain";
  return headers;
}

std::unique_ptr<QuicReceivedPacket> QuicTestPacketMaker::MakePacket(
    const QuicPacketHeader& header,
    const QuicFrame& frame) {
  QuicFrames frames;
  frames.push_back(frame);
  return MakeMultipleFramesPacket(header, frames);
}

std::unique_ptr<QuicReceivedPacket>
QuicTestPacketMaker::MakeMultipleFramesPacket(const QuicPacketHeader& header,
                                              const QuicFrames& frames) {
  QuicFramer framer(SupportedVersions(version_), clock_->Now(),
                    Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> packet(
      BuildUnsizedDataPacket(&framer, header, frames));
  char buffer[kMaxPacketSize];
  size_t encrypted_size = framer.EncryptPayload(ENCRYPTION_NONE, /*path_id=*/0u,
                                                header.packet_number, *packet,
                                                buffer, kMaxPacketSize);
  EXPECT_NE(0u, encrypted_size);
  QuicReceivedPacket encrypted(buffer, encrypted_size, clock_->Now(), false);
  return std::unique_ptr<QuicReceivedPacket>(encrypted.Clone());
}

void QuicTestPacketMaker::InitializeHeader(QuicPacketNumber packet_number,
                                           bool should_include_version) {
  header_.public_header.connection_id = connection_id_;
  header_.public_header.reset_flag = false;
  header_.public_header.version_flag = should_include_version;
  header_.public_header.packet_number_length = PACKET_1BYTE_PACKET_NUMBER;
  header_.packet_number = packet_number;
  header_.fec_group = 0;
  header_.entropy_flag = false;
  header_.fec_flag = false;
}

}  // namespace test
}  // namespace net
