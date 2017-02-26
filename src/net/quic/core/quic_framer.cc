// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_framer.h"

#include <cstdint>
#include <memory>

#include "base/compiler_specific.h"
#include "net/quic/core/crypto/crypto_framer.h"
#include "net/quic/core/crypto/crypto_handshake_message.h"
#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/crypto/null_decrypter.h"
#include "net/quic/core/crypto/null_encrypter.h"
#include "net/quic/core/crypto/quic_decrypter.h"
#include "net/quic/core/crypto/quic_encrypter.h"
#include "net/quic/core/quic_data_reader.h"
#include "net/quic/core/quic_data_writer.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_socket_address_coder.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_aligned.h"
#include "net/quic/platform/api/quic_bug_tracker.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/quic/platform/api/quic_map_util.h"
#include "net/quic/platform/api/quic_ptr_util.h"

using base::StringPiece;
using std::string;

namespace net {

namespace {

#define ENDPOINT \
  (perspective_ == Perspective::IS_SERVER ? "Server: " : "Client: ")

// Mask to select the lowest 48 bits of a packet number.
const QuicPacketNumber k6ByteSequenceNumberMask = UINT64_C(0x0000FFFFFFFFFFFF);
const QuicPacketNumber k4ByteSequenceNumberMask = UINT64_C(0x00000000FFFFFFFF);
const QuicPacketNumber k2ByteSequenceNumberMask = UINT64_C(0x000000000000FFFF);
const QuicPacketNumber k1ByteSequenceNumberMask = UINT64_C(0x00000000000000FF);

// Number of bits the packet number length bits are shifted from the right
// edge of the public header.
const uint8_t kPublicHeaderSequenceNumberShift = 4;

// New Frame Types, QUIC v. >= 10:
// There are two interpretations for the Frame Type byte in the QUIC protocol,
// resulting in two Frame Types: Special Frame Types and Regular Frame Types.
//
// Regular Frame Types use the Frame Type byte simply. Currently defined
// Regular Frame Types are:
// Padding            : 0b 00000000 (0x00)
// ResetStream        : 0b 00000001 (0x01)
// ConnectionClose    : 0b 00000010 (0x02)
// GoAway             : 0b 00000011 (0x03)
// WindowUpdate       : 0b 00000100 (0x04)
// Blocked            : 0b 00000101 (0x05)
//
// Special Frame Types encode both a Frame Type and corresponding flags
// all in the Frame Type byte. Currently defined Special Frame Types are:
// Stream             : 0b 1xxxxxxx
// Ack                : 0b 01xxxxxx
//
// Semantics of the flag bits above (the x bits) depends on the frame type.

// Masks to determine if the frame type is a special use
// and for specific special frame types.
const uint8_t kQuicFrameTypeSpecialMask = 0xE0;  // 0b 11100000
const uint8_t kQuicFrameTypeStreamMask = 0x80;
const uint8_t kQuicFrameTypeAckMask = 0x40;

// Stream frame relative shifts and masks for interpreting the stream flags.
// StreamID may be 1, 2, 3, or 4 bytes.
const uint8_t kQuicStreamIdShift = 2;
const uint8_t kQuicStreamIDLengthMask = 0x03;

// Offset may be 0, 2, 3, 4, 5, 6, 7, 8 bytes.
const uint8_t kQuicStreamOffsetShift = 3;
const uint8_t kQuicStreamOffsetMask = 0x07;

// Data length may be 0 or 2 bytes.
const uint8_t kQuicStreamDataLengthShift = 1;
const uint8_t kQuicStreamDataLengthMask = 0x01;

// Fin bit may be set or not.
const uint8_t kQuicStreamFinShift = 1;
const uint8_t kQuicStreamFinMask = 0x01;

// packet number size shift used in AckFrames.
const uint8_t kQuicSequenceNumberLengthShift = 2;

// Acks may have only one ack block.
const uint8_t kQuicHasMultipleAckBlocksMask = 0x01;
const uint8_t kQuicHasMultipleAckBlocksShift = 1;

// Returns the absolute value of the difference between |a| and |b|.
QuicPacketNumber Delta(QuicPacketNumber a, QuicPacketNumber b) {
  // Since these are unsigned numbers, we can't just return abs(a - b)
  if (a < b) {
    return b - a;
  }
  return a - b;
}

QuicPacketNumber ClosestTo(QuicPacketNumber target,
                           QuicPacketNumber a,
                           QuicPacketNumber b) {
  return (Delta(target, a) < Delta(target, b)) ? a : b;
}

QuicPacketNumberLength ReadSequenceNumberLength(uint8_t flags) {
  switch (flags & PACKET_FLAGS_6BYTE_PACKET) {
    case PACKET_FLAGS_6BYTE_PACKET:
      return PACKET_6BYTE_PACKET_NUMBER;
    case PACKET_FLAGS_4BYTE_PACKET:
      return PACKET_4BYTE_PACKET_NUMBER;
    case PACKET_FLAGS_2BYTE_PACKET:
      return PACKET_2BYTE_PACKET_NUMBER;
    case PACKET_FLAGS_1BYTE_PACKET:
      return PACKET_1BYTE_PACKET_NUMBER;
    default:
      QUIC_BUG << "Unreachable case statement.";
      return PACKET_6BYTE_PACKET_NUMBER;
  }
}

}  // namespace

QuicFramer::QuicFramer(const QuicVersionVector& supported_versions,
                       QuicTime creation_time,
                       Perspective perspective)
    : visitor_(nullptr),
      error_(QUIC_NO_ERROR),
      last_packet_number_(0),
      largest_packet_number_(0),
      last_serialized_connection_id_(0),
      last_version_tag_(0),
      supported_versions_(supported_versions),
      decrypter_level_(ENCRYPTION_NONE),
      alternative_decrypter_level_(ENCRYPTION_NONE),
      alternative_decrypter_latch_(false),
      perspective_(perspective),
      validate_flags_(true),
      creation_time_(creation_time),
      last_timestamp_(QuicTime::Delta::Zero()) {
  DCHECK(!supported_versions.empty());
  quic_version_ = supported_versions_[0];
  decrypter_ = QuicMakeUnique<NullDecrypter>(perspective);
  encrypter_[ENCRYPTION_NONE] = QuicMakeUnique<NullEncrypter>(perspective);
}

QuicFramer::~QuicFramer() {}

// static
size_t QuicFramer::GetMinStreamFrameSize(QuicStreamId stream_id,
                                         QuicStreamOffset offset,
                                         bool last_frame_in_packet) {
  return kQuicFrameTypeSize + GetStreamIdSize(stream_id) +
         GetStreamOffsetSize(offset) +
         (last_frame_in_packet ? 0 : kQuicStreamPayloadLengthSize);
}

// static
size_t QuicFramer::GetMinAckFrameSize(
    QuicVersion version,
    QuicPacketNumberLength largest_observed_length) {
  size_t min_size = kQuicFrameTypeSize + largest_observed_length +
                    kQuicDeltaTimeLargestObservedSize;
  return min_size + kQuicNumTimestampsSize;
}

// static
size_t QuicFramer::GetStopWaitingFrameSize(
    QuicVersion version,
    QuicPacketNumberLength packet_number_length) {
  size_t min_size = kQuicFrameTypeSize + packet_number_length;
  return min_size;
}

// static
size_t QuicFramer::GetRstStreamFrameSize() {
  return kQuicFrameTypeSize + kQuicMaxStreamIdSize + kQuicMaxStreamOffsetSize +
         kQuicErrorCodeSize;
}

// static
size_t QuicFramer::GetMinConnectionCloseFrameSize() {
  return kQuicFrameTypeSize + kQuicErrorCodeSize + kQuicErrorDetailsLengthSize;
}

// static
size_t QuicFramer::GetMinGoAwayFrameSize() {
  return kQuicFrameTypeSize + kQuicErrorCodeSize + kQuicErrorDetailsLengthSize +
         kQuicMaxStreamIdSize;
}

// static
size_t QuicFramer::GetWindowUpdateFrameSize() {
  return kQuicFrameTypeSize + kQuicMaxStreamIdSize + kQuicMaxStreamOffsetSize;
}

// static
size_t QuicFramer::GetBlockedFrameSize() {
  return kQuicFrameTypeSize + kQuicMaxStreamIdSize;
}

// static
size_t QuicFramer::GetPathCloseFrameSize() {
  return kQuicFrameTypeSize + kQuicPathIdSize;
}

// static
size_t QuicFramer::GetStreamIdSize(QuicStreamId stream_id) {
  // Sizes are 1 through 4 bytes.
  for (int i = 1; i <= 4; ++i) {
    stream_id >>= 8;
    if (stream_id == 0) {
      return i;
    }
  }
  QUIC_BUG << "Failed to determine StreamIDSize.";
  return 4;
}

// static
size_t QuicFramer::GetStreamOffsetSize(QuicStreamOffset offset) {
  // 0 is a special case.
  if (offset == 0) {
    return 0;
  }
  // 2 through 8 are the remaining sizes.
  offset >>= 8;
  for (int i = 2; i <= 8; ++i) {
    offset >>= 8;
    if (offset == 0) {
      return i;
    }
  }
  QUIC_BUG << "Failed to determine StreamOffsetSize.";
  return 8;
}

// static
size_t QuicFramer::GetVersionNegotiationPacketSize(size_t number_versions) {
  return kPublicFlagsSize + PACKET_8BYTE_CONNECTION_ID +
         number_versions * kQuicVersionSize;
}

bool QuicFramer::IsSupportedVersion(const QuicVersion version) const {
  for (size_t i = 0; i < supported_versions_.size(); ++i) {
    if (version == supported_versions_[i]) {
      return true;
    }
  }
  return false;
}

size_t QuicFramer::GetSerializedFrameLength(
    const QuicFrame& frame,
    size_t free_bytes,
    bool first_frame,
    bool last_frame,
    QuicPacketNumberLength packet_number_length) {
  // Prevent a rare crash reported in b/19458523.
  if ((frame.type == STREAM_FRAME || frame.type == ACK_FRAME) &&
      frame.stream_frame == nullptr) {
    QUIC_BUG << "Cannot compute the length of a null frame. "
             << "type:" << frame.type << "free_bytes:" << free_bytes
             << " first_frame:" << first_frame << " last_frame:" << last_frame
             << " seq num length:" << packet_number_length;
    set_error(QUIC_INTERNAL_ERROR);
    visitor_->OnError(this);
    return 0;
  }
  if (frame.type == PADDING_FRAME) {
    if (frame.padding_frame.num_padding_bytes == -1) {
      // Full padding to the end of the packet.
      return free_bytes;
    } else {
      // Lite padding.
      return free_bytes <
                     static_cast<size_t>(frame.padding_frame.num_padding_bytes)
                 ? free_bytes
                 : frame.padding_frame.num_padding_bytes;
    }
  }

  size_t frame_len =
      ComputeFrameLength(frame, last_frame, packet_number_length);
  if (frame_len <= free_bytes) {
    // Frame fits within packet. Note that acks may be truncated.
    return frame_len;
  }
  // Only truncate the first frame in a packet, so if subsequent ones go
  // over, stop including more frames.
  if (!first_frame) {
    return 0;
  }
  bool can_truncate =
      frame.type == ACK_FRAME &&
      free_bytes >=
          GetMinAckFrameSize(quic_version_, PACKET_6BYTE_PACKET_NUMBER);
  if (can_truncate) {
    // Truncate the frame so the packet will not exceed kMaxPacketSize.
    // Note that we may not use every byte of the writer in this case.
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Truncating large frame, free bytes: " << free_bytes;
    return free_bytes;
  }
  return 0;
}

QuicFramer::AckFrameInfo::AckFrameInfo()
    : max_block_length(0), first_block_length(0), num_ack_blocks(0) {}

QuicFramer::AckFrameInfo::AckFrameInfo(const AckFrameInfo& other) = default;

QuicFramer::AckFrameInfo::~AckFrameInfo() {}

size_t QuicFramer::BuildDataPacket(const QuicPacketHeader& header,
                                   const QuicFrames& frames,
                                   char* buffer,
                                   size_t packet_length) {
  QuicDataWriter writer(packet_length, buffer);
  if (!AppendPacketHeader(header, &writer)) {
    QUIC_BUG << "AppendPacketHeader failed";
    return 0;
  }

  size_t i = 0;
  for (const QuicFrame& frame : frames) {
    // Determine if we should write stream frame length in header.
    const bool no_stream_frame_length = i == frames.size() - 1;
    if (!AppendTypeByte(frame, no_stream_frame_length, &writer)) {
      QUIC_BUG << "AppendTypeByte failed";
      return 0;
    }

    switch (frame.type) {
      case PADDING_FRAME:
        writer.WritePadding();
        break;
      case STREAM_FRAME:
        if (!AppendStreamFrame(*frame.stream_frame, no_stream_frame_length,
                               &writer)) {
          QUIC_BUG << "AppendStreamFrame failed";
          return 0;
        }
        break;
      case ACK_FRAME:
        if (!AppendAckFrameAndTypeByte(*frame.ack_frame, &writer)) {
          QUIC_BUG << "AppendAckFrameAndTypeByte failed";
          return 0;
        }
        break;
      case STOP_WAITING_FRAME:
        if (!AppendStopWaitingFrame(header, *frame.stop_waiting_frame,
                                    &writer)) {
          QUIC_BUG << "AppendStopWaitingFrame failed";
          return 0;
        }
        break;
      case MTU_DISCOVERY_FRAME:
      // MTU discovery frames are serialized as ping frames.
      case PING_FRAME:
        // Ping has no payload.
        break;
      case RST_STREAM_FRAME:
        if (!AppendRstStreamFrame(*frame.rst_stream_frame, &writer)) {
          QUIC_BUG << "AppendRstStreamFrame failed";
          return 0;
        }
        break;
      case CONNECTION_CLOSE_FRAME:
        if (!AppendConnectionCloseFrame(*frame.connection_close_frame,
                                        &writer)) {
          QUIC_BUG << "AppendConnectionCloseFrame failed";
          return 0;
        }
        break;
      case GOAWAY_FRAME:
        if (!AppendGoAwayFrame(*frame.goaway_frame, &writer)) {
          QUIC_BUG << "AppendGoAwayFrame failed";
          return 0;
        }
        break;
      case WINDOW_UPDATE_FRAME:
        if (!AppendWindowUpdateFrame(*frame.window_update_frame, &writer)) {
          QUIC_BUG << "AppendWindowUpdateFrame failed";
          return 0;
        }
        break;
      case BLOCKED_FRAME:
        if (!AppendBlockedFrame(*frame.blocked_frame, &writer)) {
          QUIC_BUG << "AppendBlockedFrame failed";
          return 0;
        }
        break;
      case PATH_CLOSE_FRAME:
        if (!AppendPathCloseFrame(*frame.path_close_frame, &writer)) {
          QUIC_BUG << "AppendPathCloseFrame failed";
          return 0;
        }
        break;
      default:
        RaiseError(QUIC_INVALID_FRAME_DATA);
        QUIC_BUG << "QUIC_INVALID_FRAME_DATA";
        return 0;
    }
    ++i;
  }

  return writer.length();
}

// static
std::unique_ptr<QuicEncryptedPacket> QuicFramer::BuildPublicResetPacket(
    const QuicPublicResetPacket& packet) {
  DCHECK(packet.public_header.reset_flag);

  CryptoHandshakeMessage reset;
  reset.set_tag(kPRST);
  reset.SetValue(kRNON, packet.nonce_proof);
  if (!FLAGS_quic_reloadable_flag_quic_remove_packet_number_from_public_reset) {
    reset.SetValue(kRSEQ, packet.rejected_packet_number);
  }
  if (packet.client_address.host().address_family() !=
      IpAddressFamily::IP_UNSPEC) {
    // packet.client_address is non-empty.
    QuicSocketAddressCoder address_coder(packet.client_address);
    string serialized_address = address_coder.Encode();
    if (serialized_address.empty()) {
      return nullptr;
    }
    reset.SetStringPiece(kCADR, serialized_address);
  }
  const QuicData& reset_serialized = reset.GetSerialized();

  size_t len =
      kPublicFlagsSize + PACKET_8BYTE_CONNECTION_ID + reset_serialized.length();
  std::unique_ptr<char[]> buffer(new char[len]);
  QuicDataWriter writer(len, buffer.get());

  uint8_t flags = static_cast<uint8_t>(PACKET_PUBLIC_FLAGS_RST |
                                       PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID);
  if (FLAGS_quic_reloadable_flag_quic_use_old_public_reset_packets) {
    // TODO(rch): Remove this QUIC_VERSION_32 is retired.
    flags |= static_cast<uint8_t>(PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID_OLD);
  }
  if (!writer.WriteUInt8(flags)) {
    return nullptr;
  }

  if (!writer.WriteUInt64(packet.public_header.connection_id)) {
    return nullptr;
  }

  if (!writer.WriteBytes(reset_serialized.data(), reset_serialized.length())) {
    return nullptr;
  }

  return QuicMakeUnique<QuicEncryptedPacket>(buffer.release(), len, true);
}

// static
std::unique_ptr<QuicEncryptedPacket> QuicFramer::BuildVersionNegotiationPacket(
    QuicConnectionId connection_id,
    const QuicVersionVector& versions) {
  DCHECK(!versions.empty());
  size_t len = GetVersionNegotiationPacketSize(versions.size());
  std::unique_ptr<char[]> buffer(new char[len]);
  QuicDataWriter writer(len, buffer.get());

  uint8_t flags = static_cast<uint8_t>(
      PACKET_PUBLIC_FLAGS_VERSION | PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID |
      // TODO(rch): Remove this QUIC_VERSION_32 is retired.
      PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID_OLD);
  if (!writer.WriteUInt8(flags)) {
    return nullptr;
  }

  if (!writer.WriteUInt64(connection_id)) {
    return nullptr;
  }

  for (QuicVersion version : versions) {
    if (!writer.WriteUInt32(QuicVersionToQuicTag(version))) {
      return nullptr;
    }
  }

  return QuicMakeUnique<QuicEncryptedPacket>(buffer.release(), len, true);
}

bool QuicFramer::ProcessPacket(const QuicEncryptedPacket& packet) {
  QuicDataReader reader(packet.data(), packet.length());

  visitor_->OnPacket();

  // First parse the public header.
  QuicPacketPublicHeader public_header;
  if (!ProcessPublicHeader(&reader, &public_header)) {
    DCHECK_NE("", detailed_error_);
    QUIC_DVLOG(1) << ENDPOINT << "Unable to process public header. Error: "
                  << detailed_error_;
    DCHECK_NE("", detailed_error_);
    return RaiseError(QUIC_INVALID_PACKET_HEADER);
  }

  if (!visitor_->OnUnauthenticatedPublicHeader(public_header)) {
    // The visitor suppresses further processing of the packet.
    return true;
  }

  if (perspective_ == Perspective::IS_SERVER && public_header.version_flag &&
      public_header.versions[0] != quic_version_) {
    if (!visitor_->OnProtocolVersionMismatch(public_header.versions[0])) {
      return true;
    }
  }

  bool rv;
  if (perspective_ == Perspective::IS_CLIENT && public_header.version_flag) {
    rv = ProcessVersionNegotiationPacket(&reader, &public_header);
  } else if (public_header.reset_flag) {
    rv = ProcessPublicResetPacket(&reader, public_header);
  } else if (packet.length() <= kMaxPacketSize) {
    // The optimized decryption algorithm implementations run faster when
    // operating on aligned memory.
    QUIC_CACHELINE_ALIGNED char buffer[kMaxPacketSize];
    rv = ProcessDataPacket(&reader, public_header, packet, buffer,
                           kMaxPacketSize);
  } else {
    std::unique_ptr<char[]> large_buffer(new char[packet.length()]);
    rv = ProcessDataPacket(&reader, public_header, packet, large_buffer.get(),
                           packet.length());
    QUIC_BUG_IF(rv) << "QUIC should never successfully process packets larger"
                    << "than kMaxPacketSize. packet size:" << packet.length();
  }

  return rv;
}

bool QuicFramer::ProcessVersionNegotiationPacket(
    QuicDataReader* reader,
    QuicPacketPublicHeader* public_header) {
  DCHECK_EQ(Perspective::IS_CLIENT, perspective_);
  // Try reading at least once to raise error if the packet is invalid.
  do {
    QuicTag version;
    if (!reader->ReadBytes(&version, kQuicVersionSize)) {
      set_detailed_error("Unable to read supported version in negotiation.");
      return RaiseError(QUIC_INVALID_VERSION_NEGOTIATION_PACKET);
    }
    public_header->versions.push_back(QuicTagToQuicVersion(version));
  } while (!reader->IsDoneReading());

  visitor_->OnVersionNegotiationPacket(*public_header);
  return true;
}

bool QuicFramer::ProcessDataPacket(QuicDataReader* encrypted_reader,
                                   const QuicPacketPublicHeader& public_header,
                                   const QuicEncryptedPacket& packet,
                                   char* decrypted_buffer,
                                   size_t buffer_length) {
  QuicPacketHeader header(public_header);
  if (!ProcessUnauthenticatedHeader(encrypted_reader, &header)) {
    DCHECK_NE("", detailed_error_);
    QUIC_DVLOG(1)
        << ENDPOINT
        << "Unable to process packet header. Stopping parsing. Error: "
        << detailed_error_;
    return false;
  }

  size_t decrypted_length = 0;
  if (!DecryptPayload(encrypted_reader, header, packet, decrypted_buffer,
                      buffer_length, &decrypted_length)) {
    set_detailed_error("Unable to decrypt payload.");
    return RaiseError(QUIC_DECRYPTION_FAILURE);
  }

  QuicDataReader reader(decrypted_buffer, decrypted_length);

  // Set the last packet number after we have decrypted the packet
  // so we are confident is not attacker controlled.
  SetLastPacketNumber(header);

  if (!visitor_->OnPacketHeader(header)) {
    // The visitor suppresses further processing of the packet.
    return true;
  }

  if (packet.length() > kMaxPacketSize) {
    // If the packet has gotten this far, it should not be too large.
    QUIC_BUG << "Packet too large:" << packet.length();
    return RaiseError(QUIC_PACKET_TOO_LARGE);
  }

  // Handle the payload.
  if (!ProcessFrameData(&reader, header)) {
    DCHECK_NE(QUIC_NO_ERROR, error_);  // ProcessFrameData sets the error.
    DCHECK_NE("", detailed_error_);
    QUIC_DLOG(WARNING) << ENDPOINT << "Unable to process frame data. Error: "
                       << detailed_error_;
    return false;
  }

  visitor_->OnPacketComplete();
  return true;
}

bool QuicFramer::ProcessPublicResetPacket(
    QuicDataReader* reader,
    const QuicPacketPublicHeader& public_header) {
  QuicPublicResetPacket packet(public_header);

  std::unique_ptr<CryptoHandshakeMessage> reset(
      CryptoFramer::ParseMessage(reader->ReadRemainingPayload()));
  if (!reset.get()) {
    set_detailed_error("Unable to read reset message.");
    return RaiseError(QUIC_INVALID_PUBLIC_RST_PACKET);
  }
  if (reset->tag() != kPRST) {
    set_detailed_error("Incorrect message tag.");
    return RaiseError(QUIC_INVALID_PUBLIC_RST_PACKET);
  }

  if (reset->GetUint64(kRNON, &packet.nonce_proof) != QUIC_NO_ERROR) {
    set_detailed_error("Unable to read nonce proof.");
    return RaiseError(QUIC_INVALID_PUBLIC_RST_PACKET);
  }
  // TODO(satyamshekhar): validate nonce to protect against DoS.

  StringPiece address;
  if (reset->GetStringPiece(kCADR, &address)) {
    QuicSocketAddressCoder address_coder;
    if (address_coder.Decode(address.data(), address.length())) {
      packet.client_address =
          QuicSocketAddress(address_coder.ip(), address_coder.port());
    }
  }

  visitor_->OnPublicResetPacket(packet);
  return true;
}

bool QuicFramer::AppendPacketHeader(const QuicPacketHeader& header,
                                    QuicDataWriter* writer) {
  QUIC_DVLOG(1) << ENDPOINT << "Appending header: " << header;
  uint8_t public_flags = 0;
  if (header.public_header.reset_flag) {
    public_flags |= PACKET_PUBLIC_FLAGS_RST;
  }
  if (header.public_header.version_flag) {
    public_flags |= PACKET_PUBLIC_FLAGS_VERSION;
  }
  if (header.public_header.multipath_flag) {
    public_flags |= PACKET_PUBLIC_FLAGS_MULTIPATH;
  }

  public_flags |=
      GetSequenceNumberFlags(header.public_header.packet_number_length)
      << kPublicHeaderSequenceNumberShift;

  if (header.public_header.nonce != nullptr) {
    DCHECK_EQ(Perspective::IS_SERVER, perspective_);
    public_flags |= PACKET_PUBLIC_FLAGS_NONCE;
  }

  switch (header.public_header.connection_id_length) {
    case PACKET_0BYTE_CONNECTION_ID:
      if (!writer->WriteUInt8(public_flags |
                              PACKET_PUBLIC_FLAGS_0BYTE_CONNECTION_ID)) {
        return false;
      }
      break;
    case PACKET_8BYTE_CONNECTION_ID:
      public_flags |= PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID;
      if (!FLAGS_quic_reloadable_flag_quic_remove_v33_hacks2 &&
          perspective_ == Perspective::IS_CLIENT) {
        public_flags |= PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID_OLD;
      }
      if (!writer->WriteUInt8(public_flags) ||
          !writer->WriteUInt64(header.public_header.connection_id)) {
        return false;
      }
      break;
  }
  last_serialized_connection_id_ = header.public_header.connection_id;

  if (header.public_header.version_flag) {
    DCHECK_EQ(Perspective::IS_CLIENT, perspective_);
    QuicTag tag = QuicVersionToQuicTag(quic_version_);
    if (!writer->WriteUInt32(tag)) {
      return false;
    }
    QUIC_DVLOG(1) << ENDPOINT << "version = " << quic_version_ << ", tag = '"
                  << QuicTagToString(tag) << "'";
  }

  if (header.public_header.multipath_flag &&
      !writer->WriteUInt8(header.path_id)) {
    return false;
  }

  if (header.public_header.nonce != nullptr &&
      !writer->WriteBytes(header.public_header.nonce,
                          kDiversificationNonceSize)) {
    return false;
  }

  if (!AppendPacketSequenceNumber(header.public_header.packet_number_length,
                                  header.packet_number, writer)) {
    return false;
  }

  return true;
}

const QuicTime::Delta QuicFramer::CalculateTimestampFromWire(
    uint32_t time_delta_us) {
  // The new time_delta might have wrapped to the next epoch, or it
  // might have reverse wrapped to the previous epoch, or it might
  // remain in the same epoch. Select the time closest to the previous
  // time.
  //
  // epoch_delta is the delta between epochs. A delta is 4 bytes of
  // microseconds.
  const uint64_t epoch_delta = UINT64_C(1) << 32;
  uint64_t epoch = last_timestamp_.ToMicroseconds() & ~(epoch_delta - 1);
  // Wrapping is safe here because a wrapped value will not be ClosestTo below.
  uint64_t prev_epoch = epoch - epoch_delta;
  uint64_t next_epoch = epoch + epoch_delta;

  uint64_t time = ClosestTo(
      last_timestamp_.ToMicroseconds(), epoch + time_delta_us,
      ClosestTo(last_timestamp_.ToMicroseconds(), prev_epoch + time_delta_us,
                next_epoch + time_delta_us));

  return QuicTime::Delta::FromMicroseconds(time);
}

void QuicFramer::SetLastPacketNumber(const QuicPacketHeader& header) {
  last_packet_number_ = header.packet_number;
  largest_packet_number_ =
      std::max(header.packet_number, largest_packet_number_);
}

QuicPacketNumber QuicFramer::CalculatePacketNumberFromWire(
    QuicPacketNumberLength packet_number_length,
    QuicPacketNumber base_packet_number,
    QuicPacketNumber packet_number) const {
  // The new packet number might have wrapped to the next epoch, or
  // it might have reverse wrapped to the previous epoch, or it might
  // remain in the same epoch.  Select the packet number closest to the
  // next expected packet number, the previous packet number plus 1.

  // epoch_delta is the delta between epochs the packet number was serialized
  // with, so the correct value is likely the same epoch as the last sequence
  // number or an adjacent epoch.
  const QuicPacketNumber epoch_delta = UINT64_C(1)
                                       << (8 * packet_number_length);
  QuicPacketNumber next_packet_number = base_packet_number + 1;
  QuicPacketNumber epoch = base_packet_number & ~(epoch_delta - 1);
  QuicPacketNumber prev_epoch = epoch - epoch_delta;
  QuicPacketNumber next_epoch = epoch + epoch_delta;

  return ClosestTo(next_packet_number, epoch + packet_number,
                   ClosestTo(next_packet_number, prev_epoch + packet_number,
                             next_epoch + packet_number));
}

bool QuicFramer::ProcessPublicHeader(QuicDataReader* reader,
                                     QuicPacketPublicHeader* public_header) {
  uint8_t public_flags;
  if (!reader->ReadBytes(&public_flags, 1)) {
    set_detailed_error("Unable to read public flags.");
    return false;
  }

  public_header->multipath_flag =
      (public_flags & PACKET_PUBLIC_FLAGS_MULTIPATH) != 0;
  public_header->reset_flag = (public_flags & PACKET_PUBLIC_FLAGS_RST) != 0;
  public_header->version_flag =
      (public_flags & PACKET_PUBLIC_FLAGS_VERSION) != 0;

  if (validate_flags_ && !public_header->version_flag &&
      public_flags > PACKET_PUBLIC_FLAGS_MAX) {
    set_detailed_error("Illegal public flags value.");
    return false;
  }

  if (public_header->reset_flag && public_header->version_flag) {
    set_detailed_error("Got version flag in reset packet");
    return false;
  }

  switch (public_flags & PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID) {
    case PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID:
      if (!reader->ReadUInt64(&public_header->connection_id)) {
        set_detailed_error("Unable to read ConnectionId.");
        return false;
      }
      public_header->connection_id_length = PACKET_8BYTE_CONNECTION_ID;
      break;
    case PACKET_PUBLIC_FLAGS_0BYTE_CONNECTION_ID:
      public_header->connection_id_length = PACKET_0BYTE_CONNECTION_ID;
      public_header->connection_id = last_serialized_connection_id_;
      break;
  }

  public_header->packet_number_length = ReadSequenceNumberLength(
      public_flags >> kPublicHeaderSequenceNumberShift);

  // Read the version only if the packet is from the client.
  // version flag from the server means version negotiation packet.
  if (public_header->version_flag && perspective_ == Perspective::IS_SERVER) {
    QuicTag version_tag;
    if (!reader->ReadUInt32(&version_tag)) {
      set_detailed_error("Unable to read protocol version.");
      return false;
    }

    // If the version from the new packet is the same as the version of this
    // framer, then the public flags should be set to something we understand.
    // If not, this raises an error.
    last_version_tag_ = version_tag;
    QuicVersion version = QuicTagToQuicVersion(version_tag);
    if (version == quic_version_ && public_flags > PACKET_PUBLIC_FLAGS_MAX) {
      set_detailed_error("Illegal public flags value.");
      return false;
    }
    public_header->versions.push_back(version);
  }

  // A nonce should only be present in packets from the server to the client,
  // which are neither version negotiation nor public reset packets.
  if (public_flags & PACKET_PUBLIC_FLAGS_NONCE &&
      !(public_flags & PACKET_PUBLIC_FLAGS_VERSION) &&
      !(public_flags & PACKET_PUBLIC_FLAGS_RST) &&
      // The nonce flag from a client is ignored and is assumed to be an older
      // client indicating an eight-byte connection ID.
      perspective_ == Perspective::IS_CLIENT) {
    if (!reader->ReadBytes(reinterpret_cast<uint8_t*>(last_nonce_.data()),
                           last_nonce_.size())) {
      set_detailed_error("Unable to read nonce.");
      return false;
    }
    public_header->nonce = &last_nonce_;
  } else {
    public_header->nonce = nullptr;
  }

  return true;
}

// static
QuicPacketNumberLength QuicFramer::GetMinSequenceNumberLength(
    QuicPacketNumber packet_number) {
  if (packet_number < 1 << (PACKET_1BYTE_PACKET_NUMBER * 8)) {
    return PACKET_1BYTE_PACKET_NUMBER;
  } else if (packet_number < 1 << (PACKET_2BYTE_PACKET_NUMBER * 8)) {
    return PACKET_2BYTE_PACKET_NUMBER;
  } else if (packet_number < UINT64_C(1) << (PACKET_4BYTE_PACKET_NUMBER * 8)) {
    return PACKET_4BYTE_PACKET_NUMBER;
  } else {
    return PACKET_6BYTE_PACKET_NUMBER;
  }
}

// static
uint8_t QuicFramer::GetSequenceNumberFlags(
    QuicPacketNumberLength packet_number_length) {
  switch (packet_number_length) {
    case PACKET_1BYTE_PACKET_NUMBER:
      return PACKET_FLAGS_1BYTE_PACKET;
    case PACKET_2BYTE_PACKET_NUMBER:
      return PACKET_FLAGS_2BYTE_PACKET;
    case PACKET_4BYTE_PACKET_NUMBER:
      return PACKET_FLAGS_4BYTE_PACKET;
    case PACKET_6BYTE_PACKET_NUMBER:
      return PACKET_FLAGS_6BYTE_PACKET;
    default:
      QUIC_BUG << "Unreachable case statement.";
      return PACKET_FLAGS_6BYTE_PACKET;
  }
}

// static
QuicFramer::AckFrameInfo QuicFramer::GetAckFrameInfo(
    const QuicAckFrame& frame) {
  AckFrameInfo new_ack_info;
  if (frame.packets.Empty()) {
    return new_ack_info;
  }
  // The first block is the last interval. It isn't encoded with the gap-length
  // encoding, so skip it.
  new_ack_info.first_block_length = frame.packets.LastIntervalLength();
  auto itr = frame.packets.rbegin();
  QuicPacketNumber previous_start = itr->min();
  new_ack_info.max_block_length = itr->Length();
  ++itr;

  // Don't do any more work after getting information for 256 ACK blocks; any
  // more can't be encoded anyway.
  for (; itr != frame.packets.rend() &&
         new_ack_info.num_ack_blocks < std::numeric_limits<uint8_t>::max();
       previous_start = itr->min(), ++itr) {
    const auto& interval = *itr;
    const QuicPacketNumber total_gap = previous_start - interval.max();
    new_ack_info.num_ack_blocks +=
        (total_gap + std::numeric_limits<uint8_t>::max() - 1) /
        std::numeric_limits<uint8_t>::max();
    new_ack_info.max_block_length =
        std::max(new_ack_info.max_block_length, interval.Length());
  }
  return new_ack_info;
}

bool QuicFramer::ProcessUnauthenticatedHeader(QuicDataReader* encrypted_reader,
                                              QuicPacketHeader* header) {
  header->path_id = kDefaultPathId;
  if (header->public_header.multipath_flag &&
      !ProcessPathId(encrypted_reader, &header->path_id)) {
    set_detailed_error("Unable to read path id.");
    return RaiseError(QUIC_INVALID_PACKET_HEADER);
  }

  QuicPacketNumber base_packet_number = largest_packet_number_;

  if (!ProcessPacketSequenceNumber(
          encrypted_reader, header->public_header.packet_number_length,
          base_packet_number, &header->packet_number)) {
    set_detailed_error("Unable to read packet number.");
    return RaiseError(QUIC_INVALID_PACKET_HEADER);
  }

  if (header->packet_number == 0u) {
    set_detailed_error("packet numbers cannot be 0.");
    return RaiseError(QUIC_INVALID_PACKET_HEADER);
  }

  if (!visitor_->OnUnauthenticatedHeader(*header)) {
    set_detailed_error(
        "Visitor asked to stop processing of unauthenticated header.");
    return false;
  }
  return true;
}

bool QuicFramer::ProcessPathId(QuicDataReader* reader, QuicPathId* path_id) {
  if (!reader->ReadBytes(path_id, 1)) {
    return false;
  }

  return true;
}

bool QuicFramer::ProcessPacketSequenceNumber(
    QuicDataReader* reader,
    QuicPacketNumberLength packet_number_length,
    QuicPacketNumber base_packet_number,
    QuicPacketNumber* packet_number) {
  QuicPacketNumber wire_packet_number = 0u;
  if (!reader->ReadBytes(&wire_packet_number, packet_number_length)) {
    return false;
  }

  // TODO(ianswett): Explore the usefulness of trying multiple packet numbers
  // in case the first guess is incorrect.
  *packet_number = CalculatePacketNumberFromWire(
      packet_number_length, base_packet_number, wire_packet_number);
  return true;
}

bool QuicFramer::ProcessFrameData(QuicDataReader* reader,
                                  const QuicPacketHeader& header) {
  if (reader->IsDoneReading()) {
    set_detailed_error("Packet has no frames.");
    return RaiseError(QUIC_MISSING_PAYLOAD);
  }
  while (!reader->IsDoneReading()) {
    uint8_t frame_type;
    if (!reader->ReadBytes(&frame_type, 1)) {
      set_detailed_error("Unable to read frame type.");
      return RaiseError(QUIC_INVALID_FRAME_DATA);
    }

    if (frame_type & kQuicFrameTypeSpecialMask) {
      // Stream Frame
      if (frame_type & kQuicFrameTypeStreamMask) {
        QuicStreamFrame frame;
        if (!ProcessStreamFrame(reader, frame_type, &frame)) {
          return RaiseError(QUIC_INVALID_STREAM_DATA);
        }
        if (!visitor_->OnStreamFrame(frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }

      // Ack Frame
      if (frame_type & kQuicFrameTypeAckMask) {
        QuicAckFrame frame;
        if (!ProcessAckFrame(reader, frame_type, &frame)) {
          return RaiseError(QUIC_INVALID_ACK_DATA);
        }
        if (!visitor_->OnAckFrame(frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }

      // This was a special frame type that did not match any
      // of the known ones. Error.
      set_detailed_error("Illegal frame type.");
      QUIC_DLOG(WARNING) << ENDPOINT << "Illegal frame type: "
                         << static_cast<int>(frame_type);
      return RaiseError(QUIC_INVALID_FRAME_DATA);
    }

    switch (frame_type) {
      case PADDING_FRAME: {
        QuicPaddingFrame frame(reader->BytesRemaining());
        if (!visitor_->OnPaddingFrame(frame)) {
          QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
        }
        // We're done with the packet.
        return true;
      }

      case RST_STREAM_FRAME: {
        QuicRstStreamFrame frame;
        if (!ProcessRstStreamFrame(reader, &frame)) {
          return RaiseError(QUIC_INVALID_RST_STREAM_DATA);
        }
        if (!visitor_->OnRstStreamFrame(frame)) {
          QUIC_DVLOG(1) << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }

      case CONNECTION_CLOSE_FRAME: {
        QuicConnectionCloseFrame frame;
        if (!ProcessConnectionCloseFrame(reader, &frame)) {
          return RaiseError(QUIC_INVALID_CONNECTION_CLOSE_DATA);
        }

        if (!visitor_->OnConnectionCloseFrame(frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }

      case GOAWAY_FRAME: {
        QuicGoAwayFrame goaway_frame;
        if (!ProcessGoAwayFrame(reader, &goaway_frame)) {
          return RaiseError(QUIC_INVALID_GOAWAY_DATA);
        }
        if (!visitor_->OnGoAwayFrame(goaway_frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }

      case WINDOW_UPDATE_FRAME: {
        QuicWindowUpdateFrame window_update_frame;
        if (!ProcessWindowUpdateFrame(reader, &window_update_frame)) {
          return RaiseError(QUIC_INVALID_WINDOW_UPDATE_DATA);
        }
        if (!visitor_->OnWindowUpdateFrame(window_update_frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }

      case BLOCKED_FRAME: {
        QuicBlockedFrame blocked_frame;
        if (!ProcessBlockedFrame(reader, &blocked_frame)) {
          return RaiseError(QUIC_INVALID_BLOCKED_DATA);
        }
        if (!visitor_->OnBlockedFrame(blocked_frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }

      case STOP_WAITING_FRAME: {
        QuicStopWaitingFrame stop_waiting_frame;
        if (!ProcessStopWaitingFrame(reader, header, &stop_waiting_frame)) {
          return RaiseError(QUIC_INVALID_STOP_WAITING_DATA);
        }
        if (!visitor_->OnStopWaitingFrame(stop_waiting_frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }
      case PING_FRAME: {
        // Ping has no payload.
        QuicPingFrame ping_frame;
        if (!visitor_->OnPingFrame(ping_frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }
      case PATH_CLOSE_FRAME: {
        QuicPathCloseFrame path_close_frame;
        if (!ProcessPathCloseFrame(reader, &path_close_frame)) {
          return RaiseError(QUIC_INVALID_PATH_CLOSE_DATA);
        }
        if (!visitor_->OnPathCloseFrame(path_close_frame)) {
          QUIC_DVLOG(1) << ENDPOINT
                        << "Visitor asked to stop further processing.";
          // Returning true since there was no parsing error.
          return true;
        }
        continue;
      }

      default:
        set_detailed_error("Illegal frame type.");
        QUIC_DLOG(WARNING) << ENDPOINT << "Illegal frame type: "
                           << static_cast<int>(frame_type);
        return RaiseError(QUIC_INVALID_FRAME_DATA);
    }
  }

  return true;
}

bool QuicFramer::ProcessStreamFrame(QuicDataReader* reader,
                                    uint8_t frame_type,
                                    QuicStreamFrame* frame) {
  uint8_t stream_flags = frame_type;

  stream_flags &= ~kQuicFrameTypeStreamMask;

  // Read from right to left: StreamID, Offset, Data Length, Fin.
  const uint8_t stream_id_length = (stream_flags & kQuicStreamIDLengthMask) + 1;
  stream_flags >>= kQuicStreamIdShift;

  uint8_t offset_length = (stream_flags & kQuicStreamOffsetMask);
  // There is no encoding for 1 byte, only 0 and 2 through 8.
  if (offset_length > 0) {
    offset_length += 1;
  }
  stream_flags >>= kQuicStreamOffsetShift;

  bool has_data_length =
      (stream_flags & kQuicStreamDataLengthMask) == kQuicStreamDataLengthMask;
  stream_flags >>= kQuicStreamDataLengthShift;

  frame->fin = (stream_flags & kQuicStreamFinMask) == kQuicStreamFinShift;

  frame->stream_id = 0;
  if (!reader->ReadBytes(&frame->stream_id, stream_id_length)) {
    set_detailed_error("Unable to read stream_id.");
    return false;
  }

  frame->offset = 0;
  if (!reader->ReadBytes(&frame->offset, offset_length)) {
    set_detailed_error("Unable to read offset.");
    return false;
  }

  // TODO(ianswett): Don't use StringPiece as an intermediary.
  StringPiece data;
  if (has_data_length) {
    if (!reader->ReadStringPiece16(&data)) {
      set_detailed_error("Unable to read frame data.");
      return false;
    }
  } else {
    if (!reader->ReadStringPiece(&data, reader->BytesRemaining())) {
      set_detailed_error("Unable to read frame data.");
      return false;
    }
  }
  frame->data_buffer = data.data();
  frame->data_length = static_cast<uint16_t>(data.length());

  return true;
}

bool QuicFramer::ProcessAckFrame(QuicDataReader* reader,
                                 uint8_t frame_type,
                                 QuicAckFrame* ack_frame) {
  // Determine the two lengths from the frame type: largest acked length,
  // ack block length.
  const QuicPacketNumberLength ack_block_length =
      ReadSequenceNumberLength(frame_type);
  frame_type >>= kQuicSequenceNumberLengthShift;
  const QuicPacketNumberLength largest_acked_length =
      ReadSequenceNumberLength(frame_type);
  frame_type >>= kQuicSequenceNumberLengthShift;
  frame_type >>= kQuicHasMultipleAckBlocksShift;
  bool has_ack_blocks = frame_type & kQuicHasMultipleAckBlocksMask;

  if (!reader->ReadBytes(&ack_frame->largest_observed, largest_acked_length)) {
    set_detailed_error("Unable to read largest acked.");
    return false;
  }

  uint64_t ack_delay_time_us;
  if (!reader->ReadUFloat16(&ack_delay_time_us)) {
    set_detailed_error("Unable to read ack delay time.");
    return false;
  }

  if (ack_delay_time_us == kUFloat16MaxValue) {
    ack_frame->ack_delay_time = QuicTime::Delta::Infinite();
  } else {
    ack_frame->ack_delay_time =
        QuicTime::Delta::FromMicroseconds(ack_delay_time_us);
  }

  uint8_t num_ack_blocks = 0;
  if (has_ack_blocks) {
    if (!reader->ReadBytes(&num_ack_blocks, 1)) {
      set_detailed_error("Unable to read num of ack blocks.");
      return false;
    }
  }

  size_t first_block_length = 0;
  if (!reader->ReadBytes(&first_block_length, ack_block_length)) {
    set_detailed_error("Unable to read first ack block length.");
    return false;
  }
  QuicPacketNumber first_received =
      ack_frame->largest_observed + 1 - first_block_length;
  ack_frame->packets.Add(first_received, ack_frame->largest_observed + 1);

  if (num_ack_blocks > 0) {
    for (size_t i = 0; i < num_ack_blocks; ++i) {
      size_t gap = 0;
      if (!reader->ReadBytes(&gap, PACKET_1BYTE_PACKET_NUMBER)) {
        set_detailed_error("Unable to read gap to next ack block.");
        return false;
      }
      size_t current_block_length = 0;
      if (!reader->ReadBytes(&current_block_length, ack_block_length)) {
        set_detailed_error("Unable to ack block length.");
        return false;
      }
      first_received -= (gap + current_block_length);
      if (current_block_length > 0) {
        ack_frame->packets.Add(first_received,
                               first_received + current_block_length);
      }
    }
  }

  if (!ProcessTimestampsInAckFrame(reader, ack_frame)) {
    return false;
  }

  return true;
}

bool QuicFramer::ProcessTimestampsInAckFrame(QuicDataReader* reader,
                                             QuicAckFrame* ack_frame) {
  uint8_t num_received_packets;
  if (!reader->ReadBytes(&num_received_packets, 1)) {
    set_detailed_error("Unable to read num received packets.");
    return false;
  }

  if (num_received_packets > 0) {
    uint8_t delta_from_largest_observed;
    if (!reader->ReadBytes(&delta_from_largest_observed,
                           PACKET_1BYTE_PACKET_NUMBER)) {
      set_detailed_error("Unable to read sequence delta in received packets.");
      return false;
    }
    QuicPacketNumber seq_num =
        ack_frame->largest_observed - delta_from_largest_observed;

    // Time delta from the framer creation.
    uint32_t time_delta_us;
    if (!reader->ReadBytes(&time_delta_us, sizeof(time_delta_us))) {
      set_detailed_error("Unable to read time delta in received packets.");
      return false;
    }

    last_timestamp_ = CalculateTimestampFromWire(time_delta_us);

    ack_frame->received_packet_times.reserve(num_received_packets);
    ack_frame->received_packet_times.push_back(
        std::make_pair(seq_num, creation_time_ + last_timestamp_));

    for (uint8_t i = 1; i < num_received_packets; ++i) {
      if (!reader->ReadBytes(&delta_from_largest_observed,
                             PACKET_1BYTE_PACKET_NUMBER)) {
        set_detailed_error(
            "Unable to read sequence delta in received packets.");
        return false;
      }
      seq_num = ack_frame->largest_observed - delta_from_largest_observed;

      // Time delta from the previous timestamp.
      uint64_t incremental_time_delta_us;
      if (!reader->ReadUFloat16(&incremental_time_delta_us)) {
        set_detailed_error(
            "Unable to read incremental time delta in received packets.");
        return false;
      }

      last_timestamp_ = last_timestamp_ + QuicTime::Delta::FromMicroseconds(
                                              incremental_time_delta_us);
      ack_frame->received_packet_times.push_back(
          std::make_pair(seq_num, creation_time_ + last_timestamp_));
    }
  }
  return true;
}

bool QuicFramer::ProcessStopWaitingFrame(QuicDataReader* reader,
                                         const QuicPacketHeader& header,
                                         QuicStopWaitingFrame* stop_waiting) {
  QuicPacketNumber least_unacked_delta = 0;
  if (!reader->ReadBytes(&least_unacked_delta,
                         header.public_header.packet_number_length)) {
    set_detailed_error("Unable to read least unacked delta.");
    return false;
  }
  DCHECK_GE(header.packet_number, least_unacked_delta);
  stop_waiting->least_unacked = header.packet_number - least_unacked_delta;

  return true;
}

bool QuicFramer::ProcessRstStreamFrame(QuicDataReader* reader,
                                       QuicRstStreamFrame* frame) {
  if (!reader->ReadUInt32(&frame->stream_id)) {
    set_detailed_error("Unable to read stream_id.");
    return false;
  }

  if (!reader->ReadUInt64(&frame->byte_offset)) {
    set_detailed_error("Unable to read rst stream sent byte offset.");
    return false;
  }

  uint32_t error_code;
  if (!reader->ReadUInt32(&error_code)) {
    set_detailed_error("Unable to read rst stream error code.");
    return false;
  }

  if (error_code >= QUIC_STREAM_LAST_ERROR) {
    // Ignore invalid stream error code if any.
    error_code = QUIC_STREAM_LAST_ERROR;
  }

  frame->error_code = static_cast<QuicRstStreamErrorCode>(error_code);
  return true;
}

bool QuicFramer::ProcessConnectionCloseFrame(QuicDataReader* reader,
                                             QuicConnectionCloseFrame* frame) {
  uint32_t error_code;
  if (!reader->ReadUInt32(&error_code)) {
    set_detailed_error("Unable to read connection close error code.");
    return false;
  }

  if (error_code >= QUIC_LAST_ERROR) {
    // Ignore invalid QUIC error code if any.
    error_code = QUIC_LAST_ERROR;
  }

  frame->error_code = static_cast<QuicErrorCode>(error_code);

  StringPiece error_details;
  if (!reader->ReadStringPiece16(&error_details)) {
    set_detailed_error("Unable to read connection close error details.");
    return false;
  }
  frame->error_details = error_details.as_string();

  return true;
}

bool QuicFramer::ProcessGoAwayFrame(QuicDataReader* reader,
                                    QuicGoAwayFrame* frame) {
  uint32_t error_code;
  if (!reader->ReadUInt32(&error_code)) {
    set_detailed_error("Unable to read go away error code.");
    return false;
  }

  if (error_code >= QUIC_LAST_ERROR) {
    // Ignore invalid QUIC error code if any.
    error_code = QUIC_LAST_ERROR;
  }
  frame->error_code = static_cast<QuicErrorCode>(error_code);

  uint32_t stream_id;
  if (!reader->ReadUInt32(&stream_id)) {
    set_detailed_error("Unable to read last good stream id.");
    return false;
  }
  frame->last_good_stream_id = static_cast<QuicStreamId>(stream_id);

  StringPiece reason_phrase;
  if (!reader->ReadStringPiece16(&reason_phrase)) {
    set_detailed_error("Unable to read goaway reason.");
    return false;
  }
  frame->reason_phrase = reason_phrase.as_string();

  return true;
}

bool QuicFramer::ProcessWindowUpdateFrame(QuicDataReader* reader,
                                          QuicWindowUpdateFrame* frame) {
  if (!reader->ReadUInt32(&frame->stream_id)) {
    set_detailed_error("Unable to read stream_id.");
    return false;
  }

  if (!reader->ReadUInt64(&frame->byte_offset)) {
    set_detailed_error("Unable to read window byte_offset.");
    return false;
  }

  return true;
}

bool QuicFramer::ProcessBlockedFrame(QuicDataReader* reader,
                                     QuicBlockedFrame* frame) {
  if (!reader->ReadUInt32(&frame->stream_id)) {
    set_detailed_error("Unable to read stream_id.");
    return false;
  }

  return true;
}

bool QuicFramer::ProcessPathCloseFrame(QuicDataReader* reader,
                                       QuicPathCloseFrame* frame) {
  if (!reader->ReadBytes(&frame->path_id, 1)) {
    set_detailed_error("Unable to read path_id.");
    return false;
  }

  return true;
}

// static
StringPiece QuicFramer::GetAssociatedDataFromEncryptedPacket(
    QuicVersion version,
    const QuicEncryptedPacket& encrypted,
    QuicConnectionIdLength connection_id_length,
    bool includes_version,
    bool includes_diversification_nonce,
    QuicPacketNumberLength packet_number_length) {
  // TODO(ianswett): This is identical to QuicData::AssociatedData.
  return StringPiece(encrypted.data(),
                     GetStartOfEncryptedData(
                         version, connection_id_length, includes_version,
                         includes_diversification_nonce, packet_number_length));
}

void QuicFramer::SetDecrypter(EncryptionLevel level, QuicDecrypter* decrypter) {
  DCHECK(alternative_decrypter_.get() == nullptr);
  DCHECK_GE(level, decrypter_level_);
  decrypter_.reset(decrypter);
  decrypter_level_ = level;
}

void QuicFramer::SetAlternativeDecrypter(EncryptionLevel level,
                                         QuicDecrypter* decrypter,
                                         bool latch_once_used) {
  alternative_decrypter_.reset(decrypter);
  alternative_decrypter_level_ = level;
  alternative_decrypter_latch_ = latch_once_used;
}

const QuicDecrypter* QuicFramer::decrypter() const {
  return decrypter_.get();
}

const QuicDecrypter* QuicFramer::alternative_decrypter() const {
  return alternative_decrypter_.get();
}

void QuicFramer::SetEncrypter(EncryptionLevel level, QuicEncrypter* encrypter) {
  DCHECK_GE(level, 0);
  DCHECK_LT(level, NUM_ENCRYPTION_LEVELS);
  encrypter_[level].reset(encrypter);
}

size_t QuicFramer::EncryptInPlace(EncryptionLevel level,
                                  QuicPathId path_id,
                                  QuicPacketNumber packet_number,
                                  size_t ad_len,
                                  size_t total_len,
                                  size_t buffer_len,
                                  char* buffer) {
  size_t output_length = 0;
  if (!encrypter_[level]->EncryptPacket(
          quic_version_, packet_number,
          StringPiece(buffer, ad_len),                       // Associated data
          StringPiece(buffer + ad_len, total_len - ad_len),  // Plaintext
          buffer + ad_len,  // Destination buffer
          &output_length, buffer_len - ad_len)) {
    RaiseError(QUIC_ENCRYPTION_FAILURE);
    return 0;
  }

  return ad_len + output_length;
}

size_t QuicFramer::EncryptPayload(EncryptionLevel level,
                                  QuicPacketNumber packet_number,
                                  const QuicPacket& packet,
                                  char* buffer,
                                  size_t buffer_len) {
  DCHECK(encrypter_[level].get() != nullptr);

  StringPiece associated_data = packet.AssociatedData(quic_version_);
  // Copy in the header, because the encrypter only populates the encrypted
  // plaintext content.
  const size_t ad_len = associated_data.length();
  memmove(buffer, associated_data.data(), ad_len);
  // Encrypt the plaintext into the buffer.
  size_t output_length = 0;
  if (!encrypter_[level]->EncryptPacket(
          quic_version_, packet_number, associated_data,
          packet.Plaintext(quic_version_), buffer + ad_len, &output_length,
          buffer_len - ad_len)) {
    RaiseError(QUIC_ENCRYPTION_FAILURE);
    return 0;
  }

  return ad_len + output_length;
}

size_t QuicFramer::GetMaxPlaintextSize(size_t ciphertext_size) {
  // In order to keep the code simple, we don't have the current encryption
  // level to hand. Both the NullEncrypter and AES-GCM have a tag length of 12.
  size_t min_plaintext_size = ciphertext_size;

  for (int i = ENCRYPTION_NONE; i < NUM_ENCRYPTION_LEVELS; i++) {
    if (encrypter_[i].get() != nullptr) {
      size_t size = encrypter_[i]->GetMaxPlaintextSize(ciphertext_size);
      if (size < min_plaintext_size) {
        min_plaintext_size = size;
      }
    }
  }

  return min_plaintext_size;
}

bool QuicFramer::DecryptPayload(QuicDataReader* encrypted_reader,
                                const QuicPacketHeader& header,
                                const QuicEncryptedPacket& packet,
                                char* decrypted_buffer,
                                size_t buffer_length,
                                size_t* decrypted_length) {
  StringPiece encrypted = encrypted_reader->ReadRemainingPayload();
  DCHECK(decrypter_.get() != nullptr);
  StringPiece associated_data = GetAssociatedDataFromEncryptedPacket(
      quic_version_, packet, header.public_header.connection_id_length,
      header.public_header.version_flag, header.public_header.nonce != nullptr,
      header.public_header.packet_number_length);

  bool success = decrypter_->DecryptPacket(
      quic_version_, header.packet_number, associated_data, encrypted,
      decrypted_buffer, decrypted_length, buffer_length);
  if (success) {
    visitor_->OnDecryptedPacket(decrypter_level_);
  } else if (alternative_decrypter_.get() != nullptr) {
    if (header.public_header.nonce != nullptr) {
      DCHECK_EQ(perspective_, Perspective::IS_CLIENT);
      alternative_decrypter_->SetDiversificationNonce(
          *header.public_header.nonce);
    }
    bool try_alternative_decryption = true;
    if (alternative_decrypter_level_ == ENCRYPTION_INITIAL) {
      if (perspective_ == Perspective::IS_CLIENT) {
        if (header.public_header.nonce == nullptr) {
          // Can not use INITIAL decryption without a diversification nonce.
          try_alternative_decryption = false;
        }
      } else {
        DCHECK(header.public_header.nonce == nullptr);
      }
    }

    if (try_alternative_decryption) {
      success = alternative_decrypter_->DecryptPacket(
          quic_version_, header.packet_number, associated_data, encrypted,
          decrypted_buffer, decrypted_length, buffer_length);
    }
    if (success) {
      visitor_->OnDecryptedPacket(alternative_decrypter_level_);
      if (alternative_decrypter_latch_) {
        // Switch to the alternative decrypter and latch so that we cannot
        // switch back.
        decrypter_ = std::move(alternative_decrypter_);
        decrypter_level_ = alternative_decrypter_level_;
        alternative_decrypter_level_ = ENCRYPTION_NONE;
      } else {
        // Switch the alternative decrypter so that we use it first next time.
        decrypter_.swap(alternative_decrypter_);
        EncryptionLevel level = alternative_decrypter_level_;
        alternative_decrypter_level_ = decrypter_level_;
        decrypter_level_ = level;
      }
    }
  }

  if (!success) {
    QUIC_DVLOG(1) << ENDPOINT << "DecryptPacket failed for packet_number:"
                  << header.packet_number;
    return false;
  }

  return true;
}

size_t QuicFramer::GetAckFrameTimeStampSize(const QuicAckFrame& ack) {
  if (ack.received_packet_times.empty()) {
    return 0;
  }

  return 5 + 3 * (ack.received_packet_times.size() - 1);
}

size_t QuicFramer::GetAckFrameSize(
    const QuicAckFrame& ack,
    QuicPacketNumberLength packet_number_length) {
  size_t ack_size = 0;

  AckFrameInfo ack_info = GetAckFrameInfo(ack);
  QuicPacketNumberLength largest_acked_length =
      GetMinSequenceNumberLength(ack.largest_observed);
  QuicPacketNumberLength ack_block_length =
      GetMinSequenceNumberLength(ack_info.max_block_length);

  ack_size = GetMinAckFrameSize(quic_version_, largest_acked_length);
  // First ack block length.
  ack_size += ack_block_length;
  if (ack_info.num_ack_blocks != 0) {
    ack_size += kNumberOfAckBlocksSize;
    ack_size += std::min(ack_info.num_ack_blocks, kMaxAckBlocks) *
                (ack_block_length + PACKET_1BYTE_PACKET_NUMBER);
  }

  // Include timestamps.
  ack_size += GetAckFrameTimeStampSize(ack);

  return ack_size;
}

size_t QuicFramer::ComputeFrameLength(
    const QuicFrame& frame,
    bool last_frame_in_packet,
    QuicPacketNumberLength packet_number_length) {
  switch (frame.type) {
    case STREAM_FRAME:
      return GetMinStreamFrameSize(frame.stream_frame->stream_id,
                                   frame.stream_frame->offset,
                                   last_frame_in_packet) +
             frame.stream_frame->data_length;
    case ACK_FRAME: {
      return GetAckFrameSize(*frame.ack_frame, packet_number_length);
    }
    case STOP_WAITING_FRAME:
      return GetStopWaitingFrameSize(quic_version_, packet_number_length);
    case MTU_DISCOVERY_FRAME:
    // MTU discovery frames are serialized as ping frames.
    case PING_FRAME:
      // Ping has no payload.
      return kQuicFrameTypeSize;
    case RST_STREAM_FRAME:
      return GetRstStreamFrameSize();
    case CONNECTION_CLOSE_FRAME:
      return GetMinConnectionCloseFrameSize() +
             frame.connection_close_frame->error_details.size();
    case GOAWAY_FRAME:
      return GetMinGoAwayFrameSize() + frame.goaway_frame->reason_phrase.size();
    case WINDOW_UPDATE_FRAME:
      return GetWindowUpdateFrameSize();
    case BLOCKED_FRAME:
      return GetBlockedFrameSize();
    case PATH_CLOSE_FRAME:
      return GetPathCloseFrameSize();
    case PADDING_FRAME:
      DCHECK(false);
      return 0;
    case NUM_FRAME_TYPES:
      DCHECK(false);
      return 0;
  }

  // Not reachable, but some Chrome compilers can't figure that out.  *sigh*
  DCHECK(false);
  return 0;
}

bool QuicFramer::AppendTypeByte(const QuicFrame& frame,
                                bool no_stream_frame_length,
                                QuicDataWriter* writer) {
  uint8_t type_byte = 0;
  switch (frame.type) {
    case STREAM_FRAME: {
      if (frame.stream_frame == nullptr) {
        QUIC_BUG << "Failed to append STREAM frame with no stream_frame.";
      }
      // Fin bit.
      type_byte |= frame.stream_frame->fin ? kQuicStreamFinMask : 0;

      // Data Length bit.
      type_byte <<= kQuicStreamDataLengthShift;
      type_byte |= no_stream_frame_length ? 0 : kQuicStreamDataLengthMask;

      // Offset 3 bits.
      type_byte <<= kQuicStreamOffsetShift;
      const size_t offset_len = GetStreamOffsetSize(frame.stream_frame->offset);
      if (offset_len > 0) {
        type_byte |= offset_len - 1;
      }

      // stream id 2 bits.
      type_byte <<= kQuicStreamIdShift;
      type_byte |= GetStreamIdSize(frame.stream_frame->stream_id) - 1;
      type_byte |= kQuicFrameTypeStreamMask;  // Set Stream Frame Type to 1.
      break;
    }
    case ACK_FRAME:
      return true;
    case MTU_DISCOVERY_FRAME:
      type_byte = static_cast<uint8_t>(PING_FRAME);
      break;
    default:
      type_byte = static_cast<uint8_t>(frame.type);
      break;
  }

  return writer->WriteUInt8(type_byte);
}

// static
bool QuicFramer::AppendPacketSequenceNumber(
    QuicPacketNumberLength packet_number_length,
    QuicPacketNumber packet_number,
    QuicDataWriter* writer) {
  // Ensure the entire packet number can be written.
  if (writer->capacity() - writer->length() <
      static_cast<size_t>(packet_number_length)) {
    return false;
  }
  switch (packet_number_length) {
    case PACKET_1BYTE_PACKET_NUMBER:
      return writer->WriteUInt8(packet_number & k1ByteSequenceNumberMask);
      break;
    case PACKET_2BYTE_PACKET_NUMBER:
      return writer->WriteUInt16(packet_number & k2ByteSequenceNumberMask);
      break;
    case PACKET_4BYTE_PACKET_NUMBER:
      return writer->WriteUInt32(packet_number & k4ByteSequenceNumberMask);
      break;
    case PACKET_6BYTE_PACKET_NUMBER:
      return writer->WriteUInt48(packet_number & k6ByteSequenceNumberMask);
      break;
    default:
      DCHECK(false) << "packet_number_length: " << packet_number_length;
      return false;
  }
}

// static
bool QuicFramer::AppendAckBlock(uint8_t gap,
                                QuicPacketNumberLength length_length,
                                QuicPacketNumber length,
                                QuicDataWriter* writer) {
  return AppendPacketSequenceNumber(PACKET_1BYTE_PACKET_NUMBER, gap, writer) &&
         AppendPacketSequenceNumber(length_length, length, writer);
}

bool QuicFramer::AppendStreamFrame(const QuicStreamFrame& frame,
                                   bool no_stream_frame_length,
                                   QuicDataWriter* writer) {
  if (!writer->WriteBytes(&frame.stream_id, GetStreamIdSize(frame.stream_id))) {
    QUIC_BUG << "Writing stream id size failed.";
    return false;
  }
  if (!writer->WriteBytes(&frame.offset, GetStreamOffsetSize(frame.offset))) {
    QUIC_BUG << "Writing offset size failed.";
    return false;
  }
  if (!no_stream_frame_length) {
    if ((frame.data_length > std::numeric_limits<uint16_t>::max()) ||
        !writer->WriteUInt16(static_cast<uint16_t>(frame.data_length))) {
      QUIC_BUG << "Writing stream frame length failed";
      return false;
    }
  }

  if (!writer->WriteBytes(frame.data_buffer, frame.data_length)) {
    QUIC_BUG << "Writing frame data failed.";
    return false;
  }
  return true;
}

void QuicFramer::set_version(const QuicVersion version) {
  DCHECK(IsSupportedVersion(version)) << QuicVersionToString(version);
  quic_version_ = version;
}

bool QuicFramer::AppendAckFrameAndTypeByte(const QuicAckFrame& frame,
                                           QuicDataWriter* writer) {
  const AckFrameInfo new_ack_info = GetAckFrameInfo(frame);
  QuicPacketNumber largest_acked = frame.largest_observed;
  QuicPacketNumberLength largest_acked_length =
      GetMinSequenceNumberLength(largest_acked);
  QuicPacketNumberLength ack_block_length =
      GetMinSequenceNumberLength(new_ack_info.max_block_length);
  // Calculate available bytes for timestamps and ack blocks.
  int32_t available_timestamp_and_ack_block_bytes =
      writer->capacity() - writer->length() - ack_block_length -
      GetMinAckFrameSize(quic_version_, largest_acked_length) -
      (new_ack_info.num_ack_blocks != 0 ? kNumberOfAckBlocksSize : 0);
  DCHECK_LE(0, available_timestamp_and_ack_block_bytes);

  // Write out the type byte by setting the low order bits and doing shifts
  // to make room for the next bit flags to be set.
  // Whether there are multiple ack blocks.
  uint8_t type_byte =
      new_ack_info.num_ack_blocks == 0 ? 0 : kQuicHasMultipleAckBlocksMask;
  type_byte <<= kQuicHasMultipleAckBlocksShift;

  // Largest acked length.
  type_byte <<= kQuicSequenceNumberLengthShift;
  type_byte |= GetSequenceNumberFlags(largest_acked_length);

  // Ack block length.
  type_byte <<= kQuicSequenceNumberLengthShift;
  type_byte |= GetSequenceNumberFlags(ack_block_length);

  type_byte |= kQuicFrameTypeAckMask;

  if (!writer->WriteUInt8(type_byte)) {
    return false;
  }

  // Largest acked.
  if (!AppendPacketSequenceNumber(largest_acked_length, largest_acked,
                                  writer)) {
    return false;
  }

  // Largest acked delta time.
  uint64_t ack_delay_time_us = kUFloat16MaxValue;
  if (!frame.ack_delay_time.IsInfinite()) {
    DCHECK_LE(0u, frame.ack_delay_time.ToMicroseconds());
    ack_delay_time_us = frame.ack_delay_time.ToMicroseconds();
  }
  if (!writer->WriteUFloat16(ack_delay_time_us)) {
    return false;
  }

  size_t max_num_ack_blocks = available_timestamp_and_ack_block_bytes /
                              (ack_block_length + PACKET_1BYTE_PACKET_NUMBER);

  // Number of ack blocks.
  size_t num_ack_blocks =
      std::min(new_ack_info.num_ack_blocks, max_num_ack_blocks);
  if (num_ack_blocks > std::numeric_limits<uint8_t>::max()) {
    num_ack_blocks = std::numeric_limits<uint8_t>::max();
  }

  if (num_ack_blocks > 0) {
    if (!writer->WriteBytes(&num_ack_blocks, 1)) {
      return false;
    }
  }

  // First ack block length.
  if (!AppendPacketSequenceNumber(ack_block_length,
                                  new_ack_info.first_block_length, writer)) {
    return false;
  }

  // Ack blocks.
  if (num_ack_blocks > 0) {
    size_t num_ack_blocks_written = 0;
    // Append, in descending order from the largest ACKed packet, a series of
    // ACK blocks that represents the successfully acknoweldged packets. Each
    // appended gap/block length represents a descending delta from the previous
    // block. i.e.:
    // |--- length ---|--- gap ---|--- length ---|--- gap ---|--- largest ---|
    // For gaps larger than can be represented by a single encoded gap, a 0
    // length gap of the maximum is used, i.e.:
    // |--- length ---|--- gap ---|- 0 -|--- gap ---|--- largest ---|
    auto itr = frame.packets.rbegin();
    QuicPacketNumber previous_start = itr->min();
    ++itr;

    for (;
         itr != frame.packets.rend() && num_ack_blocks_written < num_ack_blocks;
         previous_start = itr->min(), ++itr) {
      const auto& interval = *itr;
      const QuicPacketNumber total_gap = previous_start - interval.max();
      const size_t num_encoded_gaps =
          (total_gap + std::numeric_limits<uint8_t>::max() - 1) /
          std::numeric_limits<uint8_t>::max();
      DCHECK_LE(0u, num_encoded_gaps);

      // Append empty ACK blocks because the gap is longer than a single gap.
      for (size_t i = 1;
           i < num_encoded_gaps && num_ack_blocks_written < num_ack_blocks;
           ++i) {
        if (!AppendAckBlock(std::numeric_limits<uint8_t>::max(),
                            ack_block_length, 0, writer)) {
          return false;
        }
        ++num_ack_blocks_written;
      }
      if (num_ack_blocks_written >= num_ack_blocks) {
        if (QUIC_PREDICT_FALSE(num_ack_blocks_written != num_ack_blocks)) {
          QUIC_BUG << "Wrote " << num_ack_blocks_written
                   << ", expected to write " << num_ack_blocks;
        }
        break;
      }

      const uint8_t last_gap =
          total_gap -
          (num_encoded_gaps - 1) * std::numeric_limits<uint8_t>::max();
      // Append the final ACK block with a non-empty size.
      if (!AppendAckBlock(last_gap, ack_block_length, interval.Length(),
                          writer)) {
        return false;
      }
      ++num_ack_blocks_written;
    }
    DCHECK_EQ(num_ack_blocks, num_ack_blocks_written);
  }

  // Timestamps.
  // If we don't have enough available space to append all the timestamps, don't
  // append any of them.
  if (writer->capacity() - writer->length() >=
      GetAckFrameTimeStampSize(frame)) {
    if (!AppendTimestampToAckFrame(frame, writer)) {
      return false;
    }
  } else {
    uint8_t num_received_packets = 0;
    if (!writer->WriteBytes(&num_received_packets, 1)) {
      return false;
    }
  }

  return true;
}

bool QuicFramer::AppendTimestampToAckFrame(const QuicAckFrame& frame,
                                           QuicDataWriter* writer) {
  DCHECK_GE(std::numeric_limits<uint8_t>::max(),
            frame.received_packet_times.size());
  // num_received_packets is only 1 byte.
  if (frame.received_packet_times.size() >
      std::numeric_limits<uint8_t>::max()) {
    return false;
  }

  uint8_t num_received_packets = frame.received_packet_times.size();
  if (!writer->WriteBytes(&num_received_packets, 1)) {
    return false;
  }
  if (num_received_packets == 0) {
    return true;
  }

  PacketTimeVector::const_iterator it = frame.received_packet_times.begin();
  QuicPacketNumber packet_number = it->first;
  QuicPacketNumber delta_from_largest_observed =
      frame.largest_observed - packet_number;

  DCHECK_GE(std::numeric_limits<uint8_t>::max(), delta_from_largest_observed);
  if (delta_from_largest_observed > std::numeric_limits<uint8_t>::max()) {
    return false;
  }

  if (!writer->WriteUInt8(delta_from_largest_observed &
                          k1ByteSequenceNumberMask)) {
    return false;
  }

  // Use the lowest 4 bytes of the time delta from the creation_time_.
  const uint64_t time_epoch_delta_us = UINT64_C(1) << 32;
  uint32_t time_delta_us =
      static_cast<uint32_t>((it->second - creation_time_).ToMicroseconds() &
                            (time_epoch_delta_us - 1));
  if (!writer->WriteBytes(&time_delta_us, sizeof(time_delta_us))) {
    return false;
  }

  QuicTime prev_time = it->second;

  for (++it; it != frame.received_packet_times.end(); ++it) {
    packet_number = it->first;
    delta_from_largest_observed = frame.largest_observed - packet_number;

    if (delta_from_largest_observed > std::numeric_limits<uint8_t>::max()) {
      return false;
    }

    if (!writer->WriteUInt8(delta_from_largest_observed &
                            k1ByteSequenceNumberMask)) {
      return false;
    }

    uint64_t frame_time_delta_us = (it->second - prev_time).ToMicroseconds();
    prev_time = it->second;
    if (!writer->WriteUFloat16(frame_time_delta_us)) {
      return false;
    }
  }
  return true;
}

bool QuicFramer::AppendStopWaitingFrame(const QuicPacketHeader& header,
                                        const QuicStopWaitingFrame& frame,
                                        QuicDataWriter* writer) {
  DCHECK_GE(header.packet_number, frame.least_unacked);
  const QuicPacketNumber least_unacked_delta =
      header.packet_number - frame.least_unacked;
  const QuicPacketNumber length_shift =
      header.public_header.packet_number_length * 8;

  if (least_unacked_delta >> length_shift > 0) {
    QUIC_BUG << "packet_number_length "
             << header.public_header.packet_number_length
             << " is too small for least_unacked_delta: " << least_unacked_delta
             << " packet_number:" << header.packet_number
             << " least_unacked:" << frame.least_unacked
             << " version:" << quic_version_;
    return false;
  }
  if (!AppendPacketSequenceNumber(header.public_header.packet_number_length,
                                  least_unacked_delta, writer)) {
    QUIC_BUG << " seq failed: " << header.public_header.packet_number_length;
    return false;
  }

  return true;
}

bool QuicFramer::AppendRstStreamFrame(const QuicRstStreamFrame& frame,
                                      QuicDataWriter* writer) {
  if (!writer->WriteUInt32(frame.stream_id)) {
    return false;
  }

  if (!writer->WriteUInt64(frame.byte_offset)) {
    return false;
  }

  uint32_t error_code = static_cast<uint32_t>(frame.error_code);
  if (!writer->WriteUInt32(error_code)) {
    return false;
  }

  return true;
}

bool QuicFramer::AppendConnectionCloseFrame(
    const QuicConnectionCloseFrame& frame,
    QuicDataWriter* writer) {
  uint32_t error_code = static_cast<uint32_t>(frame.error_code);
  if (!writer->WriteUInt32(error_code)) {
    return false;
  }
  if (!writer->WriteStringPiece16(frame.error_details)) {
    return false;
  }
  return true;
}

bool QuicFramer::AppendGoAwayFrame(const QuicGoAwayFrame& frame,
                                   QuicDataWriter* writer) {
  uint32_t error_code = static_cast<uint32_t>(frame.error_code);
  if (!writer->WriteUInt32(error_code)) {
    return false;
  }
  uint32_t stream_id = static_cast<uint32_t>(frame.last_good_stream_id);
  if (!writer->WriteUInt32(stream_id)) {
    return false;
  }
  if (!writer->WriteStringPiece16(frame.reason_phrase)) {
    return false;
  }
  return true;
}

bool QuicFramer::AppendWindowUpdateFrame(const QuicWindowUpdateFrame& frame,
                                         QuicDataWriter* writer) {
  uint32_t stream_id = static_cast<uint32_t>(frame.stream_id);
  if (!writer->WriteUInt32(stream_id)) {
    return false;
  }
  if (!writer->WriteUInt64(frame.byte_offset)) {
    return false;
  }
  return true;
}

bool QuicFramer::AppendBlockedFrame(const QuicBlockedFrame& frame,
                                    QuicDataWriter* writer) {
  uint32_t stream_id = static_cast<uint32_t>(frame.stream_id);
  if (!writer->WriteUInt32(stream_id)) {
    return false;
  }
  return true;
}

bool QuicFramer::AppendPathCloseFrame(const QuicPathCloseFrame& frame,
                                      QuicDataWriter* writer) {
  uint8_t path_id = static_cast<uint8_t>(frame.path_id);
  if (!writer->WriteUInt8(path_id)) {
    return false;
  }
  return true;
}

bool QuicFramer::RaiseError(QuicErrorCode error) {
  QUIC_DLOG(INFO) << ENDPOINT << "Error: " << QuicErrorCodeToString(error)
                  << " detail: " << detailed_error_;
  set_error(error);
  visitor_->OnError(this);
  return false;
}

}  // namespace net
