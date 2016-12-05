// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_PROTOCOL_H_
#define NET_QUIC_QUIC_PROTOCOL_H_

#include <limits>
#include <list>
#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_piece.h"
#include "net/base/int128.h"
#include "net/base/iovec.h"
#include "net/base/net_export.h"
#include "net/quic/core/frames/quic_frame.h"
#include "net/quic/core/quic_ack_listener_interface.h"
#include "net/quic/core/quic_bandwidth.h"
#include "net/quic/core/quic_constants.h"
#include "net/quic/core/quic_error_codes.h"
#include "net/quic/core/quic_time.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/core/quic_versions.h"
#include "net/quic/platform/api/quic_socket_address.h"

namespace net {

class QuicPacket;
struct QuicPacketHeader;

// Size in bytes of the data packet header.
NET_EXPORT_PRIVATE size_t GetPacketHeaderSize(QuicVersion version,
                                              const QuicPacketHeader& header);

NET_EXPORT_PRIVATE size_t
GetPacketHeaderSize(QuicVersion version,
                    QuicConnectionIdLength connection_id_length,
                    bool include_version,
                    bool include_path_id,
                    bool include_diversification_nonce,
                    QuicPacketNumberLength packet_number_length);

// Index of the first byte in a QUIC packet of encrypted data.
NET_EXPORT_PRIVATE size_t
GetStartOfEncryptedData(QuicVersion version, const QuicPacketHeader& header);

NET_EXPORT_PRIVATE size_t
GetStartOfEncryptedData(QuicVersion version,
                        QuicConnectionIdLength connection_id_length,
                        bool include_version,
                        bool include_path_id,
                        bool include_diversification_nonce,
                        QuicPacketNumberLength packet_number_length);

struct NET_EXPORT_PRIVATE QuicPacketPublicHeader {
  QuicPacketPublicHeader();
  explicit QuicPacketPublicHeader(const QuicPacketPublicHeader& other);
  ~QuicPacketPublicHeader();

  // Universal header. All QuicPacket headers will have a connection_id and
  // public flags.
  QuicConnectionId connection_id;
  QuicConnectionIdLength connection_id_length;
  bool multipath_flag;
  bool reset_flag;
  bool version_flag;
  QuicPacketNumberLength packet_number_length;
  QuicVersionVector versions;
  // nonce contains an optional, 32-byte nonce value. If not included in the
  // packet, |nonce| will be empty.
  DiversificationNonce* nonce;
};

// Header for Data packets.
struct NET_EXPORT_PRIVATE QuicPacketHeader {
  QuicPacketHeader();
  explicit QuicPacketHeader(const QuicPacketPublicHeader& header);
  QuicPacketHeader(const QuicPacketHeader& other);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicPacketHeader& s);

  QuicPacketPublicHeader public_header;
  QuicPacketNumber packet_number;
  QuicPathId path_id;
};

struct NET_EXPORT_PRIVATE QuicPublicResetPacket {
  QuicPublicResetPacket();
  explicit QuicPublicResetPacket(const QuicPacketPublicHeader& header);

  QuicPacketPublicHeader public_header;
  QuicPublicResetNonceProof nonce_proof;
  // TODO(fayang): remove rejected_packet_number when deprecating
  // FLAGS_quic_remove_packet_number_from_public_reset.
  QuicPacketNumber rejected_packet_number;
  QuicSocketAddress client_address;
};

typedef QuicPacketPublicHeader QuicVersionNegotiationPacket;

class NET_EXPORT_PRIVATE QuicData {
 public:
  QuicData(const char* buffer, size_t length);
  QuicData(const char* buffer, size_t length, bool owns_buffer);
  virtual ~QuicData();

  base::StringPiece AsStringPiece() const {
    return base::StringPiece(data(), length());
  }

  const char* data() const { return buffer_; }
  size_t length() const { return length_; }

 private:
  const char* buffer_;
  size_t length_;
  bool owns_buffer_;

  DISALLOW_COPY_AND_ASSIGN(QuicData);
};

class NET_EXPORT_PRIVATE QuicPacket : public QuicData {
 public:
  // TODO(fayang): 4 fields from public header are passed in as arguments.
  // Consider to add a convenience method which directly accepts the entire
  // public header.
  QuicPacket(char* buffer,
             size_t length,
             bool owns_buffer,
             QuicConnectionIdLength connection_id_length,
             bool includes_version,
             bool includes_path_id,
             bool includes_diversification_nonce,
             QuicPacketNumberLength packet_number_length);

  base::StringPiece AssociatedData(QuicVersion version) const;
  base::StringPiece Plaintext(QuicVersion version) const;

  char* mutable_data() { return buffer_; }

 private:
  char* buffer_;
  const QuicConnectionIdLength connection_id_length_;
  const bool includes_version_;
  const bool includes_path_id_;
  const bool includes_diversification_nonce_;
  const QuicPacketNumberLength packet_number_length_;

  DISALLOW_COPY_AND_ASSIGN(QuicPacket);
};

class NET_EXPORT_PRIVATE QuicEncryptedPacket : public QuicData {
 public:
  QuicEncryptedPacket(const char* buffer, size_t length);
  QuicEncryptedPacket(const char* buffer, size_t length, bool owns_buffer);

  // Clones the packet into a new packet which owns the buffer.
  std::unique_ptr<QuicEncryptedPacket> Clone() const;

  // By default, gtest prints the raw bytes of an object. The bool data
  // member (in the base class QuicData) causes this object to have padding
  // bytes, which causes the default gtest object printer to read
  // uninitialize memory. So we need to teach gtest how to print this object.
  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os,
      const QuicEncryptedPacket& s);

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicEncryptedPacket);
};

// A received encrypted QUIC packet, with a recorded time of receipt.
class NET_EXPORT_PRIVATE QuicReceivedPacket : public QuicEncryptedPacket {
 public:
  QuicReceivedPacket(const char* buffer, size_t length, QuicTime receipt_time);
  QuicReceivedPacket(const char* buffer,
                     size_t length,
                     QuicTime receipt_time,
                     bool owns_buffer);
  QuicReceivedPacket(const char* buffer,
                     size_t length,
                     QuicTime receipt_time,
                     bool owns_buffer,
                     int ttl,
                     bool ttl_valid);

  // Clones the packet into a new packet which owns the buffer.
  std::unique_ptr<QuicReceivedPacket> Clone() const;

  // Returns the time at which the packet was received.
  QuicTime receipt_time() const { return receipt_time_; }

  // This is the TTL of the packet, assuming ttl_vaild_ is true.
  int ttl() const { return ttl_; }

  // By default, gtest prints the raw bytes of an object. The bool data
  // member (in the base class QuicData) causes this object to have padding
  // bytes, which causes the default gtest object printer to read
  // uninitialize memory. So we need to teach gtest how to print this object.
  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os,
      const QuicReceivedPacket& s);

 private:
  const QuicTime receipt_time_;
  int ttl_;

  DISALLOW_COPY_AND_ASSIGN(QuicReceivedPacket);
};

struct NET_EXPORT_PRIVATE SerializedPacket {
  SerializedPacket(QuicPathId path_id,
                   QuicPacketNumber packet_number,
                   QuicPacketNumberLength packet_number_length,
                   const char* encrypted_buffer,
                   QuicPacketLength encrypted_length,
                   bool has_ack,
                   bool has_stop_waiting);
  SerializedPacket(const SerializedPacket& other);
  ~SerializedPacket();

  // Not owned.
  const char* encrypted_buffer;
  QuicPacketLength encrypted_length;
  QuicFrames retransmittable_frames;
  IsHandshake has_crypto_handshake;
  // -1: full padding to the end of a max-sized packet
  //  0: no padding
  //  otherwise: only pad up to num_padding_bytes bytes
  int16_t num_padding_bytes;
  QuicPathId path_id;
  QuicPacketNumber packet_number;
  QuicPacketNumberLength packet_number_length;
  EncryptionLevel encryption_level;
  bool has_ack;
  bool has_stop_waiting;
  TransmissionType transmission_type;
  QuicPathId original_path_id;
  QuicPacketNumber original_packet_number;

  // Optional notifiers which will be informed when this packet has been ACKed.
  std::list<AckListenerWrapper> listeners;
};

// Deletes and clears all the frames and the packet from serialized packet.
NET_EXPORT_PRIVATE void ClearSerializedPacket(
    SerializedPacket* serialized_packet);

// Allocates a new char[] of size |packet.encrypted_length| and copies in
// |packet.encrypted_buffer|.
NET_EXPORT_PRIVATE char* CopyBuffer(const SerializedPacket& packet);

}  // namespace net

#endif  // NET_QUIC_QUIC_PROTOCOL_H_
