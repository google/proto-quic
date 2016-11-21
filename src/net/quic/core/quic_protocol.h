// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_PROTOCOL_H_
#define NET_QUIC_QUIC_PROTOCOL_H_

#include <stddef.h>
#include <stdint.h>

#include <array>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <ostream>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_piece.h"
#include "net/base/int128.h"
#include "net/base/iovec.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_export.h"
#include "net/quic/core/interval_set.h"
#include "net/quic/core/quic_bandwidth.h"
#include "net/quic/core/quic_buffer_allocator.h"
#include "net/quic/core/quic_constants.h"
#include "net/quic/core/quic_error_codes.h"
#include "net/quic/core/quic_time.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/core/quic_versions.h"

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
  IPEndPoint client_address;
};

typedef QuicPacketPublicHeader QuicVersionNegotiationPacket;

// A padding frame contains no payload.
struct NET_EXPORT_PRIVATE QuicPaddingFrame {
  QuicPaddingFrame() : num_padding_bytes(-1) {}
  explicit QuicPaddingFrame(int num_padding_bytes)
      : num_padding_bytes(num_padding_bytes) {}

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicPaddingFrame& s);

  // -1: full padding to the end of a max-sized packet
  // otherwise: only pad up to num_padding_bytes bytes
  int num_padding_bytes;
};

// A ping frame contains no payload, though it is retransmittable,
// and ACK'd just like other normal frames.
struct NET_EXPORT_PRIVATE QuicPingFrame {};

// A path MTU discovery frame contains no payload and is serialized as a ping
// frame.
struct NET_EXPORT_PRIVATE QuicMtuDiscoveryFrame {};

// Deleter for stream buffers. Copyable to support platforms where the deleter
// of a unique_ptr must be copyable. Otherwise it would be nice for this to be
// move-only.
class NET_EXPORT_PRIVATE StreamBufferDeleter {
 public:
  StreamBufferDeleter() : allocator_(nullptr) {}
  explicit StreamBufferDeleter(QuicBufferAllocator* allocator)
      : allocator_(allocator) {}

  // Deletes |buffer| using |allocator_|.
  void operator()(char* buffer) const;

 private:
  // Not owned; must be valid so long as the buffer stored in the unique_ptr
  // that owns |this| is valid.
  QuicBufferAllocator* allocator_;
};

using UniqueStreamBuffer = std::unique_ptr<char[], StreamBufferDeleter>;

// Allocates memory of size |size| using |allocator| for a QUIC stream buffer.
NET_EXPORT_PRIVATE UniqueStreamBuffer
NewStreamBuffer(QuicBufferAllocator* allocator, size_t size);

struct NET_EXPORT_PRIVATE QuicStreamFrame {
  QuicStreamFrame();
  QuicStreamFrame(QuicStreamId stream_id,
                  bool fin,
                  QuicStreamOffset offset,
                  base::StringPiece data);
  QuicStreamFrame(QuicStreamId stream_id,
                  bool fin,
                  QuicStreamOffset offset,
                  QuicPacketLength data_length,
                  UniqueStreamBuffer buffer);
  ~QuicStreamFrame();

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicStreamFrame& s);

  QuicStreamId stream_id;
  bool fin;
  QuicPacketLength data_length;
  const char* data_buffer;
  QuicStreamOffset offset;  // Location of this data in the stream.
  // nullptr when the QuicStreamFrame is received, and non-null when sent.
  UniqueStreamBuffer buffer;

 private:
  QuicStreamFrame(QuicStreamId stream_id,
                  bool fin,
                  QuicStreamOffset offset,
                  const char* data_buffer,
                  QuicPacketLength data_length,
                  UniqueStreamBuffer buffer);

  DISALLOW_COPY_AND_ASSIGN(QuicStreamFrame);
};
static_assert(sizeof(QuicStreamFrame) <= 64,
              "Keep the QuicStreamFrame size to a cacheline.");

typedef std::vector<std::pair<QuicPacketNumber, QuicTime>> PacketTimeVector;

struct NET_EXPORT_PRIVATE QuicStopWaitingFrame {
  QuicStopWaitingFrame();
  ~QuicStopWaitingFrame();

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os,
      const QuicStopWaitingFrame& s);
  // Path which this stop waiting frame belongs to.
  QuicPathId path_id;
  // The lowest packet we've sent which is unacked, and we expect an ack for.
  QuicPacketNumber least_unacked;
};

// A sequence of packet numbers where each number is unique. Intended to be used
// in a sliding window fashion, where smaller old packet numbers are removed and
// larger new packet numbers are added, with the occasional random access.
class NET_EXPORT_PRIVATE PacketNumberQueue {
 public:
  using const_iterator = IntervalSet<QuicPacketNumber>::const_iterator;
  using const_reverse_iterator =
      IntervalSet<QuicPacketNumber>::const_reverse_iterator;

  PacketNumberQueue();
  PacketNumberQueue(const PacketNumberQueue& other);
  // TODO(rtenneti): on windows RValue reference gives errors.
  // PacketNumberQueue(PacketNumberQueue&& other);
  ~PacketNumberQueue();

  PacketNumberQueue& operator=(const PacketNumberQueue& other);
  // PacketNumberQueue& operator=(PacketNumberQueue&& other);

  // Adds |packet_number| to the set of packets in the queue.
  void Add(QuicPacketNumber packet_number);

  // Adds packets between [lower, higher) to the set of packets in the queue. It
  // is undefined behavior to call this with |higher| < |lower|.
  void Add(QuicPacketNumber lower, QuicPacketNumber higher);

  // Removes |packet_number| from the set of packets in the queue.
  void Remove(QuicPacketNumber packet_number);

  // Removes packets numbers between [lower, higher) to the set of packets in
  // the queue. It is undefined behavior to call this with |higher| < |lower|.
  void Remove(QuicPacketNumber lower, QuicPacketNumber higher);

  // Removes packets with values less than |higher| from the set of packets in
  // the queue. Returns true if packets were removed.
  bool RemoveUpTo(QuicPacketNumber higher);

  // Mutates packet number set so that it contains only those packet numbers
  // from minimum to maximum packet number not currently in the set. Do nothing
  // if packet number set is empty.
  void Complement();

  // Returns true if the queue contains |packet_number|.
  bool Contains(QuicPacketNumber packet_number) const;

  // Returns true if the queue is empty.
  bool Empty() const;

  // Returns the minimum packet number stored in the queue. It is undefined
  // behavior to call this if the queue is empty.
  QuicPacketNumber Min() const;

  // Returns the maximum packet number stored in the queue. It is undefined
  // behavior to call this if the queue is empty.
  QuicPacketNumber Max() const;

  // Returns the number of unique packets stored in the queue. Inefficient; only
  // exposed for testing.
  size_t NumPacketsSlow() const;

  // Returns the number of disjoint packet number intervals contained in the
  // queue.
  size_t NumIntervals() const;

  // Returns the length of last interval.
  QuicPacketNumber LastIntervalLength() const;

  // Returns iterators over the packet number intervals.
  const_iterator begin() const;
  const_iterator end() const;
  const_reverse_iterator rbegin() const;
  const_reverse_iterator rend() const;
  const_iterator lower_bound(QuicPacketNumber packet_number) const;

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os,
      const PacketNumberQueue& q);

 private:
  IntervalSet<QuicPacketNumber> packet_number_intervals_;
};

struct NET_EXPORT_PRIVATE QuicAckFrame {
  QuicAckFrame();
  QuicAckFrame(const QuicAckFrame& other);
  ~QuicAckFrame();

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicAckFrame& s);

  // The highest packet number we've observed from the peer.
  QuicPacketNumber largest_observed;

  // Time elapsed since largest_observed was received until this Ack frame was
  // sent.
  QuicTime::Delta ack_delay_time;

  // Vector of <packet_number, time> for when packets arrived.
  PacketTimeVector received_packet_times;

  // Set of packets.
  PacketNumberQueue packets;

  // Path which this ack belongs to.
  QuicPathId path_id;
};

// True if the packet number is greater than largest_observed or is listed
// as missing.
// Always returns false for packet numbers less than least_unacked.
bool NET_EXPORT_PRIVATE
IsAwaitingPacket(const QuicAckFrame& ack_frame,
                 QuicPacketNumber packet_number,
                 QuicPacketNumber peer_least_packet_awaiting_ack);

struct NET_EXPORT_PRIVATE QuicRstStreamFrame {
  QuicRstStreamFrame();
  QuicRstStreamFrame(QuicStreamId stream_id,
                     QuicRstStreamErrorCode error_code,
                     QuicStreamOffset bytes_written);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os,
      const QuicRstStreamFrame& r);

  QuicStreamId stream_id;
  QuicRstStreamErrorCode error_code;

  // Used to update flow control windows. On termination of a stream, both
  // endpoints must inform the peer of the number of bytes they have sent on
  // that stream. This can be done through normal termination (data packet with
  // FIN) or through a RST.
  QuicStreamOffset byte_offset;
};

struct NET_EXPORT_PRIVATE QuicConnectionCloseFrame {
  QuicConnectionCloseFrame();

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os,
      const QuicConnectionCloseFrame& c);

  QuicErrorCode error_code;
  std::string error_details;
};

struct NET_EXPORT_PRIVATE QuicGoAwayFrame {
  QuicGoAwayFrame();
  QuicGoAwayFrame(QuicErrorCode error_code,
                  QuicStreamId last_good_stream_id,
                  const std::string& reason);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicGoAwayFrame& g);

  QuicErrorCode error_code;
  QuicStreamId last_good_stream_id;
  std::string reason_phrase;
};

// Flow control updates per-stream and at the connection levoel.
// Based on SPDY's WINDOW_UPDATE frame, but uses an absolute byte offset rather
// than a window delta.
// TODO(rjshade): A possible future optimization is to make stream_id and
//                byte_offset variable length, similar to stream frames.
struct NET_EXPORT_PRIVATE QuicWindowUpdateFrame {
  QuicWindowUpdateFrame() {}
  QuicWindowUpdateFrame(QuicStreamId stream_id, QuicStreamOffset byte_offset);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os,
      const QuicWindowUpdateFrame& w);

  // The stream this frame applies to.  0 is a special case meaning the overall
  // connection rather than a specific stream.
  QuicStreamId stream_id;

  // Byte offset in the stream or connection. The receiver of this frame must
  // not send data which would result in this offset being exceeded.
  QuicStreamOffset byte_offset;
};

// The BLOCKED frame is used to indicate to the remote endpoint that this
// endpoint believes itself to be flow-control blocked but otherwise ready to
// send data. The BLOCKED frame is purely advisory and optional.
// Based on SPDY's BLOCKED frame (undocumented as of 2014-01-28).
struct NET_EXPORT_PRIVATE QuicBlockedFrame {
  QuicBlockedFrame() {}
  explicit QuicBlockedFrame(QuicStreamId stream_id);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicBlockedFrame& b);

  // The stream this frame applies to.  0 is a special case meaning the overall
  // connection rather than a specific stream.
  QuicStreamId stream_id;
};

// The PATH_CLOSE frame is used to explicitly close a path. Both endpoints can
// send a PATH_CLOSE frame to initiate a path termination. A path is considered
// to be closed either a PATH_CLOSE frame is sent or received. An endpoint drops
// receive side of a closed path, and packets with retransmittable frames on a
// closed path are marked as retransmissions which will be transmitted on other
// paths.
struct NET_EXPORT_PRIVATE QuicPathCloseFrame {
  QuicPathCloseFrame() {}
  explicit QuicPathCloseFrame(QuicPathId path_id);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os,
      const QuicPathCloseFrame& p);

  QuicPathId path_id;
};

struct NET_EXPORT_PRIVATE QuicFrame {
  QuicFrame();
  explicit QuicFrame(QuicPaddingFrame padding_frame);
  explicit QuicFrame(QuicMtuDiscoveryFrame frame);
  explicit QuicFrame(QuicPingFrame frame);

  explicit QuicFrame(QuicStreamFrame* stream_frame);
  explicit QuicFrame(QuicAckFrame* frame);
  explicit QuicFrame(QuicRstStreamFrame* frame);
  explicit QuicFrame(QuicConnectionCloseFrame* frame);
  explicit QuicFrame(QuicStopWaitingFrame* frame);
  explicit QuicFrame(QuicGoAwayFrame* frame);
  explicit QuicFrame(QuicWindowUpdateFrame* frame);
  explicit QuicFrame(QuicBlockedFrame* frame);
  explicit QuicFrame(QuicPathCloseFrame* frame);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicFrame& frame);

  QuicFrameType type;
  union {
    // Frames smaller than a pointer are inline.
    QuicPaddingFrame padding_frame;
    QuicMtuDiscoveryFrame mtu_discovery_frame;
    QuicPingFrame ping_frame;

    // Frames larger than a pointer.
    QuicStreamFrame* stream_frame;
    QuicAckFrame* ack_frame;
    QuicStopWaitingFrame* stop_waiting_frame;
    QuicRstStreamFrame* rst_stream_frame;
    QuicConnectionCloseFrame* connection_close_frame;
    QuicGoAwayFrame* goaway_frame;
    QuicWindowUpdateFrame* window_update_frame;
    QuicBlockedFrame* blocked_frame;
    QuicPathCloseFrame* path_close_frame;
  };
};
// QuicFrameType consumes 8 bytes with padding.
static_assert(sizeof(QuicFrame) <= 16,
              "Frames larger than 8 bytes should be referenced by pointer.");

typedef std::vector<QuicFrame> QuicFrames;

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
  bool owns_buffer() const { return owns_buffer_; }

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

// Pure virtual class to listen for packet acknowledgements.
class NET_EXPORT_PRIVATE QuicAckListenerInterface
    : public base::RefCounted<QuicAckListenerInterface> {
 public:
  QuicAckListenerInterface() {}

  // Called when a packet is acked.  Called once per packet.
  // |acked_bytes| is the number of data bytes acked.
  virtual void OnPacketAcked(int acked_bytes,
                             QuicTime::Delta ack_delay_time) = 0;

  // Called when a packet is retransmitted.  Called once per packet.
  // |retransmitted_bytes| is the number of data bytes retransmitted.
  virtual void OnPacketRetransmitted(int retransmitted_bytes) = 0;

 protected:
  friend class base::RefCounted<QuicAckListenerInterface>;

  // Delegates are ref counted.
  virtual ~QuicAckListenerInterface() {}
};

// Pure virtual class to close connection on unrecoverable errors.
class NET_EXPORT_PRIVATE QuicConnectionCloseDelegateInterface {
 public:
  virtual ~QuicConnectionCloseDelegateInterface() {}

  // Called when an unrecoverable error is encountered.
  virtual void OnUnrecoverableError(QuicErrorCode error,
                                    const std::string& error_details,
                                    ConnectionCloseSource source) = 0;
};

// Used to generate filtered supported versions based on flags.
class NET_EXPORT_PRIVATE QuicVersionManager {
 public:
  explicit QuicVersionManager(QuicVersionVector supported_versions);
  virtual ~QuicVersionManager();

  // Returns currently supported QUIC versions.
  const QuicVersionVector& GetSupportedVersions();

 protected:
  // Maybe refilter filtered_supported_versions_ based on flags.
  void MaybeRefilterSupportedVersions();

  // Refilters filtered_supported_versions_.
  virtual void RefilterSupportedVersions();

  const QuicVersionVector& filtered_supported_versions() const {
    return filtered_supported_versions_;
  }

 private:
  // FLAGS_quic_enable_version_36_v3
  bool enable_version_36_;
  // The list of versions that may be supported.
  QuicVersionVector allowed_supported_versions_;
  // This vector contains QUIC versions which are currently supported based
  // on flags.
  QuicVersionVector filtered_supported_versions_;
};

struct NET_EXPORT_PRIVATE AckListenerWrapper {
  AckListenerWrapper(QuicAckListenerInterface* listener,
                     QuicPacketLength data_length);
  AckListenerWrapper(const AckListenerWrapper& other);
  ~AckListenerWrapper();

  scoped_refptr<QuicAckListenerInterface> ack_listener;
  QuicPacketLength length;
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

struct NET_EXPORT_PRIVATE TransmissionInfo {
  // Used by STL when assigning into a map.
  TransmissionInfo();

  // Constructs a Transmission with a new all_transmissions set
  // containing |packet_number|.
  TransmissionInfo(EncryptionLevel level,
                   QuicPacketNumberLength packet_number_length,
                   TransmissionType transmission_type,
                   QuicTime sent_time,
                   QuicPacketLength bytes_sent,
                   bool has_crypto_handshake,
                   int num_padding_bytes);

  TransmissionInfo(const TransmissionInfo& other);

  ~TransmissionInfo();

  QuicFrames retransmittable_frames;
  EncryptionLevel encryption_level;
  QuicPacketNumberLength packet_number_length;
  QuicPacketLength bytes_sent;
  QuicTime sent_time;
  // Reason why this packet was transmitted.
  TransmissionType transmission_type;
  // In flight packets have not been abandoned or lost.
  bool in_flight;
  // True if the packet can never be acked, so it can be removed.  Occurs when
  // a packet is never sent, after it is acknowledged once, or if it's a crypto
  // packet we never expect to receive an ack for.
  bool is_unackable;
  // True if the packet contains stream data from the crypto stream.
  bool has_crypto_handshake;
  // Non-zero if the packet needs padding if it's retransmitted.
  int16_t num_padding_bytes;
  // Stores the packet number of the next retransmission of this packet.
  // Zero if the packet has not been retransmitted.
  QuicPacketNumber retransmission;
  // Non-empty if there is a std::listener for this packet.
  std::list<AckListenerWrapper> ack_listeners;
};

// Struct to store the pending retransmission information.
struct PendingRetransmission {
  PendingRetransmission(QuicPathId path_id,
                        QuicPacketNumber packet_number,
                        TransmissionType transmission_type,
                        const QuicFrames& retransmittable_frames,
                        bool has_crypto_handshake,
                        int num_padding_bytes,
                        EncryptionLevel encryption_level,
                        QuicPacketNumberLength packet_number_length)
      : packet_number(packet_number),
        retransmittable_frames(retransmittable_frames),
        transmission_type(transmission_type),
        path_id(path_id),
        has_crypto_handshake(has_crypto_handshake),
        num_padding_bytes(num_padding_bytes),
        encryption_level(encryption_level),
        packet_number_length(packet_number_length) {}

  QuicPacketNumber packet_number;
  const QuicFrames& retransmittable_frames;
  TransmissionType transmission_type;
  QuicPathId path_id;
  bool has_crypto_handshake;
  int num_padding_bytes;
  EncryptionLevel encryption_level;
  QuicPacketNumberLength packet_number_length;
};

}  // namespace net

#endif  // NET_QUIC_QUIC_PROTOCOL_H_
