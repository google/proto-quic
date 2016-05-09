// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_connection_logger.h"

#include <algorithm>
#include <string>
#include <utility>

#include "base/bind.h"
#include "base/callback.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "base/profiler/scoped_tracker.h"
#include "base/strings/string_number_conversions.h"
#include "base/values.h"
#include "net/base/ip_address.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/x509_certificate.h"
#include "net/log/net_log.h"
#include "net/quic/crypto/crypto_handshake_message.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/quic_address_mismatch.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_socket_address_coder.h"
#include "net/quic/quic_time.h"

using base::StringPiece;
using std::string;

namespace net {

namespace {

// We have ranges-of-buckets in the cumulative histogram (covering 21 packet
// sequences) of length 2, 3, 4, ... 22.
// Hence the largest sample is bounded by the sum of those numbers.
const int kBoundingSampleInCumulativeHistogram = ((2 + 22) * 21) / 2;

std::unique_ptr<base::Value> NetLogQuicPacketCallback(
    const IPEndPoint* self_address,
    const IPEndPoint* peer_address,
    size_t packet_size,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("self_address", self_address->ToString());
  dict->SetString("peer_address", peer_address->ToString());
  dict->SetInteger("size", packet_size);
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicPacketSentCallback(
    const SerializedPacket& serialized_packet,
    TransmissionType transmission_type,
    QuicTime sent_time,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("transmission_type", transmission_type);
  dict->SetString("packet_number",
                  base::Uint64ToString(serialized_packet.packet_number));
  dict->SetString("sent_time_us",
                  base::Int64ToString(sent_time.ToDebuggingValue()));
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicPacketRetransmittedCallback(
    QuicPacketNumber old_packet_number,
    QuicPacketNumber new_packet_number,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("old_packet_number", base::Uint64ToString(old_packet_number));
  dict->SetString("new_packet_number", base::Uint64ToString(new_packet_number));
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicDuplicatePacketCallback(
    QuicPacketNumber packet_number,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("packet_number", base::Uint64ToString(packet_number));
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicPacketHeaderCallback(
    const QuicPacketHeader* header,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("connection_id",
                  base::Uint64ToString(header->public_header.connection_id));
  dict->SetInteger("reset_flag", header->public_header.reset_flag);
  dict->SetInteger("version_flag", header->public_header.version_flag);
  dict->SetString("packet_number", base::Uint64ToString(header->packet_number));
  dict->SetInteger("entropy_flag", header->entropy_flag);
  dict->SetInteger("fec_flag", header->fec_flag);
  dict->SetInteger("fec_group", static_cast<int>(header->fec_group));
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicStreamFrameCallback(
    const QuicStreamFrame* frame,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("stream_id", frame->stream_id);
  dict->SetBoolean("fin", frame->fin);
  dict->SetString("offset", base::Uint64ToString(frame->offset));
  dict->SetInteger("length", frame->frame_length);
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicAckFrameCallback(
    const QuicAckFrame* frame,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("largest_observed",
                  base::Uint64ToString(frame->largest_observed));
  dict->SetString("delta_time_largest_observed_us",
                  base::Int64ToString(frame->ack_delay_time.ToMicroseconds()));
  dict->SetInteger("entropy_hash", frame->entropy_hash);
  dict->SetBoolean("truncated", frame->is_truncated);

  base::ListValue* missing = new base::ListValue();
  dict->Set("packets", missing);
  for (QuicPacketNumber packet : frame->packets)
    missing->AppendString(base::Uint64ToString(packet));

  base::ListValue* received = new base::ListValue();
  dict->Set("received_packet_times", received);
  const PacketTimeVector& received_times = frame->received_packet_times;
  for (PacketTimeVector::const_iterator it = received_times.begin();
       it != received_times.end(); ++it) {
    base::DictionaryValue* info = new base::DictionaryValue();
    info->SetInteger("packet_number", static_cast<int>(it->first));
    info->SetString("received",
                    base::Int64ToString(it->second.ToDebuggingValue()));
    received->Append(info);
  }

  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicRstStreamFrameCallback(
    const QuicRstStreamFrame* frame,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("stream_id", frame->stream_id);
  dict->SetInteger("quic_rst_stream_error", frame->error_code);
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicConnectionCloseFrameCallback(
    const QuicConnectionCloseFrame* frame,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("quic_error", frame->error_code);
  dict->SetString("details", frame->error_details);
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicWindowUpdateFrameCallback(
    const QuicWindowUpdateFrame* frame,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("stream_id", frame->stream_id);
  dict->SetString("byte_offset", base::Uint64ToString(frame->byte_offset));
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicBlockedFrameCallback(
    const QuicBlockedFrame* frame,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("stream_id", frame->stream_id);
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicGoAwayFrameCallback(
    const QuicGoAwayFrame* frame,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("quic_error", frame->error_code);
  dict->SetInteger("last_good_stream_id", frame->last_good_stream_id);
  dict->SetString("reason_phrase", frame->reason_phrase);
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicStopWaitingFrameCallback(
    const QuicStopWaitingFrame* frame,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  base::DictionaryValue* sent_info = new base::DictionaryValue();
  dict->Set("sent_info", sent_info);
  sent_info->SetString("least_unacked",
                       base::Uint64ToString(frame->least_unacked));
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicVersionNegotiationPacketCallback(
    const QuicVersionNegotiationPacket* packet,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  base::ListValue* versions = new base::ListValue();
  dict->Set("versions", versions);
  for (QuicVersionVector::const_iterator it = packet->versions.begin();
       it != packet->versions.end(); ++it) {
    versions->AppendString(QuicVersionToString(*it));
  }
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicCryptoHandshakeMessageCallback(
    const CryptoHandshakeMessage* message,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("quic_crypto_handshake_message", message->DebugString());
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicOnConnectionClosedCallback(
    QuicErrorCode error,
    ConnectionCloseSource source,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("quic_error", error);
  dict->SetBoolean("from_peer",
                   source == ConnectionCloseSource::FROM_PEER ? true : false);
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogQuicCertificateVerifiedCallback(
    scoped_refptr<X509Certificate> cert,
    NetLogCaptureMode /* capture_mode */) {
  // Only the subjects are logged so that we can investigate connection pooling.
  // More fields could be logged in the future.
  std::vector<std::string> dns_names;
  cert->GetDNSNames(&dns_names);
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  base::ListValue* subjects = new base::ListValue();
  for (std::vector<std::string>::const_iterator it = dns_names.begin();
       it != dns_names.end(); it++) {
    subjects->Append(new base::StringValue(*it));
  }
  dict->Set("subjects", subjects);
  return std::move(dict);
}

void UpdatePacketGapSentHistogram(size_t num_consecutive_missing_packets) {
  UMA_HISTOGRAM_COUNTS("Net.QuicSession.PacketGapSent",
                       num_consecutive_missing_packets);
}

void UpdatePublicResetAddressMismatchHistogram(
    const IPEndPoint& server_hello_address,
    const IPEndPoint& public_reset_address) {
  int sample = GetAddressMismatch(server_hello_address, public_reset_address);
  // We are seemingly talking to an older server that does not support the
  // feature, so we can't report the results in the histogram.
  if (sample < 0) {
    return;
  }
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.PublicResetAddressMismatch2",
                            sample, QUIC_ADDRESS_MISMATCH_MAX);
}

// If |address| is an IPv4-mapped IPv6 address, returns ADDRESS_FAMILY_IPV4
// instead of ADDRESS_FAMILY_IPV6. Othewise, behaves like GetAddressFamily().
AddressFamily GetRealAddressFamily(const IPAddress& address) {
  return address.IsIPv4MappedIPv6() ? ADDRESS_FAMILY_IPV4
                                    : GetAddressFamily(address);
}

}  // namespace

QuicConnectionLogger::QuicConnectionLogger(
    QuicSpdySession* session,
    const char* const connection_description,
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    const BoundNetLog& net_log)
    : net_log_(net_log),
      session_(session),
      last_received_packet_number_(0),
      last_received_packet_size_(0),
      previous_received_packet_size_(0),
      last_packet_sent_time_(base::TimeTicks()),
      largest_received_packet_number_(0),
      largest_received_missing_packet_number_(0),
      num_out_of_order_received_packets_(0),
      num_out_of_order_large_received_packets_(0),
      num_packets_received_(0),
      num_truncated_acks_sent_(0),
      num_truncated_acks_received_(0),
      num_frames_received_(0),
      num_duplicate_frames_received_(0),
      num_incorrect_connection_ids_(0),
      num_undecryptable_packets_(0),
      num_duplicate_packets_(0),
      num_blocked_frames_received_(0),
      num_blocked_frames_sent_(0),
      connection_description_(connection_description),
      socket_performance_watcher_(std::move(socket_performance_watcher)) {}

QuicConnectionLogger::~QuicConnectionLogger() {
  UMA_HISTOGRAM_COUNTS("Net.QuicSession.OutOfOrderPacketsReceived",
                       num_out_of_order_received_packets_);
  UMA_HISTOGRAM_COUNTS("Net.QuicSession.OutOfOrderLargePacketsReceived",
                       num_out_of_order_large_received_packets_);
  UMA_HISTOGRAM_COUNTS("Net.QuicSession.TruncatedAcksSent",
                       num_truncated_acks_sent_);
  UMA_HISTOGRAM_COUNTS("Net.QuicSession.TruncatedAcksReceived",
                       num_truncated_acks_received_);
  UMA_HISTOGRAM_COUNTS("Net.QuicSession.IncorrectConnectionIDsReceived",
                       num_incorrect_connection_ids_);
  UMA_HISTOGRAM_COUNTS("Net.QuicSession.UndecryptablePacketsReceived",
                       num_undecryptable_packets_);
  UMA_HISTOGRAM_COUNTS("Net.QuicSession.DuplicatePacketsReceived",
                       num_duplicate_packets_);
  UMA_HISTOGRAM_COUNTS("Net.QuicSession.BlockedFrames.Received",
                       num_blocked_frames_received_);
  UMA_HISTOGRAM_COUNTS("Net.QuicSession.BlockedFrames.Sent",
                       num_blocked_frames_sent_);
  UMA_HISTOGRAM_COUNTS("Net.QuicSession.HeadersStream.EarlyFramesReceived",
                       session_->headers_stream()->num_early_frames_received());

  if (num_frames_received_ > 0) {
    int duplicate_stream_frame_per_thousand =
        num_duplicate_frames_received_ * 1000 / num_frames_received_;
    if (num_packets_received_ < 100) {
      UMA_HISTOGRAM_CUSTOM_COUNTS(
          "Net.QuicSession.StreamFrameDuplicatedShortConnection",
          duplicate_stream_frame_per_thousand, 1, 1000, 75);
    } else {
      UMA_HISTOGRAM_CUSTOM_COUNTS(
          "Net.QuicSession.StreamFrameDuplicatedLongConnection",
          duplicate_stream_frame_per_thousand, 1, 1000, 75);
    }
  }

  RecordLossHistograms();
}

void QuicConnectionLogger::OnFrameAddedToPacket(const QuicFrame& frame) {
  switch (frame.type) {
    case PADDING_FRAME:
      break;
    case STREAM_FRAME:
      net_log_.AddEvent(
          NetLog::TYPE_QUIC_SESSION_STREAM_FRAME_SENT,
          base::Bind(&NetLogQuicStreamFrameCallback, frame.stream_frame));
      break;
    case ACK_FRAME: {
      net_log_.AddEvent(
          NetLog::TYPE_QUIC_SESSION_ACK_FRAME_SENT,
          base::Bind(&NetLogQuicAckFrameCallback, frame.ack_frame));
      // Missing packets histogram only relevant for v33 and lower
      // TODO(rch, rtenneti) sort out histograms for v34+
      if (session_->connection()->version() > QUIC_VERSION_33) {
        break;
      }
      const PacketNumberQueue& missing_packets = frame.ack_frame->packets;
      const uint8_t max_ranges = std::numeric_limits<uint8_t>::max();
      // Compute an upper bound on the number of NACK ranges. If the bound
      // is below the max, then it clearly isn't truncated.
      if (missing_packets.NumPacketsSlow() < max_ranges ||
          (missing_packets.Max() - missing_packets.Min() -
           missing_packets.NumPacketsSlow() + 1) < max_ranges) {
        break;
      }
      size_t num_ranges = 0;
      QuicPacketNumber last_missing = 0;
      for (QuicPacketNumber packet : missing_packets) {
        if (packet != last_missing + 1 && ++num_ranges >= max_ranges) {
          ++num_truncated_acks_sent_;
          break;
        }
        last_missing = packet;
      }
      break;
    }
    case RST_STREAM_FRAME:
      UMA_HISTOGRAM_SPARSE_SLOWLY("Net.QuicSession.RstStreamErrorCodeClient",
                                  frame.rst_stream_frame->error_code);
      net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_RST_STREAM_FRAME_SENT,
                        base::Bind(&NetLogQuicRstStreamFrameCallback,
                                   frame.rst_stream_frame));
      break;
    case CONNECTION_CLOSE_FRAME:
      net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_CONNECTION_CLOSE_FRAME_SENT,
                        base::Bind(&NetLogQuicConnectionCloseFrameCallback,
                                   frame.connection_close_frame));
      break;
    case GOAWAY_FRAME:
      net_log_.AddEvent(
          NetLog::TYPE_QUIC_SESSION_GOAWAY_FRAME_SENT,
          base::Bind(&NetLogQuicGoAwayFrameCallback, frame.goaway_frame));
      break;
    case WINDOW_UPDATE_FRAME:
      net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_WINDOW_UPDATE_FRAME_SENT,
                        base::Bind(&NetLogQuicWindowUpdateFrameCallback,
                                   frame.window_update_frame));
      break;
    case BLOCKED_FRAME:
      ++num_blocked_frames_sent_;
      net_log_.AddEvent(
          NetLog::TYPE_QUIC_SESSION_BLOCKED_FRAME_SENT,
          base::Bind(&NetLogQuicBlockedFrameCallback, frame.blocked_frame));
      break;
    case STOP_WAITING_FRAME:
      net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_STOP_WAITING_FRAME_SENT,
                        base::Bind(&NetLogQuicStopWaitingFrameCallback,
                                   frame.stop_waiting_frame));
      break;
    case PING_FRAME:
      UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.ConnectionFlowControlBlocked",
                            session_->IsConnectionFlowControlBlocked());
      UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.StreamFlowControlBlocked",
                            session_->IsStreamFlowControlBlocked());
      // PingFrame has no contents to log, so just record that it was sent.
      net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_PING_FRAME_SENT);
      break;
    case MTU_DISCOVERY_FRAME:
      // MtuDiscoveryFrame is PingFrame on wire, it does not have any payload.
      net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_MTU_DISCOVERY_FRAME_SENT);
      break;
    default:
      DCHECK(false) << "Illegal frame type: " << frame.type;
  }
}

void QuicConnectionLogger::OnPacketSent(
    const SerializedPacket& serialized_packet,
    QuicPacketNumber original_packet_number,
    TransmissionType transmission_type,
    QuicTime sent_time) {
  if (original_packet_number == 0) {
    net_log_.AddEvent(
        NetLog::TYPE_QUIC_SESSION_PACKET_SENT,
        base::Bind(&NetLogQuicPacketSentCallback, serialized_packet,
                   transmission_type, sent_time));
  } else {
    net_log_.AddEvent(
        NetLog::TYPE_QUIC_SESSION_PACKET_RETRANSMITTED,
        base::Bind(&NetLogQuicPacketRetransmittedCallback,
                   original_packet_number, serialized_packet.packet_number));
  }
  // Record time duration from last packet sent to the new packet sent.
  if (last_packet_sent_time_.IsInitialized()) {
    UMA_HISTOGRAM_CUSTOM_TIMES(
        "Net.QuicTimeBetweenTwoPacketSent",
        base::TimeDelta::FromMilliseconds(
            sent_time.Subtract(last_packet_sent_time_).ToMilliseconds()),
        base::TimeDelta::FromMilliseconds(1), base::TimeDelta::FromMinutes(10),
        100);
  }
  last_packet_sent_time_ = sent_time;
}

void QuicConnectionLogger::OnPacketReceived(const IPEndPoint& self_address,
                                            const IPEndPoint& peer_address,
                                            const QuicEncryptedPacket& packet) {
  if (local_address_from_self_.GetFamily() == ADDRESS_FAMILY_UNSPECIFIED) {
    local_address_from_self_ = self_address;
    UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.ConnectionTypeFromSelf",
                              GetRealAddressFamily(self_address.address()),
                              ADDRESS_FAMILY_LAST);
  }

  previous_received_packet_size_ = last_received_packet_size_;
  last_received_packet_size_ = packet.length();
  net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_PACKET_RECEIVED,
                    base::Bind(&NetLogQuicPacketCallback, &self_address,
                               &peer_address, packet.length()));
}

void QuicConnectionLogger::OnUnauthenticatedHeader(
    const QuicPacketHeader& header) {
  net_log_.AddEvent(
      NetLog::TYPE_QUIC_SESSION_UNAUTHENTICATED_PACKET_HEADER_RECEIVED,
      base::Bind(&NetLogQuicPacketHeaderCallback, &header));
}

void QuicConnectionLogger::OnIncorrectConnectionId(
    QuicConnectionId connection_id) {
  ++num_incorrect_connection_ids_;
}

void QuicConnectionLogger::OnUndecryptablePacket() {
  ++num_undecryptable_packets_;
}

void QuicConnectionLogger::OnDuplicatePacket(QuicPacketNumber packet_number) {
  net_log_.AddEvent(
      NetLog::TYPE_QUIC_SESSION_DUPLICATE_PACKET_RECEIVED,
      base::Bind(&NetLogQuicDuplicatePacketCallback, packet_number));
  ++num_duplicate_packets_;
}

void QuicConnectionLogger::OnProtocolVersionMismatch(
    QuicVersion received_version) {
  // TODO(rtenneti): Add logging.
}

void QuicConnectionLogger::OnPacketHeader(const QuicPacketHeader& header) {
  net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_PACKET_AUTHENTICATED);
  ++num_packets_received_;
  if (largest_received_packet_number_ < header.packet_number) {
    QuicPacketNumber delta =
        header.packet_number - largest_received_packet_number_;
    if (delta > 1) {
      // There is a gap between the largest packet previously received and
      // the current packet.  This indicates either loss, or out-of-order
      // delivery.
      UMA_HISTOGRAM_COUNTS("Net.QuicSession.PacketGapReceived",
                           static_cast<base::HistogramBase::Sample>(delta - 1));
    }
    largest_received_packet_number_ = header.packet_number;
  }
  if (header.packet_number < received_packets_.size()) {
    received_packets_[static_cast<size_t>(header.packet_number)] = true;
  }
  if (header.packet_number < last_received_packet_number_) {
    ++num_out_of_order_received_packets_;
    if (previous_received_packet_size_ < last_received_packet_size_)
      ++num_out_of_order_large_received_packets_;
    UMA_HISTOGRAM_COUNTS(
        "Net.QuicSession.OutOfOrderGapReceived",
        static_cast<base::HistogramBase::Sample>(last_received_packet_number_ -
                                                 header.packet_number));
  }
  last_received_packet_number_ = header.packet_number;
}

void QuicConnectionLogger::OnStreamFrame(const QuicStreamFrame& frame) {
  net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_STREAM_FRAME_RECEIVED,
                    base::Bind(&NetLogQuicStreamFrameCallback, &frame));
}

void QuicConnectionLogger::OnAckFrame(const QuicAckFrame& frame) {
  net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_ACK_FRAME_RECEIVED,
                    base::Bind(&NetLogQuicAckFrameCallback, &frame));

  const size_t kApproximateLargestSoloAckBytes = 100;
  if (last_received_packet_number_ < received_acks_.size() &&
      last_received_packet_size_ < kApproximateLargestSoloAckBytes) {
    received_acks_[static_cast<size_t>(last_received_packet_number_)] = true;
  }

  if (frame.is_truncated)
    ++num_truncated_acks_received_;

  if (frame.packets.Empty())
    return;

  // TODO(rch, rtenneti) sort out histograms for QUIC_VERSION_34 and above.
  if (session_->connection()->version() > QUIC_VERSION_33) {
    return;
  }
  const PacketNumberQueue& missing_packets = frame.packets;
  PacketNumberQueue::const_iterator it =
      missing_packets.lower_bound(largest_received_missing_packet_number_);
  if (it == missing_packets.end())
    return;

  if (*it == largest_received_missing_packet_number_) {
    ++it;
    if (it == missing_packets.end())
      return;
  }
  // Scan through the list and log consecutive ranges of missing packets.
  size_t num_consecutive_missing_packets = 0;
  QuicPacketNumber previous_missing_packet = *it - 1;
  while (it != missing_packets.end()) {
    if (previous_missing_packet == *it - 1) {
      ++num_consecutive_missing_packets;
    } else {
      DCHECK_NE(0u, num_consecutive_missing_packets);
      UpdatePacketGapSentHistogram(num_consecutive_missing_packets);
      // Make sure this packet it included in the count.
      num_consecutive_missing_packets = 1;
    }
    previous_missing_packet = *it;
    ++it;
  }
  if (num_consecutive_missing_packets != 0) {
    UpdatePacketGapSentHistogram(num_consecutive_missing_packets);
  }
  largest_received_missing_packet_number_ = missing_packets.Max();
}

void QuicConnectionLogger::OnStopWaitingFrame(
    const QuicStopWaitingFrame& frame) {
  net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_STOP_WAITING_FRAME_RECEIVED,
                    base::Bind(&NetLogQuicStopWaitingFrameCallback, &frame));
}

void QuicConnectionLogger::OnRstStreamFrame(const QuicRstStreamFrame& frame) {
  UMA_HISTOGRAM_SPARSE_SLOWLY("Net.QuicSession.RstStreamErrorCodeServer",
                              frame.error_code);
  net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_RST_STREAM_FRAME_RECEIVED,
                    base::Bind(&NetLogQuicRstStreamFrameCallback, &frame));
}

void QuicConnectionLogger::OnConnectionCloseFrame(
    const QuicConnectionCloseFrame& frame) {
  net_log_.AddEvent(
      NetLog::TYPE_QUIC_SESSION_CONNECTION_CLOSE_FRAME_RECEIVED,
      base::Bind(&NetLogQuicConnectionCloseFrameCallback, &frame));
}

void QuicConnectionLogger::OnWindowUpdateFrame(
    const QuicWindowUpdateFrame& frame) {
  net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_WINDOW_UPDATE_FRAME_RECEIVED,
                    base::Bind(&NetLogQuicWindowUpdateFrameCallback, &frame));
}

void QuicConnectionLogger::OnBlockedFrame(const QuicBlockedFrame& frame) {
  ++num_blocked_frames_received_;
  net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_BLOCKED_FRAME_RECEIVED,
                    base::Bind(&NetLogQuicBlockedFrameCallback, &frame));
}

void QuicConnectionLogger::OnGoAwayFrame(const QuicGoAwayFrame& frame) {
  UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.GoAwayReceivedForConnectionMigration",
                        frame.error_code == QUIC_ERROR_MIGRATING_PORT);

  net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_GOAWAY_FRAME_RECEIVED,
                    base::Bind(&NetLogQuicGoAwayFrameCallback, &frame));
}

void QuicConnectionLogger::OnPingFrame(const QuicPingFrame& frame) {
  // PingFrame has no contents to log, so just record that it was received.
  net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_PING_FRAME_RECEIVED);
}

void QuicConnectionLogger::OnPublicResetPacket(
    const QuicPublicResetPacket& packet) {
  net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_PUBLIC_RESET_PACKET_RECEIVED);
  UpdatePublicResetAddressMismatchHistogram(local_address_from_shlo_,
                                            packet.client_address);
}

void QuicConnectionLogger::OnVersionNegotiationPacket(
    const QuicVersionNegotiationPacket& packet) {
  net_log_.AddEvent(
      NetLog::TYPE_QUIC_SESSION_VERSION_NEGOTIATION_PACKET_RECEIVED,
      base::Bind(&NetLogQuicVersionNegotiationPacketCallback, &packet));
}

void QuicConnectionLogger::OnCryptoHandshakeMessageReceived(
    const CryptoHandshakeMessage& message) {
  net_log_.AddEvent(
      NetLog::TYPE_QUIC_SESSION_CRYPTO_HANDSHAKE_MESSAGE_RECEIVED,
      base::Bind(&NetLogQuicCryptoHandshakeMessageCallback, &message));

  if (message.tag() == kSHLO) {
    StringPiece address;
    QuicSocketAddressCoder decoder;
    if (message.GetStringPiece(kCADR, &address) &&
        decoder.Decode(address.data(), address.size())) {
      local_address_from_shlo_ = IPEndPoint(decoder.ip(), decoder.port());
      UMA_HISTOGRAM_ENUMERATION(
          "Net.QuicSession.ConnectionTypeFromPeer",
          GetRealAddressFamily(local_address_from_shlo_.address()),
          ADDRESS_FAMILY_LAST);
    }
  }
}

void QuicConnectionLogger::OnCryptoHandshakeMessageSent(
    const CryptoHandshakeMessage& message) {
  net_log_.AddEvent(
      NetLog::TYPE_QUIC_SESSION_CRYPTO_HANDSHAKE_MESSAGE_SENT,
      base::Bind(&NetLogQuicCryptoHandshakeMessageCallback, &message));
}

void QuicConnectionLogger::OnConnectionClosed(QuicErrorCode error,
                                              const string& error_details,
                                              ConnectionCloseSource source) {
  net_log_.AddEvent(
      NetLog::TYPE_QUIC_SESSION_CLOSED,
      base::Bind(&NetLogQuicOnConnectionClosedCallback, error, source));
}

void QuicConnectionLogger::OnSuccessfulVersionNegotiation(
    const QuicVersion& version) {
  string quic_version = QuicVersionToString(version);
  net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_VERSION_NEGOTIATED,
                    NetLog::StringCallback("version", &quic_version));
}

void QuicConnectionLogger::UpdateReceivedFrameCounts(
    QuicStreamId stream_id,
    int num_frames_received,
    int num_duplicate_frames_received) {
  if (stream_id != kCryptoStreamId) {
    num_frames_received_ += num_frames_received;
    num_duplicate_frames_received_ += num_duplicate_frames_received;
  }
}

void QuicConnectionLogger::OnCertificateVerified(
    const CertVerifyResult& result) {
  if (result.cert_status == CERT_STATUS_INVALID) {
    net_log_.AddEvent(NetLog::TYPE_QUIC_SESSION_CERTIFICATE_VERIFY_FAILED);
    return;
  }
  net_log_.AddEvent(
      NetLog::TYPE_QUIC_SESSION_CERTIFICATE_VERIFIED,
      base::Bind(&NetLogQuicCertificateVerifiedCallback, result.verified_cert));
}

base::HistogramBase* QuicConnectionLogger::GetPacketNumberHistogram(
    const char* statistic_name) const {
  string prefix("Net.QuicSession.PacketReceived_");
  return base::LinearHistogram::FactoryGet(
      prefix + statistic_name + connection_description_, 1,
      received_packets_.size(), received_packets_.size() + 1,
      base::HistogramBase::kUmaTargetedHistogramFlag);
}

base::HistogramBase* QuicConnectionLogger::Get6PacketHistogram(
    const char* which_6) const {
  // This histogram takes a binary encoding of the 6 consecutive packets
  // received.  As a result, there are 64 possible sample-patterns.
  string prefix("Net.QuicSession.6PacketsPatternsReceived_");
  return base::LinearHistogram::FactoryGet(
      prefix + which_6 + connection_description_, 1, 64, 65,
      base::HistogramBase::kUmaTargetedHistogramFlag);
}

base::HistogramBase* QuicConnectionLogger::Get21CumulativeHistogram(
    const char* which_21) const {
  // This histogram contains, for each sequence of 21 packets, the results from
  // 21 distinct questions about that sequence.  Conceptually the histogtram is
  // broken into 21 distinct ranges, and one sample is added into each of those
  // ranges whenever we process a set of 21 packets.
  // There is a little rendundancy, as each "range" must have the same number
  // of samples, all told, but the histogram is a tad easier to read this way.
  // The questions are:
  // Was the first packet present (bucket 0==>no; bucket 1==>yes)
  // Of the first two packets, how many were present? (bucket 2==> none;
  //   bucket 3==> 1 of 2; bucket 4==> 2 of 2)
  // Of the  first three packets, how many were present? (bucket 5==>none;
  //   bucket 6==> 1 of 3; bucket 7==> 2 of 3; bucket 8==> 3 of 3).
  // etc.
  string prefix("Net.QuicSession.21CumulativePacketsReceived_");
  return base::LinearHistogram::FactoryGet(
      prefix + which_21 + connection_description_, 1,
      kBoundingSampleInCumulativeHistogram,
      kBoundingSampleInCumulativeHistogram + 1,
      base::HistogramBase::kUmaTargetedHistogramFlag);
}

// static
void QuicConnectionLogger::AddTo21CumulativeHistogram(
    base::HistogramBase* histogram,
    int bit_mask_of_packets,
    int valid_bits_in_mask) {
  DCHECK_LE(valid_bits_in_mask, 21);
  DCHECK_LT(bit_mask_of_packets, 1 << 21);
  const int blank_bits_in_mask = 21 - valid_bits_in_mask;
  DCHECK_EQ(bit_mask_of_packets & ((1 << blank_bits_in_mask) - 1), 0);
  bit_mask_of_packets >>= blank_bits_in_mask;
  int bits_so_far = 0;
  int range_start = 0;
  for (int i = 1; i <= valid_bits_in_mask; ++i) {
    bits_so_far += bit_mask_of_packets & 1;
    bit_mask_of_packets >>= 1;
    DCHECK_LT(range_start + bits_so_far, kBoundingSampleInCumulativeHistogram);
    histogram->Add(range_start + bits_so_far);
    range_start += i + 1;
  }
}

float QuicConnectionLogger::ReceivedPacketLossRate() const {
  if (largest_received_packet_number_ <= num_packets_received_)
    return 0.0f;
  float num_received = largest_received_packet_number_ - num_packets_received_;
  return num_received / largest_received_packet_number_;
}

void QuicConnectionLogger::OnRttChanged(QuicTime::Delta rtt) const {
  // Notify socket performance watcher of the updated RTT value.
  if (!socket_performance_watcher_)
    return;

  int64_t microseconds = rtt.ToMicroseconds();
  if (microseconds != 0) {
    socket_performance_watcher_->OnUpdatedRTTAvailable(
        base::TimeDelta::FromMicroseconds(rtt.ToMicroseconds()));
  }
}

void QuicConnectionLogger::RecordAggregatePacketLossRate() const {
  // For short connections under 22 packets in length, we'll rely on the
  // Net.QuicSession.21CumulativePacketsReceived_* histogram to indicate packet
  // loss rates.  This way we avoid tremendously anomalous contributions to our
  // histogram.  (e.g., if we only got 5 packets, but lost 1, we'd otherwise
  // record a 20% loss in this histogram!). We may still get some strange data
  // (1 loss in 22 is still high :-/).
  if (largest_received_packet_number_ <= 21)
    return;

  string prefix("Net.QuicSession.PacketLossRate_");
  base::HistogramBase* histogram = base::Histogram::FactoryGet(
      prefix + connection_description_, 1, 1000, 75,
      base::HistogramBase::kUmaTargetedHistogramFlag);
  histogram->Add(static_cast<base::HistogramBase::Sample>(
      ReceivedPacketLossRate() * 1000));
}

void QuicConnectionLogger::RecordLossHistograms() const {
  if (largest_received_packet_number_ == 0)
    return;  // Connection was never used.
  RecordAggregatePacketLossRate();

  base::HistogramBase* is_not_ack_histogram =
      GetPacketNumberHistogram("IsNotAck_");
  base::HistogramBase* is_an_ack_histogram =
      GetPacketNumberHistogram("IsAnAck_");
  base::HistogramBase* packet_arrived_histogram =
      GetPacketNumberHistogram("Ack_");
  base::HistogramBase* packet_missing_histogram =
      GetPacketNumberHistogram("Nack_");
  base::HistogramBase* ongoing_cumulative_packet_histogram =
      Get21CumulativeHistogram("Some21s_");
  base::HistogramBase* first_cumulative_packet_histogram =
      Get21CumulativeHistogram("First21_");
  base::HistogramBase* six_packet_histogram = Get6PacketHistogram("Some6s_");

  DCHECK_EQ(received_packets_.size(), received_acks_.size());
  const QuicPacketNumber last_index = std::min<QuicPacketNumber>(
      received_packets_.size() - 1, largest_received_packet_number_);
  const QuicPacketNumber index_of_first_21_contribution =
      std::min<QuicPacketNumber>(21, last_index);
  // Bit pattern of consecutively received packets that is maintained as we scan
  // through the received_packets_ vector. Less significant bits correspond to
  // less recent packets, and only the low order 21 bits are ever defined.
  // Bit is 1 iff corresponding packet was received.
  int packet_pattern_21 = 0;
  // Zero is an invalid packet sequence number.
  DCHECK(!received_packets_[0]);
  for (size_t i = 1; i <= last_index; ++i) {
    if (received_acks_[i])
      is_an_ack_histogram->Add(i);
    else
      is_not_ack_histogram->Add(i);

    packet_pattern_21 >>= 1;
    if (received_packets_[i]) {
      packet_arrived_histogram->Add(i);
      packet_pattern_21 |= (1 << 20);  // Turn on the 21st bit.
    } else {
      packet_missing_histogram->Add(i);
    }

    if (i == index_of_first_21_contribution) {
      AddTo21CumulativeHistogram(first_cumulative_packet_histogram,
                                 packet_pattern_21, i);
    }
    // We'll just record for non-overlapping ranges, to reduce histogramming
    // cost for now.  Each call does 21 separate histogram additions.
    if (i > 21 || i % 21 == 0) {
      AddTo21CumulativeHistogram(ongoing_cumulative_packet_histogram,
                                 packet_pattern_21, 21);
    }

    if (i < 6)
      continue;  // Not enough packets to do any pattern recording.
    int recent_6_mask = packet_pattern_21 >> 15;
    DCHECK_LT(recent_6_mask, 64);
    if (i == 6) {
      Get6PacketHistogram("First6_")->Add(recent_6_mask);
      continue;
    }
    // Record some overlapping patterns, to get a better picture, since this is
    // not very expensive.
    if (i % 3 == 0)
      six_packet_histogram->Add(recent_6_mask);
  }
}

}  // namespace net
