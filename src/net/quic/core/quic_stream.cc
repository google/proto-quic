// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_stream.h"

#include "net/quic/core/quic_flow_controller.h"
#include "net/quic/core/quic_session.h"
#include "net/quic/platform/api/quic_bug_tracker.h"
#include "net/quic/platform/api/quic_logging.h"

using std::string;

namespace net {

#define ENDPOINT \
  (perspective_ == Perspective::IS_SERVER ? "Server: " : "Client: ")

namespace {

struct iovec MakeIovec(QuicStringPiece data) {
  struct iovec iov = {const_cast<char*>(data.data()),
                      static_cast<size_t>(data.size())};
  return iov;
}

size_t GetInitialStreamFlowControlWindowToSend(QuicSession* session) {
  return session->config()->GetInitialStreamFlowControlWindowToSend();
}

size_t GetReceivedFlowControlWindow(QuicSession* session) {
  if (session->config()->HasReceivedInitialStreamFlowControlWindowBytes()) {
    return session->config()->ReceivedInitialStreamFlowControlWindowBytes();
  }

  return kMinimumFlowControlSendWindow;
}

}  // namespace

QuicStream::PendingData::PendingData(
    string data_in,
    QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener)
    : data(std::move(data_in)),
      offset(0),
      ack_listener(std::move(ack_listener)) {}

QuicStream::PendingData::~PendingData() {}

QuicStream::QuicStream(QuicStreamId id, QuicSession* session)
    : queued_data_bytes_(0),
      sequencer_(this, session->connection()->clock()),
      id_(id),
      session_(session),
      stream_bytes_read_(0),
      stream_bytes_written_(0),
      stream_bytes_outstanding_(0),
      stream_error_(QUIC_STREAM_NO_ERROR),
      connection_error_(QUIC_NO_ERROR),
      read_side_closed_(false),
      write_side_closed_(false),
      fin_buffered_(false),
      fin_sent_(false),
      fin_outstanding_(false),
      fin_received_(false),
      rst_sent_(false),
      rst_received_(false),
      perspective_(session_->perspective()),
      flow_controller_(session_->connection(),
                       id_,
                       perspective_,
                       GetReceivedFlowControlWindow(session),
                       GetInitialStreamFlowControlWindowToSend(session),
                       session_->flow_controller()->auto_tune_receive_window(),
                       session_->flow_controller()),
      connection_flow_controller_(session_->flow_controller()),
      stream_contributes_to_connection_flow_control_(true),
      busy_counter_(0),
      add_random_padding_after_fin_(false),
      ack_listener_(nullptr),
      send_buffer_(session->connection()->helper()->GetBufferAllocator()) {
  SetFromConfig();
}

QuicStream::~QuicStream() {
  if (session_ != nullptr && session_->use_stream_notifier() &&
      IsWaitingForAcks()) {
    QUIC_DVLOG(1)
        << ENDPOINT << "Stream " << id_
        << " gets destroyed while waiting for acks. stream_bytes_outstanding = "
        << stream_bytes_outstanding_
        << ", fin_outstanding: " << fin_outstanding_;
  }
}

void QuicStream::SetFromConfig() {}

void QuicStream::OnStreamFrame(const QuicStreamFrame& frame) {
  DCHECK_EQ(frame.stream_id, id_);

  DCHECK(!(read_side_closed_ && write_side_closed_));

  if (frame.fin) {
    fin_received_ = true;
    if (fin_sent_) {
      session_->StreamDraining(id_);
    }
  }

  if (read_side_closed_) {
    QUIC_DLOG(INFO)
        << ENDPOINT << "Stream " << frame.stream_id
        << " is closed for reading. Ignoring newly received stream data.";
    // The subclass does not want to read data:  blackhole the data.
    return;
  }

  // This count includes duplicate data received.
  size_t frame_payload_size = frame.data_length;
  stream_bytes_read_ += frame_payload_size;

  // Flow control is interested in tracking highest received offset.
  // Only interested in received frames that carry data.
  if (frame_payload_size > 0 &&
      MaybeIncreaseHighestReceivedOffset(frame.offset + frame_payload_size)) {
    // As the highest received offset has changed, check to see if this is a
    // violation of flow control.
    if (flow_controller_.FlowControlViolation() ||
        connection_flow_controller_->FlowControlViolation()) {
      CloseConnectionWithDetails(
          QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA,
          "Flow control violation after increasing offset");
      return;
    }
  }

  sequencer_.OnStreamFrame(frame);
}

int QuicStream::num_frames_received() const {
  return sequencer_.num_frames_received();
}

int QuicStream::num_duplicate_frames_received() const {
  return sequencer_.num_duplicate_frames_received();
}

void QuicStream::OnStreamReset(const QuicRstStreamFrame& frame) {
  rst_received_ = true;
  MaybeIncreaseHighestReceivedOffset(frame.byte_offset);

  stream_error_ = frame.error_code;
  CloseWriteSide();
  CloseReadSide();
}

void QuicStream::OnConnectionClosed(QuicErrorCode error,
                                    ConnectionCloseSource /*source*/) {
  if (read_side_closed_ && write_side_closed_) {
    return;
  }
  if (error != QUIC_NO_ERROR) {
    stream_error_ = QUIC_STREAM_CONNECTION_ERROR;
    connection_error_ = error;
  }

  CloseWriteSide();
  CloseReadSide();
}

void QuicStream::OnFinRead() {
  DCHECK(sequencer_.IsClosed());
  // OnFinRead can be called due to a FIN flag in a headers block, so there may
  // have been no OnStreamFrame call with a FIN in the frame.
  fin_received_ = true;
  // If fin_sent_ is true, then CloseWriteSide has already been called, and the
  // stream will be destroyed by CloseReadSide, so don't need to call
  // StreamDraining.
  CloseReadSide();
}

void QuicStream::Reset(QuicRstStreamErrorCode error) {
  stream_error_ = error;
  // Sending a RstStream results in calling CloseStream.
  session()->SendRstStream(id(), error, stream_bytes_written_);
  rst_sent_ = true;
}

void QuicStream::CloseConnectionWithDetails(QuicErrorCode error,
                                            const string& details) {
  session()->connection()->CloseConnection(
      error, details, ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

void QuicStream::WriteOrBufferData(
    QuicStringPiece data,
    bool fin,
    QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener) {
  if (data.empty() && !fin) {
    QUIC_BUG << "data.empty() && !fin";
    return;
  }

  if (fin_buffered_) {
    QUIC_BUG << "Fin already buffered";
    return;
  }
  if (write_side_closed_) {
    QUIC_DLOG(ERROR) << ENDPOINT
                     << "Attempt to write when the write side is closed";
    return;
  }

  QuicConsumedData consumed_data(0, false);
  fin_buffered_ = fin;

  if (queued_data_.empty()) {
    struct iovec iov(MakeIovec(data));
    consumed_data = WritevData(&iov, 1, fin, ack_listener);
    DCHECK_LE(consumed_data.bytes_consumed, data.length());
  }

  // If there's unconsumed data or an unconsumed fin, queue it.
  if (consumed_data.bytes_consumed < data.length() ||
      (fin && !consumed_data.fin_consumed)) {
    QuicStringPiece remainder(data.substr(consumed_data.bytes_consumed));
    queued_data_bytes_ += remainder.size();
    queued_data_.emplace_back(remainder.as_string(), ack_listener);
  }
}

void QuicStream::OnCanWrite() {
  bool fin = false;
  while (!queued_data_.empty()) {
    PendingData* pending_data = &queued_data_.front();
    QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener =
        pending_data->ack_listener;
    if (queued_data_.size() == 1 && fin_buffered_) {
      fin = true;
    }
    if (pending_data->offset > 0 &&
        pending_data->offset >= pending_data->data.size()) {
      // This should be impossible because offset tracks the amount of
      // pending_data written thus far.
      QUIC_BUG << "Pending offset is beyond available data. offset: "
               << pending_data->offset << " vs: " << pending_data->data.size();
      return;
    }
    size_t remaining_len = pending_data->data.size() - pending_data->offset;
    struct iovec iov = {
        const_cast<char*>(pending_data->data.data()) + pending_data->offset,
        remaining_len};
    QuicConsumedData consumed_data = WritevData(&iov, 1, fin, ack_listener);
    queued_data_bytes_ -= consumed_data.bytes_consumed;
    if (consumed_data.bytes_consumed == remaining_len &&
        fin == consumed_data.fin_consumed) {
      queued_data_.pop_front();
    } else {
      if (consumed_data.bytes_consumed > 0) {
        pending_data->offset += consumed_data.bytes_consumed;
      }
      break;
    }
  }
}

void QuicStream::MaybeSendBlocked() {
  flow_controller_.MaybeSendBlocked();
  if (!stream_contributes_to_connection_flow_control_) {
    return;
  }
  connection_flow_controller_->MaybeSendBlocked();
  // If the stream is blocked by connection-level flow control but not by
  // stream-level flow control, add the stream to the write blocked list so that
  // the stream will be given a chance to write when a connection-level
  // WINDOW_UPDATE arrives.
  if (connection_flow_controller_->IsBlocked() &&
      !flow_controller_.IsBlocked()) {
    session_->MarkConnectionLevelWriteBlocked(id());
  }
}

QuicConsumedData QuicStream::WritevData(
    const struct iovec* iov,
    int iov_count,
    bool fin,
    QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener) {
  if (write_side_closed_) {
    QUIC_DLOG(ERROR) << ENDPOINT << "Stream " << id()
                     << "attempting to write when the write side is closed";
    return QuicConsumedData(0, false);
  }

  // How much data was provided.
  size_t write_length = 0;
  if (iov != nullptr) {
    for (int i = 0; i < iov_count; ++i) {
      write_length += iov[i].iov_len;
    }
  }

  // A FIN with zero data payload should not be flow control blocked.
  bool fin_with_zero_data = (fin && write_length == 0);

  // How much data flow control permits to be written.
  QuicByteCount send_window = flow_controller_.SendWindowSize();
  if (stream_contributes_to_connection_flow_control_) {
    send_window =
        std::min(send_window, connection_flow_controller_->SendWindowSize());
  }

  if (session_->ShouldYield(id())) {
    session_->MarkConnectionLevelWriteBlocked(id());
    return QuicConsumedData(0, false);
  }

  if (send_window == 0 && !fin_with_zero_data) {
    // Quick return if nothing can be sent.
    MaybeSendBlocked();
    return QuicConsumedData(0, false);
  }

  if (write_length > send_window) {
    // Don't send the FIN unless all the data will be sent.
    fin = false;

    // Writing more data would be a violation of flow control.
    write_length = static_cast<size_t>(send_window);
    QUIC_DVLOG(1) << "stream " << id() << " shortens write length to "
                  << write_length << " due to flow control";
  }

  QuicConsumedData consumed_data =
      WritevDataInner(QuicIOVector(iov, iov_count, write_length),
                      stream_bytes_written_, fin, std::move(ack_listener));
  stream_bytes_written_ += consumed_data.bytes_consumed;
  stream_bytes_outstanding_ += consumed_data.bytes_consumed;

  AddBytesSent(consumed_data.bytes_consumed);

  // The write may have generated a write error causing this stream to be
  // closed. If so, simply return without marking the stream write blocked.
  if (write_side_closed_) {
    return consumed_data;
  }

  if (consumed_data.bytes_consumed == write_length) {
    if (!fin_with_zero_data) {
      MaybeSendBlocked();
    }
    if (fin && consumed_data.fin_consumed) {
      fin_sent_ = true;
      fin_outstanding_ = true;
      if (fin_received_) {
        session_->StreamDraining(id_);
      }
      CloseWriteSide();
    } else if (fin && !consumed_data.fin_consumed) {
      session_->MarkConnectionLevelWriteBlocked(id());
    }
  } else {
    session_->MarkConnectionLevelWriteBlocked(id());
  }
  if (consumed_data.bytes_consumed > 0 || consumed_data.fin_consumed) {
    busy_counter_ = 0;
  }
  return consumed_data;
}

QuicConsumedData QuicStream::WritevDataInner(
    QuicIOVector iov,
    QuicStreamOffset offset,
    bool fin,
    QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener) {
  StreamSendingState state = fin ? FIN : NO_FIN;
  if (fin && add_random_padding_after_fin_) {
    state = FIN_AND_PADDING;
  }
  return session()->WritevData(this, id(), iov, offset, state,
                               std::move(ack_listener));
}

void QuicStream::CloseReadSide() {
  if (read_side_closed_) {
    return;
  }
  QUIC_DLOG(INFO) << ENDPOINT << "Done reading from stream " << id();

  read_side_closed_ = true;
  sequencer_.ReleaseBuffer();

  if (write_side_closed_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Closing stream " << id();
    session_->CloseStream(id());
  }
}

void QuicStream::CloseWriteSide() {
  if (write_side_closed_) {
    return;
  }
  QUIC_DLOG(INFO) << ENDPOINT << "Done writing to stream " << id();

  write_side_closed_ = true;
  if (read_side_closed_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Closing stream " << id();
    session_->CloseStream(id());
  }
}

bool QuicStream::HasBufferedData() const {
  return !queued_data_.empty();
}

QuicVersion QuicStream::version() const {
  return session_->connection()->version();
}

void QuicStream::StopReading() {
  QUIC_DLOG(INFO) << ENDPOINT << "Stop reading from stream " << id();
  sequencer_.StopReading();
}

const QuicSocketAddress& QuicStream::PeerAddressOfLatestPacket() const {
  return session_->connection()->last_packet_source_address();
}

void QuicStream::OnClose() {
  CloseReadSide();
  CloseWriteSide();

  if (!fin_sent_ && !rst_sent_) {
    // For flow control accounting, tell the peer how many bytes have been
    // written on this stream before termination. Done here if needed, using a
    // RST_STREAM frame.
    QUIC_DLOG(INFO) << ENDPOINT << "Sending RST_STREAM in OnClose: " << id();
    session_->SendRstStream(id(), QUIC_RST_ACKNOWLEDGEMENT,
                            stream_bytes_written_);
    rst_sent_ = true;
  }

  // The stream is being closed and will not process any further incoming bytes.
  // As there may be more bytes in flight, to ensure that both endpoints have
  // the same connection level flow control state, mark all unreceived or
  // buffered bytes as consumed.
  QuicByteCount bytes_to_consume =
      flow_controller_.highest_received_byte_offset() -
      flow_controller_.bytes_consumed();
  AddBytesConsumed(bytes_to_consume);
}

void QuicStream::OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) {
  if (flow_controller_.UpdateSendWindowOffset(frame.byte_offset)) {
    // Writing can be done again!
    // TODO(rjshade): This does not respect priorities (e.g. multiple
    //                outstanding POSTs are unblocked on arrival of
    //                SHLO with initial window).
    // As long as the connection is not flow control blocked, write on!
    OnCanWrite();
  }
}

bool QuicStream::MaybeIncreaseHighestReceivedOffset(
    QuicStreamOffset new_offset) {
  uint64_t increment =
      new_offset - flow_controller_.highest_received_byte_offset();
  if (!flow_controller_.UpdateHighestReceivedOffset(new_offset)) {
    return false;
  }

  // If |new_offset| increased the stream flow controller's highest received
  // offset, increase the connection flow controller's value by the incremental
  // difference.
  if (stream_contributes_to_connection_flow_control_) {
    connection_flow_controller_->UpdateHighestReceivedOffset(
        connection_flow_controller_->highest_received_byte_offset() +
        increment);
  }
  return true;
}

void QuicStream::AddBytesSent(QuicByteCount bytes) {
  flow_controller_.AddBytesSent(bytes);
  if (stream_contributes_to_connection_flow_control_) {
    connection_flow_controller_->AddBytesSent(bytes);
  }
}

void QuicStream::AddBytesConsumed(QuicByteCount bytes) {
  // Only adjust stream level flow controller if still reading.
  if (!read_side_closed_) {
    flow_controller_.AddBytesConsumed(bytes);
  }

  if (stream_contributes_to_connection_flow_control_) {
    connection_flow_controller_->AddBytesConsumed(bytes);
  }
}

void QuicStream::UpdateSendWindowOffset(QuicStreamOffset new_window) {
  if (flow_controller_.UpdateSendWindowOffset(new_window)) {
    OnCanWrite();
  }
}

void QuicStream::AddRandomPaddingAfterFin() {
  add_random_padding_after_fin_ = true;
}

void QuicStream::OnStreamFrameAcked(const QuicStreamFrame& frame,
                                    QuicTime::Delta ack_delay_time) {
  OnStreamFrameDiscarded(frame);
  if (ack_listener_ != nullptr) {
    ack_listener_->OnPacketAcked(frame.data_length, ack_delay_time);
  }
}

void QuicStream::OnStreamFrameRetransmitted(const QuicStreamFrame& frame) {
  if (ack_listener_ != nullptr) {
    ack_listener_->OnPacketRetransmitted(frame.data_length);
  }
}

void QuicStream::OnStreamFrameDiscarded(const QuicStreamFrame& frame) {
  DCHECK_EQ(id_, frame.stream_id);
  if (stream_bytes_outstanding_ < frame.data_length ||
      (!fin_outstanding_ && frame.fin)) {
    CloseConnectionWithDetails(QUIC_INTERNAL_ERROR,
                               "Trying to discard unsent data.");
    return;
  }
  stream_bytes_outstanding_ -= frame.data_length;
  if (frame.fin) {
    fin_outstanding_ = false;
  }
  if (session_->streams_own_data() && frame.data_length > 0) {
    send_buffer_.RemoveStreamFrame(frame.offset, frame.data_length);
  }
  if (!IsWaitingForAcks()) {
    session_->OnStreamDoneWaitingForAcks(id_);
  }
}

bool QuicStream::IsWaitingForAcks() const {
  return stream_bytes_outstanding_ || fin_outstanding_;
}

void QuicStream::SaveStreamData(QuicIOVector iov,
                                size_t iov_offset,
                                QuicStreamOffset offset,
                                QuicByteCount data_length) {
  DCHECK_LT(0u, data_length);
  send_buffer_.SaveStreamData(iov, iov_offset, offset, data_length);
}

bool QuicStream::WriteStreamData(QuicStreamOffset offset,
                                 QuicByteCount data_length,
                                 QuicDataWriter* writer) {
  DCHECK_LT(0u, data_length);
  return send_buffer_.WriteStreamData(offset, data_length, writer);
}

}  // namespace net
