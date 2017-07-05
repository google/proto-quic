// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// The base class for client/server QUIC streams.

// It does not contain the entire interface needed by an application to interact
// with a QUIC stream.  Some parts of the interface must be obtained by
// accessing the owning session object.  A subclass of QuicStream
// connects the object and the application that generates and consumes the data
// of the stream.

// The QuicStream object has a dependent QuicStreamSequencer object,
// which is given the stream frames as they arrive, and provides stream data in
// order by invoking ProcessRawData().

#ifndef NET_QUIC_CORE_QUIC_STREAM_H_
#define NET_QUIC_CORE_QUIC_STREAM_H_

#include <cstddef>
#include <cstdint>
#include <list>
#include <string>

#include "base/macros.h"
#include "net/base/iovec.h"
#include "net/quic/core/quic_flow_controller.h"
#include "net/quic/core/quic_iovector.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_stream_send_buffer.h"
#include "net/quic/core/quic_stream_sequencer.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/core/stream_notifier_interface.h"
#include "net/quic/platform/api/quic_export.h"
#include "net/quic/platform/api/quic_reference_counted.h"
#include "net/quic/platform/api/quic_string_piece.h"

namespace net {

namespace test {
class QuicStreamPeer;
}  // namespace test

class QuicSession;

class QUIC_EXPORT_PRIVATE QuicStream : public StreamNotifierInterface {
 public:
  QuicStream(QuicStreamId id, QuicSession* session);

  ~QuicStream() override;

  // Not in use currently.
  void SetFromConfig();

  // Called by the session when a (potentially duplicate) stream frame has been
  // received for this stream.
  virtual void OnStreamFrame(const QuicStreamFrame& frame);

  // Called by the session when the connection becomes writeable to allow the
  // stream to write any pending data.
  virtual void OnCanWrite();

  // Called by the session just before the object is destroyed.
  // The object should not be accessed after OnClose is called.
  // Sends a RST_STREAM with code QUIC_RST_ACKNOWLEDGEMENT if neither a FIN nor
  // a RST_STREAM has been sent.
  virtual void OnClose();

  // Called by the session when the endpoint receives a RST_STREAM from the
  // peer.
  virtual void OnStreamReset(const QuicRstStreamFrame& frame);

  // Called by the session when the endpoint receives or sends a connection
  // close, and should immediately close the stream.
  virtual void OnConnectionClosed(QuicErrorCode error,
                                  ConnectionCloseSource source);

  // Called by the stream subclass after it has consumed the final incoming
  // data.
  virtual void OnFinRead();

  // Called when new data is available from the sequencer.  Subclasses must
  // actively retrieve the data using the sequencer's Readv() or
  // GetReadableRegions() method.
  virtual void OnDataAvailable() = 0;

  // Called by the subclass or the sequencer to reset the stream from this
  // end.
  virtual void Reset(QuicRstStreamErrorCode error);

  // Called by the subclass or the sequencer to close the entire connection from
  // this end.
  virtual void CloseConnectionWithDetails(QuicErrorCode error,
                                          const std::string& details);

  // Returns true if this stream is still waiting for acks of sent data.
  // This will return false if all data has been acked, or if the stream
  // is no longer interested in data being acked (which happens when
  // a stream is reset because of an error).
  bool IsWaitingForAcks() const;

  QuicStreamId id() const { return id_; }

  QuicRstStreamErrorCode stream_error() const { return stream_error_; }
  QuicErrorCode connection_error() const { return connection_error_; }

  bool reading_stopped() const {
    return sequencer_.ignore_read_data() || read_side_closed_;
  }
  bool write_side_closed() const { return write_side_closed_; }

  bool rst_received() { return rst_received_; }
  bool rst_sent() { return rst_sent_; }
  bool fin_received() { return fin_received_; }
  bool fin_sent() { return fin_sent_; }

  uint64_t queued_data_bytes() const { return queued_data_bytes_; }

  uint64_t stream_bytes_read() const { return stream_bytes_read_; }
  uint64_t stream_bytes_written() const { return stream_bytes_written_; }
  // For tests that override WritevData.
  void set_stream_bytes_written(uint64_t bytes_written) {
    stream_bytes_written_ = bytes_written;
  }

  size_t busy_counter() const { return busy_counter_; }
  void set_busy_counter(size_t busy_counter) { busy_counter_ = busy_counter; }

  void set_fin_sent(bool fin_sent) { fin_sent_ = fin_sent; }
  void set_fin_received(bool fin_received) { fin_received_ = fin_received; }
  void set_rst_sent(bool rst_sent) { rst_sent_ = rst_sent; }

  void set_rst_received(bool rst_received) { rst_received_ = rst_received; }
  void set_stream_error(QuicRstStreamErrorCode error) { stream_error_ = error; }

  // Adjust the flow control window according to new offset in |frame|.
  virtual void OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame);

  // Used in Chrome.
  int num_frames_received() const;
  int num_duplicate_frames_received() const;

  QuicFlowController* flow_controller() { return &flow_controller_; }

  // Called when endpoint receives a frame which could increase the highest
  // offset.
  // Returns true if the highest offset did increase.
  bool MaybeIncreaseHighestReceivedOffset(QuicStreamOffset new_offset);
  // Called when bytes are sent to the peer.
  void AddBytesSent(QuicByteCount bytes);
  // Called by the stream sequencer as bytes are consumed from the buffer.
  // If the receive window has dropped below the threshold, then send a
  // WINDOW_UPDATE frame.
  void AddBytesConsumed(QuicByteCount bytes);

  // Updates the flow controller's send window offset and calls OnCanWrite if
  // it was blocked before.
  void UpdateSendWindowOffset(QuicStreamOffset new_offset);

  // Returns true if the stream has received either a RST_STREAM or a FIN -
  // either of which gives a definitive number of bytes which the peer has
  // sent. If this is not true on deletion of the stream object, the session
  // must keep track of the stream's byte offset until a definitive final value
  // arrives.
  bool HasFinalReceivedByteOffset() const {
    return fin_received_ || rst_received_;
  }

  // Returns true if the stream has queued data waiting to write.
  bool HasBufferedData() const;

  // Returns the version of QUIC being used for this stream.
  QuicVersion version() const;

  bool fin_received() const { return fin_received_; }

  // Sets the sequencer to consume all incoming data itself and not call
  // OnDataAvailable().
  // When the FIN is received, the stream will be notified automatically (via
  // OnFinRead()) (which may happen during the call of StopReading()).
  // TODO(dworley): There should be machinery to send a RST_STREAM/NO_ERROR and
  // stop sending stream-level flow-control updates when this end sends FIN.
  virtual void StopReading();

  // Get peer IP of the lastest packet which connection is dealing/delt with.
  virtual const QuicSocketAddress& PeerAddressOfLatestPacket() const;

  // Sends as much of 'data' to the connection as the connection will consume,
  // and then buffers any remaining data in queued_data_.
  // If fin is true: if it is immediately passed on to the session,
  // write_side_closed() becomes true, otherwise fin_buffered_ becomes true.
  void WriteOrBufferData(
      QuicStringPiece data,
      bool fin,
      QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener);

  // Adds random padding after the fin is consumed for this stream.
  void AddRandomPaddingAfterFin();

  // Save |data_length| of data starts at |iov_offset| in |iov| to send buffer.
  void SaveStreamData(QuicIOVector iov,
                      size_t iov_offset,
                      QuicStreamOffset offset,
                      QuicByteCount data_length);

  // Write |data_length| of data starts at |offset| from send buffer.
  bool WriteStreamData(QuicStreamOffset offset,
                       QuicByteCount data_length,
                       QuicDataWriter* writer);

  // StreamNotifierInterface methods:
  void OnStreamFrameAcked(const QuicStreamFrame& frame,
                          QuicTime::Delta ack_delay_time) override;
  void OnStreamFrameRetransmitted(const QuicStreamFrame& frame) override;
  void OnStreamFrameDiscarded(const QuicStreamFrame& frame) override;

 protected:
  // Sends as many bytes in the first |count| buffers of |iov| to the connection
  // as the connection will consume.
  // If |ack_listener| is provided, then it will be notified once all
  // the ACKs for this write have been received.
  // Returns the number of bytes consumed by the connection.
  QuicConsumedData WritevData(
      const struct iovec* iov,
      int iov_count,
      bool fin,
      QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener);

  // Allows override of the session level writev, for the force HOL
  // blocking experiment.
  virtual QuicConsumedData WritevDataInner(
      QuicIOVector iov,
      QuicStreamOffset offset,
      bool fin,
      QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener);

  // Close the write side of the socket.  Further writes will fail.
  // Can be called by the subclass or internally.
  // Does not send a FIN.  May cause the stream to be closed.
  virtual void CloseWriteSide();

  bool fin_buffered() const { return fin_buffered_; }

  const QuicSession* session() const { return session_; }
  QuicSession* session() { return session_; }

  const QuicStreamSequencer* sequencer() const { return &sequencer_; }
  QuicStreamSequencer* sequencer() { return &sequencer_; }

  void DisableConnectionFlowControlForThisStream() {
    stream_contributes_to_connection_flow_control_ = false;
  }

  void set_ack_listener(
      QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener) {
    ack_listener_ = std::move(ack_listener);
  }

 private:
  friend class test::QuicStreamPeer;
  friend class QuicStreamUtils;

  // Close the read side of the socket.  May cause the stream to be closed.
  // Subclasses and consumers should use StopReading to terminate reading early.
  void CloseReadSide();

  // Subclasses and consumers should use reading_stopped.
  bool read_side_closed() const { return read_side_closed_; }

  struct PendingData {
    PendingData(
        std::string data_in,
        QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener);
    ~PendingData();

    // Pending data to be written.
    std::string data;
    // Index of the first byte in data still to be written.
    size_t offset;
    // AckListener that should be notified when the pending data is acked.
    // Can be nullptr.
    QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener;
  };

  // Calls MaybeSendBlocked on the stream's flow controller and the connection
  // level flow controller.  If the stream is flow control blocked by the
  // connection-level flow controller but not by the stream-level flow
  // controller, marks this stream as connection-level write blocked.
  void MaybeSendBlocked();

  std::list<PendingData> queued_data_;
  // How many bytes are queued?
  uint64_t queued_data_bytes_;

  QuicStreamSequencer sequencer_;
  QuicStreamId id_;
  // Pointer to the owning QuicSession object.
  QuicSession* session_;
  // Bytes read and written refer to payload bytes only: they do not include
  // framing, encryption overhead etc.
  uint64_t stream_bytes_read_;
  uint64_t stream_bytes_written_;
  // Written bytes which are waiting to be acked.
  uint64_t stream_bytes_outstanding_;

  // Stream error code received from a RstStreamFrame or error code sent by the
  // visitor or sequencer in the RstStreamFrame.
  QuicRstStreamErrorCode stream_error_;
  // Connection error code due to which the stream was closed. |stream_error_|
  // is set to |QUIC_STREAM_CONNECTION_ERROR| when this happens and consumers
  // should check |connection_error_|.
  QuicErrorCode connection_error_;

  // True if the read side is closed and further frames should be rejected.
  bool read_side_closed_;
  // True if the write side is closed, and further writes should fail.
  bool write_side_closed_;

  // True if the subclass has written a FIN with WriteOrBufferData, but it was
  // buffered in queued_data_ rather than being sent to the session.
  bool fin_buffered_;
  // True if a FIN has been sent to the session.
  bool fin_sent_;
  // True if a FIN is waiting to be acked.
  bool fin_outstanding_;

  // True if this stream has received (and the sequencer has accepted) a
  // StreamFrame with the FIN set.
  bool fin_received_;

  // True if an RST_STREAM has been sent to the session.
  // In combination with fin_sent_, used to ensure that a FIN and/or a
  // RST_STREAM is always sent to terminate the stream.
  bool rst_sent_;

  // True if this stream has received a RST_STREAM frame.
  bool rst_received_;

  // Tracks if the session this stream is running under was created by a
  // server or a client.
  Perspective perspective_;

  QuicFlowController flow_controller_;

  // The connection level flow controller. Not owned.
  QuicFlowController* connection_flow_controller_;

  // Special streams, such as the crypto and headers streams, do not respect
  // connection level flow control limits (but are stream level flow control
  // limited).
  bool stream_contributes_to_connection_flow_control_;

  // A counter incremented when OnCanWrite() is called and no progress is made.
  // For debugging only.
  size_t busy_counter_;

  // Indicates whether paddings will be added after the fin is consumed for this
  // stream.
  bool add_random_padding_after_fin_;

  // Ack listener of this stream, and it is notified when any of written bytes
  // are acked.
  QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener_;

  // Send buffer of this stream. Send buffer is cleaned up when data gets acked
  // or discarded.
  QuicStreamSendBuffer send_buffer_;

  DISALLOW_COPY_AND_ASSIGN(QuicStream);
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_STREAM_H_
