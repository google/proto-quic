// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_SPDY_STREAM_H_
#define NET_SPDY_SPDY_STREAM_H_

#include <stddef.h>
#include <stdint.h>

#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "net/base/io_buffer.h"
#include "net/base/net_export.h"
#include "net/base/request_priority.h"
#include "net/log/net_log.h"
#include "net/socket/ssl_client_socket.h"
#include "net/spdy/spdy_buffer.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_protocol.h"
#include "net/ssl/ssl_client_cert_type.h"
#include "url/gurl.h"

namespace net {

class AddressList;
class IPEndPoint;
struct LoadTimingInfo;
class SSLInfo;
class SpdySession;

enum SpdyStreamType {
  // The most general type of stream; there are no restrictions on
  // when data can be sent and received.
  SPDY_BIDIRECTIONAL_STREAM,
  // A stream where the client sends a request with possibly a body,
  // and the server then sends a response with a body.
  SPDY_REQUEST_RESPONSE_STREAM,
  // A server-initiated stream where the server just sends a response
  // with a body and the client does not send anything.
  SPDY_PUSH_STREAM
};

// Passed to some SpdyStream functions to indicate whether there's
// more data to send.
enum SpdySendStatus {
  MORE_DATA_TO_SEND,
  NO_MORE_DATA_TO_SEND
};

// Returned by SpdyStream::OnResponseHeadersUpdated() to indicate
// whether the current response headers are complete or not, or whether
// trailers have been received. TRAILERS_RECEIVED denotes the state where
// headers are received after DATA frames. TRAILERS_RECEIVED is only used for
// SPDY_REQUEST_RESPONSE_STREAM, and this state also implies that the response
// headers are complete.
enum SpdyResponseHeadersStatus {
  RESPONSE_HEADERS_ARE_INCOMPLETE,
  RESPONSE_HEADERS_ARE_COMPLETE,
  TRAILERS_RECEIVED,
};

// The SpdyStream is used by the SpdySession to represent each stream known
// on the SpdySession.  This class provides interfaces for SpdySession to use.
// Streams can be created either by the client or by the server.  When they
// are initiated by the client, both the SpdySession and client object (such as
// a SpdyNetworkTransaction) will maintain a reference to the stream.  When
// initiated by the server, only the SpdySession will maintain any reference,
// until such a time as a client object requests a stream for the path.
class NET_EXPORT_PRIVATE SpdyStream {
 public:
  // Delegate handles protocol specific behavior of spdy stream.
  class NET_EXPORT_PRIVATE Delegate {
   public:
    Delegate() {}

    // Called when the request headers have been sent. Never called
    // for push streams. Must not cause the stream to be closed.
    virtual void OnRequestHeadersSent() = 0;

    // WARNING: This function is complicated! Be sure to read the
    // whole comment below if you're working with code that implements
    // or calls this function.
    //
    // Called when the response headers are updated from the
    // server. |response_headers| contains the set of all headers
    // received up to this point; delegates can assume that any
    // headers previously received remain unchanged.
    //
    // This is called at least once before any data is received. If
    // RESPONSE_HEADERS_ARE_INCOMPLETE is returned, this will be
    // called again when more headers are received until
    // RESPONSE_HEADERS_ARE_COMPLETE is returned, and any data
    // received before then will be treated as a protocol error.
    //
    // If RESPONSE_HEADERS_ARE_INCOMPLETE is returned, the delegate
    // must not have closed the stream. Otherwise, if
    // RESPONSE_HEADERS_ARE_COMPLETE is returned, the delegate has
    // processed the headers successfully. However, it still may have
    // closed the stream, e.g. if the headers indicated an error
    // condition.
    //
    // Some type-specific behavior:
    //
    //   - For bidirectional streams, this may be called even after
    //     data is received, but it is expected that
    //     RESPONSE_HEADERS_ARE_COMPLETE is always returned. If
    //     RESPONSE_HEADERS_ARE_INCOMPLETE is returned, this is
    //     treated as a protocol error.
    //
    //   - For request/response streams, this function is called
    //     exactly once before data is received, and it is expected
    //     that RESPONSE_HEADERS_ARE_COMPLETE is returned. If
    //     RESPONSE_HEADERS_ARE_INCOMPLETE is returned, this is
    //     treated as a protocol error.
    //
    //   - For push streams, it is expected that this function will be
    //     called until RESPONSE_HEADERS_ARE_COMPLETE is returned
    //     before any data is received; any deviation from this is
    //     treated as a protocol error.
    //
    // TODO(jgraettinger): This should be at the semantic (HTTP) rather
    // than stream layer. Streams shouldn't have a notion of header
    // completeness. Move to SpdyHttpStream/SpdyWebsocketStream.
    virtual SpdyResponseHeadersStatus OnResponseHeadersUpdated(
        const SpdyHeaderBlock& response_headers) = 0;

    // Called when data is received after all required response
    // headers have been received. |buffer| may be NULL, which signals
    // EOF.  Must return OK if the data was received successfully, or
    // a network error code otherwise.
    //
    // May cause the stream to be closed.
    virtual void OnDataReceived(std::unique_ptr<SpdyBuffer> buffer) = 0;

    // Called when data is sent. Must not cause the stream to be
    // closed.
    virtual void OnDataSent() = 0;

    // Called when trailers are received. Note that trailers HEADER frame will
    // have END_STREAM flag set according to section 8.1 of the HTTP/2 RFC,
    // so this will be followed by OnClose.
    virtual void OnTrailers(const SpdyHeaderBlock& trailers) = 0;

    // Called when SpdyStream is closed. No other delegate functions
    // will be called after this is called, and the delegate must not
    // access the stream after this is called. Must not cause the
    // stream to be be (re-)closed.
    //
    // TODO(akalin): Allow this function to re-close the stream and
    // handle it gracefully.
    virtual void OnClose(int status) = 0;

   protected:
    virtual ~Delegate() {}

   private:
    DISALLOW_COPY_AND_ASSIGN(Delegate);
  };

  // SpdyStream constructor
  SpdyStream(SpdyStreamType type,
             const base::WeakPtr<SpdySession>& session,
             const GURL& url,
             RequestPriority priority,
             int32_t initial_send_window_size,
             int32_t max_recv_window_size,
             const BoundNetLog& net_log);

  ~SpdyStream();

  // Set the delegate, which must not be NULL. Must not be called more
  // than once. For push streams, calling this may cause buffered data
  // to be sent to the delegate (from a posted task).
  void SetDelegate(Delegate* delegate);

  // Detach the delegate from the stream, which must not yet be
  // closed, and cancel it.
  void DetachDelegate();

  // The time at which the first bytes of the response were received
  // from the server, or null if the response hasn't been received
  // yet.
  base::Time response_time() const { return response_time_; }

  SpdyStreamType type() const { return type_; }

  SpdyStreamId stream_id() const { return stream_id_; }
  void set_stream_id(SpdyStreamId stream_id) { stream_id_ = stream_id; }

  const GURL& url() const { return url_; }

  RequestPriority priority() const { return priority_; }

  int32_t send_window_size() const { return send_window_size_; }

  int32_t recv_window_size() const { return recv_window_size_; }

  bool send_stalled_by_flow_control() const {
    return send_stalled_by_flow_control_;
  }

  void set_send_stalled_by_flow_control(bool stalled) {
    send_stalled_by_flow_control_ = stalled;
  }

  // Called by the session to adjust this stream's send window size by
  // |delta_window_size|, which is the difference between the
  // SETTINGS_INITIAL_WINDOW_SIZE in the most recent SETTINGS frame
  // and the previous initial send window size, possibly unstalling
  // this stream. Although |delta_window_size| may cause this stream's
  // send window size to go negative, it must not cause it to wrap
  // around in either direction. Does nothing if the stream is already
  // closed.
  //
  // If stream flow control is turned off, this must not be called.
  void AdjustSendWindowSize(int32_t delta_window_size);

  // Called when bytes are consumed from a SpdyBuffer for a DATA frame
  // that is to be written or is being written. Increases the send
  // window size accordingly if some or all of the SpdyBuffer is being
  // discarded.
  //
  // If stream flow control is turned off, this must not be called.
  void OnWriteBufferConsumed(size_t frame_payload_size,
                             size_t consume_size,
                             SpdyBuffer::ConsumeSource consume_source);

  // Called by the session to increase this stream's send window size
  // by |delta_window_size| (which must be at least 1) from a received
  // WINDOW_UPDATE frame or from a dropped DATA frame that was
  // intended to be sent, possibly unstalling this stream. If
  // |delta_window_size| would cause this stream's send window size to
  // overflow, calls into the session to reset this stream. Does
  // nothing if the stream is already closed.
  //
  // If stream flow control is turned off, this must not be called.
  void IncreaseSendWindowSize(int32_t delta_window_size);

  // If stream flow control is turned on, called by the session to
  // decrease this stream's send window size by |delta_window_size|,
  // which must be at least 0 and at most kMaxSpdyFrameChunkSize.
  // |delta_window_size| must not cause this stream's send window size
  // to go negative. Does nothing if the stream is already closed.
  //
  // If stream flow control is turned off, this must not be called.
  void DecreaseSendWindowSize(int32_t delta_window_size);

  // Called when bytes are consumed by the delegate from a SpdyBuffer
  // containing received data. Increases the receive window size
  // accordingly.
  //
  // If stream flow control is turned off, this must not be called.
  void OnReadBufferConsumed(size_t consume_size,
                            SpdyBuffer::ConsumeSource consume_source);

  // Called by OnReadBufferConsume to increase this stream's receive
  // window size by |delta_window_size|, which must be at least 1 and
  // must not cause this stream's receive window size to overflow,
  // possibly also sending a WINDOW_UPDATE frame. Does nothing if the
  // stream is not active.
  //
  // If stream flow control is turned off, this must not be called.
  void IncreaseRecvWindowSize(int32_t delta_window_size);

  // Called by OnDataReceived or OnPaddingConsumed (which are in turn called by
  // the session) to decrease this stream's receive window size by
  // |delta_window_size|, which must be at least 1.  May close the stream on
  // flow control error.
  //
  // If stream flow control is turned off or the stream is not active,
  // this must not be called.
  void DecreaseRecvWindowSize(int32_t delta_window_size);

  int GetPeerAddress(IPEndPoint* address) const;
  int GetLocalAddress(IPEndPoint* address) const;

  // Returns true if the underlying transport socket ever had any reads or
  // writes.
  bool WasEverUsed() const;

  const BoundNetLog& net_log() const { return net_log_; }

  base::Time GetRequestTime() const;
  void SetRequestTime(base::Time t);

  // Called at most once by the SpdySession when the initial response
  // headers have been received for this stream, i.e., a SYN_REPLY (or
  // SYN_STREAM for push streams) frame has been received. Returns a status
  // code; if it is an error, the stream was closed by this function.
  int OnInitialResponseHeadersReceived(const SpdyHeaderBlock& response_headers,
                                       base::Time response_time,
                                       base::TimeTicks recv_first_byte_time);

  // Called by the SpdySession (only after
  // OnInitialResponseHeadersReceived() has been called) when
  // late-bound headers are received for a stream. Returns a status
  // code; if it is an error, the stream was closed by this function.
  int OnAdditionalResponseHeadersReceived(
      const SpdyHeaderBlock& additional_response_headers);

  // Called by the SpdySession when a frame carrying request headers opening a
  // push stream is received. Stream transits to STATE_RESERVED_REMOTE state.
  void OnPushPromiseHeadersReceived(const SpdyHeaderBlock& headers);

  // Called by the SpdySession when response data has been received
  // for this stream.  This callback may be called multiple times as
  // data arrives from the network, and will never be called prior to
  // OnResponseHeadersReceived.
  //
  // |buffer| contains the data received, or NULL if the stream is
  //          being closed.  The stream must copy any data from this
  //          buffer before returning from this callback.
  //
  // |length| is the number of bytes received (at most 2^24 - 1) or 0 if
  //          the stream is being closed.
  void OnDataReceived(std::unique_ptr<SpdyBuffer> buffer);

  // Called by the SpdySession when padding is consumed to allow for the stream
  // receiving window to be updated.
  void OnPaddingConsumed(size_t len);

  // Called by the SpdySession when a frame has been successfully and completely
  // written. |frame_size| is the total size of the logical frame in bytes,
  // including framing overhead.  For fragmented headers, this is the total size
  // of the HEADERS or PUSH_PROMISE frame and subsequent CONTINUATION frames.
  void OnFrameWriteComplete(SpdyFrameType frame_type, size_t frame_size);

  // SYN_STREAM-specific write handler invoked by OnFrameWriteComplete().
  int OnRequestHeadersSent();

  // DATA-specific write handler invoked by OnFrameWriteComplete().
  // If more data is already available to be written, the next write is
  // queued and ERR_IO_PENDING is returned. Returns OK otherwise.
  int OnDataSent(size_t frame_size);

  // Called by the SpdySession when the request is finished.  This callback
  // will always be called at the end of the request and signals to the
  // stream that the stream has no more network events.  No further callbacks
  // to the stream will be made after this call.
  // |status| is an error code or OK.
  void OnClose(int status);

  // Called by the SpdySession to log stream related errors.
  void LogStreamError(int status, const std::string& description);

  // If this stream is active, reset it, and close it otherwise. In
  // either case the stream is deleted.
  void Cancel();

  // Close this stream without sending a RST_STREAM and delete
  // it.
  void Close();

  // Must be used only by |session_|.
  base::WeakPtr<SpdyStream> GetWeakPtr();

  // Interface for the delegate to use.

  // Only one send can be in flight at a time, except for push
  // streams, which must not send anything.

  // Sends the request headers. The delegate is called back via
  // OnRequestHeadersSent() when the request headers have completed
  // sending. |send_status| must be MORE_DATA_TO_SEND for
  // bidirectional streams; for request/response streams, it must be
  // MORE_DATA_TO_SEND if the request has data to upload, or
  // NO_MORE_DATA_TO_SEND if not.
  int SendRequestHeaders(std::unique_ptr<SpdyHeaderBlock> request_headers,
                         SpdySendStatus send_status);

  // Sends a DATA frame. The delegate will be notified via
  // OnDataSent() when the send is complete. |send_status| must be
  // MORE_DATA_TO_SEND for bidirectional streams; for request/response
  // streams, it must be MORE_DATA_TO_SEND if there is more data to
  // upload, or NO_MORE_DATA_TO_SEND if not.
  void SendData(IOBuffer* data, int length, SpdySendStatus send_status);

  // Fills SSL info in |ssl_info| and returns true when SSL is in use.
  bool GetSSLInfo(SSLInfo* ssl_info,
                  bool* was_npn_negotiated,
                  NextProto* protocol_negotiated);

  // If the stream is stalled on sending data, but the session is not
  // stalled on sending data and |send_window_size_| is positive, then
  // set |send_stalled_by_flow_control_| to false and unstall the data
  // sending. Called by the session or by the stream itself. Must be
  // called only when the stream is still open.
  void PossiblyResumeIfSendStalled();

  // Returns whether or not this stream is closed. Note that the only
  // time a stream is closed and not deleted is in its delegate's
  // OnClose() method.
  bool IsClosed() const;

  // Returns whether the streams local endpoint is closed.
  // The remote endpoint may still be active.
  bool IsLocallyClosed() const;

  // Returns whether this stream is IDLE: request and response headers
  // have neither been sent nor receieved.
  bool IsIdle() const;

  // Returns whether or not this stream is fully open: that request and
  // response headers are complete, and it is not in a half-closed state.
  bool IsOpen() const;

  // Returns whether the stream is reserved by remote endpoint: server has sent
  // intended request headers for a pushed stream, but haven't started response
  // yet.
  bool IsReservedRemote() const;

  // Returns the protocol used by this stream. Always between
  // kProtoSPDYMinimumVersion and kProtoSPDYMaximumVersion.
  NextProto GetProtocol() const;

  int response_status() const { return response_status_; }

  void AddRawReceivedBytes(size_t received_bytes);
  void AddRawSentBytes(size_t sent_bytes);

  int64_t raw_received_bytes() const { return raw_received_bytes_; }
  int64_t raw_sent_bytes() const { return raw_sent_bytes_; }

  bool GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const;

  // Get the URL from the appropriate stream headers, or the empty
  // GURL() if it is unknown.
  //
  // TODO(akalin): Figure out if we really need this function,
  // i.e. can we just use the URL this stream was created with and/or
  // one we receive headers validate that the URL from them is the
  // same.
  GURL GetUrlFromHeaders() const;

  // Returns whether the URL for this stream is known.
  //
  // TODO(akalin): Remove this, as it's only used in tests.
  bool HasUrlFromHeaders() const;

  SpdyMajorVersion GetProtocolVersion() const;

 private:
  class SynStreamBufferProducer;
  class HeaderBufferProducer;

  // SpdyStream states and transitions are modeled
  // on the HTTP/2 stream state machine. All states and transitions
  // are modeled, with the exceptions of RESERVED_LOCAL (the client
  // cannot initate push streams), and the transition to OPEN due to
  // a remote SYN_STREAM (the client can only initate streams).
  enum State {
    STATE_IDLE,
    STATE_OPEN,
    STATE_HALF_CLOSED_LOCAL_UNCLAIMED,
    STATE_HALF_CLOSED_LOCAL,
    STATE_HALF_CLOSED_REMOTE,
    STATE_RESERVED_REMOTE,
    STATE_CLOSED,
  };

  // Update the histograms.  Can safely be called repeatedly, but should only
  // be called after the stream has completed.
  void UpdateHistograms();

  // When a server-push stream is claimed by SetDelegate(), this function is
  // posted on the current MessageLoop to replay everything the server has sent.
  // From the perspective of SpdyStream's state machine, headers, data, and
  // FIN states received prior to the delegate being attached have not yet been
  // read. While buffered by |pending_recv_data_| it's not until
  // PushedStreamReplay() is invoked that reads are considered
  // to have occurred, driving the state machine forward.
  void PushedStreamReplay();

  // Produces the SYN_STREAM frame for the stream. The stream must
  // already be activated.
  std::unique_ptr<SpdySerializedFrame> ProduceSynStreamFrame();

  // Produce the initial HEADER frame for the stream with the given
  // block. The stream must already be activated.
  std::unique_ptr<SpdySerializedFrame> ProduceHeaderFrame(
      std::unique_ptr<SpdyHeaderBlock> header_block);

  // Queues the send for next frame of the remaining data in
  // |pending_send_data_|. Must be called only when
  // |pending_send_data_| is set.
  void QueueNextDataFrame();

  // Merge the given headers into |response_headers_| and calls
  // OnResponseHeadersUpdated() on the delegate (if attached).
  // Returns a status code; if it is an error, the stream was closed
  // by this function.
  int MergeWithResponseHeaders(const SpdyHeaderBlock& new_response_headers);

  static std::string DescribeState(State state);

  const SpdyStreamType type_;

  SpdyStreamId stream_id_;
  const GURL url_;
  const RequestPriority priority_;

  bool send_stalled_by_flow_control_;

  // Current send window size.
  int32_t send_window_size_;

  // Maximum receive window size.  Each time a WINDOW_UPDATE is sent, it
  // restores the receive window size to this value.
  int32_t max_recv_window_size_;

  // Sum of |session_unacked_recv_window_bytes_| and current receive window
  // size.
  // TODO(bnc): Rename or change semantics so that |window_size_| is actual
  // window size.
  int32_t recv_window_size_;

  // When bytes are consumed, SpdyIOBuffer destructor calls back to SpdySession,
  // and this member keeps count of them until the corresponding WINDOW_UPDATEs
  // are sent.
  int32_t unacked_recv_window_bytes_;

  const base::WeakPtr<SpdySession> session_;

  // The transaction should own the delegate.
  SpdyStream::Delegate* delegate_;

  // The headers for the request to send.
  //
  // TODO(akalin): Hang onto this only until we send it. This
  // necessitates stashing the URL separately.
  std::unique_ptr<SpdyHeaderBlock> request_headers_;

  // Data waiting to be sent, and the close state of the local endpoint
  // after the data is fully written.
  scoped_refptr<DrainableIOBuffer> pending_send_data_;
  SpdySendStatus pending_send_status_;

  // Data waiting to be received, and the close state of the remote endpoint
  // after the data is fully read. Specifically, data received before the
  // delegate is attached must be buffered and later replayed. A remote FIN
  // is represented by a final, zero-length buffer.
  std::vector<std::unique_ptr<SpdyBuffer>> pending_recv_data_;

  // The time at which the request was made that resulted in this response.
  // For cached responses, this time could be "far" in the past.
  base::Time request_time_;

  SpdyHeaderBlock response_headers_;
  SpdyResponseHeadersStatus response_headers_status_;
  base::Time response_time_;

  State io_state_;

  // Since we buffer the response, we also buffer the response status.
  // Not valid until the stream is closed.
  int response_status_;

  BoundNetLog net_log_;

  base::TimeTicks send_time_;
  base::TimeTicks recv_first_byte_time_;
  base::TimeTicks recv_last_byte_time_;

  // Number of bytes that have been received on this stream, including frame
  // overhead and headers.
  int64_t raw_received_bytes_;
  // Number of bytes that have been sent on this stream, including frame
  // overhead and headers.
  int64_t raw_sent_bytes_;

  // Number of data bytes that have been sent/received on this stream, not
  // including frame overhead. Note that this does not count headers.
  int send_bytes_;
  int recv_bytes_;

  // Guards calls of delegate write handlers ensuring |this| is not destroyed.
  // TODO(jgraettinger): Consider removing after crbug.com/35511 is tracked
  // down.
  bool write_handler_guard_;

  base::WeakPtrFactory<SpdyStream> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(SpdyStream);
};

}  // namespace net

#endif  // NET_SPDY_SPDY_STREAM_H_
