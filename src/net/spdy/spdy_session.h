// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_SPDY_SESSION_H_
#define NET_SPDY_SPDY_SESSION_H_

#include <stddef.h>
#include <stdint.h>

#include <deque>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/time/time.h"
#include "net/base/host_port_pair.h"
#include "net/base/io_buffer.h"
#include "net/base/load_states.h"
#include "net/base/net_errors.h"
#include "net/base/net_export.h"
#include "net/base/request_priority.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/client_socket_pool.h"
#include "net/socket/next_proto.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/stream_socket.h"
#include "net/spdy/buffered_spdy_framer.h"
#include "net/spdy/http2_priority_dependencies.h"
#include "net/spdy/multiplexed_session.h"
#include "net/spdy/server_push_delegate.h"
#include "net/spdy/spdy_alt_svc_wire_format.h"
#include "net/spdy/spdy_buffer.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_protocol.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/spdy/spdy_stream.h"
#include "net/spdy/spdy_write_queue.h"
#include "net/ssl/ssl_config_service.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"

namespace net {

namespace test {
class SpdyStreamTest;
}

// This is somewhat arbitrary and not really fixed, but it will always work
// reasonably with ethernet. Chop the world into 2-packet chunks.  This is
// somewhat arbitrary, but is reasonably small and ensures that we elicit
// ACKs quickly from TCP (because TCP tries to only ACK every other packet).
const int kMss = 1430;
// The 8 is the size of the SPDY frame header.
const int kMaxSpdyFrameChunkSize = (2 * kMss) - 8;

// Default value of SETTINGS_INITIAL_WINDOW_SIZE per protocol specification.
// A session is always created with this initial window size.
const int32_t kDefaultInitialWindowSize = 65535;

// Maximum number of concurrent streams we will create, unless the server
// sends a SETTINGS frame with a different value.
const size_t kInitialMaxConcurrentStreams = 100;

// If more than this many bytes have been read or more than that many
// milliseconds have passed, return ERR_IO_PENDING from ReadLoop.
const int kYieldAfterBytesRead = 32 * 1024;
const int kYieldAfterDurationMilliseconds = 20;

// First and last valid stream IDs. As we always act as the client,
// start at 1 for the first stream id.
const SpdyStreamId kFirstStreamId = 1;
const SpdyStreamId kLastStreamId = 0x7fffffff;

struct LoadTimingInfo;
class NetLog;
class NetLogWithSource;
class ProxyDelegate;
class SpdyStream;
class SSLInfo;
class TransportSecurityState;

// NOTE: There's an enum of the same name (also with numeric suffixes)
// in histograms.xml. Be sure to add new values there also.
enum SpdyProtocolErrorDetails {
  // SpdyFramer::SpdyError mappings.
  SPDY_ERROR_NO_ERROR = 0,
  SPDY_ERROR_INVALID_STREAM_ID = 38,
  SPDY_ERROR_INVALID_CONTROL_FRAME = 1,
  SPDY_ERROR_CONTROL_PAYLOAD_TOO_LARGE = 2,
  SPDY_ERROR_ZLIB_INIT_FAILURE = 3,
  SPDY_ERROR_UNSUPPORTED_VERSION = 4,
  SPDY_ERROR_DECOMPRESS_FAILURE = 5,
  SPDY_ERROR_COMPRESS_FAILURE = 6,
  SPDY_ERROR_GOAWAY_FRAME_CORRUPT = 29,
  SPDY_ERROR_RST_STREAM_FRAME_CORRUPT = 30,
  SPDY_ERROR_INVALID_PADDING = 39,
  SPDY_ERROR_INVALID_DATA_FRAME_FLAGS = 8,
  SPDY_ERROR_INVALID_CONTROL_FRAME_FLAGS = 9,
  SPDY_ERROR_UNEXPECTED_FRAME = 31,
  SPDY_ERROR_INTERNAL_FRAMER_ERROR = 41,
  SPDY_ERROR_INVALID_CONTROL_FRAME_SIZE = 37,
  SPDY_ERROR_OVERSIZED_PAYLOAD = 40,
  // SpdyRstStreamStatus mappings.
  STATUS_CODE_NO_ERROR = 41,
  STATUS_CODE_PROTOCOL_ERROR = 11,
  STATUS_CODE_INTERNAL_ERROR = 16,
  STATUS_CODE_FLOW_CONTROL_ERROR = 17,
  STATUS_CODE_SETTINGS_TIMEOUT = 32,
  STATUS_CODE_STREAM_CLOSED = 12,
  STATUS_CODE_FRAME_SIZE_ERROR = 21,
  STATUS_CODE_REFUSED_STREAM = 13,
  STATUS_CODE_CANCEL = 15,
  STATUS_CODE_COMPRESSION_ERROR = 42,
  STATUS_CODE_CONNECT_ERROR = 33,
  STATUS_CODE_ENHANCE_YOUR_CALM = 34,
  STATUS_CODE_INADEQUATE_SECURITY = 35,
  STATUS_CODE_HTTP_1_1_REQUIRED = 36,
  // Deprecated SpdyRstStrreamStatus mappings.
  STATUS_CODE_UNSUPPORTED_VERSION = 14,
  STATUS_CODE_STREAM_IN_USE = 18,
  STATUS_CODE_STREAM_ALREADY_CLOSED = 19,

  // SpdySession errors
  PROTOCOL_ERROR_UNEXPECTED_PING = 22,
  PROTOCOL_ERROR_RST_STREAM_FOR_NON_ACTIVE_STREAM = 23,
  PROTOCOL_ERROR_SPDY_COMPRESSION_FAILURE = 24,
  PROTOCOL_ERROR_REQUEST_FOR_SECURE_CONTENT_OVER_INSECURE_SESSION = 25,
  PROTOCOL_ERROR_SYN_REPLY_NOT_RECEIVED = 26,
  PROTOCOL_ERROR_INVALID_WINDOW_UPDATE_SIZE = 27,
  PROTOCOL_ERROR_RECEIVE_WINDOW_VIOLATION = 28,

  // Next free value.
  NUM_SPDY_PROTOCOL_ERROR_DETAILS = 43,
};
SpdyProtocolErrorDetails NET_EXPORT_PRIVATE
    MapFramerErrorToProtocolError(SpdyFramer::SpdyError error);
Error NET_EXPORT_PRIVATE MapFramerErrorToNetError(SpdyFramer::SpdyError error);
SpdyProtocolErrorDetails NET_EXPORT_PRIVATE
    MapRstStreamStatusToProtocolError(SpdyRstStreamStatus status);
SpdyGoAwayStatus NET_EXPORT_PRIVATE MapNetErrorToGoAwayStatus(Error err);

// If these compile asserts fail then SpdyProtocolErrorDetails needs
// to be updated with new values, as do the mapping functions above.
static_assert(17 == SpdyFramer::LAST_ERROR,
              "SpdyProtocolErrorDetails / Spdy Errors mismatch");
static_assert(14 == RST_STREAM_NUM_STATUS_CODES,
              "SpdyProtocolErrorDetails / RstStreamStatus mismatch");

// A helper class used to manage a request to create a stream.
class NET_EXPORT_PRIVATE SpdyStreamRequest {
 public:
  SpdyStreamRequest();
  // Calls CancelRequest().
  ~SpdyStreamRequest();

  // Starts the request to create a stream. If OK is returned, then
  // ReleaseStream() may be called. If ERR_IO_PENDING is returned,
  // then when the stream is created, |callback| will be called, at
  // which point ReleaseStream() may be called. Otherwise, the stream
  // is not created, an error is returned, and ReleaseStream() may not
  // be called.
  //
  // If OK is returned, must not be called again without
  // ReleaseStream() being called first. If ERR_IO_PENDING is
  // returned, must not be called again without CancelRequest() or
  // ReleaseStream() being called first. Otherwise, in case of an
  // immediate error, this may be called again.
  int StartRequest(SpdyStreamType type,
                   const base::WeakPtr<SpdySession>& session,
                   const GURL& url,
                   RequestPriority priority,
                   const NetLogWithSource& net_log,
                   const CompletionCallback& callback);

  // Cancels any pending stream creation request. May be called
  // repeatedly.
  void CancelRequest();

  // Transfers the created stream (guaranteed to not be NULL) to the
  // caller. Must be called at most once after StartRequest() returns
  // OK or |callback| is called with OK. The caller must immediately
  // set a delegate for the returned stream (except for test code).
  base::WeakPtr<SpdyStream> ReleaseStream();

 private:
  friend class SpdySession;

  // Called by |session_| when the stream attempt has finished
  // successfully.
  void OnRequestCompleteSuccess(const base::WeakPtr<SpdyStream>& stream);

  // Called by |session_| when the stream attempt has finished with an
  // error. Also called with ERR_ABORTED if |session_| is destroyed
  // while the stream attempt is still pending.
  void OnRequestCompleteFailure(int rv);

  // Accessors called by |session_|.
  SpdyStreamType type() const { return type_; }
  const GURL& url() const { return url_; }
  RequestPriority priority() const { return priority_; }
  const NetLogWithSource& net_log() const { return net_log_; }

  void Reset();

  SpdyStreamType type_;
  base::WeakPtr<SpdySession> session_;
  base::WeakPtr<SpdyStream> stream_;
  GURL url_;
  RequestPriority priority_;
  NetLogWithSource net_log_;
  CompletionCallback callback_;

  base::WeakPtrFactory<SpdyStreamRequest> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(SpdyStreamRequest);
};

class NET_EXPORT SpdySession : public BufferedSpdyFramerVisitorInterface,
                               public SpdyFramerDebugVisitorInterface,
                               public MultiplexedSession,
                               public HigherLayeredPool {
 public:
  // TODO(akalin): Use base::TickClock when it becomes available.
  typedef base::TimeTicks (*TimeFunc)(void);

  // Container class for unclaimed pushed streams on a SpdySession.  Guarantees
  // that |spdy_session_.pool_| gets notified every time a stream is pushed or
  // an unclaimed pushed stream is claimed.
  class UnclaimedPushedStreamContainer {
   public:
    struct PushedStreamInfo {
      PushedStreamInfo() : stream_id(0) {}
      PushedStreamInfo(SpdyStreamId stream_id, base::TimeTicks creation_time)
          : stream_id(stream_id), creation_time(creation_time) {}
      ~PushedStreamInfo() {}

      SpdyStreamId stream_id;
      base::TimeTicks creation_time;
    };
    using PushedStreamMap = std::map<GURL, PushedStreamInfo>;
    using iterator = PushedStreamMap::iterator;
    using const_iterator = PushedStreamMap::const_iterator;

    UnclaimedPushedStreamContainer() = delete;
    explicit UnclaimedPushedStreamContainer(SpdySession* spdy_session);
    ~UnclaimedPushedStreamContainer();

    bool empty() const { return streams_.empty(); }
    size_t size() const { return streams_.size(); }
    const_iterator begin() const { return streams_.begin(); }
    const_iterator end() const { return streams_.end(); }
    const_iterator find(const GURL& url) const { return streams_.find(url); }
    size_t count(const GURL& url) const { return streams_.count(url); }
    const_iterator lower_bound(const GURL& url) const {
      return streams_.lower_bound(url);
    }

    size_t erase(const GURL& url);
    iterator erase(const_iterator it);
    iterator insert(const_iterator position,
                    const GURL& url,
                    SpdyStreamId stream_id,
                    const base::TimeTicks& creation_time);

   private:
    SpdySession* spdy_session_;

    // (Bijective) map from the URL to the ID of the streams that have
    // already started to be pushed by the server, but do not have
    // consumers yet. Contains a subset of |active_streams_|.
    PushedStreamMap streams_;
  };

  // Returns true if |new_hostname| can be pooled into an existing connection to
  // |old_hostname| associated with |ssl_info|.
  static bool CanPool(TransportSecurityState* transport_security_state,
                      const SSLInfo& ssl_info,
                      const std::string& old_hostname,
                      const std::string& new_hostname);

  // Create a new SpdySession.
  // |spdy_session_key| is the host/port that this session connects to, privacy
  // and proxy configuration settings that it's using.
  // |session| is the HttpNetworkSession.  |net_log| is the NetLog that we log
  // network events to.
  SpdySession(const SpdySessionKey& spdy_session_key,
              HttpServerProperties* http_server_properties,
              TransportSecurityState* transport_security_state,
              bool enable_sending_initial_data,
              bool enable_ping_based_connection_checking,
              size_t session_max_recv_window_size,
              const SettingsMap& initial_settings,
              TimeFunc time_func,
              ServerPushDelegate* push_delegate,
              ProxyDelegate* proxy_delegate,
              NetLog* net_log);

  ~SpdySession() override;

  const HostPortPair& host_port_pair() const {
    return spdy_session_key_.host_port_proxy_pair().first;
  }
  const HostPortProxyPair& host_port_proxy_pair() const {
    return spdy_session_key_.host_port_proxy_pair();
  }
  const SpdySessionKey& spdy_session_key() const {
    return spdy_session_key_;
  }
  // Get a pushed stream for a given |url|.  If the server initiates a
  // stream, it might already exist for a given path.  The server
  // might also not have initiated the stream yet, but indicated it
  // will via X-Associated-Content.  Returns OK if a stream was found
  // and put into |spdy_stream|, or if one was not found but it is
  // okay to create a new stream (in which case |spdy_stream| is
  // reset).  Returns an error (not ERR_IO_PENDING) otherwise, and
  // resets |spdy_stream|.
  //
  // If a stream was found and the stream is still open, the priority
  // of that stream is updated to match |priority|.
  int GetPushStream(const GURL& url,
                    RequestPriority priority,
                    base::WeakPtr<SpdyStream>* spdy_stream,
                    const NetLogWithSource& stream_net_log);

  // Called when the pushed stream should be cancelled. If the pushed stream is
  // not claimed and active, sends RST to the server to cancel the stream.
  void CancelPush(const GURL& url);

  // Initialize the session with the given connection. |is_secure|
  // must indicate whether |connection| uses an SSL socket or not; it
  // is usually true, but it can be false for testing or when SPDY is
  // configured to work with non-secure sockets.
  //
  // |pool| is the SpdySessionPool that owns us.  Its lifetime must
  // strictly be greater than |this|.
  //
  // The session begins reading from |connection| on a subsequent event loop
  // iteration, so the SpdySession may close immediately afterwards if the first
  // read of |connection| fails.
  void InitializeWithSocket(std::unique_ptr<ClientSocketHandle> connection,
                            SpdySessionPool* pool,
                            bool is_secure);

  // Check to see if this SPDY session can support an additional domain.
  // If the session is un-authenticated, then this call always returns true.
  // For SSL-based sessions, verifies that the server certificate in use by
  // this session provides authentication for the domain and no client
  // certificate or channel ID was sent to the original server during the SSL
  // handshake.  NOTE:  This function can have false negatives on some
  // platforms.
  // TODO(wtc): rename this function and the Net.SpdyIPPoolDomainMatch
  // histogram because this function does more than verifying domain
  // authentication now.
  bool VerifyDomainAuthentication(const std::string& domain);

  // Pushes the given producer into the write queue for
  // |stream|. |stream| is guaranteed to be activated before the
  // producer is used to produce its frame.
  void EnqueueStreamWrite(const base::WeakPtr<SpdyStream>& stream,
                          SpdyFrameType frame_type,
                          std::unique_ptr<SpdyBufferProducer> producer);

  // Creates and returns a HEADERS frame for |stream_id|.
  std::unique_ptr<SpdySerializedFrame> CreateHeaders(SpdyStreamId stream_id,
                                                     RequestPriority priority,
                                                     SpdyControlFlags flags,
                                                     SpdyHeaderBlock headers);

  // Creates and returns a SpdyBuffer holding a data frame with the
  // given data. May return NULL if stalled by flow control.
  std::unique_ptr<SpdyBuffer> CreateDataBuffer(SpdyStreamId stream_id,
                                               IOBuffer* data,
                                               int len,
                                               SpdyDataFlags flags);

  // Close the stream with the given ID, which must exist and be
  // active. Note that that stream may hold the last reference to the
  // session.
  void CloseActiveStream(SpdyStreamId stream_id, int status);

  // Close the given created stream, which must exist but not yet be
  // active. Note that |stream| may hold the last reference to the
  // session.
  void CloseCreatedStream(const base::WeakPtr<SpdyStream>& stream, int status);

  // Send a RST_STREAM frame with the given status code and close the
  // stream with the given ID, which must exist and be active. Note
  // that that stream may hold the last reference to the session.
  void ResetStream(SpdyStreamId stream_id,
                   SpdyRstStreamStatus status,
                   const std::string& description);

  // Check if a stream is active.
  bool IsStreamActive(SpdyStreamId stream_id) const;

  // The LoadState is used for informing the user of the current network
  // status, such as "resolving host", "connecting", etc.
  LoadState GetLoadState() const;

  // Returns server infomation in the form of (scheme/host/port).
  url::SchemeHostPort GetServer();

  // MultiplexedSession methods:
  bool GetRemoteEndpoint(IPEndPoint* endpoint) override;
  bool GetSSLInfo(SSLInfo* ssl_info) const override;
  Error GetTokenBindingSignature(crypto::ECPrivateKey* key,
                                 TokenBindingType tb_type,
                                 std::vector<uint8_t>* out) override;

  // Returns true if ALPN was negotiated for the underlying socket.
  bool WasAlpnNegotiated() const;

  // Returns the protocol negotiated via ALPN for the underlying socket.
  NextProto GetNegotiatedProtocol() const;

  // Send a WINDOW_UPDATE frame for a stream. Called by a stream
  // whenever receive window size is increased.
  void SendStreamWindowUpdate(SpdyStreamId stream_id,
                              uint32_t delta_window_size);

  // Accessors for the session's availability state.
  bool IsAvailable() const { return availability_state_ == STATE_AVAILABLE; }
  bool IsGoingAway() const { return availability_state_ == STATE_GOING_AWAY; }
  bool IsDraining() const { return availability_state_ == STATE_DRAINING; }

  // Closes this session. This will close all active streams and mark
  // the session as permanently closed. Callers must assume that the
  // session is destroyed after this is called. (However, it may not
  // be destroyed right away, e.g. when a SpdySession function is
  // present in the call stack.)
  //
  // |err| should be < ERR_IO_PENDING; this function is intended to be
  // called on error.
  // |description| indicates the reason for the error.
  void CloseSessionOnError(Error err, const std::string& description);

  // Mark this session as unavailable, meaning that it will not be used to
  // service new streams. Unlike when a GOAWAY frame is received, this function
  // will not close any streams.
  void MakeUnavailable();

  // Closes all active streams with stream id's greater than
  // |last_good_stream_id|, as well as any created or pending
  // streams. Must be called only when |availability_state_| >=
  // STATE_GOING_AWAY. After this function, DcheckGoingAway() will
  // pass. May be called multiple times.
  void StartGoingAway(SpdyStreamId last_good_stream_id, Error status);

  // Must be called only when going away (i.e., DcheckGoingAway()
  // passes). If there are no more active streams and the session
  // isn't closed yet, close it.
  void MaybeFinishGoingAway();

  // Retrieves information on the current state of the SPDY session as a
  // Value.
  std::unique_ptr<base::Value> GetInfoAsValue() const;

  // Indicates whether the session is being reused after having successfully
  // used to send/receive data in the past or if the underlying socket was idle
  // before being used for a SPDY session.
  bool IsReused() const;

  // Returns true if the underlying transport socket ever had any reads or
  // writes.
  bool WasEverUsed() const {
    return connection_->socket()->WasEverUsed();
  }

  // Returns the load timing information from the perspective of the given
  // stream.  If it's not the first stream, the connection is considered reused
  // for that stream.
  //
  // This uses a different notion of reuse than IsReused().  This function
  // sets |socket_reused| to false only if |stream_id| is the ID of the first
  // stream using the session.  IsReused(), on the other hand, indicates if the
  // session has been used to send/receive data at all.
  bool GetLoadTimingInfo(SpdyStreamId stream_id,
                         LoadTimingInfo* load_timing_info) const;

  // Returns true if session is not currently active
  bool is_active() const {
    return !active_streams_.empty() || !created_streams_.empty();
  }

  // Access to the number of active and pending streams.  These are primarily
  // available for testing and diagnostics.
  size_t num_active_streams() const { return active_streams_.size(); }
  size_t num_unclaimed_pushed_streams() const;
  size_t num_created_streams() const { return created_streams_.size(); }
  size_t count_unclaimed_pushed_streams_for_url(const GURL& url) const;

  size_t num_pushed_streams() const { return num_pushed_streams_; }
  size_t num_active_pushed_streams() const {
    return num_active_pushed_streams_;
  }

  size_t pending_create_stream_queue_size(RequestPriority priority) const {
    DCHECK_GE(priority, MINIMUM_PRIORITY);
    DCHECK_LE(priority, MAXIMUM_PRIORITY);
    return pending_create_stream_queues_[priority].size();
  }

  // Returns the current |stream_initial_send_window_size_|.
  int32_t stream_initial_send_window_size() const {
    return stream_initial_send_window_size_;
  }

  // Returns true if no stream in the session can send data due to
  // session flow control.
  bool IsSendStalled() const { return session_send_window_size_ == 0; }

  const NetLogWithSource& net_log() const { return net_log_; }

  int GetPeerAddress(IPEndPoint* address) const;
  int GetLocalAddress(IPEndPoint* address) const;

  // Adds |alias| to set of aliases associated with this session.
  void AddPooledAlias(const SpdySessionKey& alias_key);

  // Returns the set of aliases associated with this session.
  const std::set<SpdySessionKey>& pooled_aliases() const {
    return pooled_aliases_;
  }

  size_t GetDataFrameMinimumSize() const {
    return buffered_spdy_framer_->GetDataFrameMinimumSize();
  }

  size_t GetFrameHeaderSize() const {
    return buffered_spdy_framer_->GetFrameHeaderSize();
  }

  size_t GetFrameMinimumSize() const {
    return buffered_spdy_framer_->GetFrameMinimumSize();
  }

  size_t GetFrameMaximumSize() const {
    return buffered_spdy_framer_->GetFrameMaximumSize();
  }

  size_t GetDataFrameMaximumPayload() const {
    return buffered_spdy_framer_->GetDataFrameMaximumPayload();
  }

  // https://http2.github.io/http2-spec/#TLSUsage mandates minimum security
  // standards for TLS.
  bool HasAcceptableTransportSecurity() const;

  // Must be used only by |pool_|.
  base::WeakPtr<SpdySession> GetWeakPtr();

  // HigherLayeredPool implementation:
  bool CloseOneIdleConnection() override;

  // Dumps memory allocation stats to |stats|. Sets |*is_session_active| to
  // indicate whether session is active.
  // |stats| can be assumed as being default initialized upon entry.
  // Implementation overrides fields in |stats|.
  void DumpMemoryStats(StreamSocket::SocketMemoryStats* stats,
                       bool* is_session_active) const;

 private:
  friend class test::SpdyStreamTest;
  friend class base::RefCounted<SpdySession>;
  friend class HttpNetworkTransactionTest;
  friend class HttpProxyClientSocketPoolTest;
  friend class SpdyHttpStreamTest;
  friend class SpdyNetworkTransactionTest;
  friend class SpdyProxyClientSocketTest;
  friend class SpdySessionTest;
  friend class SpdyStreamRequest;

  // Allow tests to access our innards for testing purposes.
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, ClientPing);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, FailedPing);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, GetActivePushStream);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, DeleteExpiredPushStreams);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, MetricsCollectionOnPushStreams);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, CancelPushBeforeClaimed);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, CancelPushAfterSessionGoesAway);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, CancelPushAfterExpired);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, ProtocolNegotiation);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, ClearSettings);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, AdjustRecvWindowSize);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, AdjustSendWindowSize);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, SessionFlowControlInactiveStream);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, SessionFlowControlPadding);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest,
                           SessionFlowControlTooMuchDataTwoDataFrames);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest,
                           StreamFlowControlTooMuchDataTwoDataFrames);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, SessionFlowControlNoReceiveLeaks);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, SessionFlowControlNoSendLeaks);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, SessionFlowControlEndToEnd);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, StreamIdSpaceExhausted);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, MaxConcurrentStreamsZero);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, UnstallRacesWithStreamCreation);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, GoAwayOnSessionFlowControlError);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest,
                           RejectPushedStreamExceedingConcurrencyLimit);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, IgnoreReservedRemoteStreamsCount);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest,
                           CancelReservedStreamOnHeadersReceived);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionTest, RejectInvalidUnknownFrames);
  FRIEND_TEST_ALL_PREFIXES(SpdySessionPoolTest, IPAddressChanged);
  FRIEND_TEST_ALL_PREFIXES(SpdyNetworkTransactionTest,
                           ServerPushValidCrossOrigin);
  FRIEND_TEST_ALL_PREFIXES(SpdyNetworkTransactionTest,
                           ServerPushValidCrossOriginWithOpenSession);

  typedef std::deque<base::WeakPtr<SpdyStreamRequest>>
      PendingStreamRequestQueue;
  typedef std::map<SpdyStreamId, SpdyStream*> ActiveStreamMap;
  typedef std::set<SpdyStream*> CreatedStreamSet;

  enum AvailabilityState {
    // The session is available in its socket pool and can be used
    // freely.
    STATE_AVAILABLE,
    // The session can process data on existing streams but will
    // refuse to create new ones.
    STATE_GOING_AWAY,
    // The session is draining its write queue in preparation of closing.
    // Further writes will not be queued, and further reads will not be issued
    // (though the remainder of a current read may be processed). The session
    // will be destroyed by its write loop once the write queue is drained.
    STATE_DRAINING,
  };

  enum ReadState {
    READ_STATE_DO_READ,
    READ_STATE_DO_READ_COMPLETE,
  };

  enum WriteState {
    // There is no in-flight write and the write queue is empty.
    WRITE_STATE_IDLE,
    WRITE_STATE_DO_WRITE,
    WRITE_STATE_DO_WRITE_COMPLETE,
  };

  // Called by SpdyStreamRequest to start a request to create a
  // stream. If OK is returned, then |stream| will be filled in with a
  // valid stream. If ERR_IO_PENDING is returned, then
  // |request->OnRequestComplete{Success,Failure}()| will be called
  // when the stream is created (unless it is cancelled). Otherwise,
  // no stream is created and the error is returned.
  int TryCreateStream(const base::WeakPtr<SpdyStreamRequest>& request,
                      base::WeakPtr<SpdyStream>* stream);

  // Actually create a stream into |stream|. Returns OK if successful;
  // otherwise, returns an error and |stream| is not filled.
  int CreateStream(const SpdyStreamRequest& request,
                   base::WeakPtr<SpdyStream>* stream);

  // Called by SpdyStreamRequest to remove |request| from the stream
  // creation queue.
  void CancelStreamRequest(const base::WeakPtr<SpdyStreamRequest>& request);

  // Returns the next pending stream request to process, or NULL if
  // there is none.
  base::WeakPtr<SpdyStreamRequest> GetNextPendingStreamRequest();

  // Called when there is room to create more streams (e.g., a stream
  // was closed). Processes as many pending stream requests as
  // possible.
  void ProcessPendingStreamRequests();

  void TryCreatePushStream(SpdyStreamId stream_id,
                           SpdyStreamId associated_stream_id,
                           SpdyHeaderBlock headers);

  // Close the stream pointed to by the given iterator. Note that that
  // stream may hold the last reference to the session.
  void CloseActiveStreamIterator(ActiveStreamMap::iterator it, int status);

  // Close the stream pointed to by the given iterator. Note that that
  // stream may hold the last reference to the session.
  void CloseCreatedStreamIterator(CreatedStreamSet::iterator it, int status);

  // Calls EnqueueResetStreamFrame() and then
  // CloseActiveStreamIterator().
  void ResetStreamIterator(ActiveStreamMap::iterator it,
                           SpdyRstStreamStatus status,
                           const std::string& description);

  // Send a RST_STREAM frame with the given parameters. There should
  // either be no active stream with the given ID, or that active
  // stream should be closed shortly after this function is called.
  void EnqueueResetStreamFrame(SpdyStreamId stream_id,
                               RequestPriority priority,
                               SpdyRstStreamStatus status,
                               const std::string& description);

  // Send a PRIORITY frame with the given parameters.
  void EnqueuePriorityFrame(SpdyStreamId stream_id,
                            SpdyStreamId dependency_id,
                            int weight,
                            bool exclusive);

  // Calls DoReadLoop. Use this function instead of DoReadLoop when
  // posting a task to pump the read loop.
  void PumpReadLoop(ReadState expected_read_state, int result);

  // Advance the ReadState state machine. |expected_read_state| is the
  // expected starting read state.
  //
  // This function must always be called via PumpReadLoop().
  int DoReadLoop(ReadState expected_read_state, int result);
  // The implementations of the states of the ReadState state machine.
  int DoRead();
  int DoReadComplete(int result);

  // Calls DoWriteLoop. If |availability_state_| is STATE_DRAINING and no
  // writes remain, the session is removed from the session pool and
  // destroyed.
  //
  // Use this function instead of DoWriteLoop when posting a task to
  // pump the write loop.
  void PumpWriteLoop(WriteState expected_write_state, int result);

  // Iff the write loop is not currently active, posts a callback into
  // PumpWriteLoop().
  void MaybePostWriteLoop();

  // Advance the WriteState state machine. |expected_write_state| is
  // the expected starting write state.
  //
  // This function must always be called via PumpWriteLoop().
  int DoWriteLoop(WriteState expected_write_state, int result);
  // The implementations of the states of the WriteState state machine.
  int DoWrite();
  int DoWriteComplete(int result);

  // TODO(akalin): Rename the Send* and Write* functions below to
  // Enqueue*.

  // Send initial data. Called when a connection is successfully
  // established in InitializeWithSocket() and
  // |enable_sending_initial_data_| is true.
  void SendInitialData();

  // Helper method to send a SETTINGS frame.
  void SendSettings(const SettingsMap& settings);

  // Handle SETTING.  Either when we send settings, or when we receive a
  // SETTINGS control frame, update our SpdySession accordingly.
  void HandleSetting(uint32_t id, uint32_t value);

  // Adjust the send window size of all ActiveStreams and PendingStreamRequests.
  void UpdateStreamsSendWindowSize(int32_t delta_window_size);

  // Send the PING (preface-PING) frame.
  void SendPrefacePingIfNoneInFlight();

  // Send PING if there are no PINGs in flight and we haven't heard from server.
  void SendPrefacePing();

  // Send a single WINDOW_UPDATE frame.
  void SendWindowUpdateFrame(SpdyStreamId stream_id,
                             uint32_t delta_window_size,
                             RequestPriority priority);

  // Send the PING frame.
  void WritePingFrame(SpdyPingId unique_id, bool is_ack);

  // Post a CheckPingStatus call after delay. Don't post if there is already
  // CheckPingStatus running.
  void PlanToCheckPingStatus();

  // Check the status of the connection. It calls |CloseSessionOnError| if we
  // haven't received any data in |kHungInterval| time period.
  void CheckPingStatus(base::TimeTicks last_check_time);

  // Get a new stream id.
  SpdyStreamId GetNewStreamId();

  // Pushes the given frame with the given priority into the write
  // queue for the session.
  void EnqueueSessionWrite(RequestPriority priority,
                           SpdyFrameType frame_type,
                           std::unique_ptr<SpdySerializedFrame> frame);

  // Puts |producer| associated with |stream| onto the write queue
  // with the given priority.
  void EnqueueWrite(RequestPriority priority,
                    SpdyFrameType frame_type,
                    std::unique_ptr<SpdyBufferProducer> producer,
                    const base::WeakPtr<SpdyStream>& stream);

  // Inserts a newly-created stream into |created_streams_|.
  void InsertCreatedStream(std::unique_ptr<SpdyStream> stream);

  // Activates |stream| (which must be in |created_streams_|) by
  // assigning it an ID and returns it.
  std::unique_ptr<SpdyStream> ActivateCreatedStream(SpdyStream* stream);

  // Inserts a newly-activated stream into |active_streams_|.
  void InsertActivatedStream(std::unique_ptr<SpdyStream> stream);

  // Remove all internal references to |stream|, call OnClose() on it,
  // and process any pending stream requests before deleting it.  Note
  // that |stream| may hold the last reference to the session.
  void DeleteStream(std::unique_ptr<SpdyStream> stream, int status);

  // Returns the stream id of the push stream if it is not claimed yet, or 0
  // otherwise.
  SpdyStreamId GetStreamIdForPush(const GURL& url);

  // Check if we have a pending pushed-stream for this url
  // Returns the stream if found (and returns it from the pending
  // list). Returns NULL otherwise.
  base::WeakPtr<SpdyStream> GetActivePushStream(const GURL& url);

  void RecordPingRTTHistogram(base::TimeDelta duration);
  void RecordHistograms();
  void RecordProtocolErrorHistogram(SpdyProtocolErrorDetails details);

  // DCHECKs that |availability_state_| >= STATE_GOING_AWAY, that
  // there are no pending stream creation requests, and that there are
  // no created streams.
  void DcheckGoingAway() const;

  // Calls DcheckGoingAway(), then DCHECKs that |availability_state_|
  // == STATE_DRAINING, |error_on_close_| has a valid value, and that there
  // are no active streams or unclaimed pushed streams.
  void DcheckDraining() const;

  // If the session is already draining, does nothing. Otherwise, moves
  // the session to the draining state.
  void DoDrainSession(Error err, const std::string& description);

  // Called right before closing a (possibly-inactive) stream for a
  // reason other than being requested to by the stream.
  void LogAbandonedStream(SpdyStream* stream, Error status);

  // Called right before closing an active stream for a reason other
  // than being requested to by the stream.
  void LogAbandonedActiveStream(ActiveStreamMap::const_iterator it,
                                Error status);

  // Invokes a user callback for stream creation.  We provide this method so it
  // can be deferred to the MessageLoop, so we avoid re-entrancy problems.
  void CompleteStreamRequest(
      const base::WeakPtr<SpdyStreamRequest>& pending_request);

  // Remove old unclaimed pushed streams.
  void DeleteExpiredPushedStreams();

  // BufferedSpdyFramerVisitorInterface:
  void OnError(SpdyFramer::SpdyError error_code) override;
  void OnStreamError(SpdyStreamId stream_id,
                     const std::string& description) override;
  void OnPing(SpdyPingId unique_id, bool is_ack) override;
  void OnRstStream(SpdyStreamId stream_id, SpdyRstStreamStatus status) override;
  void OnGoAway(SpdyStreamId last_accepted_stream_id,
                SpdyGoAwayStatus status,
                base::StringPiece debug_data) override;
  void OnDataFrameHeader(SpdyStreamId stream_id,
                         size_t length,
                         bool fin) override;
  void OnStreamFrameData(SpdyStreamId stream_id,
                         const char* data,
                         size_t len) override;
  void OnStreamEnd(SpdyStreamId stream_id) override;
  void OnStreamPadding(SpdyStreamId stream_id, size_t len) override;
  void OnSettings() override;
  void OnSetting(SpdySettingsIds id, uint32_t value) override;
  void OnWindowUpdate(SpdyStreamId stream_id, int delta_window_size) override;
  void OnPushPromise(SpdyStreamId stream_id,
                     SpdyStreamId promised_stream_id,
                     SpdyHeaderBlock headers) override;
  void OnHeaders(SpdyStreamId stream_id,
                 bool has_priority,
                 int weight,
                 SpdyStreamId parent_stream_id,
                 bool exclusive,
                 bool fin,
                 SpdyHeaderBlock headers) override;
  void OnAltSvc(SpdyStreamId stream_id,
                base::StringPiece origin,
                const SpdyAltSvcWireFormat::AlternativeServiceVector&
                    altsvc_vector) override;
  bool OnUnknownFrame(SpdyStreamId stream_id, int frame_type) override;

  // SpdyFramerDebugVisitorInterface
  void OnSendCompressedFrame(SpdyStreamId stream_id,
                             SpdyFrameType type,
                             size_t payload_len,
                             size_t frame_len) override;
  void OnReceiveCompressedFrame(SpdyStreamId stream_id,
                                SpdyFrameType type,
                                size_t frame_len) override;

  // Called when bytes are consumed from a SpdyBuffer for a DATA frame
  // that is to be written or is being written. Increases the send
  // window size accordingly if some or all of the SpdyBuffer is being
  // discarded.
  //
  // If session flow control is turned off, this must not be called.
  void OnWriteBufferConsumed(size_t frame_payload_size,
                             size_t consume_size,
                             SpdyBuffer::ConsumeSource consume_source);

  // Called by OnWindowUpdate() (which is in turn called by the
  // framer) to increase this session's send window size by
  // |delta_window_size| from a WINDOW_UPDATE frome, which must be at
  // least 1. If |delta_window_size| would cause this session's send
  // window size to overflow, does nothing.
  //
  // If session flow control is turned off, this must not be called.
  void IncreaseSendWindowSize(int delta_window_size);

  // If session flow control is turned on, called by CreateDataFrame()
  // (which is in turn called by a stream) to decrease this session's
  // send window size by |delta_window_size|, which must be at least 1
  // and at most kMaxSpdyFrameChunkSize.  |delta_window_size| must not
  // cause this session's send window size to go negative.
  //
  // If session flow control is turned off, this must not be called.
  void DecreaseSendWindowSize(int32_t delta_window_size);

  // Called when bytes are consumed by the delegate from a SpdyBuffer
  // containing received data. Increases the receive window size
  // accordingly.
  //
  // If session flow control is turned off, this must not be called.
  void OnReadBufferConsumed(size_t consume_size,
                            SpdyBuffer::ConsumeSource consume_source);

  // Called by OnReadBufferConsume to increase this session's receive
  // window size by |delta_window_size|, which must be at least 1 and
  // must not cause this session's receive window size to overflow,
  // possibly also sending a WINDOW_UPDATE frame. Also called during
  // initialization to set the initial receive window size.
  //
  // If session flow control is turned off, this must not be called.
  void IncreaseRecvWindowSize(int32_t delta_window_size);

  // Called by OnStreamFrameData (which is in turn called by the
  // framer) to decrease this session's receive window size by
  // |delta_window_size|, which must be at least 1 and must not cause
  // this session's receive window size to go negative.
  //
  // If session flow control is turned off, this must not be called.
  void DecreaseRecvWindowSize(int32_t delta_window_size);

  // Queue a send-stalled stream for possibly resuming once we're not
  // send-stalled anymore.
  void QueueSendStalledStream(const SpdyStream& stream);

  // Go through the queue of send-stalled streams and try to resume as
  // many as possible.
  void ResumeSendStalledStreams();

  // Returns the next stream to possibly resume, or 0 if the queue is
  // empty.
  SpdyStreamId PopStreamToPossiblyResume();

  // --------------------------
  // Helper methods for testing
  // --------------------------

  void set_connection_at_risk_of_loss_time(base::TimeDelta duration) {
    connection_at_risk_of_loss_time_ = duration;
  }

  void set_hung_interval(base::TimeDelta duration) {
    hung_interval_ = duration;
  }

  void set_max_concurrent_pushed_streams(size_t value) {
    max_concurrent_pushed_streams_ = value;
  }

  int64_t pings_in_flight() const { return pings_in_flight_; }

  SpdyPingId next_ping_id() const { return next_ping_id_; }

  base::TimeTicks last_activity_time() const { return last_activity_time_; }

  bool check_ping_status_pending() const { return check_ping_status_pending_; }

  // Whether Do{Read,Write}Loop() is in the call stack. Useful for
  // making sure we don't destroy ourselves prematurely in that case.
  bool in_io_loop_;

  // The key used to identify this session.
  const SpdySessionKey spdy_session_key_;

  // Set set of SpdySessionKeys for which this session has serviced
  // requests.
  std::set<SpdySessionKey> pooled_aliases_;

  // |pool_| owns us, therefore its lifetime must exceed ours.
  SpdySessionPool* pool_;
  HttpServerProperties* http_server_properties_;

  TransportSecurityState* transport_security_state_;

  // The socket handle for this session.
  std::unique_ptr<ClientSocketHandle> connection_;

  // The read buffer used to read data from the socket.
  scoped_refptr<IOBuffer> read_buffer_;

  SpdyStreamId stream_hi_water_mark_;  // The next stream id to use.

  // Used to ensure the server increments push stream ids correctly.
  SpdyStreamId last_accepted_push_stream_id_;

  // Queue, for each priority, of pending stream requests that have
  // not yet been satisfied.
  PendingStreamRequestQueue pending_create_stream_queues_[NUM_PRIORITIES];

  // Map from stream id to all active streams.  Streams are active in the sense
  // that they have a consumer (typically SpdyNetworkTransaction and regardless
  // of whether or not there is currently any ongoing IO [might be waiting for
  // the server to start pushing the stream]) or there are still network events
  // incoming even though the consumer has already gone away (cancellation).
  //
  // |active_streams_| owns all its SpdyStream objects.
  //
  // TODO(willchan): Perhaps we should separate out cancelled streams and move
  // them into a separate ActiveStreamMap, and not deliver network events to
  // them?
  ActiveStreamMap active_streams_;

  UnclaimedPushedStreamContainer unclaimed_pushed_streams_;

  // Not owned. |push_delegate_| outlives the session and handles server pushes
  // received by session.
  ServerPushDelegate* push_delegate_;

  // Set of all created streams but that have not yet sent any frames.
  //
  // |created_streams_| owns all its SpdyStream objects.
  CreatedStreamSet created_streams_;

  // Number of pushed streams. All active streams are stored in
  // |active_streams_|, but it's better to know the number of push streams
  // without traversing the whole collection.
  size_t num_pushed_streams_;

  // Number of active pushed streams in |active_streams_|, i.e. not in reserved
  // remote state. Streams in reserved state are not counted towards any
  // concurrency limits.
  size_t num_active_pushed_streams_;

  // Number of bytes that has been pushed by the server.
  uint64_t bytes_pushed_count_;

  // Number of bytes that has been pushed by the server but never claimed.
  uint64_t bytes_pushed_and_unclaimed_count_;

  // The write queue.
  SpdyWriteQueue write_queue_;

  // Data for the frame we are currently sending.

  // The buffer we're currently writing.
  std::unique_ptr<SpdyBuffer> in_flight_write_;
  // The type of the frame in |in_flight_write_|.
  SpdyFrameType in_flight_write_frame_type_;
  // The size of the frame in |in_flight_write_|.
  size_t in_flight_write_frame_size_;
  // The stream to notify when |in_flight_write_| has been written to
  // the socket completely.
  base::WeakPtr<SpdyStream> in_flight_write_stream_;

  // Flag if we're using an SSL connection for this SpdySession.
  bool is_secure_;

  // Spdy Frame state.
  std::unique_ptr<BufferedSpdyFramer> buffered_spdy_framer_;

  // The state variables.
  AvailabilityState availability_state_;
  ReadState read_state_;
  WriteState write_state_;

  // If the session is closing (i.e., |availability_state_| is STATE_DRAINING),
  // then |error_on_close_| holds the error with which it was closed, which
  // may be OK (upon a polite GOAWAY) or an error < ERR_IO_PENDING otherwise.
  // Initialized to OK.
  Error error_on_close_;

  // Settings that are sent in the initial SETTINGS frame
  // (if |enable_sending_initial_data_| is true),
  // and also control SpdySession parameters like initial receive window size
  // and maximum HPACK dynamic table size.
  const SettingsMap initial_settings_;

  // Limits
  size_t max_concurrent_streams_;
  size_t max_concurrent_pushed_streams_;

  // Some statistics counters for the session.
  int streams_initiated_count_;
  int streams_pushed_count_;
  int streams_pushed_and_claimed_count_;
  int streams_abandoned_count_;

  // Count of all pings on the wire, for which we have not gotten a response.
  int64_t pings_in_flight_;

  // This is the next ping_id (unique_id) to be sent in PING frame.
  SpdyPingId next_ping_id_;

  // This is the last time we have sent a PING.
  base::TimeTicks last_ping_sent_time_;

  // This is the last time we had activity in the session.
  base::TimeTicks last_activity_time_;

  // This is the length of the last compressed frame.
  size_t last_compressed_frame_len_;

  // This is the next time that unclaimed push streams should be checked for
  // expirations.
  base::TimeTicks next_unclaimed_push_stream_sweep_time_;

  // Indicate if we have already scheduled a delayed task to check the ping
  // status.
  bool check_ping_status_pending_;

  // Current send window size.  Zero unless session flow control is turned on.
  int32_t session_send_window_size_;

  // Maximum receive window size.  Each time a WINDOW_UPDATE is sent, it
  // restores the receive window size to this value.  Zero unless session flow
  // control is turned on.
  int32_t session_max_recv_window_size_;

  // Sum of |session_unacked_recv_window_bytes_| and current receive window
  // size.  Zero unless session flow control is turned on.
  // TODO(bnc): Rename or change semantics so that |window_size_| is actual
  // window size.
  int32_t session_recv_window_size_;

  // When bytes are consumed, SpdyIOBuffer destructor calls back to SpdySession,
  // and this member keeps count of them until the corresponding WINDOW_UPDATEs
  // are sent.  Zero unless session flow control is turned on.
  int32_t session_unacked_recv_window_bytes_;

  // Initial send window size for this session's streams. Can be
  // changed by an arriving SETTINGS frame. Newly created streams use
  // this value for the initial send window size.
  int32_t stream_initial_send_window_size_;

  // The maximum HPACK dynamic table size the server is allowed to set.
  uint32_t max_header_table_size_;

  // Initial receive window size for this session's streams. There are
  // plans to add a command line switch that would cause a SETTINGS
  // frame with window size announcement to be sent on startup. Newly
  // created streams will use this value for the initial receive
  // window size.
  int32_t stream_max_recv_window_size_;

  // A queue of stream IDs that have been send-stalled at some point
  // in the past.
  std::deque<SpdyStreamId> stream_send_unstall_queue_[NUM_PRIORITIES];

  NetLogWithSource net_log_;

  // Outside of tests, these should always be true.
  bool enable_sending_initial_data_;
  bool enable_ping_based_connection_checking_;

  // |connection_at_risk_of_loss_time_| is an optimization to avoid sending
  // wasteful preface pings (when we just got some data).
  //
  // If it is zero (the most conservative figure), then we always send the
  // preface ping (when none are in flight).
  //
  // It is common for TCP/IP sessions to time out in about 3-5 minutes.
  // Certainly if it has been more than 3 minutes, we do want to send a preface
  // ping.
  //
  // We don't think any connection will time out in under about 10 seconds. So
  // this might as well be set to something conservative like 10 seconds. Later,
  // we could adjust it to send fewer pings perhaps.
  base::TimeDelta connection_at_risk_of_loss_time_;

  // The amount of time that we are willing to tolerate with no activity (of any
  // form), while there is a ping in flight, before we declare the connection to
  // be hung. TODO(rtenneti): When hung, instead of resetting connection, race
  // to build a new connection, and see if that completes before we (finally)
  // get a PING response (http://crbug.com/127812).
  base::TimeDelta hung_interval_;

  // The |proxy_delegate_| verifies that a given proxy is a trusted SPDY proxy,
  // which is allowed to push resources from origins that are different from
  // those of their associated streams. May be nullptr.
  ProxyDelegate* proxy_delegate_;

  TimeFunc time_func_;

  Http2PriorityDependencies priority_dependency_state_;

  // Used for posting asynchronous IO tasks.  We use this even though
  // SpdySession is refcounted because we don't need to keep the SpdySession
  // alive if the last reference is within a RunnableMethod.  Just revoke the
  // method.
  base::WeakPtrFactory<SpdySession> weak_factory_;
};

}  // namespace net

#endif  // NET_SPDY_SPDY_SESSION_H_
