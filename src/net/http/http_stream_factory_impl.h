// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_HTTP_STREAM_FACTORY_IMPL_H_
#define NET_HTTP_HTTP_STREAM_FACTORY_IMPL_H_

#include <stddef.h>

#include <map>
#include <set>
#include <vector>

#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "net/base/host_port_pair.h"
#include "net/http/http_stream_factory.h"
#include "net/log/net_log.h"
#include "net/proxy/proxy_server.h"
#include "net/socket/ssl_client_socket.h"
#include "net/spdy/spdy_session_key.h"

namespace net {

class HttpNetworkSession;
class SpdySession;

class NET_EXPORT_PRIVATE HttpStreamFactoryImpl : public HttpStreamFactory {
 public:
  class NET_EXPORT_PRIVATE Job;
  class NET_EXPORT_PRIVATE JobController;
  class NET_EXPORT_PRIVATE JobFactory;
  class NET_EXPORT_PRIVATE Request;
  // RequestStream may only be called if |for_websockets| is false.
  // RequestWebSocketHandshakeStream may only be called if |for_websockets|
  // is true.
  HttpStreamFactoryImpl(HttpNetworkSession* session, bool for_websockets);
  ~HttpStreamFactoryImpl() override;

  // HttpStreamFactory interface
  HttpStreamRequest* RequestStream(const HttpRequestInfo& info,
                                   RequestPriority priority,
                                   const SSLConfig& server_ssl_config,
                                   const SSLConfig& proxy_ssl_config,
                                   HttpStreamRequest::Delegate* delegate,
                                   const BoundNetLog& net_log) override;

  HttpStreamRequest* RequestWebSocketHandshakeStream(
      const HttpRequestInfo& info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HttpStreamRequest::Delegate* delegate,
      WebSocketHandshakeStreamBase::CreateHelper* create_helper,
      const BoundNetLog& net_log) override;

  HttpStreamRequest* RequestBidirectionalStreamImpl(
      const HttpRequestInfo& info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HttpStreamRequest::Delegate* delegate,
      const BoundNetLog& net_log) override;

  void PreconnectStreams(int num_streams, const HttpRequestInfo& info) override;
  const HostMappingRules* GetHostMappingRules() const override;

  enum JobType {
    MAIN,
    ALTERNATIVE,
    PRECONNECT,
  };

 private:
  FRIEND_TEST_ALL_PREFIXES(HttpStreamFactoryImplRequestTest, SetPriority);
  FRIEND_TEST_ALL_PREFIXES(HttpStreamFactoryImplRequestTest, DelayMainJob);

  friend class HttpStreamFactoryImplPeer;

  typedef std::set<Request*> RequestSet;
  typedef std::map<SpdySessionKey, RequestSet> SpdySessionRequestMap;
  typedef std::set<std::unique_ptr<JobController>> JobControllerSet;

  // Values must not be changed or reused.  Keep in sync with identically named
  // enum in histograms.xml.
  enum AlternativeServiceType {
    NO_ALTERNATIVE_SERVICE = 0,
    QUIC_SAME_DESTINATION = 1,
    QUIC_DIFFERENT_DESTINATION = 2,
    NOT_QUIC_SAME_DESTINATION = 3,
    NOT_QUIC_DIFFERENT_DESTINATION = 4,
    MAX_ALTERNATIVE_SERVICE_TYPE
  };

  HttpStreamRequest* RequestStreamInternal(
      const HttpRequestInfo& info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HttpStreamRequest::Delegate* delegate,
      WebSocketHandshakeStreamBase::CreateHelper* create_helper,
      HttpStreamRequest::StreamType stream_type,
      const BoundNetLog& net_log);

  // Called when a SpdySession is ready. It will find appropriate Requests and
  // fulfill them. |direct| indicates whether or not |spdy_session| uses a
  // proxy.
  void OnNewSpdySessionReady(const base::WeakPtr<SpdySession>& spdy_session,
                             bool direct,
                             const SSLConfig& used_ssl_config,
                             const ProxyInfo& used_proxy_info,
                             bool was_npn_negotiated,
                             NextProto protocol_negotiated,
                             bool using_spdy,
                             const BoundNetLog& net_log);

  // Called when the Job detects that the endpoint indicated by the
  // Alternate-Protocol does not work. Lets the factory update
  // HttpAlternateProtocols with the failure and resets the SPDY session key.
  void OnBrokenAlternateProtocol(const Job*, const HostPortPair& origin);

  // Called when the Preconnect completes. Used for testing.
  virtual void OnPreconnectsCompleteInternal() {}

  // Called when the JobController finishes service. Delete the JobController
  // from |job_controller_set_|.
  void OnJobControllerComplete(JobController* controller);

  HttpNetworkSession* const session_;

  // All Requests are handed out to clients. By the time HttpStreamFactoryImpl
  // is destroyed, all Requests should be deleted (which should remove them from
  // |request_map_|. The Requests will delete the corresponding job.
  std::map<const Job*, Request*> request_map_;

  // All Requests/Preconnects are assigned with a JobController to manage
  // serving Job(s). JobController might outlive Request when Request
  // is served while there's some working Job left. JobController will be
  // deleted from |job_controller_set_| when it determines the completion of
  // its work.
  JobControllerSet job_controller_set_;

  // Factory used by job controllers for creating jobs.
  std::unique_ptr<JobFactory> job_factory_;

  SpdySessionRequestMap spdy_session_request_map_;

  const bool for_websockets_;
  DISALLOW_COPY_AND_ASSIGN(HttpStreamFactoryImpl);
};

}  // namespace net

#endif  // NET_HTTP_HTTP_STREAM_FACTORY_IMPL_H_
