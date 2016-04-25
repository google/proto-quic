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

  size_t num_orphaned_jobs() const { return orphaned_job_set_.size(); }

 private:
  FRIEND_TEST_ALL_PREFIXES(HttpStreamFactoryImplRequestTest, SetPriority);
  FRIEND_TEST_ALL_PREFIXES(HttpStreamFactoryImplRequestTest, DelayMainJob);

  class NET_EXPORT_PRIVATE Request;
  class NET_EXPORT_PRIVATE Job;

  typedef std::set<Request*> RequestSet;
  typedef std::map<SpdySessionKey, RequestSet> SpdySessionRequestMap;

  HttpStreamRequest* RequestStreamInternal(
      const HttpRequestInfo& info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HttpStreamRequest::Delegate* delegate,
      WebSocketHandshakeStreamBase::CreateHelper* create_helper,
      HttpStreamRequest::StreamType stream_type,
      const BoundNetLog& net_log);

  AlternativeService GetAlternativeServiceFor(
      const HttpRequestInfo& request_info,
      HttpStreamRequest::Delegate* delegate,
      HttpStreamRequest::StreamType stream_type);

  // Detaches |job| from |request|.
  void OrphanJob(Job* job, const Request* request);

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

  // Invoked when an orphaned Job finishes.
  void OnOrphanedJobComplete(const Job* job);

  // Invoked when the Job finishes preconnecting sockets.
  void OnPreconnectsComplete(const Job* job);

  // Called when the Preconnect completes. Used for testing.
  virtual void OnPreconnectsCompleteInternal() {}

  // Returns true if QUIC is whitelisted for |host|.
  bool IsQuicWhitelistedForHost(const std::string& host);

  HttpNetworkSession* const session_;

  // All Requests are handed out to clients. By the time HttpStreamFactoryImpl
  // is destroyed, all Requests should be deleted (which should remove them from
  // |request_map_|. The Requests will delete the corresponding job.
  std::map<const Job*, Request*> request_map_;

  SpdySessionRequestMap spdy_session_request_map_;

  // These jobs correspond to jobs orphaned by Requests and now owned by
  // HttpStreamFactoryImpl. Since they are no longer tied to Requests, they will
  // not be canceled when Requests are canceled. Therefore, in
  // ~HttpStreamFactoryImpl, it is possible for some jobs to still exist in this
  // set. Leftover jobs will be deleted when the factory is destroyed.
  std::set<const Job*> orphaned_job_set_;

  // These jobs correspond to preconnect requests and have no associated Request
  // object. They're owned by HttpStreamFactoryImpl. Leftover jobs will be
  // deleted when the factory is destroyed.
  std::set<const Job*> preconnect_job_set_;

  const bool for_websockets_;
  DISALLOW_COPY_AND_ASSIGN(HttpStreamFactoryImpl);
};

}  // namespace net

#endif  // NET_HTTP_HTTP_STREAM_FACTORY_IMPL_H_
