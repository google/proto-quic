// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_URL_REQUEST_URL_REQUEST_HTTP_JOB_H_
#define NET_URL_REQUEST_URL_REQUEST_HTTP_JOB_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/time/time.h"
#include "net/base/auth.h"
#include "net/base/completion_callback.h"
#include "net/base/net_error_details.h"
#include "net/base/net_export.h"
#include "net/base/sdch_manager.h"
#include "net/cookies/cookie_store.h"
#include "net/filter/filter.h"
#include "net/http/http_request_info.h"
#include "net/socket/connection_attempts.h"
#include "net/url_request/url_request_job.h"
#include "net/url_request/url_request_throttler_entry_interface.h"

namespace net {

class HttpRequestHeaders;
class HttpResponseHeaders;
class HttpResponseInfo;
class HttpTransaction;
class HttpUserAgentSettings;
class ProxyInfo;
class SSLPrivateKey;
class UploadDataStream;
class URLRequestContext;

// A URLRequestJob subclass that is built on top of HttpTransaction. It
// provides an implementation for both HTTP and HTTPS.
class NET_EXPORT_PRIVATE URLRequestHttpJob : public URLRequestJob {
 public:
  static URLRequestJob* Factory(URLRequest* request,
                                NetworkDelegate* network_delegate,
                                const std::string& scheme);

 protected:
  URLRequestHttpJob(URLRequest* request,
                    NetworkDelegate* network_delegate,
                    const HttpUserAgentSettings* http_user_agent_settings);

  ~URLRequestHttpJob() override;

  // Overridden from URLRequestJob:
  void SetPriority(RequestPriority priority) override;
  void Start() override;
  void Kill() override;
  void GetConnectionAttempts(ConnectionAttempts* out) const override;

  RequestPriority priority() const {
    return priority_;
  }

 private:
  enum CompletionCause {
    ABORTED,
    FINISHED
  };

  typedef base::RefCountedData<bool> SharedBoolean;

  class HttpFilterContext;

  // Shadows URLRequestJob's version of this method so we can grab cookies.
  void NotifyHeadersComplete();

  void DestroyTransaction();

  void AddExtraHeaders();
  void AddCookieHeaderAndStart();
  void SaveCookiesAndNotifyHeadersComplete(int result);
  void FetchResponseCookies(std::vector<std::string>* cookies);

  // Processes a Backoff header, if one exists.
  void ProcessBackoffHeader();

  // Processes the Strict-Transport-Security header, if one exists.
  void ProcessStrictTransportSecurityHeader();

  // Processes the Public-Key-Pins header, if one exists.
  void ProcessPublicKeyPinsHeader();

  // Processes the Expect-CT header, if one exists. This header
  // indicates that the server wants the user agent to send a report
  // when a connection violates the Expect CT policy.
  void ProcessExpectCTHeader();

  // |result| should be OK, or the request is canceled.
  void OnHeadersReceivedCallback(int result);
  void OnStartCompleted(int result);
  void OnReadCompleted(int result);
  void NotifyBeforeStartTransactionCallback(int result);
  void NotifyBeforeSendHeadersCallback(const ProxyInfo& proxy_info,
                                       HttpRequestHeaders* request_headers);

  void RestartTransactionWithAuth(const AuthCredentials& credentials);

  // Overridden from URLRequestJob:
  void SetUpload(UploadDataStream* upload) override;
  void SetExtraRequestHeaders(const HttpRequestHeaders& headers) override;
  LoadState GetLoadState() const override;
  bool GetMimeType(std::string* mime_type) const override;
  bool GetCharset(std::string* charset) override;
  void GetResponseInfo(HttpResponseInfo* info) override;
  void GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const override;
  bool GetRemoteEndpoint(IPEndPoint* endpoint) const override;
  int GetResponseCode() const override;
  void PopulateNetErrorDetails(NetErrorDetails* details) const override;
  std::unique_ptr<Filter> SetupFilter() const override;
  bool CopyFragmentOnRedirect(const GURL& location) const override;
  bool IsSafeRedirect(const GURL& location) override;
  bool NeedsAuth() override;
  void GetAuthChallengeInfo(scoped_refptr<AuthChallengeInfo>*) override;
  void SetAuth(const AuthCredentials& credentials) override;
  void CancelAuth() override;
  void ContinueWithCertificate(X509Certificate* client_cert,
                               SSLPrivateKey* client_private_key) override;
  void ContinueDespiteLastError() override;
  int ReadRawData(IOBuffer* buf, int buf_size) override;
  void StopCaching() override;
  bool GetFullRequestHeaders(HttpRequestHeaders* headers) const override;
  int64_t GetTotalReceivedBytes() const override;
  int64_t GetTotalSentBytes() const override;
  void DoneReading() override;
  void DoneReadingRedirectResponse() override;

  HostPortPair GetSocketAddress() const override;
  void NotifyURLRequestDestroyed() override;

  void RecordTimer();
  void ResetTimer();

  void UpdatePacketReadTimes() override;
  void RecordPacketStats(FilterContext::StatisticSelector statistic) const;

  // Starts the transaction if extensions using the webrequest API do not
  // object.
  void StartTransaction();
  // If |result| is OK, calls StartTransactionInternal. Otherwise notifies
  // cancellation.
  void MaybeStartTransactionInternal(int result);
  void StartTransactionInternal();

  void RecordPerfHistograms(CompletionCause reason);
  void DoneWithRequest(CompletionCause reason);

  // Callback functions for Cookie Monster
  void SetCookieHeaderAndStart(const CookieList& cookie_list);
  void DoStartTransaction();

  // Some servers send the body compressed, but specify the content length as
  // the uncompressed size. If this is the case, we return true in order
  // to request to work around this non-adherence to the HTTP standard.
  // |rv| is the standard return value of a read function indicating the number
  // of bytes read or, if negative, an error code.
  bool ShouldFixMismatchedContentLength(int rv) const;

  // Returns the effective response headers, considering that they may be
  // overridden by |override_response_headers_|.
  HttpResponseHeaders* GetResponseHeaders() const;

  RequestPriority priority_;

  HttpRequestInfo request_info_;
  const HttpResponseInfo* response_info_;

  // Auth states for proxy and origin server.
  AuthState proxy_auth_state_;
  AuthState server_auth_state_;
  AuthCredentials auth_credentials_;

  CompletionCallback start_callback_;
  CompletionCallback notify_before_headers_sent_callback_;

  bool read_in_progress_;

  std::unique_ptr<HttpTransaction> transaction_;

  // This is used to supervise traffic and enforce exponential
  // back-off. May be NULL.
  scoped_refptr<URLRequestThrottlerEntryInterface> throttling_entry_;

  // A handle to the SDCH dictionaries that were advertised in this request.
  // May be null.
  std::unique_ptr<SdchManager::DictionarySet> dictionaries_advertised_;

  // For SDCH latency experiments, when we are able to do SDCH, we may enable
  // either an SDCH latency test xor a pass through test. The following bools
  // indicate what we decided on for this instance.
  bool sdch_test_activated_;  // Advertising a dictionary for sdch.
  bool sdch_test_control_;    // Not even accepting-content sdch.

  // For recording of stats, we need to remember if this is cached content.
  bool is_cached_content_;

  base::Time request_creation_time_;

  // Data used for statistics gathering. This data is only used for histograms
  // and is not required. It is only gathered if packet_timing_enabled_ == true.
  //
  // TODO(jar): improve the quality of the gathered info by gathering most times
  // at a lower point in the network stack, assuring we have actual packet
  // boundaries, rather than approximations. Also note that input byte count
  // as gathered here is post-SSL, and post-cache-fetch, and does not reflect
  // true packet arrival times in such cases.

  // Enable recording of packet arrival times for histogramming.
  bool packet_timing_enabled_;
  bool done_;  // True when we are done doing work.

  // The number of bytes that have been accounted for in packets (where some of
  // those packets may possibly have had their time of arrival recorded).
  int64_t bytes_observed_in_packets_;

  // The request time may not be available when we are being destroyed, so we
  // snapshot it early on.
  base::Time request_time_snapshot_;

  // Since we don't save all packet times in packet_times_, we save the
  // last time for use in histograms.
  base::Time final_packet_time_;

  // The start time for the job, ignoring re-starts.
  base::TimeTicks start_time_;

  // When the transaction finished reading the request headers.
  base::TimeTicks receive_headers_end_;

  std::unique_ptr<HttpFilterContext> filter_context_;

  CompletionCallback on_headers_received_callback_;

  // We allow the network delegate to modify a copy of the response headers.
  // This prevents modifications of headers that are shared with the underlying
  // layers of the network stack.
  scoped_refptr<HttpResponseHeaders> override_response_headers_;

  // The network delegate can mark a URL as safe for redirection.
  // The reference fragment of the original URL is not appended to the redirect
  // URL when the redirect URL is equal to |allowed_unsafe_redirect_url_|.
  GURL allowed_unsafe_redirect_url_;

  // Flag used to verify that |this| is not deleted while we are awaiting
  // a callback from the NetworkDelegate. Used as a fail-fast mechanism.
  // True if we are waiting a callback and
  // NetworkDelegate::NotifyURLRequestDestroyed has not been called, yet,
  // to inform the NetworkDelegate that it may not call back.
  bool awaiting_callback_;

  const HttpUserAgentSettings* http_user_agent_settings_;

  // Keeps track of total received bytes over the network from transactions used
  // by this job that have already been destroyed.
  int64_t total_received_bytes_from_previous_transactions_;
  // Keeps track of total sent bytes over the network from transactions used by
  // this job that have already been destroyed.
  int64_t total_sent_bytes_from_previous_transactions_;

  base::WeakPtrFactory<URLRequestHttpJob> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(URLRequestHttpJob);
};

}  // namespace net

#endif  // NET_URL_REQUEST_URL_REQUEST_HTTP_JOB_H_
