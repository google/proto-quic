// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_URL_REQUEST_URL_REQUEST_H_
#define NET_URL_REQUEST_URL_REQUEST_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "base/debug/leak_tracker.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/strings/string16.h"
#include "base/supports_user_data.h"
#include "base/threading/non_thread_safe.h"
#include "base/time/time.h"
#include "net/base/auth.h"
#include "net/base/completion_callback.h"
#include "net/base/load_states.h"
#include "net/base/load_timing_info.h"
#include "net/base/net_error_details.h"
#include "net/base/net_export.h"
#include "net/base/network_delegate.h"
#include "net/base/request_priority.h"
#include "net/base/upload_progress.h"
#include "net/cookies/canonical_cookie.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_info.h"
#include "net/log/net_log.h"
#include "net/socket/connection_attempts.h"
#include "net/url_request/url_request_status.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace base {
class Value;

namespace debug {
class StackTrace;
}  // namespace debug
}  // namespace base

namespace net {

class CookieOptions;
class HostPortPair;
class IOBuffer;
struct LoadTimingInfo;
struct RedirectInfo;
class SSLCertRequestInfo;
class SSLInfo;
class SSLPrivateKey;
class UploadDataStream;
class URLRequestContext;
class URLRequestJob;
class X509Certificate;

//-----------------------------------------------------------------------------
// A class  representing the asynchronous load of a data stream from an URL.
//
// The lifetime of an instance of this class is completely controlled by the
// consumer, and the instance is not required to live on the heap or be
// allocated in any special way.  It is also valid to delete an URLRequest
// object during the handling of a callback to its delegate.  Of course, once
// the URLRequest is deleted, no further callbacks to its delegate will occur.
//
// NOTE: All usage of all instances of this class should be on the same thread.
//
class NET_EXPORT URLRequest : NON_EXPORTED_BASE(public base::NonThreadSafe),
                              public base::SupportsUserData {
 public:
  // Callback function implemented by protocol handlers to create new jobs.
  // The factory may return NULL to indicate an error, which will cause other
  // factories to be queried.  If no factory handles the request, then the
  // default job will be used.
  typedef URLRequestJob* (ProtocolFactory)(URLRequest* request,
                                           NetworkDelegate* network_delegate,
                                           const std::string& scheme);

  // A ReferrerPolicy for the request can be set with
  // set_referrer_policy() and controls the contents of the Referer
  // header when URLRequest follows server redirects.
  enum ReferrerPolicy {
    // Clear the referrer header if the protocol changes from HTTPS to
    // HTTP. This is the default behavior of URLRequest.
    CLEAR_REFERRER_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
    // A slight variant on
    // CLEAR_REFERRER_ON_TRANSITION_FROM_SECURE_TO_INSECURE: If the
    // request downgrades from HTTPS to HTTP, the referrer will be
    // cleared. If the request transitions cross-origin (but does not
    // downgrade), the referrer's granularity will be reduced (currently
    // stripped down to an origin rather than a full URL). Same-origin
    // requests will send the full referrer.
    REDUCE_REFERRER_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN,
    // Strip the referrer down to an origin upon cross-origin navigation.
    ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN,
    // Never change the referrer.
    NEVER_CLEAR_REFERRER,
    // Strip the referrer down to the origin regardless of the redirect
    // location.
    ORIGIN,
    // Always clear the referrer regardless of the redirect location.
    NO_REFERRER,
    MAX_REFERRER_POLICY
  };

  // First-party URL redirect policy: During server redirects, the first-party
  // URL for cookies normally doesn't change. However, if the request is a
  // top-level first-party request, the first-party URL should be updated to the
  // URL on every redirect.
  enum FirstPartyURLPolicy {
    NEVER_CHANGE_FIRST_PARTY_URL,
    UPDATE_FIRST_PARTY_URL_ON_REDIRECT,
  };

  // The delegate's methods are called from the message loop of the thread
  // on which the request's Start() method is called. See above for the
  // ordering of callbacks.
  //
  // The callbacks will be called in the following order:
  //   Start()
  //    - OnCertificateRequested* (zero or more calls, if the SSL server and/or
  //      SSL proxy requests a client certificate for authentication)
  //    - OnSSLCertificateError* (zero or one call, if the SSL server's
  //      certificate has an error)
  //    - OnReceivedRedirect* (zero or more calls, for the number of redirects)
  //    - OnAuthRequired* (zero or more calls, for the number of
  //      authentication failures)
  //    - OnResponseStarted
  //   Read() initiated by delegate
  //    - OnReadCompleted* (zero or more calls until all data is read)
  //
  // Read() must be called at least once. Read() returns true when it completed
  // immediately, and false if an IO is pending or if there is an error.  When
  // Read() returns false, the caller can check the Request's status() to see
  // if an error occurred, or if the IO is just pending.  When Read() returns
  // true with zero bytes read, it indicates the end of the response.
  //
  class NET_EXPORT Delegate {
   public:
    // Called upon receiving a redirect.  The delegate may call the request's
    // Cancel method to prevent the redirect from being followed.  Since there
    // may be multiple chained redirects, there may also be more than one
    // redirect call.
    //
    // When this function is called, the request will still contain the
    // original URL, the destination of the redirect is provided in
    // |redirect_info.new_url|.  If the delegate does not cancel the request
    // and |*defer_redirect| is false, then the redirect will be followed, and
    // the request's URL will be changed to the new URL.  Otherwise if the
    // delegate does not cancel the request and |*defer_redirect| is true, then
    // the redirect will be followed once FollowDeferredRedirect is called
    // on the URLRequest.
    //
    // The caller must set |*defer_redirect| to false, so that delegates do not
    // need to set it if they are happy with the default behavior of not
    // deferring redirect.
    virtual void OnReceivedRedirect(URLRequest* request,
                                    const RedirectInfo& redirect_info,
                                    bool* defer_redirect);

    // Called when we receive an authentication failure.  The delegate should
    // call request->SetAuth() with the user's credentials once it obtains them,
    // or request->CancelAuth() to cancel the login and display the error page.
    // When it does so, the request will be reissued, restarting the sequence
    // of On* callbacks.
    virtual void OnAuthRequired(URLRequest* request,
                                AuthChallengeInfo* auth_info);

    // Called when we receive an SSL CertificateRequest message for client
    // authentication.  The delegate should call
    // request->ContinueWithCertificate() with the client certificate the user
    // selected and its private key, or request->ContinueWithCertificate(NULL,
    // NULL)
    // to continue the SSL handshake without a client certificate.
    virtual void OnCertificateRequested(
        URLRequest* request,
        SSLCertRequestInfo* cert_request_info);

    // Called when using SSL and the server responds with a certificate with
    // an error, for example, whose common name does not match the common name
    // we were expecting for that host.  The delegate should either do the
    // safe thing and Cancel() the request or decide to proceed by calling
    // ContinueDespiteLastError().  cert_error is a ERR_* error code
    // indicating what's wrong with the certificate.
    // If |fatal| is true then the host in question demands a higher level
    // of security (due e.g. to HTTP Strict Transport Security, user
    // preference, or built-in policy). In this case, errors must not be
    // bypassable by the user.
    virtual void OnSSLCertificateError(URLRequest* request,
                                       const SSLInfo& ssl_info,
                                       bool fatal);

    // After calling Start(), the delegate will receive an OnResponseStarted
    // callback when the request has completed. |net_error| will be set to OK
    // or an actual net error.  On success, all redirects have been
    // followed and the final response is beginning to arrive.  At this point,
    // meta data about the response is available, including for example HTTP
    // response headers if this is a request for a HTTP resource.
    virtual void OnResponseStarted(URLRequest* request, int net_error);
    // Deprecated.
    // TODO(maksims): Remove this;
    virtual void OnResponseStarted(URLRequest* request);

    // Called when the a Read of the response body is completed after an
    // IO_PENDING status from a Read() call.
    // The data read is filled into the buffer which the caller passed
    // to Read() previously.
    //
    // If an error occurred, |bytes_read| will be set to the error.
    virtual void OnReadCompleted(URLRequest* request, int bytes_read) = 0;

   protected:
    virtual ~Delegate() {}
  };

  // If destroyed after Start() has been called but while IO is pending,
  // then the request will be effectively canceled and the delegate
  // will not have any more of its methods called.
  ~URLRequest() override;

  // Changes the default cookie policy from allowing all cookies to blocking all
  // cookies. Embedders that want to implement a more flexible policy should
  // change the default to blocking all cookies, and provide a NetworkDelegate
  // with the URLRequestContext that maintains the CookieStore.
  // The cookie policy default has to be set before the first URLRequest is
  // started. Once it was set to block all cookies, it cannot be changed back.
  static void SetDefaultCookiePolicyToBlock();

  // Returns true if the scheme can be handled by URLRequest. False otherwise.
  static bool IsHandledProtocol(const std::string& scheme);

  // Returns true if the url can be handled by URLRequest. False otherwise.
  // The function returns true for invalid urls because URLRequest knows how
  // to handle those.
  // NOTE: This will also return true for URLs that are handled by
  // ProtocolFactories that only work for requests that are scoped to a
  // Profile.
  static bool IsHandledURL(const GURL& url);

  // The original url is the url used to initialize the request, and it may
  // differ from the url if the request was redirected.
  const GURL& original_url() const { return url_chain_.front(); }
  // The chain of urls traversed by this request.  If the request had no
  // redirects, this vector will contain one element.
  const std::vector<GURL>& url_chain() const { return url_chain_; }
  const GURL& url() const { return url_chain_.back(); }

  // The URL that should be consulted for the third-party cookie blocking
  // policy, as defined in Section 2.1.1 and 2.1.2 of
  // https://tools.ietf.org/html/draft-west-first-party-cookies.
  //
  // WARNING: This URL must only be used for the third-party cookie blocking
  //          policy. It MUST NEVER be used for any kind of SECURITY check.
  //
  //          For example, if a top-level navigation is redirected, the
  //          first-party for cookies will be the URL of the first URL in the
  //          redirect chain throughout the whole redirect. If it was used for
  //          a security check, an attacker might try to get around this check
  //          by starting from some page that redirects to the
  //          host-to-be-attacked.
  //
  // TODO(mkwst): Convert this to a 'url::Origin'. Several callsites are using
  // this value as a proxy for the "top-level frame URL", which is simply
  // incorrect and fragile. We don't need the full URL for any //net checks,
  // so we should drop the pieces we don't need. https://crbug.com/577565
  const GURL& first_party_for_cookies() const {
    return first_party_for_cookies_;
  }
  // This method may only be called before Start().
  void set_first_party_for_cookies(const GURL& first_party_for_cookies);

  // The first-party URL policy to apply when updating the first party URL
  // during redirects. The first-party URL policy may only be changed before
  // Start() is called.
  FirstPartyURLPolicy first_party_url_policy() const {
    return first_party_url_policy_;
  }
  void set_first_party_url_policy(FirstPartyURLPolicy first_party_url_policy);

  // The origin of the context which initiated the request. This is distinct
  // from the "first party for cookies" discussed above in a number of ways:
  //
  // 1. The request's initiator does not change during a redirect. If a form
  //    submission from `https://example.com/` redirects through a number of
  //    sites before landing on `https://not-example.com/`, the initiator for
  //    each of those requests will be `https://example.com/`.
  //
  // 2. The request's initiator is the origin of the frame or worker which made
  //    the request, even for top-level navigations. That is, if
  //    `https://example.com/`'s form submission is made in the top-level frame,
  //    the first party for cookies would be the target URL's origin. The
  //    initiator remains `https://example.com/`.
  //
  // This value is used to perform the cross-origin check specified in Section
  // 4.3 of https://tools.ietf.org/html/draft-west-first-party-cookies.
  const url::Origin& initiator() const { return initiator_; }
  // This method may only be called before Start().
  void set_initiator(const url::Origin& initiator);

  // The request method, as an uppercase string.  "GET" is the default value.
  // The request method may only be changed before Start() is called and
  // should only be assigned an uppercase value.
  const std::string& method() const { return method_; }
  void set_method(const std::string& method);

  // The referrer URL for the request.  This header may actually be suppressed
  // from the underlying network request for security reasons (e.g., a HTTPS
  // URL will not be sent as the referrer for a HTTP request).  The referrer
  // may only be changed before Start() is called.
  const std::string& referrer() const { return referrer_; }
  // Referrer is sanitized to remove URL fragment, user name and password.
  void SetReferrer(const std::string& referrer);

  // The referrer policy to apply when updating the referrer during redirects.
  // The referrer policy may only be changed before Start() is called.
  ReferrerPolicy referrer_policy() const { return referrer_policy_; }
  void set_referrer_policy(ReferrerPolicy referrer_policy);

  // If this request should include a referred Token Binding, this returns the
  // hostname of the referrer that indicated this request should include a
  // referred Token Binding. Otherwise, this returns the empty string.
  const std::string& token_binding_referrer() const {
    return token_binding_referrer_;
  }

  // Sets the delegate of the request.  This is only to allow creating a request
  // before creating its delegate.  |delegate| must be non-NULL and the request
  // must not yet have a Delegate set.
  void set_delegate(Delegate* delegate);

  // Sets the upload data.
  void set_upload(std::unique_ptr<UploadDataStream> upload);

  // Gets the upload data.
  const UploadDataStream* get_upload() const;

  // Returns true if the request has a non-empty message body to upload.
  bool has_upload() const;

  // Set or remove a extra request header.  These methods may only be called
  // before Start() is called, or between receiving a redirect and trying to
  // follow it.
  void SetExtraRequestHeaderByName(const std::string& name,
                                   const std::string& value, bool overwrite);
  void RemoveRequestHeaderByName(const std::string& name);

  // Sets all extra request headers.  Any extra request headers set by other
  // methods are overwritten by this method.  This method may only be called
  // before Start() is called.  It is an error to call it later.
  void SetExtraRequestHeaders(const HttpRequestHeaders& headers);

  const HttpRequestHeaders& extra_request_headers() const {
    return extra_request_headers_;
  }

  // Gets the full request headers sent to the server.
  //
  // Return true and overwrites headers if it can get the request headers;
  // otherwise, returns false and does not modify headers.  (Always returns
  // false for request types that don't have headers, like file requests.)
  //
  // This is guaranteed to succeed if:
  //
  // 1. A redirect or auth callback is currently running.  Once it ends, the
  //    headers may become unavailable as a new request with the new address
  //    or credentials is made.
  //
  // 2. The OnResponseStarted callback is currently running or has run.
  bool GetFullRequestHeaders(HttpRequestHeaders* headers) const;

  // Gets the total amount of data received from network after SSL decoding and
  // proxy handling. Pertains only to the last URLRequestJob issued by this
  // URLRequest, i.e. reset on redirects, but not reset when multiple roundtrips
  // are used for range requests or auth.
  int64_t GetTotalReceivedBytes() const;

  // Gets the total amount of data sent over the network before SSL encoding and
  // proxy handling. Pertains only to the last URLRequestJob issued by this
  // URLRequest, i.e. reset on redirects, but not reset when multiple roundtrips
  // are used for range requests or auth.
  int64_t GetTotalSentBytes() const;

  // The size of the response body before removing any content encodings.
  // Does not include redirects or sub-requests issued at lower levels (range
  // requests or auth). Only includes bytes which have been read so far,
  // including bytes from the cache.
  int64_t GetRawBodyBytes() const;

  // Returns the current load state for the request. The returned value's
  // |param| field is an optional parameter describing details related to the
  // load state. Not all load states have a parameter.
  LoadStateWithParam GetLoadState() const;

  // Returns a partial representation of the request's state as a value, for
  // debugging.
  std::unique_ptr<base::Value> GetStateAsValue() const;

  // Logs information about the what external object currently blocking the
  // request.  LogUnblocked must be called before resuming the request.  This
  // can be called multiple times in a row either with or without calling
  // LogUnblocked between calls.  |blocked_by| must not be NULL or have length
  // 0.
  void LogBlockedBy(const char* blocked_by);

  // Just like LogBlockedBy, but also makes GetLoadState return source as the
  // |param| in the value returned by GetLoadState.  Calling LogUnblocked or
  // LogBlockedBy will clear the load param.  |blocked_by| must not be NULL or
  // have length 0.
  void LogAndReportBlockedBy(const char* blocked_by);

  // Logs that the request is no longer blocked by the last caller to
  // LogBlockedBy.
  void LogUnblocked();

  // Returns the current upload progress in bytes. When the upload data is
  // chunked, size is set to zero, but position will not be.
  UploadProgress GetUploadProgress() const;

  // Get response header(s) by name.  This method may only be called
  // once the delegate's OnResponseStarted method has been called.  Headers
  // that appear more than once in the response are coalesced, with values
  // separated by commas (per RFC 2616). This will not work with cookies since
  // comma can be used in cookie values.
  void GetResponseHeaderByName(const std::string& name,
                               std::string* value) const;

  // The time when |this| was constructed.
  base::TimeTicks creation_time() const { return creation_time_; }

  // The time at which the returned response was requested.  For cached
  // responses, this is the last time the cache entry was validated.
  const base::Time& request_time() const {
    return response_info_.request_time;
  }

  // The time at which the returned response was generated.  For cached
  // responses, this is the last time the cache entry was validated.
  const base::Time& response_time() const {
    return response_info_.response_time;
  }

  // Indicate if this response was fetched from disk cache.
  bool was_cached() const { return response_info_.was_cached; }

  // Returns true if the URLRequest was delivered through a proxy.
  bool was_fetched_via_proxy() const {
    return response_info_.was_fetched_via_proxy;
  }

  // Returns true if the URLRequest was delivered over SPDY.
  bool was_fetched_via_spdy() const {
    return response_info_.was_fetched_via_spdy;
  }

  // Returns the host and port that the content was fetched from.  See
  // http_response_info.h for caveats relating to cached content.
  HostPortPair GetSocketAddress() const;

  // Get all response headers, as a HttpResponseHeaders object.  See comments
  // in HttpResponseHeaders class as to the format of the data.
  HttpResponseHeaders* response_headers() const;

  // Get the SSL connection info.
  const SSLInfo& ssl_info() const {
    return response_info_.ssl_info;
  }

  // Gets timing information related to the request.  Events that have not yet
  // occurred are left uninitialized.  After a second request starts, due to
  // a redirect or authentication, values will be reset.
  //
  // LoadTimingInfo only contains ConnectTiming information and socket IDs for
  // non-cached HTTP responses.
  void GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const;

  // Gets the networkd error details of the most recent origin that the network
  // stack makes the request to.
  void PopulateNetErrorDetails(NetErrorDetails* details) const;

  // Gets the remote endpoint of the most recent socket that the network stack
  // used to make this request.
  //
  // Note that GetSocketAddress returns the |socket_address| field from
  // HttpResponseInfo, which is only populated once the response headers are
  // received, and can return cached values for cache revalidation requests.
  // GetRemoteEndpoint will only return addresses from the current request.
  //
  // Returns true and fills in |endpoint| if the endpoint is available; returns
  // false and leaves |endpoint| unchanged if it is unavailable.
  bool GetRemoteEndpoint(IPEndPoint* endpoint) const;

  // Get the mime type.  This method may only be called once the delegate's
  // OnResponseStarted method has been called.
  void GetMimeType(std::string* mime_type) const;

  // Get the charset (character encoding).  This method may only be called once
  // the delegate's OnResponseStarted method has been called.
  void GetCharset(std::string* charset) const;

  // Returns the HTTP response code (e.g., 200, 404, and so on).  This method
  // may only be called once the delegate's OnResponseStarted method has been
  // called.  For non-HTTP requests, this method returns -1.
  int GetResponseCode() const;

  // Get the HTTP response info in its entirety.
  const HttpResponseInfo& response_info() const { return response_info_; }

  // Access the LOAD_* flags modifying this request (see load_flags.h).
  int load_flags() const { return load_flags_; }

  // The new flags may change the IGNORE_LIMITS flag only when called
  // before Start() is called, it must only set the flag, and if set,
  // the priority of this request must already be MAXIMUM_PRIORITY.
  void SetLoadFlags(int flags);

  // Returns true if the request is "pending" (i.e., if Start() has been called,
  // and the response has not yet been called).
  bool is_pending() const { return is_pending_; }

  // Returns true if the request is in the process of redirecting to a new
  // URL but has not yet initiated the new request.
  bool is_redirecting() const { return is_redirecting_; }

  // Returns a globally unique identifier for this request.
  uint64_t identifier() const { return identifier_; }

  // This method is called to start the request.  The delegate will receive
  // a OnResponseStarted callback when the request is started.  The request
  // must have a delegate set before this method is called.
  void Start();

  // This method may be called at any time after Start() has been called to
  // cancel the request.  This method may be called many times, and it has
  // no effect once the response has completed.  It is guaranteed that no
  // methods of the delegate will be called after the request has been
  // cancelled, except that this may call the delegate's OnReadCompleted()
  // during the call to Cancel itself. Returns |ERR_ABORTED| or other net error
  // if there was one.
  int Cancel();

  // Cancels the request and sets the error to |error|, unless the request
  // already failed with another error code (see net_error_list.h). Returns
  // final network error code.
  int CancelWithError(int error);

  // Cancels the request and sets the error to |error| (see net_error_list.h
  // for values) and attaches |ssl_info| as the SSLInfo for that request.  This
  // is useful to attach a certificate and certificate error to a canceled
  // request.
  void CancelWithSSLError(int error, const SSLInfo& ssl_info);

  //  Read initiates an asynchronous read from the response, and must only be
  // called after the OnResponseStarted callback is received with a net::OK. If
  // data is available, length and the data will be returned immediately. If the
  // request has failed, an error code will be returned. If data is not yet
  // available, Read returns net::ERR_IO_PENDING, and the Delegate's
  // OnReadComplete method will be called asynchronously with the result of the
  // read, unless the URLRequest is canceled.
  //
  // The |buf| parameter is a buffer to receive the data. If the operation
  // completes asynchronously, the implementation will reference the buffer
  // until OnReadComplete is called. The buffer must be at least |max_bytes| in
  // length.
  //
  // The |max_bytes| parameter is the maximum number of bytes to read.
  int Read(IOBuffer* buf, int max_bytes);
  // Deprecated.
  // TODO(maksims): Remove this.
  bool Read(IOBuffer* buf, int max_bytes, int* bytes_read);

  // If this request is being cached by the HTTP cache, stop subsequent caching.
  // Note that this method has no effect on other (simultaneous or not) requests
  // for the same resource. The typical example is a request that results in
  // the data being stored to disk (downloaded instead of rendered) so we don't
  // want to store it twice.
  void StopCaching();

  // This method may be called to follow a redirect that was deferred in
  // response to an OnReceivedRedirect call.
  void FollowDeferredRedirect();

  // One of the following two methods should be called in response to an
  // OnAuthRequired() callback (and only then).
  // SetAuth will reissue the request with the given credentials.
  // CancelAuth will give up and display the error page.
  void SetAuth(const AuthCredentials& credentials);
  void CancelAuth();

  // This method can be called after the user selects a client certificate to
  // instruct this URLRequest to continue with the request with the
  // certificate.  Pass NULL if the user doesn't have a client certificate.
  void ContinueWithCertificate(X509Certificate* client_cert,
                               SSLPrivateKey* client_private_key);

  // This method can be called after some error notifications to instruct this
  // URLRequest to ignore the current error and continue with the request.  To
  // cancel the request instead, call Cancel().
  void ContinueDespiteLastError();

  // Used to specify the context (cookie store, cache) for this request.
  const URLRequestContext* context() const;

  const NetLogWithSource& net_log() const { return net_log_; }

  // Returns the expected content size if available
  int64_t GetExpectedContentSize() const;

  // Returns the priority level for this request.
  RequestPriority priority() const { return priority_; }

  // Sets the priority level for this request and any related
  // jobs. Must not change the priority to anything other than
  // MAXIMUM_PRIORITY if the IGNORE_LIMITS load flag is set.
  void SetPriority(RequestPriority priority);

  void set_received_response_content_length(int64_t received_content_length) {
    received_response_content_length_ = received_content_length;
  }

  // The number of bytes in the raw response body (before any decompression,
  // etc.). This is only available after the final Read completes. Not available
  // for FTP responses.
  int64_t received_response_content_length() const {
    return received_response_content_length_;
  }

  // Available at NetworkDelegate::NotifyHeadersReceived() time, which is before
  // the more general response_info() is available, even though it is a subset.
  const HostPortPair& proxy_server() const {
    return proxy_server_;
  }

  // Gets the connection attempts made in the process of servicing this
  // URLRequest. Only guaranteed to be valid if called after the request fails
  // or after the response headers are received.
  void GetConnectionAttempts(ConnectionAttempts* out) const;

  // Gets the over the wire raw header size of the response after https
  // encryption, 0 for cached responses.
  int raw_header_size() const { return raw_header_size_; }

  // Returns the error status of the request.
  // Do not use! Going to be protected!
  const URLRequestStatus& status() const { return status_; }
 protected:
  // Allow the URLRequestJob class to control the is_pending() flag.
  void set_is_pending(bool value) { is_pending_ = value; }

  // Allow the URLRequestJob class to set our status too.
  void set_status(URLRequestStatus status);

  // Allow the URLRequestJob to redirect this request.  Returns OK if
  // successful, otherwise an error code is returned.
  int Redirect(const RedirectInfo& redirect_info);

  // Called by URLRequestJob to allow interception when a redirect occurs.
  void NotifyReceivedRedirect(const RedirectInfo& redirect_info,
                              bool* defer_redirect);

  // Allow an interceptor's URLRequestJob to restart this request.
  // Should only be called if the original job has not started a response.
  void Restart();

 private:
  friend class URLRequestJob;
  friend class URLRequestContext;

  // For testing purposes.
  // TODO(maksims): Remove this.
  friend class TestNetworkDelegate;

  // URLRequests are always created by calling URLRequestContext::CreateRequest.
  //
  // If no network delegate is passed in, will use the ones from the
  // URLRequestContext.
  URLRequest(const GURL& url,
             RequestPriority priority,
             Delegate* delegate,
             const URLRequestContext* context,
             NetworkDelegate* network_delegate);

  // Resumes or blocks a request paused by the NetworkDelegate::OnBeforeRequest
  // handler. If |blocked| is true, the request is blocked and an error page is
  // returned indicating so. This should only be called after Start is called
  // and OnBeforeRequest returns true (signalling that the request should be
  // paused).
  void BeforeRequestComplete(int error);

  // TODO(mmenke):  Make this take a scoped_ptr.
  void StartJob(URLRequestJob* job);

  // Restarting involves replacing the current job with a new one such as what
  // happens when following a HTTP redirect.
  void RestartWithJob(URLRequestJob* job);
  void PrepareToRestart();

  // Detaches the job from this request in preparation for this object going
  // away or the job being replaced. The job will not call us back when it has
  // been orphaned.
  void OrphanJob();

  // Cancels the request and set the error and ssl info for this request to the
  // passed values. Returns the error that was set.
  int DoCancel(int error, const SSLInfo& ssl_info);

  // Called by the URLRequestJob when the headers are received, before any other
  // method, to allow caching of load timing information.
  void OnHeadersComplete();

  // Notifies the network delegate that the request has been completed.
  // This does not imply a successful completion. Also a canceled request is
  // considered completed.
  void NotifyRequestCompleted();

  // Called by URLRequestJob to allow interception when the final response
  // occurs.
  void NotifyResponseStarted(const URLRequestStatus& status);

  // These functions delegate to |delegate_|.  See URLRequest::Delegate for the
  // meaning of these functions.
  void NotifyAuthRequired(AuthChallengeInfo* auth_info);
  void NotifyAuthRequiredComplete(NetworkDelegate::AuthRequiredResponse result);
  void NotifyCertificateRequested(SSLCertRequestInfo* cert_request_info);
  void NotifySSLCertificateError(const SSLInfo& ssl_info, bool fatal);
  void NotifyReadCompleted(int bytes_read);

  // These functions delegate to |network_delegate_| if it is not NULL.
  // If |network_delegate_| is NULL, cookies can be used unless
  // SetDefaultCookiePolicyToBlock() has been called.
  bool CanGetCookies(const CookieList& cookie_list) const;
  bool CanSetCookie(const std::string& cookie_line,
                    CookieOptions* options) const;
  bool CanEnablePrivacyMode() const;

  // Called just before calling a delegate that may block a request.
  void OnCallToDelegate();
  // Called when the delegate lets a request continue.  Also called on
  // cancellation.
  void OnCallToDelegateComplete();

  // Contextual information used for this request. Cannot be NULL. This contains
  // most of the dependencies which are shared between requests (disk cache,
  // cookie store, socket pool, etc.)
  const URLRequestContext* context_;

  NetworkDelegate* network_delegate_;

  // Tracks the time spent in various load states throughout this request.
  NetLogWithSource net_log_;

  std::unique_ptr<URLRequestJob> job_;
  std::unique_ptr<UploadDataStream> upload_data_stream_;

  std::vector<GURL> url_chain_;
  GURL first_party_for_cookies_;
  url::Origin initiator_;
  GURL delegate_redirect_url_;
  std::string method_;  // "GET", "POST", etc. Should be all uppercase.
  std::string referrer_;
  ReferrerPolicy referrer_policy_;
  std::string token_binding_referrer_;
  FirstPartyURLPolicy first_party_url_policy_;
  HttpRequestHeaders extra_request_headers_;
  int load_flags_;  // Flags indicating the request type for the load;
                    // expected values are LOAD_* enums above.

  // Never access methods of the |delegate_| directly. Always use the
  // Notify... methods for this.
  Delegate* delegate_;

  // Current error status of the job. When no error has been encountered, this
  // will be SUCCESS. If multiple errors have been encountered, this will be
  // the first non-SUCCESS status seen.
  URLRequestStatus status_;

  // The HTTP response info, lazily initialized.
  HttpResponseInfo response_info_;

  // Tells us whether the job is outstanding. This is true from the time
  // Start() is called to the time we dispatch RequestComplete and indicates
  // whether the job is active.
  bool is_pending_;

  // Indicates if the request is in the process of redirecting to a new
  // location.  It is true from the time the headers complete until a
  // new request begins.
  bool is_redirecting_;

  // Number of times we're willing to redirect.  Used to guard against
  // infinite redirects.
  int redirect_limit_;

  // Cached value for use after we've orphaned the job handling the
  // first transaction in a request involving redirects.
  UploadProgress final_upload_progress_;

  // The priority level for this request.  Objects like
  // ClientSocketPool use this to determine which URLRequest to
  // allocate sockets to first.
  RequestPriority priority_;

  // TODO(battre): The only consumer of the identifier_ is currently the
  // web request API. We need to match identifiers of requests between the
  // web request API and the web navigation API. As the URLRequest does not
  // exist when the web navigation API is triggered, the tracking probably
  // needs to be done outside of the URLRequest anyway. Therefore, this
  // identifier should be deleted here. http://crbug.com/89321
  // A globally unique identifier for this request.
  const uint64_t identifier_;

  // True if this request is currently calling a delegate, or is blocked waiting
  // for the URL request or network delegate to resume it.
  bool calling_delegate_;

  // An optional parameter that provides additional information about what
  // |this| is currently being blocked by.
  std::string blocked_by_;
  bool use_blocked_by_as_load_param_;

  base::debug::LeakTracker<URLRequest> leak_tracker_;

  // Callback passed to the network delegate to notify us when a blocked request
  // is ready to be resumed or canceled.
  CompletionCallback before_request_callback_;

  // Safe-guard to ensure that we do not send multiple "I am completed"
  // messages to network delegate.
  // TODO(battre): Remove this. http://crbug.com/89049
  bool has_notified_completion_;

  // Authentication data used by the NetworkDelegate for this request,
  // if one is present. |auth_credentials_| may be filled in when calling
  // |NotifyAuthRequired| on the NetworkDelegate. |auth_info_| holds
  // the authentication challenge being handled by |NotifyAuthRequired|.
  AuthCredentials auth_credentials_;
  scoped_refptr<AuthChallengeInfo> auth_info_;

  int64_t received_response_content_length_;

  base::TimeTicks creation_time_;

  // Timing information for the most recent request.  Its start times are
  // populated during Start(), and the rest are populated in OnResponseReceived.
  LoadTimingInfo load_timing_info_;

  // The proxy server used for this request, if any.
  HostPortPair proxy_server_;

  // The raw header size of the response.
  int raw_header_size_;

  DISALLOW_COPY_AND_ASSIGN(URLRequest);
};

}  // namespace net

#endif  // NET_URL_REQUEST_URL_REQUEST_H_
