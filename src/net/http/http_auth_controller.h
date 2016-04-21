// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_HTTP_AUTH_CONTROLLER_H_
#define NET_HTTP_HTTP_AUTH_CONTROLLER_H_

#include <memory>
#include <set>
#include <string>

#include "base/memory/ref_counted.h"
#include "base/threading/non_thread_safe.h"
#include "net/base/completion_callback.h"
#include "net/base/net_export.h"
#include "net/http/http_auth.h"
#include "net/log/net_log.h"
#include "url/gurl.h"

namespace net {

class AuthChallengeInfo;
class AuthCredentials;
class HttpAuthHandler;
class HttpAuthHandlerFactory;
class HttpAuthCache;
class HttpRequestHeaders;
struct HttpRequestInfo;
class SSLInfo;

class NET_EXPORT_PRIVATE HttpAuthController
    : public base::RefCounted<HttpAuthController>,
      NON_EXPORTED_BASE(public base::NonThreadSafe) {
 public:
  // The arguments are self explanatory except possibly for |auth_url|, which
  // should be both the auth target and auth path in a single url argument.
  HttpAuthController(HttpAuth::Target target,
                     const GURL& auth_url,
                     HttpAuthCache* http_auth_cache,
                     HttpAuthHandlerFactory* http_auth_handler_factory);

  // Generate an authentication token for |target| if necessary. The return
  // value is a net error code. |OK| will be returned both in the case that
  // a token is correctly generated synchronously, as well as when no tokens
  // were necessary.
  virtual int MaybeGenerateAuthToken(const HttpRequestInfo* request,
                                     const CompletionCallback& callback,
                                     const BoundNetLog& net_log);

  // Adds either the proxy auth header, or the origin server auth header,
  // as specified by |target_|.
  virtual void AddAuthorizationHeader(
      HttpRequestHeaders* authorization_headers);

  // Checks for and handles HTTP status code 401 or 407.
  // |HandleAuthChallenge()| returns OK on success, or a network error code
  // otherwise. It may also populate |auth_info_|.
  virtual int HandleAuthChallenge(scoped_refptr<HttpResponseHeaders> headers,
                                  const SSLInfo& ssl_info,
                                  bool do_not_send_server_auth,
                                  bool establishing_tunnel,
                                  const BoundNetLog& net_log);

  // Store the supplied credentials and prepare to restart the auth.
  virtual void ResetAuth(const AuthCredentials& credentials);

  virtual bool HaveAuthHandler() const;

  virtual bool HaveAuth() const;

  virtual scoped_refptr<AuthChallengeInfo> auth_info();

  virtual bool IsAuthSchemeDisabled(HttpAuth::Scheme scheme) const;
  virtual void DisableAuthScheme(HttpAuth::Scheme scheme);
  virtual void DisableEmbeddedIdentity();

 private:
  // Actions for InvalidateCurrentHandler()
  enum InvalidateHandlerAction {
    INVALIDATE_HANDLER_AND_CACHED_CREDENTIALS,
    INVALIDATE_HANDLER_AND_DISABLE_SCHEME,
    INVALIDATE_HANDLER
  };

  // So that we can mock this object.
  friend class base::RefCounted<HttpAuthController>;

  virtual ~HttpAuthController();

  // Searches the auth cache for an entry that encompasses the request's path.
  // If such an entry is found, updates |identity_| and |handler_| with the
  // cache entry's data and returns true.
  bool SelectPreemptiveAuth(const BoundNetLog& net_log);

  // Invalidates the current handler.  If |action| is
  // INVALIDATE_HANDLER_AND_CACHED_CREDENTIALS, then also invalidate
  // the cached credentials used by the handler.
  void InvalidateCurrentHandler(InvalidateHandlerAction action);

  // Invalidates any auth cache entries after authentication has failed.
  // The identity that was rejected is |identity_|.
  void InvalidateRejectedAuthFromCache();

  // Sets |identity_| to the next identity that the transaction should try. It
  // chooses candidates by searching the auth cache and the URL for a
  // username:password. Returns true if an identity was found.
  bool SelectNextAuthIdentityToTry();

  // Populates auth_info_ with the challenge information, so that
  // URLRequestHttpJob can prompt for credentials.
  void PopulateAuthChallenge();

  // If |result| indicates a permanent failure, disables the current
  // auth scheme for this controller and returns true.  Returns false
  // otherwise.
  bool DisableOnAuthHandlerResult(int result);

  void OnIOComplete(int result);

  // Indicates if this handler is for Proxy auth or Server auth.
  HttpAuth::Target target_;

  // Holds the {scheme, host, path, port} for the authentication target.
  const GURL auth_url_;

  // Holds the {scheme, host, port} for the authentication target.
  const GURL auth_origin_;

  // The absolute path of the resource needing authentication.
  // For proxy authentication the path is empty.
  const std::string auth_path_;

  // |handler_| encapsulates the logic for the particular auth-scheme.
  // This includes the challenge's parameters. If NULL, then there is no
  // associated auth handler.
  std::unique_ptr<HttpAuthHandler> handler_;

  // |identity_| holds the credentials that should be used by
  // the handler_ to generate challenge responses. This identity can come from
  // a number of places (url, cache, prompt).
  HttpAuth::Identity identity_;

  // |auth_token_| contains the opaque string to pass to the proxy or
  // server to authenticate the client.
  std::string auth_token_;

  // Contains information about the auth challenge.
  scoped_refptr<AuthChallengeInfo> auth_info_;

  // True if we've used the username:password embedded in the URL.  This
  // makes sure we use the embedded identity only once for the transaction,
  // preventing an infinite auth restart loop.
  bool embedded_identity_used_;

  // True if default credentials have already been tried for this transaction
  // in response to an HTTP authentication challenge.
  bool default_credentials_used_;

  // These two are owned by the HttpNetworkSession/IOThread, which own the
  // objects which reference |this|.  Therefore, these raw pointers are valid
  // for the lifetime of this object.
  HttpAuthCache* const http_auth_cache_;
  HttpAuthHandlerFactory* const http_auth_handler_factory_;

  std::set<HttpAuth::Scheme> disabled_schemes_;

  CompletionCallback callback_;
};

}  // namespace net

#endif  // NET_HTTP_HTTP_AUTH_CONTROLLER_H_
