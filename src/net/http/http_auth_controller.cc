// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_auth_controller.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/platform_thread.h"
#include "net/base/auth.h"
#include "net/base/url_util.h"
#include "net/dns/host_resolver.h"
#include "net/http/http_auth_handler.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_network_session.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_headers.h"

namespace net {

namespace {

enum AuthEvent {
  AUTH_EVENT_START = 0,
  AUTH_EVENT_REJECT,
  AUTH_EVENT_MAX,
};

enum AuthTarget {
  AUTH_TARGET_PROXY = 0,
  AUTH_TARGET_SECURE_PROXY,
  AUTH_TARGET_SERVER,
  AUTH_TARGET_SECURE_SERVER,
  AUTH_TARGET_MAX,
};

AuthTarget DetermineAuthTarget(const HttpAuthHandler* handler) {
  switch (handler->target()) {
    case HttpAuth::AUTH_PROXY:
      if (handler->origin().SchemeIsCryptographic())
        return AUTH_TARGET_SECURE_PROXY;
      else
        return AUTH_TARGET_PROXY;
    case HttpAuth::AUTH_SERVER:
      if (handler->origin().SchemeIsCryptographic())
        return AUTH_TARGET_SECURE_SERVER;
      else
        return AUTH_TARGET_SERVER;
    default:
      NOTREACHED();
      return AUTH_TARGET_MAX;
  }
}

// Records the number of authentication events per authentication scheme.
void HistogramAuthEvent(HttpAuthHandler* handler, AuthEvent auth_event) {
#if !defined(NDEBUG)
  // Note: The on-same-thread check is intentionally not using a lock
  // to protect access to first_thread. This method is meant to be only
  // used on the same thread, in which case there are no race conditions. If
  // there are race conditions (say, a read completes during a partial write),
  // the DCHECK will correctly fail.
  static base::PlatformThreadId first_thread =
      base::PlatformThread::CurrentId();
  DCHECK_EQ(first_thread, base::PlatformThread::CurrentId());
#endif

  HttpAuth::Scheme auth_scheme = handler->auth_scheme();
  DCHECK(auth_scheme >= 0 && auth_scheme < HttpAuth::AUTH_SCHEME_MAX);

  // Record start and rejection events for authentication.
  //
  // The results map to:
  //   Basic Start: 0
  //   Basic Reject: 1
  //   Digest Start: 2
  //   Digest Reject: 3
  //   NTLM Start: 4
  //   NTLM Reject: 5
  //   Negotiate Start: 6
  //   Negotiate Reject: 7
  static const int kEventBucketsEnd =
      HttpAuth::AUTH_SCHEME_MAX * AUTH_EVENT_MAX;
  int event_bucket = auth_scheme * AUTH_EVENT_MAX + auth_event;
  DCHECK(event_bucket >= 0 && event_bucket < kEventBucketsEnd);
  UMA_HISTOGRAM_ENUMERATION("Net.HttpAuthCount", event_bucket,
                            kEventBucketsEnd);

  // Record the target of the authentication.
  //
  // The results map to:
  //   Basic Proxy: 0
  //   Basic Secure Proxy: 1
  //   Basic Server: 2
  //   Basic Secure Server: 3
  //   Digest Proxy: 4
  //   Digest Secure Proxy: 5
  //   Digest Server: 6
  //   Digest Secure Server: 7
  //   NTLM Proxy: 8
  //   NTLM Secure Proxy: 9
  //   NTLM Server: 10
  //   NTLM Secure Server: 11
  //   Negotiate Proxy: 12
  //   Negotiate Secure Proxy: 13
  //   Negotiate Server: 14
  //   Negotiate Secure Server: 15
  if (auth_event != AUTH_EVENT_START)
    return;
  static const int kTargetBucketsEnd =
      HttpAuth::AUTH_SCHEME_MAX * AUTH_TARGET_MAX;
  AuthTarget auth_target = DetermineAuthTarget(handler);
  int target_bucket = auth_scheme * AUTH_TARGET_MAX + auth_target;
  DCHECK(target_bucket >= 0 && target_bucket < kTargetBucketsEnd);
  UMA_HISTOGRAM_ENUMERATION("Net.HttpAuthTarget", target_bucket,
                            kTargetBucketsEnd);
}

}  // namespace

HttpAuthController::HttpAuthController(
    HttpAuth::Target target,
    const GURL& auth_url,
    HttpAuthCache* http_auth_cache,
    HttpAuthHandlerFactory* http_auth_handler_factory)
    : target_(target),
      auth_url_(auth_url),
      auth_origin_(auth_url.GetOrigin()),
      auth_path_(HttpAuth::AUTH_PROXY ? std::string() : auth_url.path()),
      embedded_identity_used_(false),
      default_credentials_used_(false),
      http_auth_cache_(http_auth_cache),
      http_auth_handler_factory_(http_auth_handler_factory) {
}

HttpAuthController::~HttpAuthController() {
  DCHECK(CalledOnValidThread());
}

int HttpAuthController::MaybeGenerateAuthToken(
    const HttpRequestInfo* request,
    const CompletionCallback& callback,
    const NetLogWithSource& net_log) {
  DCHECK(CalledOnValidThread());
  bool needs_auth = HaveAuth() || SelectPreemptiveAuth(net_log);
  if (!needs_auth)
    return OK;
  const AuthCredentials* credentials = NULL;
  if (identity_.source != HttpAuth::IDENT_SRC_DEFAULT_CREDENTIALS)
    credentials = &identity_.credentials;
  DCHECK(auth_token_.empty());
  DCHECK(callback_.is_null());
  int rv = handler_->GenerateAuthToken(
      credentials, request,
      base::Bind(&HttpAuthController::OnIOComplete, base::Unretained(this)),
      &auth_token_);
  if (DisableOnAuthHandlerResult(rv))
    rv = OK;
  if (rv == ERR_IO_PENDING)
    callback_ = callback;
  else
    OnIOComplete(rv);
  return rv;
}

bool HttpAuthController::SelectPreemptiveAuth(const NetLogWithSource& net_log) {
  DCHECK(CalledOnValidThread());
  DCHECK(!HaveAuth());
  DCHECK(identity_.invalid);

  // Don't do preemptive authorization if the URL contains a username:password,
  // since we must first be challenged in order to use the URL's identity.
  if (auth_url_.has_username())
    return false;

  // SelectPreemptiveAuth() is on the critical path for each request, so it
  // is expected to be fast. LookupByPath() is fast in the common case, since
  // the number of http auth cache entries is expected to be very small.
  // (For most users in fact, it will be 0.)
  HttpAuthCache::Entry* entry = http_auth_cache_->LookupByPath(
      auth_origin_, auth_path_);
  if (!entry)
    return false;

  // Try to create a handler using the previous auth challenge.
  std::unique_ptr<HttpAuthHandler> handler_preemptive;
  int rv_create = http_auth_handler_factory_->
      CreatePreemptiveAuthHandlerFromString(entry->auth_challenge(), target_,
                                            auth_origin_,
                                            entry->IncrementNonceCount(),
                                            net_log, &handler_preemptive);
  if (rv_create != OK)
    return false;

  // Set the state
  identity_.source = HttpAuth::IDENT_SRC_PATH_LOOKUP;
  identity_.invalid = false;
  identity_.credentials = entry->credentials();
  handler_.swap(handler_preemptive);
  return true;
}

void HttpAuthController::AddAuthorizationHeader(
    HttpRequestHeaders* authorization_headers) {
  DCHECK(CalledOnValidThread());
  DCHECK(HaveAuth());
  // auth_token_ can be empty if we encountered a permanent error with
  // the auth scheme and want to retry.
  if (!auth_token_.empty()) {
    authorization_headers->SetHeader(
        HttpAuth::GetAuthorizationHeaderName(target_), auth_token_);
    auth_token_.clear();
  }
}

int HttpAuthController::HandleAuthChallenge(
    scoped_refptr<HttpResponseHeaders> headers,
    const SSLInfo& ssl_info,
    bool do_not_send_server_auth,
    bool establishing_tunnel,
    const NetLogWithSource& net_log) {
  DCHECK(CalledOnValidThread());
  DCHECK(headers.get());
  DCHECK(auth_origin_.is_valid());

  // Give the existing auth handler first try at the authentication headers.
  // This will also evict the entry in the HttpAuthCache if the previous
  // challenge appeared to be rejected, or is using a stale nonce in the Digest
  // case.
  if (HaveAuth()) {
    std::string challenge_used;
    HttpAuth::AuthorizationResult result = HttpAuth::HandleChallengeResponse(
        handler_.get(), *headers, target_, disabled_schemes_, &challenge_used);
    switch (result) {
      case HttpAuth::AUTHORIZATION_RESULT_ACCEPT:
        break;
      case HttpAuth::AUTHORIZATION_RESULT_INVALID:
        InvalidateCurrentHandler(INVALIDATE_HANDLER_AND_CACHED_CREDENTIALS);
        break;
      case HttpAuth::AUTHORIZATION_RESULT_REJECT:
        HistogramAuthEvent(handler_.get(), AUTH_EVENT_REJECT);
        InvalidateCurrentHandler(INVALIDATE_HANDLER_AND_CACHED_CREDENTIALS);
        break;
      case HttpAuth::AUTHORIZATION_RESULT_STALE:
        if (http_auth_cache_->UpdateStaleChallenge(auth_origin_,
                                                   handler_->realm(),
                                                   handler_->auth_scheme(),
                                                   challenge_used)) {
          InvalidateCurrentHandler(INVALIDATE_HANDLER);
        } else {
          // It's possible that a server could incorrectly issue a stale
          // response when the entry is not in the cache. Just evict the
          // current value from the cache.
          InvalidateCurrentHandler(INVALIDATE_HANDLER_AND_CACHED_CREDENTIALS);
        }
        break;
      case HttpAuth::AUTHORIZATION_RESULT_DIFFERENT_REALM:
        // If the server changes the authentication realm in a
        // subsequent challenge, invalidate cached credentials for the
        // previous realm.  If the server rejects a preemptive
        // authorization and requests credentials for a different
        // realm, we keep the cached credentials.
        InvalidateCurrentHandler(
            (identity_.source == HttpAuth::IDENT_SRC_PATH_LOOKUP) ?
            INVALIDATE_HANDLER :
            INVALIDATE_HANDLER_AND_CACHED_CREDENTIALS);
        break;
      default:
        NOTREACHED();
        break;
    }
  }

  identity_.invalid = true;

  bool can_send_auth = (target_ != HttpAuth::AUTH_SERVER ||
                        !do_not_send_server_auth);

  do {
    if (!handler_.get() && can_send_auth) {
      // Find the best authentication challenge that we support.
      HttpAuth::ChooseBestChallenge(http_auth_handler_factory_, *headers,
                                    ssl_info, target_, auth_origin_,
                                    disabled_schemes_, net_log, &handler_);
      if (handler_.get())
        HistogramAuthEvent(handler_.get(), AUTH_EVENT_START);
    }

    if (!handler_.get()) {
      if (establishing_tunnel) {
        // We are establishing a tunnel, we can't show the error page because an
        // active network attacker could control its contents.  Instead, we just
        // fail to establish the tunnel.
        DCHECK(target_ == HttpAuth::AUTH_PROXY);
        return ERR_PROXY_AUTH_UNSUPPORTED;
      }
      // We found no supported challenge -- let the transaction continue so we
      // end up displaying the error page.
      return OK;
    }

    if (handler_->NeedsIdentity()) {
      // Pick a new auth identity to try, by looking to the URL and auth cache.
      // If an identity to try is found, it is saved to identity_.
      SelectNextAuthIdentityToTry();
    } else {
      // Proceed with the existing identity or a null identity.
      identity_.invalid = false;
    }

    // From this point on, we are restartable.

    if (identity_.invalid) {
      // We have exhausted all identity possibilities.
      if (!handler_->AllowsExplicitCredentials()) {
        // If the handler doesn't accept explicit credentials, then we need to
        // choose a different auth scheme.
        HistogramAuthEvent(handler_.get(), AUTH_EVENT_REJECT);
        InvalidateCurrentHandler(INVALIDATE_HANDLER_AND_DISABLE_SCHEME);
      } else {
        // Pass the challenge information back to the client.
        PopulateAuthChallenge();
      }
    } else {
      auth_info_ = NULL;
    }

    // If we get here and we don't have a handler_, that's because we
    // invalidated it due to not having any viable identities to use with it. Go
    // back and try again.
    // TODO(asanka): Instead we should create a priority list of
    //     <handler,identity> and iterate through that.
  } while(!handler_.get());
  return OK;
}

void HttpAuthController::ResetAuth(const AuthCredentials& credentials) {
  DCHECK(CalledOnValidThread());
  DCHECK(identity_.invalid || credentials.Empty());

  if (identity_.invalid) {
    // Update the credentials.
    identity_.source = HttpAuth::IDENT_SRC_EXTERNAL;
    identity_.invalid = false;
    identity_.credentials = credentials;
  }

  DCHECK(identity_.source != HttpAuth::IDENT_SRC_PATH_LOOKUP);

  // Add the auth entry to the cache before restarting. We don't know whether
  // the identity is valid yet, but if it is valid we want other transactions
  // to know about it. If an entry for (origin, handler->realm()) already
  // exists, we update it.
  //
  // If identity_.source is HttpAuth::IDENT_SRC_NONE or
  // HttpAuth::IDENT_SRC_DEFAULT_CREDENTIALS, identity_ contains no
  // identity because identity is not required yet or we're using default
  // credentials.
  //
  // TODO(wtc): For NTLM_SSPI, we add the same auth entry to the cache in
  // round 1 and round 2, which is redundant but correct.  It would be nice
  // to add an auth entry to the cache only once, preferrably in round 1.
  // See http://crbug.com/21015.
  switch (identity_.source) {
    case HttpAuth::IDENT_SRC_NONE:
    case HttpAuth::IDENT_SRC_DEFAULT_CREDENTIALS:
      break;
    default:
      http_auth_cache_->Add(auth_origin_, handler_->realm(),
                            handler_->auth_scheme(), handler_->challenge(),
                            identity_.credentials, auth_path_);
      break;
  }
}

bool HttpAuthController::HaveAuthHandler() const {
  return handler_.get() != NULL;
}

bool HttpAuthController::HaveAuth() const {
  return handler_.get() && !identity_.invalid;
}

void HttpAuthController::InvalidateCurrentHandler(
    InvalidateHandlerAction action) {
  DCHECK(CalledOnValidThread());
  DCHECK(handler_.get());

  if (action == INVALIDATE_HANDLER_AND_CACHED_CREDENTIALS)
    InvalidateRejectedAuthFromCache();
  if (action == INVALIDATE_HANDLER_AND_DISABLE_SCHEME)
    DisableAuthScheme(handler_->auth_scheme());
  handler_.reset();
  identity_ = HttpAuth::Identity();
}

void HttpAuthController::InvalidateRejectedAuthFromCache() {
  DCHECK(CalledOnValidThread());
  DCHECK(HaveAuth());

  // Clear the cache entry for the identity we just failed on.
  // Note: we require the credentials to match before invalidating
  // since the entry in the cache may be newer than what we used last time.
  http_auth_cache_->Remove(auth_origin_, handler_->realm(),
                           handler_->auth_scheme(), identity_.credentials);
}

bool HttpAuthController::SelectNextAuthIdentityToTry() {
  DCHECK(CalledOnValidThread());
  DCHECK(handler_.get());
  DCHECK(identity_.invalid);

  // Try to use the username:password encoded into the URL first.
  if (target_ == HttpAuth::AUTH_SERVER && auth_url_.has_username() &&
      !embedded_identity_used_) {
    identity_.source = HttpAuth::IDENT_SRC_URL;
    identity_.invalid = false;
    // Extract the username:password from the URL.
    base::string16 username;
    base::string16 password;
    GetIdentityFromURL(auth_url_, &username, &password);
    identity_.credentials.Set(username, password);
    embedded_identity_used_ = true;
    // TODO(eroman): If the password is blank, should we also try combining
    // with a password from the cache?
    UMA_HISTOGRAM_BOOLEAN("net.HttpIdentSrcURL", true);
    return true;
  }

  // Check the auth cache for a realm entry.
  HttpAuthCache::Entry* entry =
      http_auth_cache_->Lookup(auth_origin_, handler_->realm(),
                               handler_->auth_scheme());

  if (entry) {
    identity_.source = HttpAuth::IDENT_SRC_REALM_LOOKUP;
    identity_.invalid = false;
    identity_.credentials = entry->credentials();
    return true;
  }

  // Use default credentials (single sign on) if this is the first attempt
  // at identity.  Do not allow multiple times as it will infinite loop.
  // We use default credentials after checking the auth cache so that if
  // single sign-on doesn't work, we won't try default credentials for future
  // transactions.
  if (!default_credentials_used_ && handler_->AllowsDefaultCredentials()) {
    identity_.source = HttpAuth::IDENT_SRC_DEFAULT_CREDENTIALS;
    identity_.invalid = false;
    default_credentials_used_ = true;
    return true;
  }

  return false;
}

void HttpAuthController::PopulateAuthChallenge() {
  DCHECK(CalledOnValidThread());

  // Populates response_.auth_challenge with the authentication challenge info.
  // This info is consumed by URLRequestHttpJob::GetAuthChallengeInfo().

  auth_info_ = new AuthChallengeInfo;
  auth_info_->is_proxy = (target_ == HttpAuth::AUTH_PROXY);
  auth_info_->challenger = url::Origin(auth_origin_);
  auth_info_->scheme = HttpAuth::SchemeToString(handler_->auth_scheme());
  auth_info_->realm = handler_->realm();
}

bool HttpAuthController::DisableOnAuthHandlerResult(int result) {
  DCHECK(CalledOnValidThread());

  switch (result) {
    // Occurs with GSSAPI, if the user has not already logged in.
    case ERR_MISSING_AUTH_CREDENTIALS:

    // Can occur with GSSAPI or SSPI if the underlying library reports
    // a permanent error.
    case ERR_UNSUPPORTED_AUTH_SCHEME:

    // These two error codes represent failures we aren't handling.
    case ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS:
    case ERR_UNDOCUMENTED_SECURITY_LIBRARY_STATUS:

    // Can be returned by SSPI if the authenticating authority or
    // target is not known.
    case ERR_MISCONFIGURED_AUTH_ENVIRONMENT:

      // In these cases, disable the current scheme as it cannot
      // succeed.
      DisableAuthScheme(handler_->auth_scheme());
      auth_token_.clear();
      return true;

    default:
      return false;
  }
}

void HttpAuthController::OnIOComplete(int result) {
  DCHECK(CalledOnValidThread());
  if (DisableOnAuthHandlerResult(result))
    result = OK;
  if (!callback_.is_null()) {
    CompletionCallback c = callback_;
    callback_.Reset();
    c.Run(result);
  }
}

scoped_refptr<AuthChallengeInfo> HttpAuthController::auth_info() {
  DCHECK(CalledOnValidThread());
  return auth_info_;
}

bool HttpAuthController::IsAuthSchemeDisabled(HttpAuth::Scheme scheme) const {
  DCHECK(CalledOnValidThread());
  return disabled_schemes_.find(scheme) != disabled_schemes_.end();
}

void HttpAuthController::DisableAuthScheme(HttpAuth::Scheme scheme) {
  DCHECK(CalledOnValidThread());
  disabled_schemes_.insert(scheme);
}

void HttpAuthController::DisableEmbeddedIdentity() {
  DCHECK(CalledOnValidThread());
  embedded_identity_used_ = true;
}

}  // namespace net
