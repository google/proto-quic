// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_auth_handler_mock.h"

#include "base/bind.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/net_errors.h"
#include "net/http/http_auth_challenge_tokenizer.h"
#include "net/http/http_request_info.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

HttpAuthHandlerMock::HttpAuthHandlerMock()
  : resolve_(RESOLVE_INIT),
    generate_async_(false),
    generate_rv_(OK),
    auth_token_(NULL),
    first_round_(true),
    connection_based_(false),
    allows_default_credentials_(false),
    allows_explicit_credentials_(true),
    weak_factory_(this) {
}

HttpAuthHandlerMock::~HttpAuthHandlerMock() {
}

void HttpAuthHandlerMock::SetResolveExpectation(Resolve resolve) {
  EXPECT_EQ(RESOLVE_INIT, resolve_);
  resolve_ = resolve;
}

bool HttpAuthHandlerMock::NeedsCanonicalName() {
  switch (resolve_) {
    case RESOLVE_SYNC:
    case RESOLVE_ASYNC:
      return true;
    case RESOLVE_SKIP:
      resolve_ = RESOLVE_TESTED;
      return false;
    default:
      NOTREACHED();
      return false;
  }
}

int HttpAuthHandlerMock::ResolveCanonicalName(
    HostResolver* host_resolver, const CompletionCallback& callback) {
  EXPECT_NE(RESOLVE_TESTED, resolve_);
  int rv = OK;
  switch (resolve_) {
    case RESOLVE_SYNC:
      resolve_ = RESOLVE_TESTED;
      break;
    case RESOLVE_ASYNC:
      EXPECT_TRUE(callback_.is_null());
      rv = ERR_IO_PENDING;
      callback_ = callback;
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(&HttpAuthHandlerMock::OnResolveCanonicalName,
                                weak_factory_.GetWeakPtr()));
      break;
    default:
      NOTREACHED();
      break;
  }
  return rv;
}

void HttpAuthHandlerMock::SetGenerateExpectation(bool async, int rv) {
  generate_async_ = async;
  generate_rv_ = rv;
}

HttpAuth::AuthorizationResult HttpAuthHandlerMock::HandleAnotherChallenge(
    HttpAuthChallengeTokenizer* challenge) {
  // If we receive an empty challenge for a connection based scheme, or a second
  // challenge for a non connection based scheme, assume it's a rejection.
  if (!is_connection_based() || challenge->base64_param().empty())
    return HttpAuth::AUTHORIZATION_RESULT_REJECT;
  if (!base::LowerCaseEqualsASCII(challenge->scheme(), "mock"))
    return HttpAuth::AUTHORIZATION_RESULT_INVALID;
  return HttpAuth::AUTHORIZATION_RESULT_ACCEPT;
}

bool HttpAuthHandlerMock::NeedsIdentity() {
  return first_round_;
}

bool HttpAuthHandlerMock::AllowsDefaultCredentials() {
  return allows_default_credentials_;
}

bool HttpAuthHandlerMock::AllowsExplicitCredentials() {
  return allows_explicit_credentials_;
}

bool HttpAuthHandlerMock::Init(HttpAuthChallengeTokenizer* challenge,
                               const SSLInfo& ssl_info) {
  auth_scheme_ = HttpAuth::AUTH_SCHEME_MOCK;
  score_ = 1;
  properties_ = connection_based_ ? IS_CONNECTION_BASED : 0;
  return true;
}

int HttpAuthHandlerMock::GenerateAuthTokenImpl(
    const AuthCredentials* credentials,
    const HttpRequestInfo* request,
    const CompletionCallback& callback,
    std::string* auth_token) {
  first_round_ = false;
  request_url_ = request->url;
  if (generate_async_) {
    EXPECT_TRUE(callback_.is_null());
    EXPECT_TRUE(auth_token_ == NULL);
    callback_ = callback;
    auth_token_ = auth_token;
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&HttpAuthHandlerMock::OnGenerateAuthToken,
                              weak_factory_.GetWeakPtr()));
    return ERR_IO_PENDING;
  } else {
    if (generate_rv_ == OK)
      *auth_token = "auth_token";
    return generate_rv_;
  }
}

void HttpAuthHandlerMock::OnResolveCanonicalName() {
  EXPECT_EQ(RESOLVE_ASYNC, resolve_);
  EXPECT_TRUE(!callback_.is_null());
  resolve_ = RESOLVE_TESTED;
  CompletionCallback callback = callback_;
  callback_.Reset();
  callback.Run(OK);
}

void HttpAuthHandlerMock::OnGenerateAuthToken() {
  EXPECT_TRUE(generate_async_);
  EXPECT_TRUE(!callback_.is_null());
  if (generate_rv_ == OK)
    *auth_token_ = "auth_token";
  auth_token_ = NULL;
  CompletionCallback callback = callback_;
  callback_.Reset();
  callback.Run(generate_rv_);
}

HttpAuthHandlerMock::Factory::Factory()
    : do_init_from_challenge_(false) {
  // TODO(cbentzel): Default do_init_from_challenge_ to true.
}

HttpAuthHandlerMock::Factory::~Factory() {
}

void HttpAuthHandlerMock::Factory::AddMockHandler(
    HttpAuthHandler* handler, HttpAuth::Target target) {
  handlers_[target].push_back(base::WrapUnique(handler));
}

int HttpAuthHandlerMock::Factory::CreateAuthHandler(
    HttpAuthChallengeTokenizer* challenge,
    HttpAuth::Target target,
    const SSLInfo& ssl_info,
    const GURL& origin,
    CreateReason reason,
    int nonce_count,
    const BoundNetLog& net_log,
    std::unique_ptr<HttpAuthHandler>* handler) {
  if (handlers_[target].empty())
    return ERR_UNEXPECTED;
  std::unique_ptr<HttpAuthHandler> tmp_handler =
      std::move(handlers_[target][0]);
  std::vector<std::unique_ptr<HttpAuthHandler>>& handlers = handlers_[target];
  handlers.erase(handlers.begin());
  if (do_init_from_challenge_ &&
      !tmp_handler->InitFromChallenge(challenge, target, ssl_info, origin,
                                      net_log))
    return ERR_INVALID_RESPONSE;
  handler->swap(tmp_handler);
  return OK;
}

}  // namespace net
