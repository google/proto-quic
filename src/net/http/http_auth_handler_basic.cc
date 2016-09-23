// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_auth_handler_basic.h"

#include <string>

#include "base/base64.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "net/base/net_errors.h"
#include "net/base/net_string_util.h"
#include "net/http/http_auth.h"
#include "net/http/http_auth_challenge_tokenizer.h"
#include "net/http/http_auth_scheme.h"

namespace net {

namespace {

// Parses a realm from an auth challenge, and converts to UTF8-encoding.
// Returns whether the realm is invalid or the parameters are invalid.
//
// Note that if a realm was not specified, we will default it to "";
// so specifying 'Basic realm=""' is equivalent to 'Basic'.
//
// This is more generous than RFC 2617, which is pretty clear in the
// production of challenge that realm is required.
//
// We allow it to be compatibility with certain embedded webservers that don't
// include a realm (see http://crbug.com/20984.)
//
// The over-the-wire realm is encoded as ISO-8859-1 (aka Latin-1).
//
// TODO(cbentzel): Realm may need to be decoded using RFC 2047 rules as
// well, see http://crbug.com/25790.
bool ParseRealm(const HttpAuthChallengeTokenizer& tokenizer,
                std::string* realm) {
  CHECK(realm);
  realm->clear();
  HttpUtil::NameValuePairsIterator parameters = tokenizer.param_pairs();
  while (parameters.GetNext()) {
    if (!base::LowerCaseEqualsASCII(parameters.name(), "realm"))
      continue;

    if (!ConvertToUtf8AndNormalize(parameters.value(), kCharsetLatin1, realm)) {
      return false;
    }
  }
  return parameters.valid();
}

}  // namespace

bool HttpAuthHandlerBasic::Init(HttpAuthChallengeTokenizer* challenge,
                                const SSLInfo& ssl_info) {
  auth_scheme_ = HttpAuth::AUTH_SCHEME_BASIC;
  score_ = 1;
  properties_ = 0;
  return ParseChallenge(challenge);
}

bool HttpAuthHandlerBasic::ParseChallenge(
    HttpAuthChallengeTokenizer* challenge) {
  // Verify the challenge's auth-scheme.
  if (!base::LowerCaseEqualsASCII(challenge->scheme(), kBasicAuthScheme))
    return false;

  std::string realm;
  if (!ParseRealm(*challenge, &realm))
    return false;

  realm_ = realm;
  return true;
}

HttpAuth::AuthorizationResult HttpAuthHandlerBasic::HandleAnotherChallenge(
    HttpAuthChallengeTokenizer* challenge) {
  // Basic authentication is always a single round, so any responses
  // should be treated as a rejection.  However, if the new challenge
  // is for a different realm, then indicate the realm change.
  std::string realm;
  if (!ParseRealm(*challenge, &realm))
    return HttpAuth::AUTHORIZATION_RESULT_INVALID;
  return (realm_ != realm)?
      HttpAuth::AUTHORIZATION_RESULT_DIFFERENT_REALM:
      HttpAuth::AUTHORIZATION_RESULT_REJECT;
}

int HttpAuthHandlerBasic::GenerateAuthTokenImpl(
    const AuthCredentials* credentials, const HttpRequestInfo*,
    const CompletionCallback&, std::string* auth_token) {
  DCHECK(credentials);
  // TODO(eroman): is this the right encoding of username/password?
  std::string base64_username_password;
  base::Base64Encode(base::UTF16ToUTF8(credentials->username()) + ":" +
                         base::UTF16ToUTF8(credentials->password()),
                     &base64_username_password);
  *auth_token = "Basic " + base64_username_password;
  return OK;
}

HttpAuthHandlerBasic::Factory::Factory() {
}

HttpAuthHandlerBasic::Factory::~Factory() {
}

int HttpAuthHandlerBasic::Factory::CreateAuthHandler(
    HttpAuthChallengeTokenizer* challenge,
    HttpAuth::Target target,
    const SSLInfo& ssl_info,
    const GURL& origin,
    CreateReason reason,
    int digest_nonce_count,
    const NetLogWithSource& net_log,
    std::unique_ptr<HttpAuthHandler>* handler) {
  // TODO(cbentzel): Move towards model of parsing in the factory
  //                 method and only constructing when valid.
  std::unique_ptr<HttpAuthHandler> tmp_handler(new HttpAuthHandlerBasic());
  if (!tmp_handler->InitFromChallenge(challenge, target, ssl_info, origin,
                                      net_log))
    return ERR_INVALID_RESPONSE;
  handler->swap(tmp_handler);
  return OK;
}

}  // namespace net
