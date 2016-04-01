// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_SSL_FAILURE_STATE_H_
#define NET_SSL_SSL_FAILURE_STATE_H_

namespace net {

// Describes the most likely cause for the TLS handshake failure. This is an
// approximation used to classify the causes of TLS version fallback. These
// values are used in histograms, so new values must be appended.
enum SSLFailureState {
  // The connection was successful.
  SSL_FAILURE_NONE = 0,

  // The connection failed for unknown reasons.
  SSL_FAILURE_UNKNOWN = 1,

  // The connection failed after sending ClientHello and before receiving
  // ServerHello.
  SSL_FAILURE_CLIENT_HELLO = 2,

  // The connection failed after negotiating TLS_RSA_WITH_AES_128_GCM_SHA256 or
  // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 and completing the client's second
  // leg. Some Microsoft IIS servers fail at this point. See
  // https://crbug.com/433406.
  SSL_FAILURE_BUGGY_GCM = 3,

  // The connection failed after CertificateVerify was sent. Some servers are
  // known to incorrectly implement TLS 1.2 client auth.
  SSL_FAILURE_CLIENT_AUTH = 4,

  // The connection failed because the server attempted to resume a session at
  // the wrong version. Some versions of OpenSSL may do this in rare
  // circumstances. See https://crbug.com/441456
  SSL_FAILURE_SESSION_MISMATCH = 5,

  // The connection failed after sending the NextProto message. Some F5 servers
  // fail to parse such messages in TLS 1.1 and TLS 1.2, but not 1.0. See
  // https://crbug.com/466977.
  SSL_FAILURE_NEXT_PROTO = 6,

  SSL_FAILURE_MAX,
};

}  // namespace net

#endif  // NET_SSL_SSL_FAILURE_STATE_H_
