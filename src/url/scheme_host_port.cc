// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "url/scheme_host_port.h"

#include <stdint.h>
#include <string.h>

#include <tuple>

#include "base/logging.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/string_number_conversions.h"
#include "url/gurl.h"
#include "url/url_canon.h"
#include "url/url_canon_stdstring.h"
#include "url/url_constants.h"
#include "url/url_util.h"

namespace url {

namespace {

bool IsCanonicalHost(const base::StringPiece& host) {
  std::string canon_host;

  // Try to canonicalize the host (copy/pasted from net/base. :( ).
  const Component raw_host_component(0,
                                     base::checked_cast<int>(host.length()));
  StdStringCanonOutput canon_host_output(&canon_host);
  CanonHostInfo host_info;
  CanonicalizeHostVerbose(host.data(), raw_host_component,
                          &canon_host_output, &host_info);

  if (host_info.out_host.is_nonempty() &&
      host_info.family != CanonHostInfo::BROKEN) {
    // Success!  Assert that there's no extra garbage.
    canon_host_output.Complete();
    DCHECK_EQ(host_info.out_host.len, static_cast<int>(canon_host.length()));
  } else {
    // Empty host, or canonicalization failed.
    canon_host.clear();
  }

  return host == canon_host;
}

bool IsValidInput(const base::StringPiece& scheme,
                  const base::StringPiece& host,
                  uint16_t port) {
  SchemeType scheme_type = SCHEME_WITH_PORT;
  bool is_standard = GetStandardSchemeType(
      scheme.data(),
      Component(0, base::checked_cast<int>(scheme.length())),
      &scheme_type);
  if (!is_standard)
    return false;

  // These schemes do not follow the generic URL syntax, so we treat them as
  // invalid (scheme, host, port) tuples (even though such URLs' _Origin_ might
  // have a (scheme, host, port) tuple, they themselves do not).
  if (scheme == kFileSystemScheme || scheme == kBlobScheme)
    return false;

  switch (scheme_type) {
    case SCHEME_WITH_PORT:
      // A URL with |scheme| is required to have the host and port (may be
      // omitted in a serialization if it's the same as the default value).
      // Return an invalid instance if either of them is not given.
      if (host.empty() || port == 0)
        return false;

      if (!IsCanonicalHost(host))
        return false;

      return true;

    case SCHEME_WITHOUT_PORT:
      if (port != 0) {
        // Return an invalid object if a URL with the scheme never represents
        // the port data but the given |port| is non-zero.
        return false;
      }

      if (!IsCanonicalHost(host))
        return false;

      return true;

    case SCHEME_WITHOUT_AUTHORITY:
      return false;

    default:
      NOTREACHED();
      return false;
  }
}

}  // namespace

SchemeHostPort::SchemeHostPort() : port_(0) {
}

SchemeHostPort::SchemeHostPort(base::StringPiece scheme,
                               base::StringPiece host,
                               uint16_t port)
    : port_(0) {
  if (!IsValidInput(scheme, host, port))
    return;

  scheme.CopyToString(&scheme_);
  host.CopyToString(&host_);
  port_ = port;
}

SchemeHostPort::SchemeHostPort(const GURL& url) : port_(0) {
  if (!url.is_valid())
    return;

  base::StringPiece scheme = url.scheme_piece();
  base::StringPiece host = url.host_piece();

  // A valid GURL never returns PORT_INVALID.
  int port = url.EffectiveIntPort();
  if (port == PORT_UNSPECIFIED)
    port = 0;

  if (!IsValidInput(scheme, host, port))
    return;

  scheme.CopyToString(&scheme_);
  host.CopyToString(&host_);
  port_ = port;
}

SchemeHostPort::~SchemeHostPort() {
}

bool SchemeHostPort::IsInvalid() const {
  return scheme_.empty() && host_.empty() && !port_;
}

std::string SchemeHostPort::Serialize() const {
  std::string result;
  if (IsInvalid())
    return result;

  result.append(scheme_);
  result.append(kStandardSchemeSeparator);
  result.append(host_);

  if (port_ == 0)
    return result;

  // Omit the port component if the port matches with the default port
  // defined for the scheme, if any.
  int default_port = DefaultPortForScheme(scheme_.data(),
                                          static_cast<int>(scheme_.length()));
  if (default_port == PORT_UNSPECIFIED)
    return result;
  if (port_ != default_port) {
    result.push_back(':');
    result.append(base::UintToString(port_));
  }

  return result;
}

bool SchemeHostPort::Equals(const SchemeHostPort& other) const {
  return port_ == other.port() && scheme_ == other.scheme() &&
         host_ == other.host();
}

bool SchemeHostPort::operator<(const SchemeHostPort& other) const {
  return std::tie(port_, scheme_, host_) <
         std::tie(other.port_, other.scheme_, other.host_);
}

}  // namespace url
