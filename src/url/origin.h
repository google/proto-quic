// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef URL_ORIGIN_H_
#define URL_ORIGIN_H_

#include <stdint.h>

#include <string>

#include "base/strings/string16.h"
#include "base/strings/string_piece.h"
#include "url/scheme_host_port.h"
#include "url/third_party/mozilla/url_parse.h"
#include "url/url_canon.h"
#include "url/url_constants.h"
#include "url/url_export.h"

class GURL;

namespace url {

// An Origin is a tuple of (scheme, host, port), as described in RFC 6454.
//
// TL;DR: If you need to make a security-relevant decision, use 'url::Origin'.
// If you only need to extract the bits of a URL which are relevant for a
// network connection, use 'url::SchemeHostPort'.
//
// STL;SDR: If you aren't making actual network connections, use 'url::Origin'.
//
// 'Origin', like 'SchemeHostPort', is composed of a tuple of (scheme, host,
// port), but contains a number of additional concepts which make it appropriate
// for use as a security boundary and access control mechanism between contexts.
//
// This class ought to be used when code needs to determine if two resources
// are "same-origin", and when a canonical serialization of an origin is
// required. Note that some origins are "unique", meaning that they are not
// same-origin with any other origin (including themselves).
//
// There are a few subtleties to note:
//
// * Invalid and non-standard GURLs are parsed as unique origins. This includes
//   non-hierarchical URLs like 'data:text/html,...' and 'javascript:alert(1)'.
//
// * GURLs with schemes of 'filesystem' or 'blob' parse the origin out of the
//   internals of the URL. That is, 'filesystem:https://example.com/temporary/f'
//   is parsed as ('https', 'example.com', 443).
//
// * Unique origins all serialize to the string "null"; this means that the
//   serializations of two unique origins are identical to each other, though
//   the origins themselves are not "the same". This means that origins'
//   serializations must not be relied upon for security checks.
//
// * GURLs with a 'file' scheme are tricky. They are parsed as ('file', '', 0),
//   but their behavior may differ from embedder to embedder.
//
// * The host component of an IPv6 address includes brackets, just like the URL
//   representation.
//
// Usage:
//
// * Origins are generally constructed from an already-canonicalized GURL:
//
//     GURL url("https://example.com/");
//     url::Origin origin(url);
//     origin.scheme(); // "https"
//     origin.host(); // "example.com"
//     origin.port(); // 443
//     origin.unique(); // false
//
// * To answer the question "Are |this| and |that| "same-origin" with each
//   other?", use |Origin::IsSameOriginWith|:
//
//     if (this.IsSameOriginWith(that)) {
//       // Amazingness goes here.
//     }
class URL_EXPORT Origin {
 public:
  // Creates a unique Origin.
  Origin();

  // Creates an Origin from |url|, as described at
  // https://url.spec.whatwg.org/#origin, with the following additions:
  //
  // 1. If |url| is invalid or non-standard, a unique Origin is constructed.
  // 2. 'filesystem' URLs behave as 'blob' URLs (that is, the origin is parsed
  //    out of everything in the URL which follows the scheme).
  // 3. 'file' URLs all parse as ("file", "", 0).
  explicit Origin(const GURL& url);

  // Creates an Origin from a |scheme|, |host|, and |port|. All the parameters
  // must be valid and canonicalized. Do not use this method to create unique
  // origins. Use Origin() for that.
  //
  // This constructor should be used in order to pass 'Origin' objects back and
  // forth over IPC (as transitioning through GURL would risk potentially
  // dangerous recanonicalization); other potential callers should prefer the
  // 'GURL'-based constructor.
  static Origin UnsafelyCreateOriginWithoutNormalization(
      base::StringPiece scheme,
      base::StringPiece host,
      uint16_t port);

  // Creates an origin without sanity checking that the host is canonicalized.
  // This should only be used when converting between already normalized types,
  // and should NOT be used for IPC. Method takes std::strings for use with move
  // operators to avoid copies.
  static Origin CreateFromNormalizedTupleWithSuborigin(
      std::string scheme,
      std::string host,
      uint16_t port,
      std::string suborigin);

  ~Origin();

  // For unique origins, these return ("", "", 0).
  const std::string& scheme() const { return tuple_.scheme(); }
  const std::string& host() const { return tuple_.host(); }
  uint16_t port() const { return tuple_.port(); }

  // Note that an origin without a suborgin will return the empty string.
  const std::string& suborigin() const { return suborigin_; }

  bool unique() const { return unique_; }

  // An ASCII serialization of the Origin as per Section 6.2 of RFC 6454, with
  // the addition that all Origins with a 'file' scheme serialize to "file://".
  // If the Origin has a suborigin, it will be serialized per
  // https://w3c.github.io/webappsec-suborigins/#serializing.
  std::string Serialize() const;

  // Returns the physical origin for Origin. If the suborigin is empty, this
  // will just return a copy of the Origin.  If it has a suborigin, will return
  // the Origin of just the scheme/host/port tuple, without the suborigin. See
  // https://w3c.github.io/webappsec-suborigins/.
  Origin GetPhysicalOrigin() const;

  // Two Origins are "same-origin" if their schemes, hosts, and ports are exact
  // matches; and neither is unique. If either of the origins have suborigins,
  // the suborigins also must be exact matches.
  bool IsSameOriginWith(const Origin& other) const;
  bool operator==(const Origin& other) const {
    return IsSameOriginWith(other);
  }

  // Same as above, but ignores suborigins if they exist.
  bool IsSamePhysicalOriginWith(const Origin& other) const;

  // Efficiently returns what GURL(Serialize()) would without re-parsing the
  // URL. This can be used for the (rare) times a GURL representation is needed
  // for an Origin.
  // Note: The returned URL will not necessarily be serialized to the same value
  // as the Origin would. The GURL will have an added "/" path for Origins with
  // valid SchemeHostPorts and file Origins.
  GURL GetURL() const;

  // Same as GURL::DomainIs. If |this| origin is unique, then returns false.
  bool DomainIs(base::StringPiece lower_ascii_domain) const;

  // Allows Origin to be used as a key in STL (for example, a std::set or
  // std::map).
  bool operator<(const Origin& other) const;

 private:
  Origin(base::StringPiece scheme,
         base::StringPiece host,
         uint16_t port,
         base::StringPiece suborigin,
         SchemeHostPort::ConstructPolicy policy);
  Origin(std::string scheme,
         std::string host,
         uint16_t port,
         std::string suborigin,
         SchemeHostPort::ConstructPolicy policy);

  SchemeHostPort tuple_;
  bool unique_;
  std::string suborigin_;
};

URL_EXPORT std::ostream& operator<<(std::ostream& out, const Origin& origin);

URL_EXPORT bool IsSameOriginWith(const GURL& a, const GURL& b);
URL_EXPORT bool IsSamePhysicalOriginWith(const GURL& a, const GURL& b);

}  // namespace url

#endif  // URL_ORIGIN_H_
