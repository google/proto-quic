// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/sdch_dictionary.h"

#include "base/time/clock.h"
#include "base/time/default_clock.h"
#include "base/values.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"

namespace {

bool DomainMatch(const GURL& gurl, const std::string& restriction) {
  // TODO(jar): This is not precisely a domain match definition.
  return gurl.DomainIs(restriction);
}

}  // namespace

namespace net {

SdchDictionary::SdchDictionary(const std::string& dictionary_text,
                               size_t offset,
                               const std::string& client_hash,
                               const std::string& server_hash,
                               const GURL& gurl,
                               const std::string& domain,
                               const std::string& path,
                               const base::Time& expiration,
                               const std::set<int>& ports)
    : text_(dictionary_text, offset),
      client_hash_(client_hash),
      server_hash_(server_hash),
      url_(gurl),
      domain_(domain),
      path_(path),
      expiration_(expiration),
      ports_(ports) {
}

SdchDictionary::SdchDictionary(const SdchDictionary& rhs)
    : text_(rhs.text_),
      client_hash_(rhs.client_hash_),
      server_hash_(rhs.server_hash_),
      url_(rhs.url_),
      domain_(rhs.domain_),
      path_(rhs.path_),
      expiration_(rhs.expiration_),
      ports_(rhs.ports_) {
}

SdchDictionary::~SdchDictionary() {
}

// Security functions restricting loads and use of dictionaries.

// static
SdchProblemCode SdchDictionary::CanSet(const std::string& domain,
                                       const std::string& path,
                                       const std::set<int>& ports,
                                       const GURL& dictionary_url) {
  /*
   * A dictionary is invalid and must not be stored if any of the following are
   * true:
   * 1. The dictionary has no Domain attribute.
   * 2. The effective host name that derives from the referer URL host name does
   *    not domain-match the Domain attribute.
   * 3. The Domain attribute is a top level domain.
   * 4. The referer URL host is a host domain name (not IP address) and has the
   *    form HD, where D is the value of the Domain attribute, and H is a string
   *    that contains one or more dots.
   * 5. If the dictionary has a Port attribute and the referer URL's port
   *    was not in the list.
   */

  // TODO(jar): Redirects in dictionary fetches might plausibly be problematic,
  // and hence the conservative approach is to not allow any redirects (if there
  // were any... then don't allow the dictionary to be set).

  if (domain.empty())
    return SDCH_DICTIONARY_MISSING_DOMAIN_SPECIFIER;  // Domain is required.

  if (registry_controlled_domains::GetDomainAndRegistry(
          domain, registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES)
          .empty()) {
    return SDCH_DICTIONARY_SPECIFIES_TOP_LEVEL_DOMAIN;  // domain was a TLD.
  }

  if (!DomainMatch(dictionary_url, domain))
    return SDCH_DICTIONARY_DOMAIN_NOT_MATCHING_SOURCE_URL;

  std::string referrer_url_host = dictionary_url.host();
  size_t postfix_domain_index = referrer_url_host.rfind(domain);
  // See if it is indeed a postfix, or just an internal string.
  if (referrer_url_host.size() == postfix_domain_index + domain.size()) {
    // It is a postfix... so check to see if there's a dot in the prefix.
    size_t end_of_host_index = referrer_url_host.find_first_of('.');
    if (referrer_url_host.npos != end_of_host_index &&
        end_of_host_index < postfix_domain_index) {
      return SDCH_DICTIONARY_REFERER_URL_HAS_DOT_IN_PREFIX;
    }
  }

  if (!ports.empty() && 0 == ports.count(dictionary_url.EffectiveIntPort()))
    return SDCH_DICTIONARY_PORT_NOT_MATCHING_SOURCE_URL;

  return SDCH_OK;
}

SdchProblemCode SdchDictionary::CanUse(const GURL& target_url) const {
  /*
   * 1. The request URL's host name domain-matches the Domain attribute of the
   *    dictionary.
   * 2. If the dictionary has a Port attribute, the request port is one of the
   *     ports listed in the Port attribute.
   * 3. The request URL path-matches the path attribute of the dictionary.
   *    We can override (ignore) item (4) only when we have explicitly enabled
   *    HTTPS support AND the dictionary acquisition scheme matches the target
   *   url scheme.
   */
  if (!DomainMatch(target_url, domain_))
    return SDCH_DICTIONARY_FOUND_HAS_WRONG_DOMAIN;

  if (!ports_.empty() && 0 == ports_.count(target_url.EffectiveIntPort()))
    return SDCH_DICTIONARY_FOUND_HAS_WRONG_PORT_LIST;

  if (path_.size() && !PathMatch(target_url.path(), path_))
    return SDCH_DICTIONARY_FOUND_HAS_WRONG_PATH;

  if (target_url.SchemeIsCryptographic() != url_.SchemeIsCryptographic())
    return SDCH_DICTIONARY_FOUND_HAS_WRONG_SCHEME;

  // TODO(jar): Remove overly restrictive failsafe test (added per security
  // review) when we have a need to be more general.
  if (!target_url.SchemeIsHTTPOrHTTPS())
    return SDCH_ATTEMPT_TO_DECODE_NON_HTTP_DATA;

  return SDCH_OK;
}

// static
bool SdchDictionary::PathMatch(const std::string& path,
                               const std::string& restriction) {
  /*  Must be either:
   *  1. P2 is equal to P1
   *  2. P2 is a prefix of P1 and either the final character in P2 is "/"
   *     or the character following P2 in P1 is "/".
   */
  if (path == restriction)
    return true;
  size_t prefix_length = restriction.size();
  if (prefix_length > path.size())
    return false;  // Can't be a prefix.
  if (0 != path.compare(0, prefix_length, restriction))
    return false;
  return restriction[prefix_length - 1] == '/' || path[prefix_length] == '/';
}

bool SdchDictionary::Expired() const {
  return base::Time::Now() > expiration_;
}

}  // namespace net
