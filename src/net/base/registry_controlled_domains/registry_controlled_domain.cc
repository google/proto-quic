// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// NB: Modelled after Mozilla's code (originally written by Pamela Greene,
// later modified by others), but almost entirely rewritten for Chrome.
//   (netwerk/dns/src/nsEffectiveTLDService.cpp)
/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is Mozilla Effective-TLD Service
 *
 * The Initial Developer of the Original Code is
 * Google Inc.
 * Portions created by the Initial Developer are Copyright (C) 2006
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Pamela Greene <pamg.bugs@gmail.com> (original author)
 *   Daniel Witte <dwitte@stanford.edu>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#include "net/base/registry_controlled_domains/registry_controlled_domain.h"

#include "base/logging.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "net/base/lookup_string_in_fixed_set.h"
#include "net/base/net_module.h"
#include "net/base/url_util.h"
#include "url/gurl.h"
#include "url/origin.h"
#include "url/third_party/mozilla/url_parse.h"
#include "url/url_util.h"

namespace net {
namespace registry_controlled_domains {

namespace {
#include "net/base/registry_controlled_domains/effective_tld_names-inc.cc"

// See make_dafsa.py for documentation of the generated dafsa byte array.

const unsigned char* g_graph = kDafsa;
size_t g_graph_length = sizeof(kDafsa);

struct MappedHostComponent {
  size_t original_begin;
  size_t original_end;

  size_t canonical_begin;
  size_t canonical_end;
};

size_t GetRegistryLengthImpl(base::StringPiece host,
                             UnknownRegistryFilter unknown_filter,
                             PrivateRegistryFilter private_filter) {
  if (host.empty())
    return std::string::npos;

  // Skip leading dots.
  const size_t host_check_begin = host.find_first_not_of('.');
  if (host_check_begin == std::string::npos)
    return 0;  // Host is only dots.

  // A single trailing dot isn't relevant in this determination, but does need
  // to be included in the final returned length.
  size_t host_check_len = host.length();
  if (host[host_check_len - 1] == '.') {
    --host_check_len;
    DCHECK(host_check_len > 0);  // If this weren't true, the host would be ".",
                                 // and we'd have already returned above.
    if (host[host_check_len - 1] == '.')
      return 0;  // Multiple trailing dots.
  }

  // Walk up the domain tree, most specific to least specific,
  // looking for matches at each level.
  size_t prev_start = std::string::npos;
  size_t curr_start = host_check_begin;
  size_t next_dot = host.find('.', curr_start);
  if (next_dot >= host_check_len)  // Catches std::string::npos as well.
    return 0;  // This can't have a registry + domain.
  while (1) {
    const char* domain_str = host.data() + curr_start;
    size_t domain_length = host_check_len - curr_start;
    int type = LookupStringInFixedSet(g_graph, g_graph_length, domain_str,
                                      domain_length);
    bool do_check = type != kDafsaNotFound &&
                    (!(type & kDafsaPrivateRule) ||
                     private_filter == INCLUDE_PRIVATE_REGISTRIES);

    // If the apparent match is a private registry and we're not including
    // those, it can't be an actual match.
    if (do_check) {
      // Exception rules override wildcard rules when the domain is an exact
      // match, but wildcards take precedence when there's a subdomain.
      if (type & kDafsaWildcardRule && (prev_start != std::string::npos)) {
        // If prev_start == host_check_begin, then the host is the registry
        // itself, so return 0.
        return (prev_start == host_check_begin) ? 0
                                                : (host.length() - prev_start);
      }

      if (type & kDafsaExceptionRule) {
        if (next_dot == std::string::npos) {
          // If we get here, we had an exception rule with no dots (e.g.
          // "!foo").  This would only be valid if we had a corresponding
          // wildcard rule, which would have to be "*".  But we explicitly
          // disallow that case, so this kind of rule is invalid.
          NOTREACHED() << "Invalid exception rule";
          return 0;
        }
        return host.length() - next_dot - 1;
      }

      // If curr_start == host_check_begin, then the host is the registry
      // itself, so return 0.
      return (curr_start == host_check_begin) ? 0
                                              : (host.length() - curr_start);
    }

    if (next_dot >= host_check_len)  // Catches std::string::npos as well.
      break;

    prev_start = curr_start;
    curr_start = next_dot + 1;
    next_dot = host.find('.', curr_start);
  }

  // No rule found in the registry.  curr_start now points to the first
  // character of the last subcomponent of the host, so if we allow unknown
  // registries, return the length of this subcomponent.
  return unknown_filter == INCLUDE_UNKNOWN_REGISTRIES ?
      (host.length() - curr_start) : 0;
}

base::StringPiece GetDomainAndRegistryImpl(
    base::StringPiece host,
    PrivateRegistryFilter private_filter) {
  DCHECK(!host.empty());

  // Find the length of the registry for this host.
  const size_t registry_length =
      GetRegistryLengthImpl(host, INCLUDE_UNKNOWN_REGISTRIES, private_filter);
  if ((registry_length == std::string::npos) || (registry_length == 0))
    return base::StringPiece();  // No registry.
  // The "2" in this next line is 1 for the dot, plus a 1-char minimum preceding
  // subcomponent length.
  DCHECK(host.length() >= 2);
  if (registry_length > (host.length() - 2)) {
    NOTREACHED() <<
        "Host does not have at least one subcomponent before registry!";
    return base::StringPiece();
  }

  // Move past the dot preceding the registry, and search for the next previous
  // dot.  Return the host from after that dot, or the whole host when there is
  // no dot.
  const size_t dot = host.rfind('.', host.length() - registry_length - 2);
  if (dot == std::string::npos)
    return host;
  return host.substr(dot + 1);
}

// Same as GetDomainAndRegistry, but returns the domain and registry as a
// StringPiece that references the underlying string of the passed-in |gurl|.
// TODO(pkalinnikov): Eliminate this helper by exposing StringPiece as the
// interface type for all the APIs.
base::StringPiece GetDomainAndRegistryAsStringPiece(
    base::StringPiece host,
    PrivateRegistryFilter filter) {
  if (host.empty() || url::HostIsIPAddress(host))
    return base::StringPiece();
  return GetDomainAndRegistryImpl(host, filter);
}

// These two functions append the given string as-is to the given output,
// converting to UTF-8 if necessary.
void AppendInvalidString(base::StringPiece str, url::CanonOutput* output) {
  output->Append(str.data(), static_cast<int>(str.length()));
}
void AppendInvalidString(base::StringPiece16 str, url::CanonOutput* output) {
  std::string utf8 = base::UTF16ToUTF8(str);
  output->Append(utf8.data(), static_cast<int>(utf8.length()));
}

// Backend for PermissiveGetHostRegistryLength that handles both UTF-8 and
// UTF-16 input. The template type is the std::string type to use (it makes the
// typedefs easier than using the character type).
template <typename Str>
size_t DoPermissiveGetHostRegistryLength(base::BasicStringPiece<Str> host,
                                         UnknownRegistryFilter unknown_filter,
                                         PrivateRegistryFilter private_filter) {
  std::string canonical_host;  // Do not modify outside of canon_output.
  canonical_host.reserve(host.length());
  url::StdStringCanonOutput canon_output(&canonical_host);

  std::vector<MappedHostComponent> components;

  for (size_t current = 0; current < host.length(); current++) {
    size_t begin = current;

    // Advance to next "." or end.
    current = host.find('.', begin);
    if (current == std::string::npos)
      current = host.length();

    MappedHostComponent mapping;
    mapping.original_begin = begin;
    mapping.original_end = current;
    mapping.canonical_begin = static_cast<size_t>(canon_output.length());

    // Try to append the canonicalized version of this component.
    int current_len = static_cast<int>(current - begin);
    if (!url::CanonicalizeHostSubstring(
            host.data(), url::Component(static_cast<int>(begin), current_len),
            &canon_output)) {
      // Failed to canonicalize this component; append as-is.
      AppendInvalidString(host.substr(begin, current_len), &canon_output);
    }

    mapping.canonical_end = static_cast<size_t>(canon_output.length());
    components.push_back(mapping);

    if (current < host.length())
      canon_output.push_back('.');
  }
  canon_output.Complete();

  size_t canonical_rcd_len =
      GetRegistryLengthImpl(canonical_host, unknown_filter, private_filter);
  if (canonical_rcd_len == 0 || canonical_rcd_len == std::string::npos)
    return canonical_rcd_len;  // Error or no registry controlled domain.

  // Find which host component the result started in.
  size_t canonical_rcd_begin = canonical_host.length() - canonical_rcd_len;
  for (const auto& mapping : components) {
    // In the common case, GetRegistryLengthImpl will identify the beginning
    // of a component and we can just return where that component was in the
    // original string.
    if (canonical_rcd_begin == mapping.canonical_begin)
      return host.length() - mapping.original_begin;

    if (canonical_rcd_begin >= mapping.canonical_end)
      continue;

    // The registry controlled domain begin was identified as being in the
    // middle of this dot-separated domain component in the non-canonical
    // input. This indicates some form of escaped dot, or a non-ASCII
    // character that was canonicalized to a dot.
    //
    // Brute-force search from the end by repeatedly canonicalizing longer
    // substrings until we get a match for the canonicalized version. This
    // can't be done with binary search because canonicalization might increase
    // or decrease the length of the produced string depending on where it's
    // split. This depends on the canonicalization process not changing the
    // order of the characters. Punycode can change the order of characters,
    // but it doesn't work across dots so this is safe.

    // Expected canonical registry controlled domain.
    base::StringPiece canonical_rcd(&canonical_host[canonical_rcd_begin],
                                    canonical_rcd_len);

    for (int current_try = static_cast<int>(mapping.original_end) - 1;
         current_try >= static_cast<int>(mapping.original_begin);
         current_try--) {
      std::string try_string;
      url::StdStringCanonOutput try_output(&try_string);

      if (!url::CanonicalizeHostSubstring(
              host.data(),
              url::Component(
                  current_try,
                  static_cast<int>(mapping.original_end) - current_try),
              &try_output))
        continue;  // Invalid substring, skip.

      try_output.Complete();
      if (try_string == canonical_rcd)
        return host.length() - current_try;
    }
  }

  NOTREACHED();
  return canonical_rcd_len;
}

bool SameDomainOrHost(base::StringPiece host1,
                      base::StringPiece host2,
                      PrivateRegistryFilter filter) {
  // Quickly reject cases where either host is empty.
  if (host1.empty() || host2.empty())
    return false;

  // Check for exact host matches, which is faster than looking up the domain
  // and registry.
  if (host1 == host2)
    return true;

  // Check for a domain and registry match.
  const base::StringPiece& domain1 =
      GetDomainAndRegistryAsStringPiece(host1, filter);
  return !domain1.empty() &&
         (domain1 == GetDomainAndRegistryAsStringPiece(host2, filter));
}

}  // namespace

std::string GetDomainAndRegistry(const GURL& gurl,
                                 PrivateRegistryFilter filter) {
  return GetDomainAndRegistryAsStringPiece(gurl.host_piece(), filter)
      .as_string();
}

std::string GetDomainAndRegistry(base::StringPiece host,
                                 PrivateRegistryFilter filter) {
  url::CanonHostInfo host_info;
  const std::string canon_host(CanonicalizeHost(host, &host_info));
  if (canon_host.empty() || host_info.IsIPAddress())
    return std::string();
  return GetDomainAndRegistryImpl(canon_host, filter).as_string();
}

bool SameDomainOrHost(
    const GURL& gurl1,
    const GURL& gurl2,
    PrivateRegistryFilter filter) {
  return SameDomainOrHost(gurl1.host_piece(), gurl2.host_piece(), filter);
}

bool SameDomainOrHost(const url::Origin& origin1,
                      const url::Origin& origin2,
                      PrivateRegistryFilter filter) {
  return SameDomainOrHost(origin1.host(), origin2.host(), filter);
}

bool SameDomainOrHost(const url::Origin& origin1,
                      const base::Optional<url::Origin>& origin2,
                      PrivateRegistryFilter filter) {
  return origin2.has_value() &&
         SameDomainOrHost(origin1, origin2.value(), filter);
}

bool SameDomainOrHost(const GURL& gurl,
                      const url::Origin& origin,
                      PrivateRegistryFilter filter) {
  return SameDomainOrHost(gurl.host_piece(), origin.host(), filter);
}

size_t GetRegistryLength(
    const GURL& gurl,
    UnknownRegistryFilter unknown_filter,
    PrivateRegistryFilter private_filter) {
  return GetRegistryLengthImpl(gurl.host_piece(), unknown_filter,
                               private_filter);
}

bool HostHasRegistryControlledDomain(base::StringPiece host,
                                     UnknownRegistryFilter unknown_filter,
                                     PrivateRegistryFilter private_filter) {
  url::CanonHostInfo host_info;
  const std::string canon_host(CanonicalizeHost(host, &host_info));

  size_t rcd_length;
  switch (host_info.family) {
    case url::CanonHostInfo::IPV4:
    case url::CanonHostInfo::IPV6:
      // IP addresses don't have R.C.D.'s.
      return false;
    case url::CanonHostInfo::BROKEN:
      // Host is not canonicalizable. Fall back to the slower "permissive"
      // version.
      rcd_length =
          PermissiveGetHostRegistryLength(host, unknown_filter, private_filter);
      break;
    case url::CanonHostInfo::NEUTRAL:
      rcd_length =
          GetRegistryLengthImpl(canon_host, unknown_filter, private_filter);
      break;
    default:
      NOTREACHED();
      return false;
  }
  return (rcd_length != 0) && (rcd_length != std::string::npos);
}

size_t GetCanonicalHostRegistryLength(base::StringPiece canon_host,
                                      UnknownRegistryFilter unknown_filter,
                                      PrivateRegistryFilter private_filter) {
#ifndef NDEBUG
  // Ensure passed-in host name is canonical.
  url::CanonHostInfo host_info;
  DCHECK_EQ(net::CanonicalizeHost(canon_host, &host_info), canon_host);
#endif

  return GetRegistryLengthImpl(canon_host, unknown_filter, private_filter);
}

size_t PermissiveGetHostRegistryLength(base::StringPiece host,
                                       UnknownRegistryFilter unknown_filter,
                                       PrivateRegistryFilter private_filter) {
  return DoPermissiveGetHostRegistryLength<std::string>(host, unknown_filter,
                                                        private_filter);
}

size_t PermissiveGetHostRegistryLength(base::StringPiece16 host,
                                       UnknownRegistryFilter unknown_filter,
                                       PrivateRegistryFilter private_filter) {
  return DoPermissiveGetHostRegistryLength<base::string16>(host, unknown_filter,
                                                           private_filter);
}

void SetFindDomainGraph() {
  g_graph = kDafsa;
  g_graph_length = sizeof(kDafsa);
}

void SetFindDomainGraph(const unsigned char* domains, size_t length) {
  CHECK(domains);
  CHECK_NE(length, 0u);
  g_graph = domains;
  g_graph_length = length;
}

}  // namespace registry_controlled_domains
}  // namespace net
