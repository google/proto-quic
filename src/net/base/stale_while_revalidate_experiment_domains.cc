// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/stale_while_revalidate_experiment_domains.h"

#include <stddef.h>

#include "base/logging.h"
#include "net/base/lookup_string_in_fixed_set.h"

namespace net {

namespace {

#include "net/base/stale_while_revalidate_experiment_domains-inc.cc"

// The maximum number of dots in any domain in the list. This is used to ignore
// parts of the host name that are irrelevant, and so must be correct.
const int kMaxDots = 2;

// The minimum number of dots in a host necessary for it to be considered a
// match.
const int kMinDots = 1;

bool LookupTail(const base::StringPiece& host, size_t pos) {
  DCHECK_LT(pos, host.size());
  return LookupStringInFixedSet(kDafsa, sizeof(kDafsa), host.data() + pos,
                                host.size() - pos) == 0;
}

bool LookupTrimmedHost(const base::StringPiece& trimmed) {
  // |trimmed| contains at least one non-dot. The maximum number of dots we want
  // to look for is kMaxInterestingDots; any dots before that will not affect
  // the outcome of the match.
  const int kMaxInterestingDots = kMaxDots + 1;

  // Scan |trimmed| from the right for up to kMaxInterestingDots dots, checking
  // for a domain match at each position.
  int found_dots = 0;
  size_t pos = base::StringPiece::npos;
  while (found_dots < kMaxInterestingDots) {
    pos = trimmed.find_last_of('.', pos);
    if (pos == base::StringPiece::npos)
      break;
    ++found_dots;
    if (found_dots > kMinDots && LookupTail(trimmed, pos + 1))
      return true;
    if (pos == 0)
      return false;
    --pos;
  }

  if (found_dots >= kMinDots && found_dots <= kMaxDots) {
    // We might have an exact match.
    return LookupTail(trimmed, 0);
  }

  return false;
}

}  // namespace

bool IsHostInStaleWhileRevalidateExperimentDomain(
    const base::StringPiece& host) {
  // Ignore trailing dots.
  size_t last_interesting_pos = host.find_last_not_of('.');
  if (last_interesting_pos == base::StringPiece::npos)
    return false;

  return LookupTrimmedHost(host.substr(0, last_interesting_pos + 1));
}

}  // namespace net
