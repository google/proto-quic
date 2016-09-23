// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_STALE_WHILE_REVALIDATE_EXPERIMENT_DOMAINS_H_
#define NET_BASE_STALE_WHILE_REVALIDATE_EXPERIMENT_DOMAINS_H_

#include "base/strings/string_piece.h"

namespace net {

// Returns true if |host| matches one of the domains of interest for
// stale-while-revalidate histograms. If "example.com" was in the list, then
// "example.com" would match, as would "www.example.com" and "a.b.example.com",
// but not "com" or "an-example.com". Trailing '.' characters on |host| are
// ignored. |host| is expected to be canonicalised to lowercase (as performed by
// GURL).
// TODO(ricea): Remove this in April 2016 or before. crbug.com/348877
bool IsHostInStaleWhileRevalidateExperimentDomain(
    const base::StringPiece& host);

}  // namespace net

#endif  // NET_BASE_STALE_WHILE_REVALIDATE_EXPERIMENT_DOMAINS_H_
