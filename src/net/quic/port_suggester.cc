// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/port_suggester.h"

#include "base/logging.h"

namespace net {

PortSuggester::PortSuggester(const HostPortPair& server, uint64_t seed)
    : call_count_(0), previous_suggestion_(-1) {
  unsigned char hash_bytes[base::kSHA1Length];
  base::SHA1HashBytes(
      reinterpret_cast<const unsigned char*>(server.host().data()),
      server.host().length(), hash_bytes);
  static_assert(sizeof(seed_) < sizeof(hash_bytes), "seed larger than hash");
  memcpy(&seed_, hash_bytes, sizeof(seed_));
  seed_ ^= seed ^ server.port();
}

int PortSuggester::SuggestPort(int min, int max) {
  // Sometimes our suggestion can't be used, so we ensure that if additional
  // calls are made, then each call (probably) provides a new suggestion.
  if (++call_count_ > 1) {
    // Evolve the seed.
    unsigned char hash_bytes[base::kSHA1Length];
    base::SHA1HashBytes(reinterpret_cast<const unsigned char*>(&seed_),
                        sizeof(seed_), hash_bytes);
    memcpy(&seed_, hash_bytes, sizeof(seed_));
  }
  DCHECK_LE(min, max);
  DCHECK_GT(min, 0);
  int range = max - min + 1;
  // Ports (and hence the extent of the |range|) are generally under 2^16, so
  // the tiny non-uniformity in the pseudo-random distribution is not
  // significant.
  previous_suggestion_ = static_cast<int>(seed_ % range) + min;
  return previous_suggestion_;
}

int PortSuggester::previous_suggestion() const {
  DCHECK_LT(0u, call_count_);
  return previous_suggestion_;
}

}  // namespace net
