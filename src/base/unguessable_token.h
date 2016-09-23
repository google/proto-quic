// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_UNGUESSABLE_TOKEN_H_
#define BASE_UNGUESSABLE_TOKEN_H_

#include <stdint.h>
#include <string.h>
#include <iosfwd>
#include <tuple>

#include "base/base_export.h"
#include "base/hash.h"
#include "base/logging.h"

namespace base {

struct UnguessableTokenHash;

// A UnguessableToken is an 128-bit token generated from a cryptographically
// strong random source.
//
// UnguessableToken should be used when a sensitive ID needs to be unguessable,
// and is shared across processes. It can be used as part of a larger aggregate
// type, or as an ID in and of itself.
//
// Use Create() for creating new UnguessableTokens.
//
// NOTE: It is illegal to send empty UnguessableTokens across processes, and
// sending/receiving empty tokens should be treated as a security issue.
// If there is a valid scenario for sending "no token" across processes,
// base::Optional should be used instead of an empty token.
class BASE_EXPORT UnguessableToken {
 public:
  // Create a unique UnguessableToken.
  static UnguessableToken Create();

  // Return a UnguessableToken built from the high/low bytes provided.
  // It should only be used in deserialization scenarios.
  //
  // NOTE: If the deserialized token is empty, it means that it was never
  // initialized via Create(). This is a security issue, and should be handled.
  static UnguessableToken Deserialize(uint64_t high, uint64_t low);

  // Creates an empty UnguessableToken.
  // Assign to it with Create() before using it.
  UnguessableToken() = default;

  // NOTE: Serializing an empty UnguessableToken is an illegal operation.
  uint64_t GetHighForSerialization() const {
    DCHECK(!is_empty());
    return high_;
  };

  // NOTE: Serializing an empty UnguessableToken is an illegal operation.
  uint64_t GetLowForSerialization() const {
    DCHECK(!is_empty());
    return low_;
  }

  bool is_empty() const { return high_ == 0 && low_ == 0; }

  std::string ToString() const;

  explicit operator bool() const { return !is_empty(); }

  bool operator<(const UnguessableToken& other) const {
    return std::tie(high_, low_) < std::tie(other.high_, other.low_);
  }

  bool operator==(const UnguessableToken& other) const {
    return high_ == other.high_ && low_ == other.low_;
  }

  bool operator!=(const UnguessableToken& other) const {
    return !(*this == other);
  }

 private:
  friend struct UnguessableTokenHash;
  UnguessableToken(uint64_t high, uint64_t low);

  // Note: Two uint64_t are used instead of uint8_t[16], in order to have a
  // simpler ToString() and is_empty().
  uint64_t high_ = 0;
  uint64_t low_ = 0;
};

BASE_EXPORT std::ostream& operator<<(std::ostream& out,
                                     const UnguessableToken& token);

// For use in std::unordered_map.
struct UnguessableTokenHash {
  size_t operator()(const base::UnguessableToken& token) const {
    DCHECK(token);
    return base::HashInts64(token.high_, token.low_);
  }
};

}  // namespace base

#endif  // BASE_UNGUESSABLE_TOKEN_H_
