// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_HASH_VALUE_H_
#define NET_BASE_HASH_VALUE_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <string>
#include <vector>

#include "base/strings/string_piece.h"
#include "build/build_config.h"
#include "net/base/net_export.h"

namespace net {

struct NET_EXPORT SHA1HashValue {
  bool Equals(const SHA1HashValue& other) const;

  unsigned char data[20];
};

struct NET_EXPORT SHA256HashValue {
  bool Equals(const SHA256HashValue& other) const;

  unsigned char data[32];
};

enum HashValueTag {
  HASH_VALUE_SHA1,
  HASH_VALUE_SHA256,
};

class NET_EXPORT HashValue {
 public:
  explicit HashValue(const SHA1HashValue& hash);
  explicit HashValue(const SHA256HashValue& hash);
  explicit HashValue(HashValueTag tag) : tag(tag) {}
  HashValue() : tag(HASH_VALUE_SHA1) {}

  // Check for equality of hash values
  // This function may have VARIABLE timing which leaks information
  // about its inputs.  For example it may exit early once a
  // nonequal character is discovered.  Thus, for security reasons
  // this function MUST NOT be used with secret values (such as
  // password hashes, MAC tags, etc.)
  bool Equals(const HashValue& other) const;

  // Serializes/Deserializes hashes in the form of
  // <hash-name>"/"<base64-hash-value>
  // (eg: "sha1/...")
  // This format may be persisted to permanent storage, so
  // care should be taken before changing the serialization.
  //
  // This format is used for:
  //   - net_internals display/setting public-key pins
  //   - logging public-key pins
  //   - serializing public-key pins

  // Deserializes a HashValue from a string. On error, returns
  // false and MAY change the contents of HashValue to contain invalid data.
  bool FromString(const base::StringPiece input);

  // Serializes the HashValue to a string. If an invalid HashValue
  // is supplied (eg: an unknown hash tag), returns "unknown"/<base64>
  std::string ToString() const;

  size_t size() const;
  unsigned char* data();
  const unsigned char* data() const;

  HashValueTag tag;

 private:
  union {
    SHA1HashValue sha1;
    SHA256HashValue sha256;
  } fingerprint;
};

typedef std::vector<HashValue> HashValueVector;


class SHA1HashValueLessThan {
 public:
  bool operator()(const SHA1HashValue& lhs,
                  const SHA1HashValue& rhs) const {
    return memcmp(lhs.data, rhs.data, sizeof(lhs.data)) < 0;
  }
};

class SHA256HashValueLessThan {
 public:
  bool operator()(const SHA256HashValue& lhs,
                  const SHA256HashValue& rhs) const {
    return memcmp(lhs.data, rhs.data, sizeof(lhs.data)) < 0;
  }
};

class HashValuesEqual {
  public:
  explicit HashValuesEqual(const HashValue& fingerprint) :
      fingerprint_(fingerprint) {}

  bool operator()(const HashValue& other) const {
    return fingerprint_.Equals(other);
  }

  const HashValue& fingerprint_;
};

// IsSHA256HashInSortedArray returns true iff |hash| is in |array|, a sorted
// array of SHA256 hashes.
bool IsSHA256HashInSortedArray(const SHA256HashValue& hash,
                               const uint8_t* array,
                               size_t array_byte_len);

}  // namespace net

#endif  // NET_BASE_HASH_VALUE_H_
