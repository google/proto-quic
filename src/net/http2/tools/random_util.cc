// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/tools/random_util.h"

#include <cmath>

#include "net/http2/tools/http2_random.h"

using std::string;
using base::StringPiece;

namespace net {
namespace test {

const char kWebsafe64[] =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";

string RandomString(RandomBase* rng, int len, StringPiece alphabet) {
  string random_string;
  random_string.reserve(len);
  for (int i = 0; i < len; ++i)
    random_string.push_back(alphabet[rng->Uniform(alphabet.size())]);
  return random_string;
}

size_t GenerateUniformInRange(size_t lo, size_t hi, RandomBase* rng) {
  if (lo + 1 >= hi) {
    return lo;
  }
  return lo + rng->Rand64() % (hi - lo);
}

// Here "word" means something that starts with a lower-case letter, and has
// zero or more additional characters that are numbers or lower-case letters.
string GenerateHttp2HeaderName(size_t len, RandomBase* rng) {
  StringPiece alpha_lc = "abcdefghijklmnopqrstuvwxyz";
  // If the name is short, just make it one word.
  if (len < 8) {
    return RandomString(rng, len, alpha_lc);
  }
  // If the name is longer, ensure it starts with a word, and after that may
  // have any character in alphanumdash_lc. 4 is arbitrary, could be as low
  // as 1.
  StringPiece alphanumdash_lc = "abcdefghijklmnopqrstuvwxyz0123456789-";
  return RandomString(rng, 4, alpha_lc) +
         RandomString(rng, len - 4, alphanumdash_lc);
}

string GenerateWebSafeString(size_t len, RandomBase* rng) {
  return RandomString(rng, len, kWebsafe64);
}

string GenerateWebSafeString(size_t lo, size_t hi, RandomBase* rng) {
  return GenerateWebSafeString(GenerateUniformInRange(lo, hi, rng), rng);
}

}  // namespace test
}  // namespace net
