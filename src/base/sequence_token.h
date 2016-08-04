// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_SEQUENCE_TOKEN_H_
#define BASE_SEQUENCE_TOKEN_H_

#include "base/base_export.h"
#include "base/macros.h"

namespace base {

// A token that identifies a series of sequenced tasks (i.e. tasks that run one
// at a time in posting order).
class BASE_EXPORT SequenceToken {
 public:
  // Instantiates an invalid SequenceToken.
  SequenceToken() = default;

  // Explicitly allow copy.
  SequenceToken(const SequenceToken& other) = default;
  SequenceToken& operator=(const SequenceToken& other) = default;

  // An invalid SequenceToken is not equal to any other SequenceToken, including
  // other invalid SequenceTokens.
  bool operator==(const SequenceToken& other) const;
  bool operator!=(const SequenceToken& other) const;

  // Returns true if this is a valid SequenceToken.
  bool IsValid() const;

  // Returns a valid SequenceToken which isn't equal to any previously returned
  // SequenceToken.
  static SequenceToken Create();

  // Returns the SequenceToken associated with the task running on the current
  // thread, as determined by the active ScopedSetSequenceTokenForCurrentThread
  // if any.
  static SequenceToken GetForCurrentThread();

 private:
  SequenceToken(int token) : token_(token) {}

  static constexpr int kInvalidSequenceToken = -1;
  int token_ = kInvalidSequenceToken;
};

// Throughout its lifetime, determines the value returned by
// SequenceToken::GetForCurrentThread().
class BASE_EXPORT ScopedSetSequenceTokenForCurrentThread {
 public:
  ScopedSetSequenceTokenForCurrentThread(const SequenceToken& token);
  ~ScopedSetSequenceTokenForCurrentThread();

 private:
  friend class SequenceToken;

  const SequenceToken token_;

  DISALLOW_COPY_AND_ASSIGN(ScopedSetSequenceTokenForCurrentThread);
};

}  // namespace base

#endif  // BASE_SEQUENCE_TOKEN_H_
