// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_CONTAINERS_CONTAINER_TEST_UTILS_H_
#define BASE_CONTAINERS_CONTAINER_TEST_UTILS_H_

// This file contains some helper classes for testing conainer behavior.

#include "base/macros.h"

namespace base {

// A move-only class that holds an integer.
class MoveOnlyInt {
 public:
  explicit MoveOnlyInt(int data = 1) : data_(data) {}
  MoveOnlyInt(MoveOnlyInt&& other) : data_(other.data_) { other.data_ = 0; }
  MoveOnlyInt& operator=(MoveOnlyInt&& other) {
    data_ = other.data_;
    other.data_ = 0;
    return *this;
  }

  friend bool operator==(const MoveOnlyInt& lhs, const MoveOnlyInt& rhs) {
    return lhs.data_ == rhs.data_;
  }

  friend bool operator!=(const MoveOnlyInt& lhs, const MoveOnlyInt& rhs) {
    return !operator==(lhs, rhs);
  }

  friend bool operator<(const MoveOnlyInt& lhs, const MoveOnlyInt& rhs) {
    return lhs.data_ < rhs.data_;
  }

  friend bool operator>(const MoveOnlyInt& lhs, const MoveOnlyInt& rhs) {
    return rhs < lhs;
  }

  friend bool operator<=(const MoveOnlyInt& lhs, const MoveOnlyInt& rhs) {
    return !(rhs < lhs);
  }

  friend bool operator>=(const MoveOnlyInt& lhs, const MoveOnlyInt& rhs) {
    return !(lhs < rhs);
  }

  int data() const { return data_; }

 private:
  int data_;

  DISALLOW_COPY_AND_ASSIGN(MoveOnlyInt);
};

}  // namespace base

#endif  // BASE_CONTAINERS_CONTAINER_TEST_UTILS_H_
