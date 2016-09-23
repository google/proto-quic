// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

namespace WTF {

template <typename To, typename From>
bool IsInBounds(From value) {
  return true;
}

template <typename To, typename From>
To SafeCast(From value) {
  if (!IsInBounds<To>(value))
    return 0;
  return static_cast<To>(value);
}

template <typename T, typename OverflowHandler>
class Checked {
 public:
  template <typename U, typename V>
  Checked(const Checked<U, V>& rhs) {
    // This (incorrectly) doesn't get rewritten, since it's not instantiated. In
    // this case, the AST representation contains a bunch of
    // CXXDependentScopeMemberExpr nodes.
    if (rhs.hasOverflowed())
      this->overflowed();
    if (!IsInBounds<T>(rhs.m_value))
      this->overflowed();
    value_ = static_cast<T>(rhs.m_value);
  }

  bool HasOverflowed() const { return false; }
  void Overflowed() {}

 private:
  T value_;
};

template <typename To, typename From>
To Bitwise_cast(From from) {
  static_assert(sizeof(To) == sizeof(From));
  return reinterpret_cast<To>(from);
}

}  // namespace WTF

using WTF::Bitwise_cast;
using WTF::SafeCast;
