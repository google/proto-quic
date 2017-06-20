// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

namespace std {

// This is the move that should be flagged. Representes the unary std::move.
template <typename T>
T move(T t) {
  return t;
}

// This represents the algorithm std::move, it should not be flagged.
template <class InputIt, class OutputIt>
OutputIt move(InputIt first, InputIt last, OutputIt d_first) {
  return d_first;
}

}  // namespace std

// This represents some non-std move. It should not be flagged.
template <typename T>
T move(T t) {
  return t;
}

void Test() {
  int x = 3;

  // Should not be flagged: x is not a pointer.
  int y = std::move(x);

  int* p = &x;

  // Calling std::move on a raw pointer should be flagged.
  int* q = std::move(p);

  // Calling non-std move should not be flagged.
  q = move(p);
}
