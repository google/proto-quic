// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_SPAN_H_
#define BASE_SPAN_H_

#include <stddef.h>

#include <algorithm>

namespace base {

// A Span represents an array of elements of type T. It consists of a pointer to
// memory with an associated size. A Span does not own the underlying memory, so
// care must be taken to ensure that a Span does not outlive the backing store.
// Spans should be passed by value.
//
// Span is somewhat analogous to StringPiece, but with arbitrary element types,
// allowing mutation if T is non-const.
//
// TODO(https://crbug.com/754077): Document differences from the working group
// proposal: http://open-std.org/JTC1/SC22/WG21/docs/papers/2016/p0122r1.pdf.
// TODO(https://crbug.com/754077): Implement more Span support, such as
// initialization from containers, and document why this is useful (greater
// safety since no need to manually pass in data + size)
template <typename T>
class Span {
 public:
  using element_type = T;
  using pointer = T*;
  using reference = T&;
  using iterator = T*;
  using const_iterator = const T*;
  // TODO(dcheng): What about reverse iterators?

  constexpr Span() noexcept : data_(nullptr), size_(0) {}
  constexpr Span(T* data, size_t size) noexcept : data_(data), size_(size) {}
  template <size_t N>
  constexpr Span(T (&array)[N]) noexcept : data_(array), size_(N) {}

  // Span subviews
  constexpr Span subspan(size_t pos, size_t count) const {
    // Note: ideally this would DCHECK, but it requires fairly horrible
    // contortions.
    return Span(data_ + pos, count);
  }

  // Span observers
  constexpr size_t size() const noexcept { return size_; }

  // Span element access
  constexpr T& operator[](size_t index) const noexcept { return data_[index]; }
  constexpr T* data() const noexcept { return data_; }

  // Span iterator support
  iterator begin() const noexcept { return data_; }
  iterator end() const noexcept { return data_ + size_; }

  const_iterator cbegin() const noexcept { return begin(); }
  const_iterator cend() const noexcept { return end(); }

 private:
  T* data_;
  size_t size_;
};

// Relational operators. Equality is a element-wise comparison.
template <typename T>
constexpr bool operator==(const Span<T>& lhs, const Span<T>& rhs) noexcept {
  return std::equal(lhs.cbegin(), lhs.cend(), rhs.cbegin(), rhs.cend());
}

template <typename T>
constexpr bool operator!=(const Span<T>& lhs, const Span<T>& rhs) noexcept {
  return !(lhs == rhs);
}

// TODO(dcheng): Implement other relational operators.

// Type-deducing helpers for constructing a Span.
template <typename T>
constexpr Span<T> MakeSpan(T* data, size_t size) noexcept {
  return Span<T>(data, size);
}

template <typename T, size_t N>
constexpr Span<T> MakeSpan(T (&array)[N]) noexcept {
  return Span<T>(array);
}

}  // namespace base

#endif  // BASE_SPAN_H_
