// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_CONTAINERS_FLAT_SET_H_
#define BASE_CONTAINERS_FLAT_SET_H_

#include <algorithm>
#include <functional>
#include <utility>
#include <vector>

namespace base {

// Overview:
// This file implements flat_set container. It is an alternative to standard
// sorted containers that stores it's elements in contiguous memory (current
// version uses sorted std::vector).
// Discussion that preceded introduction of this container can be found here:
// https://groups.google.com/a/chromium.org/forum/#!searchin/chromium-dev/vector$20based/chromium-dev/4uQMma9vj9w/HaQ-WvMOAwAJ
//
// Motivation:
// Contiguous memory is very beneficial to iteration and copy speed at the cost
// of worse algorithmic complexity of insertion/erasure operations. They can
// be very fast for set operations and for small number of elements.
//
// Usage guidance:
// Prefer base::flat_set for:
//  * Very small sets, something that is an easy fit for cache. Consider
//    "very small" to be under a 100 32bit integers.
//  * Sets that are built once (using flat_set::flat_set(first, last)). Consider
//    collecting all data in a vector and then building flat_set out of it.
//    TODO(dyaroshev): improve the interface to better support this pattern
//    (crbug.com/682254).
//  * Sets where mutating happens in big bulks: use erase(std::remove()) idiom
//    for erasing many elements. Insertion is harder - consider set operations
//    or building a new vector. Set operations can be slow if one of the sets
//    is considerably bigger. Also be aware that beating performance of
//    sort + unique (implementation of flat_set's constructor) is hard, clever
//    merge of many sets might not win. Generally avoid inserting into flat set
//    without benchmarks.
//  * Copying and iterating.
//  * Set operations (union/intersect etc).
//
// Prefer to build a new flat_set from a std::vector (or similar) instead of
// calling insert() repeatedly, which would have O(size^2) complexity.
//
// TODO(dyaroshev): develop standalone benchmarks to find performance boundaries
// for different types of sets crbug.com/682215.
//
// If you do write a benchmark that significantly depends on using sets please
// share your results at:
// https://groups.google.com/a/chromium.org/forum/#!searchin/chromium-dev/vector$20based/chromium-dev/4uQMma9vj9w/HaQ-WvMOAwAJ
//
// Important usability aspects:
//   * flat_set implements std::set interface from C++11 where possible. It
//     also has reserve(), capacity() and shrink_to_fit() from std::vector.
//   * iteration invalidation rules differ:
//     - all cases of std::vector::iterator invalidation also apply.
//     - we ask (for now) to assume that move operations invalidate iterators.
//       TODO(dyaroshev): Research the possibility of using a small buffer
//       optimization crbug.com/682240.
//   * Constructor sorts elements in a non-stable manner (unlike std::set). So
//     among equivalent (with respect to provided compare) elements passed to
//     the constructor it is unspecified with one will end up in the set.
//     However insert()/emplace() methods are stable with respect to already
//     inserted elements - an element that is already in the set will not be
//     replaced.
//   * allocator support is not implemented.
//   * insert(first, last) and insert(std::initializer_list) are not
//     implemented (see Notes section).
//
// Notes:
// Current implementation is based on boost::containers::flat_set,
// eastl::vector_set and folly::sorted_vector. All of these implementations do
// insert(first, last) as insertion one by one (some implementations with hints
// and/or reserve). Boost documentation claims this algorithm to be O(n*log(n))
// but it seems to be a quadratic algorithm. For now we do not implement this
// method.
// TODO(dyaroshev): research an algorithm for range insertion crbug.com/682249.

template <class Key, class Compare = std::less<Key>>
// Meets the requirements of Container, AssociativeContainer,
// ReversibleContainer.
// Requires: Key is Movable, Compare is a StrictWeakOrdering on Key.
class flat_set {
 private:
  using underlying_type = std::vector<Key>;

 public:
  // --------------------------------------------------------------------------
  // Types.
  //
  using key_type = Key;
  using key_compare = Compare;
  using value_type = Key;
  using value_compare = Compare;

  using pointer = typename underlying_type::pointer;
  using const_pointer = typename underlying_type::const_pointer;
  using reference = typename underlying_type::reference;
  using const_reference = typename underlying_type::const_reference;
  using size_type = typename underlying_type::size_type;
  using difference_type = typename underlying_type::difference_type;
  using iterator = typename underlying_type::iterator;
  using const_iterator = typename underlying_type::const_iterator;
  using reverse_iterator = typename underlying_type::reverse_iterator;
  using const_reverse_iterator =
      typename underlying_type::const_reverse_iterator;

  // --------------------------------------------------------------------------
  // Lifetime.
  //
  // Constructors that take range guarantee O(N * log^2(N)) + O(N) complexity
  // and take O(N * log(N)) + O(N) if extra memory is available (N is a range
  // length).
  //
  // Assume that move constructors invalidate iterators and references.

  flat_set();
  explicit flat_set(const Compare& comp);

  template <class InputIterator>
  flat_set(InputIterator first,
           InputIterator last,
           const Compare& comp = Compare());

  flat_set(const flat_set&);
  flat_set(flat_set&&);

  flat_set(std::initializer_list<value_type> ilist,
           const Compare& comp = Compare());

  ~flat_set();

  // --------------------------------------------------------------------------
  // Assignments.
  //
  // Assume that move assignment invalidates iterators and references.

  flat_set& operator=(const flat_set&);
  flat_set& operator=(flat_set&&);
  flat_set& operator=(std::initializer_list<value_type> ilist);

  // --------------------------------------------------------------------------
  // Memory management.
  //
  // Beware that shrink_to_fit() simply forwards the request to the
  // underlying_type and its implementation is free to optimize otherwise and
  // leave capacity() to be greater that its size.
  //
  // reserve() and shrink_to_fit() invalidate iterators and references.

  void reserve(size_type new_capacity);
  size_type capacity() const;
  void shrink_to_fit();

  // --------------------------------------------------------------------------
  // Size management.
  //
  // clear() leaves the capacity() of the flat_set unchanged.

  void clear();

  size_type size() const;
  size_type max_size() const;
  bool empty() const;

  // --------------------------------------------------------------------------
  // Iterators.

  iterator begin();
  const_iterator begin() const;
  const_iterator cbegin() const;

  iterator end();
  const_iterator end() const;
  const_iterator cend() const;

  reverse_iterator rbegin();
  const_reverse_iterator rbegin() const;
  const_reverse_iterator crbegin() const;

  reverse_iterator rend();
  const_reverse_iterator rend() const;
  const_reverse_iterator crend() const;

  // --------------------------------------------------------------------------
  // Insert operations.
  //
  // Assume that every operation invalidates iterators and references.
  // Insertion of one element can take O(size). See the Notes section in the
  // class comments on why we do not currently implement range insertion.
  // Capacity of flat_set grows in an implementation-defined manner.
  //
  // NOTE: Prefer to build a new flat_set from a std::vector (or similar)
  // instead of calling insert() repeatedly.

  std::pair<iterator, bool> insert(const value_type& val);
  std::pair<iterator, bool> insert(value_type&& val);

  iterator insert(const_iterator position_hint, const value_type& x);
  iterator insert(const_iterator position_hint, value_type&& x);

  template <class... Args>
  std::pair<iterator, bool> emplace(Args&&... args);

  template <class... Args>
  iterator emplace_hint(const_iterator position_hint, Args&&... args);

  // --------------------------------------------------------------------------
  // Erase operations.
  //
  // Assume that every operation invalidates iterators and references.
  //
  // erase(position), erase(first, last) can take O(size).
  // erase(key) may take O(size) + O(log(size)).
  //
  // Prefer the erase(std::remove(), end()) idiom for deleting multiple
  // elements.

  iterator erase(const_iterator position);
  iterator erase(const_iterator first, const_iterator last);
  size_type erase(const key_type& key);

  // --------------------------------------------------------------------------
  // Comparators.

  key_compare key_comp() const;
  value_compare value_comp() const;

  // --------------------------------------------------------------------------
  // Search operations.
  //
  // Search operations have O(log(size)) complexity.

  size_type count(const key_type& key) const;

  iterator find(const key_type& key);
  const_iterator find(const key_type& key) const;

  std::pair<iterator, iterator> equal_range(const key_type& ket);
  std::pair<const_iterator, const_iterator> equal_range(
      const key_type& key) const;

  iterator lower_bound(const key_type& key);
  const_iterator lower_bound(const key_type& key) const;

  iterator upper_bound(const key_type& key);
  const_iterator upper_bound(const key_type& key) const;

  // --------------------------------------------------------------------------
  // General operations.
  //
  // Assume that swap invalidates iterators and references.
  //
  // As with std::set, equality and ordering operations for the whole flat_set
  // are equivalent to using equal() and lexicographical_compare() on the key
  // types, rather than using element-wise key_comp() as e.g. lower_bound()
  // does. Implementation note: currently we use operator==() and operator<() on
  // std::vector, because they have the same contract we need, so we use them
  // directly for brevity and in case it is more optimal than calling equal()
  // and lexicograhpical_compare(). If the underlying container type is changed,
  // this code may need to be modified.

  void swap(flat_set& other);

  friend bool operator==(const flat_set& lhs, const flat_set& rhs) {
    return lhs.impl_.body_ == rhs.impl_.body_;
  }

  friend bool operator!=(const flat_set& lhs, const flat_set& rhs) {
    return !(lhs == rhs);
  }

  friend bool operator<(const flat_set& lhs, const flat_set& rhs) {
    return lhs.impl_.body_ < rhs.impl_.body_;
  }

  friend bool operator>(const flat_set& lhs, const flat_set& rhs) {
    return rhs < lhs;
  }

  friend bool operator>=(const flat_set& lhs, const flat_set& rhs) {
    return !(lhs < rhs);
  }

  friend bool operator<=(const flat_set& lhs, const flat_set& rhs) {
    return !(lhs > rhs);
  }

  friend void swap(flat_set& lhs, flat_set& rhs) { lhs.swap(rhs); }

 private:
  const flat_set& as_const() { return *this; }

  iterator const_cast_it(const_iterator c_it) {
    auto distance = std::distance(cbegin(), c_it);
    return std::next(begin(), distance);
  }

  void sort_and_unique() {
    // std::set sorts elements preserving stability because it doesn't have any
    // performance wins in not doing that. We do, so we use an unstable sort.
    std::sort(begin(), end(), value_comp());
    erase(std::unique(begin(), end(),
                      [this](const value_type& lhs, const value_type& rhs) {
                        // lhs is already <= rhs due to sort, therefore
                        // !(lhs < rhs) <=> lhs == rhs.
                        return !value_comp()(lhs, rhs);
                      }),
          end());
  }

  // To support comparators that may not be possible to default-construct, we
  // have to store an instance of Compare. Using this to store all internal
  // state of flat_set and using private inheritance to store compare lets us
  // take advantage of an empty base class optimization to avoid extra space in
  // the common case when Compare has no state.
  struct Impl : private Compare {
    Impl() = default;

    template <class Cmp, class... Body>
    explicit Impl(Cmp&& compare_arg, Body&&... underlying_type_args)
        : Compare(std::forward<Cmp>(compare_arg)),
          body_(std::forward<Body>(underlying_type_args)...) {}

    Compare compare() const { return *this; }

    underlying_type body_;
  } impl_;
};

// ----------------------------------------------------------------------------
// Lifetime.

template <class Key, class Compare>
flat_set<Key, Compare>::flat_set() = default;

template <class Key, class Compare>
flat_set<Key, Compare>::flat_set(const Compare& comp) : impl_(comp) {}

template <class Key, class Compare>
template <class InputIterator>
flat_set<Key, Compare>::flat_set(InputIterator first,
                                 InputIterator last,
                                 const Compare& comp)
    : impl_(comp, first, last) {
  sort_and_unique();
}

template <class Key, class Compare>
flat_set<Key, Compare>::flat_set(const flat_set&) = default;

template <class Key, class Compare>
flat_set<Key, Compare>::flat_set(flat_set&&) = default;

template <class Key, class Compare>
flat_set<Key, Compare>::flat_set(std::initializer_list<value_type> ilist,
                                 const Compare& comp)
    : flat_set(std::begin(ilist), std::end(ilist), comp) {}

template <class Key, class Compare>
flat_set<Key, Compare>::~flat_set() = default;

// ----------------------------------------------------------------------------
// Assignments.

template <class Key, class Compare>
auto flat_set<Key, Compare>::operator=(const flat_set&) -> flat_set& = default;

template <class Key, class Compare>
auto flat_set<Key, Compare>::operator=(flat_set &&) -> flat_set& = default;

template <class Key, class Compare>
auto flat_set<Key, Compare>::operator=(std::initializer_list<value_type> ilist)
    -> flat_set& {
  impl_.body_ = ilist;
  sort_and_unique();
  return *this;
}

// ----------------------------------------------------------------------------
// Memory management.

template <class Key, class Compare>
void flat_set<Key, Compare>::reserve(size_type new_capacity) {
  impl_.body_.reserve(new_capacity);
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::capacity() const -> size_type {
  return impl_.body_.capacity();
}

template <class Key, class Compare>
void flat_set<Key, Compare>::shrink_to_fit() {
  impl_.body_.shrink_to_fit();
}

// ----------------------------------------------------------------------------
// Size management.

template <class Key, class Compare>
void flat_set<Key, Compare>::clear() {
  impl_.body_.clear();
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::size() const -> size_type {
  return impl_.body_.size();
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::max_size() const -> size_type {
  return impl_.body_.max_size();
}

template <class Key, class Compare>
bool flat_set<Key, Compare>::empty() const {
  return impl_.body_.empty();
}

// ----------------------------------------------------------------------------
// Iterators.

template <class Key, class Compare>
auto flat_set<Key, Compare>::begin() -> iterator {
  return impl_.body_.begin();
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::begin() const -> const_iterator {
  return impl_.body_.begin();
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::cbegin() const -> const_iterator {
  return impl_.body_.cbegin();
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::end() -> iterator {
  return impl_.body_.end();
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::end() const -> const_iterator {
  return impl_.body_.end();
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::cend() const -> const_iterator {
  return impl_.body_.cend();
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::rbegin() -> reverse_iterator {
  return impl_.body_.rbegin();
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::rbegin() const -> const_reverse_iterator {
  return impl_.body_.rbegin();
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::crbegin() const -> const_reverse_iterator {
  return impl_.body_.crbegin();
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::rend() -> reverse_iterator {
  return impl_.body_.rend();
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::rend() const -> const_reverse_iterator {
  return impl_.body_.rend();
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::crend() const -> const_reverse_iterator {
  return impl_.body_.crend();
}

// ----------------------------------------------------------------------------
// Insert operations.
//
// Currently we use position_hint the same way as eastl or boost:
// https://github.com/electronicarts/EASTL/blob/master/include/EASTL/vector_set.h#L493
//
// We duplicate code between copy and move version so that we can avoid
// creating a temporary value.

template <class Key, class Compare>
auto flat_set<Key, Compare>::insert(const value_type& val)
    -> std::pair<iterator, bool> {
  auto position = lower_bound(val);

  if (position == end() || value_comp()(val, *position))
    return {impl_.body_.insert(position, val), true};

  return {position, false};
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::insert(value_type&& val)
    -> std::pair<iterator, bool> {
  auto position = lower_bound(val);

  if (position == end() || value_comp()(val, *position))
    return {impl_.body_.insert(position, std::move(val)), true};

  return {position, false};
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::insert(const_iterator position_hint,
                                    const value_type& val) -> iterator {
  if (position_hint == end() || value_comp()(val, *position_hint)) {
    if (position_hint == begin() || value_comp()(*(position_hint - 1), val))
      // We have to cast away const because of crbug.com/677044.
      return impl_.body_.insert(const_cast_it(position_hint), val);
  }
  return insert(val).first;
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::insert(const_iterator position_hint,
                                    value_type&& val) -> iterator {
  if (position_hint == end() || value_comp()(val, *position_hint)) {
    if (position_hint == begin() || value_comp()(*(position_hint - 1), val))
      // We have to cast away const because of crbug.com/677044.
      return impl_.body_.insert(const_cast_it(position_hint), std::move(val));
  }
  return insert(std::move(val)).first;
}

template <class Key, class Compare>
template <class... Args>
auto flat_set<Key, Compare>::emplace(Args&&... args)
    -> std::pair<iterator, bool> {
  return insert(value_type(std::forward<Args>(args)...));
}

template <class Key, class Compare>
template <class... Args>
auto flat_set<Key, Compare>::emplace_hint(const_iterator position_hint,
                                          Args&&... args) -> iterator {
  return insert(position_hint, value_type(std::forward<Args>(args)...));
}

// ----------------------------------------------------------------------------
// Erase operations.

template <class Key, class Compare>
auto flat_set<Key, Compare>::erase(const_iterator position) -> iterator {
  // We have to cast away const because of crbug.com/677044.
  return impl_.body_.erase(const_cast_it(position));
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::erase(const key_type& val) -> size_type {
  auto eq_range = equal_range(val);
  auto res = std::distance(eq_range.first, eq_range.second);
  // We have to cast away const because of crbug.com/677044.
  erase(const_cast_it(eq_range.first), const_cast_it(eq_range.second));
  return res;
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::erase(const_iterator first, const_iterator last)
    -> iterator {
  // We have to cast away const because of crbug.com/677044.
  return impl_.body_.erase(const_cast_it(first), const_cast_it(last));
}

// ----------------------------------------------------------------------------
// Comparators.

template <class Key, class Compare>
auto flat_set<Key, Compare>::key_comp() const -> key_compare {
  return impl_.compare();
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::value_comp() const -> value_compare {
  return impl_.compare();
}

// ----------------------------------------------------------------------------
// Search operations.

template <class Key, class Compare>
auto flat_set<Key, Compare>::count(const key_type& key) const -> size_type {
  auto eq_range = equal_range(key);
  return std::distance(eq_range.first, eq_range.second);
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::find(const key_type& key) -> iterator {
  return const_cast_it(as_const().find(key));
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::find(const key_type& key) const -> const_iterator {
  auto eq_range = equal_range(key);
  return (eq_range.first == eq_range.second) ? end() : eq_range.first;
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::equal_range(const key_type& key)
    -> std::pair<iterator, iterator> {
  auto res = as_const().equal_range(key);
  return {const_cast_it(res.first), const_cast_it(res.second)};
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::equal_range(const key_type& key) const
    -> std::pair<const_iterator, const_iterator> {
  auto lower = lower_bound(key);

  if (lower == end() || key_comp()(key, *lower))
    return {lower, lower};

  return {lower, std::next(lower)};
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::lower_bound(const key_type& key) -> iterator {
  return const_cast_it(as_const().lower_bound(key));
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::lower_bound(const key_type& key) const
    -> const_iterator {
  return std::lower_bound(begin(), end(), key, key_comp());
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::upper_bound(const key_type& key) -> iterator {
  return const_cast_it(as_const().upper_bound(key));
}

template <class Key, class Compare>
auto flat_set<Key, Compare>::upper_bound(const key_type& key) const
    -> const_iterator {
  return std::upper_bound(begin(), end(), key, key_comp());
}

// ----------------------------------------------------------------------------
// General operations.

template <class Key, class Compare>
void flat_set<Key, Compare>::swap(flat_set& other) {
  std::swap(impl_, other.impl_);
}

}  // namespace  base

#endif  // BASE_CONTAINERS_FLAT_SET_H_
