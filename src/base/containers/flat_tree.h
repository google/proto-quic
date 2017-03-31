// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_CONTAINERS_FLAT_TREE_H_
#define BASE_CONTAINERS_FLAT_TREE_H_

#include <algorithm>
#include <vector>

namespace base {
namespace internal {

// Implementation of a sorted vector for backing flat_set and flat_map. Do not
// use directly.
//
// The use of "value" in this is like std::map uses, meaning it's the thing
// contained (in the case of map it's a <Kay, Mapped> pair). The Key is how
// things are looked up. In the case of a set, Key == Value. In the case of
// a map, the Key is a component of a Value.
//
// The helper class GetKeyFromValue provides the means to extract a key from a
// value for comparison purposes. It should implement:
//   const Key& operator()(const Value&).
template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
class flat_tree {
 public:
 private:
  using underlying_type = std::vector<Value>;

 public:
  // --------------------------------------------------------------------------
  // Types.
  //
  using key_type = Key;
  using key_compare = KeyCompare;
  using value_type = Value;

  // Wraps the templated key comparison to compare values.
  class value_compare : public key_compare {
   public:
    value_compare() = default;

    template <class Cmp>
    explicit value_compare(Cmp&& compare_arg)
        : KeyCompare(std::forward<Cmp>(compare_arg)) {}

    bool operator()(const value_type& left, const value_type& right) const {
      GetKeyFromValue extractor;
      return key_compare::operator()(extractor(left), extractor(right));
    }
  };

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

  flat_tree();
  explicit flat_tree(const key_compare& comp);

  // Not stable in the presence of duplicates in the initializer list.
  template <class InputIterator>
  flat_tree(InputIterator first,
            InputIterator last,
            const key_compare& comp = key_compare());

  flat_tree(const flat_tree&);
  flat_tree(flat_tree&&);

  // Not stable in the presence of duplicates in the initializer list.
  flat_tree(std::initializer_list<value_type> ilist,
            const key_compare& comp = key_compare());

  ~flat_tree();

  // --------------------------------------------------------------------------
  // Assignments.
  //
  // Assume that move assignment invalidates iterators and references.

  flat_tree& operator=(const flat_tree&);
  flat_tree& operator=(flat_tree&&);
  // Not stable in the presence of duplicates in the initializer list.
  flat_tree& operator=(std::initializer_list<value_type> ilist);

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
  // clear() leaves the capacity() of the flat_tree unchanged.

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
  // Capacity of flat_tree grows in an implementation-defined manner.
  //
  // NOTE: Prefer to build a new flat_tree from a std::vector (or similar)
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
  // Prefer base::EraseIf() or some other variation on erase(remove(), end())
  // idiom when deleting multiple non-consecutive elements.

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
  // Implementation note: currently we use operator==() and operator<() on
  // std::vector, because they have the same contract we need, so we use them
  // directly for brevity and in case it is more optimal than calling equal()
  // and lexicograhpical_compare(). If the underlying container type is changed,
  // this code may need to be modified.

  void swap(flat_tree& other);

  friend bool operator==(const flat_tree& lhs, const flat_tree& rhs) {
    return lhs.impl_.body_ == rhs.impl_.body_;
  }

  friend bool operator!=(const flat_tree& lhs, const flat_tree& rhs) {
    return !(lhs == rhs);
  }

  friend bool operator<(const flat_tree& lhs, const flat_tree& rhs) {
    return lhs.impl_.body_ < rhs.impl_.body_;
  }

  friend bool operator>(const flat_tree& lhs, const flat_tree& rhs) {
    return rhs < lhs;
  }

  friend bool operator>=(const flat_tree& lhs, const flat_tree& rhs) {
    return !(lhs < rhs);
  }

  friend bool operator<=(const flat_tree& lhs, const flat_tree& rhs) {
    return !(lhs > rhs);
  }

  friend void swap(flat_tree& lhs, flat_tree& rhs) { lhs.swap(rhs); }

 protected:
  // Emplaces a new item into the tree that is known not to be in it. This
  // is for implementing map [] and at().
  template <class... Args>
  iterator unsafe_emplace(const_iterator position, Args&&... args);

 private:
  // Helper class for e.g. lower_bound that can compare a value on the left
  // to a key on the right.
  struct KeyValueCompare {
    // The key comparison object must outlive this class.
    explicit KeyValueCompare(const key_compare& key_comp)
        : key_comp_(key_comp) {}

    bool operator()(const value_type& left, const key_type& right) const {
      GetKeyFromValue extractor;
      return key_comp_(extractor(left), right);
    }

   private:
    const key_compare& key_comp_;
  };

  const flat_tree& as_const() { return *this; }

  iterator const_cast_it(const_iterator c_it) {
    auto distance = std::distance(cbegin(), c_it);
    return std::next(begin(), distance);
  }

  void sort_and_unique() {
    // std::set sorts elements preserving stability because it doesn't have any
    // performance wins in not doing that. We do, so we use an unstable sort.
    std::sort(begin(), end(), impl_.get_value_comp());
    erase(std::unique(begin(), end(),
                      [this](const value_type& lhs, const value_type& rhs) {
                        // lhs is already <= rhs due to sort, therefore
                        // !(lhs < rhs) <=> lhs == rhs.
                        return !impl_.get_value_comp()(lhs, rhs);
                      }),
          end());
  }

  // To support comparators that may not be possible to default-construct, we
  // have to store an instance of Compare. Using this to store all internal
  // state of flat_tree and using private inheritance to store compare lets us
  // take advantage of an empty base class optimization to avoid extra space in
  // the common case when Compare has no state.
  struct Impl : private value_compare {
    Impl() = default;

    template <class Cmp, class... Body>
    explicit Impl(Cmp&& compare_arg, Body&&... underlying_type_args)
        : value_compare(std::forward<Cmp>(compare_arg)),
          body_(std::forward<Body>(underlying_type_args)...) {}

    const value_compare& get_value_comp() const { return *this; }
    const key_compare& get_key_comp() const { return *this; }

    underlying_type body_;
  } impl_;
};

// ----------------------------------------------------------------------------
// Lifetime.

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::flat_tree() = default;

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::flat_tree(
    const KeyCompare& comp)
    : impl_(comp) {}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
template <class InputIterator>
flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::flat_tree(
    InputIterator first,
    InputIterator last,
    const KeyCompare& comp)
    : impl_(comp, first, last) {
  sort_and_unique();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::flat_tree(
    const flat_tree&) = default;

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::flat_tree(flat_tree&&) =
    default;

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::flat_tree(
    std::initializer_list<value_type> ilist,
    const KeyCompare& comp)
    : flat_tree(std::begin(ilist), std::end(ilist), comp) {}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::~flat_tree() = default;

// ----------------------------------------------------------------------------
// Assignments.

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::operator=(
    const flat_tree&) -> flat_tree& = default;

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::operator=(flat_tree &&)
    -> flat_tree& = default;

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::operator=(
    std::initializer_list<value_type> ilist) -> flat_tree& {
  impl_.body_ = ilist;
  sort_and_unique();
  return *this;
}

// ----------------------------------------------------------------------------
// Memory management.

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
void flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::reserve(
    size_type new_capacity) {
  impl_.body_.reserve(new_capacity);
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::capacity() const
    -> size_type {
  return impl_.body_.capacity();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
void flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::shrink_to_fit() {
  impl_.body_.shrink_to_fit();
}

// ----------------------------------------------------------------------------
// Size management.

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
void flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::clear() {
  impl_.body_.clear();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::size() const
    -> size_type {
  return impl_.body_.size();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::max_size() const
    -> size_type {
  return impl_.body_.max_size();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
bool flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::empty() const {
  return impl_.body_.empty();
}

// ----------------------------------------------------------------------------
// Iterators.

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::begin() -> iterator {
  return impl_.body_.begin();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::begin() const
    -> const_iterator {
  return impl_.body_.begin();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::cbegin() const
    -> const_iterator {
  return impl_.body_.cbegin();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::end() -> iterator {
  return impl_.body_.end();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::end() const
    -> const_iterator {
  return impl_.body_.end();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::cend() const
    -> const_iterator {
  return impl_.body_.cend();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::rbegin()
    -> reverse_iterator {
  return impl_.body_.rbegin();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::rbegin() const
    -> const_reverse_iterator {
  return impl_.body_.rbegin();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::crbegin() const
    -> const_reverse_iterator {
  return impl_.body_.crbegin();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::rend()
    -> reverse_iterator {
  return impl_.body_.rend();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::rend() const
    -> const_reverse_iterator {
  return impl_.body_.rend();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::crend() const
    -> const_reverse_iterator {
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

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::insert(
    const value_type& val) -> std::pair<iterator, bool> {
  auto position = lower_bound(val);

  if (position == end() || impl_.get_value_comp()(val, *position))
    return {impl_.body_.insert(position, val), true};

  return {position, false};
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::insert(
    value_type&& val) -> std::pair<iterator, bool> {
  GetKeyFromValue extractor;
  auto position = lower_bound(extractor(val));

  if (position == end() || impl_.get_value_comp()(val, *position))
    return {impl_.body_.insert(position, std::move(val)), true};

  return {position, false};
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::insert(
    const_iterator position_hint,
    const value_type& val) -> iterator {
  if (position_hint == end() || impl_.get_value_comp()(val, *position_hint)) {
    if (position_hint == begin() ||
        impl_.get_value_comp()(*(position_hint - 1), val))
      // We have to cast away const because of crbug.com/677044.
      return impl_.body_.insert(const_cast_it(position_hint), val);
  }
  return insert(val).first;
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::insert(
    const_iterator position_hint,
    value_type&& val) -> iterator {
  if (position_hint == end() || impl_.get_value_comp()(val, *position_hint)) {
    if (position_hint == begin() ||
        impl_.get_value_comp()(*(position_hint - 1), val))
      // We have to cast away const because of crbug.com/677044.
      return impl_.body_.insert(const_cast_it(position_hint), std::move(val));
  }
  return insert(std::move(val)).first;
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
template <class... Args>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::emplace(Args&&... args)
    -> std::pair<iterator, bool> {
  return insert(value_type(std::forward<Args>(args)...));
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
template <class... Args>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::emplace_hint(
    const_iterator position_hint,
    Args&&... args) -> iterator {
  return insert(position_hint, value_type(std::forward<Args>(args)...));
}

// ----------------------------------------------------------------------------
// Erase operations.

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::erase(
    const_iterator position) -> iterator {
  // We have to cast away const because of crbug.com/677044.
  return impl_.body_.erase(const_cast_it(position));
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::erase(
    const key_type& val) -> size_type {
  auto eq_range = equal_range(val);
  auto res = std::distance(eq_range.first, eq_range.second);
  // We have to cast away const because of crbug.com/677044.
  erase(const_cast_it(eq_range.first), const_cast_it(eq_range.second));
  return res;
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::erase(
    const_iterator first,
    const_iterator last) -> iterator {
  // We have to cast away const because of crbug.com/677044.
  return impl_.body_.erase(const_cast_it(first), const_cast_it(last));
}

// ----------------------------------------------------------------------------
// Comparators.

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::key_comp() const
    -> key_compare {
  return impl_.get_key_comp();
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::value_comp() const
    -> value_compare {
  return impl_.get_value_comp();
}

// ----------------------------------------------------------------------------
// Search operations.

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::count(
    const key_type& key) const -> size_type {
  auto eq_range = equal_range(key);
  return std::distance(eq_range.first, eq_range.second);
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::find(
    const key_type& key) -> iterator {
  return const_cast_it(as_const().find(key));
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::find(
    const key_type& key) const -> const_iterator {
  auto eq_range = equal_range(key);
  return (eq_range.first == eq_range.second) ? end() : eq_range.first;
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::equal_range(
    const key_type& key) -> std::pair<iterator, iterator> {
  auto res = as_const().equal_range(key);
  return {const_cast_it(res.first), const_cast_it(res.second)};
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::equal_range(
    const key_type& key) const -> std::pair<const_iterator, const_iterator> {
  auto lower = lower_bound(key);

  GetKeyFromValue extractor;
  if (lower == end() || impl_.get_key_comp()(key, extractor(*lower)))
    return {lower, lower};

  return {lower, std::next(lower)};
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::lower_bound(
    const key_type& key) -> iterator {
  return const_cast_it(as_const().lower_bound(key));
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::lower_bound(
    const key_type& key) const -> const_iterator {
  KeyValueCompare key_value(impl_.get_key_comp());
  return std::lower_bound(begin(), end(), key, key_value);
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::upper_bound(
    const key_type& key) -> iterator {
  return const_cast_it(as_const().upper_bound(key));
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::upper_bound(
    const key_type& key) const -> const_iterator {
  KeyValueCompare key_value(impl_.get_key_comp());
  return std::upper_bound(begin(), end(), key, key_value);
}

// ----------------------------------------------------------------------------
// General operations.

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
void flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::swap(
    flat_tree& other) {
  std::swap(impl_, other.impl_);
}

template <class Key, class Value, class GetKeyFromValue, class KeyCompare>
template <class... Args>
auto flat_tree<Key, Value, GetKeyFromValue, KeyCompare>::unsafe_emplace(
    const_iterator position,
    Args&&... args) -> iterator {
  // We have to cast away const because of crbug.com/677044.
  return impl_.body_.insert(const_cast_it(position),
                            value_type(std::forward<Args>(args)...));
}

// For containers like sets, the key is the same as the value. This implements
// the GetKeyFromValue template parameter to flat_tree for this case.
template <class Key>
struct GetKeyFromValueIdentity {
  const Key& operator()(const Key& k) const { return k; }
};

}  // namespace internal

// ----------------------------------------------------------------------------
// Free functions.

// Erases all elements that match predicate. It has O(size) complexity.
template <class Key,
          class Value,
          class GetKeyFromValue,
          class KeyCompare,
          typename Predicate>
void EraseIf(base::internal::flat_tree<Key, Value, GetKeyFromValue, KeyCompare>&
                 container,
             Predicate pred) {
  container.erase(std::remove_if(container.begin(), container.end(), pred),
                  container.end());
}

}  // namespace base

#endif  // BASE_CONTAINERS_FLAT_TREE_H_
