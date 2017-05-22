// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_CONTAINERS_FLAT_MAP_H_
#define BASE_CONTAINERS_FLAT_MAP_H_

#include <utility>

#include "base/containers/flat_tree.h"
#include "base/logging.h"

namespace base {

namespace internal {

// An implementation of the flat_tree GetKeyFromValue template parameter that
// extracts the key as the first element of a pair.
template <class Key, class Mapped>
struct GetKeyFromValuePairFirst {
  const Key& operator()(const std::pair<Key, Mapped>& p) const {
    return p.first;
  }
};

}  // namespace internal

// flat_map is a container with a std::map-like interface that stores its
// contents in a sorted vector.
//
// Please see //base/containers/README.md for an overview of which container
// to select.
//
// PROS
//
//  - Good memory locality.
//  - Low overhead, especially for smaller maps.
//  - Performance is good for more workloads than you might expect (see
//    overview link above).
//
// CONS
//
//  - Inserts and removals are O(n).
//
// IMPORTANT NOTES
//
//  - Iterators are invalidated across mutations.
//  - If possible, construct a flat_map in one operation by inserting into
//    a std::vector and moving that vector into the flat_map constructor.
//
// QUICK REFERENCE
//
// Most of the core functionality is inherited from flat_tree. Please see
// flat_tree.h for more details for most of these functions. As a quick
// reference, the functions available are:
//
// Constructors (inputs need not be sorted):
//   flat_map(InputIterator first, InputIterator last,
//            FlatContainerDupes, const Compare& compare = Compare());
//   flat_map(const flat_map&);
//   flat_map(flat_map&&);
//   flat_map(std::vector<value_type>, FlatContainerDupes);  // Re-use storage.
//   flat_map(std::initializer_list<value_type> ilist,
//            const Compare& comp = Compare());
//
// Assignment functions:
//   flat_map& operator=(const flat_map&);
//   flat_map& operator=(flat_map&&);
//   flat_map& operator=(initializer_list<pair<Key, Mapped>>);
//
// Memory management functions:
//   void   reserve(size_t);
//   size_t capacity() const;
//   void   shrink_to_fit();
//
// Size management functions:
//   void   clear();
//   size_t size() const;
//   size_t max_size() const;
//   bool   empty() const;
//
// Iterator functions:
//   iterator               begin();
//   const_iterator         begin() const;
//   const_iterator         cbegin() const;
//   iterator               end();
//   const_iterator         end() const;
//   const_iterator         cend() const;
//   reverse_iterator       rbegin();
//   const reverse_iterator rbegin() const;
//   const_reverse_iterator crbegin() const;
//   reverse_iterator       rend();
//   const_reverse_iterator rend() const;
//   const_reverse_iterator crend() const;
//
// Insert and accessor functions:
//   Mapped&              operator[](const Key&);
//   Mapped&              operator[](Key&&);
//   pair<iterator, bool> insert(const pair<Key, Mapped>&);
//   pair<iterator, bool> insert(pair<Key, Mapped>&&);
//   void                 insert(InputIterator first, InputIterator last,
//                               FlatContainerDupes);
//   pair<iterator, bool> emplace(Args&&...);
//   iterator             emplace_hint(const_iterator, Args&&...);
//
// Erase functions:
//   iterator erase(const_iterator);
//   iterator erase(const_iterator first, const_iterator& last);
//   size_t   erase(const Key& key)
//
// Comparators (see std::map documentation).
//   key_compare   key_comp() const;
//   value_compare value_comp() const;
//
// Search functions:
//   size_t                   count(const Key&) const;
//   iterator                 find(const Key&);
//   const_iterator           find(const Key&) const;
//   pair<iterator, iterator> equal_range(Key&)
//   iterator                 lower_bound(const Key&);
//   const_iterator           lower_bound(const Key&) const;
//   iterator                 upper_bound(const Key&);
//   const_iterator           upper_bound(const Key&) const;
//
// General functions:
//   void swap(flat_map&&)
//
// Non-member operators:
//   bool operator==(const flat_map&, const flat_map);
//   bool operator!=(const flat_map&, const flat_map);
//   bool operator<(const flat_map&, const flat_map);
//   bool operator>(const flat_map&, const flat_map);
//   bool operator>=(const flat_map&, const flat_map);
//   bool operator<=(const flat_map&, const flat_map);
//
template <class Key, class Mapped, class Compare = std::less<Key>>
// Meets the requirements of Container, AssociativeContainer,
// ReversibleContainer.
// Requires: Key is Movable, Compare is a StrictWeakOrdering on Key.
class flat_map : public ::base::internal::flat_tree<
                     Key,
                     std::pair<Key, Mapped>,
                     ::base::internal::GetKeyFromValuePairFirst<Key, Mapped>,
                     Compare> {
 private:
  using tree = typename ::base::internal::flat_tree<
      Key,
      std::pair<Key, Mapped>,
      ::base::internal::GetKeyFromValuePairFirst<Key, Mapped>,
      Compare>;

 public:
  using mapped_type = Mapped;
  using value_type = typename tree::value_type;

  // --------------------------------------------------------------------------
  // Lifetime.
  //
  // Constructors that take range guarantee O(N * log(N)) + O(N) complexity
  // (N is a range length). Thr range constructors are NOT stable. If there are
  // duplicates an arbitrary one will be chosen.
  //
  // Assume that move constructors invalidate iterators and references.
  //
  // The constructors that take ranges, lists, and vectors do not require that
  // the input be sorted.

  flat_map();
  explicit flat_map(const Compare& comp);

  template <class InputIterator>
  flat_map(InputIterator first,
           InputIterator last,
           FlatContainerDupes dupe_handling,
           const Compare& comp = Compare());

  flat_map(const flat_map&);
  flat_map(flat_map&&);

  flat_map(std::vector<value_type> items,
           FlatContainerDupes dupe_handling,
           const Compare& comp = Compare());

  flat_map(std::initializer_list<value_type> ilist,
           FlatContainerDupes dupe_handling,
           const Compare& comp = Compare());

  ~flat_map();

  // --------------------------------------------------------------------------
  // Assignments.
  //
  // Assume that move assignment invalidates iterators and references.

  flat_map& operator=(const flat_map&);
  flat_map& operator=(flat_map&&);
  // Takes the first if there are duplicates in the initializer list.
  flat_map& operator=(std::initializer_list<value_type> ilist);

  // --------------------------------------------------------------------------
  // Map-specific insert operations.
  //
  // Normal insert() functions are inherited from flat_tree.
  //
  // Assume that every operation invalidates iterators and references.
  // Insertion of one element can take O(size).

  mapped_type& operator[](const Key& key);
  mapped_type& operator[](Key&& key);

  // --------------------------------------------------------------------------
  // General operations.
  //
  // Assume that swap invalidates iterators and references.

  void swap(flat_map& other);

  friend void swap(flat_map& lhs, flat_map& rhs) { lhs.swap(rhs); }
};

// ----------------------------------------------------------------------------
// Lifetime.

template <class Key, class Mapped, class Compare>
flat_map<Key, Mapped, Compare>::flat_map() = default;

template <class Key, class Mapped, class Compare>
flat_map<Key, Mapped, Compare>::flat_map(const Compare& comp) : tree(comp) {}

template <class Key, class Mapped, class Compare>
template <class InputIterator>
flat_map<Key, Mapped, Compare>::flat_map(InputIterator first,
                                         InputIterator last,
                                         FlatContainerDupes dupe_handling,
                                         const Compare& comp)
    : tree(first, last, dupe_handling, comp) {}

template <class Key, class Mapped, class Compare>
flat_map<Key, Mapped, Compare>::flat_map(const flat_map&) = default;

template <class Key, class Mapped, class Compare>
flat_map<Key, Mapped, Compare>::flat_map(flat_map&&) = default;

template <class Key, class Mapped, class Compare>
flat_map<Key, Mapped, Compare>::flat_map(std::vector<value_type> items,
                                         FlatContainerDupes dupe_handling,
                                         const Compare& comp)
    : tree(std::move(items), dupe_handling, comp) {}

template <class Key, class Mapped, class Compare>
flat_map<Key, Mapped, Compare>::flat_map(
    std::initializer_list<value_type> ilist,
    FlatContainerDupes dupe_handling,
    const Compare& comp)
    : flat_map(std::begin(ilist), std::end(ilist), dupe_handling, comp) {}

template <class Key, class Mapped, class Compare>
flat_map<Key, Mapped, Compare>::~flat_map() = default;

// ----------------------------------------------------------------------------
// Assignments.

template <class Key, class Mapped, class Compare>
auto flat_map<Key, Mapped, Compare>::operator=(const flat_map&)
    -> flat_map& = default;

template <class Key, class Mapped, class Compare>
auto flat_map<Key, Mapped, Compare>::operator=(flat_map &&)
    -> flat_map& = default;

template <class Key, class Mapped, class Compare>
auto flat_map<Key, Mapped, Compare>::operator=(
    std::initializer_list<value_type> ilist) -> flat_map& {
  tree::operator=(ilist);
  return *this;
}

// ----------------------------------------------------------------------------
// Insert operations.

template <class Key, class Mapped, class Compare>
auto flat_map<Key, Mapped, Compare>::operator[](const Key& key) -> Mapped& {
  typename tree::iterator found = tree::lower_bound(key);
  if (found == tree::end() || tree::key_comp()(key, found->first))
    found = tree::unsafe_emplace(found, key, Mapped());
  return found->second;
}

template <class Key, class Mapped, class Compare>
auto flat_map<Key, Mapped, Compare>::operator[](Key&& key) -> Mapped& {
  const Key& key_ref = key;
  typename tree::iterator found = tree::lower_bound(key_ref);
  if (found == tree::end() || tree::key_comp()(key, found->first))
    found = tree::unsafe_emplace(found, std::move(key), Mapped());
  return found->second;
}

// ----------------------------------------------------------------------------
// General operations.

template <class Key, class Mapped, class Compare>
void flat_map<Key, Mapped, Compare>::swap(flat_map& other) {
  tree::swap(other);
}

}  // namespace base

#endif  // BASE_CONTAINERS_FLAT_MAP_H_
