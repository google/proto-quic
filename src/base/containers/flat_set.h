// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_CONTAINERS_FLAT_SET_H_
#define BASE_CONTAINERS_FLAT_SET_H_

#include "base/containers/flat_tree.h"

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
//  * Sets where mutating happens in big bulks: to erase multiple elements, use
//    base::EraseIf() rather than repeated single-element removal. Insertion is
//    harder - consider set operations or building a new vector. Set operations
//    can be slow if one of the sets is considerably bigger. Also be aware that
//    beating performance of sort + unique (implementation of flat_set's
//    constructor) is hard, clever merge of many sets might not win. Generally
//    avoid inserting into flat set without benchmarks.
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

// QUICK REFERENCE
//
// Most of the core functionality is inherited from flat_tree. Please see
// flat_tree.h for more details for most of these functions. As a quick
// reference, the functions available are:
//
// Assignment functions:
//   flat_set& operator=(const flat_set&);
//   flat_set& operator=(flat_set&&);
//   flat_set& operator=(initializer_list<Key>);
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
//   pair<iterator, bool> insert(const Key&);
//   pair<iterator, bool> insert(Key&&);
//   pair<iterator, bool> emplace(Args&&...);
//   iterator             emplace_hint(const_iterator, Args&&...);
//
// Erase functions:
//   iterator erase(const_iterator);
//   iterator erase(const_iterator first, const_iterator& last);
//   size_t   erase(const Key& key)
//
// Comparators (see std::set documentation).
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
// General functions
//   void swap(flat_set&&)
//
// Non-member operators:
//   bool operator==(const flat_set&, const flat_set);
//   bool operator!=(const flat_set&, const flat_set);
//   bool operator<(const flat_set&, const flat_set);
//   bool operator>(const flat_set&, const flat_set);
//   bool operator>=(const flat_set&, const flat_set);
//   bool operator<=(const flat_set&, const flat_set);
//
template <class Key, class Compare = std::less<Key>>
using flat_set = typename ::base::internal::flat_tree<
    Key,
    Key,
    ::base::internal::GetKeyFromValueIdentity<Key>,
    Compare>;

}  // namespace base

#endif  // BASE_CONTAINERS_FLAT_SET_H_
