// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_CONTAINERS_CIRCULAR_DEQUE_H_
#define BASE_CONTAINERS_CIRCULAR_DEQUE_H_

#include <cstddef>
#include <iterator>
#include <type_traits>
#include <utility>

#include "base/containers/vector_buffer.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/template_util.h"

// base::circular_deque is similar to std::deque. Unlike std::deque, the
// storage is provided in a flat circular buffer conceptually similar to a
// vector. The beginning and end will wrap around as necessary so that
// pushes and pops will be constant time as long as a capacity expansion is
// not required.
//
// The API should be identical to std::deque with the following differences:
//
//  - ITERATORS ARE NOT STABLE. Mutating the container will invalidate all
//    iterators.
//
//  - Insertions may resize the vector and so are not constant time (std::deque
//    guarantees constant time for insertions at the ends).
//
//  - Container-wide comparisons are not implemented. If you want to compare
//    two containers, use an algorithm so the expensive iteration is explicit.
//
//  - Insert and erase in the middle is not supported. This complicates the
//    implementation and is not necessary for our current goals. We can
//    consider adding this in the future if necessary. But consider that
//    the implementation will be relatively inefficient (linear time). If
//    a use wants arbitrary queue mutations, consider a std::list.
//
// If you want a similar container with only a queue API, use base::queue in
// base/containers/queue.h.
//
// Constructors:
//   circular_deque();
//   circular_deque(size_t count);
//   circular_deque(size_t count, const T& value);
//   circular_deque(InputIterator first, InputIterator last);
//   circular_deque(const circular_deque&);
//   circular_deque(circular_deque&&);
//   circular_deque(std::initializer_list<value_type>);
//
// Assignment functions:
//   circular_deque& operator=(const circular_deque&);
//   circular_deque& operator=(circular_deque&&);
//   circular_deque& operator=(std::initializer_list<T>);
//   void assign(size_t count, const T& value);
//   void assign(InputIterator first, InputIterator last);
//   void assign(std::initializer_list<T> value);
//
// Random accessors:
//   T& at(size_t);
//   const T& at(size_t) const;
//   T& operator[](size_t);
//   const T& operator[](size_t) const;
//
// End accessors:
//   T& front();
//   const T& front() const;
//   T& back();
//   const T& back() const;
//
// Iterator functions:
//   iterator               begin();
//   const_iterator         begin() const;
//   const_iterator         cbegin() const;
//   iterator               end();
//   const_iterator         end() const;
//   const_iterator         cend() const;
//   reverse_iterator       rbegin();
//   const_reverse_iterator rbegin() const;
//   const_reverse_iterator crbegin() const;
//   reverse_iterator       rend();
//   const_reverse_iterator rend() const;
//   const_reverse_iterator crend() const;
//
// Memory management:
//   void reserve(size_t);
//   size_t capacity() const;
//   void shrink_to_fit();
//
// Size management:
//   void clear();
//   bool empty() const;
//   size_t size() const;
//   void resize(size_t);
//   void resize(size_t count, const T& value);
//
// End insert and erase:
//   void push_front(const T&);
//   void push_front(T&&);
//   void push_back(const T&);
//   void push_back(T&&);
//   void emplace_front(Args&&...);
//   void emplace_back(Args&&...);
//   void pop_front();
//   void pop_back();
//
// General:
//   void swap(circular_deque&);

namespace base {

template <class T>
class circular_deque;

namespace internal {

template <typename T>
class circular_deque_const_iterator {
 public:
  using difference_type = std::ptrdiff_t;
  using value_type = T;
  using pointer = const T*;
  using reference = const T&;
  using iterator_category = std::random_access_iterator_tag;

  circular_deque_const_iterator(const circular_deque<T>* parent, size_t index)
      : parent_deque_(parent), index_(index) {
#if DCHECK_IS_ON()
    created_generation_ = parent->generation_;
#endif  // DCHECK_IS_ON()
  }

  // Dereferencing.
  const T& operator*() const {
    CheckUnstableUsage();
    parent_deque_->CheckValidIndex(index_);
    return parent_deque_->buffer_[index_];
  }
  const T* operator->() const {
    CheckUnstableUsage();
    parent_deque_->CheckValidIndex(index_);
    return &parent_deque_->buffer_[index_];
  }

  // Increment and decrement.
  circular_deque_const_iterator& operator++() {
    Increment();
    return *this;
  }
  circular_deque_const_iterator operator++(int) {
    circular_deque_const_iterator ret = *this;
    Increment();
    return ret;
  }
  circular_deque_const_iterator& operator--() {
    Decrement();
    return *this;
  }
  circular_deque_const_iterator operator--(int) {
    circular_deque_const_iterator ret = *this;
    Decrement();
    return ret;
  }

  // Random access mutation.
  friend circular_deque_const_iterator operator+(
      const circular_deque_const_iterator& iter,
      difference_type offset) {
    circular_deque_const_iterator ret = iter;
    ret.Add(offset);
    return ret;
  }
  circular_deque_const_iterator& operator+=(difference_type offset) {
    Add(offset);
    return *this;
  }
  friend circular_deque_const_iterator operator-(
      const circular_deque_const_iterator& iter,
      difference_type offset) {
    circular_deque_const_iterator ret = iter;
    ret.Add(-offset);
    return ret;
  }
  circular_deque_const_iterator& operator-=(difference_type offset) {
    Add(-offset);
    return *this;
  }

  friend std::ptrdiff_t operator-(const circular_deque_const_iterator& lhs,
                                  const circular_deque_const_iterator& rhs) {
    lhs.CheckComparable(rhs);
    return lhs.OffsetFromBegin() - rhs.OffsetFromBegin();
  }

  // Comparisons.
  friend bool operator==(const circular_deque_const_iterator& lhs,
                         const circular_deque_const_iterator& rhs) {
    lhs.CheckComparable(rhs);
    return lhs.index_ == rhs.index_;
  }
  friend bool operator!=(const circular_deque_const_iterator& lhs,
                         const circular_deque_const_iterator& rhs) {
    return !(lhs == rhs);
  }
  friend bool operator<(const circular_deque_const_iterator& lhs,
                        const circular_deque_const_iterator& rhs) {
    lhs.CheckComparable(rhs);
    return lhs.OffsetFromBegin() < rhs.OffsetFromBegin();
  }
  friend bool operator<=(const circular_deque_const_iterator& lhs,
                         const circular_deque_const_iterator& rhs) {
    return !(lhs > rhs);
  }
  friend bool operator>(const circular_deque_const_iterator& lhs,
                        const circular_deque_const_iterator& rhs) {
    lhs.CheckComparable(rhs);
    return lhs.OffsetFromBegin() > rhs.OffsetFromBegin();
  }
  friend bool operator>=(const circular_deque_const_iterator& lhs,
                         const circular_deque_const_iterator& rhs) {
    return !(lhs < rhs);
  }

 protected:
  // Returns the offset from the beginning index of the buffer to the current
  // iten.
  size_t OffsetFromBegin() const {
    if (index_ >= parent_deque_->begin_)
      return index_ - parent_deque_->begin_;  // On the same side as begin.
    return parent_deque_->buffer_.capacity() - parent_deque_->begin_ + index_;
  }

  // Most uses will be ++ and -- so use a simplified implementation.
  void Increment() {
    CheckUnstableUsage();
    parent_deque_->CheckValidIndex(index_);
    index_++;
    if (index_ == parent_deque_->buffer_.capacity())
      index_ = 0;
  }
  void Decrement() {
    CheckUnstableUsage();
    parent_deque_->CheckValidIndexOrEnd(index_);
    if (index_ == 0)
      index_ = parent_deque_->buffer_.capacity() - 1;
    else
      index_--;
  }
  void Add(difference_type delta) {
    CheckUnstableUsage();
    parent_deque_->CheckValidIndex(index_);
    difference_type new_offset = OffsetFromBegin() + delta;
    DCHECK(new_offset >= 0 &&
           new_offset <= static_cast<difference_type>(parent_deque_->size()));
    index_ = (new_offset + parent_deque_->begin_) %
             parent_deque_->buffer_.capacity();
  }

#if DCHECK_IS_ON()
  void CheckUnstableUsage() const {
    // Since circular_deque doesn't guarantee stability, any attempt to
    // dereference this iterator after a mutation (i.e. the generation doesn't
    // match the original) in the container is illegal.
    DCHECK(parent_deque_);
    DCHECK_EQ(created_generation_, parent_deque_->generation_)
        << "circular_deque iterator dereferenced after mutation.";
  }
  void CheckComparable(const circular_deque_const_iterator& other) const {
    DCHECK_EQ(parent_deque_, other.parent_deque_);
    CheckUnstableUsage();
    other.CheckUnstableUsage();
  }
#else
  inline void CheckUnstableUsage() const {}
  inline void CheckComparable(const circular_deque_const_iterator&) const {}
#endif  // DCHECK_IS_ON()

  const circular_deque<T>* parent_deque_;
  size_t index_;

#if DCHECK_IS_ON()
  // The generation of the parent deque when this iterator was created. The
  // container will update the generation for every modification so we can
  // test if the container was modified by comparing them.
  uint64_t created_generation_;
#endif  // DCHECK_IS_ON()
};

template <typename T>
class circular_deque_iterator : public circular_deque_const_iterator<T> {
  using base = circular_deque_const_iterator<T>;

 public:
  using difference_type = std::ptrdiff_t;
  using value_type = T;
  using pointer = T*;
  using reference = T&;
  using iterator_category = std::random_access_iterator_tag;

  // Expose the base class' constructor.
  using base::circular_deque_const_iterator;

  // Dereferencing.
  T& operator*() { return const_cast<T&>(base::operator*()); }
  T* operator->() { return const_cast<T*>(base::operator->()); }

  // Random access mutation.
  friend circular_deque_iterator operator+(const circular_deque_iterator& iter,
                                           difference_type offset) {
    circular_deque_iterator ret = iter;
    ret.Add(offset);
    return ret;
  }
  circular_deque_iterator& operator+=(difference_type offset) {
    base::Add(offset);
    return *this;
  }
  friend circular_deque_iterator operator-(const circular_deque_iterator& iter,
                                           difference_type offset) {
    circular_deque_iterator ret = iter;
    ret.Add(-offset);
    return ret;
  }
  circular_deque_iterator& operator-=(difference_type offset) {
    base::Add(-offset);
    return *this;
  }

  // Increment and decrement.
  circular_deque_iterator& operator++() {
    base::Increment();
    return *this;
  }
  circular_deque_iterator operator++(int) {
    circular_deque_iterator ret = *this;
    base::Increment();
    return ret;
  }
  circular_deque_iterator& operator--() {
    base::Decrement();
    return *this;
  }
  circular_deque_iterator operator--(int) {
    circular_deque_iterator ret = *this;
    base::Decrement();
    return ret;
  }
};

}  // namespace internal

template <typename T>
class circular_deque {
 private:
  using VectorBuffer = internal::VectorBuffer<T>;

 public:
  using value_type = T;
  using size_type = std::size_t;
  using difference_type = std::ptrdiff_t;
  using reference = value_type&;
  using const_reference = const value_type&;
  using pointer = value_type*;
  using const_pointer = const value_type*;

  using iterator = internal::circular_deque_iterator<T>;
  using const_iterator = internal::circular_deque_const_iterator<T>;
  using reverse_iterator = std::reverse_iterator<iterator>;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  // ---------------------------------------------------------------------------
  // Constructor

  circular_deque() = default;

  // Constructs with |count| copies of |value| or default constructed version.
  circular_deque(size_type count) { resize(count); }
  circular_deque(size_type count, const T& value) { resize(count, value); }

  // Range constructor.
  template <class InputIterator>
  circular_deque(InputIterator first, InputIterator last) {
    assign(first, last);
  }

  // Copy/move.
  circular_deque(const circular_deque& other) : buffer_(other.size() + 1) {
    assign(other.begin(), other.end());
  }
  circular_deque(circular_deque&& other) noexcept
      : buffer_(std::move(other.buffer_)),
        begin_(other.begin_),
        end_(other.end_) {
    other.begin_ = 0;
    other.end_ = 0;
  }

  circular_deque(std::initializer_list<value_type> init) { assign(init); }

  ~circular_deque() { DestructRange(begin_, end_); }

  // ---------------------------------------------------------------------------
  // Assignments.
  //
  // All of these may invalidate iterators and references.

  circular_deque& operator=(const circular_deque& other) {
    reserve(other.size());
    assign(other.begin(), other.end());
    return *this;
  }
  circular_deque& operator=(circular_deque&& other) noexcept {
    // We're about to overwrite the buffer, so don't free it in clear to
    // avoid doing it twice.
    ClearRetainCapacity();
    buffer_ = std::move(other.buffer_);
    begin_ = other.begin_;
    end_ = other.end_;

    other.begin_ = 0;
    other.end_ = 0;

    IncrementGeneration();
    return *this;
  }
  circular_deque& operator=(std::initializer_list<value_type> ilist) {
    reserve(ilist.size());
    assign(std::begin(ilist), std::end(ilist));
    return *this;
  }

  void assign(size_type count, const value_type& value) {
    ClearRetainCapacity();
    reserve(count);
    for (size_t i = 0; i < count; i++)
      emplace_back(value);
    IncrementGeneration();
  }

  // This variant should be enabled only when InputIterator is an iterator.
  template <typename InputIterator>
  typename std::enable_if<::base::internal::is_iterator<InputIterator>::value,
                          void>::type
  assign(InputIterator first, InputIterator last) {
    // Possible future enhancement, dispatch on iterator tag type. For forward
    // iterators we can use std::difference to preallocate the space required
    // and only do one copy.
    ClearRetainCapacity();
    for (; first != last; ++first)
      emplace_back(*first);
    IncrementGeneration();
  }

  void assign(std::initializer_list<value_type> value) {
    reserve(std::distance(value.begin(), value.end()));
    assign(value.begin(), value.end());
  }

  // ---------------------------------------------------------------------------
  // Accessors.
  //
  // Since this class assumes no exceptions, at() and operator[] are equivalent.

  const value_type& at(size_type i) const {
    DCHECK(i < size());
    size_t right_size = buffer_.capacity() - begin_;
    if (begin_ <= end_ || i < right_size)
      return buffer_[begin_ + i];
    return buffer_[i - right_size];
  }
  value_type& at(size_type i) {
    return const_cast<value_type&>(
        const_cast<const circular_deque*>(this)->at(i));
  }

  value_type& operator[](size_type i) { return at(i); }
  const value_type& operator[](size_type i) const {
    return const_cast<circular_deque*>(this)->at(i);
  }

  value_type& front() {
    DCHECK(!empty());
    return buffer_[begin_];
  }
  const value_type& front() const {
    DCHECK(!empty());
    return buffer_[begin_];
  }

  value_type& back() {
    DCHECK(!empty());
    return *(--end());
  }
  const value_type& back() const {
    DCHECK(!empty());
    return *(--end());
  }

  // ---------------------------------------------------------------------------
  // Iterators.

  iterator begin() { return iterator(this, begin_); }
  const_iterator begin() const { return const_iterator(this, begin_); }
  const_iterator cbegin() const { return const_iterator(this, begin_); }

  iterator end() { return iterator(this, end_); }
  const_iterator end() const { return const_iterator(this, end_); }
  const_iterator cend() const { return const_iterator(this, end_); }

  reverse_iterator rbegin() { return reverse_iterator(begin()); }
  const_reverse_iterator rbegin() const {
    return const_reverse_iterator(begin());
  }
  const_reverse_iterator crbegin() const { return rbegin(); }

  reverse_iterator rend() { return reverse_iterator(end()); }
  const_reverse_iterator rend() const { return const_reverse_iterator(end()); }
  const_reverse_iterator crend() const { return rend(); }

  // ---------------------------------------------------------------------------
  // Memory management.

  void reserve(size_type new_capacity) {
    if (new_capacity > capacity())
      ExpandCapacityTo(new_capacity + 1);
  }
  size_type capacity() const {
    // One item is wasted to indicate end().
    return buffer_.capacity() == 0 ? 0 : buffer_.capacity() - 1;
  }
  void shrink_to_fit() {
    if (empty()) {
      // Optimize empty case to really delete everything if there was
      // something.
      if (buffer_.capacity())
        buffer_ = VectorBuffer();
    } else {
      // One item is wasted to indicate end().
      ExpandCapacityTo(size() + 1);
    }
  }

  // ---------------------------------------------------------------------------
  // Size management.

  // This will additionally reset the capacity() to 0.
  void clear() {
    // This can't resize(0) because that requires a default constructor to
    // compile, which not all contained classes may implement.
    ClearRetainCapacity();
    buffer_ = VectorBuffer();
  }

  bool empty() const { return begin_ == end_; }

  size_type size() const {
    if (begin_ <= end_)
      return end_ - begin_;
    return buffer_.capacity() - begin_ + end_;
  }

  // When reducing size, the elements are deleted from the end. When expanding
  // size, elements are added to the end with |value| or the default
  // constructed version.
  //
  // There are two versions rather than using a default value to avoid
  // creating a temporary when shrinking (when it's not needed). Plus if
  // the default constructor is desired when expanding usually just calling it
  // for each element is faster than making a default-constructed temporary and
  // copying it.
  void resize(size_type count) {
    // SEE BELOW VERSION if you change this. The code is mostly the same.
    if (count > size()) {
      // This could be slighly more efficient but expanding a queue with
      // identical elements is unusual and the extra computations of emplacing
      // one-by-one will typically be small relative to calling the constructor
      // for every item.
      ExpandCapacityIfNecessary(count - size());
      while (size() < count)
        emplace_back();
    } else if (count < size()) {
      // This doesn't resize the storage.
      // TODO(brettw) revisit this decision (change below version also).
      size_t new_end = (begin_ + count) % buffer_.capacity();
      DestructRange(new_end, end_);
      end_ = new_end;
    }
    IncrementGeneration();
  }
  void resize(size_type count, const value_type& value) {
    // SEE ABOVE VERSION if you change this. The code is mostly the same.
    if (count > size()) {
      ExpandCapacityIfNecessary(count - size());
      while (size() < count)
        emplace_back(value);
    } else if (count < size()) {
      size_t new_end = (begin_ + count) % buffer_.capacity();
      DestructRange(new_end, end_);
      end_ = new_end;
    }
    IncrementGeneration();
  }

  // ---------------------------------------------------------------------------
  // Insert and erase.
  //
  // These bulk insert operations are not provided as described in the file
  // level comment above:
  //
  //   void insert(const_iterator pos, size_type count, const T& value);
  //   void insert(const_iterator pos, InputIterator first, InputIterator last);
  //   iterator insert(const_iterator pos, const T& value);
  //   iterator insert(const_iterator pos, T&& value);
  //   iterator emplace(const_iterator pos, Args&&... args);
  //
  //   iterator erase(const_iterator pos);
  //   iterator erase(const_iterator first, const_iterator last);

  // ---------------------------------------------------------------------------
  // Begin/end operations.

  void push_front(const T& value) { emplace_front(value); }
  void push_front(T&& value) { emplace_front(std::move(value)); }

  void push_back(const T& value) { emplace_back(value); }
  void push_back(T&& value) { emplace_back(std::move(value)); }

  template <class... Args>
  void emplace_front(Args&&... args) {
    ExpandCapacityIfNecessary(1);
    if (begin_ == 0)
      begin_ = buffer_.capacity() - 1;
    else
      begin_--;
    IncrementGeneration();
    new (&buffer_[begin_]) T(std::forward<Args>(args)...);
  }

  template <class... Args>
  void emplace_back(Args&&... args) {
    ExpandCapacityIfNecessary(1);
    new (&buffer_[end_]) T(std::forward<Args>(args)...);
    if (end_ == buffer_.capacity() - 1)
      end_ = 0;
    else
      end_++;
    IncrementGeneration();
  }

  void pop_front() {
    DCHECK(size());
    buffer_.DestructRange(&buffer_[begin_], &buffer_[begin_ + 1]);
    begin_++;
    if (begin_ == buffer_.capacity())
      begin_ = 0;

    // Technically popping will not invalidate any iterators since the
    // underlying buffer will be stable. But in the future we may want to add a
    // feature that resizes the buffer smaller if there is too much wasted
    // space. This ensures we can make such a change safely.
    IncrementGeneration();
  }
  void pop_back() {
    DCHECK(size());
    if (end_ == 0)
      end_ = buffer_.capacity() - 1;
    else
      end_--;
    buffer_.DestructRange(&buffer_[end_], &buffer_[end_ + 1]);

    // See pop_front comment about why this is here.
    IncrementGeneration();
  }

  // ---------------------------------------------------------------------------
  // General operations.

  void swap(circular_deque& other) {
    std::swap(buffer_, other.buffer_);
    std::swap(begin_, other.begin_);
    std::swap(end_, other.end_);
    IncrementGeneration();
  }

  friend void swap(circular_deque& lhs, circular_deque& rhs) { lhs.swap(rhs); }

 private:
  friend internal::circular_deque_iterator<T>;
  friend internal::circular_deque_const_iterator<T>;

  // Moves the items in the given circular buffer to the current one. The
  // source is moved from so will become invalid. The destination buffer must
  // have already been allocated with enough size.
  static void MoveBuffer(VectorBuffer& from_buf,
                         size_t from_begin,
                         size_t from_end,
                         VectorBuffer* to_buf,
                         size_t* to_begin,
                         size_t* to_end) {
    size_t from_capacity = from_buf.capacity();

    *to_begin = 0;
    if (from_begin < from_end) {
      // Contiguous.
      from_buf.MoveRange(&from_buf[from_begin], &from_buf[from_end],
                         to_buf->begin());
      *to_end = from_end - from_begin;
    } else if (from_begin > from_end) {
      // Discontiguous, copy the right side to the beginning of the new buffer.
      from_buf.MoveRange(&from_buf[from_begin], &from_buf[from_capacity],
                         to_buf->begin());
      size_t right_size = from_capacity - from_begin;
      // Append the left side.
      from_buf.MoveRange(&from_buf[0], &from_buf[from_end],
                         &(*to_buf)[right_size]);
      *to_end = right_size + from_end;
    } else {
      // No items.
      *to_end = 0;
    }
  }

  // Expands the buffer size. This assumes the size is larger than the
  // number of elements in the vector (it won't call delete on anything).
  // Note the capacity passed here will be one larger than the "publicly
  // exposed capacity" to account for the unused end element.
  void ExpandCapacityTo(size_t new_capacity) {
    VectorBuffer new_buffer(new_capacity);
    MoveBuffer(buffer_, begin_, end_, &new_buffer, &begin_, &end_);
    buffer_ = std::move(new_buffer);
  }
  void ExpandCapacityIfNecessary(size_t additional_elts) {
    // Capacity is internal capacity, which is one extra.
    size_t min_new_capacity = size() + additional_elts + 1;
    if (buffer_.capacity() >= min_new_capacity)
      return;  // Already enough room.

    // Start allocating nonempty buffers with this many entries.
    constexpr size_t min_slots = 4;
    min_new_capacity = std::max(min_new_capacity, min_slots);

    // std::vector always grows by at least 50%. WTF::Deque grows by at least
    // 25%. We expect queue workloads to generally stay at a similar size and
    // grow less than a vector might, so use 25%.
    size_t new_capacity = std::max(
        min_new_capacity, buffer_.capacity() + buffer_.capacity() / 4 + 1);
    ExpandCapacityTo(new_capacity);
  }

  // Backend for clear() but does not resize the internal buffer.
  void ClearRetainCapacity() {
    // This can't resize(0) because that requires a default constructor to
    // compile, which not all contained classes may implement.
    DestructRange(begin_, end_);
    begin_ = 0;
    end_ = 0;
    IncrementGeneration();
  }

  // Calls destructors for the given begin->end indices. The indices may wrap
  // around. The buffer is not resized, and the begin_ and end_ members are
  // not changed.
  void DestructRange(size_t begin, size_t end) {
    if (end == begin) {
      return;
    } else if (end > begin) {
      buffer_.DestructRange(&buffer_[begin], &buffer_[end]);
    } else {
      buffer_.DestructRange(&buffer_[begin], &buffer_[buffer_.capacity()]);
      buffer_.DestructRange(&buffer_[0], &buffer_[end]);
    }
  }

#if DCHECK_IS_ON()
  // Asserts the given index is dereferencable. The index is an index into the
  // buffer, not an index used by operator[] or at() which will be offsets from
  // begin.
  void CheckValidIndex(size_t i) const {
    if (begin_ <= end_)
      DCHECK(i >= begin_ && i < end_);
    else
      DCHECK((i >= begin_ && i < buffer_.capacity()) || i < end_);
  }

  // Asserts the given index is either dereferencable or points to end().
  void CheckValidIndexOrEnd(size_t i) const {
    if (i != end_)
      CheckValidIndex(i);
  }

  // See generation_ below.
  void IncrementGeneration() { generation_++; }
#else
  // No-op versions of these functions for release builds.
  void CheckValidIndex(size_t) const {}
  void CheckValidIndexOrEnd(size_t) const {}
  void IncrementGeneration() {}
#endif

  // Danger, the buffer_.capacity() is capacity() + 1 since there is an
  // extra item to indicate the end. Container internal code will want to use
  // buffer_.capacity() for offset computations.
  VectorBuffer buffer_;
  size_type begin_ = 0;
  size_type end_ = 0;

#if DCHECK_IS_ON()
  // Incremented every time a modification that could affect iterator
  // invalidations.
  uint64_t generation_ = 0;
#endif
};

}  // namespace base

#endif  // BASE_CONTAINERS_CIRCULAR_DEQUE_H_
