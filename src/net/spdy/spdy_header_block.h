// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_SPDY_HEADER_BLOCK_H_
#define NET_SPDY_SPDY_HEADER_BLOCK_H_

#include <stddef.h>

#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/linked_hash_map.h"
#include "net/base/net_export.h"
#include "net/log/net_log.h"

namespace base {
class Value;
}

namespace net {

class NetLogCaptureMode;

namespace test {
class SpdyHeaderBlockPeer;
class ValueProxyPeer;
}

// This class provides a key-value map that can be used to store SPDY header
// names and values. This data structure preserves insertion order.
//
// Under the hood, this data structure uses large, contiguous blocks of memory
// to store names and values. Lookups may be performed with StringPiece keys,
// and values are returned as StringPieces (via ValueProxy, below).
// Value StringPieces are valid as long as the SpdyHeaderBlock exists; allocated
// memory is never freed until SpdyHeaderBlock's destruction.
//
// This implementation does not make much of an effort to minimize wasted space.
// It's expected that keys are rarely deleted from a SpdyHeaderBlock.
class NET_EXPORT SpdyHeaderBlock {
 private:
  class Storage;

  // Stores a list of value fragments that can be joined later with a
  // key-dependent separator.
  class NET_EXPORT HeaderValue {
   public:
    HeaderValue(Storage* storage,
                base::StringPiece key,
                base::StringPiece initial_value);

    // Moves are allowed.
    HeaderValue(HeaderValue&& other);
    HeaderValue& operator=(HeaderValue&& other);

    // Copies are not.
    HeaderValue(const HeaderValue& other) = delete;
    HeaderValue& operator=(const HeaderValue& other) = delete;

    ~HeaderValue();

    // Consumes at most |fragment.size()| bytes of memory.
    void Append(base::StringPiece fragment);

    base::StringPiece value() const { return as_pair().second; }
    const std::pair<base::StringPiece, base::StringPiece>& as_pair() const;

   private:
    // May allocate a large contiguous region of memory to hold the concatenated
    // fragments and separators.
    base::StringPiece ConsolidatedValue() const;

    mutable Storage* storage_;
    mutable std::vector<base::StringPiece> fragments_;
    // The first element is the key; the second is the consolidated value.
    mutable std::pair<base::StringPiece, base::StringPiece> pair_;
  };

  typedef linked_hash_map<base::StringPiece, HeaderValue, base::StringPieceHash>
      MapType;

 public:
  typedef std::pair<base::StringPiece, base::StringPiece> value_type;

  // Provides iteration over a sequence of std::pair<StringPiece, StringPiece>,
  // even though the underlying MapType::value_type is different. Dereferencing
  // the iterator will result in memory allocation for multi-value headers.
  class NET_EXPORT iterator {
   public:
    // The following type definitions fulfill the requirements for iterator
    // implementations.
    typedef std::pair<base::StringPiece, base::StringPiece> value_type;
    typedef value_type& reference;
    typedef value_type* pointer;
    typedef std::forward_iterator_tag iterator_category;
    typedef MapType::iterator::difference_type difference_type;

    // In practice, this iterator only offers access to const value_type.
    typedef const value_type& const_reference;
    typedef const value_type* const_pointer;

    explicit iterator(MapType::const_iterator it);
    iterator(const iterator& other);
    ~iterator();

    // This will result in memory allocation if the value consists of multiple
    // fragments.
    const_reference operator*() const { return it_->second.as_pair(); }

    const_pointer operator->() const { return &(this->operator*()); }
    bool operator==(const iterator& it) const { return it_ == it.it_; }
    bool operator!=(const iterator& it) const { return !(*this == it); }

    iterator& operator++() {
      it_++;
      return *this;
    }

    iterator operator++(int) {
      auto ret = *this;
      this->operator++();
      return ret;
    }

   private:
    MapType::const_iterator it_;
  };
  typedef iterator const_iterator;

  class ValueProxy;

  SpdyHeaderBlock();
  SpdyHeaderBlock(const SpdyHeaderBlock& other) = delete;
  SpdyHeaderBlock(SpdyHeaderBlock&& other);
  ~SpdyHeaderBlock();

  SpdyHeaderBlock& operator=(const SpdyHeaderBlock& other) = delete;
  SpdyHeaderBlock& operator=(SpdyHeaderBlock&& other);
  SpdyHeaderBlock Clone() const;

  bool operator==(const SpdyHeaderBlock& other) const;
  bool operator!=(const SpdyHeaderBlock& other) const;

  // Provides a human readable multi-line representation of the stored header
  // keys and values.
  std::string DebugString() const;

  iterator begin() { return iterator(block_.begin()); }
  iterator end() { return iterator(block_.end()); }
  const_iterator begin() const { return const_iterator(block_.begin()); }
  const_iterator end() const { return const_iterator(block_.end()); }
  bool empty() const { return block_.empty(); }
  size_t size() const { return block_.size(); }
  iterator find(base::StringPiece key) { return iterator(block_.find(key)); }
  const_iterator find(base::StringPiece key) const {
    return const_iterator(block_.find(key));
  }
  void erase(base::StringPiece key) { block_.erase(key); }

  // Clears both our MapType member and the memory used to hold headers.
  void clear();

  // The next few methods copy data into our backing storage.

  // If key already exists in the block, replaces the value of that key. Else
  // adds a new header to the end of the block.
  void insert(const value_type& value);

  // If a header with the key is already present, then append the value to the
  // existing header value, NUL ("\0") separated unless the key is cookie, in
  // which case the separator is "; ".
  // If there is no such key, a new header with the key and value is added.
  void AppendValueOrAddHeader(const base::StringPiece key,
                              const base::StringPiece value);

  // Allows either lookup or mutation of the value associated with a key.
  ValueProxy operator[](const base::StringPiece key);

  // This object provides automatic conversions that allow SpdyHeaderBlock to be
  // nearly a drop-in replacement for linked_hash_map<string, string>. It reads
  // data from or writes data to a SpdyHeaderBlock::Storage.
  class NET_EXPORT ValueProxy {
   public:
    ~ValueProxy();

    // Moves are allowed.
    ValueProxy(ValueProxy&& other);
    ValueProxy& operator=(ValueProxy&& other);

    // Copies are not.
    ValueProxy(const ValueProxy& other) = delete;
    ValueProxy& operator=(const ValueProxy& other) = delete;

    // Assignment modifies the underlying SpdyHeaderBlock.
    ValueProxy& operator=(const base::StringPiece other);

    std::string as_string() const;

   private:
    friend class SpdyHeaderBlock;
    friend class test::ValueProxyPeer;

    ValueProxy(SpdyHeaderBlock::MapType* block,
               SpdyHeaderBlock::Storage* storage,
               SpdyHeaderBlock::MapType::iterator lookup_result,
               const base::StringPiece key);

    SpdyHeaderBlock::MapType* block_;
    SpdyHeaderBlock::Storage* storage_;
    SpdyHeaderBlock::MapType::iterator lookup_result_;
    base::StringPiece key_;
    bool valid_;
  };

  // Returns the estimate of dynamically allocated memory in bytes.
  size_t EstimateMemoryUsage() const;

 private:
  friend class test::SpdyHeaderBlockPeer;

  void AppendHeader(const base::StringPiece key, const base::StringPiece value);
  Storage* GetStorage();
  size_t bytes_allocated() const;

  // StringPieces held by |block_| point to memory owned by |*storage_|.
  // |storage_| might be nullptr as long as |block_| is empty.
  MapType block_;
  std::unique_ptr<Storage> storage_;
};

// Writes |fragments| to |dst|, joined by |separator|. |dst| must be large
// enough to hold the result. Returns the number of bytes written.
NET_EXPORT size_t Join(char* dst,
                       const std::vector<base::StringPiece>& fragments,
                       base::StringPiece separator);

// Converts a SpdyHeaderBlock into NetLog event parameters.
NET_EXPORT std::unique_ptr<base::Value> SpdyHeaderBlockNetLogCallback(
    const SpdyHeaderBlock* headers,
    NetLogCaptureMode capture_mode);

// Converts NetLog event parameters into a SPDY header block and writes them
// to |headers|.  |event_param| must have been created by
// SpdyHeaderBlockNetLogCallback.  On failure, returns false and clears
// |headers|.
NET_EXPORT bool SpdyHeaderBlockFromNetLogParam(
    const base::Value* event_param,
    SpdyHeaderBlock* headers);

}  // namespace net

#endif  // NET_SPDY_SPDY_HEADER_BLOCK_H_
