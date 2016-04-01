// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_BALSA_BALSA_HEADERS_H_
#define NET_TOOLS_BALSA_BALSA_HEADERS_H_

#include <stddef.h>

#include <algorithm>
#include <iosfwd>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "net/tools/balsa/balsa_enums.h"
#include "net/tools/balsa/string_piece_utils.h"

namespace net {

// WARNING:
// Note that -no- char* returned by any function in this
// file is null-terminated.

// This class exists to service the specific needs of BalsaHeaders.
//
// Functional goals:
//   1) provide a backing-store for all of the StringPieces that BalsaHeaders
//      returns. Every StringPiece returned from BalsaHeaders should remain
//      valid until the BalsaHeader's object is cleared, or the header-line is
//      erased.
//   2) provide a backing-store for BalsaFrame, which requires contiguous memory
//      for its fast-path parsing functions. Note that the cost of copying is
//      less than the cost of requiring the parser to do slow-path parsing, as
//      it would have to check for bounds every byte, instead of every 16 bytes.
//
// This class is optimized for the case where headers are stored in one of two
// buffers. It doesn't make a lot of effort to densely pack memory-- in fact,
// it -may- be somewhat memory inefficient. This possible inefficiency allows a
// certain simplicity of implementation and speed which makes it worthwhile.
// If, in the future, better memory density is required, it should be possible
// to reuse the abstraction presented by this object to achieve those goals.
//
// In the most common use-case, this memory inefficiency should be relatively
// small.
//
// Alternate implementations of BalsaBuffer may include:
//  - vector of strings, one per header line (similar to HTTPHeaders)
//  - densely packed strings:
//    - keep a sorted array/map of free-space linked lists or numbers.
//      - use the entry that most closely first your needs.
//    - at this point, perhaps just use a vector of strings, and let
//      the allocator do the right thing.
//
class BalsaBuffer {
 public:
  static const size_t kDefaultBlocksize = 4096;
  // We have two friends here. These exist as friends as we
  // want to allow access to the constructors for the test
  // class and the Balsa* classes. We put this into the
  // header file as we want this class to be inlined into the
  // BalsaHeaders implementation, yet be testable.
  friend class BalsaBufferTestSpouse;
  friend class BalsaHeaders;
  friend class BalsaBufferTest;

  // The BufferBlock is a structure used internally by the
  // BalsaBuffer class to store the base buffer pointers to
  // each block, as well as the important metadata for buffer
  // sizes and bytes free.
  struct BufferBlock {
   public:
    char* buffer;
    size_t buffer_size;
    size_t bytes_free;

    size_t bytes_used() const {
      return buffer_size - bytes_free;
    }
    char* start_of_unused_bytes() const {
      return buffer + bytes_used();
    }

    BufferBlock() : buffer(NULL), buffer_size(0), bytes_free(0) {}
    ~BufferBlock() {}

    BufferBlock(char* buf, size_t size, size_t free) :
        buffer(buf), buffer_size(size), bytes_free(free) {}
    // Yes we want this to be copyable (it gets stuck into vectors).
    // For this reason, we don't use scoped ptrs, etc. here-- it
    // is more efficient to manage this memory externally to this
    // object.
  };

  typedef std::vector<BufferBlock> Blocks;

  ~BalsaBuffer();

  // Returns the total amount of memory used by the buffer blocks.
  size_t GetTotalBufferBlockSize() const;

  const char* GetPtr(Blocks::size_type block_idx) const {
    DCHECK_LT(block_idx, blocks_.size())
      << block_idx << ", " << blocks_.size();
    return blocks_[block_idx].buffer;
  }

  char* GetPtr(Blocks::size_type block_idx) {
    DCHECK_LT(block_idx, blocks_.size())
      << block_idx << ", " << blocks_.size();
    return blocks_[block_idx].buffer;
  }

  // This function is different from Write(), as it ensures that the data
  // stored via subsequent calls to this function are all contiguous (and in
  // the order in which these writes happened). This is essentially the same
  // as a string append.
  //
  // You may call this function at any time between object
  // construction/Clear(), and the calling of the
  // NoMoreWriteToContiguousBuffer() function.
  //
  // You must not call this function after the NoMoreWriteToContiguousBuffer()
  // function is called, unless a Clear() has been called since.
  // If you do, the program will abort().
  //
  // This condition is placed upon this code so that calls to Write() can
  // append to the buffer in the first block safely, and without invaliding
  // the StringPiece which it returns.
  //
  // This function's main intended user is the BalsaFrame class, which,
  // for reasons of efficiency, requires that the buffer from which it parses
  // the headers be contiguous.
  //
  void WriteToContiguousBuffer(const base::StringPiece& sp);

  void NoMoreWriteToContiguousBuffer() {
    can_write_to_contiguous_buffer_ = false;
  }

  // Takes a StringPiece and writes it to "permanent" storage, then returns a
  // StringPiece which points to that data.  If block_idx != NULL, it will be
  // assigned the index of the block into which the data was stored.
  // Note that the 'permanent' storage in which it stores data may be in
  // the first block IFF the NoMoreWriteToContiguousBuffer function has
  // been called since the last Clear/Construction.
  base::StringPiece Write(const base::StringPiece& sp,
                          Blocks::size_type* block_buffer_idx);

  // Reserves "permanent" storage of the size indicated. Returns a pointer to
  // the beginning of that storage, and assigns the index of the block used to
  // block_buffer_idx. This function uses the first block IFF the
  // NoMoreWriteToContiguousBuffer function has been called since the last
  // Clear/Construction.
  char* Reserve(size_t size, Blocks::size_type* block_buffer_idx);

  void Clear();

  void Swap(BalsaBuffer* b);

  void CopyFrom(const BalsaBuffer& b);

  const char* StartOfFirstBlock() const {
    return blocks_[0].buffer;
  }

  const char* EndOfFirstBlock() const {
    return blocks_[0].buffer + blocks_[0].bytes_used();
  }

  bool can_write_to_contiguous_buffer() const {
    return can_write_to_contiguous_buffer_;
  }
  size_t blocksize() const { return blocksize_; }
  Blocks::size_type num_blocks() const { return blocks_.size(); }
  size_t buffer_size(size_t idx) const { return blocks_[idx].buffer_size; }
  size_t bytes_used(size_t idx) const { return blocks_[idx].bytes_used(); }

 protected:
  BalsaBuffer();

  explicit BalsaBuffer(size_t blocksize);

  BufferBlock AllocBlock();

  BufferBlock AllocCustomBlock(size_t blocksize);

  BufferBlock CopyBlock(const BufferBlock& b);

  // Cleans up the object.
  // The block at start_idx, and all subsequent blocks
  // will be cleared and have associated memory deleted.
  void CleanupBlocksStartingFrom(Blocks::size_type start_idx);

  // A container of BufferBlocks
  Blocks blocks_;

  // The default allocation size for a block.
  // In general, blocksize_ bytes will be allocated for
  // each buffer.
  size_t blocksize_;

  // If set to true, then the first block cannot be used for Write() calls as
  // the WriteToContiguous... function will modify the base pointer for this
  // block, and the Write() calls need to be sure that the base pointer will
  // not be changing in order to provide the user with StringPieces which
  // continue to be valid.
  bool can_write_to_contiguous_buffer_;
};

////////////////////////////////////////////////////////////////////////////////

// All of the functions in the BalsaHeaders class use string pieces, by either
// using the StringPiece class, or giving an explicit size and char* (as these
// are the native representation for these string pieces).
// This is done for several reasons.
//  1) This minimizes copying/allocation/deallocation as compared to using
//  string parameters
//  2) This reduces the number of strlen() calls done (as the length of any
//  string passed in is relatively likely to be known at compile time, and for
//  those strings passed back we obviate the need for a strlen() to determine
//  the size of new storage allocations if a new allocation is required.
//  3) This class attempts to store all of its data in two linear buffers in
//  order to enhance the speed of parsing and writing out to a buffer. As a
//  result, many string pieces are -not- terminated by '\0', and are not
//  c-strings.  Since this is the case, we must delineate the length of the
//  string explicitly via a length.
//
//  WARNING:  The side effect of using StringPiece is that if the underlying
//  buffer changes (due to modifying the headers) the StringPieces which point
//  to the data which was modified, may now contain "garbage", and should not
//  be dereferenced.
//  For example, If you fetch some component of the first-line, (request or
//  response), and then you modify the first line, the StringPieces you
//  originally received from the original first-line may no longer be valid).
//
//  StringPieces pointing to pieces of header lines which have not been
//  erased() or modified should be valid until the object is cleared or
//  destroyed.

class BalsaHeaders {
 public:
  struct HeaderLineDescription {
    HeaderLineDescription(size_t first_character_index,
                          size_t key_end_index,
                          size_t value_begin_index,
                          size_t last_character_index,
                          size_t buffer_base_index) :
        first_char_idx(first_character_index),
        key_end_idx(key_end_index),
        value_begin_idx(value_begin_index),
        last_char_idx(last_character_index),
        buffer_base_idx(buffer_base_index),
        skip(false) {}

    HeaderLineDescription() :
        first_char_idx(0),
        key_end_idx(0),
        value_begin_idx(0),
        last_char_idx(0),
        buffer_base_idx(0),
        skip(false) {}

    size_t first_char_idx;
    size_t key_end_idx;
    size_t value_begin_idx;
    size_t last_char_idx;
    BalsaBuffer::Blocks::size_type buffer_base_idx;
    bool skip;
  };

  typedef std::vector<base::StringPiece> HeaderTokenList;
  friend bool ParseHTTPFirstLine(const char* begin,
                                 const char* end,
                                 bool is_request,
                                 size_t max_request_uri_length,
                                 BalsaHeaders* headers,
                                 BalsaFrameEnums::ErrorCode* error_code);

 protected:
  typedef std::vector<HeaderLineDescription> HeaderLines;

  // Why these base classes (iterator_base, reverse_iterator_base)?  Well, if
  // we do want to export both iterator and const_iterator types (currently we
  // only have const_iterator), then this is useful to avoid code duplication.
  // Additionally, having this base class makes comparisons of iterators of
  // different types (they're different types to ensure that operator= and
  // constructors do not work in the places where they're expected to not work)
  // work properly. There could be as many as 4 iterator types, all based on
  // the same data as iterator_base... so it makes sense to simply have some
  // base classes.

  class iterator_base {
   public:
    friend class BalsaHeaders;
    friend class reverse_iterator_base;
    typedef std::pair<base::StringPiece, base::StringPiece> StringPiecePair;
    typedef StringPiecePair value_type;
    typedef value_type& reference;
    typedef value_type* pointer;

    typedef std::forward_iterator_tag iterator_category;
    typedef ptrdiff_t difference_type;

    typedef iterator_base self;

    // default constructor.
    iterator_base();

    // copy constructor.
    iterator_base(const iterator_base& it);

    reference operator*() const {
      return Lookup(idx_);
    }

    pointer operator->() const {
      return &(this->operator*());
    }

    bool operator==(const self& it) const {
      return idx_ == it.idx_;
    }

    bool operator<(const self& it) const {
      return idx_ < it.idx_;
    }

    bool operator<=(const self& it) const {
      return idx_ <= it.idx_;
    }

    bool operator!=(const self& it) const {
      return !(*this == it);
    }

    bool operator>(const self& it) const {
      return it < *this;
    }

    bool operator>=(const self& it) const {
      return it <= *this;
    }

    // This mainly exists so that we can have interesting output for
    // unittesting. The EXPECT_EQ, EXPECT_NE functions require that
    // operator<< work for the classes it sees.  It would be better if there
    // was an additional traits-like system for the gUnit output... but oh
    // well.
    std::ostream& operator<<(std::ostream& os) const;

   protected:
    iterator_base(const BalsaHeaders* headers, HeaderLines::size_type index);

    void increment() {
      const HeaderLines& header_lines = headers_->header_lines_;
      const HeaderLines::size_type header_lines_size = header_lines.size();
      const HeaderLines::size_type original_idx = idx_;
      do {
        ++idx_;
      } while (idx_ < header_lines_size && header_lines[idx_].skip == true);
      // The condition below exists so that ++(end() - 1) == end(), even
      // if there are only 'skip == true' elements between the end() iterator
      // and the end of the vector of HeaderLineDescriptions.
      // TODO(fenix): refactor this list so that we don't have to do
      // linear scanning through skipped headers (and this condition is
      // then unnecessary)
      if (idx_ == header_lines_size) {
        idx_ = original_idx + 1;
      }
    }

    void decrement() {
      const HeaderLines& header_lines = headers_->header_lines_;
      const HeaderLines::size_type header_lines_size = header_lines.size();
      const HeaderLines::size_type original_idx = idx_;
      do {
        --idx_;
      } while (idx_ < header_lines_size && header_lines[idx_].skip == true);
      // The condition below exists so that --(rbegin() + 1) == rbegin(), even
      // if there are only 'skip == true' elements between the rbegin() iterator
      // and the beginning of the vector of HeaderLineDescriptions.
      // TODO(fenix): refactor this list so that we don't have to do
      // linear scanning through skipped headers (and this condition is
      // then unnecessary)
      if (idx_ > header_lines_size) {
        idx_ = original_idx - 1;
      }
    }

    reference Lookup(HeaderLines::size_type index) const {
      DCHECK_LT(index, headers_->header_lines_.size());
      const HeaderLineDescription& line = headers_->header_lines_[index];
      const char* stream_begin = headers_->GetPtr(line.buffer_base_idx);
      value_ = value_type(
          base::StringPiece(stream_begin + line.first_char_idx,
                      line.key_end_idx - line.first_char_idx),
          base::StringPiece(stream_begin + line.value_begin_idx,
                      line.last_char_idx - line.value_begin_idx));
      DCHECK_GE(line.key_end_idx, line.first_char_idx);
      DCHECK_GE(line.last_char_idx, line.value_begin_idx);
      return value_;
    }

    const BalsaHeaders* headers_;
    HeaderLines::size_type idx_;
    mutable StringPiecePair value_;
  };

  class reverse_iterator_base : public iterator_base {
   public:
    typedef reverse_iterator_base self;
    typedef iterator_base::reference reference;
    typedef iterator_base::pointer pointer;
    using iterator_base::headers_;
    using iterator_base::idx_;

    reverse_iterator_base() : iterator_base() {}

    // This constructor is no explicit purposely.
    reverse_iterator_base(const iterator_base& it) :  // NOLINT
        iterator_base(it) {
    }

    self& operator=(const iterator_base& it) {
      idx_ = it.idx_;
      headers_ = it.headers_;
      return *this;
    }

    self& operator=(const reverse_iterator_base& it) {
      idx_ = it.idx_;
      headers_ = it.headers_;
      return *this;
    }

    reference operator*() const {
      return Lookup(idx_ - 1);
    }

    pointer operator->() const {
      return &(this->operator*());
    }

    reverse_iterator_base(const reverse_iterator_base& it) :
        iterator_base(it) { }

   protected:
    void increment() {
      --idx_;
      iterator_base::decrement();
      ++idx_;
    }

    void decrement() {
      ++idx_;
      iterator_base::increment();
      --idx_;
    }

    reverse_iterator_base(const BalsaHeaders* headers,
                          HeaderLines::size_type index) :
        iterator_base(headers, index) {}
  };

 public:
  class const_header_lines_iterator : public iterator_base {
    friend class BalsaHeaders;
   public:
    typedef const_header_lines_iterator self;
    const_header_lines_iterator() : iterator_base() {}

    const_header_lines_iterator(const const_header_lines_iterator& it) :
        iterator_base(it.headers_, it.idx_) {}

    self& operator++() {
      iterator_base::increment();
      return *this;
    }

    self& operator--() {
      iterator_base::decrement();
      return *this;
    }
   protected:
    const_header_lines_iterator(const BalsaHeaders* headers,
                                HeaderLines::size_type index) :
        iterator_base(headers, index) {}
  };

  class const_reverse_header_lines_iterator : public reverse_iterator_base {
   public:
    typedef const_reverse_header_lines_iterator self;
    const_reverse_header_lines_iterator() : reverse_iterator_base() {}

    const_reverse_header_lines_iterator(
      const const_header_lines_iterator& it) :
        reverse_iterator_base(it.headers_, it.idx_) {}

    const_reverse_header_lines_iterator(
      const const_reverse_header_lines_iterator& it) :
        reverse_iterator_base(it.headers_, it.idx_) {}

    const_header_lines_iterator base() {
      return const_header_lines_iterator(headers_, idx_);
    }

    self& operator++() {
      reverse_iterator_base::increment();
      return *this;
    }

    self& operator--() {
      reverse_iterator_base::decrement();
      return *this;
    }
   protected:
    const_reverse_header_lines_iterator(const BalsaHeaders* headers,
                                        HeaderLines::size_type index) :
        reverse_iterator_base(headers, index) {}

    friend class BalsaHeaders;
  };

  // An iterator that only stops at lines with a particular key.
  // See also GetIteratorForKey.
  //
  // Check against header_lines_key_end() to determine when iteration is
  // finished. header_lines_end() will also work.
  class const_header_lines_key_iterator : public iterator_base {
    friend class BalsaHeaders;
   public:
    typedef const_header_lines_key_iterator self;
    const_header_lines_key_iterator(const const_header_lines_key_iterator&);

    self& operator++() {
      do {
        iterator_base::increment();
      } while (!AtEnd() &&
               !base::EqualsCaseInsensitiveASCII(key_, (**this).first));
      return *this;
    }

    void operator++(int ignore) {
      ++(*this);
    }

    // Only forward-iteration makes sense, so no operator-- defined.

   private:
    const_header_lines_key_iterator(const BalsaHeaders* headers,
                                    HeaderLines::size_type index,
                                    const base::StringPiece& key);

    // Should only be used for creating an end iterator.
    const_header_lines_key_iterator(const BalsaHeaders* headers,
                                    HeaderLines::size_type index);

    bool AtEnd() const {
      return *this >= headers_->header_lines_end();
    }

    base::StringPiece key_;
  };

  // TODO(fenix): Revisit the amount of bytes initially allocated to the second
  // block of the balsa_buffer_. It may make sense to pre-allocate some amount
  // (roughly the amount we'd append in new headers such as X-User-Ip, etc.)
  BalsaHeaders();
  ~BalsaHeaders();

  const_header_lines_iterator header_lines_begin() {
    return HeaderLinesBeginHelper<const_header_lines_iterator>();
  }

  const_header_lines_iterator header_lines_begin() const {
    return HeaderLinesBeginHelper<const_header_lines_iterator>();
  }

  const_header_lines_iterator header_lines_end() {
    return HeaderLinesEndHelper<const_header_lines_iterator>();
  }

  const_header_lines_iterator header_lines_end() const {
    return HeaderLinesEndHelper<const_header_lines_iterator>();
  }

  const_reverse_header_lines_iterator header_lines_rbegin() {
    return const_reverse_header_lines_iterator(header_lines_end());
  }

  const_reverse_header_lines_iterator header_lines_rbegin() const {
    return const_reverse_header_lines_iterator(header_lines_end());
  }

  const_reverse_header_lines_iterator header_lines_rend() {
    return const_reverse_header_lines_iterator(header_lines_begin());
  }

  const_reverse_header_lines_iterator header_lines_rend() const {
    return const_reverse_header_lines_iterator(header_lines_begin());
  }

  const_header_lines_key_iterator header_lines_key_end() const {
    return HeaderLinesEndHelper<const_header_lines_key_iterator>();
  }

  void erase(const const_header_lines_iterator& it) {
    DCHECK_EQ(it.headers_, this);
    DCHECK_LT(it.idx_, header_lines_.size());
    DCHECK_GE(it.idx_, 0u);
    header_lines_[it.idx_].skip = true;
  }

  void Clear();

  void Swap(BalsaHeaders* other);

  void CopyFrom(const BalsaHeaders& other);

  void HackHeader(const base::StringPiece& key, const base::StringPiece& value);

  // Same as AppendToHeader, except that it will attempt to preserve
  // header ordering.
  // Note that this will always append to an existing header, if available,
  // without moving the header around, or collapsing multiple header lines
  // with the same key together. For this reason, it only 'attempts' to
  // preserve header ordering.
  // TODO(fenix): remove this function and rename all occurances
  // of it in the code to AppendToHeader when the condition above
  // has been satisified.
  void HackAppendToHeader(const base::StringPiece& key,
                          const base::StringPiece& value);

  // Replaces header entries with key 'key' if they exist, or appends
  // a new header if none exist.  See 'AppendHeader' below for additional
  // comments about ContentLength and TransferEncoding headers. Note that this
  // will allocate new storage every time that it is called.
  // TODO(fenix): modify this function to reuse existing storage
  // if it is available.
  void ReplaceOrAppendHeader(const base::StringPiece& key,
                             const base::StringPiece& value);

  // Append a new header entry to the header object. Clients who wish to append
  // Content-Length header should use SetContentLength() method instead of
  // adding the content length header using AppendHeader (manually adding the
  // content length header will not update the content_length_ and
  // content_length_status_ values).
  // Similarly, clients who wish to add or remove the transfer encoding header
  // in order to apply or remove chunked encoding should use SetChunkEncoding()
  // instead.
  void AppendHeader(const base::StringPiece& key,
                    const base::StringPiece& value);

  // Appends ',value' to an existing header named 'key'.  If no header with the
  // correct key exists, it will call AppendHeader(key, value).  Calling this
  // function on a key which exists several times in the headers will produce
  // unpredictable results.
  void AppendToHeader(const base::StringPiece& key,
                      const base::StringPiece& value);

  // Prepends 'value,' to an existing header named 'key'.  If no header with the
  // correct key exists, it will call AppendHeader(key, value).  Calling this
  // function on a key which exists several times in the headers will produce
  // unpredictable results.
  void PrependToHeader(const base::StringPiece& key,
                       const base::StringPiece& value);

  const base::StringPiece GetHeader(const base::StringPiece& key) const;

  // Iterates over all currently valid header lines, appending their
  // values into the vector 'out', in top-to-bottom order.
  // Header-lines which have been erased are not currently valid, and
  // will not have their values appended. Empty values will be
  // represented as empty string. If 'key' doesn't exist in the headers at
  // all, out will not be changed. We do not clear the vector out
  // before adding new entries. If there are header lines with matching
  // key but empty value then they are also added to the vector out.
  // (Basically empty values are not treated in any special manner).
  //
  // Example:
  // Input header:
  // "GET / HTTP/1.0\r\n"
  //    "key1: v1\r\n"
  //    "key1: \r\n"
  //    "key1:\r\n"
  //    "key1:  v1\r\n"
  //    "key1:v2\r\n"
  //
  //  vector out is initially: ["foo"]
  //  vector out after GetAllOfHeader("key1", &out) is:
  // ["foo", "v1", "", "", "v2", "v1", "v2"]

  void GetAllOfHeader(const base::StringPiece& key,
                      std::vector<base::StringPiece>* out) const;

  // Joins all values for key into a comma-separated string in out.
  // More efficient than calling JoinStrings on result of GetAllOfHeader if
  // you don't need the intermediate vector<StringPiece>.
  void GetAllOfHeaderAsString(const base::StringPiece& key,
                              std::string* out) const;

  // Returns true if RFC 2616 Section 14 indicates that header can
  // have multiple values.
  static bool IsMultivaluedHeader(const base::StringPiece& header);

  // Determine if a given header is present.
  inline bool HasHeader(const base::StringPiece& key) const {
    return (GetConstHeaderLinesIterator(key, header_lines_.begin()) !=
            header_lines_.end());
  }

  // Returns true iff any header 'key' exists with non-empty value.
  bool HasNonEmptyHeader(const base::StringPiece& key) const;

  const_header_lines_iterator GetHeaderPosition(
      const base::StringPiece& key) const;

  // Returns a forward-only iterator that only stops at lines matching key.
  // String backing 'key' must remain valid for lifetime of iterator.
  //
  // Check returned iterator against header_lines_key_end() to determine when
  // iteration is finished.
  const_header_lines_key_iterator GetIteratorForKey(
      const base::StringPiece& key) const;

  void RemoveAllOfHeader(const base::StringPiece& key);

  // Removes all headers starting with 'key' [case insensitive]
  void RemoveAllHeadersWithPrefix(const base::StringPiece& key);

  // Returns the lower bound of memory  used by this header object, including
  // all internal buffers and data structure. Some of the memory used cannot be
  // directly measure. For example, memory used for bookkeeping by standard
  // containers.
  size_t GetMemoryUsedLowerBound() const;

  // Returns the upper bound on the required buffer space to fully write out
  // the header object (this include the first line, all header lines, and the
  // final CRLF that marks the ending of the header).
  size_t GetSizeForWriteBuffer() const;

  // The following WriteHeader* methods are template member functions that
  // place one requirement on the Buffer class: it must implement a Write
  // method that takes a pointer and a length. The buffer passed in is not
  // required to be stretchable. For non-stretchable buffers, the user must
  // call GetSizeForWriteBuffer() to find out the upper bound on the output
  // buffer space required to make sure that the entire header is serialized.
  // BalsaHeaders will not check that there is adequate space in the buffer
  // object during the write.

  // Writes the entire header and the final CRLF that marks the end of the HTTP
  // header section to the buffer. After this method returns, no more header
  // data should be written to the buffer.
  template <typename Buffer>
  void WriteHeaderAndEndingToBuffer(Buffer* buffer) const {
    WriteToBuffer(buffer);
    WriteHeaderEndingToBuffer(buffer);
  }

  // Writes the final CRLF to the buffer to terminate the HTTP header section.
  // After this method returns, no more header data should be written to the
  // buffer.
  template <typename Buffer>
  static void WriteHeaderEndingToBuffer(Buffer* buffer) {
    buffer->Write("\r\n", 2);
  }

  // Writes the entire header to the buffer without the CRLF that terminates
  // the HTTP header. This lets users append additional header lines using
  // WriteHeaderLineToBuffer and then terminate the header with
  // WriteHeaderEndingToBuffer as the header is serialized to the
  // buffer, without having to first copy the header.
  template <typename Buffer>
  void WriteToBuffer(Buffer* buffer) const {
    // write the first line.
    const size_t firstline_len = whitespace_4_idx_ - non_whitespace_1_idx_;
    const char* stream_begin = GetPtr(firstline_buffer_base_idx_);
    buffer->Write(stream_begin + non_whitespace_1_idx_, firstline_len);
    buffer->Write("\r\n", 2);
    const HeaderLines::size_type end = header_lines_.size();
    for (HeaderLines::size_type i = 0; i < end; ++i) {
      const HeaderLineDescription& line = header_lines_[i];
      if (line.skip) {
        continue;
      }
      const char* line_ptr = GetPtr(line.buffer_base_idx);
      WriteHeaderLineToBuffer(
          buffer,
          base::StringPiece(line_ptr + line.first_char_idx,
                      line.key_end_idx - line.first_char_idx),
          base::StringPiece(line_ptr + line.value_begin_idx,
                      line.last_char_idx - line.value_begin_idx));
    }
  }

  // Takes a header line in the form of a key/value pair and append it to the
  // buffer. This function should be called after WriteToBuffer to
  // append additional header lines to the header without copying the header.
  // When the user is done with appending to the buffer,
  // WriteHeaderEndingToBuffer must be used to terminate the HTTP
  // header in the buffer. This method is a no-op if key is empty.
  template <typename Buffer>
  static void WriteHeaderLineToBuffer(Buffer* buffer,
                                      const base::StringPiece& key,
                                      const base::StringPiece& value) {
    // if the key is empty, we don't want to write the rest because it
    // will not be a well-formed header line.
    if (!key.empty()) {
      buffer->Write(key.data(), key.size());
      buffer->Write(": ", 2);
      buffer->Write(value.data(), value.size());
      buffer->Write("\r\n", 2);
    }
  }

  // Dump the textural representation of the header object to a string, which
  // is suitable for writing out to logs. All CRLF will be printed out as \n.
  // This function can be called on a header object in any state. The header
  // content is appended to the string; the original content is not cleared.
  void DumpHeadersToString(std::string* str) const;

  // Calls DumpHeadersToString to dump the textural representation of the header
  // object to a string. Raw header data will be printed out if the header
  // object is not completely parsed, e.g., when there was an error in the
  // middle of parsing.
  void DumpToString(std::string* str) const;

  const base::StringPiece first_line() const {
    DCHECK_GE(whitespace_4_idx_, non_whitespace_1_idx_);
    return base::StringPiece(BeginningOfFirstLine() + non_whitespace_1_idx_,
                       whitespace_4_idx_ - non_whitespace_1_idx_);
  }

  // Returns the parsed value of the response code if it has been parsed.
  // Guaranteed to return 0 when unparsed (though it is a much better idea to
  // verify that the BalsaFrame had no errors while parsing).
  // This may return response codes which are outside the normal bounds of
  // HTTP response codes-- it is up to the user of this class to ensure that
  // the response code is one which is interpretable.
  size_t parsed_response_code() const { return parsed_response_code_; }

  const base::StringPiece request_method() const {
    DCHECK_GE(whitespace_2_idx_, non_whitespace_1_idx_);
    return base::StringPiece(BeginningOfFirstLine() + non_whitespace_1_idx_,
                       whitespace_2_idx_ - non_whitespace_1_idx_);
  }

  const base::StringPiece response_version() const {
    // Note: There is no difference between request_method() and
    // response_version(). They both could be called
    // GetFirstTokenFromFirstline()... but that wouldn't be anywhere near as
    // descriptive.
    return request_method();
  }

  const base::StringPiece request_uri() const {
    DCHECK_GE(whitespace_3_idx_, non_whitespace_2_idx_);
    return base::StringPiece(BeginningOfFirstLine() + non_whitespace_2_idx_,
                       whitespace_3_idx_ - non_whitespace_2_idx_);
  }

  const base::StringPiece response_code() const {
    // Note: There is no difference between request_uri() and response_code().
    // They both could be called GetSecondtTokenFromFirstline(), but, as noted
    // in an earlier comment, that wouldn't be as descriptive.
    return request_uri();
  }

  const base::StringPiece request_version() const {
    DCHECK_GE(whitespace_4_idx_, non_whitespace_3_idx_);
    return base::StringPiece(BeginningOfFirstLine() + non_whitespace_3_idx_,
                       whitespace_4_idx_ - non_whitespace_3_idx_);
  }

  const base::StringPiece response_reason_phrase() const {
    // Note: There is no difference between request_version() and
    // response_reason_phrase(). They both could be called
    // GetThirdTokenFromFirstline(), but, as noted in an earlier comment, that
    // wouldn't be as descriptive.
    return request_version();
  }

  // Note that SetFirstLine will not update the internal indices for the
  // various bits of the first-line (and may set them all to zero).
  // If you'd like to use the accessors for the various bits of the firstline,
  // then you should use the Set* functions, or SetFirstlineFromStringPieces,
  // below, instead.
  //
  void SetFirstlineFromStringPieces(const base::StringPiece& firstline_a,
                                    const base::StringPiece& firstline_b,
                                    const base::StringPiece& firstline_c);

  void SetRequestFirstlineFromStringPieces(const base::StringPiece& method,
                                           const base::StringPiece& uri,
                                           const base::StringPiece& version) {
    SetFirstlineFromStringPieces(method, uri, version);
  }

  void SetResponseFirstlineFromStringPieces(
      const base::StringPiece& version,
      const base::StringPiece& code,
      const base::StringPiece& reason_phrase) {
    SetFirstlineFromStringPieces(version, code, reason_phrase);
  }

  // These functions are exactly the same, except that their names are
  // different. This is done so that the code using this class is more
  // expressive.
  void SetRequestMethod(const base::StringPiece& method);
  void SetResponseVersion(const base::StringPiece& version);

  void SetRequestUri(const base::StringPiece& uri);
  void SetResponseCode(const base::StringPiece& code);
  void set_parsed_response_code(size_t parsed_response_code) {
    parsed_response_code_ = parsed_response_code;
  }
  void SetParsedResponseCodeAndUpdateFirstline(size_t parsed_response_code);

  // These functions are exactly the same, except that their names are
  // different. This is done so that the code using this class is more
  // expressive.
  void SetRequestVersion(const base::StringPiece& version);
  void SetResponseReasonPhrase(const base::StringPiece& reason_phrase);

  // The biggest problem with SetFirstLine is that we don't want to use a
  // separate buffer for it.  The second biggest problem with it is that the
  // first biggest problem requires that we store offsets into a buffer instead
  // of pointers into a buffer. Cuteness aside, SetFirstLine doesn't parse
  // the individual fields of the firstline, and so accessors to those fields
  // will not work properly after calling SetFirstLine. If you want those
  // accessors to work, use the Set* functions above this one.
  // SetFirstLine is stuff useful, however, if all you care about is correct
  // serialization with the rest of the header object.
  void SetFirstLine(const base::StringPiece& line);

  // Simple accessors to some of the internal state
  bool transfer_encoding_is_chunked() const {
    return transfer_encoding_is_chunked_;
  }

  static bool ResponseCodeImpliesNoBody(size_t code) {
    // From HTTP spec section 6.1.1 all 1xx responses must not have a body,
    // as well as 204 No Content and 304 Not Modified.
    return ((code >= 100) && (code <= 199)) || (code == 204) || (code == 304);
  }

  // Note: never check this for requests. Nothing bad will happen if you do,
  // but spec does not allow requests framed by connection close.
  // TODO(vitaliyl): refactor.
  bool is_framed_by_connection_close() const {
    // We declare that response is framed by connection close if it has no
    // content-length, no transfer encoding, and is allowed to have a body by
    // the HTTP spec.
    // parsed_response_code_ is 0 for requests, so ResponseCodeImpliesNoBody
    // will return false.
    return (content_length_status_ == BalsaHeadersEnums::NO_CONTENT_LENGTH) &&
        !transfer_encoding_is_chunked_ &&
        !ResponseCodeImpliesNoBody(parsed_response_code_);
  }

  size_t content_length() const { return content_length_; }
  BalsaHeadersEnums::ContentLengthStatus content_length_status() const {
    return content_length_status_;
  }

  // SetContentLength and SetChunkEncoding modifies the header object to use
  // content-length and transfer-encoding headers in a consistent manner. They
  // set all internal flags and status so client can get a consistent view from
  // various accessors.
  void SetContentLength(size_t length);
  void SetChunkEncoding(bool chunk_encode);

 protected:
  friend class BalsaFrame;
  friend class SpdyFrame;
  friend class HTTPMessage;
  friend class BalsaHeadersTokenUtils;

  const char* BeginningOfFirstLine() const {
    return GetPtr(firstline_buffer_base_idx_);
  }

  char* GetPtr(BalsaBuffer::Blocks::size_type block_idx) {
    return balsa_buffer_.GetPtr(block_idx);
  }

  const char* GetPtr(BalsaBuffer::Blocks::size_type block_idx) const {
    return balsa_buffer_.GetPtr(block_idx);
  }

  void WriteFromFramer(const char* ptr, size_t size) {
    balsa_buffer_.WriteToContiguousBuffer(base::StringPiece(ptr, size));
  }

  void DoneWritingFromFramer() {
    balsa_buffer_.NoMoreWriteToContiguousBuffer();
  }

  const char* OriginalHeaderStreamBegin() const {
    return balsa_buffer_.StartOfFirstBlock();
  }

  const char* OriginalHeaderStreamEnd() const {
    return balsa_buffer_.EndOfFirstBlock();
  }

  size_t GetReadableBytesFromHeaderStream() const {
    return OriginalHeaderStreamEnd() - OriginalHeaderStreamBegin();
  }

  void GetReadablePtrFromHeaderStream(const char** p, size_t* s) {
    *p = OriginalHeaderStreamBegin();
    *s = GetReadableBytesFromHeaderStream();
  }

  base::StringPiece GetValueFromHeaderLineDescription(
      const HeaderLineDescription& line) const;

  void AddAndMakeDescription(const base::StringPiece& key,
                             const base::StringPiece& value,
                             HeaderLineDescription* d);

  void AppendOrPrependAndMakeDescription(const base::StringPiece& key,
                                         const base::StringPiece& value,
                                         bool append,
                                         HeaderLineDescription* d);

  // Removes all header lines with the given key starting at start.
  void RemoveAllOfHeaderStartingAt(const base::StringPiece& key,
                                   HeaderLines::iterator start);

  // If the 'key' does not exist in the headers, calls
  // AppendHeader(key, value).  Otherwise if append is true, appends ',value'
  // to the first existing header with key 'key'.  If append is false, prepends
  // 'value,' to the first existing header with key 'key'.
  void AppendOrPrependToHeader(const base::StringPiece& key,
                               const base::StringPiece& value,
                               bool append);

  HeaderLines::const_iterator GetConstHeaderLinesIterator(
      const base::StringPiece& key,
      HeaderLines::const_iterator start) const;

  HeaderLines::iterator GetHeaderLinesIteratorNoSkip(
      const base::StringPiece& key,
      HeaderLines::iterator start);

  HeaderLines::iterator GetHeaderLinesIterator(
      const base::StringPiece& key,
      HeaderLines::iterator start);

  template <typename IteratorType>
  const IteratorType HeaderLinesBeginHelper() const {
    if (header_lines_.empty()) {
      return IteratorType(this, 0);
    }
    const HeaderLines::size_type header_lines_size = header_lines_.size();
    for (HeaderLines::size_type i = 0; i < header_lines_size; ++i) {
      if (header_lines_[i].skip == false) {
        return IteratorType(this, i);
      }
    }
    return IteratorType(this, 0);
  }

  template <typename IteratorType>
  const IteratorType HeaderLinesEndHelper() const {
    if (header_lines_.empty()) {
      return IteratorType(this, 0);
    }
    const HeaderLines::size_type header_lines_size = header_lines_.size();
    HeaderLines::size_type i = header_lines_size;
    do {
      --i;
      if (header_lines_[i].skip == false) {
        return IteratorType(this, i + 1);
      }
    } while (i != 0);
    return IteratorType(this, 0);
  }

  // At the moment, this function will always return the original headers.
  // In the future, it may not do so after erasing header lines, modifying
  // header lines, or modifying the first line.
  // For this reason, it is strongly suggested that use of this function is
  // only acceptable for the purpose of debugging parse errors seen by the
  // BalsaFrame class.
  base::StringPiece OriginalHeadersForDebugging() const {
    return base::StringPiece(OriginalHeaderStreamBegin(),
                       OriginalHeaderStreamEnd() - OriginalHeaderStreamBegin());
  }

  BalsaBuffer balsa_buffer_;

  size_t content_length_;
  BalsaHeadersEnums::ContentLengthStatus content_length_status_;
  size_t parsed_response_code_;
  // HTTP firstlines all have the following structure:
  //  LWS         NONWS  LWS    NONWS   LWS    NONWS   NOTCRLF  CRLF
  //  [\t \r\n]+ [^\t ]+ [\t ]+ [^\t ]+ [\t ]+ [^\t ]+ [^\r\n]+ "\r\n"
  //  ws1        nws1    ws2    nws2    ws3    nws3             ws4
  //  |          [-------)      [-------)      [----------------)
  //    REQ:     method         request_uri    version
  //   RESP:     version        statuscode     reason
  //
  //   The first NONWS->LWS component we'll call firstline_a.
  //   The second firstline_b, and the third firstline_c.
  //
  //   firstline_a goes from nws1 to (but not including) ws2
  //   firstline_b goes from nws2 to (but not including) ws3
  //   firstline_c goes from nws3 to (but not including) ws4
  //
  // In the code:
  //    ws1 == whitespace_1_idx_
  //   nws1 == non_whitespace_1_idx_
  //    ws2 == whitespace_2_idx_
  //   nws2 == non_whitespace_2_idx_
  //    ws3 == whitespace_3_idx_
  //   nws3 == non_whitespace_3_idx_
  //    ws4 == whitespace_4_idx_
  BalsaBuffer::Blocks::size_type firstline_buffer_base_idx_;
  size_t whitespace_1_idx_;
  size_t non_whitespace_1_idx_;
  size_t whitespace_2_idx_;
  size_t non_whitespace_2_idx_;
  size_t whitespace_3_idx_;
  size_t non_whitespace_3_idx_;
  size_t whitespace_4_idx_;
  size_t end_of_firstline_idx_;

  bool transfer_encoding_is_chunked_;

  HeaderLines header_lines_;
};

}  // namespace net

#endif  // NET_TOOLS_BALSA_BALSA_HEADERS_H_
