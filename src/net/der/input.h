// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DER_INPUT_H_
#define NET_DER_INPUT_H_

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "base/compiler_specific.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"

namespace net {

namespace der {

class Mark;

// An opaque class that represents a fixed buffer of data of a fixed length,
// to be used as an input to other operations. An Input object does not own
// the data it references, so callers are responsible for making sure that
// the data outlives the Input object and any other associated objects.
//
// All data access for an Input should be done through the ByteReader and Mark
// classes. This class and associated classes are designed with safety in mind
// to make it difficult to read memory outside of an Input. ByteReader provides
// a simple API for reading through the Input sequentially. For more
// complicated uses, multiple instances of a ByteReader for a particular Input
// can be created, and instances of Mark can be used to coordinate between the
// ByteReaders.
//
// One such use case of multiple ByteReaders would be looking ahead in an
// input: A ByteReader is copied and then is used to read some number of
// bytes into the input, based on the content it is reading. A Mark can then be
// set using the temporary ByteReader to indicate how far it read into the
// Input. The original ByteReader can then be synchronized with how far the
// temporary ByteReader read, by using either AdvanceToMark() or ReadToMark().
class NET_EXPORT_PRIVATE Input {
 public:
  // Creates an empty Input, one from which no data can be read.
  Input();

  // Creates an Input from a constant array |data|.
  template <size_t N>
  explicit Input(const uint8_t(&data)[N])
      : data_(data), len_(N) {}

  // Creates an Input from the given |data| and |len|.
  explicit Input(const uint8_t* data, size_t len);

  // Creates an Input from a base::StringPiece.
  explicit Input(const base::StringPiece& sp);

  // Creates an Input from a std::string. The lifetimes are a bit subtle when
  // using this function: The constructed Input is only valid so long as |s| is
  // still alive and not mutated.
  Input(const std::string* s);

  // Returns the length in bytes of an Input's data.
  size_t Length() const { return len_; }

  // Returns a pointer to the Input's data. This method is marked as "unsafe"
  // because access to the Input's data should be done through ByteReader
  // instead. This method should only be used where using a ByteReader truly
  // is not an option.
  const uint8_t* UnsafeData() const { return data_; }

  // Returns a copy of the data represented by this object as a std::string.
  std::string AsString() const;

  // Returns a StringPiece pointing to the same data as the Input. The resulting
  // StringPiece must not outlive the data that was used to construct this
  // Input.
  base::StringPiece AsStringPiece() const;

 private:
  // This constructor is deleted to prevent constructing an Input from a
  // std::string r-value. Since the Input points to memory owned by another
  // object, such an Input would point to invalid memory. Without this deleted
  // constructor, a std::string could be passed in to the base::StringPiece
  // constructor because of StringPiece's implicit constructor.
  Input(std::string) = delete;
  const uint8_t* data_;
  size_t len_;
};

// Return true if |lhs|'s data and |rhs|'s data are byte-wise equal.
NET_EXPORT_PRIVATE bool operator==(const Input& lhs, const Input& rhs);

// Return true if |lhs|'s data and |rhs|'s data are not byte-wise equal.
NET_EXPORT_PRIVATE bool operator!=(const Input& lhs, const Input& rhs);

// Returns true if |lhs|'s data is lexicographically less than |rhs|'s data.
NET_EXPORT_PRIVATE bool operator<(const Input& lhs, const Input& rhs);

// This class provides ways to read data from an Input in a bounds-checked way.
// The ByteReader is designed to read through the input sequentially. Once a
// byte has been read with a ByteReader, the caller can't go back and re-read
// that byte with the same reader. Of course, the caller can create multiple
// ByteReaders for the same input (or copy an existing ByteReader).
//
// For something simple like a single byte lookahead, the easiest way to do
// that is to copy the ByteReader and call ReadByte() on the copy - the original
// ByteReader will be unaffected and the peeked byte will be read through
// ReadByte(). For other read patterns, it can be useful to mark where one is
// in a ByteReader to be able to return to that spot.
//
// Some operations using Mark can also be done by creating a copy of the
// ByteReader. By using a Mark instead, you use less memory, but more
// importantly, you end up with an immutable object that matches the semantics
// of what is intended.
class NET_EXPORT_PRIVATE ByteReader {
 public:
  // Creates a ByteReader to read the data represented by an Input.
  explicit ByteReader(const Input& in);

  // Reads a single byte from the input source, putting the byte read in
  // |*byte_p|. If a byte cannot be read from the input (because there is
  // no input left), then this method returns false.
  bool ReadByte(uint8_t* out) WARN_UNUSED_RESULT;

  // Reads |len| bytes from the input source, and initializes an Input to
  // point to that data. If there aren't enough bytes left in the input source,
  // then this method returns false.
  bool ReadBytes(size_t len, Input* out) WARN_UNUSED_RESULT;

  // Returns how many bytes are left to read.
  size_t BytesLeft() const { return len_; }

  // Returns whether there is any more data to be read.
  bool HasMore();

  // Creates a new Mark at the current position of this ByteReader. If another
  // ByteReader is advanced to this mark, the next byte read by the other
  // ByteReader will be the same as the next byte read by this ByteReader.
  Mark NewMark();

  // Advances this ByteReader to the position marked by |mark|. Note that
  // a ByteReader can only advance forward - it is not possible to "rewind"
  // to a previous mark. To do this, one would need to create a new ByteReader
  // (from the same input) and AdvanceToMark() on the new ByteReader.
  //
  // If it is not possible to advance this ByteReader to the mark, this method
  // returns false and does nothing.
  bool AdvanceToMark(Mark mark) WARN_UNUSED_RESULT;

  // Reads all data from the cursor of this ByteReader up to the mark, and
  // initializes an Input to point to that data. If the Mark is not valid for
  // this ByteReader, then this method returns false and does not modify |*out|.
  bool ReadToMark(Mark mark, Input* out) WARN_UNUSED_RESULT;

 private:
  void Advance(size_t len);

  const uint8_t* data_;
  size_t len_;
};

// An immutable opaque pointer into the data represented by an Input. A Mark
// object is used to save and restore the state (position) of a ByteReader to
// allow for lookahead or backtracking. All interaction with a Mark object is
// done through the ByteReader class.
class NET_EXPORT_PRIVATE Mark {
 public:
  // Creates a null Mark. This Mark will not be usable with any ByteReader.
  // This only exists so that a class can have a Mark member which may or may
  // not be a valid Mark at any given time.
  static Mark NullMark();

  // Checks whether a given Mark is an empty Mark.
  bool IsEmpty();
  friend class ByteReader;

 private:
  explicit Mark(const uint8_t* ptr);
  Mark();
  const uint8_t* ptr_;
};

}  // namespace der

}  // namespace net

#endif  // NET_DER_INPUT_H_
