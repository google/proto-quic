// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_BALSA_BUFFER_INTERFACE_H__
#define NET_TOOLS_BALSA_BUFFER_INTERFACE_H__

namespace net {

class BufferInterface {
 public:

  //   Returns the bytes which can be read from the buffer.  There is no
  //   guarantee that the bytes are contiguous.
  virtual int ReadableBytes() const = 0;

  // Summary:
  //   returns the size of this buffer
  // Returns:
  //   size of this buffer.
  virtual int BufferSize() const = 0;

  // Summary:
  //   returns the number of bytes free in this buffer.
  // Returns:
  //   number of bytes free.
  virtual int BytesFree() const = 0;

  // Summary:
  //   Returns true if empty.
  // Returns:
  //   true - if empty
  //   false - otherwise
  virtual bool Empty() const = 0;

  // Summary:
  //   Returns true if the buffer is full.
  virtual bool Full() const = 0;

  // Summary:
  //   returns the number of characters written.
  //   appends up-to-'size' bytes to the buffer.
  // Args:
  //   bytes - bytes which are read, and copied into the buffer.
  //   size  - number of bytes which are read and copied.
  //           this number shall be >= 0.
  virtual int Write(const char* bytes, int size) = 0;

  // Summary:
  //   Gets a pointer which can be written to (assigned to).
  //   this pointer (and size) can be used in functions like
  //   recv() or read(), etc.
  //   If *size is zero upon returning from this function, that it
  //   is unsafe to dereference *ptr.
  // Args:
  //   ptr - assigned a pointer to which we can write
  //   size - the amount of data (in bytes) that it is safe to write to ptr.
  virtual void GetWritablePtr(char **ptr, int* size) const = 0;

  // Summary:
  //   Gets a pointer which can be read from
  //   this pointer (and size) can be used in functions like
  //   send() or write(), etc.
  //   If *size is zero upon returning from this function, that it
  //   is unsafe to dereference *ptr.
  // Args:
  //   ptr - assigned a pointer from which we may read
  //   size - the amount of data (in bytes) that it is safe to read
  virtual void GetReadablePtr(char **ptr, int* size) const = 0;

  // Summary:
  //   Reads bytes out of the buffer, and writes them into 'bytes'.
  //   Returns the number of bytes read.
  //   Consumes bytes from the buffer (possibly, but not necessarily
  //   rendering them free)
  // Args:
  //   bytes - the pointer into which bytes are read from this buffer
  //           and written into
  //   size  - number of bytes which are read and copied.
  //           this number shall be >= 0.
  // Returns:
  //   the number of bytes read from 'bytes'
  virtual int Read(char* bytes, int size) = 0;

  // Summary:
  //   removes all data from the buffer
  virtual void Clear() = 0;

  // Summary:
  //   reserves contiguous writable empty space in the buffer of size bytes.
  //   Returns true if the reservation is successful.
  //   If a derive class chooses not to implement reservation, its
  //   implementation should return false.
  virtual bool Reserve(int size) = 0;

  // Summary:
  //   removes the oldest 'amount_to_consume' characters from this buffer,
  // Args:
  //   amount_to_advance - .. this should be self-explanatory =)
  //                       this number shall be >= 0.
  virtual void AdvanceReadablePtr(int amount_to_advance) = 0;

  // Summary:
  //   Moves the internal pointers around such that the
  //   amount of data specified here is expected to
  //   already be resident (as if it was Written)
  // Args:
  //   amount_to_advance - self explanatory.
  //                       this number shall be >= 0.
  virtual void AdvanceWritablePtr(int amount_to_advance) = 0;

  virtual ~BufferInterface() {}

 protected:
  BufferInterface() {}
};

}  // namespace net

#endif  // NET_TOOLS_BALSA_BUFFER_INTERFACE__H__

