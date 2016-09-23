// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_UPLOAD_DATA_STREAM_H_
#define NET_BASE_UPLOAD_DATA_STREAM_H_

#include <stdint.h>

#include <memory>
#include <vector>

#include "base/macros.h"
#include "net/base/completion_callback.h"
#include "net/base/net_export.h"
#include "net/base/upload_progress.h"
#include "net/log/net_log.h"

namespace net {

class DrainableIOBuffer;
class IOBuffer;
class UploadElementReader;

// A class for retrieving all data to be sent as a request body. Supports both
// chunked and non-chunked uploads.
class NET_EXPORT UploadDataStream {
 public:
  // |identifier| identifies a particular upload instance, which is used by the
  // cache to formulate a cache key. This value should be unique across browser
  // sessions. A value of 0 is used to indicate an unspecified identifier.
  UploadDataStream(bool is_chunked, int64_t identifier);

  virtual ~UploadDataStream();

  // Initializes the stream. This function must be called before calling any
  // other method. It is not valid to call any method (other than the
  // destructor) if Init() fails. This method can be called multiple times.
  // Calling this method after an Init() success results in resetting the
  // state (i.e. the stream is rewound).
  //
  // Does the initialization synchronously and returns the result if possible,
  // otherwise returns ERR_IO_PENDING and runs the callback with the result.
  //
  // Returns OK on success. Returns ERR_UPLOAD_FILE_CHANGED if the expected
  // file modification time is set (usually not set, but set for sliced
  // files) and the target file is changed.
  int Init(const CompletionCallback& callback, const NetLogWithSource& net_log);

  // When possible, reads up to |buf_len| bytes synchronously from the upload
  // data stream to |buf| and returns the number of bytes read; otherwise,
  // returns ERR_IO_PENDING and calls |callback| with the number of bytes read.
  // Partial reads are allowed. Zero is returned on a call to Read when there
  // are no remaining bytes in the stream, and IsEof() will return true
  // hereafter.
  //
  // If there's less data to read than we initially observed (i.e. the actual
  // upload data is smaller than size()), zeros are padded to ensure that
  // size() bytes can be read, which can happen for TYPE_FILE payloads.
  //
  // TODO(mmenke):  Investigate letting reads fail.
  int Read(IOBuffer* buf, int buf_len, const CompletionCallback& callback);

  // Returns the total size of the data stream and the current position.
  // When the data is chunked, always returns zero. Must always return the same
  // value after each call to Initialize().
  uint64_t size() const { return total_size_; }
  uint64_t position() const { return current_position_; }

  // See constructor for description.
  int64_t identifier() const { return identifier_; }

  bool is_chunked() const { return is_chunked_; }

  // Returns true if all data has been consumed from this upload data
  // stream. For chunked uploads, returns false until the first read attempt.
  // This makes some state machines a little simpler.
  bool IsEOF() const;

  // Cancels all pending callbacks, and resets state. Any IOBuffer currently
  // being read to is not safe for future use, as it may be in use on another
  // thread.
  void Reset();

  // Returns true if the upload data in the stream is entirely in memory, and
  // all read requests will succeed synchronously. Expected to return false for
  // chunked requests.
  virtual bool IsInMemory() const;

  // Returns a list of element readers owned by |this|, if it has any.
  virtual const std::vector<std::unique_ptr<UploadElementReader>>*
  GetElementReaders() const;

  // Returns the upload progress. If the stream was not initialized
  // successfully, or has been reset and not yet re-initialized, returns an
  // empty UploadProgress.
  virtual UploadProgress GetUploadProgress() const;

 protected:
  // Must be called by subclasses when InitInternal and ReadInternal complete
  // asynchronously.
  void OnInitCompleted(int result);
  void OnReadCompleted(int result);

  // Must be called before InitInternal completes, for non-chunked uploads.
  // Must not be called for chunked uploads.
  void SetSize(uint64_t size);

  // Must be called for chunked uploads before the final ReadInternal call
  // completes. Must not be called for non-chunked uploads.
  void SetIsFinalChunk();

 private:
  // See Init(). If it returns ERR_IO_PENDING, OnInitCompleted must be called
  // once it completes. If the upload is not chunked, SetSize must be called
  // before it completes.
  virtual int InitInternal(const NetLogWithSource& net_log) = 0;

  // See Read(). For chunked uploads, must call SetIsFinalChunk if this is the
  // final chunk. For non-chunked uploads, the UploadDataStream determins which
  // read is the last based on size. Must read 1 or more bytes on every call,
  // though the final chunk may be 0 bytes, for chunked requests. If it returns
  // ERR_IO_PENDING, OnInitCompleted must be called once it completes. Must not
  // return any error, other than ERR_IO_PENDING.
  virtual int ReadInternal(IOBuffer* buf, int buf_len) = 0;

  // Resets state and cancels any pending callbacks. Guaranteed to be called
  // before all but the first call to InitInternal.
  virtual void ResetInternal() = 0;

  uint64_t total_size_;
  uint64_t current_position_;

  const int64_t identifier_;

  const bool is_chunked_;

  // True if the initialization was successful.
  bool initialized_successfully_;

  bool is_eof_;

  CompletionCallback callback_;

  NetLogWithSource net_log_;

  DISALLOW_COPY_AND_ASSIGN(UploadDataStream);
};

}  // namespace net

#endif  // NET_BASE_UPLOAD_DATA_STREAM_H_
