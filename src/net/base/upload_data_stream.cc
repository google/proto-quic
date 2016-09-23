// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/upload_data_stream.h"

#include "base/callback_helpers.h"
#include "base/logging.h"
#include "base/values.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/log/net_log_event_type.h"

namespace net {

namespace {

std::unique_ptr<base::Value> NetLogInitEndInfoCallback(
    int result,
    int total_size,
    bool is_chunked,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

  dict->SetInteger("net_error", result);
  dict->SetInteger("total_size", total_size);
  dict->SetBoolean("is_chunked", is_chunked);
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogReadInfoCallback(
    int current_position,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

  dict->SetInteger("current_position", current_position);
  return std::move(dict);
}

}  // namespace

UploadDataStream::UploadDataStream(bool is_chunked, int64_t identifier)
    : total_size_(0),
      current_position_(0),
      identifier_(identifier),
      is_chunked_(is_chunked),
      initialized_successfully_(false),
      is_eof_(false) {
}

UploadDataStream::~UploadDataStream() {
}

int UploadDataStream::Init(const CompletionCallback& callback,
                           const NetLogWithSource& net_log) {
  Reset();
  DCHECK(!initialized_successfully_);
  DCHECK(callback_.is_null());
  DCHECK(!callback.is_null() || IsInMemory());
  net_log_ = net_log;
  net_log_.BeginEvent(NetLogEventType::UPLOAD_DATA_STREAM_INIT);

  int result = InitInternal(net_log_);
  if (result == ERR_IO_PENDING) {
    DCHECK(!IsInMemory());
    callback_ = callback;
  } else {
    OnInitCompleted(result);
  }

  return result;
}

int UploadDataStream::Read(IOBuffer* buf,
                           int buf_len,
                           const CompletionCallback& callback) {
  DCHECK(!callback.is_null() || IsInMemory());
  DCHECK(initialized_successfully_);
  DCHECK_GT(buf_len, 0);

  net_log_.BeginEvent(NetLogEventType::UPLOAD_DATA_STREAM_READ,
                      base::Bind(&NetLogReadInfoCallback, current_position_));

  int result = 0;
  if (!is_eof_)
    result = ReadInternal(buf, buf_len);

  if (result == ERR_IO_PENDING) {
    DCHECK(!IsInMemory());
    callback_ = callback;
  } else {
    OnReadCompleted(result);
  }

  return result;
}

bool UploadDataStream::IsEOF() const {
  DCHECK(initialized_successfully_);
  DCHECK(is_chunked_ || is_eof_ == (current_position_ == total_size_));
  return is_eof_;
}

void UploadDataStream::Reset() {
  // If there's a pending callback, there's a pending init or read call that is
  // being canceled.
  if (!callback_.is_null()) {
    if (!initialized_successfully_) {
      // If initialization has not yet succeeded, this call is aborting
      // initialization.
      net_log_.EndEventWithNetErrorCode(
          NetLogEventType::UPLOAD_DATA_STREAM_INIT, ERR_ABORTED);
    } else {
      // Otherwise, a read is being aborted.
      net_log_.EndEventWithNetErrorCode(
          NetLogEventType::UPLOAD_DATA_STREAM_READ, ERR_ABORTED);
    }
  }

  current_position_ = 0;
  initialized_successfully_ = false;
  is_eof_ = false;
  total_size_ = 0;
  callback_.Reset();
  ResetInternal();
}

void UploadDataStream::SetSize(uint64_t size) {
  DCHECK(!initialized_successfully_);
  DCHECK(!is_chunked_);
  total_size_ = size;
}

void UploadDataStream::SetIsFinalChunk() {
  DCHECK(initialized_successfully_);
  DCHECK(is_chunked_);
  DCHECK(!is_eof_);
  is_eof_ = true;
}

bool UploadDataStream::IsInMemory() const {
  return false;
}

const std::vector<std::unique_ptr<UploadElementReader>>*
UploadDataStream::GetElementReaders() const {
  return NULL;
}

void UploadDataStream::OnInitCompleted(int result) {
  DCHECK_NE(ERR_IO_PENDING, result);
  DCHECK(!initialized_successfully_);
  DCHECK_EQ(0u, current_position_);
  DCHECK(!is_eof_);

  if (result == OK) {
    initialized_successfully_ = true;
    if (!is_chunked_ && total_size_ == 0)
      is_eof_ = true;
  }

  net_log_.EndEvent(
      NetLogEventType::UPLOAD_DATA_STREAM_INIT,
      base::Bind(&NetLogInitEndInfoCallback, result, total_size_, is_chunked_));

  if (!callback_.is_null())
    base::ResetAndReturn(&callback_).Run(result);
}

void UploadDataStream::OnReadCompleted(int result) {
  DCHECK(initialized_successfully_);
  DCHECK(result != 0 || is_eof_);
  DCHECK_NE(ERR_IO_PENDING, result);

  if (result > 0) {
    current_position_ += result;
    if (!is_chunked_) {
      DCHECK_LE(current_position_, total_size_);
      if (current_position_ == total_size_)
        is_eof_ = true;
    }
  }

  net_log_.EndEventWithNetErrorCode(NetLogEventType::UPLOAD_DATA_STREAM_READ,
                                    result);

  if (!callback_.is_null())
    base::ResetAndReturn(&callback_).Run(result);
}

UploadProgress UploadDataStream::GetUploadProgress() const {
  // While initialization / rewinding is in progress, return nothing.
  if (!initialized_successfully_)
    return UploadProgress();

  return UploadProgress(current_position_, total_size_);
}

}  // namespace net
