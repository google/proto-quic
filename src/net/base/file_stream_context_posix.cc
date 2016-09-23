// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/file_stream_context.h"

#include <errno.h>
#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback.h"
#include "base/files/file_path.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/posix/eintr_wrapper.h"
#include "base/profiler/scoped_tracker.h"
#include "base/task_runner.h"
#include "base/task_runner_util.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"

namespace net {

FileStream::Context::Context(const scoped_refptr<base::TaskRunner>& task_runner)
    : async_in_progress_(false),
      orphaned_(false),
      task_runner_(task_runner) {
}

FileStream::Context::Context(base::File file,
                             const scoped_refptr<base::TaskRunner>& task_runner)
    : file_(std::move(file)),
      async_in_progress_(false),
      orphaned_(false),
      task_runner_(task_runner) {}

FileStream::Context::~Context() {
}

int FileStream::Context::Read(IOBuffer* in_buf,
                              int buf_len,
                              const CompletionCallback& callback) {
  DCHECK(!async_in_progress_);

  scoped_refptr<IOBuffer> buf = in_buf;
  const bool posted = base::PostTaskAndReplyWithResult(
      task_runner_.get(),
      FROM_HERE,
      base::Bind(&Context::ReadFileImpl, base::Unretained(this), buf, buf_len),
      base::Bind(&Context::OnAsyncCompleted,
                 base::Unretained(this),
                 IntToInt64(callback)));
  DCHECK(posted);

  async_in_progress_ = true;
  return ERR_IO_PENDING;
}

int FileStream::Context::Write(IOBuffer* in_buf,
                               int buf_len,
                               const CompletionCallback& callback) {
  DCHECK(!async_in_progress_);

  scoped_refptr<IOBuffer> buf = in_buf;
  const bool posted = base::PostTaskAndReplyWithResult(
      task_runner_.get(),
      FROM_HERE,
      base::Bind(&Context::WriteFileImpl, base::Unretained(this), buf, buf_len),
      base::Bind(&Context::OnAsyncCompleted,
                 base::Unretained(this),
                 IntToInt64(callback)));
  DCHECK(posted);

  async_in_progress_ = true;
  return ERR_IO_PENDING;
}

FileStream::Context::IOResult FileStream::Context::SeekFileImpl(
    int64_t offset) {
  int64_t res = file_.Seek(base::File::FROM_BEGIN, offset);
  if (res == -1)
    return IOResult::FromOSError(errno);

  return IOResult(res, 0);
}

void FileStream::Context::OnFileOpened() {
}

FileStream::Context::IOResult FileStream::Context::ReadFileImpl(
    scoped_refptr<IOBuffer> buf,
    int buf_len) {
  // TODO(pkasting): Remove ScopedTracker below once crbug.com/477117 is fixed.
  tracked_objects::ScopedTracker tracking_profile(
      FROM_HERE_WITH_EXPLICIT_FUNCTION(
          "477117 FileStream::Context::ReadFileImpl"));
  int res = file_.ReadAtCurrentPosNoBestEffort(buf->data(), buf_len);
  if (res == -1)
    return IOResult::FromOSError(errno);

  return IOResult(res, 0);
}

FileStream::Context::IOResult FileStream::Context::WriteFileImpl(
    scoped_refptr<IOBuffer> buf,
    int buf_len) {
  int res = file_.WriteAtCurrentPosNoBestEffort(buf->data(), buf_len);
  if (res == -1)
    return IOResult::FromOSError(errno);

  return IOResult(res, 0);
}

}  // namespace net
