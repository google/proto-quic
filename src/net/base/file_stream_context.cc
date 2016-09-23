// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/file_stream_context.h"

#include <utility>

#include "base/files/file_path.h"
#include "base/location.h"
#include "base/profiler/scoped_tracker.h"
#include "base/task_runner.h"
#include "base/task_runner_util.h"
#include "base/threading/thread_restrictions.h"
#include "base/values.h"
#include "net/base/net_errors.h"

#if defined(OS_ANDROID)
#include "base/android/content_uri_utils.h"
#endif

namespace net {

namespace {

void CallInt64ToInt(const CompletionCallback& callback, int64_t result) {
  callback.Run(static_cast<int>(result));
}

}  // namespace

FileStream::Context::IOResult::IOResult()
    : result(OK),
      os_error(0) {
}

FileStream::Context::IOResult::IOResult(int64_t result,
                                        logging::SystemErrorCode os_error)
    : result(result), os_error(os_error) {
}

// static
FileStream::Context::IOResult FileStream::Context::IOResult::FromOSError(
    logging::SystemErrorCode os_error) {
  return IOResult(MapSystemError(os_error), os_error);
}

// ---------------------------------------------------------------------

FileStream::Context::OpenResult::OpenResult() {
}

FileStream::Context::OpenResult::OpenResult(base::File file,
                                            IOResult error_code)
    : file(std::move(file)), error_code(error_code) {}

FileStream::Context::OpenResult::OpenResult(OpenResult&& other)
    : file(std::move(other.file)), error_code(other.error_code) {}

FileStream::Context::OpenResult& FileStream::Context::OpenResult::operator=(
    OpenResult&& other) {
  file = std::move(other.file);
  error_code = other.error_code;
  return *this;
}

// ---------------------------------------------------------------------

void FileStream::Context::Orphan() {
  DCHECK(!orphaned_);

  orphaned_ = true;

  if (!async_in_progress_) {
    CloseAndDelete();
  } else if (file_.IsValid()) {
#if defined(OS_WIN)
    CancelIo(file_.GetPlatformFile());
#endif
  }
}

void FileStream::Context::Open(const base::FilePath& path,
                               int open_flags,
                               const CompletionCallback& callback) {
  // TODO(jkarlin): Change back to a DCHECK once https://crbug.com/487732 is
  // fixed.
  CHECK(!async_in_progress_);

  bool posted = base::PostTaskAndReplyWithResult(
      task_runner_.get(),
      FROM_HERE,
      base::Bind(
          &Context::OpenFileImpl, base::Unretained(this), path, open_flags),
      base::Bind(&Context::OnOpenCompleted, base::Unretained(this), callback));
  DCHECK(posted);

  async_in_progress_ = true;
}

void FileStream::Context::Close(const CompletionCallback& callback) {
  // TODO(jkarlin): Change back to a DCHECK once https://crbug.com/487732 is
  // fixed.
  CHECK(!async_in_progress_);
  bool posted = base::PostTaskAndReplyWithResult(
      task_runner_.get(),
      FROM_HERE,
      base::Bind(&Context::CloseFileImpl, base::Unretained(this)),
      base::Bind(&Context::OnAsyncCompleted,
                 base::Unretained(this),
                 IntToInt64(callback)));
  DCHECK(posted);

  async_in_progress_ = true;
}

void FileStream::Context::Seek(int64_t offset,
                               const Int64CompletionCallback& callback) {
  // TODO(jkarlin): Change back to a DCHECK once https://crbug.com/487732 is
  // fixed.
  CHECK(!async_in_progress_);

  bool posted = base::PostTaskAndReplyWithResult(
      task_runner_.get(), FROM_HERE,
      base::Bind(&Context::SeekFileImpl, base::Unretained(this), offset),
      base::Bind(&Context::OnAsyncCompleted, base::Unretained(this), callback));
  DCHECK(posted);

  async_in_progress_ = true;
}

void FileStream::Context::Flush(const CompletionCallback& callback) {
  // TODO(jkarlin): Change back to a DCHECK once https://crbug.com/487732 is
  // fixed.
  CHECK(!async_in_progress_);

  bool posted = base::PostTaskAndReplyWithResult(
      task_runner_.get(),
      FROM_HERE,
      base::Bind(&Context::FlushFileImpl, base::Unretained(this)),
      base::Bind(&Context::OnAsyncCompleted,
                 base::Unretained(this),
                 IntToInt64(callback)));
  DCHECK(posted);

  async_in_progress_ = true;
}

bool FileStream::Context::IsOpen() const {
  return file_.IsValid();
}

FileStream::Context::OpenResult FileStream::Context::OpenFileImpl(
    const base::FilePath& path, int open_flags) {
#if defined(OS_POSIX)
  // Always use blocking IO.
  open_flags &= ~base::File::FLAG_ASYNC;
#endif
  base::File file;
#if defined(OS_ANDROID)
  if (path.IsContentUri()) {
    // Check that only Read flags are set.
    DCHECK_EQ(open_flags & ~base::File::FLAG_ASYNC,
              base::File::FLAG_OPEN | base::File::FLAG_READ);
    file = base::OpenContentUriForRead(path);
  } else {
#endif  // defined(OS_ANDROID)
    // FileStream::Context actually closes the file asynchronously,
    // independently from FileStream's destructor. It can cause problems for
    // users wanting to delete the file right after FileStream deletion. Thus
    // we are always adding SHARE_DELETE flag to accommodate such use case.
    // TODO(rvargas): This sounds like a bug, as deleting the file would
    // presumably happen on the wrong thread. There should be an async delete.
    open_flags |= base::File::FLAG_SHARE_DELETE;
    file.Initialize(path, open_flags);
#if defined(OS_ANDROID)
  }
#endif  // defined(OS_ANDROID)
  if (!file.IsValid())
    return OpenResult(base::File(),
                      IOResult::FromOSError(logging::GetLastSystemErrorCode()));

  return OpenResult(std::move(file), IOResult(OK, 0));
}

FileStream::Context::IOResult FileStream::Context::CloseFileImpl() {
  file_.Close();
  return IOResult(OK, 0);
}

FileStream::Context::IOResult FileStream::Context::FlushFileImpl() {
  if (file_.Flush())
    return IOResult(OK, 0);

  return IOResult::FromOSError(logging::GetLastSystemErrorCode());
}

void FileStream::Context::OnOpenCompleted(const CompletionCallback& callback,
                                          OpenResult open_result) {
  file_ = std::move(open_result.file);
  if (file_.IsValid() && !orphaned_)
    OnFileOpened();

  OnAsyncCompleted(IntToInt64(callback), open_result.error_code);
}

void FileStream::Context::CloseAndDelete() {
  // TODO(ananta)
  // Replace this CHECK with a DCHECK once we figure out the root cause of
  // http://crbug.com/455066
  CHECK(!async_in_progress_);

  if (file_.IsValid()) {
    bool posted = task_runner_.get()->PostTask(
        FROM_HERE,
        base::Bind(base::IgnoreResult(&Context::CloseFileImpl),
                   base::Owned(this)));
    DCHECK(posted);
  } else {
    delete this;
  }
}

Int64CompletionCallback FileStream::Context::IntToInt64(
    const CompletionCallback& callback) {
  return base::Bind(&CallInt64ToInt, callback);
}

void FileStream::Context::OnAsyncCompleted(
    const Int64CompletionCallback& callback,
    const IOResult& result) {
  // TODO(pkasting): Remove ScopedTracker below once crbug.com/477117 is fixed.
  tracked_objects::ScopedTracker tracking_profile(
      FROM_HERE_WITH_EXPLICIT_FUNCTION(
          "477117 FileStream::Context::OnAsyncCompleted"));
  // Reset this before Run() as Run() may issue a new async operation. Also it
  // should be reset before Close() because it shouldn't run if any async
  // operation is in progress.
  async_in_progress_ = false;
  if (orphaned_)
    CloseAndDelete();
  else
    callback.Run(result.result);
}

}  // namespace net
