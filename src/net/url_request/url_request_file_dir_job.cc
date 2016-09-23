// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_file_dir_job.h"

#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/location.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/sys_string_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "net/base/directory_listing.h"
#include "net/base/io_buffer.h"
#include "net/url_request/url_request_status.h"
#include "url/gurl.h"

#if defined(OS_POSIX)
#include <sys/stat.h>
#endif

namespace net {

URLRequestFileDirJob::URLRequestFileDirJob(URLRequest* request,
                                           NetworkDelegate* network_delegate,
                                           const base::FilePath& dir_path)
    : URLRequestFileDirJob(request,
                           network_delegate,
                           dir_path,
                           base::WorkerPool::GetTaskRunner(true)) {}

URLRequestFileDirJob::URLRequestFileDirJob(
    URLRequest* request,
    NetworkDelegate* network_delegate,
    const base::FilePath& dir_path,
    const scoped_refptr<base::TaskRunner>& dir_task_runner)
    : URLRequestJob(request, network_delegate),
      lister_(dir_path, this),
      dir_path_(dir_path),
      dir_task_runner_(dir_task_runner),
      canceled_(false),
      list_complete_(false),
      wrote_header_(false),
      read_pending_(false),
      read_buffer_length_(0),
      weak_factory_(this) {}

void URLRequestFileDirJob::StartAsync() {
  lister_.Start(dir_task_runner_.get());

  NotifyHeadersComplete();
}

void URLRequestFileDirJob::Start() {
  // Start reading asynchronously so that all error reporting and data
  // callbacks happen as they would for network requests.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&URLRequestFileDirJob::StartAsync,
                            weak_factory_.GetWeakPtr()));
}

void URLRequestFileDirJob::Kill() {
  if (canceled_)
    return;

  canceled_ = true;

  if (!list_complete_)
    lister_.Cancel();

  URLRequestJob::Kill();

  weak_factory_.InvalidateWeakPtrs();
}

int URLRequestFileDirJob::ReadRawData(IOBuffer* buf, int buf_size) {
  int result = ReadBuffer(buf->data(), buf_size);
  if (result == ERR_IO_PENDING) {
    // We are waiting for more data
    read_pending_ = true;
    read_buffer_ = buf;
    read_buffer_length_ = buf_size;
    return ERR_IO_PENDING;
  }

  return result;
}

bool URLRequestFileDirJob::GetMimeType(std::string* mime_type) const {
  *mime_type = "text/html";
  return true;
}

bool URLRequestFileDirJob::GetCharset(std::string* charset) {
  // All the filenames are converted to UTF-8 before being added.
  *charset = "utf-8";
  return true;
}

void URLRequestFileDirJob::OnListFile(
    const DirectoryLister::DirectoryListerData& data) {
  // We wait to write out the header until we get the first file, so that we
  // can catch errors from DirectoryLister and show an error page.
  if (!wrote_header_) {
#if defined(OS_WIN)
    const base::string16& title = dir_path_.value();
#elif defined(OS_POSIX)
    // TODO(jungshik): Add SysNativeMBToUTF16 to sys_string_conversions.
    // On Mac, need to add NFKC->NFC conversion either here or in file_path.
    // On Linux, the file system encoding is not defined, but we assume that
    // SysNativeMBToWide takes care of it at least for now. We can try something
    // more sophisticated if necessary later.
    const base::string16& title = base::WideToUTF16(
        base::SysNativeMBToWide(dir_path_.value()));
#endif
    data_.append(GetDirectoryListingHeader(title));
    wrote_header_ = true;
  }

#if defined(OS_WIN)
  std::string raw_bytes;  // Empty on Windows means UTF-8 encoded name.
#elif defined(OS_POSIX)
  // TOOD(jungshik): The same issue as for the directory name.
  base::FilePath filename = data.info.GetName();
  const std::string& raw_bytes = filename.value();
#endif
  data_.append(GetDirectoryListingEntry(
      data.info.GetName().LossyDisplayName(),
      raw_bytes,
      data.info.IsDirectory(),
      data.info.GetSize(),
      data.info.GetLastModifiedTime()));

  // TODO(darin): coalesce more?
  CompleteRead(OK);
}

void URLRequestFileDirJob::OnListDone(int error) {
  DCHECK(!canceled_);
  DCHECK_LE(error, OK);

  list_complete_ = true;
  list_complete_result_ = static_cast<Error>(error);
  CompleteRead(list_complete_result_);
}

URLRequestFileDirJob::~URLRequestFileDirJob() {}

void URLRequestFileDirJob::CompleteRead(Error error) {
  DCHECK_LE(error, OK);
  DCHECK_NE(error, ERR_IO_PENDING);

  // Do nothing if there is no read pending.
  if (!read_pending_)
    return;

  int result = error;
  if (error == OK) {
    result = ReadBuffer(read_buffer_->data(), read_buffer_length_);
    if (result >= 0) {
      // We completed the read, so reset the read buffer.
      read_buffer_ = NULL;
      read_buffer_length_ = 0;
    } else {
      NOTREACHED();
      // TODO: Better error code.
      result = ERR_FAILED;
    }
  }

  read_pending_ = false;
  ReadRawDataComplete(result);
}

int URLRequestFileDirJob::ReadBuffer(char* buf, int buf_size) {
  int count = std::min(buf_size, static_cast<int>(data_.size()));
  if (count) {
    memcpy(buf, &data_[0], count);
    data_.erase(0, count);
    return count;
  } else if (list_complete_) {
    // EOF
    return list_complete_result_;
  }
  return ERR_IO_PENDING;
}

}  // namespace net
