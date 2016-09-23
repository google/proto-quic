// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_fetcher_response_writer.h"

#include "base/files/file_util.h"
#include "base/location.h"
#include "base/sequenced_task_runner.h"
#include "base/task_runner_util.h"
#include "net/base/file_stream.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"

namespace net {

URLFetcherStringWriter* URLFetcherResponseWriter::AsStringWriter() {
  return NULL;
}

URLFetcherFileWriter* URLFetcherResponseWriter::AsFileWriter() {
  return NULL;
}

URLFetcherStringWriter::URLFetcherStringWriter() {
}

URLFetcherStringWriter::~URLFetcherStringWriter() {
}

int URLFetcherStringWriter::Initialize(const CompletionCallback& callback) {
  data_.clear();
  return OK;
}

int URLFetcherStringWriter::Write(IOBuffer* buffer,
                                  int num_bytes,
                                  const CompletionCallback& callback) {
  data_.append(buffer->data(), num_bytes);
  return num_bytes;
}

int URLFetcherStringWriter::Finish(const CompletionCallback& callback) {
  // Do nothing.
  return OK;
}

URLFetcherStringWriter* URLFetcherStringWriter::AsStringWriter() {
  return this;
}

URLFetcherFileWriter::URLFetcherFileWriter(
    scoped_refptr<base::SequencedTaskRunner> file_task_runner,
    const base::FilePath& file_path)
    : file_task_runner_(file_task_runner),
      file_path_(file_path),
      owns_file_(false),
      weak_factory_(this) {
  DCHECK(file_task_runner_.get());
}

URLFetcherFileWriter::~URLFetcherFileWriter() {
  CloseAndDeleteFile();
}

int URLFetcherFileWriter::Initialize(const CompletionCallback& callback) {
  file_stream_.reset(new FileStream(file_task_runner_));

  int result = ERR_IO_PENDING;
  if (file_path_.empty()) {
    base::FilePath* temp_file_path = new base::FilePath;
    base::PostTaskAndReplyWithResult(
        file_task_runner_.get(),
        FROM_HERE,
        base::Bind(&base::CreateTemporaryFile, temp_file_path),
        base::Bind(&URLFetcherFileWriter::DidCreateTempFile,
                   weak_factory_.GetWeakPtr(),
                   callback,
                   base::Owned(temp_file_path)));
  } else {
    result = file_stream_->Open(
        file_path_,
        base::File::FLAG_WRITE | base::File::FLAG_ASYNC |
        base::File::FLAG_CREATE_ALWAYS,
        base::Bind(&URLFetcherFileWriter::DidOpenFile,
                   weak_factory_.GetWeakPtr(),
                   callback));
    DCHECK_NE(OK, result);
  }
  return result;
}

int URLFetcherFileWriter::Write(IOBuffer* buffer,
                                int num_bytes,
                                const CompletionCallback& callback) {
  DCHECK(file_stream_);
  DCHECK(owns_file_);

  int result = file_stream_->Write(buffer, num_bytes,
                                   base::Bind(&URLFetcherFileWriter::DidWrite,
                                              weak_factory_.GetWeakPtr(),
                                              callback));
  if (result < 0 && result != ERR_IO_PENDING)
    CloseAndDeleteFile();

  return result;
}

int URLFetcherFileWriter::Finish(const CompletionCallback& callback) {
  // If the file_stream_ still exists at this point, close it.
  if (file_stream_) {
    int result = file_stream_->Close(base::Bind(
        &URLFetcherFileWriter::CloseComplete,
        weak_factory_.GetWeakPtr(), callback));
    if (result != ERR_IO_PENDING)
      file_stream_.reset();
    return result;
  }
  return OK;
}

URLFetcherFileWriter* URLFetcherFileWriter::AsFileWriter() {
  return this;
}

void URLFetcherFileWriter::DisownFile() {
  // Disowning is done by the delegate's OnURLFetchComplete method.
  // The file should be closed by the time that method is called.
  DCHECK(!file_stream_);

  owns_file_ = false;
}

void URLFetcherFileWriter::DidWrite(const CompletionCallback& callback,
                                    int result) {
  if (result < 0)
    CloseAndDeleteFile();

  callback.Run(result);
}

void URLFetcherFileWriter::CloseAndDeleteFile() {
  if (!owns_file_)
    return;

  file_stream_.reset();
  DisownFile();
  file_task_runner_->PostTask(FROM_HERE,
                              base::Bind(base::IgnoreResult(&base::DeleteFile),
                                         file_path_,
                                         false /* recursive */));
}

void URLFetcherFileWriter::DidCreateTempFile(const CompletionCallback& callback,
                                             base::FilePath* temp_file_path,
                                             bool success) {
  if (!success) {
    callback.Run(ERR_FILE_NOT_FOUND);
    return;
  }
  file_path_ = *temp_file_path;
  owns_file_ = true;
  const int result = file_stream_->Open(
      file_path_,
      base::File::FLAG_WRITE | base::File::FLAG_ASYNC |
      base::File::FLAG_OPEN,
      base::Bind(&URLFetcherFileWriter::DidOpenFile,
                 weak_factory_.GetWeakPtr(),
                 callback));
  if (result != ERR_IO_PENDING)
    DidOpenFile(callback, result);
}

void URLFetcherFileWriter::DidOpenFile(const CompletionCallback& callback,
                                       int result) {
  if (result == OK)
    owns_file_ = true;
  else
    CloseAndDeleteFile();

  callback.Run(result);
}

void URLFetcherFileWriter::CloseComplete(const CompletionCallback& callback,
                                         int result) {
  // Destroy |file_stream_| whether or not the close succeeded.
  file_stream_.reset();
  callback.Run(result);
}

}  // namespace net
