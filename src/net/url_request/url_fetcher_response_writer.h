// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_URL_REQUEST_URL_FETCHER_RESPONSE_WRITER_H_
#define NET_URL_REQUEST_URL_FETCHER_RESPONSE_WRITER_H_

#include <memory>
#include <string>

#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "net/base/completion_callback.h"
#include "net/base/net_export.h"

namespace base {
class SequencedTaskRunner;
}  // namespace base

namespace net {

class DrainableIOBuffer;
class FileStream;
class IOBuffer;
class URLFetcherFileWriter;
class URLFetcherStringWriter;

// This class encapsulates all state involved in writing URLFetcher response
// bytes to the destination.
class NET_EXPORT URLFetcherResponseWriter {
 public:
  virtual ~URLFetcherResponseWriter() {}

  // Initializes this instance. If ERR_IO_PENDING is returned, |callback| will
  // be run later with the result. Calling this method again after a
  // Initialize() success results in discarding already written data.
  virtual int Initialize(const CompletionCallback& callback) = 0;

  // Writes |num_bytes| bytes in |buffer|, and returns the number of bytes
  // written or an error code. If ERR_IO_PENDING is returned, |callback| will be
  // run later with the result.
  virtual int Write(IOBuffer* buffer,
                    int num_bytes,
                    const CompletionCallback& callback) = 0;

  // Finishes writing. If ERR_IO_PENDING is returned, |callback| will be run
  // later with the result.
  virtual int Finish(const CompletionCallback& callback) = 0;

  // Returns this instance's pointer as URLFetcherStringWriter when possible.
  virtual URLFetcherStringWriter* AsStringWriter();

  // Returns this instance's pointer as URLFetcherFileWriter when possible.
  virtual URLFetcherFileWriter* AsFileWriter();
};

// URLFetcherResponseWriter implementation for std::string.
class NET_EXPORT URLFetcherStringWriter : public URLFetcherResponseWriter {
 public:
  URLFetcherStringWriter();
  ~URLFetcherStringWriter() override;

  const std::string& data() const { return data_; }

  // URLFetcherResponseWriter overrides:
  int Initialize(const CompletionCallback& callback) override;
  int Write(IOBuffer* buffer,
            int num_bytes,
            const CompletionCallback& callback) override;
  int Finish(const CompletionCallback& callback) override;
  URLFetcherStringWriter* AsStringWriter() override;

 private:
  std::string data_;

  DISALLOW_COPY_AND_ASSIGN(URLFetcherStringWriter);
};

// URLFetcherResponseWriter implementation for files.
class NET_EXPORT URLFetcherFileWriter : public URLFetcherResponseWriter {
 public:
  // |file_path| is used as the destination path. If |file_path| is empty,
  // Initialize() will create a temporary file.
  URLFetcherFileWriter(
      scoped_refptr<base::SequencedTaskRunner> file_task_runner,
      const base::FilePath& file_path);
  ~URLFetcherFileWriter() override;

  const base::FilePath& file_path() const { return file_path_; }

  // URLFetcherResponseWriter overrides:
  int Initialize(const CompletionCallback& callback) override;
  int Write(IOBuffer* buffer,
            int num_bytes,
            const CompletionCallback& callback) override;
  int Finish(const CompletionCallback& callback) override;
  URLFetcherFileWriter* AsFileWriter() override;

  // Drops ownership of the file at |file_path_|.
  // This class will not delete it or write to it again.
  void DisownFile();

 private:
  // Called when a write has been done.
  void DidWrite(const CompletionCallback& callback, int result);

  // Closes the file if it is open and then delete it.
  void CloseAndDeleteFile();

  // Callback which gets the result of a temporary file creation.
  void DidCreateTempFile(const CompletionCallback& callback,
                         base::FilePath* temp_file_path,
                         bool success);

  // Callback which gets the result of FileStream::Open.
  void DidOpenFile(const CompletionCallback& callback,
                   int result);

  // Callback which gets the result of closing a file.
  void CloseComplete(const CompletionCallback& callback, int result);

  // Task runner on which file operations should happen.
  scoped_refptr<base::SequencedTaskRunner> file_task_runner_;

  // Destination file path.
  // Initialize() creates a temporary file if this variable is empty.
  base::FilePath file_path_;

  // True when this instance is responsible to delete the file at |file_path_|.
  bool owns_file_;

  std::unique_ptr<FileStream> file_stream_;

  // Callbacks are created for use with base::FileUtilProxy.
  base::WeakPtrFactory<URLFetcherFileWriter> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(URLFetcherFileWriter);
};

}  // namespace net

#endif  // NET_URL_REQUEST_URL_FETCHER_RESPONSE_WRITER_H_
