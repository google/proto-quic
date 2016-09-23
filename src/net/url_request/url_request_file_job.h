// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_URL_REQUEST_URL_REQUEST_FILE_JOB_H_
#define NET_URL_REQUEST_URL_REQUEST_FILE_JOB_H_

#include <stdint.h>

#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "net/base/net_errors.h"
#include "net/base/net_export.h"
#include "net/http/http_byte_range.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_job.h"

namespace base {
class TaskRunner;
}
namespace file_util {
struct FileInfo;
}

namespace net {

class FileStream;

// A request job that handles reading file URLs
class NET_EXPORT URLRequestFileJob : public URLRequestJob {
 public:
  URLRequestFileJob(URLRequest* request,
                    NetworkDelegate* network_delegate,
                    const base::FilePath& file_path,
                    const scoped_refptr<base::TaskRunner>& file_task_runner);

  // URLRequestJob:
  void Start() override;
  void Kill() override;
  int ReadRawData(IOBuffer* buf, int buf_size) override;
  bool IsRedirectResponse(GURL* location, int* http_status_code) override;
  std::unique_ptr<Filter> SetupFilter() const override;
  bool GetMimeType(std::string* mime_type) const override;
  void SetExtraRequestHeaders(const HttpRequestHeaders& headers) override;

  // An interface for subclasses who wish to monitor read operations.
  virtual void OnSeekComplete(int64_t result);
  virtual void OnReadComplete(IOBuffer* buf, int result);

 protected:
  ~URLRequestFileJob() override;

  int64_t remaining_bytes() const { return remaining_bytes_; }

  // The OS-specific full path name of the file
  base::FilePath file_path_;

 private:
  // Meta information about the file. It's used as a member in the
  // URLRequestFileJob and also passed between threads because disk access is
  // necessary to obtain it.
  struct FileMetaInfo {
    FileMetaInfo();

    // Size of the file.
    int64_t file_size;
    // Mime type associated with the file.
    std::string mime_type;
    // Result returned from GetMimeTypeFromFile(), i.e. flag showing whether
    // obtaining of the mime type was successful.
    bool mime_type_result;
    // Flag showing whether the file exists.
    bool file_exists;
    // Flag showing whether the file name actually refers to a directory.
    bool is_directory;
  };

  // Fetches file info on a background thread.
  static void FetchMetaInfo(const base::FilePath& file_path,
                            FileMetaInfo* meta_info);

  // Callback after fetching file info on a background thread.
  void DidFetchMetaInfo(const FileMetaInfo* meta_info);

  // Callback after opening file on a background thread.
  void DidOpen(int result);

  // Callback after seeking to the beginning of |byte_range_| in the file
  // on a background thread.
  void DidSeek(int64_t result);

  // Callback after data is asynchronously read from the file into |buf|.
  void DidRead(scoped_refptr<IOBuffer> buf, int result);

  std::unique_ptr<FileStream> stream_;
  FileMetaInfo meta_info_;
  const scoped_refptr<base::TaskRunner> file_task_runner_;

  std::vector<HttpByteRange> byte_ranges_;
  HttpByteRange byte_range_;
  int64_t remaining_bytes_;

  Error range_parse_result_;

  base::WeakPtrFactory<URLRequestFileJob> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(URLRequestFileJob);
};

}  // namespace net

#endif  // NET_URL_REQUEST_URL_REQUEST_FILE_JOB_H_
