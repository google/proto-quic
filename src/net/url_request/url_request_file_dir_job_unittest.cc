// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_file_dir_job.h"

#include <memory>
#include <string>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "base/test/scoped_task_environment.h"
#include "net/base/filename_util.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/test/gtest_util.h"
#include "net/test/net_test_suite.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

const int kBufferSize = 4096;

class TestJobFactory : public URLRequestJobFactory {
 public:
  explicit TestJobFactory(const base::FilePath& path) : path_(path) {}
  ~TestJobFactory() override {}

  URLRequestJob* MaybeCreateJobWithProtocolHandler(
      const std::string& scheme,
      URLRequest* request,
      NetworkDelegate* network_delegate) const override {
    URLRequestJob* job =
        new URLRequestFileDirJob(request, network_delegate, path_);

    return job;
  }

  URLRequestJob* MaybeInterceptRedirect(URLRequest* request,
                                        NetworkDelegate* network_delegate,
                                        const GURL& location) const override {
    return nullptr;
  }

  URLRequestJob* MaybeInterceptResponse(
      URLRequest* request,
      NetworkDelegate* network_delegate) const override {
    return nullptr;
  }

  bool IsHandledProtocol(const std::string& scheme) const override {
    return scheme == "file";
  }

  bool IsSafeRedirectTarget(const GURL& location) const override {
    return false;
  }

 private:
  const base::FilePath path_;

  DISALLOW_COPY_AND_ASSIGN(TestJobFactory);
};

class TestDirectoryURLRequestDelegate : public TestDelegate {
 public:
  TestDirectoryURLRequestDelegate() {}

  ~TestDirectoryURLRequestDelegate() override {}

  void OnResponseStarted(URLRequest* request, int net_error) override {
    got_response_started_ = true;
  }

  bool got_response_started() const { return got_response_started_; }

 private:
  bool got_response_started_ = false;

  DISALLOW_COPY_AND_ASSIGN(TestDirectoryURLRequestDelegate);
};

class URLRequestFileDirTest : public testing::Test {
 public:
  URLRequestFileDirTest() : buffer_(new IOBuffer(kBufferSize)) {}

 protected:
  TestURLRequestContext context_;
  TestDirectoryURLRequestDelegate delegate_;
  scoped_refptr<IOBuffer> buffer_;
};

TEST_F(URLRequestFileDirTest, ListCompletionOnNoPending) {
  base::ScopedTempDir directory;
  // It is necessary to pass an existing directory to UrlRequest object,
  // but it will be deleted for testing purpose after request is started.
  ASSERT_TRUE(directory.CreateUniqueTempDir());
  TestJobFactory factory(directory.GetPath());
  context_.set_job_factory(&factory);
  std::unique_ptr<URLRequest> request(context_.CreateRequest(
      FilePathToFileURL(
          directory.GetPath().AppendASCII("this_path_does_not_exist")),
      DEFAULT_PRIORITY, &delegate_, TRAFFIC_ANNOTATION_FOR_TESTS));

  request->Start();
  ASSERT_TRUE(directory.Delete());

  // Since the DirectoryLister is running on the network thread, this
  // will spin the message loop until the read error is returned to the
  // URLRequestFileDirJob.
  NetTestSuite::GetScopedTaskEnvironment()->RunUntilIdle();
  ASSERT_TRUE(delegate_.got_response_started());

  int bytes_read = request->Read(buffer_.get(), kBufferSize);

  // The URLRequestFileDirJobShould return the cached read error synchronously.
  // If it's not returned synchronously, the code path this is intended to test
  // was not executed.
  EXPECT_THAT(bytes_read, IsError(ERR_FILE_NOT_FOUND));
}

// Test the case where reading the response completes synchronously.
TEST_F(URLRequestFileDirTest, DirectoryWithASingleFileSync) {
  base::ScopedTempDir directory;
  ASSERT_TRUE(directory.CreateUniqueTempDir());
  base::FilePath path;
  base::CreateTemporaryFileInDir(directory.GetPath(), &path);

  TestJobFactory factory(directory.GetPath());
  context_.set_job_factory(&factory);

  std::unique_ptr<URLRequest> request(
      context_.CreateRequest(FilePathToFileURL(path), DEFAULT_PRIORITY,
                             &delegate_, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  EXPECT_TRUE(request->is_pending());

  // Since the DirectoryLister is running on the network thread, this will spin
  // the message loop until the URLRequetsFileDirJob has received the
  // entire directory listing and cached it.
  NetTestSuite::GetScopedTaskEnvironment()->RunUntilIdle();

  // This will complete synchronously, since the URLRequetsFileDirJob had
  // directory listing cached in memory.
  int bytes_read = request->Read(buffer_.get(), kBufferSize);

  ASSERT_GT(bytes_read, 0);
  ASSERT_LE(bytes_read, kBufferSize);
  std::string data(buffer_->data(), bytes_read);
  EXPECT_TRUE(data.find(directory.GetPath().BaseName().MaybeAsASCII()) !=
              std::string::npos);
  EXPECT_TRUE(data.find(path.BaseName().MaybeAsASCII()) != std::string::npos);
}

// Test the case where reading the response completes asynchronously.
TEST_F(URLRequestFileDirTest, DirectoryWithASingleFileAsync) {
  base::ScopedTempDir directory;
  ASSERT_TRUE(directory.CreateUniqueTempDir());
  base::FilePath path;
  base::CreateTemporaryFileInDir(directory.GetPath(), &path);

  TestJobFactory factory(directory.GetPath());
  context_.set_job_factory(&factory);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request(
      context_.CreateRequest(FilePathToFileURL(path), DEFAULT_PRIORITY,
                             &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  EXPECT_TRUE(request->is_pending());

  base::RunLoop().Run();

  ASSERT_GT(delegate.bytes_received(), 0);
  ASSERT_LE(delegate.bytes_received(), kBufferSize);
  EXPECT_TRUE(delegate.data_received().find(
                  directory.GetPath().BaseName().MaybeAsASCII()) !=
              std::string::npos);
  EXPECT_TRUE(delegate.data_received().find(path.BaseName().MaybeAsASCII()) !=
              std::string::npos);
}

TEST_F(URLRequestFileDirTest, DirectoryWithAFileAndSubdirectory) {
  base::ScopedTempDir directory;
  ASSERT_TRUE(directory.CreateUniqueTempDir());

  base::FilePath sub_dir;
  CreateTemporaryDirInDir(directory.GetPath(),
                          FILE_PATH_LITERAL("CreateNewSubDirectoryInDirectory"),
                          &sub_dir);

  base::FilePath path;
  base::CreateTemporaryFileInDir(directory.GetPath(), &path);

  TestJobFactory factory(directory.GetPath());
  context_.set_job_factory(&factory);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request(
      context_.CreateRequest(FilePathToFileURL(path), DEFAULT_PRIORITY,
                             &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  EXPECT_TRUE(request->is_pending());

  base::RunLoop().Run();

  ASSERT_GT(delegate.bytes_received(), 0);
  ASSERT_LE(delegate.bytes_received(), kBufferSize);
  EXPECT_TRUE(delegate.data_received().find(
                  directory.GetPath().BaseName().MaybeAsASCII()) !=
              std::string::npos);
  EXPECT_TRUE(delegate.data_received().find(
                  sub_dir.BaseName().MaybeAsASCII()) != std::string::npos);
  EXPECT_TRUE(delegate.data_received().find(path.BaseName().MaybeAsASCII()) !=
              std::string::npos);
}

TEST_F(URLRequestFileDirTest, EmptyDirectory) {
  base::ScopedTempDir directory;
  ASSERT_TRUE(directory.CreateUniqueTempDir());

  TestJobFactory factory(directory.GetPath());
  context_.set_job_factory(&factory);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request(context_.CreateRequest(
      FilePathToFileURL(directory.GetPath()), DEFAULT_PRIORITY, &delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  EXPECT_TRUE(request->is_pending());

  base::RunLoop().Run();

  ASSERT_GT(delegate.bytes_received(), 0);
  ASSERT_LE(delegate.bytes_received(), kBufferSize);
  EXPECT_TRUE(delegate.data_received().find(
                  directory.GetPath().BaseName().MaybeAsASCII()) !=
              std::string::npos);
}

}  // namespace

}  // namespace net
