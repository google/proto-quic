// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_file_job.h"

#include <memory>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/logging.h"
#include "base/run_loop.h"
#include "base/strings/stringprintf.h"
#include "base/threading/sequenced_worker_pool.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/filename_util.h"
#include "net/base/net_errors.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// A URLRequestFileJob for testing values passed to OnSeekComplete and
// OnReadComplete.
class TestURLRequestFileJob : public URLRequestFileJob {
 public:
  // |seek_position| will be set to the value passed in to OnSeekComplete.
  // |observed_content| will be set to the concatenated data from all calls to
  // OnReadComplete.
  TestURLRequestFileJob(URLRequest* request,
                        NetworkDelegate* network_delegate,
                        const base::FilePath& file_path,
                        const scoped_refptr<base::TaskRunner>& file_task_runner,
                        int* open_result,
                        int64_t* seek_position,
                        std::string* observed_content)
      : URLRequestFileJob(request,
                          network_delegate,
                          file_path,
                          file_task_runner),
        open_result_(open_result),
        seek_position_(seek_position),
        observed_content_(observed_content) {
    *open_result_ = ERR_IO_PENDING;
    *seek_position_ = ERR_IO_PENDING;
    observed_content_->clear();
  }

  ~TestURLRequestFileJob() override {}

 protected:
  void OnOpenComplete(int result) override {
    // Should only be called once.
    ASSERT_EQ(ERR_IO_PENDING, *open_result_);
    *open_result_ = result;
  }

  void OnSeekComplete(int64_t result) override {
    // Should only call this if open succeeded.
    EXPECT_EQ(OK, *open_result_);
    // Should only be called once.
    ASSERT_EQ(ERR_IO_PENDING, *seek_position_);
    *seek_position_ = result;
  }

  void OnReadComplete(IOBuffer* buf, int result) override {
    // Should only call this if seek succeeded.
    EXPECT_GE(*seek_position_, 0);
    observed_content_->append(std::string(buf->data(), result));
  }

  int* const open_result_;
  int64_t* const seek_position_;
  std::string* const observed_content_;
};

// A URLRequestJobFactory that will return TestURLRequestFileJob instances for
// file:// scheme URLs.  Can only be used to create a single job.
class TestJobFactory : public URLRequestJobFactory {
 public:
  TestJobFactory(const base::FilePath& path,
                 int* open_result,
                 int64_t* seek_position,
                 std::string* observed_content)
      : path_(path),
        open_result_(open_result),
        seek_position_(seek_position),
        observed_content_(observed_content) {
    CHECK(open_result_);
    CHECK(seek_position_);
    CHECK(observed_content_);
  }

  ~TestJobFactory() override {}

  URLRequestJob* MaybeCreateJobWithProtocolHandler(
      const std::string& scheme,
      URLRequest* request,
      NetworkDelegate* network_delegate) const override {
    CHECK(open_result_);
    CHECK(seek_position_);
    CHECK(observed_content_);
    URLRequestJob* job = new TestURLRequestFileJob(
        request, network_delegate, path_, base::ThreadTaskRunnerHandle::Get(),
        open_result_, seek_position_, observed_content_);
    open_result_ = nullptr;
    seek_position_ = nullptr;
    observed_content_ = nullptr;
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

  bool IsHandledURL(const GURL& url) const override {
    return IsHandledProtocol(url.scheme());
  }

  bool IsSafeRedirectTarget(const GURL& location) const override {
    return false;
  }

 private:
  const base::FilePath path_;

  // These are mutable because MaybeCreateJobWithProtocolHandler is const.
  mutable int* open_result_;
  mutable int64_t* seek_position_;
  mutable std::string* observed_content_;
};

// Helper function to create a file at |path| filled with |content|.
// Returns true on success.
bool CreateFileWithContent(const std::string& content,
                           const base::FilePath& path) {
  return base::WriteFile(path, content.c_str(), content.length());
}

// A simple holder for start/end used in http range requests.
struct Range {
  int start;
  int end;

  Range() {
    start = 0;
    end = 0;
  }

  Range(int start, int end) {
    this->start = start;
    this->end = end;
  }
};

// A superclass for tests of the OnReadComplete / OnSeekComplete /
// OnReadComplete functions of URLRequestFileJob.
class URLRequestFileJobEventsTest : public testing::Test {
 public:
  URLRequestFileJobEventsTest();

 protected:
  void TearDown() override;

  // This creates a file with |content| as the contents, and then creates and
  // runs a TestURLRequestFileJob job to get the contents out of it,
  // and makes sure that the callbacks observed the correct bytes. If a Range
  // is provided, this function will add the appropriate Range http header to
  // the request and verify that only the bytes in that range (inclusive) were
  // observed.
  void RunSuccessfulRequestWithString(const std::string& content,
                                      const Range* range);

  // This is the same as the method above it, except that it will make sure
  // the content matches |expected_content| and allow caller to specify the
  // extension of the filename in |file_extension|.
  void RunSuccessfulRequestWithString(
      const std::string& content,
      const std::string& expected_content,
      const base::FilePath::StringPieceType& file_extension,
      const Range* range);

  // Creates and runs a TestURLRequestFileJob job to read from file provided by
  // |path|. If |range| value is provided, it will be passed in the range
  // header.
  void RunRequestWithPath(const base::FilePath& path,
                          const std::string& range,
                          int* open_result,
                          int64_t* seek_position,
                          std::string* observed_content);

  TestURLRequestContext context_;
  TestDelegate delegate_;
};

URLRequestFileJobEventsTest::URLRequestFileJobEventsTest() {}

void URLRequestFileJobEventsTest::TearDown() {
  // Gives a chance to close the opening file.
  base::RunLoop().RunUntilIdle();
}

void URLRequestFileJobEventsTest::RunSuccessfulRequestWithString(
    const std::string& content,
    const Range* range) {
  RunSuccessfulRequestWithString(content, content, FILE_PATH_LITERAL(""),
                                 range);
}

void URLRequestFileJobEventsTest::RunSuccessfulRequestWithString(
    const std::string& raw_content,
    const std::string& expected_content,
    const base::FilePath::StringPieceType& file_extension,
    const Range* range) {
  base::ScopedTempDir directory;
  ASSERT_TRUE(directory.CreateUniqueTempDir());
  base::FilePath path = directory.GetPath().Append(FILE_PATH_LITERAL("test"));
  if (!file_extension.empty())
    path = path.AddExtension(file_extension);
  ASSERT_TRUE(CreateFileWithContent(raw_content, path));

  std::string range_value;
  if (range) {
    ASSERT_GE(range->start, 0);
    ASSERT_GE(range->end, 0);
    ASSERT_LE(range->start, range->end);
    ASSERT_LT(static_cast<unsigned int>(range->end), expected_content.length());
    range_value = base::StringPrintf("bytes=%d-%d", range->start, range->end);
  }

  {
    int open_result;
    int64_t seek_position;
    std::string observed_content;
    RunRequestWithPath(path, range_value, &open_result, &seek_position,
                       &observed_content);

    EXPECT_EQ(OK, open_result);
    EXPECT_FALSE(delegate_.request_failed());
    int expected_length =
        range ? (range->end - range->start + 1) : expected_content.length();
    EXPECT_EQ(delegate_.bytes_received(), expected_length);

    std::string expected_data_received;
    if (range) {
      expected_data_received.insert(0, expected_content, range->start,
                                    expected_length);
      EXPECT_EQ(expected_data_received, observed_content);
    } else {
      expected_data_received = expected_content;
      EXPECT_EQ(raw_content, observed_content);
    }

    EXPECT_EQ(expected_data_received, delegate_.data_received());
    EXPECT_EQ(seek_position, range ? range->start : 0);
  }
}

void URLRequestFileJobEventsTest::RunRequestWithPath(
    const base::FilePath& path,
    const std::string& range,
    int* open_result,
    int64_t* seek_position,
    std::string* observed_content) {
  TestJobFactory factory(path, open_result, seek_position, observed_content);
  context_.set_job_factory(&factory);

  std::unique_ptr<URLRequest> request(context_.CreateRequest(
      FilePathToFileURL(path), DEFAULT_PRIORITY, &delegate_));
  if (!range.empty()) {
    request->SetExtraRequestHeaderByName(HttpRequestHeaders::kRange, range,
                                         true /*overwrite*/);
  }
  request->Start();

  base::RunLoop().Run();
}

// Helper function to make a character array filled with |size| bytes of
// test content.
std::string MakeContentOfSize(int size) {
  EXPECT_GE(size, 0);
  std::string result;
  result.reserve(size);
  for (int i = 0; i < size; i++) {
    result.append(1, static_cast<char>(i % 256));
  }
  return result;
}

TEST_F(URLRequestFileJobEventsTest, TinyFile) {
  RunSuccessfulRequestWithString(std::string("hello world"), NULL);
}

TEST_F(URLRequestFileJobEventsTest, SmallFile) {
  RunSuccessfulRequestWithString(MakeContentOfSize(17 * 1024), NULL);
}

TEST_F(URLRequestFileJobEventsTest, BigFile) {
  RunSuccessfulRequestWithString(MakeContentOfSize(3 * 1024 * 1024), NULL);
}

TEST_F(URLRequestFileJobEventsTest, Range) {
  // Use a 15KB content file and read a range chosen somewhat arbitrarily but
  // not aligned on any likely page boundaries.
  int size = 15 * 1024;
  Range range(1701, (6 * 1024) + 3);
  RunSuccessfulRequestWithString(MakeContentOfSize(size), &range);
}

TEST_F(URLRequestFileJobEventsTest, DecodeSvgzFile) {
  std::string expected_content("Hello, World!");
  unsigned char gzip_data[] = {
      // From:
      //   echo -n 'Hello, World!' | gzip | xxd -i | sed -e 's/^/  /'
      0x1f, 0x8b, 0x08, 0x00, 0x2b, 0x02, 0x84, 0x55, 0x00, 0x03, 0xf3,
      0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49,
      0x51, 0x04, 0x00, 0xd0, 0xc3, 0x4a, 0xec, 0x0d, 0x00, 0x00, 0x00};
  RunSuccessfulRequestWithString(
      std::string(reinterpret_cast<char*>(gzip_data), sizeof(gzip_data)),
      expected_content, FILE_PATH_LITERAL("svgz"), nullptr);
}

TEST_F(URLRequestFileJobEventsTest, OpenNonExistentFile) {
  base::FilePath path;
  PathService::Get(base::DIR_SOURCE_ROOT, &path);
  path = path.Append(
      FILE_PATH_LITERAL("net/data/url_request_unittest/non-existent.txt"));

  int open_result;
  int64_t seek_position;
  std::string observed_content;
  RunRequestWithPath(path, std::string(), &open_result, &seek_position,
                     &observed_content);

  EXPECT_EQ(ERR_FILE_NOT_FOUND, open_result);
  EXPECT_TRUE(delegate_.request_failed());
}

TEST_F(URLRequestFileJobEventsTest, MultiRangeRequestNotSupported) {
  base::FilePath path;
  PathService::Get(base::DIR_SOURCE_ROOT, &path);
  path = path.Append(
      FILE_PATH_LITERAL("net/data/url_request_unittest/BullRunSpeech.txt"));

  int open_result;
  int64_t seek_position;
  std::string observed_content;
  RunRequestWithPath(path, "bytes=1-5,20-30", &open_result, &seek_position,
                     &observed_content);

  EXPECT_EQ(OK, open_result);
  EXPECT_EQ(ERR_REQUEST_RANGE_NOT_SATISFIABLE, seek_position);
  EXPECT_TRUE(delegate_.request_failed());
}

TEST_F(URLRequestFileJobEventsTest, RangeExceedingFileSize) {
  base::FilePath path;
  PathService::Get(base::DIR_SOURCE_ROOT, &path);
  path = path.Append(
      FILE_PATH_LITERAL("net/data/url_request_unittest/BullRunSpeech.txt"));

  int open_result;
  int64_t seek_position;
  std::string observed_content;
  RunRequestWithPath(path, "bytes=50000-", &open_result, &seek_position,
                     &observed_content);

  EXPECT_EQ(OK, open_result);
  EXPECT_EQ(ERR_REQUEST_RANGE_NOT_SATISFIABLE, seek_position);
  EXPECT_TRUE(delegate_.request_failed());
}

TEST_F(URLRequestFileJobEventsTest, IgnoreRangeParsingError) {
  base::FilePath path;
  PathService::Get(base::DIR_SOURCE_ROOT, &path);
  path = path.Append(
      FILE_PATH_LITERAL("net/data/url_request_unittest/simple.html"));

  int open_result;
  int64_t seek_position;
  std::string observed_content;
  RunRequestWithPath(path, "bytes=3-z", &open_result, &seek_position,
                     &observed_content);

  EXPECT_EQ(OK, open_result);
  EXPECT_EQ(0, seek_position);
  EXPECT_EQ("hello\n", observed_content);
  EXPECT_FALSE(delegate_.request_failed());
}

}  // namespace

}  // namespace net
