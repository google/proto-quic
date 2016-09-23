// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_fetcher_response_writer.h"

#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/run_loop.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/platform_test.h"

using net::test::IsOk;

namespace net {

namespace {

const char kData[] = "Hello!";

}  // namespace

class URLFetcherStringWriterTest : public PlatformTest {
 protected:
  void SetUp() override {
    writer_.reset(new URLFetcherStringWriter);
    buf_ = new StringIOBuffer(kData);
  }

  std::unique_ptr<URLFetcherStringWriter> writer_;
  scoped_refptr<StringIOBuffer> buf_;
};

TEST_F(URLFetcherStringWriterTest, Basic) {
  int rv = 0;
  // Initialize(), Write() and Finish().
  TestCompletionCallback callback;
  rv = writer_->Initialize(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  rv = writer_->Write(buf_.get(), buf_->size(), callback.callback());
  EXPECT_EQ(buf_->size(), callback.GetResult(rv));
  rv = writer_->Finish(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  // Verify the result.
  EXPECT_EQ(kData, writer_->data());

  // Initialize() again to reset.
  rv = writer_->Initialize(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(writer_->data().empty());
}

class URLFetcherFileWriterTest : public PlatformTest {
 protected:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    file_path_ = temp_dir_.GetPath().AppendASCII("test.txt");
    writer_.reset(new URLFetcherFileWriter(base::ThreadTaskRunnerHandle::Get(),
                                           file_path_));
    buf_ = new StringIOBuffer(kData);
  }

  base::ScopedTempDir temp_dir_;
  base::FilePath file_path_;
  std::unique_ptr<URLFetcherFileWriter> writer_;
  scoped_refptr<StringIOBuffer> buf_;
};

TEST_F(URLFetcherFileWriterTest, WriteToFile) {
  int rv = 0;
  // Initialize(), Write() and Finish().
  TestCompletionCallback callback;
  rv = writer_->Initialize(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  rv = writer_->Write(buf_.get(), buf_->size(), callback.callback());
  EXPECT_EQ(buf_->size(), callback.GetResult(rv));
  rv = writer_->Finish(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  // Verify the result.
  EXPECT_EQ(file_path_.value(), writer_->file_path().value());
  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(writer_->file_path(), &file_contents));
  EXPECT_EQ(kData, file_contents);

  // Destroy the writer. File should be deleted.
  writer_.reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(base::PathExists(file_path_));
}

TEST_F(URLFetcherFileWriterTest, InitializeAgain) {
  int rv = 0;
  // Initialize(), Write() and Finish().
  TestCompletionCallback callback;
  rv = writer_->Initialize(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  rv = writer_->Write(buf_.get(), buf_->size(), callback.callback());
  EXPECT_EQ(buf_->size(), callback.GetResult(rv));
  rv = writer_->Finish(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  // Verify the result.
  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(writer_->file_path(), &file_contents));
  EXPECT_EQ(kData, file_contents);

  // Initialize() again to reset. Write different data.
  const std::string data2 = "Bye!";
  scoped_refptr<StringIOBuffer> buf2(new StringIOBuffer(data2));

  rv = writer_->Initialize(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  rv = writer_->Write(buf2.get(), buf2->size(), callback.callback());
  EXPECT_EQ(buf2->size(), callback.GetResult(rv));
  rv = writer_->Finish(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  // Verify the result.
  file_contents.clear();
  EXPECT_TRUE(base::ReadFileToString(writer_->file_path(), &file_contents));
  EXPECT_EQ(data2, file_contents);
}

TEST_F(URLFetcherFileWriterTest, DisownFile) {
  int rv = 0;
  // Initialize() and Finish() to create a file.
  TestCompletionCallback callback;
  rv = writer_->Initialize(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  rv = writer_->Finish(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  // Disown file.
  writer_->DisownFile();

  // File is not deleted even after the writer gets destroyed.
  writer_.reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(base::PathExists(file_path_));
}

class URLFetcherFileWriterTemporaryFileTest : public PlatformTest {
 protected:
  void SetUp() override {
    writer_.reset(new URLFetcherFileWriter(base::ThreadTaskRunnerHandle::Get(),
                                           base::FilePath()));
    buf_ = new StringIOBuffer(kData);
  }

  std::unique_ptr<URLFetcherFileWriter> writer_;
  scoped_refptr<StringIOBuffer> buf_;
};

TEST_F(URLFetcherFileWriterTemporaryFileTest, WriteToTemporaryFile) {
  int rv = 0;
  // Initialize(), Write() and Finish().
  TestCompletionCallback callback;
  rv = writer_->Initialize(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  rv = writer_->Write(buf_.get(), buf_->size(), callback.callback());
  EXPECT_EQ(buf_->size(), callback.GetResult(rv));
  rv = writer_->Finish(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  // Verify the result.
  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(writer_->file_path(), &file_contents));
  EXPECT_EQ(kData, file_contents);

  // Destroy the writer. File should be deleted.
  const base::FilePath file_path = writer_->file_path();
  writer_.reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(base::PathExists(file_path));
}

}  // namespace net
