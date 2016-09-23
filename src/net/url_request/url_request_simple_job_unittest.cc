// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_simple_job.h"

#include <memory>
#include <utility>

#include "base/bind_helpers.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/sequenced_task_runner.h"
#include "base/strings/string_piece.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread.h"
#include "net/base/request_priority.h"
#include "net/test/gtest_util.h"
#include "net/url_request/url_request_job.h"
#include "net/url_request/url_request_job_factory.h"
#include "net/url_request/url_request_job_factory_impl.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

const char kTestData[] = "Huge data array";
const int kRangeFirstPosition = 5;
const int kRangeLastPosition = 8;
static_assert(kRangeFirstPosition > 0 &&
                  kRangeFirstPosition < kRangeLastPosition &&
                  kRangeLastPosition <
                      static_cast<int>(arraysize(kTestData) - 1),
              "invalid range");

class MockSimpleJob : public URLRequestSimpleJob {
 public:
  MockSimpleJob(URLRequest* request,
                NetworkDelegate* network_delegate,
                scoped_refptr<base::TaskRunner> task_runner,
                base::StringPiece data)
      : URLRequestSimpleJob(request, network_delegate),
        data_(data.as_string()),
        task_runner_(std::move(task_runner)) {}

 protected:
  // URLRequestSimpleJob implementation:
  int GetData(std::string* mime_type,
              std::string* charset,
              std::string* data,
              const CompletionCallback& callback) const override {
    mime_type->assign("text/plain");
    charset->assign("US-ASCII");
    data->assign(data_);
    return OK;
  }

  base::TaskRunner* GetTaskRunner() const override {
    return task_runner_.get();
  }

 private:
  ~MockSimpleJob() override {}

  const std::string data_;

  const scoped_refptr<base::TaskRunner> task_runner_;

  DISALLOW_COPY_AND_ASSIGN(MockSimpleJob);
};

class CancelAfterFirstReadURLRequestDelegate : public TestDelegate {
 public:
  CancelAfterFirstReadURLRequestDelegate() : run_loop_(new base::RunLoop) {}

  ~CancelAfterFirstReadURLRequestDelegate() override {}

  void OnResponseStarted(URLRequest* request, int net_error) override {
    DCHECK_NE(ERR_IO_PENDING, net_error);
    // net::TestDelegate will start the first read.
    TestDelegate::OnResponseStarted(request, net_error);
    request->Cancel();
    run_loop_->Quit();
  }

  void WaitUntilHeadersReceived() const { run_loop_->Run(); }

 private:
  std::unique_ptr<base::RunLoop> run_loop_;

  DISALLOW_COPY_AND_ASSIGN(CancelAfterFirstReadURLRequestDelegate);
};

class SimpleJobProtocolHandler :
    public URLRequestJobFactory::ProtocolHandler {
 public:
  SimpleJobProtocolHandler(scoped_refptr<base::TaskRunner> task_runner)
      : task_runner_(std::move(task_runner)) {}
  URLRequestJob* MaybeCreateJob(
      URLRequest* request,
      NetworkDelegate* network_delegate) const override {
    if (request->url().spec() == "data:empty")
      return new MockSimpleJob(request, network_delegate, task_runner_, "");
    return new MockSimpleJob(request, network_delegate, task_runner_,
                             kTestData);
  }

  ~SimpleJobProtocolHandler() override {}

 private:
  const scoped_refptr<base::TaskRunner> task_runner_;

  DISALLOW_COPY_AND_ASSIGN(SimpleJobProtocolHandler);
};

class URLRequestSimpleJobTest : public ::testing::Test {
 public:
  URLRequestSimpleJobTest()
      : worker_thread_("URLRequestSimpleJobTest"), context_(true) {
    EXPECT_TRUE(worker_thread_.Start());

    job_factory_.SetProtocolHandler(
        "data", base::MakeUnique<SimpleJobProtocolHandler>(task_runner()));
    context_.set_job_factory(&job_factory_);
    context_.Init();

    request_ =
        context_.CreateRequest(GURL("data:test"), DEFAULT_PRIORITY, &delegate_);
  }

  void StartRequest(const HttpRequestHeaders* headers) {
    if (headers)
      request_->SetExtraRequestHeaders(*headers);
    request_->Start();

    EXPECT_TRUE(request_->is_pending());
    base::RunLoop().Run();
    EXPECT_FALSE(request_->is_pending());
  }

  scoped_refptr<base::SequencedTaskRunner> task_runner() {
    return worker_thread_.task_runner();
  }

 protected:
  base::Thread worker_thread_;
  TestURLRequestContext context_;
  URLRequestJobFactoryImpl job_factory_;
  TestDelegate delegate_;
  std::unique_ptr<URLRequest> request_;

  DISALLOW_COPY_AND_ASSIGN(URLRequestSimpleJobTest);
};

}  // namespace

TEST_F(URLRequestSimpleJobTest, SimpleRequest) {
  StartRequest(NULL);
  EXPECT_THAT(delegate_.request_status(), IsOk());
  EXPECT_EQ(kTestData, delegate_.data_received());
}

TEST_F(URLRequestSimpleJobTest, RangeRequest) {
  const std::string kExpectedBody = std::string(
      kTestData + kRangeFirstPosition, kTestData + kRangeLastPosition + 1);
  HttpRequestHeaders headers;
  headers.SetHeader(
      HttpRequestHeaders::kRange,
      HttpByteRange::Bounded(kRangeFirstPosition, kRangeLastPosition)
          .GetHeaderValue());

  StartRequest(&headers);

  EXPECT_THAT(delegate_.request_status(), IsOk());
  EXPECT_EQ(kExpectedBody, delegate_.data_received());
}

TEST_F(URLRequestSimpleJobTest, MultipleRangeRequest) {
  HttpRequestHeaders headers;
  int middle_pos = (kRangeFirstPosition + kRangeLastPosition)/2;
  std::string range = base::StringPrintf("bytes=%d-%d,%d-%d",
                                         kRangeFirstPosition,
                                         middle_pos,
                                         middle_pos + 1,
                                         kRangeLastPosition);
  headers.SetHeader(HttpRequestHeaders::kRange, range);

  StartRequest(&headers);

  EXPECT_TRUE(delegate_.request_failed());
  EXPECT_EQ(ERR_REQUEST_RANGE_NOT_SATISFIABLE, delegate_.request_status());
}

TEST_F(URLRequestSimpleJobTest, InvalidRangeRequest) {
  HttpRequestHeaders headers;
  std::string range = base::StringPrintf(
      "bytes=%d-%d", kRangeLastPosition, kRangeFirstPosition);
  headers.SetHeader(HttpRequestHeaders::kRange, range);

  StartRequest(&headers);

  EXPECT_THAT(delegate_.request_status(), IsOk());
  EXPECT_EQ(kTestData, delegate_.data_received());
}

TEST_F(URLRequestSimpleJobTest, EmptyDataRequest) {
  request_ =
      context_.CreateRequest(GURL("data:empty"), DEFAULT_PRIORITY, &delegate_);
  StartRequest(nullptr);
  EXPECT_THAT(delegate_.request_status(), IsOk());
  EXPECT_EQ("", delegate_.data_received());
}

TEST_F(URLRequestSimpleJobTest, CancelBeforeResponseStarts) {
  request_ =
      context_.CreateRequest(GURL("data:cancel"), DEFAULT_PRIORITY, &delegate_);
  request_->Start();
  request_->Cancel();

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(delegate_.request_status(), IsError(ERR_ABORTED));
  EXPECT_EQ(1, delegate_.response_started_count());
}

TEST_F(URLRequestSimpleJobTest, CancelAfterFirstReadStarted) {
  CancelAfterFirstReadURLRequestDelegate cancel_delegate;
  request_ = context_.CreateRequest(GURL("data:cancel"), DEFAULT_PRIORITY,
                                    &cancel_delegate);
  request_->Start();
  cancel_delegate.WaitUntilHeadersReceived();

  // Feed a dummy task to the SequencedTaskRunner to make sure that the
  // callbacks which are invoked in ReadRawData have completed safely.
  base::RunLoop run_loop;
  EXPECT_TRUE(task_runner()->PostTaskAndReply(
      FROM_HERE, base::Bind(&base::DoNothing), run_loop.QuitClosure()));
  run_loop.Run();

  EXPECT_THAT(cancel_delegate.request_status(), IsError(ERR_ABORTED));
  EXPECT_EQ(1, cancel_delegate.response_started_count());
  EXPECT_EQ("", cancel_delegate.data_received());
  // Destroy the request so it doesn't outlive its delegate.
  request_.reset();
}

}  // namespace net
