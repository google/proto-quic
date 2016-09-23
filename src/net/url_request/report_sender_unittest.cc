// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/report_sender.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/macros.h"
#include "base/run_loop.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/load_flags.h"
#include "net/base/network_delegate_impl.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/base/upload_data_stream.h"
#include "net/base/upload_element_reader.h"
#include "net/test/url_request/url_request_failed_job.h"
#include "net/test/url_request/url_request_mock_data_job.h"
#include "net/url_request/url_request_filter.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

const char kDummyReport[] = "foo.test";
const char kSecondDummyReport[] = "foo2.test";

void MarkURLRequestDestroyed(bool* url_request_destroyed) {
  *url_request_destroyed = true;
}

// Checks that data uploaded in the request matches the test report
// data. Erases the sent reports from |expect_reports|.
void CheckUploadData(const URLRequest& request,
                     std::set<std::string>* expect_reports) {
  const UploadDataStream* upload = request.get_upload();
  ASSERT_TRUE(upload);
  ASSERT_TRUE(upload->GetElementReaders());
  ASSERT_EQ(1u, upload->GetElementReaders()->size());

  const UploadBytesElementReader* reader =
      (*upload->GetElementReaders())[0]->AsBytesReader();
  ASSERT_TRUE(reader);
  std::string upload_data(reader->bytes(), reader->length());

  EXPECT_EQ(1u, expect_reports->erase(upload_data));
}

// Provides an error callback for report sending that sets |called| to
// true.
void ErrorCallback(bool* called, const GURL& report_uri, int net_error) {
  EXPECT_NE(OK, net_error);
  *called = true;
}

// A network delegate that lets tests check that a report
// was sent. It counts the number of requests and lets tests register a
// callback to run when the request is destroyed. It also checks that
// the uploaded data is as expected.
class TestReportSenderNetworkDelegate : public NetworkDelegateImpl {
 public:
  TestReportSenderNetworkDelegate()
      : url_request_destroyed_callback_(base::Bind(&base::DoNothing)),
        all_url_requests_destroyed_callback_(base::Bind(&base::DoNothing)),
        num_requests_(0),
        expect_cookies_(false) {}

  void ExpectReport(const std::string& report) {
    expect_reports_.insert(report);
  }

  void set_all_url_requests_destroyed_callback(const base::Closure& callback) {
    all_url_requests_destroyed_callback_ = callback;
  }

  void set_url_request_destroyed_callback(const base::Closure& callback) {
    url_request_destroyed_callback_ = callback;
  }

  void set_expect_url(const GURL& expect_url) { expect_url_ = expect_url; }

  size_t num_requests() const { return num_requests_; }

  // Sets whether cookies are expected to be sent on requests.
  void set_expect_cookies(bool expect_cookies) {
    expect_cookies_ = expect_cookies;
  }

  // NetworkDelegateImpl implementation.
  int OnBeforeURLRequest(URLRequest* request,
                         const CompletionCallback& callback,
                         GURL* new_url) override {
    num_requests_++;
    EXPECT_EQ(expect_url_, request->url());
    EXPECT_STRCASEEQ("POST", request->method().data());

    if (expect_cookies_) {
      EXPECT_FALSE(request->load_flags() & LOAD_DO_NOT_SEND_COOKIES);
      EXPECT_FALSE(request->load_flags() & LOAD_DO_NOT_SAVE_COOKIES);
    } else {
      EXPECT_TRUE(request->load_flags() & LOAD_DO_NOT_SEND_COOKIES);
      EXPECT_TRUE(request->load_flags() & LOAD_DO_NOT_SAVE_COOKIES);
    }

    CheckUploadData(*request, &expect_reports_);

    // Unconditionally return OK, since the sender ignores the results
    // anyway.
    return OK;
  }

  void OnURLRequestDestroyed(URLRequest* request) override {
    url_request_destroyed_callback_.Run();
    if (expect_reports_.empty())
      all_url_requests_destroyed_callback_.Run();
  }

 private:
  base::Closure url_request_destroyed_callback_;
  base::Closure all_url_requests_destroyed_callback_;
  size_t num_requests_;
  GURL expect_url_;
  std::set<std::string> expect_reports_;
  bool expect_cookies_;

  DISALLOW_COPY_AND_ASSIGN(TestReportSenderNetworkDelegate);
};

class ReportSenderTest : public ::testing::Test {
 public:
  ReportSenderTest() : context_(true) {
    context_.set_network_delegate(&network_delegate_);
    context_.Init();
  }

  void SetUp() override {
    URLRequestFailedJob::AddUrlHandler();
    URLRequestMockDataJob::AddUrlHandler();
  }

  void TearDown() override { URLRequestFilter::GetInstance()->ClearHandlers(); }

  TestURLRequestContext* context() { return &context_; }

 protected:
  void SendReport(ReportSender* reporter,
                  const std::string& report,
                  const GURL& url,
                  size_t request_sequence_number) {
    base::RunLoop run_loop;
    network_delegate_.set_url_request_destroyed_callback(
        run_loop.QuitClosure());

    network_delegate_.set_expect_url(url);
    network_delegate_.ExpectReport(report);

    EXPECT_EQ(request_sequence_number, network_delegate_.num_requests());

    reporter->Send(url, report);

    // The report is sent asynchronously, so wait for the report's
    // URLRequest to be destroyed before checking that the report was
    // sent.
    run_loop.Run();

    EXPECT_EQ(request_sequence_number + 1, network_delegate_.num_requests());
  }

  TestReportSenderNetworkDelegate network_delegate_;

 private:
  TestURLRequestContext context_;
};

// Test that ReportSender::Send creates a URLRequest for the
// endpoint and sends the expected data.
TEST_F(ReportSenderTest, SendsRequest) {
  GURL url = URLRequestMockDataJob::GetMockHttpsUrl("dummy data", 1);
  ReportSender reporter(context(), ReportSender::DO_NOT_SEND_COOKIES);
  SendReport(&reporter, kDummyReport, url, 0);
}

TEST_F(ReportSenderTest, SendMultipleReportsSequentially) {
  GURL url = URLRequestMockDataJob::GetMockHttpsUrl("dummy data", 1);
  ReportSender reporter(context(), ReportSender::DO_NOT_SEND_COOKIES);
  SendReport(&reporter, kDummyReport, url, 0);
  SendReport(&reporter, kDummyReport, url, 1);
}

TEST_F(ReportSenderTest, SendMultipleReportsSimultaneously) {
  base::RunLoop run_loop;
  network_delegate_.set_all_url_requests_destroyed_callback(
      run_loop.QuitClosure());

  GURL url = URLRequestMockDataJob::GetMockHttpsUrl("dummy data", 1);
  network_delegate_.set_expect_url(url);
  network_delegate_.ExpectReport(kDummyReport);
  network_delegate_.ExpectReport(kSecondDummyReport);

  ReportSender reporter(context(), ReportSender::DO_NOT_SEND_COOKIES);

  EXPECT_EQ(0u, network_delegate_.num_requests());

  reporter.Send(url, kDummyReport);
  reporter.Send(url, kSecondDummyReport);

  run_loop.Run();

  EXPECT_EQ(2u, network_delegate_.num_requests());
}

// Test that pending URLRequests get cleaned up when the report sender
// is deleted.
TEST_F(ReportSenderTest, PendingRequestGetsDeleted) {
  bool url_request_destroyed = false;
  network_delegate_.set_url_request_destroyed_callback(base::Bind(
      &MarkURLRequestDestroyed, base::Unretained(&url_request_destroyed)));

  GURL url = URLRequestFailedJob::GetMockHttpUrlWithFailurePhase(
      URLRequestFailedJob::START, ERR_IO_PENDING);
  network_delegate_.set_expect_url(url);
  network_delegate_.ExpectReport(kDummyReport);

  EXPECT_EQ(0u, network_delegate_.num_requests());

  std::unique_ptr<ReportSender> reporter(
      new ReportSender(context(), ReportSender::DO_NOT_SEND_COOKIES));
  reporter->Send(url, kDummyReport);
  reporter.reset();

  EXPECT_EQ(1u, network_delegate_.num_requests());
  EXPECT_TRUE(url_request_destroyed);
}

// Test that a request that returns an error gets cleaned up.
TEST_F(ReportSenderTest, ErroredRequestGetsDeleted) {
  GURL url = URLRequestFailedJob::GetMockHttpsUrl(ERR_FAILED);
  ReportSender reporter(context(), ReportSender::DO_NOT_SEND_COOKIES);
  // SendReport will block until the URLRequest is destroyed.
  SendReport(&reporter, kDummyReport, url, 0);
}

// Test that the error callback, if provided, gets called when a request
// returns an error.
TEST_F(ReportSenderTest, ErroredRequestCallsCallback) {
  bool error_callback_called = false;
  GURL url = URLRequestFailedJob::GetMockHttpsUrl(ERR_FAILED);
  ReportSender reporter(context(), ReportSender::DO_NOT_SEND_COOKIES,
                        base::Bind(ErrorCallback, &error_callback_called));
  // SendReport will block until the URLRequest is destroyed.
  SendReport(&reporter, kDummyReport, url, 0);
  EXPECT_TRUE(error_callback_called);
}

// Test that the error callback does not get called when a request
// does not return an error.
TEST_F(ReportSenderTest, SuccessfulRequestDoesNotCallErrorCallback) {
  bool error_callback_called = false;
  GURL url = URLRequestMockDataJob::GetMockHttpsUrl("dummy data", 1);
  ReportSender reporter(context(), ReportSender::DO_NOT_SEND_COOKIES,
                        base::Bind(ErrorCallback, &error_callback_called));
  SendReport(&reporter, kDummyReport, url, 0);
  EXPECT_FALSE(error_callback_called);
}

// Test that cookies are sent or not sent according to the error
// reporter's cookies preference.

TEST_F(ReportSenderTest, SendCookiesPreference) {
  GURL url = URLRequestMockDataJob::GetMockHttpsUrl("dummy data", 1);
  ReportSender reporter(context(), ReportSender::SEND_COOKIES);

  network_delegate_.set_expect_cookies(true);
  SendReport(&reporter, kDummyReport, url, 0);
}

TEST_F(ReportSenderTest, DoNotSendCookiesPreference) {
  GURL url = URLRequestMockDataJob::GetMockHttpsUrl("dummy data", 1);
  ReportSender reporter(context(), ReportSender::DO_NOT_SEND_COOKIES);

  network_delegate_.set_expect_cookies(false);
  SendReport(&reporter, kDummyReport, url, 0);
}

}  // namespace
}  // namespace net
