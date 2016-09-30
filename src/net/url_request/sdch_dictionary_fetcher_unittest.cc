// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/sdch_dictionary_fetcher.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/callback.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/sdch_manager.h"
#include "net/http/http_response_headers.h"
#include "net/url_request/url_request_filter.h"
#include "net/url_request/url_request_interceptor.h"
#include "net/url_request/url_request_job.h"
#include "net/url_request/url_request_redirect_job.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

const char kSampleBufferContext[] = "This is a sample buffer.";
const char kTestDomain1[] = "top.domain.test";
const char kTestDomain2[] = "top2.domain.test";

// A URLRequestJob that returns a fixed response body, based on the URL, with
// the specified HttpResponseInfo. Can also be made to return an error after the
// response body has been read.
class URLRequestSpecifiedResponseJob : public URLRequestJob {
 public:
  // Called on destruction with load flags used for this request.
  typedef base::Callback<void(int)> DestructionCallback;

  URLRequestSpecifiedResponseJob(
      URLRequest* request,
      NetworkDelegate* network_delegate,
      const HttpResponseInfo& response_info_to_return,
      const DestructionCallback& destruction_callback)
      : URLRequestJob(request, network_delegate),
        response_info_to_return_(response_info_to_return),
        last_load_flags_seen_(request->load_flags()),
        destruction_callback_(destruction_callback),
        bytes_read_(0),
        final_read_result_(OK),
        weak_factory_(this) {
    DCHECK(!destruction_callback.is_null());
  }

  ~URLRequestSpecifiedResponseJob() override {
    destruction_callback_.Run(last_load_flags_seen_);
  }

  // Sets the result of the final read, after the entire body has been read.
  // Defaults to OK.
  void set_final_read_result(Error final_read_result) {
    final_read_result_ = final_read_result;
  }

  // URLRequestJob implementation:
  void Start() override {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&URLRequestSpecifiedResponseJob::StartAsync,
                              weak_factory_.GetWeakPtr()));
  }

  int ReadRawData(IOBuffer* buf, int buf_size) override {
    std::string response = ExpectedResponseForURL(request_->url());
    response = response.substr(bytes_read_);
    size_t bytes_to_copy =
        std::min(static_cast<size_t>(buf_size), response.size());
    if (bytes_to_copy == 0)
      return final_read_result_;
    memcpy(buf->data(), response.c_str(), bytes_to_copy);
    bytes_read_ += bytes_to_copy;
    return bytes_to_copy;
  }

  static std::string ExpectedResponseForURL(const GURL& url) {
    return base::StringPrintf("Response for %s\n%s\nEnd Response for %s\n",
                              url.spec().c_str(),
                              kSampleBufferContext,
                              url.spec().c_str());
  }

  void GetResponseInfo(HttpResponseInfo* info) override {
    *info = response_info_to_return_;
  }

 private:
  void StartAsync() { NotifyHeadersComplete(); }

  const HttpResponseInfo response_info_to_return_;
  int last_load_flags_seen_;
  const DestructionCallback destruction_callback_;

  int bytes_read_;
  Error final_read_result_;

  base::WeakPtrFactory<URLRequestSpecifiedResponseJob> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(URLRequestSpecifiedResponseJob);
};

// Wrap URLRequestRedirectJob in a destruction callback.
class TestURLRequestRedirectJob : public URLRequestRedirectJob {
 public:
  TestURLRequestRedirectJob(URLRequest* request,
                            NetworkDelegate* network_delegate,
                            const GURL& redirect_destination,
                            ResponseCode response_code,
                            const std::string& redirect_reason,
                            base::Closure destruction_callback)
      : URLRequestRedirectJob(request,
                              network_delegate,
                              redirect_destination,
                              response_code,
                              redirect_reason),
        destruction_callback_(destruction_callback) {}
  ~TestURLRequestRedirectJob() override { destruction_callback_.Run(); }

 private:
  const base::Closure destruction_callback_;
};

const char kRedirectPath[] = "/redirect/";
const char kBodyErrorPath[] = "/body_error/";

class SDCHTestRequestInterceptor : public URLRequestInterceptor {
 public:
  // A callback to be called whenever a URLRequestJob child of this
  // interceptor is created or destroyed.  The first argument will be the
  // change in number of jobs (i.e. +1 for created, -1 for destroyed).
  // The second argument will be undefined if the job is being created
  // or a redirect job is being destroyed, and (for non-redirect job
  // destruction) will contain the load flags passed to the request the
  // job was created for.
  typedef base::Callback<void(int outstanding_job_delta,
                              int destruction_load_flags)> LifecycleCallback;

  // |*info| will be returned from all child URLRequestSpecifiedResponseJobs.
  // Note that: a) this pointer is shared with the caller, and the caller must
  // guarantee that |*info| outlives the SDCHTestRequestInterceptor, and
  // b) |*info| is mutable, and changes to should propagate to
  // URLRequestSpecifiedResponseJobs created after any change.
  SDCHTestRequestInterceptor(HttpResponseInfo* http_response_info,
                             const LifecycleCallback& lifecycle_callback)
      : http_response_info_(http_response_info),
        lifecycle_callback_(lifecycle_callback) {
    DCHECK(!lifecycle_callback_.is_null());
  }
  ~SDCHTestRequestInterceptor() override {}

  URLRequestJob* MaybeInterceptRequest(
      URLRequest* request,
      NetworkDelegate* network_delegate) const override {
    lifecycle_callback_.Run(1, 0);

    std::string path = request->url().path();
    if (base::StartsWith(path, kRedirectPath, base::CompareCase::SENSITIVE)) {
      return new TestURLRequestRedirectJob(
          request, network_delegate, GURL(path.substr(strlen(kRedirectPath))),
          URLRequestRedirectJob::REDIRECT_307_TEMPORARY_REDIRECT, "testing",
          base::Bind(lifecycle_callback_, -1, 0));
    }

    std::unique_ptr<URLRequestSpecifiedResponseJob> job(
        new URLRequestSpecifiedResponseJob(
            request, network_delegate, *http_response_info_,
            base::Bind(lifecycle_callback_, -1)));
    if (base::StartsWith(path, kBodyErrorPath, base::CompareCase::SENSITIVE))
      job->set_final_read_result(net::ERR_FAILED);
    return job.release();
  }

  // The caller must ensure that both |*http_response_info| and the
  // callback remain valid for the lifetime of the
  // SDCHTestRequestInterceptor (i.e. until Unregister() is called).
  static void RegisterWithFilter(HttpResponseInfo* http_response_info,
                                 const LifecycleCallback& lifecycle_callback) {
    URLRequestFilter::GetInstance()->AddHostnameInterceptor(
        "http", kTestDomain1,
        std::unique_ptr<URLRequestInterceptor>(new SDCHTestRequestInterceptor(
            http_response_info, lifecycle_callback)));

    URLRequestFilter::GetInstance()->AddHostnameInterceptor(
        "https", kTestDomain1,
        std::unique_ptr<URLRequestInterceptor>(new SDCHTestRequestInterceptor(
            http_response_info, lifecycle_callback)));

    URLRequestFilter::GetInstance()->AddHostnameInterceptor(
        "http", kTestDomain2,
        std::unique_ptr<URLRequestInterceptor>(new SDCHTestRequestInterceptor(
            http_response_info, lifecycle_callback)));

    URLRequestFilter::GetInstance()->AddHostnameInterceptor(
        "https", kTestDomain2,
        std::unique_ptr<URLRequestInterceptor>(new SDCHTestRequestInterceptor(
            http_response_info, lifecycle_callback)));
  }

  static void Unregister() {
    URLRequestFilter::GetInstance()->RemoveHostnameHandler("http",
                                                           kTestDomain1);
    URLRequestFilter::GetInstance()->RemoveHostnameHandler("https",
                                                           kTestDomain1);
    URLRequestFilter::GetInstance()->RemoveHostnameHandler("http",
                                                           kTestDomain2);
    URLRequestFilter::GetInstance()->RemoveHostnameHandler("https",
                                                           kTestDomain2);
  }

 private:
  HttpResponseInfo* http_response_info_;
  LifecycleCallback lifecycle_callback_;
  DISALLOW_COPY_AND_ASSIGN(SDCHTestRequestInterceptor);
};

// Local test infrastructure
// * URLRequestSpecifiedResponseJob: A URLRequestJob that returns
//   a different but derivable response for each URL (used for all
//   url requests in this file).  This class is initialized with
//   the HttpResponseInfo to return (if any), as well as a callback
//   that is called when the class is destroyed.  That callback
//   takes as arguemnt the load flags used for the request the
//   job was created for.
// * SDCHTestRequestInterceptor: This class is a
//   URLRequestInterceptor that generates either the class above or an
//   instance of URLRequestRedirectJob (if the first component of the path
//   is "redirect").  It is constructed
//   with a pointer to the (mutable) resposne info that should be
//   returned from constructed URLRequestSpecifiedResponseJobs, as well as
//   a callback that is run when URLRequestSpecifiedResponseJobs are
//   created or destroyed.
// * SdchDictionaryFetcherTest: This class registers the above interceptor,
//   tracks the number of jobs requested and the subset of those
//   that are still outstanding.  It exports an interface to wait until there
//   are no jobs outstanding.  It shares an HttpResponseInfo structure
//   with the SDCHTestRequestInterceptor to control the response
//   information returned by the jbos.
// The standard pattern for tests is to schedule a dictionary fetch, wait
// for no jobs outstanding, then test that the fetch results are as expected.

class SdchDictionaryFetcherTest : public ::testing::Test {
 public:
  struct DictionaryAdditions {
    DictionaryAdditions(const std::string& dictionary_text,
                        const GURL& dictionary_url)
        : dictionary_text(dictionary_text), dictionary_url(dictionary_url) {}

    std::string dictionary_text;
    GURL dictionary_url;
  };

  SdchDictionaryFetcherTest()
      : jobs_requested_(0),
        jobs_outstanding_(0),
        last_load_flags_seen_(LOAD_NORMAL),
        context_(new TestURLRequestContext),
        fetcher_(new SdchDictionaryFetcher(context_.get())),
        factory_(this) {
    response_info_to_return_.request_time = base::Time::Now();
    response_info_to_return_.response_time = base::Time::Now();
    SDCHTestRequestInterceptor::RegisterWithFilter(
        &response_info_to_return_,
        base::Bind(&SdchDictionaryFetcherTest::OnNumberJobsChanged,
                   factory_.GetWeakPtr()));
  }

  ~SdchDictionaryFetcherTest() override {
    SDCHTestRequestInterceptor::Unregister();
  }

  void OnDictionaryFetched(const std::string& dictionary_text,
                           const GURL& dictionary_url,
                           const BoundNetLog& net_log,
                           bool was_from_cache) {
    dictionary_additions_.push_back(
        DictionaryAdditions(dictionary_text, dictionary_url));
  }

  // Return (in |*out|) all dictionary additions since the last time
  // this function was called.
  void GetDictionaryAdditions(std::vector<DictionaryAdditions>* out) {
    out->swap(dictionary_additions_);
    dictionary_additions_.clear();
  }

  SdchDictionaryFetcher* fetcher() { return fetcher_.get(); }

  // May not be called outside the SetUp()/TearDown() interval.
  int jobs_requested() const { return jobs_requested_; }

  GURL PathToGurl(const char* path) const {
    std::string gurl_string("http://");
    gurl_string += kTestDomain1;
    gurl_string += "/";
    gurl_string += path;
    return GURL(gurl_string);
  }

  // Block until there are no outstanding URLRequestSpecifiedResponseJobs.
  void WaitForNoJobs() {
    // A job may be started after the previous one was destroyed, with a brief
    // period of 0 jobs in between, so may have to start the run loop multiple
    // times.
    while (jobs_outstanding_ != 0) {
      run_loop_.reset(new base::RunLoop);
      run_loop_->Run();
      run_loop_.reset();
    }
  }

  HttpResponseInfo* response_info_to_return() {
    return &response_info_to_return_;
  }

  int last_load_flags_seen() const { return last_load_flags_seen_; }

  const SdchDictionaryFetcher::OnDictionaryFetchedCallback
      GetDefaultCallback() {
    return base::Bind(&SdchDictionaryFetcherTest::OnDictionaryFetched,
                      base::Unretained(this));
  }

 private:
  void OnNumberJobsChanged(int outstanding_jobs_delta, int load_flags) {
    DCHECK_NE(0, outstanding_jobs_delta);
    if (outstanding_jobs_delta > 0)
      jobs_requested_ += outstanding_jobs_delta;
    else
      last_load_flags_seen_ = load_flags;
    jobs_outstanding_ += outstanding_jobs_delta;
    if (jobs_outstanding_ == 0 && run_loop_)
      run_loop_->Quit();
  }

  int jobs_requested_;
  int jobs_outstanding_;

  // Last load flags seen by the interceptor installed in
  // SdchDictionaryFetcherTest(). These are available to test bodies and
  // currently used for ensuring that certain loads are marked only-from-cache.
  int last_load_flags_seen_;

  std::unique_ptr<base::RunLoop> run_loop_;
  std::unique_ptr<TestURLRequestContext> context_;
  std::unique_ptr<SdchDictionaryFetcher> fetcher_;
  std::vector<DictionaryAdditions> dictionary_additions_;

  // The request_time and response_time fields are filled in by the constructor
  // for SdchDictionaryFetcherTest. Tests can fill the other fields of this
  // member in to alter the HttpResponseInfo returned by the fetcher's
  // URLRequestJob.
  HttpResponseInfo response_info_to_return_;

  base::WeakPtrFactory<SdchDictionaryFetcherTest> factory_;

  DISALLOW_COPY_AND_ASSIGN(SdchDictionaryFetcherTest);
};

// Schedule a fetch and make sure it happens.
TEST_F(SdchDictionaryFetcherTest, Basic) {
  GURL dictionary_url(PathToGurl("dictionary"));
  fetcher()->Schedule(dictionary_url, GetDefaultCallback());
  WaitForNoJobs();

  EXPECT_EQ(1, jobs_requested());
  std::vector<DictionaryAdditions> additions;
  GetDictionaryAdditions(&additions);
  ASSERT_EQ(1u, additions.size());
  EXPECT_EQ(
      URLRequestSpecifiedResponseJob::ExpectedResponseForURL(dictionary_url),
      additions[0].dictionary_text);
  EXPECT_FALSE(last_load_flags_seen() & LOAD_ONLY_FROM_CACHE);
}

// Multiple fetches of the same URL should result in only one request.
TEST_F(SdchDictionaryFetcherTest, Multiple) {
  GURL dictionary_url(PathToGurl("dictionary"));
  EXPECT_TRUE(fetcher()->Schedule(dictionary_url, GetDefaultCallback()));
  EXPECT_FALSE(fetcher()->Schedule(dictionary_url, GetDefaultCallback()));
  EXPECT_FALSE(fetcher()->Schedule(dictionary_url, GetDefaultCallback()));
  WaitForNoJobs();

  EXPECT_EQ(1, jobs_requested());
  std::vector<DictionaryAdditions> additions;
  GetDictionaryAdditions(&additions);
  ASSERT_EQ(1u, additions.size());
  EXPECT_EQ(
      URLRequestSpecifiedResponseJob::ExpectedResponseForURL(dictionary_url),
      additions[0].dictionary_text);
}

// A cancel should result in no actual requests being generated.
TEST_F(SdchDictionaryFetcherTest, Cancel) {
  GURL dictionary_url_1(PathToGurl("dictionary_1"));
  GURL dictionary_url_2(PathToGurl("dictionary_2"));
  GURL dictionary_url_3(PathToGurl("dictionary_3"));

  fetcher()->Schedule(dictionary_url_1, GetDefaultCallback());
  fetcher()->Schedule(dictionary_url_2, GetDefaultCallback());
  fetcher()->Schedule(dictionary_url_3, GetDefaultCallback());
  fetcher()->Cancel();
  WaitForNoJobs();

  // Synchronous execution may have resulted in a single job being scheduled.
  EXPECT_GE(1, jobs_requested());
}

// Attempt to confuse the fetcher loop processing by scheduling a
// dictionary addition while another fetch is in process.
TEST_F(SdchDictionaryFetcherTest, LoopRace) {
  GURL dictionary0_url(PathToGurl("dictionary0"));
  GURL dictionary1_url(PathToGurl("dictionary1"));
  fetcher()->Schedule(dictionary0_url, GetDefaultCallback());
  fetcher()->Schedule(dictionary1_url, GetDefaultCallback());
  WaitForNoJobs();

  ASSERT_EQ(2, jobs_requested());
  std::vector<DictionaryAdditions> additions;
  GetDictionaryAdditions(&additions);
  ASSERT_EQ(2u, additions.size());
  EXPECT_EQ(
      URLRequestSpecifiedResponseJob::ExpectedResponseForURL(dictionary0_url),
      additions[0].dictionary_text);
  EXPECT_EQ(
      URLRequestSpecifiedResponseJob::ExpectedResponseForURL(dictionary1_url),
      additions[1].dictionary_text);
}

TEST_F(SdchDictionaryFetcherTest, ScheduleReloadLoadFlags) {
  GURL dictionary_url(PathToGurl("dictionary"));
  fetcher()->ScheduleReload(dictionary_url, GetDefaultCallback());

  WaitForNoJobs();
  EXPECT_EQ(1, jobs_requested());
  std::vector<DictionaryAdditions> additions;
  GetDictionaryAdditions(&additions);
  ASSERT_EQ(1u, additions.size());
  EXPECT_EQ(
      URLRequestSpecifiedResponseJob::ExpectedResponseForURL(dictionary_url),
      additions[0].dictionary_text);
  EXPECT_TRUE(last_load_flags_seen() & LOAD_ONLY_FROM_CACHE);
}

TEST_F(SdchDictionaryFetcherTest, ScheduleReloadFresh) {
  std::string raw_headers = "\0";
  response_info_to_return()->headers = new HttpResponseHeaders(
      HttpUtil::AssembleRawHeaders(raw_headers.data(), raw_headers.size()));
  response_info_to_return()->headers->AddHeader("Cache-Control: max-age=1000");

  GURL dictionary_url(PathToGurl("dictionary"));
  fetcher()->ScheduleReload(dictionary_url, GetDefaultCallback());

  WaitForNoJobs();
  EXPECT_EQ(1, jobs_requested());
  std::vector<DictionaryAdditions> additions;
  GetDictionaryAdditions(&additions);
  ASSERT_EQ(1u, additions.size());
  EXPECT_EQ(
      URLRequestSpecifiedResponseJob::ExpectedResponseForURL(dictionary_url),
      additions[0].dictionary_text);
  EXPECT_TRUE(last_load_flags_seen() & LOAD_ONLY_FROM_CACHE);
}

TEST_F(SdchDictionaryFetcherTest, ScheduleReloadStale) {
  response_info_to_return()->headers = new HttpResponseHeaders("");
  response_info_to_return()->headers->AddHeader("Cache-Control: no-cache");

  GURL dictionary_url(PathToGurl("dictionary"));
  fetcher()->ScheduleReload(dictionary_url, GetDefaultCallback());

  WaitForNoJobs();
  EXPECT_EQ(1, jobs_requested());
  std::vector<DictionaryAdditions> additions;
  GetDictionaryAdditions(&additions);
  EXPECT_EQ(0u, additions.size());
  EXPECT_TRUE(last_load_flags_seen() & LOAD_ONLY_FROM_CACHE);
}

TEST_F(SdchDictionaryFetcherTest, ScheduleReloadThenLoad) {
  GURL dictionary_url(PathToGurl("dictionary"));
  EXPECT_TRUE(fetcher()->ScheduleReload(dictionary_url, GetDefaultCallback()));
  EXPECT_TRUE(fetcher()->Schedule(dictionary_url, GetDefaultCallback()));

  WaitForNoJobs();
  EXPECT_EQ(2, jobs_requested());
}

TEST_F(SdchDictionaryFetcherTest, ScheduleLoadThenReload) {
  GURL dictionary_url(PathToGurl("dictionary"));
  EXPECT_TRUE(fetcher()->Schedule(dictionary_url, GetDefaultCallback()));
  EXPECT_FALSE(fetcher()->ScheduleReload(dictionary_url, GetDefaultCallback()));

  WaitForNoJobs();
  EXPECT_EQ(1, jobs_requested());
}

TEST_F(SdchDictionaryFetcherTest, CancelAllowsFutureFetches) {
  GURL dictionary_url(PathToGurl("dictionary"));
  EXPECT_TRUE(fetcher()->Schedule(dictionary_url, GetDefaultCallback()));
  EXPECT_FALSE(fetcher()->Schedule(dictionary_url, GetDefaultCallback()));

  WaitForNoJobs();
  EXPECT_EQ(1, jobs_requested());

  fetcher()->Cancel();
  WaitForNoJobs();
  EXPECT_TRUE(fetcher()->Schedule(dictionary_url, GetDefaultCallback()));

  WaitForNoJobs();
  EXPECT_EQ(2, jobs_requested());
}

TEST_F(SdchDictionaryFetcherTest, Redirect) {
  GURL dictionary_url(PathToGurl("dictionary"));
  GURL local_redirect_url(dictionary_url.GetWithEmptyPath().spec() +
                          "redirect/" + dictionary_url.spec());
  EXPECT_TRUE(fetcher()->Schedule(local_redirect_url, GetDefaultCallback()));
  WaitForNoJobs();

  // The redirect should have been rejected with no dictionary added.
  EXPECT_EQ(1, jobs_requested());
  std::vector<DictionaryAdditions> additions;
  GetDictionaryAdditions(&additions);
  EXPECT_EQ(0u, additions.size());

  // Simple SDCH dictionary fetch test, to make sure the fetcher was left
  // in reasonable shape by the above.

  GURL dictionary2_url(PathToGurl("dictionary2"));
  fetcher()->Schedule(dictionary2_url, GetDefaultCallback());
  WaitForNoJobs();

  EXPECT_EQ(2, jobs_requested());
  GetDictionaryAdditions(&additions);
  ASSERT_EQ(1u, additions.size());
  EXPECT_EQ(
      URLRequestSpecifiedResponseJob::ExpectedResponseForURL(dictionary2_url),
      additions[0].dictionary_text);
  EXPECT_FALSE(last_load_flags_seen() & LOAD_ONLY_FROM_CACHE);
}

// Check the case of two requests for different URLs, where the first request
// fails after receiving body data.
TEST_F(SdchDictionaryFetcherTest, TwoDictionariesFirstFails) {
  GURL dictionary_with_error_url(PathToGurl("body_error/"));
  GURL dictionary_url(PathToGurl("dictionary"));
  EXPECT_TRUE(
      fetcher()->Schedule(dictionary_with_error_url, GetDefaultCallback()));
  EXPECT_TRUE(fetcher()->Schedule(dictionary_url, GetDefaultCallback()));
  WaitForNoJobs();

  EXPECT_EQ(2, jobs_requested());
  std::vector<DictionaryAdditions> additions;
  GetDictionaryAdditions(&additions);
  // Should only have a dictionary for the successful request.
  ASSERT_EQ(1u, additions.size());
  EXPECT_EQ(
      URLRequestSpecifiedResponseJob::ExpectedResponseForURL(dictionary_url),
      additions[0].dictionary_text);
}

}  // namespace

}  // namespace net
