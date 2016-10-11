// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/sdch/sdch_owner.h"

#include <utility>

#include "base/location.h"
#include "base/macros.h"
#include "base/memory/memory_pressure_listener.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/stringprintf.h"
#include "base/test/histogram_tester.h"
#include "base/test/simple_test_clock.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/values.h"
#include "net/base/sdch_manager.h"
#include "net/log/net_log_with_source.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_error_job.h"
#include "net/url_request/url_request_job.h"
#include "net/url_request/url_request_job_factory.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

bool GetDictionaryForURL(SdchOwner::PrefStorage* store,
                         const GURL& url,
                         std::string* hash,
                         base::DictionaryValue** dict) {
  base::DictionaryValue* sdch_dict = nullptr;
  if (!store->GetMutableValue(&sdch_dict))
    return false;

  base::DictionaryValue* dicts_dict = nullptr;
  if (!sdch_dict->GetDictionary("dictionaries", &dicts_dict))
    return false;

  base::DictionaryValue::Iterator it(*dicts_dict);
  while (!it.IsAtEnd()) {
    const base::DictionaryValue* d = nullptr;
    if (!it.value().GetAsDictionary(&d))
      continue;
    std::string dict_url;
    if (d->GetString("url", &dict_url) && dict_url == url.spec()) {
      if (hash)
        *hash = it.key();
      if (dict)
        dicts_dict->GetDictionary(it.key(), dict);
      return true;
    }
    it.Advance();
  }

  return false;
}

// This class supports copying so we can emulate persistent storage.
class TestPrefStorage : public SdchOwner::PrefStorage {
 public:
  explicit TestPrefStorage(bool initialized)
      : initialized_(initialized), initialization_observer_(nullptr) {}
  explicit TestPrefStorage(const TestPrefStorage& other)
      : initialized_(other.initialized_),
        initialization_observer_(nullptr) {  // Don't copy observer.
    storage_.MergeDictionary(&other.storage_);
  }

  ~TestPrefStorage() override {}

  void SetInitialized() {
    DCHECK(!initialized_);
    initialized_ = true;
    if (initialization_observer_)
      initialization_observer_->OnPrefStorageInitializationComplete(true);
  }

  ReadError GetReadError() const override { return PERSISTENCE_FAILURE_NONE; }

  bool GetValue(const base::DictionaryValue** result) const override {
    *result = &storage_;
    return true;
  }
  bool GetMutableValue(base::DictionaryValue** result) override {
    *result = &storage_;
    return true;
  }
  void SetValue(std::unique_ptr<base::DictionaryValue> value) override {
    storage_.Clear();
    storage_.MergeDictionary(value.get());
  }

  void ReportValueChanged() override {}

  // This storage class requires no special initialization.
  bool IsInitializationComplete() override { return initialized_; }
  void StartObservingInit(SdchOwner* observer) override {
    DCHECK(!initialization_observer_);
    initialization_observer_ = observer;
  }
  void StopObservingInit() override { initialization_observer_ = nullptr; }

 private:
  bool initialized_;
  SdchOwner* initialization_observer_;

  base::DictionaryValue storage_;
};

}  // namespace

static const char generic_url[] = "http://www.example.com";
static const char generic_domain[] = "www.example.com";

static std::string NewSdchDictionary(size_t dictionary_size) {
  std::string dictionary;
  dictionary.append("Domain: ");
  dictionary.append(generic_domain);
  dictionary.append("\n");
  dictionary.append("\n");

  size_t original_dictionary_size = dictionary.size();
  dictionary.resize(dictionary_size);
  for (size_t i = original_dictionary_size; i < dictionary_size; ++i)
    dictionary[i] = static_cast<char>((i % 127) + 1);

  return dictionary;
}

int outstanding_url_request_error_counting_jobs = 0;
base::Closure* empty_url_request_jobs_callback = 0;

// Variation of URLRequestErrorJob to count number of outstanding
// instances and notify when that goes to zero.
class URLRequestErrorCountingJob : public URLRequestJob {
 public:
  URLRequestErrorCountingJob(URLRequest* request,
                             NetworkDelegate* network_delegate,
                             int error)
      : URLRequestJob(request, network_delegate),
        error_(error),
        weak_factory_(this) {
    ++outstanding_url_request_error_counting_jobs;
  }

  void Start() override {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&URLRequestErrorCountingJob::StartAsync,
                              weak_factory_.GetWeakPtr()));
  }

 private:
  ~URLRequestErrorCountingJob() override {
    --outstanding_url_request_error_counting_jobs;
    if (0 == outstanding_url_request_error_counting_jobs &&
        empty_url_request_jobs_callback) {
      empty_url_request_jobs_callback->Run();
    }
  }

  void StartAsync() {
    NotifyStartError(URLRequestStatus(URLRequestStatus::FAILED, error_));
  }

  int error_;

  base::WeakPtrFactory<URLRequestErrorCountingJob> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(URLRequestErrorCountingJob);
};

static int error_jobs_created = 0;

class MockURLRequestJobFactory : public URLRequestJobFactory {
 public:
  MockURLRequestJobFactory() {}

  ~MockURLRequestJobFactory() override {}

  URLRequestJob* MaybeCreateJobWithProtocolHandler(
      const std::string& scheme,
      URLRequest* request,
      NetworkDelegate* network_delegate) const override {
    ++error_jobs_created;
    return new URLRequestErrorCountingJob(request, network_delegate,
                                          ERR_INTERNET_DISCONNECTED);
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
    return scheme == "http";
  };

  bool IsHandledURL(const GURL& url) const override {
    return url.SchemeIs("http");
  }

  bool IsSafeRedirectTarget(const GURL& location) const override {
    return false;
  }
};

class MockSdchDictionaryFetcher : public SdchDictionaryFetcher {
 public:
  MockSdchDictionaryFetcher() : SdchDictionaryFetcher(&test_context_) {}
  ~MockSdchDictionaryFetcher() {}

  struct PendingRequest {
    PendingRequest(const GURL& url,
                   const OnDictionaryFetchedCallback& callback)
        : url_(url), callback_(callback) {}
    GURL url_;
    OnDictionaryFetchedCallback callback_;
  };

  virtual bool Schedule(const GURL& dictionary_url,
                        const OnDictionaryFetchedCallback& callback) {
    if (!HasPendingRequest(dictionary_url)) {
      requests_.push_back(PendingRequest(dictionary_url, callback));
      return true;
    }
    return false;
  }

  virtual bool ScheduleReload(const GURL& dictionary_url,
                              const OnDictionaryFetchedCallback& callback) {
    if (!HasPendingRequest(dictionary_url)) {
      requests_.push_back(PendingRequest(dictionary_url, callback));
      return true;
    }
    return false;
  }

  virtual void Cancel() {
    requests_.clear();
  }

  bool HasPendingRequest(const GURL& dictionary_url) {
    for (std::vector<PendingRequest>::iterator it = requests_.begin();
         it != requests_.end(); ++it) {
      if (it->url_ == dictionary_url)
        return true;
    }
    return false;
  }

  bool CompletePendingRequest(const GURL& dictionary_url,
                              const std::string& dictionary_text,
                              const NetLogWithSource& net_log,
                              bool was_from_cache) {
    for (std::vector<PendingRequest>::iterator it = requests_.begin();
         it != requests_.end(); ++it) {
      if (it->url_ == dictionary_url) {
        it->callback_.Run(dictionary_text, dictionary_url, net_log,
                          was_from_cache);
        requests_.erase(it);
        return true;
      }
    }
    return false;
  }

 private:
  TestURLRequestContext test_context_;
  std::vector<PendingRequest> requests_;
  DISALLOW_COPY_AND_ASSIGN(MockSdchDictionaryFetcher);
};

// File testing infrastructure summary:
// * NewSdchDictionary(): Creates a dictionary of a specific size.
// * URLRequestErrorCountingJob: A URLRequestJob that returns an error
//   and counts the number of outstanding (started but not finished)
//   jobs, and calls a global callback when that number transitions to zero.
// * MockURLRequestJobFactory: Factory to create the above jobs.  Tracks
//   the number of jobs created.
// * SdchOwnerTest: Interfaces
//      * Access manager, owner, and net log
//      * Return the number of jobs created in a time interval
//      * Return dictionary present in the manager
//      * Notify SdchOwner of an incoming dictionary (& wait until jobs clear)
//      * Attempt to add a dictionary and test for success.
// Test patterns:
//      * Let the owner know about a Get-Dictionary header and test for
//        appropriate jobs being created.
//      * Let the owner know that a dictionary was successfully fetched
//        and test for appropriate outcome.
//      * Either of the above, having previously added dictionaries to create
//        a particular initial state.
class SdchOwnerTest : public testing::Test {
 public:
  static const size_t kMaxSizeForTesting = 1000 * 50;
  static const size_t kMinFetchSpaceForTesting = 500;

  SdchOwnerTest()
      : last_jobs_created_(error_jobs_created),
        dictionary_creation_index_(0),
        sdch_owner_(new SdchOwner(&sdch_manager_, &url_request_context_)) {
    // Any jobs created on this context will immediately error,
    // which leaves the test in control of signals to SdchOwner.
    url_request_context_.set_job_factory(&job_factory_);

    // Reduce sizes to reduce time for string operations.
    sdch_owner_->SetMaxTotalDictionarySize(kMaxSizeForTesting);
    sdch_owner_->SetMinSpaceForDictionaryFetch(kMinFetchSpaceForTesting);
  }

  SdchManager& sdch_manager() { return sdch_manager_; }
  SdchOwner& sdch_owner() { return *(sdch_owner_.get()); }
  NetLogWithSource& net_log() { return net_log_; }

  int JobsRecentlyCreated() {
    int result = error_jobs_created - last_jobs_created_;
    last_jobs_created_ = error_jobs_created;
    return result;
  }

  bool DictionaryPresentInManager(const std::string& server_hash) {
    // Presumes all tests use generic url.
    SdchProblemCode tmp;
    std::unique_ptr<SdchManager::DictionarySet> set(
        sdch_manager_.GetDictionarySetByHash(GURL(generic_url), server_hash,
                                             &tmp));
    return !!set.get();
  }

  void WaitForNoJobs() {
    if (outstanding_url_request_error_counting_jobs == 0)
      return;

    base::RunLoop run_loop;
    base::Closure quit_closure(run_loop.QuitClosure());
    empty_url_request_jobs_callback = &quit_closure;
    run_loop.Run();
    empty_url_request_jobs_callback = NULL;
  }

  void SignalGetDictionaryAndClearJobs(GURL request_url, GURL dictionary_url) {
    sdch_owner().OnGetDictionary(request_url, dictionary_url);
    WaitForNoJobs();
  }

  // Create a unique (by hash) dictionary of the given size,
  // associate it with a unique URL, add it to the manager through
  // SdchOwner::OnDictionaryFetched(), and return whether that
  // addition was successful or not.
  bool CreateAndAddDictionary(size_t size,
                              base::Time last_used_time,
                              base::Time created_time,
                              std::string* server_hash_p) {
    GURL dictionary_url(
        base::StringPrintf("%s/d%d", generic_url, dictionary_creation_index_));
    std::string dictionary_text(NewSdchDictionary(size - 4));
    dictionary_text += base::StringPrintf("%04d", dictionary_creation_index_);
    ++dictionary_creation_index_;
    std::string client_hash;
    std::string server_hash;
    SdchManager::GenerateHash(dictionary_text, &client_hash, &server_hash);

    if (DictionaryPresentInManager(server_hash))
      return false;
    sdch_owner().OnDictionaryFetched(last_used_time, created_time, 0,
                                     dictionary_text, dictionary_url, net_log_,
                                     false);
    if (server_hash_p)
      *server_hash_p = server_hash;
    return DictionaryPresentInManager(server_hash);
  }

  bool CreateAndAddDictionary(size_t size,
                              base::Time last_used_time,
                              std::string* server_hash_p) {
    return CreateAndAddDictionary(size, last_used_time, base::Time(),
                                  server_hash_p);
  }

  void ResetOwner() {
    sdch_owner_.reset(new SdchOwner(&sdch_manager_, &url_request_context_));
  }

 private:
  int last_jobs_created_;
  NetLogWithSource net_log_;
  int dictionary_creation_index_;

  // The dependencies of these objects (sdch_owner_ -> {sdch_manager_,
  // url_request_context_}, url_request_context_->job_factory_) require
  // this order for correct destruction semantics.
  MockURLRequestJobFactory job_factory_;
  URLRequestContext url_request_context_;
  SdchManager sdch_manager_;
  std::unique_ptr<SdchOwner> sdch_owner_;

  DISALLOW_COPY_AND_ASSIGN(SdchOwnerTest);
};

// Does OnGetDictionary result in a fetch when there's enough space, and not
// when there's not?
TEST_F(SdchOwnerTest, OnGetDictionary_Fetching) {
  GURL request_url(std::string(generic_url) + "/r1");

  // Fetch generated when empty.
  GURL dict_url1(std::string(generic_url) + "/d1");
  EXPECT_EQ(0, JobsRecentlyCreated());
  SignalGetDictionaryAndClearJobs(request_url, dict_url1);
  EXPECT_EQ(1, JobsRecentlyCreated());

  // Fetch generated when half full.
  GURL dict_url2(std::string(generic_url) + "/d2");
  std::string dictionary1(NewSdchDictionary(kMaxSizeForTesting / 2));
  sdch_owner().OnDictionaryFetched(base::Time::Now(), base::Time::Now(), 1,
                                   dictionary1, dict_url1, net_log(), false);
  EXPECT_EQ(0, JobsRecentlyCreated());
  SignalGetDictionaryAndClearJobs(request_url, dict_url2);
  EXPECT_EQ(1, JobsRecentlyCreated());

  // Fetch not generated when close to completely full.
  GURL dict_url3(std::string(generic_url) + "/d3");
  std::string dictionary2(NewSdchDictionary(
      (kMaxSizeForTesting / 2 - kMinFetchSpaceForTesting / 2)));
  sdch_owner().OnDictionaryFetched(base::Time::Now(), base::Time::Now(), 1,
                                   dictionary2, dict_url2, net_log(), false);
  EXPECT_EQ(0, JobsRecentlyCreated());
  SignalGetDictionaryAndClearJobs(request_url, dict_url3);
  EXPECT_EQ(0, JobsRecentlyCreated());
}

// Make sure attempts to add dictionaries do what they should.
TEST_F(SdchOwnerTest, OnDictionaryFetched_Fetching) {
  GURL request_url(std::string(generic_url) + "/r1");
  std::string client_hash;
  std::string server_hash;

  // In the past, but still fresh for an unused dictionary.
  base::Time dictionary_last_used_time(base::Time::Now() -
                                       base::TimeDelta::FromMinutes(30));

  // Add successful when empty.
  EXPECT_TRUE(CreateAndAddDictionary(kMaxSizeForTesting / 2,
                                     dictionary_last_used_time, nullptr));
  EXPECT_EQ(0, JobsRecentlyCreated());

  // Add successful when half full.
  EXPECT_TRUE(CreateAndAddDictionary(kMaxSizeForTesting / 2,
                                     dictionary_last_used_time, nullptr));
  EXPECT_EQ(0, JobsRecentlyCreated());

  // Add unsuccessful when full.
  EXPECT_FALSE(CreateAndAddDictionary(kMaxSizeForTesting / 2,
                                      dictionary_last_used_time, nullptr));
  EXPECT_EQ(0, JobsRecentlyCreated());
}

// Confirm auto-eviction happens if space is needed.
TEST_F(SdchOwnerTest, ConfirmAutoEviction) {
  base::Time start_time = base::Time::Now();
  std::string server_hash_d1;
  std::string server_hash_d2;
  std::string server_hash_d3;

  base::SimpleTestClock* test_clock = new base::SimpleTestClock();
  sdch_owner().SetClockForTesting(base::WrapUnique(test_clock));
  test_clock->SetNow(base::Time::Now());

  // Add two dictionaries, one recent, one more than a day in the past.
  base::Time fresh(base::Time::Now() - base::TimeDelta::FromHours(23));
  base::Time stale(base::Time::Now() - base::TimeDelta::FromHours(25));

  EXPECT_TRUE(
      CreateAndAddDictionary(kMaxSizeForTesting / 2, fresh, &server_hash_d1));
  EXPECT_TRUE(
      CreateAndAddDictionary(kMaxSizeForTesting / 2, stale, &server_hash_d2));

  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d1));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d2));

  base::HistogramTester tester;
  const base::TimeDelta synthetic_delta = base::TimeDelta::FromSeconds(5);

  test_clock->Advance(synthetic_delta);

  EXPECT_TRUE(
      CreateAndAddDictionary(kMaxSizeForTesting / 2, fresh, &server_hash_d3));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d1));
  EXPECT_FALSE(DictionaryPresentInManager(server_hash_d2));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d3));

  base::TimeDelta expected_proc_lifetime = synthetic_delta * 3 +
    base::Time::Now() -  start_time;
  size_t expected_value_base = ((kMaxSizeForTesting / 2) *
                                synthetic_delta.InMilliseconds()) /
                                expected_proc_lifetime.InMilliseconds();

  const char *kHistogram = "Sdch3.TimeWeightedMemoryUse";
  tester.ExpectTotalCount(kHistogram, 0);

  // Dictionary insertions and deletions:
  // T = 0: insert d1 and d2
  // T = 5: insert d3, which evicts d2
  // T = 15: destroy SdchOwner, which evicts d1 and d3
  // Therefore, d2's lifetime is synthetic_delta, d1's is synthetic_delta * 3,
  // and d3's is synthetic_delta * 2. The expected_value_base variable is the
  // base factor for d2's memory consumption, of which d1's and d3's are
  // multiples.
  test_clock->Advance(synthetic_delta * 2);
  ResetOwner();

  tester.ExpectTotalCount(kHistogram, 3);
  tester.ExpectBucketCount(kHistogram, expected_value_base, 1);
  tester.ExpectBucketCount(kHistogram, expected_value_base * 2, 1);
  tester.ExpectBucketCount(kHistogram, expected_value_base * 3, 1);
}

// Confirm auto-eviction happens if space is needed, with a more complicated
// situation
TEST_F(SdchOwnerTest, ConfirmAutoEviction_2) {
  std::string server_hash_d1;
  std::string server_hash_d2;
  std::string server_hash_d3;

  // Add dictionaries, one recent, two more than a day in the past that
  // between them add up to the space needed.
  base::Time fresh(base::Time::Now() - base::TimeDelta::FromHours(23));
  base::Time stale(base::Time::Now() - base::TimeDelta::FromHours(25));
  EXPECT_TRUE(
      CreateAndAddDictionary(kMaxSizeForTesting / 2, fresh, &server_hash_d1));

  EXPECT_TRUE(
      CreateAndAddDictionary(kMaxSizeForTesting / 4, stale, &server_hash_d2));
  EXPECT_TRUE(
      CreateAndAddDictionary(kMaxSizeForTesting / 4, stale, &server_hash_d3));

  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d1));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d2));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d3));

  std::string server_hash_d4;
  EXPECT_TRUE(
      CreateAndAddDictionary(kMaxSizeForTesting / 2, fresh, &server_hash_d4));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d1));
  EXPECT_FALSE(DictionaryPresentInManager(server_hash_d2));
  EXPECT_FALSE(DictionaryPresentInManager(server_hash_d3));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d4));
}

// Confirm if only one dictionary needs to be evicted it's the oldest.
TEST_F(SdchOwnerTest, ConfirmAutoEviction_Oldest) {
  std::string server_hash_d1;
  std::string server_hash_d2;
  std::string server_hash_d3;

  // Add dictionaries, one recent, one two days in the past, and one
  // four days in the past.
  base::Time fresh(base::Time::Now() - base::TimeDelta::FromHours(23));
  base::Time stale_newer(base::Time::Now() - base::TimeDelta::FromHours(47));
  base::Time stale_older(base::Time::Now() - base::TimeDelta::FromHours(71));

  EXPECT_TRUE(
      CreateAndAddDictionary(kMaxSizeForTesting / 4, fresh, &server_hash_d1));

  EXPECT_TRUE(CreateAndAddDictionary(kMaxSizeForTesting / 4, stale_newer,
                                     &server_hash_d2));

  EXPECT_TRUE(CreateAndAddDictionary(kMaxSizeForTesting / 4, stale_older,
                                     &server_hash_d3));

  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d1));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d2));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d3));

  // The addition of a new dictionary should succeed, evicting only the
  // oldest one.

  std::string server_hash_d4;
  EXPECT_TRUE(
      CreateAndAddDictionary(kMaxSizeForTesting / 2, fresh, &server_hash_d4));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d1));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d2));
  EXPECT_FALSE(DictionaryPresentInManager(server_hash_d3));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d4));
}

// Confirm using a dictionary changes eviction behavior properly.
TEST_F(SdchOwnerTest, UseChangesEviction) {
  std::string server_hash_d1;
  std::string server_hash_d2;
  std::string server_hash_d3;

  // Add dictionaries, one recent, one two days in the past, and one
  // four days in the past.
  base::Time fresh(base::Time::Now() - base::TimeDelta::FromHours(23));
  base::Time stale_newer(base::Time::Now() - base::TimeDelta::FromHours(47));
  base::Time stale_older(base::Time::Now() - base::TimeDelta::FromHours(71));

  EXPECT_TRUE(
      CreateAndAddDictionary(kMaxSizeForTesting / 4, fresh, &server_hash_d1));

  EXPECT_TRUE(CreateAndAddDictionary(kMaxSizeForTesting / 4, stale_newer,
                                     &server_hash_d2));

  EXPECT_TRUE(CreateAndAddDictionary(kMaxSizeForTesting / 4, stale_older,
                                     &server_hash_d3));

  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d1));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d2));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d3));

  // Use the oldest dictionary.
  sdch_owner().OnDictionaryUsed(server_hash_d3);

  // The addition of a new dictionary should succeed, evicting only the
  // newer stale one.
  std::string server_hash_d4;
  EXPECT_TRUE(
      CreateAndAddDictionary(kMaxSizeForTesting / 2, fresh, &server_hash_d4));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d1));
  EXPECT_FALSE(DictionaryPresentInManager(server_hash_d2));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d3));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d4));
}

// Confirm using a dictionary can prevent the addition of a new dictionary.
TEST_F(SdchOwnerTest, UsePreventsAddition) {
  std::string server_hash_d1;
  std::string server_hash_d2;
  std::string server_hash_d3;

  // Add dictionaries, one recent, one two days in the past, and one
  // four days in the past.
  base::Time fresh(base::Time::Now() - base::TimeDelta::FromMinutes(30));
  base::Time stale_newer(base::Time::Now() - base::TimeDelta::FromHours(47));
  base::Time stale_older(base::Time::Now() - base::TimeDelta::FromHours(71));

  EXPECT_TRUE(
      CreateAndAddDictionary(kMaxSizeForTesting / 4, fresh, &server_hash_d1));

  EXPECT_TRUE(CreateAndAddDictionary(kMaxSizeForTesting / 4, stale_newer,
                                     &server_hash_d2));

  EXPECT_TRUE(CreateAndAddDictionary(kMaxSizeForTesting / 4, stale_older,
                                     &server_hash_d3));

  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d1));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d2));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d3));

  // Use the older dictionaries.
  sdch_owner().OnDictionaryUsed(server_hash_d2);
  sdch_owner().OnDictionaryUsed(server_hash_d3);

  // The addition of a new dictionary should fail, not evicting anything.
  std::string server_hash_d4;
  EXPECT_FALSE(
      CreateAndAddDictionary(kMaxSizeForTesting / 2, fresh, &server_hash_d4));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d1));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d2));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d3));
  EXPECT_FALSE(DictionaryPresentInManager(server_hash_d4));
}

// Confirm clear gets all the space back.
TEST_F(SdchOwnerTest, ClearReturnsSpace) {
  std::string server_hash_d1;
  std::string server_hash_d2;

  // Take up all the space.
  EXPECT_TRUE(CreateAndAddDictionary(kMaxSizeForTesting, base::Time::Now(),
                                     &server_hash_d1));
  // Addition should fail.
  EXPECT_FALSE(CreateAndAddDictionary(kMaxSizeForTesting, base::Time::Now(),
                                      &server_hash_d2));
  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d1));
  EXPECT_FALSE(DictionaryPresentInManager(server_hash_d2));
  sdch_manager().ClearData();
  EXPECT_FALSE(DictionaryPresentInManager(server_hash_d1));
  EXPECT_FALSE(DictionaryPresentInManager(server_hash_d2));

  // Addition should now succeed.
  EXPECT_TRUE(
      CreateAndAddDictionary(kMaxSizeForTesting, base::Time::Now(), nullptr));
}

// Confirm memory pressure gets all the space back.
TEST_F(SdchOwnerTest, MemoryPressureReturnsSpace) {
  std::string server_hash_d1;
  std::string server_hash_d2;

  // Take up all the space.
  EXPECT_TRUE(CreateAndAddDictionary(kMaxSizeForTesting, base::Time::Now(),
                                     &server_hash_d1));

  // Addition should fail.
  EXPECT_FALSE(CreateAndAddDictionary(kMaxSizeForTesting, base::Time::Now(),
                                      &server_hash_d2));

  EXPECT_TRUE(DictionaryPresentInManager(server_hash_d1));
  EXPECT_FALSE(DictionaryPresentInManager(server_hash_d2));

  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_MODERATE);
  // The notification may have (implementation note: does :-}) use a PostTask,
  // so we drain the local message queue.  This should be safe (i.e. not have
  // an inifinite number of messages) in a unit test.
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(DictionaryPresentInManager(server_hash_d1));
  EXPECT_FALSE(DictionaryPresentInManager(server_hash_d2));

  // Addition should now succeed.
  EXPECT_TRUE(
      CreateAndAddDictionary(kMaxSizeForTesting, base::Time::Now(), nullptr));
}

// Confirm that use of a pinned dictionary after its removal works properly.
TEST_F(SdchOwnerTest, PinRemoveUse) {
  // Pass ownership of the storage to the SdchOwner, but keep a pointer.
  TestPrefStorage* pref_store = new TestPrefStorage(true);
  sdch_owner().EnablePersistentStorage(
      std::unique_ptr<SdchOwner::PrefStorage>(pref_store));

  std::string server_hash_d1;
  EXPECT_TRUE(CreateAndAddDictionary(kMaxSizeForTesting / 2, base::Time::Now(),
                                     &server_hash_d1));

  std::unique_ptr<SdchManager::DictionarySet> return_set(
      sdch_manager().GetDictionarySet(
          GURL(std::string(generic_url) + "/x.html")));
  ASSERT_TRUE(return_set.get());
  EXPECT_TRUE(return_set->GetDictionaryText(server_hash_d1));

  const base::Value* result = nullptr;
  const base::DictionaryValue* dict_result = nullptr;
  ASSERT_TRUE(pref_store->GetValue(&dict_result));
  EXPECT_TRUE(dict_result->Get("dictionaries", &result));
  EXPECT_TRUE(dict_result->Get("dictionaries." + server_hash_d1, &result));

  sdch_manager().ClearData();

  ASSERT_TRUE(pref_store->GetValue(&dict_result));
  EXPECT_TRUE(dict_result->Get("dictionaries", &result));
  EXPECT_FALSE(dict_result->Get("dictionaries." + server_hash_d1, &result));

  std::unique_ptr<SdchManager::DictionarySet> return_set2(
      sdch_manager().GetDictionarySet(
          GURL(std::string(generic_url) + "/x.html")));
  EXPECT_FALSE(return_set2.get());

  sdch_manager().OnDictionaryUsed(server_hash_d1);

  ASSERT_TRUE(pref_store->GetValue(&dict_result));
  EXPECT_TRUE(dict_result->Get("dictionaries", &result));
  EXPECT_FALSE(dict_result->Get("dictionaries." + server_hash_d1, &result));
}

TEST_F(SdchOwnerTest, UsageIntervalMetrics) {
  const GURL url("http://www.example.com/dict0");

  std::string server_hash;
  base::Time last_used_time(base::Time::Now() - base::TimeDelta::FromHours(23));
  base::Time created_time(base::Time::Now() - base::TimeDelta::FromHours(47));

  EXPECT_TRUE(CreateAndAddDictionary(kMaxSizeForTesting / 3, last_used_time,
                                     created_time, &server_hash));

  base::HistogramTester tester;

  sdch_owner().OnDictionaryUsed(server_hash);
  tester.ExpectTotalCount("Sdch3.FirstUseInterval", 1);
  tester.ExpectTotalCount("Sdch3.UsageInterval2", 0);

  sdch_owner().OnDictionaryUsed(server_hash);
  tester.ExpectTotalCount("Sdch3.FirstUseInterval", 1);  // count didn't change
  tester.ExpectTotalCount("Sdch3.UsageInterval2", 1);
}

class SdchOwnerPersistenceTest : public ::testing::Test {
 public:
  SdchOwnerPersistenceTest() {}
  virtual ~SdchOwnerPersistenceTest() {}

  void ClearOwner() {
    owner_.reset(NULL);
  }

  // If the storage points is non-null it will be saved as the persistent
  // storage for the SdchOwner.
  void ResetOwner(std::unique_ptr<SdchOwner::PrefStorage> storage) {
    // This has to be done first, since SdchOwner may be observing SdchManager,
    // and SdchManager can't be destroyed with a live observer.
    owner_.reset(NULL);
    manager_.reset(new SdchManager());
    fetcher_ = new MockSdchDictionaryFetcher();
    owner_.reset(new SdchOwner(manager_.get(),
                               &url_request_context_));
    owner_->SetMaxTotalDictionarySize(SdchOwnerTest::kMaxSizeForTesting);
    owner_->SetMinSpaceForDictionaryFetch(
        SdchOwnerTest::kMinFetchSpaceForTesting);
    owner_->SetFetcherForTesting(base::WrapUnique(fetcher_));
    if (storage)
      owner_->EnablePersistentStorage(std::move(storage));
  }

  void InsertDictionaryForURL(const GURL& url, const std::string& nonce) {
    owner_->OnDictionaryFetched(base::Time::Now(), base::Time::Now(), 1,
                                CreateDictionary(url, nonce), url, net_log_,
                                false);
  }

  bool CompleteLoadFromURL(const GURL& url, const std::string& nonce,
                           bool was_from_cache) {
    return fetcher_->CompletePendingRequest(url, CreateDictionary(url, nonce),
                                            net_log_, was_from_cache);
  }

  std::string CreateDictionary(const GURL& url, const std::string& nonce) {
    std::string dict;
    dict.append("Domain: ");
    dict.append(url.host());
    dict.append("\n\n");
    dict.append(url.spec());
    dict.append(nonce);
    return dict;
  }

 protected:
  NetLogWithSource net_log_;
  std::unique_ptr<SdchManager> manager_;
  MockSdchDictionaryFetcher* fetcher_;
  std::unique_ptr<SdchOwner> owner_;
  TestURLRequestContext url_request_context_;
};

// Test an empty persistence store.
TEST_F(SdchOwnerPersistenceTest, Empty) {
  ResetOwner(base::WrapUnique(new TestPrefStorage(true)));
  EXPECT_EQ(0, owner_->GetDictionaryCountForTesting());
}

// Test a persistence store with a bad version number.
TEST_F(SdchOwnerPersistenceTest, Persistent_BadVersion) {
  std::unique_ptr<base::DictionaryValue> sdch_dict(new base::DictionaryValue());
  sdch_dict->SetInteger("version", 2);

  std::unique_ptr<TestPrefStorage> storage(new TestPrefStorage(true));
  storage->SetValue(std::move(sdch_dict));

  TestPrefStorage* old_storage = storage.get();  // Save storage pointer.
  ResetOwner(std::move(storage));  // Takes ownership of storage pointer.

  storage.reset(new TestPrefStorage(*old_storage));
  ResetOwner(std::move(storage));
  EXPECT_EQ(0, owner_->GetDictionaryCountForTesting());
}

// Test a persistence store with an empty dictionaries map.
TEST_F(SdchOwnerPersistenceTest, Persistent_EmptyDictList) {
  std::unique_ptr<base::DictionaryValue> sdch_dict(new base::DictionaryValue());
  std::unique_ptr<base::DictionaryValue> dicts(new base::DictionaryValue());
  sdch_dict->SetInteger("version", 1);
  sdch_dict->Set("dictionaries", std::move(dicts));

  std::unique_ptr<TestPrefStorage> storage(new TestPrefStorage(true));
  storage->SetValue(std::move(sdch_dict));
  ResetOwner(std::move(storage));
  EXPECT_EQ(0, owner_->GetDictionaryCountForTesting());
}

TEST_F(SdchOwnerPersistenceTest, OneDict) {
  const GURL url("http://www.example.com/dict");

  std::unique_ptr<TestPrefStorage> storage(new TestPrefStorage(true));
  TestPrefStorage* old_storage = storage.get();  // Save storage pointer.
  ResetOwner(std::move(storage));  // Takes ownership of storage pointer.
  EXPECT_EQ(0, owner_->GetDictionaryCountForTesting());
  InsertDictionaryForURL(url, "0");
  EXPECT_EQ(1, owner_->GetDictionaryCountForTesting());

  storage.reset(new TestPrefStorage(*old_storage));
  ResetOwner(std::move(storage));
  EXPECT_EQ(0, owner_->GetDictionaryCountForTesting());
  EXPECT_TRUE(CompleteLoadFromURL(url, "0", true));
  EXPECT_EQ(1, owner_->GetDictionaryCountForTesting());
}

TEST_F(SdchOwnerPersistenceTest, TwoDicts) {
  const GURL url0("http://www.example.com/dict0");
  const GURL url1("http://www.example.com/dict1");

  std::unique_ptr<TestPrefStorage> storage(new TestPrefStorage(true));
  TestPrefStorage* old_storage = storage.get();  // Save storage pointer.
  ResetOwner(std::move(storage));  // Takes ownership of storage pointer.
  InsertDictionaryForURL(url0, "0");
  InsertDictionaryForURL(url1, "1");

  storage.reset(new TestPrefStorage(*old_storage));
  ResetOwner(std::move(storage));
  EXPECT_TRUE(CompleteLoadFromURL(url0, "0", true));
  EXPECT_TRUE(CompleteLoadFromURL(url1, "1", true));
  EXPECT_EQ(2, owner_->GetDictionaryCountForTesting());
  EXPECT_TRUE(owner_->HasDictionaryFromURLForTesting(url0));
  EXPECT_TRUE(owner_->HasDictionaryFromURLForTesting(url1));
}

TEST_F(SdchOwnerPersistenceTest, OneGoodDictOneBadDict) {
  const GURL url0("http://www.example.com/dict0");
  const GURL url1("http://www.example.com/dict1");

  std::unique_ptr<TestPrefStorage> storage(new TestPrefStorage(true));
  TestPrefStorage* old_storage = storage.get();  // Save storage pointer.
  ResetOwner(std::move(storage));                // Takes ownership of storage.
  InsertDictionaryForURL(url0, "0");
  InsertDictionaryForURL(url1, "1");

  // Make a new storage based on the current contents of the old one.
  storage.reset(new TestPrefStorage(*old_storage));
  base::DictionaryValue* dict = nullptr;
  ASSERT_TRUE(GetDictionaryForURL(storage.get(), url1, nullptr, &dict));
  dict->Remove("use_count", nullptr);

  ResetOwner(std::move(storage));
  EXPECT_TRUE(CompleteLoadFromURL(url0, "0", true));
  EXPECT_FALSE(CompleteLoadFromURL(url1, "1", true));
  EXPECT_EQ(1, owner_->GetDictionaryCountForTesting());
  EXPECT_TRUE(owner_->HasDictionaryFromURLForTesting(url0));
  EXPECT_FALSE(owner_->HasDictionaryFromURLForTesting(url1));
}

TEST_F(SdchOwnerPersistenceTest, UsingDictionaryUpdatesUseCount) {
  const GURL url("http://www.example.com/dict");

  std::unique_ptr<TestPrefStorage> storage(new TestPrefStorage(true));
  TestPrefStorage* old_storage = storage.get();  // Save storage pointer.
  ResetOwner(std::move(storage));  // Takes ownership of storage pointer.
  InsertDictionaryForURL(url, "0");

  std::string hash;
  int old_count;
  storage.reset(new TestPrefStorage(*old_storage));
  {
    ClearOwner();
    base::DictionaryValue* dict = nullptr;
    ASSERT_TRUE(GetDictionaryForURL(storage.get(), url, &hash, &dict));
    ASSERT_TRUE(dict->GetInteger("use_count", &old_count));
  }

  old_storage = storage.get();     // Save storage pointer.
  ResetOwner(std::move(storage));  // Takes ownership of storage pointer.
  ASSERT_TRUE(CompleteLoadFromURL(url, "0", true));
  owner_->OnDictionaryUsed(hash);

  int new_count;
  {
    base::DictionaryValue* dict = nullptr;
    ASSERT_TRUE(GetDictionaryForURL(old_storage, url, nullptr, &dict));
    ASSERT_TRUE(dict->GetInteger("use_count", &new_count));
  }

  EXPECT_EQ(old_count + 1, new_count);
}

TEST_F(SdchOwnerPersistenceTest, LoadingDictionaryMerges) {
  const GURL url0("http://www.example.com/dict0");
  const GURL url1("http://www.example.com/dict1");

  std::unique_ptr<TestPrefStorage> storage(new TestPrefStorage(true));
  TestPrefStorage* old_storage = storage.get();  // Save storage pointer.
  ResetOwner(std::move(storage));  // Takes ownership of storage pointer.
  InsertDictionaryForURL(url1, "1");

  storage.reset(new TestPrefStorage(*old_storage));
  ResetOwner(std::unique_ptr<SdchOwner::PrefStorage>());
  InsertDictionaryForURL(url0, "0");
  EXPECT_EQ(1, owner_->GetDictionaryCountForTesting());
  owner_->EnablePersistentStorage(std::move(storage));
  ASSERT_TRUE(CompleteLoadFromURL(url1, "1", true));
  EXPECT_EQ(2, owner_->GetDictionaryCountForTesting());
}

TEST_F(SdchOwnerPersistenceTest, PersistenceMetrics) {
  const GURL url0("http://www.example.com/dict0");
  const GURL url1("http://www.example.com/dict1");

  std::unique_ptr<TestPrefStorage> storage(new TestPrefStorage(true));
  TestPrefStorage* old_storage = storage.get();  // Save storage pointer.
  ResetOwner(std::move(storage));  // Takes ownership of storage pointer.

  InsertDictionaryForURL(url0, "0");
  InsertDictionaryForURL(url1, "1");

  storage.reset(new TestPrefStorage(*old_storage));
  ResetOwner(std::move(storage));

  base::HistogramTester tester;

  EXPECT_TRUE(CompleteLoadFromURL(url0, "0", true));
  EXPECT_TRUE(CompleteLoadFromURL(url1, "1", false));

  tester.ExpectTotalCount("Sdch3.NetworkBytesSpent", 1);
  tester.ExpectUniqueSample("Sdch3.NetworkBytesSpent",
                            CreateDictionary(url1, "1").size(), 1);
}

}  // namespace net
