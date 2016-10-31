// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/filter/sdch_policy_delegate.h"

#include <string>

#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "net/base/sdch_manager.h"
#include "net/base/sdch_observer.h"
#include "net/url_request/url_request_http_job.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// Provide sample data and compression results with a sample VCDIFF dictionary.
// Note an SDCH dictionary has extra meta-data before the VCDIFF dictionary.
static const char kTestVcdiffDictionary[] =
    "DictionaryFor"
    "SdchCompression1SdchCompression2SdchCompression3SdchCompression\n";

const char kRefreshHtml[] =
    "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"0\"></head>";

const char kTextHtmlMime[] = "text/html";

class SimpleSdchObserver : public SdchObserver {
 public:
  explicit SimpleSdchObserver(SdchManager* manager)
      : dictionary_used_(0), manager_(manager) {
    manager_->AddObserver(this);
  }
  ~SimpleSdchObserver() override { manager_->RemoveObserver(this); }

  // SdchObserver
  void OnDictionaryUsed(const std::string& server_hash) override {
    dictionary_used_++;
    last_server_hash_ = server_hash;
  }

  int dictionary_used_calls() const { return dictionary_used_; }
  std::string last_server_hash() const { return last_server_hash_; }

  void OnDictionaryAdded(const GURL& /* dictionary_url */,
                         const std::string& /* server_hash */) override {}
  void OnDictionaryRemoved(const std::string& /* server_hash */) override {}
  void OnGetDictionary(const GURL& /* request_url */,
                       const GURL& /* dictionary_url */) override {}
  void OnClearDictionaries() override {}

 private:
  int dictionary_used_;
  std::string last_server_hash_;
  SdchManager* manager_;

  DISALLOW_COPY_AND_ASSIGN(SimpleSdchObserver);
};

std::string NewSdchDictionary(const std::string& domain) {
  std::string dictionary;
  if (!domain.empty()) {
    dictionary.append("Domain: ");
    dictionary.append(domain);
    dictionary.append("\n");
  }
  dictionary.append("\n");
  dictionary.append(kTestVcdiffDictionary, sizeof(kTestVcdiffDictionary) - 1);
  return dictionary;
}

// Inherit from URLRequestHttpJob to expose the hidden constructor.
class TestURLRequestHttpJob : public URLRequestHttpJob {
 public:
  explicit TestURLRequestHttpJob(URLRequest* request)
      : URLRequestHttpJob(request,
                          request->context()->network_delegate(),
                          request->context()->http_user_agent_settings()) {}
  ~TestURLRequestHttpJob() override {}

 private:
  DISALLOW_COPY_AND_ASSIGN(TestURLRequestHttpJob);
};

class SdchPolicyDelegateTest : public testing::Test {
 protected:
  SdchPolicyDelegateTest()
      : sdch_manager_(new SdchManager),
        is_cached_content_(false),
        response_code_(200) {
    req_ = context_.CreateRequest(GURL("http://www.example.com"),
                                  DEFAULT_PRIORITY, &request_delegate_);
    job_.reset(new TestURLRequestHttpJob(req_.get()));
  }

  std::unique_ptr<SdchPolicyDelegate> GetDelegate(bool possible_pass_through) {
    return base::WrapUnique(new SdchPolicyDelegate(
        possible_pass_through, job_.get(), mime_type_, url_, is_cached_content_,
        sdch_manager_.get(), std::move(dictionary_set_), response_code_,
        net_log_));
  }

  void set_mime_type(const std::string& mime_type) { mime_type_ = mime_type; }
  void set_url(const GURL& url) { url_ = url; }
  void set_is_cached_content(bool is_cached_content) {
    is_cached_content_ = is_cached_content;
  }
  void set_response_code(int response_code) { response_code_ = response_code; }
  void set_dictionaries_advertised(
      std::unique_ptr<SdchManager::DictionarySet> dictionary_set) {
    dictionary_set_ = std::move(dictionary_set);
  }

  // Getters:
  std::unique_ptr<SdchPolicyDelegate> delegate() {
    return std::move(delegate_);
  }

  SdchManager* sdch_manager() const { return sdch_manager_.get(); }

 private:
  TestURLRequestContext context_;
  TestDelegate request_delegate_;
  std::unique_ptr<URLRequest> req_;
  std::unique_ptr<TestURLRequestHttpJob> job_;
  std::unique_ptr<SdchManager> sdch_manager_;
  std::unique_ptr<SdchPolicyDelegate> delegate_;
  std::string mime_type_;
  GURL url_;
  bool is_cached_content_;
  int response_code_;
  NetLogWithSource net_log_;
  std::unique_ptr<SdchManager::DictionarySet> dictionary_set_;

  DISALLOW_COPY_AND_ASSIGN(SdchPolicyDelegateTest);
};

}  // namespace

// Tests FixUpSdchContentEncodings() does the right thing when Sdch is present
// in the encodings.
TEST_F(SdchPolicyDelegateTest, FixUpSdchContentEncodingsWhenSdchPresent) {
  std::vector<SourceStream::SourceType> encoding_types;

  // Check for most common encoding, and verify it survives unchanged.
  encoding_types.clear();
  encoding_types.push_back(SourceStream::TYPE_SDCH);
  encoding_types.push_back(SourceStream::TYPE_GZIP);
  std::unique_ptr<SdchManager::DictionarySet> dictionary_set(
      SdchManager::CreateEmptyDictionarySetForTesting());
  NetLogWithSource net_log;
  SdchPolicyDelegate::FixUpSdchContentEncodings(
      net_log, kTextHtmlMime, dictionary_set.get(), &encoding_types);
  ASSERT_EQ(2U, encoding_types.size());
  EXPECT_EQ(SourceStream::TYPE_SDCH, encoding_types[0]);
  EXPECT_EQ(SourceStream::TYPE_GZIP, encoding_types[1]);

  // Unchanged even with other mime types.
  encoding_types.clear();
  encoding_types.push_back(SourceStream::TYPE_SDCH);
  encoding_types.push_back(SourceStream::TYPE_GZIP);
  SdchPolicyDelegate::FixUpSdchContentEncodings(
      net_log, "other/type", dictionary_set.get(), &encoding_types);
  ASSERT_EQ(2U, encoding_types.size());
  EXPECT_EQ(SourceStream::TYPE_SDCH, encoding_types[0]);
  EXPECT_EQ(SourceStream::TYPE_GZIP, encoding_types[1]);

  // Solo SDCH is extended to include optional gunzip.
  encoding_types.clear();
  encoding_types.push_back(SourceStream::TYPE_SDCH);
  SdchPolicyDelegate::FixUpSdchContentEncodings(
      net_log, "other/type", dictionary_set.get(), &encoding_types);
  ASSERT_EQ(2U, encoding_types.size());
  EXPECT_EQ(SourceStream::TYPE_SDCH, encoding_types[0]);
  EXPECT_EQ(SourceStream::TYPE_GZIP_FALLBACK, encoding_types[1]);
}

// Tests FixUpSdchContentEncodings() does the right thing when Sdch is missing
// from the encodings.
TEST_F(SdchPolicyDelegateTest, FixUpSdchContentEncodingsSdchMissing) {
  std::vector<SourceStream::SourceType> encoding_types;

  // When content encodings are empty, but dictionary is advertised. Make sure
  // that Sdch and Gzip filters are added.
  std::unique_ptr<SdchManager::DictionarySet> dictionary_set(
      SdchManager::CreateEmptyDictionarySetForTesting());
  NetLogWithSource net_log;
  SdchPolicyDelegate::FixUpSdchContentEncodings(
      net_log, "other/type", dictionary_set.get(), &encoding_types);
  ASSERT_EQ(2U, encoding_types.size());
  EXPECT_EQ(SourceStream::TYPE_SDCH_POSSIBLE, encoding_types[0]);
  EXPECT_EQ(SourceStream::TYPE_GZIP_FALLBACK, encoding_types[1]);

  // Only Gzip present, but dictionary is advertised.
  encoding_types.clear();
  encoding_types.push_back(SourceStream::TYPE_GZIP);
  SdchPolicyDelegate::FixUpSdchContentEncodings(
      net_log, "other/type", dictionary_set.get(), &encoding_types);
  ASSERT_EQ(3U, encoding_types.size());
  EXPECT_EQ(SourceStream::TYPE_SDCH_POSSIBLE, encoding_types[0]);
  EXPECT_EQ(SourceStream::TYPE_GZIP_FALLBACK, encoding_types[1]);
  EXPECT_EQ(SourceStream::TYPE_GZIP, encoding_types[2]);
}

TEST_F(SdchPolicyDelegateTest, PossiblePassThrough) {
  // TODO(xunjieli): Right now possible pass-throughs are handled by
  // meta-refresh. This is done to match old behavior.
  set_dictionaries_advertised(
      SdchManager::CreateEmptyDictionarySetForTesting());
  set_mime_type("text/html");
  std::unique_ptr<SdchPolicyDelegate> delegate(GetDelegate(true));
  std::string replace_output;
  EXPECT_EQ(SdchPolicyDelegate::REPLACE_OUTPUT,
            delegate->OnDictionaryIdError(&replace_output));
  EXPECT_EQ(kRefreshHtml, replace_output);

  replace_output.clear();
  EXPECT_EQ(SdchPolicyDelegate::REPLACE_OUTPUT,
            delegate->OnGetDictionaryError(&replace_output));
  EXPECT_EQ(kRefreshHtml, replace_output);
  // |possible_pass_through_| shouldn't have any effect on non-dictionary
  // errors, because at this point a dictionary is successfully fetched.
  // Make sure meta refresh is issued.
  set_mime_type("text/html; charset=UTF-8");
  set_dictionaries_advertised(
      SdchManager::CreateEmptyDictionarySetForTesting());
  delegate = GetDelegate(true);
  replace_output.clear();
  EXPECT_EQ(SdchPolicyDelegate::REPLACE_OUTPUT,
            delegate->OnDecodingError(&replace_output));
  EXPECT_EQ(kRefreshHtml, replace_output);
}

TEST_F(SdchPolicyDelegateTest, OnDictionaryIdError) {
  std::unique_ptr<SdchPolicyDelegate> delegate;
  // 404 case.
  set_response_code(404);
  std::string replace_output;
  delegate = GetDelegate(false);
  EXPECT_EQ(SdchPolicyDelegate::PASS_THROUGH,
            delegate->OnDictionaryIdError(&replace_output));

  // non-200 case.
  replace_output.clear();
  set_response_code(500);
  set_mime_type("text/html; charset=UTF-8");
  delegate = GetDelegate(false);
  EXPECT_EQ(SdchPolicyDelegate::REPLACE_OUTPUT,
            delegate->OnDictionaryIdError(&replace_output));
  EXPECT_EQ(kRefreshHtml, replace_output);

  // Cached content case.
  set_response_code(200);
  set_is_cached_content(true);
  delegate = GetDelegate(false);
  EXPECT_EQ(SdchPolicyDelegate::PASS_THROUGH,
            delegate->OnDictionaryIdError(&replace_output));

  // Dictionary not advertised case.
  set_is_cached_content(false);
  delegate = GetDelegate(false);
  EXPECT_EQ(SdchPolicyDelegate::PASS_THROUGH,
            delegate->OnDictionaryIdError(&replace_output));

  // Dictionary advertised case.
  replace_output.clear();
  set_is_cached_content(false);
  set_dictionaries_advertised(
      SdchManager::CreateEmptyDictionarySetForTesting());
  delegate = GetDelegate(false);
  EXPECT_EQ(SdchPolicyDelegate::REPLACE_OUTPUT,
            delegate->OnDictionaryIdError(&replace_output));
  EXPECT_EQ(kRefreshHtml, replace_output);
}

TEST_F(SdchPolicyDelegateTest, OnGetDictionaryError) {
  std::unique_ptr<SdchPolicyDelegate> delegate;

  // 404 case.
  set_response_code(404);
  std::string replace_output;
  delegate = GetDelegate(false);
  EXPECT_EQ(SdchPolicyDelegate::PASS_THROUGH,
            delegate->OnGetDictionaryError(&replace_output));

  // Meta-refresh case.
  set_response_code(200);
  set_mime_type("text/html; charset=UTF-8");
  delegate = GetDelegate(false);
  EXPECT_EQ(SdchPolicyDelegate::REPLACE_OUTPUT,
            delegate->OnGetDictionaryError(&replace_output));
  EXPECT_EQ(kRefreshHtml, replace_output);

  // Meta-refresh not applied case. Hard failure.
  replace_output.clear();
  set_mime_type("other/mime");
  delegate = GetDelegate(false);
  EXPECT_EQ(SdchPolicyDelegate::NONE,
            delegate->OnGetDictionaryError(&replace_output));
}

TEST_F(SdchPolicyDelegateTest, OnDecodingError) {
  std::unique_ptr<SdchPolicyDelegate> delegate;

  std::string replace_output;
  // Meta-refresh case.
  set_mime_type("text/html; charset=UTF-8");
  delegate = GetDelegate(false);
  EXPECT_EQ(SdchPolicyDelegate::REPLACE_OUTPUT,
            delegate->OnDecodingError(&replace_output));
  EXPECT_EQ(kRefreshHtml, replace_output);

  // Meta-refresh not applied case. Hard failure.
  replace_output.clear();
  set_mime_type("other/mime");
  delegate = GetDelegate(false);
  EXPECT_EQ(SdchPolicyDelegate::NONE,
            delegate->OnDecodingError(&replace_output));
}

TEST_F(SdchPolicyDelegateTest, DictionaryUsedSignal) {
  // Construct a valid SDCH dictionary from a VCDIFF dictionary.
  const std::string kSampleDomain = "sdchtest.com";
  std::string dictionary(NewSdchDictionary(kSampleDomain));
  std::string url_string = "http://" + kSampleDomain;
  GURL url(url_string);
  std::string server_id;
  sdch_manager()->AddSdchDictionary(dictionary, url, &server_id);
  SimpleSdchObserver observer(sdch_manager());
  set_dictionaries_advertised(sdch_manager()->GetDictionarySet(url));
  std::unique_ptr<SdchPolicyDelegate> delegate = GetDelegate(false);

  const std::string* dictionary_text;
  delegate->OnGetDictionary(server_id, &dictionary_text);
  delegate->OnStreamDestroyed(SdchSourceStream::STATE_DECODE, false, false);
  EXPECT_EQ(1, observer.dictionary_used_calls());
  EXPECT_EQ(server_id, observer.last_server_hash());
}

}  // namespace net
