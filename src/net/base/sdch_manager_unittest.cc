// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/sdch_manager.h"

#include <inttypes.h>
#include <limits.h>

#include <memory>
#include <string>

#include "base/logging.h"
#include "base/macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/test/simple_test_clock.h"
#include "base/trace_event/memory_allocator_dump.h"
#include "base/trace_event/process_memory_dump.h"
#include "base/trace_event/trace_event_argument.h"
#include "net/base/sdch_observer.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

//------------------------------------------------------------------------------
// Provide sample data and compression results with a sample VCDIFF dictionary.
// Note an SDCH dictionary has extra meta-data before the VCDIFF dictionary.
static const char kTestVcdiffDictionary[] = "DictionaryFor"
    "SdchCompression1SdchCompression2SdchCompression3SdchCompression\n";

//------------------------------------------------------------------------------

class MockSdchObserver : public SdchObserver {
 public:
  MockSdchObserver()
      : dictionary_added_notifications_(0),
        dictionary_removed_notifications_(0),
        dictionary_used_notifications_(0),
        get_dictionary_notifications_(0),
        clear_dictionaries_notifications_(0) {}

  int dictionary_added_notifications() const {
    return dictionary_added_notifications_;
  }
  int dictionary_removed_notifications() const {
    return dictionary_removed_notifications_;
  }
  std::string last_server_hash() const { return last_server_hash_; }
  int dictionary_used_notifications() const {
    return dictionary_used_notifications_;
  }
  const GURL& last_dictionary_request_url() const {
    return last_dictionary_request_url_;
  }
  const GURL& last_dictionary_url() const { return last_dictionary_url_; }
  int get_dictionary_notifications() const {
    return get_dictionary_notifications_;
  }

  int clear_dictionary_notifications() const {
    return clear_dictionaries_notifications_;
  }

  // SdchObserver implementation
  void OnDictionaryAdded(const GURL& dictionary_url,
                         const std::string& server_hash) override {
    last_server_hash_ = server_hash;
    last_dictionary_url_ = dictionary_url;
    ++dictionary_added_notifications_;
  }
  void OnDictionaryRemoved(const std::string& server_hash) override {
    last_server_hash_ = server_hash;
    ++dictionary_removed_notifications_;
  }
  void OnDictionaryUsed(const std::string& server_hash) override {
    last_server_hash_ = server_hash;
    ++dictionary_used_notifications_;
  }

  void OnGetDictionary(const GURL& request_url,
                       const GURL& dictionary_url) override {
    ++get_dictionary_notifications_;
    last_dictionary_request_url_ = request_url;
    last_dictionary_url_ = dictionary_url;
  }
  void OnClearDictionaries() override {
    ++clear_dictionaries_notifications_;
  }

 private:
  int dictionary_added_notifications_;
  int dictionary_removed_notifications_;
  int dictionary_used_notifications_;
  int get_dictionary_notifications_;
  int clear_dictionaries_notifications_;

  std::string last_server_hash_;
  GURL last_dictionary_request_url_;
  GURL last_dictionary_url_;

  DISALLOW_COPY_AND_ASSIGN(MockSdchObserver);
};

class SdchManagerTest : public testing::Test {
 protected:
  SdchManagerTest()
      : sdch_manager_(new SdchManager) {}

  ~SdchManagerTest() override {}

  SdchManager* sdch_manager() { return sdch_manager_.get(); }

  // Attempt to add a dictionary to the manager and probe for success or
  // failure.
  bool AddSdchDictionary(const std::string& dictionary_text,
                         const GURL& gurl) {
    return sdch_manager_->AddSdchDictionary(dictionary_text, gurl, nullptr) ==
           SDCH_OK;
  }

 private:
  std::unique_ptr<SdchManager> sdch_manager_;
};

static std::string NewSdchDictionary(const std::string& domain) {
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

TEST_F(SdchManagerTest, DomainSupported) {
  GURL google_url("http://www.google.com");

  EXPECT_EQ(SDCH_OK, sdch_manager()->IsInSupportedDomain(google_url));
}

TEST_F(SdchManagerTest, DomainBlacklisting) {
  GURL test_url("http://www.test.com");
  GURL google_url("http://www.google.com");

  sdch_manager()->BlacklistDomain(test_url, SDCH_OK);
  EXPECT_EQ(SDCH_DOMAIN_BLACKLIST_INCLUDES_TARGET,
            sdch_manager()->IsInSupportedDomain(test_url));
  EXPECT_EQ(SDCH_OK, sdch_manager()->IsInSupportedDomain(google_url));

  sdch_manager()->BlacklistDomain(google_url, SDCH_OK);
  EXPECT_EQ(SDCH_DOMAIN_BLACKLIST_INCLUDES_TARGET,
            sdch_manager()->IsInSupportedDomain(google_url));
}

TEST_F(SdchManagerTest, DomainBlacklistingCaseSensitivity) {
  GURL test_url("http://www.TesT.com");
  GURL test2_url("http://www.tEst.com");

  EXPECT_EQ(SDCH_OK, sdch_manager()->IsInSupportedDomain(test_url));
  EXPECT_EQ(SDCH_OK, sdch_manager()->IsInSupportedDomain(test2_url));
  sdch_manager()->BlacklistDomain(test_url, SDCH_OK);
  EXPECT_EQ(SDCH_DOMAIN_BLACKLIST_INCLUDES_TARGET,
            sdch_manager()->IsInSupportedDomain(test2_url));
}

TEST_F(SdchManagerTest, BlacklistingReset) {
  GURL gurl("http://mytest.DoMain.com");
  std::string domain(gurl.host());

  sdch_manager()->ClearBlacklistings();
  EXPECT_EQ(sdch_manager()->BlackListDomainCount(domain), 0);
  EXPECT_EQ(sdch_manager()->BlacklistDomainExponential(domain), 0);
  EXPECT_EQ(SDCH_OK, sdch_manager()->IsInSupportedDomain(gurl));
}

TEST_F(SdchManagerTest, BlacklistingSingleBlacklist) {
  GURL gurl("http://mytest.DoMain.com");
  std::string domain(gurl.host());
  sdch_manager()->ClearBlacklistings();

  sdch_manager()->BlacklistDomain(gurl, SDCH_OK);
  EXPECT_EQ(sdch_manager()->BlackListDomainCount(domain), 1);
  EXPECT_EQ(sdch_manager()->BlacklistDomainExponential(domain), 1);

  // Check that any domain lookup reduces the blacklist counter.
  EXPECT_EQ(SDCH_DOMAIN_BLACKLIST_INCLUDES_TARGET,
            sdch_manager()->IsInSupportedDomain(gurl));
  EXPECT_EQ(sdch_manager()->BlackListDomainCount(domain), 0);
  EXPECT_EQ(SDCH_OK, sdch_manager()->IsInSupportedDomain(gurl));
}

TEST_F(SdchManagerTest, BlacklistingExponential) {
  GURL gurl("http://mytest.DoMain.com");
  std::string domain(gurl.host());
  sdch_manager()->ClearBlacklistings();

  int exponential = 1;
  for (int i = 1; i < 100; ++i) {
    sdch_manager()->BlacklistDomain(gurl, SDCH_OK);
    EXPECT_EQ(sdch_manager()->BlacklistDomainExponential(domain), exponential);

    EXPECT_EQ(sdch_manager()->BlackListDomainCount(domain), exponential);
    EXPECT_EQ(SDCH_DOMAIN_BLACKLIST_INCLUDES_TARGET,
              sdch_manager()->IsInSupportedDomain(gurl));
    EXPECT_EQ(sdch_manager()->BlackListDomainCount(domain), exponential - 1);

    // Simulate a large number of domain checks (which eventually remove the
    // blacklisting).
    sdch_manager()->ClearDomainBlacklisting(domain);
    EXPECT_EQ(sdch_manager()->BlackListDomainCount(domain), 0);
    EXPECT_EQ(SDCH_OK, sdch_manager()->IsInSupportedDomain(gurl));

    // Predict what exponential backoff will be.
    exponential = 1 + 2 * exponential;
    if (exponential < 0)
      exponential = INT_MAX;  // We don't wrap.
  }
}

TEST_F(SdchManagerTest, CanSetExactMatchDictionary) {
  std::string dictionary_domain("x.y.z.google.com");
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));

  // Perfect match should work.
  EXPECT_TRUE(AddSdchDictionary(dictionary_text,
                                GURL("http://" + dictionary_domain)));
}

TEST_F(SdchManagerTest, CanAdvertiseDictionaryOverHTTP) {
  std::string dictionary_domain("x.y.z.google.com");
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));

  EXPECT_TRUE(AddSdchDictionary(dictionary_text,
                                GURL("http://" + dictionary_domain)));

  // HTTP target URL can advertise dictionary.
  EXPECT_TRUE(sdch_manager()->GetDictionarySet(
      GURL("http://" + dictionary_domain + "/test")));
}

TEST_F(SdchManagerTest, CanNotAdvertiseDictionaryOverHTTPS) {
  std::string dictionary_domain("x.y.z.google.com");
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));

  EXPECT_TRUE(AddSdchDictionary(dictionary_text,
                                GURL("http://" + dictionary_domain)));

  // HTTPS target URL should NOT advertise dictionary.
  EXPECT_FALSE(sdch_manager()->GetDictionarySet(
      GURL("https://" + dictionary_domain + "/test")));
}

TEST_F(SdchManagerTest, CanUseHTTPSDictionaryOverHTTPSIfEnabled) {
  std::string dictionary_domain("x.y.z.google.com");
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));

  EXPECT_TRUE(AddSdchDictionary(dictionary_text,
                                GURL("https://" + dictionary_domain)));

  GURL target_url("https://" + dictionary_domain + "/test");
  // HTTPS target URL should advertise dictionary if secure scheme support is
  // enabled.
  EXPECT_TRUE(sdch_manager()->GetDictionarySet(target_url));

  // Dictionary should be available.
  std::string client_hash;
  std::string server_hash;
  sdch_manager()->GenerateHash(dictionary_text, &client_hash, &server_hash);
  SdchProblemCode problem_code;
  std::unique_ptr<SdchManager::DictionarySet> dict_set(
      sdch_manager()->GetDictionarySetByHash(target_url, server_hash,
                                             &problem_code));
  EXPECT_EQ(SDCH_OK, problem_code);
  EXPECT_TRUE(dict_set.get());
  EXPECT_TRUE(dict_set->GetDictionaryText(server_hash));
}

TEST_F(SdchManagerTest, CanNotUseHTTPDictionaryOverHTTPS) {
  std::string dictionary_domain("x.y.z.google.com");
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));

  EXPECT_TRUE(AddSdchDictionary(dictionary_text,
                                GURL("http://" + dictionary_domain)));

  GURL target_url("https://" + dictionary_domain + "/test");
  // HTTPS target URL should not advertise dictionary acquired over HTTP even if
  // secure scheme support is enabled.
  EXPECT_FALSE(sdch_manager()->GetDictionarySet(target_url));

  std::string client_hash;
  std::string server_hash;
  sdch_manager()->GenerateHash(dictionary_text, &client_hash, &server_hash);
  SdchProblemCode problem_code;
  std::unique_ptr<SdchManager::DictionarySet> dict_set(
      sdch_manager()->GetDictionarySetByHash(target_url, server_hash,
                                             &problem_code));
  EXPECT_FALSE(dict_set.get());
  EXPECT_EQ(SDCH_DICTIONARY_FOUND_HAS_WRONG_SCHEME, problem_code);
}

TEST_F(SdchManagerTest, CanNotUseHTTPSDictionaryOverHTTP) {
  std::string dictionary_domain("x.y.z.google.com");
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));

  EXPECT_TRUE(AddSdchDictionary(dictionary_text,
                                GURL("https://" + dictionary_domain)));

  GURL target_url("http://" + dictionary_domain + "/test");
  // HTTP target URL should not advertise dictionary acquired over HTTPS even if
  // secure scheme support is enabled.
  EXPECT_FALSE(sdch_manager()->GetDictionarySet(target_url));

  std::string client_hash;
  std::string server_hash;
  sdch_manager()->GenerateHash(dictionary_text, &client_hash, &server_hash);
  SdchProblemCode problem_code;
  std::unique_ptr<SdchManager::DictionarySet> dict_set(
      sdch_manager()->GetDictionarySetByHash(target_url, server_hash,
                                             &problem_code));
  EXPECT_FALSE(dict_set.get());
  EXPECT_EQ(SDCH_DICTIONARY_FOUND_HAS_WRONG_SCHEME, problem_code);
}

TEST_F(SdchManagerTest, FailToSetDomainMismatchDictionary) {
  std::string dictionary_domain("x.y.z.google.com");
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));

  // Fail the "domain match" requirement.
  EXPECT_FALSE(AddSdchDictionary(dictionary_text,
                                 GURL("http://y.z.google.com")));
}

TEST_F(SdchManagerTest, FailToSetDotHostPrefixDomainDictionary) {
  std::string dictionary_domain("x.y.z.google.com");
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));

  // Fail the HD with D being the domain and H having a dot requirement.
  EXPECT_FALSE(AddSdchDictionary(dictionary_text,
                                 GURL("http://w.x.y.z.google.com")));
}

TEST_F(SdchManagerTest, FailToSetDotHostPrefixDomainDictionaryTrailingDot) {
  std::string dictionary_domain("x.y.z.google.com");
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));

  // Fail the HD with D being the domain and H having a dot requirement.
  EXPECT_FALSE(AddSdchDictionary(dictionary_text,
                                 GURL("http://w.x.y.z.google.com.")));
}

TEST_F(SdchManagerTest, FailToSetRepeatPrefixWithDotDictionary) {
  // Make sure that a prefix that matches the domain postfix won't confuse
  // the validation checks.
  std::string dictionary_domain("www.google.com");
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));

  // Fail the HD with D being the domain and H having a dot requirement.
  EXPECT_FALSE(AddSdchDictionary(dictionary_text,
                                 GURL("http://www.google.com.www.google.com")));
}

TEST_F(SdchManagerTest, CanSetLeadingDotDomainDictionary) {
  // Make sure that a prefix that matches the domain postfix won't confuse
  // the validation checks.
  std::string dictionary_domain(".google.com");
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));

  // Verify that a leading dot in the domain is acceptable, as long as the host
  // name does not contain any dots preceding the matched domain name.
  EXPECT_TRUE(AddSdchDictionary(dictionary_text, GURL("http://www.google.com")));
}

TEST_F(SdchManagerTest,
       CanSetLeadingDotDomainDictionaryFromURLWithTrailingDot) {
  // Make sure that a prefix that matches the domain postfix won't confuse
  // the validation checks.
  std::string dictionary_domain(".google.com");
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));

  // Verify that a leading dot in the domain is acceptable, as long as the host
  // name does not contain any dots preceding the matched domain name.
  EXPECT_TRUE(AddSdchDictionary(dictionary_text,
                                GURL("http://www.google.com.")));
}

TEST_F(SdchManagerTest, CannotSetLeadingDotDomainDictionary) {
  // Make sure that a prefix that matches the domain postfix won't confuse
  // the validation checks.
  std::string dictionary_domain(".google.com");
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));

  // Verify that a leading dot in the domain does not affect the name containing
  // dots failure.
  EXPECT_FALSE(AddSdchDictionary(dictionary_text,
                                 GURL("http://www.subdomain.google.com")));
}

TEST_F(SdchManagerTest, CannotSetLeadingDotDomainDictionaryTrailingDot) {
  // Make sure that a prefix that matches the domain postfix won't confuse
  // the validation checks.
  std::string dictionary_domain(".google.com");
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));

  // Verify that a trailing period in the URL doesn't affect the check.
  EXPECT_FALSE(AddSdchDictionary(dictionary_text,
                                 GURL("http://www.subdomain.google.com.")));
}

// Make sure the order of the tests is not helping us or confusing things.
// See test CanSetExactMatchDictionary above for first try.
TEST_F(SdchManagerTest, CanStillSetExactMatchDictionary) {
  std::string dictionary_domain("x.y.z.google.com");
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));

  // Perfect match should *STILL* work.
  EXPECT_TRUE(AddSdchDictionary(dictionary_text,
                                GURL("http://" + dictionary_domain)));
}

// The following are only applicable while we have a latency test in the code,
// and can be removed when that functionality is stripped.
TEST_F(SdchManagerTest, LatencyTestControls) {
  GURL url("http://www.google.com");
  GURL url2("http://www.google2.com");

  // First make sure we default to false.
  EXPECT_FALSE(sdch_manager()->AllowLatencyExperiment(url));
  EXPECT_FALSE(sdch_manager()->AllowLatencyExperiment(url2));

  // That we can set each to true.
  sdch_manager()->SetAllowLatencyExperiment(url, true);
  EXPECT_TRUE(sdch_manager()->AllowLatencyExperiment(url));
  EXPECT_FALSE(sdch_manager()->AllowLatencyExperiment(url2));

  sdch_manager()->SetAllowLatencyExperiment(url2, true);
  EXPECT_TRUE(sdch_manager()->AllowLatencyExperiment(url));
  EXPECT_TRUE(sdch_manager()->AllowLatencyExperiment(url2));

  // And can reset them to false.
  sdch_manager()->SetAllowLatencyExperiment(url, false);
  EXPECT_FALSE(sdch_manager()->AllowLatencyExperiment(url));
  EXPECT_TRUE(sdch_manager()->AllowLatencyExperiment(url2));

  sdch_manager()->SetAllowLatencyExperiment(url2, false);
  EXPECT_FALSE(sdch_manager()->AllowLatencyExperiment(url));
  EXPECT_FALSE(sdch_manager()->AllowLatencyExperiment(url2));
}

TEST_F(SdchManagerTest, CanUseMultipleManagers) {
  SdchManager second_manager;

  std::string dictionary_domain_1("x.y.z.google.com");
  std::string dictionary_domain_2("x.y.z.chromium.org");

  std::string dictionary_text_1(NewSdchDictionary(dictionary_domain_1));
  std::string dictionary_text_2(NewSdchDictionary(dictionary_domain_2));

  std::string tmp_hash;
  std::string server_hash_1;
  std::string server_hash_2;

  SdchManager::GenerateHash(dictionary_text_1, &tmp_hash, &server_hash_1);
  SdchManager::GenerateHash(dictionary_text_2, &tmp_hash, &server_hash_2);

  // Confirm that if you add directories to one manager, you
  // can't get them from the other.
  EXPECT_TRUE(AddSdchDictionary(dictionary_text_1,
                                GURL("http://" + dictionary_domain_1)));
  std::unique_ptr<SdchManager::DictionarySet> dict_set;

  SdchProblemCode problem_code;
  dict_set = sdch_manager()->GetDictionarySetByHash(
      GURL("http://" + dictionary_domain_1 + "/random_url"),
      server_hash_1, &problem_code);
  EXPECT_TRUE(dict_set);
  EXPECT_TRUE(dict_set->GetDictionaryText(server_hash_1));
  EXPECT_EQ(SDCH_OK, problem_code);

  second_manager.AddSdchDictionary(
      dictionary_text_2, GURL("http://" + dictionary_domain_2), nullptr);
  dict_set = second_manager.GetDictionarySetByHash(
      GURL("http://" + dictionary_domain_2 + "/random_url"),
      server_hash_2, &problem_code);
  EXPECT_TRUE(dict_set);
  EXPECT_TRUE(dict_set->GetDictionaryText(server_hash_2));
  EXPECT_EQ(SDCH_OK, problem_code);

  dict_set = sdch_manager()->GetDictionarySetByHash(
      GURL("http://" + dictionary_domain_2 + "/random_url"),
      server_hash_2, &problem_code);
  EXPECT_FALSE(dict_set);
  EXPECT_EQ(SDCH_DICTIONARY_HASH_NOT_FOUND, problem_code);

  dict_set = second_manager.GetDictionarySetByHash(
      GURL("http://" + dictionary_domain_1 + "/random_url"),
      server_hash_1, &problem_code);
  EXPECT_FALSE(dict_set);
  EXPECT_EQ(SDCH_DICTIONARY_HASH_NOT_FOUND, problem_code);
}

TEST_F(SdchManagerTest, ClearDictionaryData) {
  std::string dictionary_domain("x.y.z.google.com");
  GURL blacklist_url("http://bad.chromium.org");

  std::string dictionary_text(NewSdchDictionary(dictionary_domain));
  std::string tmp_hash;
  std::string server_hash;

  SdchManager::GenerateHash(dictionary_text, &tmp_hash, &server_hash);

  EXPECT_TRUE(AddSdchDictionary(dictionary_text,
                                GURL("http://" + dictionary_domain)));

  std::unique_ptr<SdchManager::DictionarySet> dict_set;

  SdchProblemCode problem_code;
  dict_set = sdch_manager()->GetDictionarySetByHash(
      GURL("http://" + dictionary_domain + "/random_url"),
      server_hash, &problem_code);
  EXPECT_TRUE(dict_set);
  EXPECT_TRUE(dict_set->GetDictionaryText(server_hash));
  EXPECT_EQ(SDCH_OK, problem_code);

  sdch_manager()->BlacklistDomain(GURL(blacklist_url), SDCH_OK);
  EXPECT_EQ(SDCH_DOMAIN_BLACKLIST_INCLUDES_TARGET,
            sdch_manager()->IsInSupportedDomain(blacklist_url));

  sdch_manager()->ClearData();

  dict_set = sdch_manager()->GetDictionarySetByHash(
      GURL("http://" + dictionary_domain + "/random_url"),
      server_hash, &problem_code);
  EXPECT_FALSE(dict_set);
  EXPECT_EQ(SDCH_DICTIONARY_HASH_NOT_FOUND, problem_code);
  EXPECT_EQ(SDCH_OK, sdch_manager()->IsInSupportedDomain(blacklist_url));
}

TEST_F(SdchManagerTest, GetDictionaryNotification) {
  GURL test_request_gurl(GURL("http://www.example.com/data"));
  GURL test_dictionary_gurl(GURL("http://www.example.com/dict"));
  MockSdchObserver observer;
  sdch_manager()->AddObserver(&observer);

  EXPECT_EQ(0, observer.get_dictionary_notifications());
  sdch_manager()->OnGetDictionary(test_request_gurl, test_dictionary_gurl);
  EXPECT_EQ(1, observer.get_dictionary_notifications());
  EXPECT_EQ(test_request_gurl, observer.last_dictionary_request_url());
  EXPECT_EQ(test_dictionary_gurl, observer.last_dictionary_url());

  sdch_manager()->RemoveObserver(&observer);
  sdch_manager()->OnGetDictionary(test_request_gurl, test_dictionary_gurl);
  EXPECT_EQ(1, observer.get_dictionary_notifications());
  EXPECT_EQ(test_request_gurl, observer.last_dictionary_request_url());
  EXPECT_EQ(test_dictionary_gurl, observer.last_dictionary_url());
}

TEST_F(SdchManagerTest, ExpirationCheckedProperly) {
  // Create an SDCH dictionary with an expiration time in the past.
  std::string dictionary_domain("x.y.z.google.com");
  // TODO(eroman): "max-age: -1" is invalid -- it is not a valid production of
  // delta-seconds (1*DIGIT). This test works because currently an invalid
  // max-age results in the dictionary being considered expired on loading
  // (crbug.com/602691)
  std::string dictionary_text(base::StringPrintf("Domain: %s\nMax-age: -1\n\n",
                                                 dictionary_domain.c_str()));
  dictionary_text.append(
      kTestVcdiffDictionary, sizeof(kTestVcdiffDictionary) - 1);
  std::string client_hash;
  std::string server_hash;
  SdchManager::GenerateHash(dictionary_text, &client_hash, &server_hash);
  GURL target_gurl("http://" + dictionary_domain);
  AddSdchDictionary(dictionary_text, target_gurl);

  // It should be visible if looked up by hash whether expired or not.
  SdchProblemCode problem_code;
  std::unique_ptr<SdchManager::DictionarySet> hash_set(
      sdch_manager()->GetDictionarySetByHash(target_gurl, server_hash,
                                             &problem_code));
  ASSERT_TRUE(hash_set);
  ASSERT_EQ(SDCH_OK, problem_code);

  // Make sure it's not visible for advertisement, but is visible
  // if looked up by hash.
  EXPECT_FALSE(sdch_manager()->GetDictionarySet(target_gurl));
  EXPECT_TRUE(sdch_manager()->GetDictionarySetByHash(
      target_gurl, server_hash, &problem_code));
  EXPECT_EQ(SDCH_OK, problem_code);
}

// Confirm dispatch of notification.
TEST_F(SdchManagerTest, SdchDictionaryUsed) {
  MockSdchObserver observer;
  sdch_manager()->AddObserver(&observer);

  EXPECT_EQ(0, observer.dictionary_used_notifications());
  sdch_manager()->OnDictionaryUsed("xyzzy");
  EXPECT_EQ(1, observer.dictionary_used_notifications());
  EXPECT_EQ("xyzzy", observer.last_server_hash());

  std::string dictionary_domain("x.y.z.google.com");
  GURL target_gurl("http://" + dictionary_domain);
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));
  std::string client_hash;
  std::string server_hash;
  SdchManager::GenerateHash(dictionary_text, &client_hash, &server_hash);
  EXPECT_TRUE(AddSdchDictionary(dictionary_text, target_gurl));
  EXPECT_EQ(1, observer.dictionary_used_notifications());

  EXPECT_TRUE(sdch_manager()->GetDictionarySet(target_gurl));
  EXPECT_EQ(1, observer.dictionary_used_notifications());

  sdch_manager()->RemoveObserver(&observer);
  EXPECT_EQ(1, observer.dictionary_used_notifications());
  sdch_manager()->OnDictionaryUsed("plugh");
  EXPECT_EQ(1, observer.dictionary_used_notifications());
}

TEST_F(SdchManagerTest, AddRemoveNotifications) {
  MockSdchObserver observer;
  sdch_manager()->AddObserver(&observer);

  std::string dictionary_domain("x.y.z.google.com");
  GURL target_gurl("http://" + dictionary_domain);
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));
  std::string client_hash;
  std::string server_hash;
  SdchManager::GenerateHash(dictionary_text, &client_hash, &server_hash);
  EXPECT_TRUE(AddSdchDictionary(dictionary_text, target_gurl));
  EXPECT_EQ(1, observer.dictionary_added_notifications());
  EXPECT_EQ(target_gurl, observer.last_dictionary_url());
  EXPECT_EQ(server_hash, observer.last_server_hash());

  EXPECT_EQ(SDCH_OK, sdch_manager()->RemoveSdchDictionary(server_hash));
  EXPECT_EQ(1, observer.dictionary_removed_notifications());
  EXPECT_EQ(server_hash, observer.last_server_hash());

  sdch_manager()->RemoveObserver(&observer);
}

class SdchManagerMemoryDumpTest
    : public SdchManagerTest,
      public testing::WithParamInterface<
          base::trace_event::MemoryDumpLevelOfDetail> {};

INSTANTIATE_TEST_CASE_P(
    /* no prefix */,
    SdchManagerMemoryDumpTest,
    ::testing::Values(base::trace_event::MemoryDumpLevelOfDetail::DETAILED,
                      base::trace_event::MemoryDumpLevelOfDetail::BACKGROUND));

TEST_P(SdchManagerMemoryDumpTest, DumpMemoryStats) {
  MockSdchObserver observer;
  sdch_manager()->AddObserver(&observer);

  std::string dictionary_domain("x.y.z.google.com");
  GURL target_gurl("http://" + dictionary_domain);
  std::string dictionary_text(NewSdchDictionary(dictionary_domain));
  std::string client_hash;
  std::string server_hash;
  SdchManager::GenerateHash(dictionary_text, &client_hash, &server_hash);
  EXPECT_TRUE(AddSdchDictionary(dictionary_text, target_gurl));
  EXPECT_EQ(1, observer.dictionary_added_notifications());
  EXPECT_EQ(target_gurl, observer.last_dictionary_url());
  EXPECT_EQ(server_hash, observer.last_server_hash());

  base::trace_event::MemoryDumpArgs dump_args = {GetParam()};
  std::unique_ptr<base::trace_event::ProcessMemoryDump> pmd(
      new base::trace_event::ProcessMemoryDump(nullptr, dump_args));

  base::trace_event::MemoryAllocatorDump* parent =
      pmd->CreateAllocatorDump("net/url_request_context/main/0x123");
  sdch_manager()->DumpMemoryStats(pmd.get(), parent->absolute_name());

  const base::trace_event::MemoryAllocatorDump* sub_dump =
      pmd->GetAllocatorDump("net/url_request_context/main/0x123/sdch_manager");
  ASSERT_NE(nullptr, sub_dump);
  const base::trace_event::MemoryAllocatorDump* dump = pmd->GetAllocatorDump(
      base::StringPrintf("net/sdch_manager_0x%" PRIxPTR,
                         reinterpret_cast<uintptr_t>(sdch_manager())));
  std::unique_ptr<base::Value> raw_attrs =
      dump->attributes_for_testing()->ToBaseValue();
  base::DictionaryValue* attrs;
  ASSERT_TRUE(raw_attrs->GetAsDictionary(&attrs));
  base::DictionaryValue* size_attrs;
  ASSERT_TRUE(attrs->GetDictionary(
      base::trace_event::MemoryAllocatorDump::kNameSize, &size_attrs));
  size_t offset = dictionary_text.find("\n\n") + 2;
  std::string size;
  ASSERT_TRUE(size_attrs->GetString("value", &size));
  int actual_size;
  ASSERT_TRUE(base::HexStringToInt(size, &actual_size));
  EXPECT_EQ(dictionary_text.size() - offset, static_cast<size_t>(actual_size));

  base::DictionaryValue* count_attrs;
  ASSERT_TRUE(attrs->GetDictionary(
      base::trace_event::MemoryAllocatorDump::kNameObjectCount, &count_attrs));
  std::string count;
  ASSERT_TRUE(count_attrs->GetString("value", &count));
  // One dictionary.
  EXPECT_EQ("1", count);

  sdch_manager()->RemoveObserver(&observer);
}

}  // namespace net
