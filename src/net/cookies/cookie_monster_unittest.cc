// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cookies/cookie_monster.h"

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include "base/bind.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/metrics/histogram.h"
#include "base/metrics/histogram_samples.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_split.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/stringprintf.h"
#include "base/test/histogram_tester.h"
#include "base/test/mock_callback.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_monster_store_test.h"  // For CookieStore mock
#include "net/cookies/cookie_store_unittest.h"
#include "net/cookies/cookie_util.h"
#include "net/cookies/parsed_cookie.h"
#include "net/ssl/channel_id_service.h"
#include "net/ssl/default_channel_id_store.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

using CookiePredicate = CookieStore::CookiePredicate;
using base::Time;
using base::TimeDelta;

namespace {

// TODO(erikwright): Replace the pre-existing MockPersistentCookieStore (and
// brethren) with this one, and remove the 'New' prefix.
class NewMockPersistentCookieStore
    : public CookieMonster::PersistentCookieStore {
 public:
  MOCK_METHOD1(Load, void(const LoadedCallback& loaded_callback));
  MOCK_METHOD2(LoadCookiesForKey,
               void(const std::string& key,
                    const LoadedCallback& loaded_callback));
  MOCK_METHOD1(AddCookie, void(const CanonicalCookie& cc));
  MOCK_METHOD1(UpdateCookieAccessTime, void(const CanonicalCookie& cc));
  MOCK_METHOD1(DeleteCookie, void(const CanonicalCookie& cc));
  virtual void Flush(const base::Closure& callback) {
    if (!callback.is_null())
      base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, callback);
  }
  MOCK_METHOD0(SetForceKeepSessionState, void());

 private:
  virtual ~NewMockPersistentCookieStore() {}
};

// False means 'less than or equal', so we test both ways for full equal.
MATCHER_P(CookieEquals, expected, "") {
  return !(arg.FullCompare(expected) || expected.FullCompare(arg));
}

const char kTopLevelDomainPlus1[] = "http://www.harvard.edu";
const char kTopLevelDomainPlus2[] = "http://www.math.harvard.edu";
const char kTopLevelDomainPlus2Secure[] = "https://www.math.harvard.edu";
const char kTopLevelDomainPlus3[] = "http://www.bourbaki.math.harvard.edu";
const char kOtherDomain[] = "http://www.mit.edu";

bool AlwaysTrueCookiePredicate(CanonicalCookie* to_save,
                               const CanonicalCookie& cookie) {
  if (to_save)
    *to_save = cookie;
  return true;
}

bool AlwaysFalseCookiePredicate(CanonicalCookie* to_save,
                                const CanonicalCookie& cookie) {
  if (to_save)
    *to_save = cookie;
  return false;
}

bool CookieValuePredicate(const std::string& true_value,
                          const CanonicalCookie& cookie) {
  return cookie.Value() == true_value;
}

struct CookieMonsterTestTraits {
  static std::unique_ptr<CookieStore> Create() {
    return base::MakeUnique<CookieMonster>(nullptr, nullptr);
  }

  static const bool supports_http_only = true;
  static const bool supports_non_dotted_domains = true;
  static const bool preserves_trailing_dots = true;
  static const bool filters_schemes = true;
  static const bool has_path_prefix_bug = false;
  static const bool forbids_setting_empty_name = false;
  static const int creation_time_granularity_in_ms = 0;
};

INSTANTIATE_TYPED_TEST_CASE_P(CookieMonster,
                              CookieStoreTest,
                              CookieMonsterTestTraits);

template <typename T>
class CookieMonsterTestBase : public CookieStoreTest<T> {
 public:
  using CookieStoreTest<T>::SetCookie;

 protected:
  using CookieStoreTest<T>::http_www_foo_;
  using CookieStoreTest<T>::https_www_foo_;

  CookieList GetAllCookiesForURLWithOptions(CookieMonster* cm,
                                            const GURL& url,
                                            const CookieOptions& options) {
    DCHECK(cm);
    GetCookieListCallback callback;
    cm->GetCookieListWithOptionsAsync(
        url, options,
        base::Bind(&GetCookieListCallback::Run, base::Unretained(&callback)));
    callback.WaitUntilDone();
    return callback.cookies();
  }

  bool SetAllCookies(CookieMonster* cm, const CookieList& list) {
    DCHECK(cm);
    ResultSavingCookieCallback<bool> callback;
    cm->SetAllCookiesAsync(list,
                           base::Bind(&ResultSavingCookieCallback<bool>::Run,
                                      base::Unretained(&callback)));
    callback.WaitUntilDone();
    return callback.result();
  }

  int DeleteAllCreatedBetween(CookieMonster* cm,
                              const base::Time& delete_begin,
                              const base::Time& delete_end) {
    DCHECK(cm);
    ResultSavingCookieCallback<int> callback;
    cm->DeleteAllCreatedBetweenAsync(
        delete_begin, delete_end,
        base::Bind(&ResultSavingCookieCallback<int>::Run,
                   base::Unretained(&callback)));
    callback.WaitUntilDone();
    return callback.result();
  }

  int DeleteAllCreatedBetweenWithPredicate(CookieMonster* cm,
                                           const base::Time delete_begin,
                                           const base::Time delete_end,
                                           const CookiePredicate& predicate) {
    DCHECK(cm);
    ResultSavingCookieCallback<int> callback;
    cm->DeleteAllCreatedBetweenWithPredicateAsync(
        delete_begin, delete_end, predicate,
        base::Bind(&ResultSavingCookieCallback<int>::Run,
                   base::Unretained(&callback)));
    callback.WaitUntilDone();
    return callback.result();
  }

  // Helper for PredicateSeesAllCookies test; repopulates CM with same layout
  // each time.
  void PopulateCmForPredicateCheck(CookieMonster* cm) {
    GURL url_top_level_domain_plus_1(kTopLevelDomainPlus1);
    GURL url_top_level_domain_plus_2(kTopLevelDomainPlus2);
    GURL url_top_level_domain_plus_2_secure(kTopLevelDomainPlus2Secure);
    GURL url_top_level_domain_plus_3(kTopLevelDomainPlus3);
    GURL url_other(kOtherDomain);

    this->DeleteAll(cm);

    // Static population for probe:
    //    * Three levels of domain cookie (.b.a, .c.b.a, .d.c.b.a)
    //    * Three levels of host cookie (w.b.a, w.c.b.a, w.d.c.b.a)
    //    * http_only cookie (w.c.b.a)
    //    * same_site cookie (w.c.b.a)
    //    * Two secure cookies (.c.b.a, w.c.b.a)
    //    * Two domain path cookies (.c.b.a/dir1, .c.b.a/dir1/dir2)
    //    * Two host path cookies (w.c.b.a/dir1, w.c.b.a/dir1/dir2)

    // Domain cookies
    EXPECT_TRUE(this->SetCookieWithDetails(
        cm, url_top_level_domain_plus_1, "dom_1", "A", ".harvard.edu", "/",
        base::Time(), base::Time(), base::Time(), false, false,
        CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));
    EXPECT_TRUE(this->SetCookieWithDetails(
        cm, url_top_level_domain_plus_2, "dom_2", "B", ".math.harvard.edu", "/",
        base::Time(), base::Time(), base::Time(), false, false,
        CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));
    EXPECT_TRUE(this->SetCookieWithDetails(
        cm, url_top_level_domain_plus_3, "dom_3", "C",
        ".bourbaki.math.harvard.edu", "/", base::Time(), base::Time(),
        base::Time(), false, false, CookieSameSite::DEFAULT_MODE,
        COOKIE_PRIORITY_DEFAULT));

    // Host cookies
    EXPECT_TRUE(this->SetCookieWithDetails(
        cm, url_top_level_domain_plus_1, "host_1", "A", std::string(), "/",
        base::Time(), base::Time(), base::Time(), false, false,
        CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));
    EXPECT_TRUE(this->SetCookieWithDetails(
        cm, url_top_level_domain_plus_2, "host_2", "B", std::string(), "/",
        base::Time(), base::Time(), base::Time(), false, false,
        CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));
    EXPECT_TRUE(this->SetCookieWithDetails(
        cm, url_top_level_domain_plus_3, "host_3", "C", std::string(), "/",
        base::Time(), base::Time(), base::Time(), false, false,
        CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));

    // http_only cookie
    EXPECT_TRUE(this->SetCookieWithDetails(
        cm, url_top_level_domain_plus_2, "httpo_check", "A", std::string(), "/",
        base::Time(), base::Time(), base::Time(), false, true,
        CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));

    // same-site cookie
    EXPECT_TRUE(this->SetCookieWithDetails(
        cm, url_top_level_domain_plus_2, "firstp_check", "A", std::string(),
        "/", base::Time(), base::Time(), base::Time(), false, false,
        CookieSameSite::STRICT_MODE, COOKIE_PRIORITY_DEFAULT));

    // Secure cookies
    EXPECT_TRUE(this->SetCookieWithDetails(
        cm, url_top_level_domain_plus_2_secure, "sec_dom", "A",
        ".math.harvard.edu", "/", base::Time(), base::Time(), base::Time(),
        true, false, CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));
    EXPECT_TRUE(this->SetCookieWithDetails(
        cm, url_top_level_domain_plus_2_secure, "sec_host", "B", std::string(),
        "/", base::Time(), base::Time(), base::Time(), true, false,
        CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));

    // Domain path cookies
    EXPECT_TRUE(this->SetCookieWithDetails(
        cm, url_top_level_domain_plus_2, "dom_path_1", "A", ".math.harvard.edu",
        "/dir1", base::Time(), base::Time(), base::Time(), false, false,
        CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));
    EXPECT_TRUE(this->SetCookieWithDetails(
        cm, url_top_level_domain_plus_2, "dom_path_2", "B", ".math.harvard.edu",
        "/dir1/dir2", base::Time(), base::Time(), base::Time(), false, false,
        CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));

    // Host path cookies
    EXPECT_TRUE(this->SetCookieWithDetails(
        cm, url_top_level_domain_plus_2, "host_path_1", "A", std::string(),
        "/dir1", base::Time(), base::Time(), base::Time(), false, false,
        CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));
    EXPECT_TRUE(this->SetCookieWithDetails(
        cm, url_top_level_domain_plus_2, "host_path_2", "B", std::string(),
        "/dir1/dir2", base::Time(), base::Time(), base::Time(), false, false,
        CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));

    EXPECT_EQ(14U, this->GetAllCookies(cm).size());
  }

  Time GetFirstCookieAccessDate(CookieMonster* cm) {
    const CookieList all_cookies(this->GetAllCookies(cm));
    return all_cookies.front().LastAccessDate();
  }

  bool FindAndDeleteCookie(CookieMonster* cm,
                           const std::string& domain,
                           const std::string& name) {
    CookieList cookies = this->GetAllCookies(cm);
    for (CookieList::iterator it = cookies.begin(); it != cookies.end(); ++it)
      if (it->Domain() == domain && it->Name() == name)
        return this->DeleteCanonicalCookie(cm, *it);
    return false;
  }

  int CountInString(const std::string& str, char c) {
    return std::count(str.begin(), str.end(), c);
  }

  void TestHostGarbageCollectHelper() {
    int domain_max_cookies = CookieMonster::kDomainMaxCookies;
    int domain_purge_cookies = CookieMonster::kDomainPurgeCookies;
    const int more_than_enough_cookies =
        (domain_max_cookies + domain_purge_cookies) * 2;
    // Add a bunch of cookies on a single host, should purge them.
    {
      std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));
      for (int i = 0; i < more_than_enough_cookies; ++i) {
        std::string cookie = base::StringPrintf("a%03d=b", i);
        EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), cookie));
        std::string cookies = this->GetCookies(cm.get(), http_www_foo_.url());
        // Make sure we find it in the cookies.
        EXPECT_NE(cookies.find(cookie), std::string::npos);
        // Count the number of cookies.
        EXPECT_LE(CountInString(cookies, '='), domain_max_cookies);
      }
    }

    // Add a bunch of cookies on multiple hosts within a single eTLD.
    // Should keep at least kDomainMaxCookies - kDomainPurgeCookies
    // between them.  We shouldn't go above kDomainMaxCookies for both together.
    GURL url_google_specific(http_www_foo_.Format("http://www.gmail.%D"));
    {
      std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));
      for (int i = 0; i < more_than_enough_cookies; ++i) {
        std::string cookie_general = base::StringPrintf("a%03d=b", i);
        EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), cookie_general));
        std::string cookie_specific = base::StringPrintf("c%03d=b", i);
        EXPECT_TRUE(SetCookie(cm.get(), url_google_specific, cookie_specific));
        std::string cookies_general =
            this->GetCookies(cm.get(), http_www_foo_.url());
        EXPECT_NE(cookies_general.find(cookie_general), std::string::npos);
        std::string cookies_specific =
            this->GetCookies(cm.get(), url_google_specific);
        EXPECT_NE(cookies_specific.find(cookie_specific), std::string::npos);
        EXPECT_LE((CountInString(cookies_general, '=') +
                   CountInString(cookies_specific, '=')),
                  domain_max_cookies);
      }
      // After all this, there should be at least
      // kDomainMaxCookies - kDomainPurgeCookies for both URLs.
      std::string cookies_general =
          this->GetCookies(cm.get(), http_www_foo_.url());
      std::string cookies_specific =
          this->GetCookies(cm.get(), url_google_specific);
      int total_cookies = (CountInString(cookies_general, '=') +
                           CountInString(cookies_specific, '='));
      EXPECT_GE(total_cookies, domain_max_cookies - domain_purge_cookies);
      EXPECT_LE(total_cookies, domain_max_cookies);
    }
  }

  CookiePriority CharToPriority(char ch) {
    switch (ch) {
      case 'L':
        return COOKIE_PRIORITY_LOW;
      case 'M':
        return COOKIE_PRIORITY_MEDIUM;
      case 'H':
        return COOKIE_PRIORITY_HIGH;
    }
    NOTREACHED();
    return COOKIE_PRIORITY_DEFAULT;
  }

  // Instantiates a CookieMonster, adds multiple cookies (to http_www_foo_)
  // with priorities specified by |coded_priority_str|, and tests priority-aware
  // domain cookie eviction.
  //
  // Example: |coded_priority_string| of "2MN 3LS MN 4HN" specifies sequential
  // (i.e., from least- to most-recently accessed) insertion of 2
  // medium-priority non-secure cookies, 3 low-priority secure cookies, 1
  // medium-priority non-secure cookie, and 4 high-priority non-secure cookies.
  //
  // Within each priority, only the least-accessed cookies should be evicted.
  // Thus, to describe expected suriving cookies, it suffices to specify the
  // expected population of surviving cookies per priority, i.e.,
  // |expected_low_count|, |expected_medium_count|, and |expected_high_count|.
  void TestPriorityCookieCase(CookieMonster* cm,
                              const std::string& coded_priority_str,
                              size_t expected_low_count,
                              size_t expected_medium_count,
                              size_t expected_high_count,
                              size_t expected_nonsecure,
                              size_t expected_secure) {
    SCOPED_TRACE(coded_priority_str);
    this->DeleteAll(cm);
    int next_cookie_id = 0;
    // A list of cookie IDs, indexed by secure status, then by priority.
    std::vector<int> id_list[2][3];
    // A list of all the cookies stored, along with their properties.
    std::vector<std::pair<bool, CookiePriority>> cookie_data;

    // Parse |coded_priority_str| and add cookies.
    for (const std::string& token :
         base::SplitString(coded_priority_str, " ", base::TRIM_WHITESPACE,
                           base::SPLIT_WANT_ALL)) {
      DCHECK(!token.empty());

      bool is_secure = token.back() == 'S';

      // The second-to-last character is the priority. Grab and discard it.
      CookiePriority priority = CharToPriority(token[token.size() - 2]);

      // Discard the security status and priority tokens. The rest of the string
      // (possibly empty) specifies repetition.
      int rep = 1;
      if (!token.empty()) {
        bool result = base::StringToInt(
            base::StringPiece(token.begin(), token.end() - 2), &rep);
        DCHECK(result);
      }
      for (; rep > 0; --rep, ++next_cookie_id) {
        std::string cookie =
            base::StringPrintf("a%d=b;priority=%s;%s", next_cookie_id,
                               CookiePriorityToString(priority).c_str(),
                               is_secure ? "secure" : "");
        EXPECT_TRUE(SetCookie(cm, https_www_foo_.url(), cookie));
        cookie_data.push_back(std::make_pair(is_secure, priority));
        id_list[is_secure][priority].push_back(next_cookie_id);
      }
    }

    int num_cookies = static_cast<int>(cookie_data.size());
    // A list of cookie IDs, indexed by secure status, then by priority.
    std::vector<int> surviving_id_list[2][3];

    // Parse the list of cookies
    std::string cookie_str = this->GetCookies(cm, https_www_foo_.url());
    size_t num_nonsecure = 0;
    size_t num_secure = 0;
    for (const std::string& token : base::SplitString(
             cookie_str, ";", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL)) {
      // Assuming *it is "a#=b", so extract and parse "#" portion.
      int id = -1;
      bool result = base::StringToInt(
          base::StringPiece(token.begin() + 1, token.end() - 2), &id);
      DCHECK(result);
      DCHECK_GE(id, 0);
      DCHECK_LT(id, num_cookies);
      surviving_id_list[cookie_data[id].first][cookie_data[id].second]
          .push_back(id);
      if (cookie_data[id].first)
        num_secure += 1;
      else
        num_nonsecure += 1;
    }

    EXPECT_EQ(expected_nonsecure, num_nonsecure);
    EXPECT_EQ(expected_secure, num_secure);

    // Validate each priority.
    size_t expected_count[3] = {
        expected_low_count, expected_medium_count, expected_high_count};
    for (int i = 0; i < 3; ++i) {
      size_t num_for_priority =
          surviving_id_list[0][i].size() + surviving_id_list[1][i].size();
      EXPECT_EQ(expected_count[i], num_for_priority);
      // Verify that the remaining cookies are the most recent among those
      // with the same priorities.
      if (expected_count[i] == num_for_priority) {
        // Non-secure:
        std::sort(surviving_id_list[0][i].begin(),
                  surviving_id_list[0][i].end());
        EXPECT_TRUE(std::equal(
            surviving_id_list[0][i].begin(), surviving_id_list[0][i].end(),
            id_list[0][i].end() - surviving_id_list[0][i].size()));

        // Secure:
        std::sort(surviving_id_list[1][i].begin(),
                  surviving_id_list[1][i].end());
        EXPECT_TRUE(std::equal(
            surviving_id_list[1][i].begin(), surviving_id_list[1][i].end(),
            id_list[1][i].end() - surviving_id_list[1][i].size()));
      }
    }
  }

  // Represents a number of cookies to create, if they are Secure cookies, and
  // a url to add them to.
  struct CookiesEntry {
    size_t num_cookies;
    bool is_secure;
  };
  // A number of secure and a number of non-secure alternative hosts to create
  // for testing.
  typedef std::pair<size_t, size_t> AltHosts;
  // Takes an array of CookieEntries which specify the number, type, and order
  // of cookies to create. Cookies are created in the order they appear in
  // cookie_entries. The value of cookie_entries[x].num_cookies specifies how
  // many cookies of that type to create consecutively, while if
  // cookie_entries[x].is_secure is |true|, those cookies will be marke as
  // Secure.
  void TestSecureCookieEviction(const CookiesEntry* cookie_entries,
                                size_t num_cookie_entries,
                                size_t expected_secure_cookies,
                                size_t expected_non_secure_cookies,
                                const AltHosts* alt_host_entries) {
    std::unique_ptr<CookieMonster> cm;

    if (alt_host_entries == nullptr) {
      cm.reset(new CookieMonster(nullptr, nullptr));
    } else {
      // When generating all of these cookies on alternate hosts, they need to
      // be all older than the max "safe" date for GC, which is currently 30
      // days, so we set them to 60.
      cm = CreateMonsterFromStoreForGC(
          alt_host_entries->first, alt_host_entries->first,
          alt_host_entries->second, alt_host_entries->second, 60);
    }

    int next_cookie_id = 0;
    for (size_t i = 0; i < num_cookie_entries; i++) {
      for (size_t j = 0; j < cookie_entries[i].num_cookies; j++) {
        std::string cookie;
        if (cookie_entries[i].is_secure)
          cookie = base::StringPrintf("a%d=b; Secure", next_cookie_id);
        else
          cookie = base::StringPrintf("a%d=b", next_cookie_id);
        EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(), cookie));
        ++next_cookie_id;
      }
    }

    CookieList cookies = this->GetAllCookies(cm.get());
    EXPECT_EQ(expected_secure_cookies + expected_non_secure_cookies,
              cookies.size());
    size_t total_secure_cookies = 0;
    size_t total_non_secure_cookies = 0;
    for (const auto& cookie : cookies) {
      if (cookie.IsSecure())
        ++total_secure_cookies;
      else
        ++total_non_secure_cookies;
    }

    EXPECT_EQ(expected_secure_cookies, total_secure_cookies);
    EXPECT_EQ(expected_non_secure_cookies, total_non_secure_cookies);
  }

  void TestPriorityAwareGarbageCollectHelperNonSecure() {
    // Hard-coding limits in the test, but use DCHECK_EQ to enforce constraint.
    DCHECK_EQ(180U, CookieMonster::kDomainMaxCookies);
    DCHECK_EQ(150U, CookieMonster::kDomainMaxCookies -
                        CookieMonster::kDomainPurgeCookies);

    std::unique_ptr<CookieMonster> cm(new CookieMonster(NULL, NULL));

    // Each test case adds 181 cookies, so 31 cookies are evicted.
    // Cookie same priority, repeated for each priority.
    TestPriorityCookieCase(cm.get(), "181LN", 150U, 0U, 0U, 150U, 0U);
    TestPriorityCookieCase(cm.get(), "181MN", 0U, 150U, 0U, 150U, 0U);
    TestPriorityCookieCase(cm.get(), "181HN", 0U, 0U, 150U, 150U, 0U);

    // Pairwise scenarios.
    // Round 1 => none; round2 => 31M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "10HN 171MN", 0U, 140U, 10U, 150U, 0U);
    // Round 1 => 10L; round2 => 21M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "141MN 40LN", 30U, 120U, 0U, 150U, 0U);
    // Round 1 => none; round2 => 30M; round 3 => 1H.
    TestPriorityCookieCase(cm.get(), "101HN 80MN", 0U, 50U, 100U, 150U, 0U);

    // For {low, medium} priorities right on quota, different orders.
    // Round 1 => 1L; round 2 => none, round3 => 30H.
    TestPriorityCookieCase(cm.get(), "31LN 50MN 100HN", 30U, 50U, 70U, 150U,
                           0U);
    // Round 1 => none; round 2 => 1M, round3 => 30H.
    TestPriorityCookieCase(cm.get(), "51MN 100HN 30LN", 30U, 50U, 70U, 150U,
                           0U);
    // Round 1 => none; round 2 => none; round3 => 31H.
    TestPriorityCookieCase(cm.get(), "101HN 50MN 30LN", 30U, 50U, 70U, 150U,
                           0U);

    // Round 1 => 10L; round 2 => 10M; round3 => 11H.
    TestPriorityCookieCase(cm.get(), "81HN 60MN 40LN", 30U, 50U, 70U, 150U, 0U);

    // More complex scenarios.
    // Round 1 => 10L; round 2 => 10M; round 3 => 11H.
    TestPriorityCookieCase(cm.get(), "21HN 60MN 40LN 60HN", 30U, 50U, 70U, 150U,
                           0U);
    // Round 1 => 10L; round 2 => 21M; round 3 => 0H.
    TestPriorityCookieCase(cm.get(), "11HN 10MN 20LN 110MN 20LN 10HN", 30U, 99U,
                           21U, 150U, 0U);
    // Round 1 => none; round 2 => none; round 3 => 31H.
    TestPriorityCookieCase(cm.get(), "11LN 10MN 140HN 10MN 10LN", 21U, 20U,
                           109U, 150U, 0U);
    // Round 1 => none; round 2 => 21M; round 3 => 10H.
    TestPriorityCookieCase(cm.get(), "11MN 10HN 10LN 60MN 90HN", 10U, 50U, 90U,
                           150U, 0U);
    // Round 1 => none; round 2 => 31M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "11MN 10HN 10LN 90MN 60HN", 10U, 70U, 70U,
                           150U, 0U);

    // Round 1 => 20L; round 2 => 0; round 3 => 11H
    TestPriorityCookieCase(cm.get(), "50LN 131HN", 30U, 0U, 120U, 150U, 0U);
    // Round 1 => 20L; round 2 => 0; round 3 => 11H
    TestPriorityCookieCase(cm.get(), "131HN 50LN", 30U, 0U, 120U, 150U, 0U);
    // Round 1 => 20L; round 2 => none; round 3 => 11H.
    TestPriorityCookieCase(cm.get(), "50HN 50LN 81HN", 30U, 0U, 120U, 150U, 0U);
    // Round 1 => 20L; round 2 => none; round 3 => 11H.
    TestPriorityCookieCase(cm.get(), "81HN 50LN 50HN", 30U, 0U, 120U, 150U, 0U);
  }

  void TestPriorityAwareGarbageCollectHelperSecure() {
    // Hard-coding limits in the test, but use DCHECK_EQ to enforce constraint.
    DCHECK_EQ(180U, CookieMonster::kDomainMaxCookies);
    DCHECK_EQ(150U, CookieMonster::kDomainMaxCookies -
                        CookieMonster::kDomainPurgeCookies);

    std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));

    // Each test case adds 181 cookies, so 31 cookies are evicted.
    // Cookie same priority, repeated for each priority.
    // Round 1 => 31L; round2 => none; round 3 => none.
    TestPriorityCookieCase(cm.get(), "181LS", 150U, 0U, 0U, 0U, 150U);
    // Round 1 => none; round2 => 31M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "181MS", 0U, 150U, 0U, 0U, 150U);
    // Round 1 => none; round2 => none; round 3 => 31H.
    TestPriorityCookieCase(cm.get(), "181HS", 0U, 0U, 150U, 0U, 150U);

    // Pairwise scenarios.
    // Round 1 => none; round2 => 31M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "10HS 171MS", 0U, 140U, 10U, 0U, 150U);
    // Round 1 => 10L; round2 => 21M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "141MS 40LS", 30U, 120U, 0U, 0U, 150U);
    // Round 1 => none; round2 => 30M; round 3 => 1H.
    TestPriorityCookieCase(cm.get(), "101HS 80MS", 0U, 50U, 100U, 0U, 150U);

    // For {low, medium} priorities right on quota, different orders.
    // Round 1 => 1L; round 2 => none, round3 => 30H.
    TestPriorityCookieCase(cm.get(), "31LS 50MS 100HS", 30U, 50U, 70U, 0U,
                           150U);
    // Round 1 => none; round 2 => 1M, round3 => 30H.
    TestPriorityCookieCase(cm.get(), "51MS 100HS 30LS", 30U, 50U, 70U, 0U,
                           150U);
    // Round 1 => none; round 2 => none; round3 => 31H.
    TestPriorityCookieCase(cm.get(), "101HS 50MS 30LS", 30U, 50U, 70U, 0U,
                           150U);

    // Round 1 => 10L; round 2 => 10M; round3 => 11H.
    TestPriorityCookieCase(cm.get(), "81HS 60MS 40LS", 30U, 50U, 70U, 0U, 150U);

    // More complex scenarios.
    // Round 1 => 10L; round 2 => 10M; round 3 => 11H.
    TestPriorityCookieCase(cm.get(), "21HS 60MS 40LS 60HS", 30U, 50U, 70U, 0U,
                           150U);
    // Round 1 => 10L; round 2 => 21M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "11HS 10MS 20LS 110MS 20LS 10HS", 30U, 99U,
                           21U, 0U, 150U);
    // Round 1 => none; round 2 => none; round 3 => 31H.
    TestPriorityCookieCase(cm.get(), "11LS 10MS 140HS 10MS 10LS", 21U, 20U,
                           109U, 0U, 150U);
    // Round 1 => none; round 2 => 21M; round 3 => 10H.
    TestPriorityCookieCase(cm.get(), "11MS 10HS 10LS 60MS 90HS", 10U, 50U, 90U,
                           0U, 150U);
    // Round 1 => none; round 2 => 31M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "11MS 10HS 10LS 90MS 60HS", 10U, 70U, 70U,
                           0U, 150U);
  }

  void TestPriorityAwareGarbageCollectHelperMixed() {
    // Hard-coding limits in the test, but use DCHECK_EQ to enforce constraint.
    DCHECK_EQ(180U, CookieMonster::kDomainMaxCookies);
    DCHECK_EQ(150U, CookieMonster::kDomainMaxCookies -
                        CookieMonster::kDomainPurgeCookies);

    std::unique_ptr<CookieMonster> cm(new CookieMonster(NULL, NULL));

    // Each test case adds 180 secure cookies, and some non-secure cookie. The
    // secure cookies take priority, so the non-secure cookie is removed, along
    // with 30 secure cookies. Repeated for each priority, and with the
    // non-secure cookie as older and newer.
    // Round 1 => 1LN; round 2 => 30LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "1LN 180LS", 150U, 0U, 0U, 0U, 150U);
    // Round 1 => none; round 2 => none; round 3 => 1MN.
    // Round 4 => none; round 5 => 30MS; round 6 => none.
    TestPriorityCookieCase(cm.get(), "1MN 180MS", 0U, 150U, 0U, 0U, 150U);
    // Round 1 => none; round 2 => none; round 3 => none.
    // Round 4 => 1HN; round 5 => none; round 6 => 30HS.
    TestPriorityCookieCase(cm.get(), "1HN 180HS", 0U, 0U, 150U, 0U, 150U);
    // Round 1 => 1LN; round 2 => 30LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "180LS 1LN", 150U, 0U, 0U, 0U, 150U);
    // Round 1 => none; round 2 => none; round 3 => 1MN.
    // Round 4 => none; round 5 => 30MS; round 6 => none.
    TestPriorityCookieCase(cm.get(), "180MS 1MN", 0U, 150U, 0U, 0U, 150U);
    // Round 1 => none; round 2 => none; round 3 => none.
    // Round 4 => 1HN; round 5 => none; round 6 => 30HS.
    TestPriorityCookieCase(cm.get(), "180HS 1HN", 0U, 0U, 150U, 0U, 150U);

    // Low-priority secure cookies are removed before higher priority non-secure
    // cookies.
    // Round 1 => none; round 2 => 31LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "180LS 1MN", 149U, 1U, 0U, 1U, 149U);
    // Round 1 => none; round 2 => 31LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "180LS 1HN", 149U, 0U, 1U, 1U, 149U);
    // Round 1 => none; round 2 => 31LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "1MN 180LS", 149U, 1U, 0U, 1U, 149U);
    // Round 1 => none; round 2 => 31LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "1HN 180LS", 149U, 0U, 1U, 1U, 149U);

    // Higher-priority non-secure cookies are removed before any secure cookie
    // with greater than low-priority. Is it true? How about the quota?
    // Round 1 => none; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => 31MS; round 6 => none.
    TestPriorityCookieCase(cm.get(), "180MS 1HN", 0U, 149U, 1U, 1U, 149U);
    // Round 1 => none; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => 31MS; round 6 => none.
    TestPriorityCookieCase(cm.get(), "1HN 180MS", 0U, 149U, 1U, 1U, 149U);

    // Pairwise:
    // Round 1 => 31LN; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "1LS 180LN", 150U, 0U, 0U, 149U, 1U);
    // Round 1 => 31LN; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "100LS 81LN", 150U, 0U, 0U, 50U, 100U);
    // Round 1 => 31LN; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "150LS 31LN", 150U, 0U, 0U, 0U, 150U);
    // Round 1 => none; round 2 => none; round 3 => none.
    // Round 4 => 31HN; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "1LS 180HN", 1U, 0U, 149U, 149U, 1U);
    // Round 1 => none; round 2 => 31LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "100LS 81HN", 69U, 0U, 81U, 81U, 69U);
    // Round 1 => none; round 2 => 31LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "150LS 31HN", 119U, 0U, 31U, 31U, 119U);

    // Quota calculations inside non-secure/secure blocks remain in place:
    // Round 1 => none; round 2 => 20LS; round 3 => none.
    // Round 4 => 11HN; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "50HN 50LS 81HS", 30U, 0U, 120U, 39U,
                           111U);
    // Round 1 => none; round 2 => none; round 3 => 31MN.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "11MS 10HN 10LS 90MN 60HN", 10U, 70U, 70U,
                           129U, 21U);
    // Round 1 => 31LN; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "40LS 40LN 101HS", 49U, 0U, 101U, 9U,
                           141U);

    // Multiple GC rounds end up with consistent behavior:
    // GC is started as soon as there are 181 cookies in the store.
    // On each major round it tries to preserve the quota for each priority.
    // It is not aware about more cookies going in.
    // 1 GC notices there are 181 cookies - 100HS 81LN 0MN
    // Round 1 => 31LN; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    // 2 GC notices there are 181 cookies - 100HS 69LN 12MN
    // Round 1 => 31LN; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    // 3 GC notices there are 181 cookies - 100HS 38LN 43MN
    // Round 1 =>  8LN; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => 23HS.
    // 4 GC notcies there are 181 cookies - 77HS 30LN 74MN
    // Round 1 => none; round 2 => none; round 3 => 24MN.
    // Round 4 => none; round 5 => none; round 6 =>  7HS.
    TestPriorityCookieCase(cm.get(), "100HS 100LN 100MN", 30U, 76U, 70U, 106U,
                           70U);
  }

  // Function for creating a CM with a number of cookies in it,
  // no store (and hence no ability to affect access time).
  CookieMonster* CreateMonsterForGC(int num_cookies) {
    CookieMonster* cm(new CookieMonster(NULL, NULL));
    for (int i = 0; i < num_cookies; i++) {
      SetCookie(cm, GURL(base::StringPrintf("http://h%05d.izzle", i)), "a=1");
    }
    return cm;
  }

  bool IsCookieInList(const CanonicalCookie& cookie, const CookieList& list) {
    for (CookieList::const_iterator it = list.begin(); it != list.end(); ++it) {
      if (it->Name() == cookie.Name() && it->Value() == cookie.Value() &&
          it->Domain() == cookie.Domain() && it->Path() == cookie.Path() &&
          it->CreationDate() == cookie.CreationDate() &&
          it->ExpiryDate() == cookie.ExpiryDate() &&
          it->LastAccessDate() == cookie.LastAccessDate() &&
          it->IsSecure() == cookie.IsSecure() &&
          it->IsHttpOnly() == cookie.IsHttpOnly() &&
          it->Priority() == cookie.Priority()) {
        return true;
      }
    }

    return false;
  }
};

using CookieMonsterTest = CookieMonsterTestBase<CookieMonsterTestTraits>;

// TODO(erikwright): Replace the other callbacks and synchronous helper methods
// in this test suite with these Mocks.
using MockClosure = base::MockCallback<base::Closure>;
using MockGetCookiesCallback =
    base::MockCallback<CookieStore::GetCookiesCallback>;
using MockSetCookiesCallback =
    base::MockCallback<CookieStore::SetCookiesCallback>;
using MockGetCookieListCallback =
    base::MockCallback<CookieMonster::GetCookieListCallback>;
using MockDeleteCallback = base::MockCallback<CookieMonster::DeleteCallback>;

struct CookiesInputInfo {
  const GURL url;
  const std::string name;
  const std::string value;
  const std::string domain;
  const std::string path;
  const base::Time expiration_time;
  bool secure;
  bool http_only;
  CookieSameSite same_site;
  CookiePriority priority;
};

ACTION_P(QuitRunLoop, run_loop) {
  run_loop->Quit();
}

// TODO(erikwright): When the synchronous helpers 'GetCookies' etc. are removed,
// rename these, removing the 'Action' suffix.
ACTION_P4(DeleteCookieAction, cookie_monster, url, name, callback) {
  cookie_monster->DeleteCookieAsync(url, name, callback->Get());
}
ACTION_P3(GetCookiesAction, cookie_monster, url, callback) {
  cookie_monster->GetCookiesWithOptionsAsync(url, CookieOptions(),
                                             callback->Get());
}
ACTION_P4(SetCookieAction, cookie_monster, url, cookie_line, callback) {
  cookie_monster->SetCookieWithOptionsAsync(url, cookie_line, CookieOptions(),
                                            callback->Get());
}
ACTION_P3(SetAllCookiesAction, cookie_monster, list, callback) {
  cookie_monster->SetAllCookiesAsync(list, callback->Get());
}
ACTION_P4(DeleteAllCreatedBetweenAction,
          cookie_monster,
          delete_begin,
          delete_end,
          callback) {
  cookie_monster->DeleteAllCreatedBetweenAsync(delete_begin, delete_end,
                                               callback->Get());
}
ACTION_P3(SetCookieWithDetailsAction, cookie_monster, cc, callback) {
  cookie_monster->SetCookieWithDetailsAsync(
      cc.url, cc.name, cc.value, cc.domain, cc.path, base::Time(),
      cc.expiration_time, base::Time(), cc.secure, cc.http_only, cc.same_site,
      cc.priority, callback->Get());
}

ACTION_P2(GetAllCookiesAction, cookie_monster, callback) {
  cookie_monster->GetAllCookiesAsync(callback->Get());
}

ACTION_P5(DeleteAllCreatedBetweenWithPredicateAction,
          cookie_monster,
          delete_begin,
          delete_end,
          predicate,
          callback) {
  cookie_monster->DeleteAllCreatedBetweenWithPredicateAsync(
      delete_begin, delete_end, predicate, callback->Get());
}

ACTION_P3(DeleteCanonicalCookieAction, cookie_monster, cookie, callback) {
  cookie_monster->DeleteCanonicalCookieAsync(cookie, callback->Get());
}

ACTION_P2(DeleteAllAction, cookie_monster, callback) {
  cookie_monster->DeleteAllAsync(callback->Get());
}

ACTION_P3(GetCookieListForUrlWithOptionsAction, cookie_monster, url, callback) {
  cookie_monster->GetCookieListWithOptionsAsync(url, CookieOptions(),
                                                callback->Get());
}

ACTION_P3(GetAllCookiesForUrlAction, cookie_monster, url, callback) {
  cookie_monster->GetAllCookiesForURLAsync(url, callback->Get());
}

ACTION_P(PushCallbackAction, callback_vector) {
  callback_vector->push(arg1);
}

ACTION_P2(DeleteSessionCookiesAction, cookie_monster, callback) {
  cookie_monster->DeleteSessionCookiesAsync(callback->Get());
}

}  // namespace

// This test suite verifies the task deferral behaviour of the CookieMonster.
// Specifically, for each asynchronous method, verify that:
// 1. invoking it on an uninitialized cookie store causes the store to begin
//    chain-loading its backing data or loading data for a specific domain key
//    (eTLD+1).
// 2. The initial invocation does not complete until the loading completes.
// 3. Invocations after the loading has completed complete immediately.
class DeferredCookieTaskTest : public CookieMonsterTest {
 protected:
  DeferredCookieTaskTest() : expect_load_called_(false) {
    persistent_store_ = new NewMockPersistentCookieStore();
    cookie_monster_.reset(new CookieMonster(persistent_store_.get(), nullptr));
  }

  // Defines a cookie to be returned from PersistentCookieStore::Load
  void DeclareLoadedCookie(const GURL& url,
                           const std::string& cookie_line,
                           const base::Time& creation_time) {
    AddCookieToList(url, cookie_line, creation_time, &loaded_cookies_);
  }

  // Runs the message loop, waiting until PersistentCookieStore::Load is called.
  // Call CompleteLoading to cause the load to complete.
  void WaitForLoadCall() {
    load_run_loop_.Run();

    // Verify that PeristentStore::Load was called.
    testing::Mock::VerifyAndClear(persistent_store_.get());
  }

  // Invokes the PersistentCookieStore::LoadCookiesForKey completion callbacks
  // and PersistentCookieStore::Load completion callback.
  void CompleteLoading() {
    while (!loaded_for_key_callbacks_.empty()) {
      loaded_for_key_callbacks_.front().Run(std::move(loaded_cookies_));
      loaded_cookies_.clear();
      loaded_for_key_callbacks_.pop();
    }
    loaded_callback_.Run(std::move(loaded_cookies_));
  }

  // Performs the provided action, expecting it to cause a call to
  // PersistentCookieStore::Load. Call WaitForLoadCall to verify the load call
  // is received.
  void BeginWith(testing::Action<void(void)> action) {
    EXPECT_CALL(*this, Begin()).WillOnce(action);
    ExpectLoadCall();
    Begin();
  }

  void BeginWithForDomainKey(std::string key,
                             testing::Action<void(void)> action) {
    EXPECT_CALL(*this, Begin()).WillOnce(action);
    ExpectLoadCall();
    ExpectLoadForKeyCall(key);
    Begin();
  }

  // Declares an expectation that PersistentCookieStore::Load will be called,
  // saving the provided callback and sending a quit to |load_run_loop_|.
  void ExpectLoadCall() {
    // Make sure the |load_run_loop_| is not reused.
    CHECK(!expect_load_called_);
    expect_load_called_ = true;
    EXPECT_CALL(*persistent_store_.get(), Load(testing::_))
        .WillOnce(testing::DoAll(testing::SaveArg<0>(&loaded_callback_),
                                 QuitRunLoop(&load_run_loop_)));
  }

  // Declares an expectation that PersistentCookieStore::LoadCookiesForKey
  // will be called, saving the provided callback.
  void ExpectLoadForKeyCall(const std::string& key) {
    EXPECT_CALL(*persistent_store_.get(), LoadCookiesForKey(key, testing::_))
        .WillOnce(PushCallbackAction(&loaded_for_key_callbacks_));
  }

  // Invokes the initial action.
  MOCK_METHOD0(Begin, void(void));

  // Returns the CookieMonster instance under test.
  CookieMonster& cookie_monster() { return *cookie_monster_.get(); }

 private:
  // Declares that mock expectations in this test suite are strictly ordered.
  testing::InSequence in_sequence_;
  // Holds cookies to be returned from PersistentCookieStore::Load or
  // PersistentCookieStore::LoadCookiesForKey.
  std::vector<std::unique_ptr<CanonicalCookie>> loaded_cookies_;
  // Stores the callback passed from the CookieMonster to the
  // PersistentCookieStore::Load
  CookieMonster::PersistentCookieStore::LoadedCallback loaded_callback_;
  // Stores the callback passed from the CookieMonster to the
  // PersistentCookieStore::LoadCookiesForKey
  std::queue<CookieMonster::PersistentCookieStore::LoadedCallback>
      loaded_for_key_callbacks_;
  // base::RunLoop used to wait for PersistentCookieStore::Load to be called.
  base::RunLoop load_run_loop_;
  // Indicates whether ExpectLoadCall() has been called.
  bool expect_load_called_;
  // Stores the CookieMonster under test.
  std::unique_ptr<CookieMonster> cookie_monster_;
  // Stores the mock PersistentCookieStore.
  scoped_refptr<NewMockPersistentCookieStore> persistent_store_;
};

TEST_F(DeferredCookieTaskTest, DeferredGetCookies) {
  DeclareLoadedCookie(http_www_foo_.url(),
                      "X=1; path=/; expires=Mon, 18-Apr-22 22:50:14 GMT",
                      Time::Now() + TimeDelta::FromDays(3));

  MockGetCookiesCallback get_cookies_callback;

  BeginWithForDomainKey(http_www_foo_.domain(),
                        GetCookiesAction(&cookie_monster(), http_www_foo_.url(),
                                         &get_cookies_callback));

  WaitForLoadCall();

  EXPECT_CALL(get_cookies_callback, Run("X=1"))
      .WillOnce(GetCookiesAction(&cookie_monster(), http_www_foo_.url(),
                                 &get_cookies_callback));
  base::RunLoop loop;
  EXPECT_CALL(get_cookies_callback, Run("X=1")).WillOnce(QuitRunLoop(&loop));

  CompleteLoading();
  loop.Run();
}

TEST_F(DeferredCookieTaskTest, DeferredSetCookie) {
  MockSetCookiesCallback set_cookies_callback;

  BeginWithForDomainKey(http_www_foo_.domain(),
                        SetCookieAction(&cookie_monster(), http_www_foo_.url(),
                                        "A=B", &set_cookies_callback));

  WaitForLoadCall();

  EXPECT_CALL(set_cookies_callback, Run(true))
      .WillOnce(SetCookieAction(&cookie_monster(), http_www_foo_.url(), "X=Y",
                                &set_cookies_callback));
  base::RunLoop loop;
  EXPECT_CALL(set_cookies_callback, Run(true)).WillOnce(QuitRunLoop(&loop));

  CompleteLoading();
  loop.Run();
}

TEST_F(DeferredCookieTaskTest, DeferredSetAllCookies) {
  MockSetCookiesCallback set_cookies_callback;
  CookieList list;
  list.push_back(CanonicalCookie("A", "B", "." + http_www_foo_.domain(), "/",
                                 base::Time::Now(), base::Time(), base::Time(),
                                 false, true, CookieSameSite::DEFAULT_MODE,
                                 COOKIE_PRIORITY_DEFAULT));
  list.push_back(CanonicalCookie("C", "D", "." + http_www_foo_.domain(), "/",
                                 base::Time::Now(), base::Time(), base::Time(),
                                 false, true, CookieSameSite::DEFAULT_MODE,
                                 COOKIE_PRIORITY_DEFAULT));

  BeginWith(
      SetAllCookiesAction(&cookie_monster(), list, &set_cookies_callback));

  WaitForLoadCall();

  EXPECT_CALL(set_cookies_callback, Run(true))
      .WillOnce(
          SetAllCookiesAction(&cookie_monster(), list, &set_cookies_callback));
  base::RunLoop loop;
  EXPECT_CALL(set_cookies_callback, Run(true)).WillOnce(QuitRunLoop(&loop));

  CompleteLoading();
  loop.Run();
}

TEST_F(DeferredCookieTaskTest, DeferredDeleteCookie) {
  MockClosure delete_cookie_callback;

  BeginWithForDomainKey(
      http_www_foo_.domain(),
      DeleteCookieAction(&cookie_monster(), http_www_foo_.url(), "A",
                         &delete_cookie_callback));

  WaitForLoadCall();

  EXPECT_CALL(delete_cookie_callback, Run())
      .WillOnce(DeleteCookieAction(&cookie_monster(), http_www_foo_.url(), "X",
                                   &delete_cookie_callback));
  base::RunLoop loop;
  EXPECT_CALL(delete_cookie_callback, Run()).WillOnce(QuitRunLoop(&loop));

  CompleteLoading();
  loop.Run();
}

TEST_F(DeferredCookieTaskTest, DeferredSetCookieWithDetails) {
  MockSetCookiesCallback set_cookies_callback;

  CookiesInputInfo cookie_info = {www_foo_foo_.url(),
                                  "A",
                                  "B",
                                  std::string(),
                                  "/foo",
                                  base::Time(),
                                  false,
                                  false,
                                  CookieSameSite::DEFAULT_MODE,
                                  COOKIE_PRIORITY_DEFAULT};
  BeginWithForDomainKey(
      http_www_foo_.domain(),
      SetCookieWithDetailsAction(&cookie_monster(), cookie_info,
                                 &set_cookies_callback));

  WaitForLoadCall();

  CookiesInputInfo cookie_info_exp = {www_foo_foo_.url(),
                                      "A",
                                      "B",
                                      std::string(),
                                      "/foo",
                                      base::Time(),
                                      false,
                                      false,
                                      CookieSameSite::DEFAULT_MODE,
                                      COOKIE_PRIORITY_DEFAULT};
  EXPECT_CALL(set_cookies_callback, Run(true))
      .WillOnce(SetCookieWithDetailsAction(&cookie_monster(), cookie_info_exp,
                                           &set_cookies_callback));
  base::RunLoop loop;
  EXPECT_CALL(set_cookies_callback, Run(true)).WillOnce(QuitRunLoop(&loop));

  CompleteLoading();
  loop.Run();
}

TEST_F(DeferredCookieTaskTest, DeferredGetAllCookies) {
  DeclareLoadedCookie(http_www_foo_.url(),
                      "X=1; path=/; expires=Mon, 18-Apr-22 22:50:14 GMT",
                      Time::Now() + TimeDelta::FromDays(3));

  MockGetCookieListCallback get_cookie_list_callback;

  BeginWith(GetAllCookiesAction(&cookie_monster(), &get_cookie_list_callback));

  WaitForLoadCall();

  EXPECT_CALL(get_cookie_list_callback, Run(testing::_))
      .WillOnce(
          GetAllCookiesAction(&cookie_monster(), &get_cookie_list_callback));
  base::RunLoop loop;
  EXPECT_CALL(get_cookie_list_callback, Run(testing::_))
      .WillOnce(QuitRunLoop(&loop));

  CompleteLoading();
  loop.Run();
}

TEST_F(DeferredCookieTaskTest, DeferredGetAllForUrlCookies) {
  DeclareLoadedCookie(http_www_foo_.url(),
                      "X=1; path=/; expires=Mon, 18-Apr-22 22:50:14 GMT",
                      Time::Now() + TimeDelta::FromDays(3));

  MockGetCookieListCallback get_cookie_list_callback;

  BeginWithForDomainKey(
      http_www_foo_.domain(),
      GetAllCookiesForUrlAction(&cookie_monster(), http_www_foo_.url(),
                                &get_cookie_list_callback));

  WaitForLoadCall();

  EXPECT_CALL(get_cookie_list_callback, Run(testing::_))
      .WillOnce(GetAllCookiesForUrlAction(
          &cookie_monster(), http_www_foo_.url(), &get_cookie_list_callback));
  base::RunLoop loop;
  EXPECT_CALL(get_cookie_list_callback, Run(testing::_))
      .WillOnce(QuitRunLoop(&loop));

  CompleteLoading();
  loop.Run();
}

TEST_F(DeferredCookieTaskTest, DeferredGetAllForUrlWithOptionsCookies) {
  DeclareLoadedCookie(http_www_foo_.url(),
                      "X=1; path=/; expires=Mon, 18-Apr-22 22:50:14 GMT",
                      Time::Now() + TimeDelta::FromDays(3));

  MockGetCookieListCallback get_cookie_list_callback;

  BeginWithForDomainKey(
      http_www_foo_.domain(),
      GetCookieListForUrlWithOptionsAction(
          &cookie_monster(), http_www_foo_.url(), &get_cookie_list_callback));

  WaitForLoadCall();

  EXPECT_CALL(get_cookie_list_callback, Run(testing::_))
      .WillOnce(GetCookieListForUrlWithOptionsAction(
          &cookie_monster(), http_www_foo_.url(), &get_cookie_list_callback));
  base::RunLoop loop;
  EXPECT_CALL(get_cookie_list_callback, Run(testing::_))
      .WillOnce(QuitRunLoop(&loop));

  CompleteLoading();
  loop.Run();
}

TEST_F(DeferredCookieTaskTest, DeferredDeleteAllCookies) {
  MockDeleteCallback delete_callback;

  BeginWith(DeleteAllAction(&cookie_monster(), &delete_callback));

  WaitForLoadCall();

  EXPECT_CALL(delete_callback, Run(false))
      .WillOnce(DeleteAllAction(&cookie_monster(), &delete_callback));

  base::RunLoop loop;
  EXPECT_CALL(delete_callback, Run(false)).WillOnce(QuitRunLoop(&loop));

  CompleteLoading();
  loop.Run();
}

TEST_F(DeferredCookieTaskTest, DeferredDeleteAllCreatedBetweenCookies) {
  MockDeleteCallback delete_callback;

  BeginWith(DeleteAllCreatedBetweenAction(&cookie_monster(), base::Time(),
                                          base::Time::Now(), &delete_callback));

  WaitForLoadCall();

  EXPECT_CALL(delete_callback, Run(false))
      .WillOnce(DeleteAllCreatedBetweenAction(&cookie_monster(), base::Time(),
                                              base::Time::Now(),
                                              &delete_callback));
  base::RunLoop loop;
  EXPECT_CALL(delete_callback, Run(false)).WillOnce(QuitRunLoop(&loop));

  CompleteLoading();
  loop.Run();
}

TEST_F(DeferredCookieTaskTest,
       DeferredDeleteAllWithPredicateCreatedBetweenCookies) {
  MockDeleteCallback delete_callback;

  CookiePredicate predicate = base::Bind(&AlwaysTrueCookiePredicate, nullptr);

  BeginWith(DeleteAllCreatedBetweenWithPredicateAction(
      &cookie_monster(), base::Time(), base::Time::Now(), predicate,
      &delete_callback));

  WaitForLoadCall();

  EXPECT_CALL(delete_callback, Run(false))
      .WillOnce(DeleteAllCreatedBetweenWithPredicateAction(
          &cookie_monster(), base::Time(), base::Time::Now(), predicate,
          &delete_callback));
  base::RunLoop loop;
  EXPECT_CALL(delete_callback, Run(false)).WillOnce(QuitRunLoop(&loop));

  CompleteLoading();
  loop.Run();
}

TEST_F(DeferredCookieTaskTest, DeferredDeleteCanonicalCookie) {
  std::vector<std::unique_ptr<CanonicalCookie>> cookies;
  std::unique_ptr<CanonicalCookie> cookie = BuildCanonicalCookie(
      http_www_foo_.url(), "X=1; path=/", base::Time::Now());

  MockDeleteCallback delete_cookie_callback;

  BeginWith(DeleteCanonicalCookieAction(&cookie_monster(), *cookie,
                                        &delete_cookie_callback));

  WaitForLoadCall();

  EXPECT_CALL(delete_cookie_callback, Run(0))
      .WillOnce(DeleteCanonicalCookieAction(&cookie_monster(), *cookie,
                                            &delete_cookie_callback));
  base::RunLoop loop;
  EXPECT_CALL(delete_cookie_callback, Run(0)).WillOnce(QuitRunLoop(&loop));

  CompleteLoading();
  loop.Run();
}

TEST_F(DeferredCookieTaskTest, DeferredDeleteSessionCookies) {
  MockDeleteCallback delete_callback;

  BeginWith(DeleteSessionCookiesAction(&cookie_monster(), &delete_callback));

  WaitForLoadCall();

  EXPECT_CALL(delete_callback, Run(false))
      .WillOnce(
          DeleteSessionCookiesAction(&cookie_monster(), &delete_callback));
  base::RunLoop loop;
  EXPECT_CALL(delete_callback, Run(false)).WillOnce(QuitRunLoop(&loop));

  CompleteLoading();
  loop.Run();
}

// Verify that a series of queued tasks are executed in order upon loading of
// the backing store and that new tasks received while the queued tasks are
// being dispatched go to the end of the queue.
TEST_F(DeferredCookieTaskTest, DeferredTaskOrder) {
  DeclareLoadedCookie(http_www_foo_.url(),
                      "X=1; path=/; expires=Mon, 18-Apr-22 22:50:14 GMT",
                      Time::Now() + TimeDelta::FromDays(3));

  MockGetCookiesCallback get_cookies_callback;
  MockSetCookiesCallback set_cookies_callback;
  MockGetCookiesCallback get_cookies_callback_deferred;

  EXPECT_CALL(*this, Begin())
      .WillOnce(testing::DoAll(
          GetCookiesAction(&cookie_monster(), http_www_foo_.url(),
                           &get_cookies_callback),
          SetCookieAction(&cookie_monster(), http_www_foo_.url(), "A=B",
                          &set_cookies_callback)));
  ExpectLoadCall();
  ExpectLoadForKeyCall(http_www_foo_.domain());
  Begin();

  WaitForLoadCall();
  EXPECT_CALL(get_cookies_callback, Run("X=1"))
      .WillOnce(GetCookiesAction(&cookie_monster(), http_www_foo_.url(),
                                 &get_cookies_callback_deferred));
  EXPECT_CALL(set_cookies_callback, Run(true));
  base::RunLoop loop;
  EXPECT_CALL(get_cookies_callback_deferred, Run("A=B; X=1"))
      .WillOnce(QuitRunLoop(&loop));

  CompleteLoading();
  loop.Run();
}

TEST_F(CookieMonsterTest, TestCookieDeleteAll) {
  scoped_refptr<MockPersistentCookieStore> store(new MockPersistentCookieStore);
  std::unique_ptr<CookieMonster> cm(new CookieMonster(store.get(), nullptr));
  CookieOptions options;
  options.set_include_httponly();

  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), kValidCookieLine));
  EXPECT_EQ("A=B", GetCookies(cm.get(), http_www_foo_.url()));

  EXPECT_TRUE(SetCookieWithOptions(cm.get(), http_www_foo_.url(),
                                   "C=D; httponly", options));
  EXPECT_EQ("A=B; C=D",
            GetCookiesWithOptions(cm.get(), http_www_foo_.url(), options));

  EXPECT_EQ(2, DeleteAll(cm.get()));
  EXPECT_EQ("", GetCookiesWithOptions(cm.get(), http_www_foo_.url(), options));
  EXPECT_EQ(0u, store->commands().size());

  // Create a persistent cookie.
  EXPECT_TRUE(SetCookie(
      cm.get(), http_www_foo_.url(),
      std::string(kValidCookieLine) + "; expires=Mon, 18-Apr-22 22:50:13 GMT"));
  ASSERT_EQ(1u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::ADD, store->commands()[0].type);

  EXPECT_EQ(1, DeleteAll(cm.get()));  // sync_to_store = true.
  ASSERT_EQ(2u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[1].type);

  EXPECT_EQ("", GetCookiesWithOptions(cm.get(), http_www_foo_.url(), options));
}

TEST_F(CookieMonsterTest, TestCookieDeleteAllCreatedBetweenTimestamps) {
  std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));
  Time now = Time::Now();

  // Nothing has been added so nothing should be deleted.
  EXPECT_EQ(0, DeleteAllCreatedBetween(cm.get(), now - TimeDelta::FromDays(99),
                                       Time()));

  // Create 5 cookies with different creation dates.
  EXPECT_TRUE(
      cm->SetCookieWithCreationTime(http_www_foo_.url(), "T-0=Now", now));
  EXPECT_TRUE(cm->SetCookieWithCreationTime(
      http_www_foo_.url(), "T-1=Yesterday", now - TimeDelta::FromDays(1)));
  EXPECT_TRUE(cm->SetCookieWithCreationTime(
      http_www_foo_.url(), "T-2=DayBefore", now - TimeDelta::FromDays(2)));
  EXPECT_TRUE(cm->SetCookieWithCreationTime(
      http_www_foo_.url(), "T-3=ThreeDays", now - TimeDelta::FromDays(3)));
  EXPECT_TRUE(cm->SetCookieWithCreationTime(http_www_foo_.url(), "T-7=LastWeek",
                                            now - TimeDelta::FromDays(7)));

  // Try to delete threedays and the daybefore.
  EXPECT_EQ(2, DeleteAllCreatedBetween(cm.get(), now - TimeDelta::FromDays(3),
                                       now - TimeDelta::FromDays(1)));

  // Try to delete yesterday, also make sure that delete_end is not
  // inclusive.
  EXPECT_EQ(
      1, DeleteAllCreatedBetween(cm.get(), now - TimeDelta::FromDays(2), now));

  // Make sure the delete_begin is inclusive.
  EXPECT_EQ(
      1, DeleteAllCreatedBetween(cm.get(), now - TimeDelta::FromDays(7), now));

  // Delete the last (now) item.
  EXPECT_EQ(1, DeleteAllCreatedBetween(cm.get(), Time(), Time()));

  // Really make sure everything is gone.
  EXPECT_EQ(0, DeleteAll(cm.get()));
}

TEST_F(CookieMonsterTest,
       TestCookieDeleteAllCreatedBetweenTimestampsWithPredicate) {
  std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));
  Time now = Time::Now();

  CanonicalCookie test_cookie;
  CookiePredicate true_predicate =
      base::Bind(&AlwaysTrueCookiePredicate, &test_cookie);

  CookiePredicate false_predicate =
      base::Bind(&AlwaysFalseCookiePredicate, &test_cookie);

  // Nothing has been added so nothing should be deleted.
  EXPECT_EQ(
      0, DeleteAllCreatedBetweenWithPredicate(
             cm.get(), now - TimeDelta::FromDays(99), Time(), true_predicate));

  // Create 5 cookies with different creation dates.
  EXPECT_TRUE(
      cm->SetCookieWithCreationTime(http_www_foo_.url(), "T-0=Now", now));
  EXPECT_TRUE(cm->SetCookieWithCreationTime(
      http_www_foo_.url(), "T-1=Yesterday", now - TimeDelta::FromDays(1)));
  EXPECT_TRUE(cm->SetCookieWithCreationTime(
      http_www_foo_.url(), "T-2=DayBefore", now - TimeDelta::FromDays(2)));
  EXPECT_TRUE(cm->SetCookieWithCreationTime(
      http_www_foo_.url(), "T-3=ThreeDays", now - TimeDelta::FromDays(3)));
  EXPECT_TRUE(cm->SetCookieWithCreationTime(http_www_foo_.url(), "T-7=LastWeek",
                                            now - TimeDelta::FromDays(7)));

  // Try to delete threedays and the daybefore, but we should do nothing due
  // to the predicate.
  EXPECT_EQ(0, DeleteAllCreatedBetweenWithPredicate(
                   cm.get(), now - TimeDelta::FromDays(3),
                   now - TimeDelta::FromDays(1), false_predicate));
  // Same as above with a null predicate, so it shouldn't delete anything.
  EXPECT_EQ(0, DeleteAllCreatedBetweenWithPredicate(
                   cm.get(), now - TimeDelta::FromDays(3),
                   now - TimeDelta::FromDays(1), CookiePredicate()));
  // Same as above, but we use the true_predicate, so it works.
  EXPECT_EQ(2, DeleteAllCreatedBetweenWithPredicate(
                   cm.get(), now - TimeDelta::FromDays(3),
                   now - TimeDelta::FromDays(1), true_predicate));

  // Try to delete yesterday, also make sure that delete_end is not
  // inclusive.
  EXPECT_EQ(0,
            DeleteAllCreatedBetweenWithPredicate(
                cm.get(), now - TimeDelta::FromDays(2), now, false_predicate));
  EXPECT_EQ(1,
            DeleteAllCreatedBetweenWithPredicate(
                cm.get(), now - TimeDelta::FromDays(2), now, true_predicate));
  // Check our cookie values.
  std::unique_ptr<CanonicalCookie> expected_cookie =
      CanonicalCookie::Create(http_www_foo_.url(), "T-1=Yesterday",
                              now - TimeDelta::FromDays(1), CookieOptions());
  EXPECT_THAT(test_cookie, CookieEquals(*expected_cookie))
      << "Actual:\n"
      << test_cookie.DebugString() << "\nExpected:\n"
      << expected_cookie->DebugString();

  // Make sure the delete_begin is inclusive.
  EXPECT_EQ(0,
            DeleteAllCreatedBetweenWithPredicate(
                cm.get(), now - TimeDelta::FromDays(7), now, false_predicate));
  EXPECT_EQ(1,
            DeleteAllCreatedBetweenWithPredicate(
                cm.get(), now - TimeDelta::FromDays(7), now, true_predicate));

  // Delete the last (now) item.
  EXPECT_EQ(0, DeleteAllCreatedBetweenWithPredicate(cm.get(), Time(), Time(),
                                                    false_predicate));
  EXPECT_EQ(1, DeleteAllCreatedBetweenWithPredicate(cm.get(), Time(), Time(),
                                                    true_predicate));
  expected_cookie = CanonicalCookie::Create(http_www_foo_.url(), "T-0=Now", now,
                                            CookieOptions());
  EXPECT_THAT(test_cookie, CookieEquals(*expected_cookie))
      << "Actual:\n"
      << test_cookie.DebugString() << "\nExpected:\n"
      << expected_cookie->DebugString();

  // Really make sure everything is gone.
  EXPECT_EQ(0, DeleteAll(cm.get()));
}

static const base::TimeDelta kLastAccessThreshold =
    base::TimeDelta::FromMilliseconds(200);
static const base::TimeDelta kAccessDelay =
    kLastAccessThreshold + base::TimeDelta::FromMilliseconds(20);

TEST_F(CookieMonsterTest, TestLastAccess) {
  std::unique_ptr<CookieMonster> cm(
      new CookieMonster(nullptr, nullptr, kLastAccessThreshold));

  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=B"));
  const Time last_access_date(GetFirstCookieAccessDate(cm.get()));

  // Reading the cookie again immediately shouldn't update the access date,
  // since we're inside the threshold.
  EXPECT_EQ("A=B", GetCookies(cm.get(), http_www_foo_.url()));
  EXPECT_EQ(last_access_date, GetFirstCookieAccessDate(cm.get()));

  // Reading after a short wait will update the access date, if the cookie
  // is requested with options that would update the access date. First, test
  // that the flag's behavior is respected.
  base::PlatformThread::Sleep(kAccessDelay);
  CookieOptions options;
  options.set_do_not_update_access_time();
  EXPECT_EQ("A=B",
            GetCookiesWithOptions(cm.get(), http_www_foo_.url(), options));
  EXPECT_EQ(last_access_date, GetFirstCookieAccessDate(cm.get()));

  // Getting all cookies for a URL doesn't update the accessed time either.
  CookieList cookies = GetAllCookiesForURL(cm.get(), http_www_foo_.url());
  CookieList::iterator it = cookies.begin();
  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ(http_www_foo_.host(), it->Domain());
  EXPECT_EQ("A", it->Name());
  EXPECT_EQ("B", it->Value());
  EXPECT_EQ(last_access_date, GetFirstCookieAccessDate(cm.get()));
  EXPECT_TRUE(++it == cookies.end());

  // If the flag isn't set, the last accessed time should be updated.
  options = CookieOptions();
  EXPECT_EQ("A=B",
            GetCookiesWithOptions(cm.get(), http_www_foo_.url(), options));
  EXPECT_FALSE(last_access_date == GetFirstCookieAccessDate(cm.get()));
}

TEST_F(CookieMonsterTest, TestHostGarbageCollection) {
  TestHostGarbageCollectHelper();
}

TEST_F(CookieMonsterTest, TestPriorityAwareGarbageCollectionNonSecure) {
  TestPriorityAwareGarbageCollectHelperNonSecure();
}

TEST_F(CookieMonsterTest, TestPriorityAwareGarbageCollectionSecure) {
  TestPriorityAwareGarbageCollectHelperSecure();
}

TEST_F(CookieMonsterTest, TestPriorityAwareGarbageCollectionMixed) {
  TestPriorityAwareGarbageCollectHelperMixed();
}

TEST_F(CookieMonsterTest, SetCookieableSchemes) {
  std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));
  std::unique_ptr<CookieMonster> cm_foo(new CookieMonster(nullptr, nullptr));

  // Only cm_foo should allow foo:// cookies.
  std::vector<std::string> schemes;
  schemes.push_back("foo");
  cm_foo->SetCookieableSchemes(schemes);

  GURL foo_url("foo://host/path");
  GURL http_url("http://host/path");

  EXPECT_TRUE(SetCookie(cm.get(), http_url, "x=1"));
  EXPECT_FALSE(SetCookie(cm.get(), foo_url, "x=1"));
  EXPECT_TRUE(SetCookie(cm_foo.get(), foo_url, "x=1"));
  EXPECT_FALSE(SetCookie(cm_foo.get(), http_url, "x=1"));
}

TEST_F(CookieMonsterTest, GetAllCookiesForURL) {
  std::unique_ptr<CookieMonster> cm(
      new CookieMonster(nullptr, nullptr, kLastAccessThreshold));

  // Create an httponly cookie.
  CookieOptions options;
  options.set_include_httponly();

  EXPECT_TRUE(SetCookieWithOptions(cm.get(), http_www_foo_.url(),
                                   "A=B; httponly", options));
  EXPECT_TRUE(SetCookieWithOptions(cm.get(), http_www_foo_.url(),
                                   http_www_foo_.Format("C=D; domain=.%D"),
                                   options));
  EXPECT_TRUE(SetCookieWithOptions(
      cm.get(), https_www_foo_.url(),
      http_www_foo_.Format("E=F; domain=.%D; secure"), options));

  const Time last_access_date(GetFirstCookieAccessDate(cm.get()));

  base::PlatformThread::Sleep(kAccessDelay);

  // Check cookies for url.
  CookieList cookies = GetAllCookiesForURL(cm.get(), http_www_foo_.url());
  CookieList::iterator it = cookies.begin();

  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ(http_www_foo_.host(), it->Domain());
  EXPECT_EQ("A", it->Name());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ(http_www_foo_.Format(".%D"), it->Domain());
  EXPECT_EQ("C", it->Name());

  ASSERT_TRUE(++it == cookies.end());

  // Check cookies for url excluding http-only cookies.
  cookies = GetAllCookiesForURLWithOptions(cm.get(), http_www_foo_.url(),
                                           CookieOptions());
  it = cookies.begin();

  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ(http_www_foo_.Format(".%D"), it->Domain());
  EXPECT_EQ("C", it->Name());

  ASSERT_TRUE(++it == cookies.end());

  // Test secure cookies.
  cookies = GetAllCookiesForURL(cm.get(), https_www_foo_.url());
  it = cookies.begin();

  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ(http_www_foo_.host(), it->Domain());
  EXPECT_EQ("A", it->Name());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ(http_www_foo_.Format(".%D"), it->Domain());
  EXPECT_EQ("C", it->Name());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ(http_www_foo_.Format(".%D"), it->Domain());
  EXPECT_EQ("E", it->Name());

  ASSERT_TRUE(++it == cookies.end());

  // Reading after a short wait should not update the access date.
  EXPECT_EQ(last_access_date, GetFirstCookieAccessDate(cm.get()));
}

TEST_F(CookieMonsterTest, GetAllCookiesForURLPathMatching) {
  std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));
  CookieOptions options;

  EXPECT_TRUE(SetCookieWithOptions(cm.get(), www_foo_foo_.url(),
                                   "A=B; path=/foo;", options));
  EXPECT_TRUE(SetCookieWithOptions(cm.get(), www_foo_bar_.url(),
                                   "C=D; path=/bar;", options));
  EXPECT_TRUE(
      SetCookieWithOptions(cm.get(), http_www_foo_.url(), "E=F;", options));

  CookieList cookies = GetAllCookiesForURL(cm.get(), www_foo_foo_.url());
  CookieList::iterator it = cookies.begin();

  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ("A", it->Name());
  EXPECT_EQ("/foo", it->Path());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ("E", it->Name());
  EXPECT_EQ("/", it->Path());

  ASSERT_TRUE(++it == cookies.end());

  cookies = GetAllCookiesForURL(cm.get(), www_foo_bar_.url());
  it = cookies.begin();

  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ("C", it->Name());
  EXPECT_EQ("/bar", it->Path());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ("E", it->Name());
  EXPECT_EQ("/", it->Path());

  ASSERT_TRUE(++it == cookies.end());
}

TEST_F(CookieMonsterTest, CookieSorting) {
  std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));

  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "B=B1; path=/"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "B=B2; path=/foo"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "B=B3; path=/foo/bar"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=A1; path=/"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=A2; path=/foo"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=A3; path=/foo/bar"));

  // Re-set cookie which should not change sort order.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "B=B3; path=/foo/bar"));

  CookieList cookies = GetAllCookies(cm.get());
  ASSERT_EQ(6u, cookies.size());
  // According to RFC 6265 5.3 (11) re-setting this cookie should retain the
  // initial creation-time from above, and the sort order should not change.
  // Chrome's current implementation deviates from the spec so capturing this to
  // avoid any inadvertent changes to this behavior.
  EXPECT_EQ("A3", cookies[0].Value());
  EXPECT_EQ("B3", cookies[1].Value());
  EXPECT_EQ("B2", cookies[2].Value());
  EXPECT_EQ("A2", cookies[3].Value());
  EXPECT_EQ("B1", cookies[4].Value());
  EXPECT_EQ("A1", cookies[5].Value());
}

TEST_F(CookieMonsterTest, DeleteCookieByName) {
  std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));

  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=A1; path=/"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=A2; path=/foo"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=A3; path=/bar"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "B=B1; path=/"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "B=B2; path=/foo"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "B=B3; path=/bar"));

  DeleteCookie(cm.get(), http_www_foo_.AppendPath("foo/bar"), "A");

  CookieList cookies = GetAllCookies(cm.get());
  size_t expected_size = 4;
  EXPECT_EQ(expected_size, cookies.size());
  for (CookieList::iterator it = cookies.begin(); it != cookies.end(); ++it) {
    EXPECT_NE("A1", it->Value());
    EXPECT_NE("A2", it->Value());
  }
}

// Tests importing from a persistent cookie store that contains duplicate
// equivalent cookies. This situation should be handled by removing the
// duplicate cookie (both from the in-memory cache, and from the backing store).
//
// This is a regression test for: http://crbug.com/17855.
TEST_F(CookieMonsterTest, DontImportDuplicateCookies) {
  scoped_refptr<MockPersistentCookieStore> store(new MockPersistentCookieStore);

  // We will fill some initial cookies into the PersistentCookieStore,
  // to simulate a database with 4 duplicates.  Note that we need to
  // be careful not to have any duplicate creation times at all (as it's a
  // violation of a CookieMonster invariant) even if Time::Now() doesn't
  // move between calls.
  std::vector<std::unique_ptr<CanonicalCookie>> initial_cookies;

  // Insert 4 cookies with name "X" on path "/", with varying creation
  // dates. We expect only the most recent one to be preserved following
  // the import.

  AddCookieToList(GURL("http://www.foo.com"),
                  "X=1; path=/; expires=Mon, 18-Apr-22 22:50:14 GMT",
                  Time::Now() + TimeDelta::FromDays(3), &initial_cookies);

  AddCookieToList(GURL("http://www.foo.com"),
                  "X=2; path=/; expires=Mon, 18-Apr-22 22:50:14 GMT",
                  Time::Now() + TimeDelta::FromDays(1), &initial_cookies);

  // ===> This one is the WINNER (biggest creation time).  <====
  AddCookieToList(GURL("http://www.foo.com"),
                  "X=3; path=/; expires=Mon, 18-Apr-22 22:50:14 GMT",
                  Time::Now() + TimeDelta::FromDays(4), &initial_cookies);

  AddCookieToList(GURL("http://www.foo.com"),
                  "X=4; path=/; expires=Mon, 18-Apr-22 22:50:14 GMT",
                  Time::Now(), &initial_cookies);

  // Insert 2 cookies with name "X" on path "/2", with varying creation
  // dates. We expect only the most recent one to be preserved the import.

  // ===> This one is the WINNER (biggest creation time).  <====
  AddCookieToList(GURL("http://www.foo.com"),
                  "X=a1; path=/2; expires=Mon, 18-Apr-22 22:50:14 GMT",
                  Time::Now() + TimeDelta::FromDays(9), &initial_cookies);

  AddCookieToList(GURL("http://www.foo.com"),
                  "X=a2; path=/2; expires=Mon, 18-Apr-22 22:50:14 GMT",
                  Time::Now() + TimeDelta::FromDays(2), &initial_cookies);

  // Insert 1 cookie with name "Y" on path "/".
  AddCookieToList(GURL("http://www.foo.com"),
                  "Y=a; path=/; expires=Mon, 18-Apr-22 22:50:14 GMT",
                  Time::Now() + TimeDelta::FromDays(10), &initial_cookies);

  // Inject our initial cookies into the mock PersistentCookieStore.
  store->SetLoadExpectation(true, std::move(initial_cookies));

  std::unique_ptr<CookieMonster> cm(new CookieMonster(store.get(), nullptr));

  // Verify that duplicates were not imported for path "/".
  // (If this had failed, GetCookies() would have also returned X=1, X=2, X=4).
  EXPECT_EQ("X=3; Y=a", GetCookies(cm.get(), GURL("http://www.foo.com/")));

  // Verify that same-named cookie on a different path ("/x2") didn't get
  // messed up.
  EXPECT_EQ("X=a1; X=3; Y=a",
            GetCookies(cm.get(), GURL("http://www.foo.com/2/x")));

  // Verify that the PersistentCookieStore was told to kill its 4 duplicates.
  ASSERT_EQ(4u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[0].type);
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[1].type);
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[2].type);
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[3].type);
}

// Tests importing from a persistent cookie store that contains cookies
// with duplicate creation times.  This situation should be handled by
// dropping the cookies before insertion/visibility to user.
//
// This is a regression test for: http://crbug.com/43188.
TEST_F(CookieMonsterTest, DontImportDuplicateCreationTimes) {
  scoped_refptr<MockPersistentCookieStore> store(new MockPersistentCookieStore);

  Time now(Time::Now());
  Time earlier(now - TimeDelta::FromDays(1));

  // Insert 8 cookies, four with the current time as creation times, and
  // four with the earlier time as creation times.  We should only get
  // two cookies remaining, but which two (other than that there should
  // be one from each set) will be random.
  std::vector<std::unique_ptr<CanonicalCookie>> initial_cookies;
  AddCookieToList(GURL("http://www.foo.com"), "X=1; path=/", now,
                  &initial_cookies);
  AddCookieToList(GURL("http://www.foo.com"), "X=2; path=/", now,
                  &initial_cookies);
  AddCookieToList(GURL("http://www.foo.com"), "X=3; path=/", now,
                  &initial_cookies);
  AddCookieToList(GURL("http://www.foo.com"), "X=4; path=/", now,
                  &initial_cookies);

  AddCookieToList(GURL("http://www.foo.com"), "Y=1; path=/", earlier,
                  &initial_cookies);
  AddCookieToList(GURL("http://www.foo.com"), "Y=2; path=/", earlier,
                  &initial_cookies);
  AddCookieToList(GURL("http://www.foo.com"), "Y=3; path=/", earlier,
                  &initial_cookies);
  AddCookieToList(GURL("http://www.foo.com"), "Y=4; path=/", earlier,
                  &initial_cookies);

  // Inject our initial cookies into the mock PersistentCookieStore.
  store->SetLoadExpectation(true, std::move(initial_cookies));

  std::unique_ptr<CookieMonster> cm(new CookieMonster(store.get(), nullptr));

  CookieList list(GetAllCookies(cm.get()));
  EXPECT_EQ(2U, list.size());
  // Confirm that we have one of each.
  std::string name1(list[0].Name());
  std::string name2(list[1].Name());
  EXPECT_TRUE(name1 == "X" || name2 == "X");
  EXPECT_TRUE(name1 == "Y" || name2 == "Y");
  EXPECT_NE(name1, name2);
}

TEST_F(CookieMonsterTest, CookieMonsterDelegate) {
  scoped_refptr<MockPersistentCookieStore> store(new MockPersistentCookieStore);
  scoped_refptr<MockCookieMonsterDelegate> delegate(
      new MockCookieMonsterDelegate);
  std::unique_ptr<CookieMonster> cm(
      new CookieMonster(store.get(), delegate.get()));

  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=B"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "C=D"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "E=F"));
  EXPECT_EQ("A=B; C=D; E=F", GetCookies(cm.get(), http_www_foo_.url()));
  ASSERT_EQ(3u, delegate->changes().size());
  EXPECT_FALSE(delegate->changes()[0].second);
  EXPECT_EQ(http_www_foo_.url().host(), delegate->changes()[0].first.Domain());
  EXPECT_EQ("A", delegate->changes()[0].first.Name());
  EXPECT_EQ("B", delegate->changes()[0].first.Value());
  EXPECT_EQ(http_www_foo_.url().host(), delegate->changes()[1].first.Domain());
  EXPECT_FALSE(delegate->changes()[1].second);
  EXPECT_EQ("C", delegate->changes()[1].first.Name());
  EXPECT_EQ("D", delegate->changes()[1].first.Value());
  EXPECT_EQ(http_www_foo_.url().host(), delegate->changes()[2].first.Domain());
  EXPECT_FALSE(delegate->changes()[2].second);
  EXPECT_EQ("E", delegate->changes()[2].first.Name());
  EXPECT_EQ("F", delegate->changes()[2].first.Value());
  delegate->reset();

  EXPECT_TRUE(FindAndDeleteCookie(cm.get(), http_www_foo_.url().host(), "C"));
  EXPECT_EQ("A=B; E=F", GetCookies(cm.get(), http_www_foo_.url()));
  ASSERT_EQ(1u, delegate->changes().size());
  EXPECT_EQ(http_www_foo_.url().host(), delegate->changes()[0].first.Domain());
  EXPECT_TRUE(delegate->changes()[0].second);
  EXPECT_EQ("C", delegate->changes()[0].first.Name());
  EXPECT_EQ("D", delegate->changes()[0].first.Value());
  delegate->reset();

  EXPECT_FALSE(FindAndDeleteCookie(cm.get(), "random.host", "E"));
  EXPECT_EQ("A=B; E=F", GetCookies(cm.get(), http_www_foo_.url()));
  EXPECT_EQ(0u, delegate->changes().size());

  // Insert a cookie "a" for path "/path1"
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(),
                        "a=val1; path=/path1; "
                        "expires=Mon, 18-Apr-22 22:50:13 GMT"));
  ASSERT_EQ(1u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::ADD, store->commands()[0].type);
  ASSERT_EQ(1u, delegate->changes().size());
  EXPECT_FALSE(delegate->changes()[0].second);
  EXPECT_EQ(http_www_foo_.url().host(), delegate->changes()[0].first.Domain());
  EXPECT_EQ("a", delegate->changes()[0].first.Name());
  EXPECT_EQ("val1", delegate->changes()[0].first.Value());
  delegate->reset();

  // Insert a cookie "a" for path "/path1", that is httponly. This should
  // overwrite the non-http-only version.
  CookieOptions allow_httponly;
  allow_httponly.set_include_httponly();
  EXPECT_TRUE(SetCookieWithOptions(cm.get(), http_www_foo_.url(),
                                   "a=val2; path=/path1; httponly; "
                                   "expires=Mon, 18-Apr-22 22:50:14 GMT",
                                   allow_httponly));
  ASSERT_EQ(3u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[1].type);
  EXPECT_EQ(CookieStoreCommand::ADD, store->commands()[2].type);
  ASSERT_EQ(2u, delegate->changes().size());
  EXPECT_EQ(http_www_foo_.url().host(), delegate->changes()[0].first.Domain());
  EXPECT_TRUE(delegate->changes()[0].second);
  EXPECT_EQ("a", delegate->changes()[0].first.Name());
  EXPECT_EQ("val1", delegate->changes()[0].first.Value());
  EXPECT_EQ(http_www_foo_.url().host(), delegate->changes()[1].first.Domain());
  EXPECT_FALSE(delegate->changes()[1].second);
  EXPECT_EQ("a", delegate->changes()[1].first.Name());
  EXPECT_EQ("val2", delegate->changes()[1].first.Value());
  delegate->reset();
}

TEST_F(CookieMonsterTest, PredicateSeesAllCookies) {
  const std::string kTrueValue = "A";
  std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));
  // We test that we can see all cookies with our predicated. This includes
  // host, http_only, host secure, and all domain cookies.
  CookiePredicate value_matcher = base::Bind(&CookieValuePredicate, kTrueValue);

  PopulateCmForPredicateCheck(cm.get());
  EXPECT_EQ(7, DeleteAllCreatedBetweenWithPredicate(
                   cm.get(), base::Time(), base::Time::Now(), value_matcher));

  EXPECT_EQ("dom_2=B; dom_3=C; host_3=C",
            GetCookies(cm.get(), GURL(kTopLevelDomainPlus3)));
  EXPECT_EQ("dom_2=B; host_2=B; sec_host=B",
            GetCookies(cm.get(), GURL(kTopLevelDomainPlus2Secure)));
  EXPECT_EQ("", GetCookies(cm.get(), GURL(kTopLevelDomainPlus1)));
  EXPECT_EQ("dom_path_2=B; host_path_2=B; dom_2=B; host_2=B; sec_host=B",
            GetCookies(cm.get(), GURL(kTopLevelDomainPlus2Secure +
                                      std::string("/dir1/dir2/xxx"))));
}

TEST_F(CookieMonsterTest, UniqueCreationTime) {
  std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));
  CookieOptions options;

  // Add in three cookies through every public interface to the
  // CookieMonster and confirm that none of them have duplicate
  // creation times.

  // SetCookieWithCreationTime and SetCookieWithCreationTimeAndOptions
  // are not included as they aren't going to be public for very much
  // longer.

  // SetCookie, SetCookieWithOptions, SetCookieWithDetails

  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "SetCookie1=A"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "SetCookie2=A"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "SetCookie3=A"));

  EXPECT_TRUE(SetCookieWithOptions(cm.get(), http_www_foo_.url(),
                                   "setCookieWithOptions1=A", options));
  EXPECT_TRUE(SetCookieWithOptions(cm.get(), http_www_foo_.url(),
                                   "setCookieWithOptions2=A", options));
  EXPECT_TRUE(SetCookieWithOptions(cm.get(), http_www_foo_.url(),
                                   "setCookieWithOptions3=A", options));

  EXPECT_TRUE(SetCookieWithDetails(
      cm.get(), http_www_foo_.url(), "setCookieWithDetails1", "A",
      http_www_foo_.Format(".%D"), "/", Time(), Time(), Time(), false, false,
      CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));
  EXPECT_TRUE(SetCookieWithDetails(
      cm.get(), http_www_foo_.url(), "setCookieWithDetails2", "A",
      http_www_foo_.Format(".%D"), "/", Time(), Time(), Time(), false, false,
      CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));
  EXPECT_TRUE(SetCookieWithDetails(
      cm.get(), http_www_foo_.url(), "setCookieWithDetails3", "A",
      http_www_foo_.Format(".%D"), "/", Time(), Time(), Time(), false, false,
      CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));

  // Now we check
  CookieList cookie_list(GetAllCookies(cm.get()));
  EXPECT_EQ(9u, cookie_list.size());
  typedef std::map<int64_t, CanonicalCookie> TimeCookieMap;
  TimeCookieMap check_map;
  for (CookieList::const_iterator it = cookie_list.begin();
       it != cookie_list.end(); it++) {
    const int64_t creation_date = it->CreationDate().ToInternalValue();
    TimeCookieMap::const_iterator existing_cookie_it(
        check_map.find(creation_date));
    EXPECT_TRUE(existing_cookie_it == check_map.end())
        << "Cookie " << it->Name() << " has same creation date ("
        << it->CreationDate().ToInternalValue()
        << ") as previously entered cookie "
        << existing_cookie_it->second.Name();

    if (existing_cookie_it == check_map.end()) {
      check_map.insert(
          TimeCookieMap::value_type(it->CreationDate().ToInternalValue(), *it));
    }
  }
}

// Mainly a test of GetEffectiveDomain, or more specifically, of the
// expected behavior of GetEffectiveDomain within the CookieMonster.
TEST_F(CookieMonsterTest, GetKey) {
  std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));

  // This test is really only interesting if GetKey() actually does something.
  EXPECT_EQ("foo.com", cm->GetKey("www.foo.com"));
  EXPECT_EQ("google.izzie", cm->GetKey("www.google.izzie"));
  EXPECT_EQ("google.izzie", cm->GetKey(".google.izzie"));
  EXPECT_EQ("bbc.co.uk", cm->GetKey("bbc.co.uk"));
  EXPECT_EQ("bbc.co.uk", cm->GetKey("a.b.c.d.bbc.co.uk"));
  EXPECT_EQ("apple.com", cm->GetKey("a.b.c.d.apple.com"));
  EXPECT_EQ("apple.izzie", cm->GetKey("a.b.c.d.apple.izzie"));

  // Cases where the effective domain is null, so we use the host
  // as the key.
  EXPECT_EQ("co.uk", cm->GetKey("co.uk"));
  const std::string extension_name("iehocdgbbocmkdidlbnnfbmbinnahbae");
  EXPECT_EQ(extension_name, cm->GetKey(extension_name));
  EXPECT_EQ("com", cm->GetKey("com"));
  EXPECT_EQ("hostalias", cm->GetKey("hostalias"));
  EXPECT_EQ("localhost", cm->GetKey("localhost"));
}

// Test that cookies transfer from/to the backing store correctly.
TEST_F(CookieMonsterTest, BackingStoreCommunication) {
  // Store details for cookies transforming through the backing store interface.

  base::Time current(base::Time::Now());
  scoped_refptr<MockSimplePersistentCookieStore> store(
      new MockSimplePersistentCookieStore);
  base::Time new_access_time;
  base::Time expires(base::Time::Now() + base::TimeDelta::FromSeconds(100));

  const CookiesInputInfo input_info[] = {
      {GURL("http://a.b.foo.com"), "a", "1", "", "/path/to/cookie", expires,
       false, false, CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT},
      {GURL("https://www.foo.com"), "b", "2", ".foo.com", "/path/from/cookie",
       expires + TimeDelta::FromSeconds(10), true, true,
       CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT},
      {GURL("https://foo.com"), "c", "3", "", "/another/path/to/cookie",
       base::Time::Now() + base::TimeDelta::FromSeconds(100), true, false,
       CookieSameSite::STRICT_MODE, COOKIE_PRIORITY_DEFAULT}};
  const int INPUT_DELETE = 1;

  // Create new cookies and flush them to the store.
  {
    std::unique_ptr<CookieMonster> cmout(
        new CookieMonster(store.get(), nullptr));
    for (const CookiesInputInfo* p = input_info;
         p < &input_info[arraysize(input_info)]; p++) {
      EXPECT_TRUE(SetCookieWithDetails(
          cmout.get(), p->url, p->name, p->value, p->domain, p->path,
          base::Time(), p->expiration_time, base::Time(), p->secure,
          p->http_only, p->same_site, p->priority));
    }
    GURL del_url(input_info[INPUT_DELETE]
                     .url.Resolve(input_info[INPUT_DELETE].path)
                     .spec());
    DeleteCookie(cmout.get(), del_url, input_info[INPUT_DELETE].name);
  }

  // Create a new cookie monster and make sure that everything is correct
  {
    std::unique_ptr<CookieMonster> cmin(
        new CookieMonster(store.get(), nullptr));
    CookieList cookies(GetAllCookies(cmin.get()));
    ASSERT_EQ(2u, cookies.size());
    // Ordering is path length, then creation time.  So second cookie
    // will come first, and we need to swap them.
    std::swap(cookies[0], cookies[1]);
    for (int output_index = 0; output_index < 2; output_index++) {
      int input_index = output_index * 2;
      const CookiesInputInfo* input = &input_info[input_index];
      const CanonicalCookie* output = &cookies[output_index];

      EXPECT_EQ(input->name, output->Name());
      EXPECT_EQ(input->value, output->Value());
      EXPECT_EQ(input->url.host(), output->Domain());
      EXPECT_EQ(input->path, output->Path());
      EXPECT_LE(current.ToInternalValue(),
                output->CreationDate().ToInternalValue());
      EXPECT_EQ(input->secure, output->IsSecure());
      EXPECT_EQ(input->http_only, output->IsHttpOnly());
      EXPECT_EQ(input->same_site, output->SameSite());
      EXPECT_TRUE(output->IsPersistent());
      EXPECT_EQ(input->expiration_time.ToInternalValue(),
                output->ExpiryDate().ToInternalValue());
    }
  }
}

TEST_F(CookieMonsterTest, CookieListOrdering) {
  // Put a random set of cookies into a monster and make sure
  // they're returned in the right order.
  std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));
  EXPECT_TRUE(
      SetCookie(cm.get(), GURL("http://d.c.b.a.foo.com/aa/x.html"), "c=1"));
  EXPECT_TRUE(SetCookie(cm.get(), GURL("http://b.a.foo.com/aa/bb/cc/x.html"),
                        "d=1; domain=b.a.foo.com"));
  EXPECT_TRUE(SetCookie(cm.get(), GURL("http://b.a.foo.com/aa/bb/cc/x.html"),
                        "a=4; domain=b.a.foo.com"));
  EXPECT_TRUE(SetCookie(cm.get(), GURL("http://c.b.a.foo.com/aa/bb/cc/x.html"),
                        "e=1; domain=c.b.a.foo.com"));
  EXPECT_TRUE(
      SetCookie(cm.get(), GURL("http://d.c.b.a.foo.com/aa/bb/x.html"), "b=1"));
  EXPECT_TRUE(SetCookie(cm.get(), GURL("http://news.bbc.co.uk/midpath/x.html"),
                        "g=10"));
  {
    unsigned int i = 0;
    CookieList cookies(GetAllCookiesForURL(
        cm.get(), GURL("http://d.c.b.a.foo.com/aa/bb/cc/dd")));
    ASSERT_EQ(5u, cookies.size());
    EXPECT_EQ("d", cookies[i++].Name());
    EXPECT_EQ("a", cookies[i++].Name());
    EXPECT_EQ("e", cookies[i++].Name());
    EXPECT_EQ("b", cookies[i++].Name());
    EXPECT_EQ("c", cookies[i++].Name());
  }

  {
    unsigned int i = 0;
    CookieList cookies(GetAllCookies(cm.get()));
    ASSERT_EQ(6u, cookies.size());
    EXPECT_EQ("d", cookies[i++].Name());
    EXPECT_EQ("a", cookies[i++].Name());
    EXPECT_EQ("e", cookies[i++].Name());
    EXPECT_EQ("g", cookies[i++].Name());
    EXPECT_EQ("b", cookies[i++].Name());
    EXPECT_EQ("c", cookies[i++].Name());
  }
}

// This test and CookieMonstertest.TestGCTimes (in cookie_monster_perftest.cc)
// are somewhat complementary twins.  This test is probing for whether
// garbage collection always happens when it should (i.e. that we actually
// get rid of cookies when we should).  The perftest is probing for
// whether garbage collection happens when it shouldn't.  See comments
// before that test for more details.

// Disabled on Windows, see crbug.com/126095
#if defined(OS_WIN)
#define MAYBE_GarbageCollectionTriggers DISABLED_GarbageCollectionTriggers
#else
#define MAYBE_GarbageCollectionTriggers GarbageCollectionTriggers
#endif

TEST_F(CookieMonsterTest, MAYBE_GarbageCollectionTriggers) {
  // First we check to make sure that a whole lot of recent cookies
  // doesn't get rid of anything after garbage collection is checked for.
  {
    std::unique_ptr<CookieMonster> cm(
        CreateMonsterForGC(CookieMonster::kMaxCookies * 2));
    EXPECT_EQ(CookieMonster::kMaxCookies * 2, GetAllCookies(cm.get()).size());
    SetCookie(cm.get(), GURL("http://newdomain.com"), "b=2");
    EXPECT_EQ(CookieMonster::kMaxCookies * 2 + 1,
              GetAllCookies(cm.get()).size());
  }

  // Now we explore a series of relationships between cookie last access
  // time and size of store to make sure we only get rid of cookies when
  // we really should.
  const struct TestCase {
    size_t num_cookies;
    size_t num_old_cookies;
    size_t expected_initial_cookies;
    // Indexed by ExpiryAndKeyScheme
    size_t expected_cookies_after_set;
  } test_cases[] = {
      {// A whole lot of recent cookies; gc shouldn't happen.
       CookieMonster::kMaxCookies * 2,
       0,
       CookieMonster::kMaxCookies * 2,
       CookieMonster::kMaxCookies * 2 + 1},
      {// Some old cookies, but still overflowing max.
       CookieMonster::kMaxCookies * 2,
       CookieMonster::kMaxCookies / 2,
       CookieMonster::kMaxCookies * 2,
       CookieMonster::kMaxCookies * 2 - CookieMonster::kMaxCookies / 2 + 1},
      {// Old cookies enough to bring us right down to our purge line.
       CookieMonster::kMaxCookies * 2,
       CookieMonster::kMaxCookies + CookieMonster::kPurgeCookies + 1,
       CookieMonster::kMaxCookies * 2,
       CookieMonster::kMaxCookies - CookieMonster::kPurgeCookies},
      {// Old cookies enough to bring below our purge line (which we
       // shouldn't do).
       CookieMonster::kMaxCookies * 2,
       CookieMonster::kMaxCookies * 3 / 2,
       CookieMonster::kMaxCookies * 2,
       CookieMonster::kMaxCookies - CookieMonster::kPurgeCookies}};

  for (int ci = 0; ci < static_cast<int>(arraysize(test_cases)); ++ci) {
    const TestCase* test_case = &test_cases[ci];
    std::unique_ptr<CookieMonster> cm = CreateMonsterFromStoreForGC(
        test_case->num_cookies, test_case->num_old_cookies, 0, 0,
        CookieMonster::kSafeFromGlobalPurgeDays * 2);
    EXPECT_EQ(test_case->expected_initial_cookies,
              GetAllCookies(cm.get()).size())
        << "For test case " << ci;
    // Will trigger GC
    SetCookie(cm.get(), GURL("http://newdomain.com"), "b=2");
    EXPECT_EQ(test_case->expected_cookies_after_set,
              GetAllCookies(cm.get()).size())
        << "For test case " << ci;
  }
}

// Tests garbage collection when there are only secure cookies.
// See https://crbug/730000
TEST_F(CookieMonsterTest, GarbageCollectWithSecureCookiesOnly) {
  // Create a CookieMonster at its cookie limit. A bit confusing, but the second
  // number is a subset of the first number.
  std::unique_ptr<CookieMonster> cm = CreateMonsterFromStoreForGC(
      CookieMonster::kMaxCookies /* num_secure_cookies */,
      CookieMonster::kMaxCookies /* num_old_secure_cookies */,
      0 /* num_non_secure_cookies */, 0 /* num_old_non_secure_cookies */,
      CookieMonster::kSafeFromGlobalPurgeDays * 2 /* days_old */);
  EXPECT_EQ(CookieMonster::kMaxCookies, GetAllCookies(cm.get()).size());

  // Trigger purge with a secure cookie (So there are still no insecure
  // cookies).
  SetCookie(cm.get(), GURL("https://newdomain.com"), "b=2; Secure");
  EXPECT_EQ(CookieMonster::kMaxCookies - CookieMonster::kPurgeCookies,
            GetAllCookies(cm.get()).size());
}

// Tests that if the main load event happens before the loaded event for a
// particular key, the tasks for that key run first.
TEST_F(CookieMonsterTest, WhileLoadingLoadCompletesBeforeKeyLoadCompletes) {
  const GURL kUrl = GURL(kTopLevelDomainPlus1);

  scoped_refptr<MockPersistentCookieStore> store(new MockPersistentCookieStore);
  store->set_store_load_commands(true);
  std::unique_ptr<CookieMonster> cm(new CookieMonster(store.get(), nullptr));

  // Get all cookies task that queues a task to set a cookie when executed.
  ResultSavingCookieCallback<bool> set_cookie_callback;
  cm->SetCookieWithOptionsAsync(
      kUrl, "a=b", CookieOptions(),
      base::Bind(&ResultSavingCookieCallback<bool>::Run,
                 base::Unretained(&set_cookie_callback)));

  GetCookieListCallback get_cookie_list_callback1;
  cm->GetAllCookiesAsync(
      base::Bind(&GetCookieListCallback::Run,
                 base::Unretained(&get_cookie_list_callback1)));

  // Two load events should have been queued.
  ASSERT_EQ(2u, store->commands().size());
  ASSERT_EQ(CookieStoreCommand::LOAD, store->commands()[0].type);
  ASSERT_EQ(CookieStoreCommand::LOAD_COOKIES_FOR_KEY,
            store->commands()[1].type);

  // The main load completes first (With no cookies).
  store->commands()[0].loaded_callback.Run(
      std::vector<std::unique_ptr<CanonicalCookie>>());

  // The tasks should run in order, and the get should see the cookies.

  set_cookie_callback.WaitUntilDone();
  EXPECT_TRUE(set_cookie_callback.result());

  get_cookie_list_callback1.WaitUntilDone();
  EXPECT_EQ(1u, get_cookie_list_callback1.cookies().size());

  // The loaded for key event completes late, with not cookies (Since they
  // were already loaded).
  store->commands()[1].loaded_callback.Run(
      std::vector<std::unique_ptr<CanonicalCookie>>());

  // The just set cookie should still be in the store.
  GetCookieListCallback get_cookie_list_callback2;
  cm->GetAllCookiesAsync(
      base::Bind(&GetCookieListCallback::Run,
                 base::Unretained(&get_cookie_list_callback2)));
  get_cookie_list_callback2.WaitUntilDone();
  EXPECT_EQ(1u, get_cookie_list_callback2.cookies().size());
}

// Tests that case that DeleteAll is waiting for load to complete, and then a
// get is queued. The get should wait to run until after all the cookies are
// retrieved, and should return nothing, since all cookies were just deleted.
TEST_F(CookieMonsterTest, WhileLoadingDeleteAllGetForURL) {
  const GURL kUrl = GURL(kTopLevelDomainPlus1);

  scoped_refptr<MockPersistentCookieStore> store(new MockPersistentCookieStore);
  store->set_store_load_commands(true);
  std::unique_ptr<CookieMonster> cm(new CookieMonster(store.get(), nullptr));

  ResultSavingCookieCallback<int> delete_callback;
  cm->DeleteAllAsync(base::Bind(&ResultSavingCookieCallback<int>::Run,
                                base::Unretained(&delete_callback)));

  GetCookieListCallback get_cookie_list_callback;
  cm->GetCookieListWithOptionsAsync(
      kUrl, CookieOptions(),
      base::Bind(&GetCookieListCallback::Run,
                 base::Unretained(&get_cookie_list_callback)));

  // Only the main load should have been queued.
  ASSERT_EQ(1u, store->commands().size());
  ASSERT_EQ(CookieStoreCommand::LOAD, store->commands()[0].type);

  std::vector<std::unique_ptr<CanonicalCookie>> cookies;
  // When passed to the CookieMonster, it takes ownership of the pointed to
  // cookies.
  cookies.push_back(
      CanonicalCookie::Create(kUrl, "a=b", base::Time(), CookieOptions()));
  ASSERT_TRUE(cookies[0]);
  store->commands()[0].loaded_callback.Run(std::move(cookies));

  delete_callback.WaitUntilDone();
  EXPECT_EQ(1, delete_callback.result());

  get_cookie_list_callback.WaitUntilDone();
  EXPECT_EQ(0u, get_cookie_list_callback.cookies().size());
}

// Tests that a set cookie call sandwiched between two get all cookies, all
// before load completes, affects the first but not the second. The set should
// also not trigger a LoadCookiesForKey (As that could complete only after the
// main load for the store).
TEST_F(CookieMonsterTest, WhileLoadingGetAllSetGetAll) {
  const GURL kUrl = GURL(kTopLevelDomainPlus1);

  scoped_refptr<MockPersistentCookieStore> store(new MockPersistentCookieStore);
  store->set_store_load_commands(true);
  std::unique_ptr<CookieMonster> cm(new CookieMonster(store.get(), nullptr));

  GetCookieListCallback get_cookie_list_callback1;
  cm->GetAllCookiesAsync(
      base::Bind(&GetCookieListCallback::Run,
                 base::Unretained(&get_cookie_list_callback1)));

  ResultSavingCookieCallback<bool> set_cookie_callback;
  cm->SetCookieWithOptionsAsync(
      kUrl, "a=b", CookieOptions(),
      base::Bind(&ResultSavingCookieCallback<bool>::Run,
                 base::Unretained(&set_cookie_callback)));

  GetCookieListCallback get_cookie_list_callback2;
  cm->GetAllCookiesAsync(
      base::Bind(&GetCookieListCallback::Run,
                 base::Unretained(&get_cookie_list_callback2)));

  // Only the main load should have been queued.
  ASSERT_EQ(1u, store->commands().size());
  ASSERT_EQ(CookieStoreCommand::LOAD, store->commands()[0].type);

  // The load completes (With no cookies).
  store->commands()[0].loaded_callback.Run(
      std::vector<std::unique_ptr<CanonicalCookie>>());

  get_cookie_list_callback1.WaitUntilDone();
  EXPECT_EQ(0u, get_cookie_list_callback1.cookies().size());

  set_cookie_callback.WaitUntilDone();
  EXPECT_TRUE(set_cookie_callback.result());

  get_cookie_list_callback2.WaitUntilDone();
  EXPECT_EQ(1u, get_cookie_list_callback2.cookies().size());
}

namespace {

void RunClosureOnCookieListReceived(const base::Closure& closure,
                                    const CookieList& cookie_list) {
  closure.Run();
}

}  // namespace

// Tests that if a single cookie task is queued as a result of a task performed
// on all cookies when loading completes, it will be run after any already
// queued tasks.
TEST_F(CookieMonsterTest, CheckOrderOfCookieTaskQueueWhenLoadingCompletes) {
  const GURL kUrl = GURL(kTopLevelDomainPlus1);

  scoped_refptr<MockPersistentCookieStore> store(new MockPersistentCookieStore);
  store->set_store_load_commands(true);
  std::unique_ptr<CookieMonster> cm(new CookieMonster(store.get(), nullptr));

  // Get all cookies task that queues a task to set a cookie when executed.
  ResultSavingCookieCallback<bool> set_cookie_callback;
  cm->GetAllCookiesAsync(base::Bind(
      &RunClosureOnCookieListReceived,
      base::Bind(&CookieStore::SetCookieWithOptionsAsync,
                 base::Unretained(cm.get()), kUrl, "a=b", CookieOptions(),
                 base::Bind(&ResultSavingCookieCallback<bool>::Run,
                            base::Unretained(&set_cookie_callback)))));

  // Get cookie task. Queued before the delete task is executed, so should not
  // see the set cookie.
  GetCookieListCallback get_cookie_list_callback1;
  cm->GetAllCookiesAsync(
      base::Bind(&GetCookieListCallback::Run,
                 base::Unretained(&get_cookie_list_callback1)));

  // Only the main load should have been queued.
  ASSERT_EQ(1u, store->commands().size());
  ASSERT_EQ(CookieStoreCommand::LOAD, store->commands()[0].type);

  // The load completes.
  store->commands()[0].loaded_callback.Run(
      std::vector<std::unique_ptr<CanonicalCookie>>());

  // The get cookies call should see no cookies set.
  get_cookie_list_callback1.WaitUntilDone();
  EXPECT_EQ(0u, get_cookie_list_callback1.cookies().size());

  set_cookie_callback.WaitUntilDone();
  EXPECT_TRUE(set_cookie_callback.result());

  // A subsequent get cookies call should see the new cookie.
  GetCookieListCallback get_cookie_list_callback2;
  cm->GetAllCookiesAsync(
      base::Bind(&GetCookieListCallback::Run,
                 base::Unretained(&get_cookie_list_callback2)));
  get_cookie_list_callback2.WaitUntilDone();
  EXPECT_EQ(1u, get_cookie_list_callback2.cookies().size());
}

namespace {

// Mock PersistentCookieStore that keeps track of the number of Flush() calls.
class FlushablePersistentStore : public CookieMonster::PersistentCookieStore {
 public:
  FlushablePersistentStore() : flush_count_(0) {}

  void Load(const LoadedCallback& loaded_callback) override {
    std::vector<std::unique_ptr<CanonicalCookie>> out_cookies;
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(loaded_callback, base::Passed(&out_cookies)));
  }

  void LoadCookiesForKey(const std::string& key,
                         const LoadedCallback& loaded_callback) override {
    Load(loaded_callback);
  }

  void AddCookie(const CanonicalCookie&) override {}
  void UpdateCookieAccessTime(const CanonicalCookie&) override {}
  void DeleteCookie(const CanonicalCookie&) override {}
  void SetForceKeepSessionState() override {}

  void Flush(const base::Closure& callback) override {
    ++flush_count_;
    if (!callback.is_null())
      callback.Run();
  }

  int flush_count() { return flush_count_; }

 private:
  ~FlushablePersistentStore() override {}

  volatile int flush_count_;
};

// Counts the number of times Callback() has been run.
class CallbackCounter : public base::RefCountedThreadSafe<CallbackCounter> {
 public:
  CallbackCounter() : callback_count_(0) {}

  void Callback() { ++callback_count_; }

  int callback_count() { return callback_count_; }

 private:
  friend class base::RefCountedThreadSafe<CallbackCounter>;
  ~CallbackCounter() {}

  volatile int callback_count_;
};

class FlushCountingChannelIDStore : public DefaultChannelIDStore {
 public:
  FlushCountingChannelIDStore()
      : DefaultChannelIDStore(nullptr), flush_count_(0) {}

  void Flush() override { flush_count_++; }

  int flush_count() { return flush_count_; }

 private:
  int flush_count_;
};

}  // namespace

// Test that FlushStore() is forwarded to the store and callbacks are posted.
TEST_F(CookieMonsterTest, FlushStore) {
  scoped_refptr<CallbackCounter> counter(new CallbackCounter());
  scoped_refptr<FlushablePersistentStore> store(new FlushablePersistentStore());
  std::unique_ptr<CookieMonster> cm(new CookieMonster(store.get(), nullptr));

  ASSERT_EQ(0, store->flush_count());
  ASSERT_EQ(0, counter->callback_count());

  // Before initialization, FlushStore() should just run the callback.
  cm->FlushStore(base::Bind(&CallbackCounter::Callback, counter));
  base::RunLoop().RunUntilIdle();

  ASSERT_EQ(0, store->flush_count());
  ASSERT_EQ(1, counter->callback_count());

  // NULL callback is safe.
  cm->FlushStore(base::Closure());
  base::RunLoop().RunUntilIdle();

  ASSERT_EQ(0, store->flush_count());
  ASSERT_EQ(1, counter->callback_count());

  // After initialization, FlushStore() should delegate to the store.
  GetAllCookies(cm.get());  // Force init.
  cm->FlushStore(base::Bind(&CallbackCounter::Callback, counter));
  base::RunLoop().RunUntilIdle();

  ASSERT_EQ(1, store->flush_count());
  ASSERT_EQ(2, counter->callback_count());

  // NULL callback is still safe.
  cm->FlushStore(base::Closure());
  base::RunLoop().RunUntilIdle();

  ASSERT_EQ(2, store->flush_count());
  ASSERT_EQ(2, counter->callback_count());

  // If there's no backing store, FlushStore() is always a safe no-op.
  cm.reset(new CookieMonster(nullptr, nullptr));
  GetAllCookies(cm.get());  // Force init.
  cm->FlushStore(base::Closure());
  base::RunLoop().RunUntilIdle();

  ASSERT_EQ(2, counter->callback_count());

  cm->FlushStore(base::Bind(&CallbackCounter::Callback, counter));
  base::RunLoop().RunUntilIdle();

  ASSERT_EQ(3, counter->callback_count());
}

TEST_F(CookieMonsterTest, FlushChannelIDs) {
  // |channel_id_service| owns |channel_id_store|.
  FlushCountingChannelIDStore* channel_id_store =
      new FlushCountingChannelIDStore();
  std::unique_ptr<ChannelIDService> channel_id_service(
      new ChannelIDService(channel_id_store));

  scoped_refptr<FlushablePersistentStore> store(new FlushablePersistentStore());
  std::unique_ptr<CookieMonster> cm(
      new CookieMonster(store.get(), nullptr, channel_id_service.get()));
  EXPECT_EQ(0, channel_id_store->flush_count());

  // Before initialization, FlushStore() doesn't propagate to the
  // ChannelIDStore.
  cm->FlushStore(base::Closure());
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0, channel_id_store->flush_count());

  // After initialization, FlushStore() propagates to the ChannelIDStore.
  GetAllCookies(cm.get());  // Force init.
  cm->FlushStore(base::Closure());
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1, channel_id_store->flush_count());

  // If there is no persistent store, then a ChannelIDStore won't be notified.
  cm.reset(new CookieMonster(nullptr, nullptr, channel_id_service.get()));
  GetAllCookies(cm.get());  // Force init.
  cm->FlushStore(base::Closure());
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1, channel_id_store->flush_count());
}

TEST_F(CookieMonsterTest, SetAllCookies) {
  scoped_refptr<FlushablePersistentStore> store(new FlushablePersistentStore());
  std::unique_ptr<CookieMonster> cm(new CookieMonster(store.get(), nullptr));
  cm->SetPersistSessionCookies(true);

  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "U=V; path=/"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "W=X; path=/foo"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "Y=Z; path=/"));

  CookieList list;
  list.push_back(CanonicalCookie(
      "A", "B", "." + http_www_foo_.url().host(), "/", base::Time::Now(),
      base::Time(), base::Time(), false, false, CookieSameSite::DEFAULT_MODE,
      COOKIE_PRIORITY_DEFAULT));
  list.push_back(CanonicalCookie(
      "W", "X", "." + http_www_foo_.url().host(), "/bar", base::Time::Now(),
      base::Time(), base::Time(), false, false, CookieSameSite::DEFAULT_MODE,
      COOKIE_PRIORITY_DEFAULT));
  list.push_back(CanonicalCookie(
      "Y", "Z", "." + http_www_foo_.url().host(), "/", base::Time::Now(),
      base::Time(), base::Time(), false, false, CookieSameSite::DEFAULT_MODE,
      COOKIE_PRIORITY_DEFAULT));

  // SetAllCookies must not flush.
  ASSERT_EQ(0, store->flush_count());
  EXPECT_TRUE(SetAllCookies(cm.get(), list));
  EXPECT_EQ(0, store->flush_count());

  CookieList cookies = GetAllCookies(cm.get());
  size_t expected_size = 3;  // "A", "W" and "Y". "U" is gone.
  EXPECT_EQ(expected_size, cookies.size());
  CookieList::iterator it = cookies.begin();

  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ("W", it->Name());
  EXPECT_EQ("X", it->Value());
  EXPECT_EQ("/bar", it->Path());  // The path has been updated.

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ("A", it->Name());
  EXPECT_EQ("B", it->Value());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ("Y", it->Name());
  EXPECT_EQ("Z", it->Value());
}

TEST_F(CookieMonsterTest, ComputeCookieDiff) {
  std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));

  base::Time now = base::Time::Now();
  base::Time creation_time = now - base::TimeDelta::FromSeconds(1);

  std::unique_ptr<CanonicalCookie> cookie1(base::MakeUnique<CanonicalCookie>(
      "A", "B", "." + http_www_foo_.url().host(), "/", creation_time,
      base::Time(), base::Time(), false, false, CookieSameSite::DEFAULT_MODE,
      COOKIE_PRIORITY_DEFAULT));
  std::unique_ptr<CanonicalCookie> cookie2(base::MakeUnique<CanonicalCookie>(
      "C", "D", "." + http_www_foo_.url().host(), "/", creation_time,
      base::Time(), base::Time(), false, false, CookieSameSite::DEFAULT_MODE,
      COOKIE_PRIORITY_DEFAULT));
  std::unique_ptr<CanonicalCookie> cookie3(base::MakeUnique<CanonicalCookie>(
      "E", "F", "." + http_www_foo_.url().host(), "/", creation_time,
      base::Time(), base::Time(), false, false, CookieSameSite::DEFAULT_MODE,
      COOKIE_PRIORITY_DEFAULT));
  std::unique_ptr<CanonicalCookie> cookie4(base::MakeUnique<CanonicalCookie>(
      "G", "H", "." + http_www_foo_.url().host(), "/", creation_time,
      base::Time(), base::Time(), false, false, CookieSameSite::DEFAULT_MODE,
      COOKIE_PRIORITY_DEFAULT));
  std::unique_ptr<CanonicalCookie> cookie4_with_new_value(
      base::MakeUnique<CanonicalCookie>(
          "G", "iamnew", "." + http_www_foo_.url().host(), "/", creation_time,
          base::Time(), base::Time(), false, false,
          CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));
  std::unique_ptr<CanonicalCookie> cookie5(base::MakeUnique<CanonicalCookie>(
      "I", "J", "." + http_www_foo_.url().host(), "/", creation_time,
      base::Time(), base::Time(), false, false, CookieSameSite::DEFAULT_MODE,
      COOKIE_PRIORITY_DEFAULT));
  std::unique_ptr<CanonicalCookie> cookie5_with_new_creation_time(
      base::MakeUnique<CanonicalCookie>(
          "I", "J", "." + http_www_foo_.url().host(), "/", now, base::Time(),
          base::Time(), false, false, CookieSameSite::DEFAULT_MODE,
          COOKIE_PRIORITY_DEFAULT));
  std::unique_ptr<CanonicalCookie> cookie6(base::MakeUnique<CanonicalCookie>(
      "K", "L", "." + http_www_foo_.url().host(), "/foo", creation_time,
      base::Time(), base::Time(), false, false, CookieSameSite::DEFAULT_MODE,
      COOKIE_PRIORITY_DEFAULT));
  std::unique_ptr<CanonicalCookie> cookie6_with_new_path(
      base::MakeUnique<CanonicalCookie>(
          "K", "L", "." + http_www_foo_.url().host(), "/bar", creation_time,
          base::Time(), base::Time(), false, false,
          CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));
  std::unique_ptr<CanonicalCookie> cookie7(base::MakeUnique<CanonicalCookie>(
      "M", "N", "." + http_www_foo_.url().host(), "/foo", creation_time,
      base::Time(), base::Time(), false, false, CookieSameSite::DEFAULT_MODE,
      COOKIE_PRIORITY_DEFAULT));
  std::unique_ptr<CanonicalCookie> cookie7_with_new_path(
      base::MakeUnique<CanonicalCookie>(
          "M", "N", "." + http_www_foo_.url().host(), "/bar", creation_time,
          base::Time(), base::Time(), false, false,
          CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));

  CookieList old_cookies;
  old_cookies.push_back(*cookie1);
  old_cookies.push_back(*cookie2);
  old_cookies.push_back(*cookie4);
  old_cookies.push_back(*cookie5);
  old_cookies.push_back(*cookie6);
  old_cookies.push_back(*cookie7);

  CookieList new_cookies;
  new_cookies.push_back(*cookie1);
  new_cookies.push_back(*cookie3);
  new_cookies.push_back(*cookie4_with_new_value);
  new_cookies.push_back(*cookie5_with_new_creation_time);
  new_cookies.push_back(*cookie6_with_new_path);
  new_cookies.push_back(*cookie7);
  new_cookies.push_back(*cookie7_with_new_path);

  CookieList cookies_to_add;
  CookieList cookies_to_delete;

  cm->ComputeCookieDiff(&old_cookies, &new_cookies, &cookies_to_add,
                        &cookies_to_delete);

  // |cookie1| has not changed.
  EXPECT_FALSE(IsCookieInList(*cookie1, cookies_to_add));
  EXPECT_FALSE(IsCookieInList(*cookie1, cookies_to_delete));

  // |cookie2| has been deleted.
  EXPECT_FALSE(IsCookieInList(*cookie2, cookies_to_add));
  EXPECT_TRUE(IsCookieInList(*cookie2, cookies_to_delete));

  // |cookie3| has been added.
  EXPECT_TRUE(IsCookieInList(*cookie3, cookies_to_add));
  EXPECT_FALSE(IsCookieInList(*cookie3, cookies_to_delete));

  // |cookie4| has a new value: new cookie overrides the old one (which does not
  // need to be explicitly removed).
  EXPECT_FALSE(IsCookieInList(*cookie4, cookies_to_add));
  EXPECT_FALSE(IsCookieInList(*cookie4, cookies_to_delete));
  EXPECT_TRUE(IsCookieInList(*cookie4_with_new_value, cookies_to_add));
  EXPECT_FALSE(IsCookieInList(*cookie4_with_new_value, cookies_to_delete));

  // |cookie5| has a new creation time: new cookie overrides the old one (which
  // does not need to be explicitly removed).
  EXPECT_FALSE(IsCookieInList(*cookie5, cookies_to_add));
  EXPECT_FALSE(IsCookieInList(*cookie5, cookies_to_delete));
  EXPECT_TRUE(IsCookieInList(*cookie5_with_new_creation_time, cookies_to_add));
  EXPECT_FALSE(
      IsCookieInList(*cookie5_with_new_creation_time, cookies_to_delete));

  // |cookie6| has a new path: the new cookie does not overrides the old one,
  // which needs to be explicitly removed.
  EXPECT_FALSE(IsCookieInList(*cookie6, cookies_to_add));
  EXPECT_TRUE(IsCookieInList(*cookie6, cookies_to_delete));
  EXPECT_TRUE(IsCookieInList(*cookie6_with_new_path, cookies_to_add));
  EXPECT_FALSE(IsCookieInList(*cookie6_with_new_path, cookies_to_delete));

  // |cookie7| is kept and |cookie7_with_new_path| is added as a new cookie.
  EXPECT_FALSE(IsCookieInList(*cookie7, cookies_to_add));
  EXPECT_FALSE(IsCookieInList(*cookie7, cookies_to_delete));
  EXPECT_TRUE(IsCookieInList(*cookie7_with_new_path, cookies_to_add));
  EXPECT_FALSE(IsCookieInList(*cookie7_with_new_path, cookies_to_delete));
}

// Check that DeleteAll does flush (as a sanity check that flush_count()
// works).
TEST_F(CookieMonsterTest, DeleteAll) {
  scoped_refptr<FlushablePersistentStore> store(new FlushablePersistentStore());
  std::unique_ptr<CookieMonster> cm(new CookieMonster(store.get(), nullptr));
  cm->SetPersistSessionCookies(true);

  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "X=Y; path=/"));

  ASSERT_EQ(0, store->flush_count());
  EXPECT_EQ(1, DeleteAll(cm.get()));
  EXPECT_EQ(1, store->flush_count());
}

TEST_F(CookieMonsterTest, HistogramCheck) {
  std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));
  // Should match call in InitializeHistograms, but doesn't really matter
  // since the histogram should have been initialized by the CM construction
  // above.
  base::HistogramBase* expired_histogram = base::Histogram::FactoryGet(
      "Cookie.ExpirationDurationMinutes", 1, 10 * 365 * 24 * 60, 50,
      base::Histogram::kUmaTargetedHistogramFlag);

  std::unique_ptr<base::HistogramSamples> samples1(
      expired_histogram->SnapshotSamples());
  ASSERT_TRUE(SetCookieWithDetails(
      cm.get(), GURL("http://fake.a.url"), "a", "b", "a.url", "/", base::Time(),
      base::Time::Now() + base::TimeDelta::FromMinutes(59), base::Time(), false,
      false, CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));

  std::unique_ptr<base::HistogramSamples> samples2(
      expired_histogram->SnapshotSamples());
  EXPECT_EQ(samples1->TotalCount() + 1, samples2->TotalCount());

  // kValidCookieLine creates a session cookie.
  ASSERT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), kValidCookieLine));

  std::unique_ptr<base::HistogramSamples> samples3(
      expired_histogram->SnapshotSamples());
  EXPECT_EQ(samples2->TotalCount(), samples3->TotalCount());
}

TEST_F(CookieMonsterTest, InvalidExpiryTime) {
  std::string cookie_line =
      std::string(kValidCookieLine) + "; expires=Blarg arg arg";
  std::unique_ptr<CanonicalCookie> cookie(CanonicalCookie::Create(
      http_www_foo_.url(), cookie_line, Time::Now(), CookieOptions()));
  ASSERT_FALSE(cookie->IsPersistent());
}

// Test that CookieMonster writes session cookies into the underlying
// CookieStore if the "persist session cookies" option is on.
TEST_F(CookieMonsterTest, PersistSessionCookies) {
  scoped_refptr<MockPersistentCookieStore> store(new MockPersistentCookieStore);
  std::unique_ptr<CookieMonster> cm(new CookieMonster(store.get(), nullptr));
  cm->SetPersistSessionCookies(true);

  // All cookies set with SetCookie are session cookies.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=B"));
  EXPECT_EQ("A=B", GetCookies(cm.get(), http_www_foo_.url()));

  // The cookie was written to the backing store.
  EXPECT_EQ(1u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::ADD, store->commands()[0].type);
  EXPECT_EQ("A", store->commands()[0].cookie.Name());
  EXPECT_EQ("B", store->commands()[0].cookie.Value());

  // Modify the cookie.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=C"));
  EXPECT_EQ("A=C", GetCookies(cm.get(), http_www_foo_.url()));
  EXPECT_EQ(3u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[1].type);
  EXPECT_EQ("A", store->commands()[1].cookie.Name());
  EXPECT_EQ("B", store->commands()[1].cookie.Value());
  EXPECT_EQ(CookieStoreCommand::ADD, store->commands()[2].type);
  EXPECT_EQ("A", store->commands()[2].cookie.Name());
  EXPECT_EQ("C", store->commands()[2].cookie.Value());

  // Delete the cookie.
  DeleteCookie(cm.get(), http_www_foo_.url(), "A");
  EXPECT_EQ("", GetCookies(cm.get(), http_www_foo_.url()));
  EXPECT_EQ(4u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[3].type);
  EXPECT_EQ("A", store->commands()[3].cookie.Name());
  EXPECT_EQ("C", store->commands()[3].cookie.Value());
}

// Test the commands sent to the persistent cookie store.
TEST_F(CookieMonsterTest, PersisentCookieStorageTest) {
  scoped_refptr<MockPersistentCookieStore> store(new MockPersistentCookieStore);
  std::unique_ptr<CookieMonster> cm(new CookieMonster(store.get(), nullptr));

  // Add a cookie.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(),
                        "A=B; expires=Mon, 18-Apr-22 22:50:13 GMT"));
  this->MatchCookieLines("A=B", GetCookies(cm.get(), http_www_foo_.url()));
  ASSERT_EQ(1u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::ADD, store->commands()[0].type);
  // Remove it.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=B; max-age=0"));
  this->MatchCookieLines(std::string(),
                         GetCookies(cm.get(), http_www_foo_.url()));
  ASSERT_EQ(2u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[1].type);

  // Add a cookie.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(),
                        "A=B; expires=Mon, 18-Apr-22 22:50:13 GMT"));
  this->MatchCookieLines("A=B", GetCookies(cm.get(), http_www_foo_.url()));
  ASSERT_EQ(3u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::ADD, store->commands()[2].type);
  // Overwrite it.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(),
                        "A=Foo; expires=Mon, 18-Apr-22 22:50:14 GMT"));
  this->MatchCookieLines("A=Foo", GetCookies(cm.get(), http_www_foo_.url()));
  ASSERT_EQ(5u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[3].type);
  EXPECT_EQ(CookieStoreCommand::ADD, store->commands()[4].type);

  // Create some non-persistent cookies and check that they don't go to the
  // persistent storage.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "B=Bar"));
  this->MatchCookieLines("A=Foo; B=Bar",
                         GetCookies(cm.get(), http_www_foo_.url()));
  EXPECT_EQ(5u, store->commands().size());
}

// Test to assure that cookies with control characters are purged appropriately.
// See http://crbug.com/238041 for background.
TEST_F(CookieMonsterTest, ControlCharacterPurge) {
  const Time now1(Time::Now());
  const Time now2(Time::Now() + TimeDelta::FromSeconds(1));
  const Time now3(Time::Now() + TimeDelta::FromSeconds(2));
  const Time later(now1 + TimeDelta::FromDays(1));
  const GURL url("http://host/path");
  const std::string domain("host");
  const std::string path("/path");

  scoped_refptr<MockPersistentCookieStore> store(new MockPersistentCookieStore);

  std::vector<std::unique_ptr<CanonicalCookie>> initial_cookies;

  AddCookieToList(url, "foo=bar; path=" + path, now1, &initial_cookies);

  // We have to manually build this cookie because it contains a control
  // character, and our cookie line parser rejects control characters.
  std::unique_ptr<CanonicalCookie> cc = base::MakeUnique<CanonicalCookie>(
      "baz",
      "\x05"
      "boo",
      "." + domain, path, now2, later, base::Time(), false, false,
      CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT);
  initial_cookies.push_back(std::move(cc));

  AddCookieToList(url, "hello=world; path=" + path, now3, &initial_cookies);

  // Inject our initial cookies into the mock PersistentCookieStore.
  store->SetLoadExpectation(true, std::move(initial_cookies));

  std::unique_ptr<CookieMonster> cm(new CookieMonster(store.get(), nullptr));

  EXPECT_EQ("foo=bar; hello=world", GetCookies(cm.get(), url));
}

// Test that cookie source schemes are histogrammed correctly.
TEST_F(CookieMonsterTest, CookieSourceHistogram) {
  base::HistogramTester histograms;
  const std::string cookie_source_histogram = "Cookie.CookieSourceScheme";

  scoped_refptr<MockPersistentCookieStore> store(new MockPersistentCookieStore);
  std::unique_ptr<CookieMonster> cm(new CookieMonster(store.get(), nullptr));

  histograms.ExpectTotalCount(cookie_source_histogram, 0);

  // Set a secure cookie on a cryptographic scheme.
  EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(), "A=B; path=/; Secure"));
  histograms.ExpectTotalCount(cookie_source_histogram, 1);
  histograms.ExpectBucketCount(
      cookie_source_histogram,
      CookieMonster::COOKIE_SOURCE_SECURE_COOKIE_CRYPTOGRAPHIC_SCHEME, 1);

  // Set a non-secure cookie on a cryptographic scheme.
  EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(), "C=D; path=/;"));
  histograms.ExpectTotalCount(cookie_source_histogram, 2);
  histograms.ExpectBucketCount(
      cookie_source_histogram,
      CookieMonster::COOKIE_SOURCE_NONSECURE_COOKIE_CRYPTOGRAPHIC_SCHEME, 1);

  // Set a secure cookie on a non-cryptographic scheme.
  EXPECT_FALSE(SetCookie(cm.get(), http_www_foo_.url(), "D=E; path=/; Secure"));
  histograms.ExpectTotalCount(cookie_source_histogram, 2);
  histograms.ExpectBucketCount(
      cookie_source_histogram,
      CookieMonster::COOKIE_SOURCE_SECURE_COOKIE_NONCRYPTOGRAPHIC_SCHEME, 0);

  // Overwrite a secure cookie (set by a cryptographic scheme) on a
  // non-cryptographic scheme.
  EXPECT_FALSE(SetCookie(cm.get(), http_www_foo_.url(), "A=B; path=/; Secure"));
  histograms.ExpectTotalCount(cookie_source_histogram, 2);
  histograms.ExpectBucketCount(
      cookie_source_histogram,
      CookieMonster::COOKIE_SOURCE_SECURE_COOKIE_CRYPTOGRAPHIC_SCHEME, 1);
  histograms.ExpectBucketCount(
      cookie_source_histogram,
      CookieMonster::COOKIE_SOURCE_SECURE_COOKIE_NONCRYPTOGRAPHIC_SCHEME, 0);

  // Test that attempting to clear a secure cookie on a http:// URL does
  // nothing.
  EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(), "F=G; path=/; Secure"));
  histograms.ExpectTotalCount(cookie_source_histogram, 3);
  std::string cookies1 = GetCookies(cm.get(), https_www_foo_.url());
  EXPECT_NE(std::string::npos, cookies1.find("F=G"));
  EXPECT_FALSE(SetCookie(cm.get(), http_www_foo_.url(),
                         "F=G; path=/; Expires=Thu, 01-Jan-1970 00:00:01 GMT"));
  std::string cookies2 = GetCookies(cm.get(), https_www_foo_.url());
  EXPECT_NE(std::string::npos, cookies2.find("F=G"));
  histograms.ExpectTotalCount(cookie_source_histogram, 3);

  // Set a non-secure cookie on a non-cryptographic scheme.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "H=I; path=/"));
  histograms.ExpectTotalCount(cookie_source_histogram, 4);
  histograms.ExpectBucketCount(
      cookie_source_histogram,
      CookieMonster::COOKIE_SOURCE_NONSECURE_COOKIE_NONCRYPTOGRAPHIC_SCHEME, 1);
}

// Test that cookie delete equivalent histograms are recorded correctly.
TEST_F(CookieMonsterTest, CookieDeleteEquivalentHistogramTest) {
  base::HistogramTester histograms;
  const std::string cookie_source_histogram = "Cookie.CookieDeleteEquivalent";

  scoped_refptr<MockPersistentCookieStore> store(new MockPersistentCookieStore);
  std::unique_ptr<CookieMonster> cm(new CookieMonster(store.get(), nullptr));

  // Set a secure cookie from a secure origin
  EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(), "A=B; Secure"));
  histograms.ExpectTotalCount(cookie_source_histogram, 1);
  histograms.ExpectBucketCount(cookie_source_histogram,
                               CookieMonster::COOKIE_DELETE_EQUIVALENT_ATTEMPT,
                               1);

  // Set a new cookie with a different name from a variety of origins (including
  // the same one).
  EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(), "B=A;"));
  histograms.ExpectTotalCount(cookie_source_histogram, 2);
  histograms.ExpectBucketCount(cookie_source_histogram,
                               CookieMonster::COOKIE_DELETE_EQUIVALENT_ATTEMPT,
                               2);
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "C=A;"));
  histograms.ExpectTotalCount(cookie_source_histogram, 3);
  histograms.ExpectBucketCount(cookie_source_histogram,
                               CookieMonster::COOKIE_DELETE_EQUIVALENT_ATTEMPT,
                               3);

  // Set a non-secure cookie from an insecure origin that matches the name of an
  // already existing cookie and additionally is equivalent to the existing
  // cookie. This should fail since it's trying to overwrite a secure cookie.
  EXPECT_FALSE(SetCookie(cm.get(), http_www_foo_.url(), "A=B;"));
  histograms.ExpectTotalCount(cookie_source_histogram, 6);
  histograms.ExpectBucketCount(cookie_source_histogram,
                               CookieMonster::COOKIE_DELETE_EQUIVALENT_ATTEMPT,
                               4);
  histograms.ExpectBucketCount(cookie_source_histogram,
                               CookieMonster::COOKIE_DELETE_EQUIVALENT_FOUND,
                               0);
  histograms.ExpectBucketCount(
      cookie_source_histogram,
      CookieMonster::COOKIE_DELETE_EQUIVALENT_SKIPPING_SECURE, 1);
  histograms.ExpectBucketCount(
      cookie_source_histogram,
      CookieMonster::COOKIE_DELETE_EQUIVALENT_WOULD_HAVE_DELETED, 1);

  // Set a non-secure cookie from an insecure origin that matches the name of an
  // already existing cookie but is not equivalent. This should fail since it's
  // trying to shadow a secure cookie.
  EXPECT_FALSE(
      SetCookie(cm.get(), http_www_foo_.url(), "A=C; path=/some/path"));
  histograms.ExpectTotalCount(cookie_source_histogram, 8);
  histograms.ExpectBucketCount(cookie_source_histogram,
                               CookieMonster::COOKIE_DELETE_EQUIVALENT_ATTEMPT,
                               5);
  histograms.ExpectBucketCount(
      cookie_source_histogram,
      CookieMonster::COOKIE_DELETE_EQUIVALENT_SKIPPING_SECURE, 2);

  // Set a secure cookie from a secure origin that matches the name of an
  // already existing cookies and is equivalent.
  EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(), "A=D; secure"));
  histograms.ExpectTotalCount(cookie_source_histogram, 10);
  histograms.ExpectBucketCount(cookie_source_histogram,
                               CookieMonster::COOKIE_DELETE_EQUIVALENT_ATTEMPT,
                               6);
  histograms.ExpectBucketCount(cookie_source_histogram,
                               CookieMonster::COOKIE_DELETE_EQUIVALENT_FOUND,
                               1);

  // Set a secure cookie from a secure origin that matches the name of an
  // already existing cookie and is not equivalent.
  EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(),
                        "A=E; secure; path=/some/other/path"));
  histograms.ExpectTotalCount(cookie_source_histogram, 11);
  histograms.ExpectBucketCount(cookie_source_histogram,
                               CookieMonster::COOKIE_DELETE_EQUIVALENT_ATTEMPT,
                               7);
}

TEST_F(CookieMonsterTest, SetSecureCookies) {
  std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));
  GURL http_url("http://www.foo.com");
  GURL http_superdomain_url("http://foo.com");
  GURL https_url("https://www.foo.com");

  // A non-secure cookie can be created from either a URL with a secure or
  // insecure scheme.
  EXPECT_TRUE(SetCookie(cm.get(), http_url, "A=C;"));
  EXPECT_TRUE(SetCookie(cm.get(), https_url, "A=B;"));

  // A secure cookie cannot be created from a URL with an insecure scheme.
  EXPECT_FALSE(SetCookie(cm.get(), http_url, "A=B; Secure"));

  // A secure cookie can be created from a URL with a secure scheme.
  EXPECT_TRUE(SetCookie(cm.get(), https_url, "A=B; Secure"));

  // If a non-secure cookie is created from a URL with an insecure scheme, and a
  // secure cookie with the same name already exists, do not update the cookie.
  EXPECT_TRUE(SetCookie(cm.get(), https_url, "A=B; Secure"));
  EXPECT_FALSE(SetCookie(cm.get(), http_url, "A=C;"));

  // If a non-secure cookie is created from a URL with an secure scheme, and a
  // secure cookie with the same name already exists, update the cookie.
  EXPECT_TRUE(SetCookie(cm.get(), https_url, "A=B; Secure"));
  EXPECT_TRUE(SetCookie(cm.get(), https_url, "A=C;"));

  // If a non-secure cookie is created from a URL with an insecure scheme, and
  // a secure cookie with the same name already exists, do not update the cookie
  // if the new cookie's path matches the existing cookie's path.
  //
  // With an existing cookie whose path is '/', a cookie with the same name
  // cannot be set on the same domain, regardless of path:
  EXPECT_TRUE(SetCookie(cm.get(), https_url, "A=B; Secure"));
  EXPECT_FALSE(SetCookie(cm.get(), http_url, "A=C; path=/"));
  EXPECT_FALSE(SetCookie(cm.get(), http_url, "A=C; path=/my/path"));

  // But if the existing cookie has a path somewhere under the root, cookies
  // with the same name may be set for paths which don't overlap the existing
  // cookie.
  EXPECT_TRUE(
      SetCookie(cm.get(), https_url, "WITH_PATH=B; Secure; path=/my/path"));
  EXPECT_TRUE(SetCookie(cm.get(), http_url, "WITH_PATH=C"));
  EXPECT_TRUE(SetCookie(cm.get(), http_url, "WITH_PATH=C; path=/"));
  EXPECT_TRUE(SetCookie(cm.get(), http_url, "WITH_PATH=C; path=/your/path"));
  EXPECT_FALSE(SetCookie(cm.get(), http_url, "WITH_PATH=C; path=/my/path"));
  EXPECT_FALSE(SetCookie(cm.get(), http_url, "WITH_PATH=C; path=/my/path/sub"));

  // If a non-secure cookie is created from a URL with an insecure scheme, and
  // a secure cookie with the same name already exists, if the domain strings
  // domain-match, do not update the cookie.
  EXPECT_TRUE(SetCookie(cm.get(), https_url, "A=B; Secure"));
  EXPECT_FALSE(SetCookie(cm.get(), http_url, "A=C; domain=foo.com"));
  EXPECT_FALSE(SetCookie(cm.get(), http_url, "A=C; domain=www.foo.com"));

  // Since A=B was set above with no domain string, set a different cookie here
  // so the insecure examples aren't trying to overwrite the one above.
  EXPECT_TRUE(SetCookie(cm.get(), https_url, "B=C; Secure; domain=foo.com"));
  EXPECT_FALSE(SetCookie(cm.get(), http_url, "B=D; domain=foo.com"));
  EXPECT_FALSE(SetCookie(cm.get(), http_url, "B=D"));
  EXPECT_FALSE(SetCookie(cm.get(), http_superdomain_url, "B=D"));

  // Verify that if an httponly version of the cookie exists, adding a Secure
  // version of the cookie still does not overwrite it.
  CookieOptions include_httponly;
  include_httponly.set_include_httponly();
  EXPECT_TRUE(SetCookieWithOptions(cm.get(), https_url, "C=D; httponly",
                                   include_httponly));
  // Note that the lack of an explicit options object below uses the default,
  // which in this case includes "exclude_httponly = true".
  EXPECT_FALSE(SetCookie(cm.get(), https_url, "C=E; Secure"));
}

// Tests for behavior for strict secure cookies.
TEST_F(CookieMonsterTest, EvictSecureCookies) {
  // Hard-coding limits in the test, but use DCHECK_EQ to enforce constraint.
  DCHECK_EQ(180U, CookieMonster::kDomainMaxCookies);
  DCHECK_EQ(150U, CookieMonster::kDomainMaxCookies -
                      CookieMonster::kDomainPurgeCookies);
  DCHECK_EQ(3300U, CookieMonster::kMaxCookies);
  DCHECK_EQ(30, CookieMonster::kSafeFromGlobalPurgeDays);

  // If secure cookies for one domain hit the per domain limit (180), a
  // non-secure cookie will not evict them (and, in fact, the non-secure cookie
  // will be removed right after creation).
  const CookiesEntry test1[] = {{180U, true}, {1U, false}};
  TestSecureCookieEviction(test1, arraysize(test1), 150U, 0U, nullptr);

  // If non-secure cookies for one domain hit the per domain limit (180), the
  // creation of secure cookies will evict the non-secure cookies first, making
  // room for the secure cookies.
  const CookiesEntry test2[] = {{180U, false}, {20U, true}};
  TestSecureCookieEviction(test2, arraysize(test2), 20U, 149U, nullptr);

  // If secure cookies for one domain go past the per domain limit (180), they
  // will be evicted as normal by the per domain purge amount (30) down to a
  // lower amount (150), and then will continue to create the remaining cookies
  // (19 more to 169).
  const CookiesEntry test3[] = {{200U, true}};
  TestSecureCookieEviction(test3, arraysize(test3), 169U, 0U, nullptr);

  // If a non-secure cookie is created, and a number of secure cookies exceeds
  // the per domain limit (18), the total cookies will be evicted down to a
  // lower amount (150), enforcing the eviction of the non-secure cookie, and
  // the remaining secure cookies will be created (another 19 to 169).
  const CookiesEntry test4[] = {{1U, false}, {199U, true}};
  TestSecureCookieEviction(test4, arraysize(test4), 169U, 0U, nullptr);

  // If an even number of non-secure and secure cookies are created below the
  // per-domain limit (180), all will be created and none evicted.
  const CookiesEntry test5[] = {{75U, false}, {75U, true}};
  TestSecureCookieEviction(test5, arraysize(test5), 75U, 75U, nullptr);

  // If the same number of secure and non-secure cookies are created (50 each)
  // below the per domain limit (180), and then another set of secure cookies
  // are created to bring the total above the per-domain limit, all secure
  // cookies will be retained, and the non-secure cookies will be culled down
  // to the limit.
  const CookiesEntry test6[] = {{50U, true}, {50U, false}, {81U, true}};
  TestSecureCookieEviction(test6, arraysize(test6), 131U, 19U, nullptr);

  // If the same number of non-secure and secure cookies are created (50 each)
  // below the per domain limit (180), and then another set of non-secure
  // cookies are created to bring the total above the per-domain limit, all
  // secure cookies will be retained, and the non-secure cookies will be culled
  // down to the limit.
  const CookiesEntry test7[] = {{50U, false}, {50U, true}, {81U, false}};
  TestSecureCookieEviction(test7, arraysize(test7), 50U, 100U, nullptr);

  // If the same number of non-secure and secure cookies are created (50 each)
  // below the per domain limit (180), and then another set of non-secure
  // cookies are created to bring the total above the per-domain limit, all
  // secure cookies will be retained, and the non-secure cookies will be culled
  // down to the limit, then the remaining non-secure cookies will be created
  // (9).
  const CookiesEntry test8[] = {{50U, false}, {50U, true}, {90U, false}};
  TestSecureCookieEviction(test8, arraysize(test8), 50U, 109U, nullptr);

  // If a number of non-secure cookies are created on other hosts (20) and are
  // past the global 'safe' date, and then the number of non-secure cookies for
  // a single domain are brought to the per-domain limit (180), followed by
  // another set of secure cookies on that same domain (20), all the secure
  // cookies for that domain should be retained, while the non-secure should be
  // culled down to the per-domain limit. The non-secure cookies for other
  // domains should remain untouched.
  const CookiesEntry test9[] = {{180U, false}, {20U, true}};
  const AltHosts test9_alt_hosts(0, 20);
  TestSecureCookieEviction(test9, arraysize(test9), 20U, 169U,
                           &test9_alt_hosts);

  // If a number of secure cookies are created on other hosts and hit the global
  // cookie limit (3300) and are past the global 'safe' date, and then a single
  // non-secure cookie is created now, the secure cookies are removed so that
  // the global total number of cookies is at the global purge goal (3000), but
  // the non-secure cookie is not evicted since it is too young.
  const CookiesEntry test10[] = {{1U, false}};
  const AltHosts test10_alt_hosts(3300, 0);
  TestSecureCookieEviction(test10, arraysize(test10), 2999U, 1U,
                           &test10_alt_hosts);

  // If a number of non-secure cookies are created on other hosts and hit the
  // global cookie limit (3300) and are past the global 'safe' date, and then a
  // single non-secure cookie is created now, the non-secure cookies are removed
  // so that the global total number of cookies is at the global purge goal
  // (3000).
  const CookiesEntry test11[] = {{1U, false}};
  const AltHosts test11_alt_hosts(0, 3300);
  TestSecureCookieEviction(test11, arraysize(test11), 0U, 3000U,
                           &test11_alt_hosts);

  // If a number of non-secure cookies are created on other hosts and hit the
  // global cookie limit (3300) and are past the global 'safe' date, and then a
  // single ecure cookie is created now, the non-secure cookies are removed so
  // that the global total number of cookies is at the global purge goal (3000),
  // but the secure cookie is not evicted.
  const CookiesEntry test12[] = {{1U, true}};
  const AltHosts test12_alt_hosts(0, 3300);
  TestSecureCookieEviction(test12, arraysize(test12), 1U, 2999U,
                           &test12_alt_hosts);

  // If a total number of secure and non-secure cookies are created on other
  // hosts and hit the global cookie limit (3300) and are past the global 'safe'
  // date, and then a single non-secure cookie is created now, the global
  // non-secure cookies are removed so that the global total number of cookies
  // is at the global purge goal (3000), but the secure cookies are not evicted.
  const CookiesEntry test13[] = {{1U, false}};
  const AltHosts test13_alt_hosts(1500, 1800);
  TestSecureCookieEviction(test13, arraysize(test13), 1500U, 1500,
                           &test13_alt_hosts);

  // If a total number of secure and non-secure cookies are created on other
  // hosts and hit the global cookie limit (3300) and are past the global 'safe'
  // date, and then a single secure cookie is created now, the global non-secure
  // cookies are removed so that the global total number of cookies is at the
  // global purge goal (3000), but the secure cookies are not evicted.
  const CookiesEntry test14[] = {{1U, true}};
  const AltHosts test14_alt_hosts(1500, 1800);
  TestSecureCookieEviction(test14, arraysize(test14), 1501U, 1499,
                           &test14_alt_hosts);
}

// Tests that strict secure cookies doesn't trip equivalent cookie checks
// accidentally. Regression test for https://crbug.com/569943.
TEST_F(CookieMonsterTest, EquivalentCookies) {
  std::unique_ptr<CookieMonster> cm(new CookieMonster(nullptr, nullptr));
  GURL http_url("http://www.foo.com");
  GURL http_superdomain_url("http://foo.com");
  GURL https_url("https://www.foo.com");

  // Tests that non-equivalent cookies because of the path attribute can be set
  // successfully.
  EXPECT_TRUE(SetCookie(cm.get(), https_url, "A=B; Secure"));
  EXPECT_TRUE(SetCookie(cm.get(), https_url, "A=C; path=/some/other/path"));
  EXPECT_FALSE(SetCookie(cm.get(), http_url, "A=D; path=/some/other/path"));

  // Tests that non-equivalent cookies because of the domain attribute can be
  // set successfully.
  EXPECT_TRUE(SetCookie(cm.get(), https_url, "A=B; Secure"));
  EXPECT_TRUE(SetCookie(cm.get(), https_url, "A=C; domain=foo.com"));
  EXPECT_FALSE(SetCookie(cm.get(), http_url, "A=D; domain=foo.com"));
}

class CookieMonsterNotificationTest : public CookieMonsterTest {
 public:
  CookieMonsterNotificationTest()
      : test_url_("http://www.foo.com/foo"),
        store_(new MockPersistentCookieStore),
        monster_(new CookieMonster(store_.get(), nullptr)) {}

  ~CookieMonsterNotificationTest() override {}

  CookieMonster* monster() { return monster_.get(); }

 protected:
  const GURL test_url_;

 private:
  scoped_refptr<MockPersistentCookieStore> store_;
  std::unique_ptr<CookieMonster> monster_;
};

void RecordCookieChanges(std::vector<CanonicalCookie>* out_cookies,
                         std::vector<CookieStore::ChangeCause>* out_causes,
                         const CanonicalCookie& cookie,
                         CookieStore::ChangeCause cause) {
  DCHECK(out_cookies);
  out_cookies->push_back(cookie);
  if (out_causes)
    out_causes->push_back(cause);
}

TEST_F(CookieMonsterNotificationTest, NoNotifyWithNoCookie) {
  std::vector<CanonicalCookie> cookies;
  std::unique_ptr<CookieStore::CookieChangedSubscription> sub(
      monster()->AddCallbackForCookie(
          test_url_, "abc",
          base::Bind(&RecordCookieChanges, &cookies, nullptr)));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0U, cookies.size());
}

TEST_F(CookieMonsterNotificationTest, NoNotifyWithInitialCookie) {
  std::vector<CanonicalCookie> cookies;
  SetCookie(monster(), test_url_, "abc=def");
  base::RunLoop().RunUntilIdle();
  std::unique_ptr<CookieStore::CookieChangedSubscription> sub(
      monster()->AddCallbackForCookie(
          test_url_, "abc",
          base::Bind(&RecordCookieChanges, &cookies, nullptr)));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0U, cookies.size());
}

TEST_F(CookieMonsterNotificationTest, NotifyOnSet) {
  std::vector<CanonicalCookie> cookies;
  std::vector<CookieStore::ChangeCause> causes;
  std::unique_ptr<CookieStore::CookieChangedSubscription> sub(
      monster()->AddCallbackForCookie(
          test_url_, "abc",
          base::Bind(&RecordCookieChanges, &cookies, &causes)));
  SetCookie(monster(), test_url_, "abc=def");
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1U, cookies.size());
  EXPECT_EQ(1U, causes.size());

  EXPECT_EQ("abc", cookies[0].Name());
  EXPECT_EQ("def", cookies[0].Value());
  EXPECT_EQ(CookieStore::ChangeCause::INSERTED, causes[0]);
}

TEST_F(CookieMonsterNotificationTest, NotifyOnDelete) {
  std::vector<CanonicalCookie> cookies;
  std::vector<CookieStore::ChangeCause> causes;
  std::unique_ptr<CookieStore::CookieChangedSubscription> sub(
      monster()->AddCallbackForCookie(
          test_url_, "abc",
          base::Bind(&RecordCookieChanges, &cookies, &causes)));
  SetCookie(monster(), test_url_, "abc=def");
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1U, cookies.size());
  EXPECT_EQ(1U, causes.size());

  DeleteCookie(monster(), test_url_, "abc");
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2U, cookies.size());
  EXPECT_EQ(2U, causes.size());

  EXPECT_EQ("abc", cookies[1].Name());
  EXPECT_EQ("def", cookies[1].Value());
  EXPECT_EQ(CookieStore::ChangeCause::EXPLICIT_DELETE_SINGLE, causes[1]);
}

TEST_F(CookieMonsterNotificationTest, NotifyOnUpdate) {
  std::vector<CanonicalCookie> cookies;
  std::vector<CookieStore::ChangeCause> causes;
  std::unique_ptr<CookieStore::CookieChangedSubscription> sub(
      monster()->AddCallbackForCookie(
          test_url_, "abc",
          base::Bind(&RecordCookieChanges, &cookies, &causes)));
  SetCookie(monster(), test_url_, "abc=def");
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1U, cookies.size());

  // Replacing an existing cookie is actually a two-phase delete + set
  // operation, so we get an extra notification.
  SetCookie(monster(), test_url_, "abc=ghi");
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(3U, cookies.size());
  EXPECT_EQ(3U, causes.size());

  EXPECT_EQ("abc", cookies[1].Name());
  EXPECT_EQ("def", cookies[1].Value());
  EXPECT_EQ(CookieStore::ChangeCause::OVERWRITE, causes[1]);

  EXPECT_EQ("abc", cookies[2].Name());
  EXPECT_EQ("ghi", cookies[2].Value());
  EXPECT_EQ(CookieStore::ChangeCause::INSERTED, causes[2]);
}

TEST_F(CookieMonsterNotificationTest, MultipleNotifies) {
  std::vector<CanonicalCookie> cookies0;
  std::vector<CanonicalCookie> cookies1;
  std::unique_ptr<CookieStore::CookieChangedSubscription> sub0(
      monster()->AddCallbackForCookie(
          test_url_, "abc",
          base::Bind(&RecordCookieChanges, &cookies0, nullptr)));
  std::unique_ptr<CookieStore::CookieChangedSubscription> sub1(
      monster()->AddCallbackForCookie(
          test_url_, "def",
          base::Bind(&RecordCookieChanges, &cookies1, nullptr)));
  SetCookie(monster(), test_url_, "abc=def");
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1U, cookies0.size());
  EXPECT_EQ(0U, cookies1.size());
  SetCookie(monster(), test_url_, "def=abc");
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1U, cookies0.size());
  EXPECT_EQ(1U, cookies1.size());
}

TEST_F(CookieMonsterNotificationTest, MultipleSameNotifies) {
  std::vector<CanonicalCookie> cookies0;
  std::vector<CanonicalCookie> cookies1;
  std::unique_ptr<CookieStore::CookieChangedSubscription> sub0(
      monster()->AddCallbackForCookie(
          test_url_, "abc",
          base::Bind(&RecordCookieChanges, &cookies0, nullptr)));
  std::unique_ptr<CookieStore::CookieChangedSubscription> sub1(
      monster()->AddCallbackForCookie(
          test_url_, "abc",
          base::Bind(&RecordCookieChanges, &cookies1, nullptr)));
  SetCookie(monster(), test_url_, "abc=def");
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1U, cookies0.size());
  EXPECT_EQ(1U, cookies0.size());
}

}  // namespace net
