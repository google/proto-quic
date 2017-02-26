// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Portions of this code based on Mozilla:
//   (netwerk/cookie/src/nsCookieService.cpp)
/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is mozilla.org code.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 2003
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Daniel Witte (dwitte@stanford.edu)
 *   Michiel van Leeuwen (mvl@exedo.nl)
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#include "net/cookies/cookie_monster.h"

#include <algorithm>
#include <functional>
#include <memory>
#include <set>

#include "base/bind.h"
#include "base/callback.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram.h"
#include "base/profiler/scoped_tracker.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_util.h"
#include "net/cookies/parsed_cookie.h"
#include "url/origin.h"

using base::Time;
using base::TimeDelta;
using base::TimeTicks;

// In steady state, most cookie requests can be satisfied by the in memory
// cookie monster store. If the cookie request cannot be satisfied by the in
// memory store, the relevant cookies must be fetched from the persistent
// store. The task is queued in CookieMonster::tasks_pending_ if it requires
// all cookies to be loaded from the backend, or tasks_pending_for_key_ if it
// only requires all cookies associated with an eTLD+1.
//
// On the browser critical paths (e.g. for loading initial web pages in a
// session restore) it may take too long to wait for the full load. If a cookie
// request is for a specific URL, DoCookieTaskForURL is called, which triggers a
// priority load if the key is not loaded yet by calling PersistentCookieStore
// :: LoadCookiesForKey. The request is queued in
// CookieMonster::tasks_pending_for_key_ and executed upon receiving
// notification of key load completion via CookieMonster::OnKeyLoaded(). If
// multiple requests for the same eTLD+1 are received before key load
// completion, only the first request calls
// PersistentCookieStore::LoadCookiesForKey, all subsequent requests are queued
// in CookieMonster::tasks_pending_for_key_ and executed upon receiving
// notification of key load completion triggered by the first request for the
// same eTLD+1.

static const int kMinutesInTenYears = 10 * 365 * 24 * 60;

namespace {

const char kFetchWhenNecessaryName[] = "FetchWhenNecessary";
const char kAlwaysFetchName[] = "AlwaysFetch";
const char kCookieMonsterFetchStrategyName[] = "CookieMonsterFetchStrategy";

}  // namespace

namespace net {

// See comments at declaration of these variables in cookie_monster.h
// for details.
const size_t CookieMonster::kDomainMaxCookies = 180;
const size_t CookieMonster::kDomainPurgeCookies = 30;
const size_t CookieMonster::kMaxCookies = 3300;
const size_t CookieMonster::kPurgeCookies = 300;

const size_t CookieMonster::kDomainCookiesQuotaLow = 30;
const size_t CookieMonster::kDomainCookiesQuotaMedium = 50;
const size_t CookieMonster::kDomainCookiesQuotaHigh =
    kDomainMaxCookies - kDomainPurgeCookies - kDomainCookiesQuotaLow -
    kDomainCookiesQuotaMedium;

const int CookieMonster::kSafeFromGlobalPurgeDays = 30;

namespace {

bool ContainsControlCharacter(const std::string& s) {
  for (std::string::const_iterator i = s.begin(); i != s.end(); ++i) {
    if ((*i >= 0) && (*i <= 31))
      return true;
  }

  return false;
}

typedef std::vector<CanonicalCookie*> CanonicalCookieVector;

// Default minimum delay after updating a cookie's LastAccessDate before we
// will update it again.
const int kDefaultAccessUpdateThresholdSeconds = 60;

// Comparator to sort cookies from highest creation date to lowest
// creation date.
struct OrderByCreationTimeDesc {
  bool operator()(const CookieMonster::CookieMap::iterator& a,
                  const CookieMonster::CookieMap::iterator& b) const {
    return a->second->CreationDate() > b->second->CreationDate();
  }
};

// Constants for use in VLOG
const int kVlogPerCookieMonster = 1;
const int kVlogGarbageCollection = 5;
const int kVlogSetCookies = 7;
const int kVlogGetCookies = 9;

// Mozilla sorts on the path length (longest first), and then it
// sorts by creation time (oldest first).
// The RFC says the sort order for the domain attribute is undefined.
bool CookieSorter(CanonicalCookie* cc1, CanonicalCookie* cc2) {
  if (cc1->Path().length() == cc2->Path().length())
    return cc1->CreationDate() < cc2->CreationDate();
  return cc1->Path().length() > cc2->Path().length();
}

bool LRACookieSorter(const CookieMonster::CookieMap::iterator& it1,
                     const CookieMonster::CookieMap::iterator& it2) {
  if (it1->second->LastAccessDate() != it2->second->LastAccessDate())
    return it1->second->LastAccessDate() < it2->second->LastAccessDate();

  // Ensure stability for == last access times by falling back to creation.
  return it1->second->CreationDate() < it2->second->CreationDate();
}

// Compare cookies using name, domain and path, so that "equivalent" cookies
// (per RFC 2965) are equal to each other.
bool PartialDiffCookieSorter(const CanonicalCookie& a,
                             const CanonicalCookie& b) {
  return a.PartialCompare(b);
}

// This is a stricter ordering than PartialDiffCookieOrdering, where all fields
// are used.
bool FullDiffCookieSorter(const CanonicalCookie& a, const CanonicalCookie& b) {
  return a.FullCompare(b);
}

// Our strategy to find duplicates is:
// (1) Build a map from (cookiename, cookiepath) to
//     {list of cookies with this signature, sorted by creation time}.
// (2) For each list with more than 1 entry, keep the cookie having the
//     most recent creation time, and delete the others.
//
// Two cookies are considered equivalent if they have the same domain,
// name, and path.
struct CookieSignature {
 public:
  CookieSignature(const std::string& name,
                  const std::string& domain,
                  const std::string& path)
      : name(name), domain(domain), path(path) {}

  // To be a key for a map this class needs to be assignable, copyable,
  // and have an operator<.  The default assignment operator
  // and copy constructor are exactly what we want.

  bool operator<(const CookieSignature& cs) const {
    // Name compare dominates, then domain, then path.
    int diff = name.compare(cs.name);
    if (diff != 0)
      return diff < 0;

    diff = domain.compare(cs.domain);
    if (diff != 0)
      return diff < 0;

    return path.compare(cs.path) < 0;
  }

  std::string name;
  std::string domain;
  std::string path;
};

// For a CookieItVector iterator range [|it_begin|, |it_end|),
// sorts the first |num_sort| + 1 elements by LastAccessDate().
// The + 1 element exists so for any interval of length <= |num_sort| starting
// from |cookies_its_begin|, a LastAccessDate() bound can be found.
void SortLeastRecentlyAccessed(CookieMonster::CookieItVector::iterator it_begin,
                               CookieMonster::CookieItVector::iterator it_end,
                               size_t num_sort) {
  DCHECK_LT(static_cast<int>(num_sort), it_end - it_begin);
  std::partial_sort(it_begin, it_begin + num_sort + 1, it_end, LRACookieSorter);
}

// Given a single cookie vector |cookie_its|, pushs all of the secure cookies in
// |cookie_its| into |secure_cookie_its| and all of the non-secure cookies into
// |non_secure_cookie_its|. Both |secure_cookie_its| and |non_secure_cookie_its|
// must be non-NULL.
void SplitCookieVectorIntoSecureAndNonSecure(
    const CookieMonster::CookieItVector& cookie_its,
    CookieMonster::CookieItVector* secure_cookie_its,
    CookieMonster::CookieItVector* non_secure_cookie_its) {
  DCHECK(secure_cookie_its && non_secure_cookie_its);
  for (const auto& curit : cookie_its) {
    if (curit->second->IsSecure())
      secure_cookie_its->push_back(curit);
    else
      non_secure_cookie_its->push_back(curit);
  }
}

bool LowerBoundAccessDateComparator(const CookieMonster::CookieMap::iterator it,
                                    const Time& access_date) {
  return it->second->LastAccessDate() < access_date;
}

// For a CookieItVector iterator range [|it_begin|, |it_end|)
// from a CookieItVector sorted by LastAccessDate(), returns the
// first iterator with access date >= |access_date|, or cookie_its_end if this
// holds for all.
CookieMonster::CookieItVector::iterator LowerBoundAccessDate(
    const CookieMonster::CookieItVector::iterator its_begin,
    const CookieMonster::CookieItVector::iterator its_end,
    const Time& access_date) {
  return std::lower_bound(its_begin, its_end, access_date,
                          LowerBoundAccessDateComparator);
}

// Mapping between DeletionCause and CookieStore::ChangeCause; the
// mapping also provides a boolean that specifies whether or not an
// OnCookieChanged notification ought to be generated.
typedef struct ChangeCausePair_struct {
  CookieStore::ChangeCause cause;
  bool notify;
} ChangeCausePair;
const ChangeCausePair kChangeCauseMapping[] = {
    // DELETE_COOKIE_EXPLICIT
    {CookieStore::ChangeCause::EXPLICIT, true},
    // DELETE_COOKIE_OVERWRITE
    {CookieStore::ChangeCause::OVERWRITE, true},
    // DELETE_COOKIE_EXPIRED
    {CookieStore::ChangeCause::EXPIRED, true},
    // DELETE_COOKIE_EVICTED
    {CookieStore::ChangeCause::EVICTED, true},
    // DELETE_COOKIE_DUPLICATE_IN_BACKING_STORE
    {CookieStore::ChangeCause::EXPLICIT, false},
    // DELETE_COOKIE_DONT_RECORD
    {CookieStore::ChangeCause::EXPLICIT, false},
    // DELETE_COOKIE_EVICTED_DOMAIN
    {CookieStore::ChangeCause::EVICTED, true},
    // DELETE_COOKIE_EVICTED_GLOBAL
    {CookieStore::ChangeCause::EVICTED, true},
    // DELETE_COOKIE_EVICTED_DOMAIN_PRE_SAFE
    {CookieStore::ChangeCause::EVICTED, true},
    // DELETE_COOKIE_EVICTED_DOMAIN_POST_SAFE
    {CookieStore::ChangeCause::EVICTED, true},
    // DELETE_COOKIE_EXPIRED_OVERWRITE
    {CookieStore::ChangeCause::EXPIRED_OVERWRITE, true},
    // DELETE_COOKIE_CONTROL_CHAR
    {CookieStore::ChangeCause::EVICTED, true},
    // DELETE_COOKIE_NON_SECURE
    {CookieStore::ChangeCause::EVICTED, true},
    // DELETE_COOKIE_CREATED_BETWEEN
    {CookieStore::ChangeCause::EXPLICIT_DELETE_BETWEEN, true},
    // DELETE_COOKIE_CREATED_BETWEEN_WITH_PREDICATE
    {CookieStore::ChangeCause::EXPLICIT_DELETE_PREDICATE, true},
    // DELETE_COOKIE_SINGLE
    {CookieStore::ChangeCause::EXPLICIT_DELETE_SINGLE, true},
    // DELETE_COOKIE_CANONICAL
    {CookieStore::ChangeCause::EXPLICIT_DELETE_CANONICAL, true},
    // DELETE_COOKIE_LAST_ENTRY
    {CookieStore::ChangeCause::EXPLICIT, false}};

void RunAsync(scoped_refptr<base::TaskRunner> proxy,
              const CookieStore::CookieChangedCallback& callback,
              const CanonicalCookie& cookie,
              CookieStore::ChangeCause cause) {
  proxy->PostTask(FROM_HERE, base::Bind(callback, cookie, cause));
}

bool IsCookieEligibleForEviction(CookiePriority current_priority_level,
                                 bool protect_secure_cookies,
                                 const CanonicalCookie* cookie) {
  if (cookie->Priority() == current_priority_level && protect_secure_cookies)
    return !cookie->IsSecure();

  return cookie->Priority() == current_priority_level;
}

size_t CountCookiesForPossibleDeletion(
    CookiePriority priority,
    const CookieMonster::CookieItVector* cookies,
    bool protect_secure_cookies) {
  size_t cookies_count = 0U;
  for (const auto& cookie : *cookies) {
    if (cookie->second->Priority() == priority) {
      if (!protect_secure_cookies || cookie->second->IsSecure())
        cookies_count++;
    }
  }
  return cookies_count;
}

}  // namespace

CookieMonster::CookieMonster(PersistentCookieStore* store,
                             CookieMonsterDelegate* delegate)
    : CookieMonster(
          store,
          delegate,
          base::TimeDelta::FromSeconds(kDefaultAccessUpdateThresholdSeconds)) {}

CookieMonster::CookieMonster(PersistentCookieStore* store,
                             CookieMonsterDelegate* delegate,
                             base::TimeDelta last_access_threshold)
    : initialized_(false),
      started_fetching_all_cookies_(false),
      finished_fetching_all_cookies_(false),
      fetch_strategy_(kUnknownFetch),
      seen_global_task_(false),
      store_(store),
      last_access_threshold_(last_access_threshold),
      delegate_(delegate),
      last_statistic_record_time_(base::Time::Now()),
      persist_session_cookies_(false),
      weak_ptr_factory_(this) {
  InitializeHistograms();
  cookieable_schemes_.insert(
      cookieable_schemes_.begin(), kDefaultCookieableSchemes,
      kDefaultCookieableSchemes + kDefaultCookieableSchemesCount);
}

// Task classes for queueing the coming request.

class CookieMonster::CookieMonsterTask
    : public base::RefCountedThreadSafe<CookieMonsterTask> {
 public:
  // Runs the task and invokes the client callback on the thread that
  // originally constructed the task.
  virtual void Run() = 0;

 protected:
  explicit CookieMonsterTask(CookieMonster* cookie_monster);
  virtual ~CookieMonsterTask();

  CookieMonster* cookie_monster() { return cookie_monster_; }

 private:
  friend class base::RefCountedThreadSafe<CookieMonsterTask>;

  CookieMonster* cookie_monster_;

  DISALLOW_COPY_AND_ASSIGN(CookieMonsterTask);
};

CookieMonster::CookieMonsterTask::CookieMonsterTask(
    CookieMonster* cookie_monster)
    : cookie_monster_(cookie_monster) {}

CookieMonster::CookieMonsterTask::~CookieMonsterTask() {
}

// Task class for SetCookieWithDetails call.
class CookieMonster::SetCookieWithDetailsTask : public CookieMonsterTask {
 public:
  SetCookieWithDetailsTask(CookieMonster* cookie_monster,
                           const GURL& url,
                           const std::string& name,
                           const std::string& value,
                           const std::string& domain,
                           const std::string& path,
                           base::Time creation_time,
                           base::Time expiration_time,
                           base::Time last_access_time,
                           bool secure,
                           bool http_only,
                           CookieSameSite same_site,
                           CookiePriority priority,
                           const SetCookiesCallback& callback)
      : CookieMonsterTask(cookie_monster),
        url_(url),
        name_(name),
        value_(value),
        domain_(domain),
        path_(path),
        creation_time_(creation_time),
        expiration_time_(expiration_time),
        last_access_time_(last_access_time),
        secure_(secure),
        http_only_(http_only),
        same_site_(same_site),
        priority_(priority),
        callback_(callback) {}

  // CookieMonsterTask:
  void Run() override;

 protected:
  ~SetCookieWithDetailsTask() override {}

 private:
  GURL url_;
  std::string name_;
  std::string value_;
  std::string domain_;
  std::string path_;
  base::Time creation_time_;
  base::Time expiration_time_;
  base::Time last_access_time_;
  bool secure_;
  bool http_only_;
  CookieSameSite same_site_;
  CookiePriority priority_;
  SetCookiesCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(SetCookieWithDetailsTask);
};

void CookieMonster::SetCookieWithDetailsTask::Run() {
  bool success = this->cookie_monster()->SetCookieWithDetails(
      url_, name_, value_, domain_, path_, creation_time_, expiration_time_,
      last_access_time_, secure_, http_only_, same_site_, priority_);
  if (!callback_.is_null())
    callback_.Run(success);
}

// Task class for GetAllCookies call.
class CookieMonster::GetAllCookiesTask : public CookieMonsterTask {
 public:
  GetAllCookiesTask(CookieMonster* cookie_monster,
                    const GetCookieListCallback& callback)
      : CookieMonsterTask(cookie_monster), callback_(callback) {}

  // CookieMonsterTask
  void Run() override;

 protected:
  ~GetAllCookiesTask() override {}

 private:
  GetCookieListCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(GetAllCookiesTask);
};

void CookieMonster::GetAllCookiesTask::Run() {
  if (!callback_.is_null()) {
    CookieList cookies = this->cookie_monster()->GetAllCookies();
    callback_.Run(cookies);
  }
}

// Task class for GetCookieListWithOptionsAsync call.
class CookieMonster::GetCookieListWithOptionsTask : public CookieMonsterTask {
 public:
  GetCookieListWithOptionsTask(CookieMonster* cookie_monster,
                               const GURL& url,
                               const CookieOptions& options,
                               const GetCookieListCallback& callback)
      : CookieMonsterTask(cookie_monster),
        url_(url),
        options_(options),
        callback_(callback) {}

  // CookieMonsterTask:
  void Run() override;

 protected:
  ~GetCookieListWithOptionsTask() override {}

 private:
  GURL url_;
  CookieOptions options_;
  GetCookieListCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(GetCookieListWithOptionsTask);
};

void CookieMonster::GetCookieListWithOptionsTask::Run() {
  if (!callback_.is_null()) {
    CookieList cookies =
        this->cookie_monster()->GetCookieListWithOptions(url_, options_);
    callback_.Run(cookies);
  }
}

template <typename Result>
struct CallbackType {
  typedef base::Callback<void(Result)> Type;
};

template <>
struct CallbackType<void> {
  typedef base::Closure Type;
};

// Base task class for Delete*Task.
template <typename Result>
class CookieMonster::DeleteTask : public CookieMonsterTask {
 public:
  DeleteTask(CookieMonster* cookie_monster,
             const typename CallbackType<Result>::Type& callback)
      : CookieMonsterTask(cookie_monster), callback_(callback) {}

  // CookieMonsterTask:
  void Run() override;

 protected:
  ~DeleteTask() override;

 private:
  // Runs the delete task and returns a result.
  virtual Result RunDeleteTask() = 0;
  // Runs the delete task and then returns a callback to be called after
  // flushing the persistent store.
  // TODO(mmenke): This seems like a pretty ugly and needlessly confusing API.
  // Simplify it?
  base::Closure RunDeleteTaskAndBindCallback();

  typename CallbackType<Result>::Type callback_;

  DISALLOW_COPY_AND_ASSIGN(DeleteTask);
};

template <typename Result>
CookieMonster::DeleteTask<Result>::~DeleteTask() {
}

template <typename Result>
base::Closure
CookieMonster::DeleteTask<Result>::RunDeleteTaskAndBindCallback() {
  Result result = RunDeleteTask();
  if (callback_.is_null())
    return base::Closure();
  return base::Bind(callback_, result);
}

template <>
base::Closure CookieMonster::DeleteTask<void>::RunDeleteTaskAndBindCallback() {
  RunDeleteTask();
  return callback_;
}

template <typename Result>
void CookieMonster::DeleteTask<Result>::Run() {
  base::Closure callback = RunDeleteTaskAndBindCallback();
  if (!callback.is_null()) {
    callback = base::Bind(
        &CookieMonster::RunCallback,
        this->cookie_monster()->weak_ptr_factory_.GetWeakPtr(), callback);
  }
  this->cookie_monster()->FlushStore(callback);
}

// Task class for DeleteAllCreatedBetween call.
class CookieMonster::DeleteAllCreatedBetweenTask : public DeleteTask<int> {
 public:
  DeleteAllCreatedBetweenTask(CookieMonster* cookie_monster,
                              const Time& delete_begin,
                              const Time& delete_end,
                              const DeleteCallback& callback)
      : DeleteTask<int>(cookie_monster, callback),
        delete_begin_(delete_begin),
        delete_end_(delete_end) {}

  // DeleteTask:
  int RunDeleteTask() override;

 protected:
  ~DeleteAllCreatedBetweenTask() override {}

 private:
  Time delete_begin_;
  Time delete_end_;

  DISALLOW_COPY_AND_ASSIGN(DeleteAllCreatedBetweenTask);
};

int CookieMonster::DeleteAllCreatedBetweenTask::RunDeleteTask() {
  return this->cookie_monster()->DeleteAllCreatedBetween(delete_begin_,
                                                         delete_end_);
}

// Task class for DeleteAllCreatedBetweenWithPredicate call.
class CookieMonster::DeleteAllCreatedBetweenWithPredicateTask
    : public DeleteTask<int> {
 public:
  DeleteAllCreatedBetweenWithPredicateTask(
      CookieMonster* cookie_monster,
      Time delete_begin,
      Time delete_end,
      base::Callback<bool(const CanonicalCookie&)> predicate,
      const DeleteCallback& callback)
      : DeleteTask<int>(cookie_monster, callback),
        delete_begin_(delete_begin),
        delete_end_(delete_end),
        predicate_(predicate) {}

  // DeleteTask:
  int RunDeleteTask() override;

 protected:
  ~DeleteAllCreatedBetweenWithPredicateTask() override {}

 private:
  Time delete_begin_;
  Time delete_end_;
  base::Callback<bool(const CanonicalCookie&)> predicate_;

  DISALLOW_COPY_AND_ASSIGN(DeleteAllCreatedBetweenWithPredicateTask);
};

int CookieMonster::DeleteAllCreatedBetweenWithPredicateTask::RunDeleteTask() {
  return this->cookie_monster()->DeleteAllCreatedBetweenWithPredicate(
      delete_begin_, delete_end_, predicate_);
}

// Task class for DeleteCanonicalCookie call.
class CookieMonster::DeleteCanonicalCookieTask : public DeleteTask<int> {
 public:
  DeleteCanonicalCookieTask(CookieMonster* cookie_monster,
                            const CanonicalCookie& cookie,
                            const DeleteCallback& callback)
      : DeleteTask<int>(cookie_monster, callback), cookie_(cookie) {}

  // DeleteTask:
  int RunDeleteTask() override;

 protected:
  ~DeleteCanonicalCookieTask() override {}

 private:
  CanonicalCookie cookie_;

  DISALLOW_COPY_AND_ASSIGN(DeleteCanonicalCookieTask);
};

int CookieMonster::DeleteCanonicalCookieTask::RunDeleteTask() {
  return this->cookie_monster()->DeleteCanonicalCookie(cookie_);
}

// Task class for SetCookieWithOptions call.
class CookieMonster::SetCookieWithOptionsTask : public CookieMonsterTask {
 public:
  SetCookieWithOptionsTask(CookieMonster* cookie_monster,
                           const GURL& url,
                           const std::string& cookie_line,
                           const CookieOptions& options,
                           const SetCookiesCallback& callback)
      : CookieMonsterTask(cookie_monster),
        url_(url),
        cookie_line_(cookie_line),
        options_(options),
        callback_(callback) {}

  // CookieMonsterTask:
  void Run() override;

 protected:
  ~SetCookieWithOptionsTask() override {}

 private:
  GURL url_;
  std::string cookie_line_;
  CookieOptions options_;
  SetCookiesCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(SetCookieWithOptionsTask);
};

void CookieMonster::SetCookieWithOptionsTask::Run() {
  bool result = this->cookie_monster()->SetCookieWithOptions(url_, cookie_line_,
                                                             options_);
  if (!callback_.is_null())
    callback_.Run(result);
}

// Task class for SetAllCookies call.
class CookieMonster::SetAllCookiesTask : public CookieMonsterTask {
 public:
  SetAllCookiesTask(CookieMonster* cookie_monster,
                    const CookieList& list,
                    const SetCookiesCallback& callback)
      : CookieMonsterTask(cookie_monster), list_(list), callback_(callback) {}

  // CookieMonsterTask:
  void Run() override;

 protected:
  ~SetAllCookiesTask() override {}

 private:
  CookieList list_;
  SetCookiesCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(SetAllCookiesTask);
};

void CookieMonster::SetAllCookiesTask::Run() {
  CookieList positive_diff;
  CookieList negative_diff;
  CookieList old_cookies = this->cookie_monster()->GetAllCookies();
  this->cookie_monster()->ComputeCookieDiff(&old_cookies, &list_,
                                            &positive_diff, &negative_diff);

  for (CookieList::const_iterator it = negative_diff.begin();
       it != negative_diff.end(); ++it) {
    this->cookie_monster()->DeleteCanonicalCookie(*it);
  }

  bool result = true;
  if (positive_diff.size() > 0)
    result = this->cookie_monster()->SetCanonicalCookies(list_);

  if (!callback_.is_null())
    callback_.Run(result);
}

// Task class for GetCookiesWithOptions call.
class CookieMonster::GetCookiesWithOptionsTask : public CookieMonsterTask {
 public:
  GetCookiesWithOptionsTask(CookieMonster* cookie_monster,
                            const GURL& url,
                            const CookieOptions& options,
                            const GetCookiesCallback& callback)
      : CookieMonsterTask(cookie_monster),
        url_(url),
        options_(options),
        callback_(callback) {}

  // CookieMonsterTask:
  void Run() override;

 protected:
  ~GetCookiesWithOptionsTask() override {}

 private:
  GURL url_;
  CookieOptions options_;
  GetCookiesCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(GetCookiesWithOptionsTask);
};

void CookieMonster::GetCookiesWithOptionsTask::Run() {
  std::string cookie =
      this->cookie_monster()->GetCookiesWithOptions(url_, options_);
  if (!callback_.is_null())
    callback_.Run(cookie);
}

// Task class for DeleteCookie call.
class CookieMonster::DeleteCookieTask : public DeleteTask<void> {
 public:
  DeleteCookieTask(CookieMonster* cookie_monster,
                   const GURL& url,
                   const std::string& cookie_name,
                   const base::Closure& callback)
      : DeleteTask<void>(cookie_monster, callback),
        url_(url),
        cookie_name_(cookie_name) {}

  // DeleteTask:
  void RunDeleteTask() override;

 protected:
  ~DeleteCookieTask() override {}

 private:
  GURL url_;
  std::string cookie_name_;

  DISALLOW_COPY_AND_ASSIGN(DeleteCookieTask);
};

void CookieMonster::DeleteCookieTask::RunDeleteTask() {
  this->cookie_monster()->DeleteCookie(url_, cookie_name_);
}

// Task class for DeleteSessionCookies call.
class CookieMonster::DeleteSessionCookiesTask : public DeleteTask<int> {
 public:
  DeleteSessionCookiesTask(CookieMonster* cookie_monster,
                           const DeleteCallback& callback)
      : DeleteTask<int>(cookie_monster, callback) {}

  // DeleteTask:
  int RunDeleteTask() override;

 protected:
  ~DeleteSessionCookiesTask() override {}

 private:
  DISALLOW_COPY_AND_ASSIGN(DeleteSessionCookiesTask);
};

int CookieMonster::DeleteSessionCookiesTask::RunDeleteTask() {
  return this->cookie_monster()->DeleteSessionCookies();
}

// Asynchronous CookieMonster API

void CookieMonster::SetCookieWithDetailsAsync(
    const GURL& url,
    const std::string& name,
    const std::string& value,
    const std::string& domain,
    const std::string& path,
    Time creation_time,
    Time expiration_time,
    Time last_access_time,
    bool secure,
    bool http_only,
    CookieSameSite same_site,
    CookiePriority priority,
    const SetCookiesCallback& callback) {
  scoped_refptr<SetCookieWithDetailsTask> task = new SetCookieWithDetailsTask(
      this, url, name, value, domain, path, creation_time, expiration_time,
      last_access_time, secure, http_only, same_site, priority, callback);
  DoCookieTaskForURL(task, url);
}

void CookieMonster::FlushStore(const base::Closure& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (initialized_ && store_.get())
    store_->Flush(callback);
  else if (!callback.is_null())
    base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, callback);
}

void CookieMonster::SetForceKeepSessionState() {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (store_)
    store_->SetForceKeepSessionState();
}

void CookieMonster::SetAllCookiesAsync(const CookieList& list,
                                       const SetCookiesCallback& callback) {
  scoped_refptr<SetAllCookiesTask> task =
      new SetAllCookiesTask(this, list, callback);
  DoCookieTask(task);
}

void CookieMonster::SetCookieWithOptionsAsync(
    const GURL& url,
    const std::string& cookie_line,
    const CookieOptions& options,
    const SetCookiesCallback& callback) {
  scoped_refptr<SetCookieWithOptionsTask> task =
      new SetCookieWithOptionsTask(this, url, cookie_line, options, callback);

  DoCookieTaskForURL(task, url);
}

void CookieMonster::GetCookiesWithOptionsAsync(
    const GURL& url,
    const CookieOptions& options,
    const GetCookiesCallback& callback) {
  scoped_refptr<GetCookiesWithOptionsTask> task =
      new GetCookiesWithOptionsTask(this, url, options, callback);

  DoCookieTaskForURL(task, url);
}

void CookieMonster::GetCookieListWithOptionsAsync(
    const GURL& url,
    const CookieOptions& options,
    const GetCookieListCallback& callback) {
  scoped_refptr<GetCookieListWithOptionsTask> task =
      new GetCookieListWithOptionsTask(this, url, options, callback);

  DoCookieTaskForURL(task, url);
}

void CookieMonster::GetAllCookiesAsync(const GetCookieListCallback& callback) {
  scoped_refptr<GetAllCookiesTask> task = new GetAllCookiesTask(this, callback);

  DoCookieTask(task);
}

void CookieMonster::DeleteCookieAsync(const GURL& url,
                                      const std::string& cookie_name,
                                      const base::Closure& callback) {
  scoped_refptr<DeleteCookieTask> task =
      new DeleteCookieTask(this, url, cookie_name, callback);

  DoCookieTaskForURL(task, url);
}

void CookieMonster::DeleteCanonicalCookieAsync(const CanonicalCookie& cookie,
                                               const DeleteCallback& callback) {
  scoped_refptr<DeleteCanonicalCookieTask> task =
      new DeleteCanonicalCookieTask(this, cookie, callback);

  DoCookieTask(task);
}

void CookieMonster::DeleteAllCreatedBetweenAsync(
    const Time& delete_begin,
    const Time& delete_end,
    const DeleteCallback& callback) {
  scoped_refptr<DeleteAllCreatedBetweenTask> task =
      new DeleteAllCreatedBetweenTask(this, delete_begin, delete_end, callback);

  DoCookieTask(task);
}

void CookieMonster::DeleteAllCreatedBetweenWithPredicateAsync(
    const Time& delete_begin,
    const Time& delete_end,
    const base::Callback<bool(const CanonicalCookie&)>& predicate,
    const DeleteCallback& callback) {
  if (predicate.is_null()) {
    callback.Run(0);
    return;
  }
  scoped_refptr<DeleteAllCreatedBetweenWithPredicateTask> task =
      new DeleteAllCreatedBetweenWithPredicateTask(
          this, delete_begin, delete_end, predicate, callback);
  DoCookieTask(task);
}

void CookieMonster::DeleteSessionCookiesAsync(
    const CookieStore::DeleteCallback& callback) {
  scoped_refptr<DeleteSessionCookiesTask> task =
      new DeleteSessionCookiesTask(this, callback);

  DoCookieTask(task);
}

void CookieMonster::SetCookieableSchemes(
    const std::vector<std::string>& schemes) {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Calls to this method will have no effect if made after a WebView or
  // CookieManager instance has been created.
  if (initialized_)
    return;

  cookieable_schemes_ = schemes;
}

// This function must be called before the CookieMonster is used.
void CookieMonster::SetPersistSessionCookies(bool persist_session_cookies) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!initialized_);
  persist_session_cookies_ = persist_session_cookies;
}

bool CookieMonster::IsCookieableScheme(const std::string& scheme) {
  DCHECK(thread_checker_.CalledOnValidThread());

  return std::find(cookieable_schemes_.begin(), cookieable_schemes_.end(),
                   scheme) != cookieable_schemes_.end();
}

const char* const CookieMonster::kDefaultCookieableSchemes[] = {"http", "https",
                                                                "ws", "wss"};
const int CookieMonster::kDefaultCookieableSchemesCount =
    arraysize(kDefaultCookieableSchemes);

std::unique_ptr<CookieStore::CookieChangedSubscription>
CookieMonster::AddCallbackForCookie(const GURL& gurl,
                                    const std::string& name,
                                    const CookieChangedCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());

  std::pair<GURL, std::string> key(gurl, name);
  if (hook_map_.count(key) == 0)
    hook_map_[key] = base::MakeUnique<CookieChangedCallbackList>();
  return hook_map_[key]->Add(
      base::Bind(&RunAsync, base::ThreadTaskRunnerHandle::Get(), callback));
}

bool CookieMonster::IsEphemeral() {
  return store_.get() == nullptr;
}

CookieMonster::~CookieMonster() {
  DCHECK(thread_checker_.CalledOnValidThread());

  // TODO(mmenke): Does it really make sense to run |delegate_| and
  // CookieChanged callbacks when the CookieStore is destroyed?
  for (CookieMap::iterator cookie_it = cookies_.begin();
       cookie_it != cookies_.end();) {
    CookieMap::iterator current_cookie_it = cookie_it;
    ++cookie_it;
    InternalDeleteCookie(current_cookie_it, false /* sync_to_store */,
                         DELETE_COOKIE_DONT_RECORD);
  }
}

bool CookieMonster::SetCookieWithDetails(const GURL& url,
                                         const std::string& name,
                                         const std::string& value,
                                         const std::string& domain,
                                         const std::string& path,
                                         base::Time creation_time,
                                         base::Time expiration_time,
                                         base::Time last_access_time,
                                         bool secure,
                                         bool http_only,
                                         CookieSameSite same_site,
                                         CookiePriority priority) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!HasCookieableScheme(url))
    return false;

  // TODO(mmenke): This class assumes each cookie to have a unique creation
  // time. Allowing the caller to set the creation time violates that
  // assumption. Worth fixing? Worth noting that time changes between browser
  // restarts can cause the same issue.
  base::Time actual_creation_time = creation_time;
  if (creation_time.is_null()) {
    actual_creation_time = CurrentTime();
    last_time_seen_ = actual_creation_time;
  }

  std::unique_ptr<CanonicalCookie> cc(CanonicalCookie::Create(
      url, name, value, domain, path, actual_creation_time, expiration_time,
      secure, http_only, same_site, priority));

  if (!cc.get())
    return false;

  if (!last_access_time.is_null())
    cc->SetLastAccessDate(last_access_time);

  CookieOptions options;
  options.set_include_httponly();
  options.set_same_site_cookie_mode(
      CookieOptions::SameSiteCookieMode::INCLUDE_STRICT_AND_LAX);
  return SetCanonicalCookie(std::move(cc), url, options);
}

CookieList CookieMonster::GetAllCookies() {
  DCHECK(thread_checker_.CalledOnValidThread());

  // This function is being called to scrape the cookie list for management UI
  // or similar.  We shouldn't show expired cookies in this list since it will
  // just be confusing to users, and this function is called rarely enough (and
  // is already slow enough) that it's OK to take the time to garbage collect
  // the expired cookies now.
  //
  // Note that this does not prune cookies to be below our limits (if we've
  // exceeded them) the way that calling GarbageCollect() would.
  GarbageCollectExpired(
      Time::Now(), CookieMapItPair(cookies_.begin(), cookies_.end()), NULL);

  // Copy the CanonicalCookie pointers from the map so that we can use the same
  // sorter as elsewhere, then copy the result out.
  std::vector<CanonicalCookie*> cookie_ptrs;
  cookie_ptrs.reserve(cookies_.size());
  for (const auto& cookie : cookies_)
    cookie_ptrs.push_back(cookie.second.get());
  std::sort(cookie_ptrs.begin(), cookie_ptrs.end(), CookieSorter);

  CookieList cookie_list;
  cookie_list.reserve(cookie_ptrs.size());
  for (auto* cookie_ptr : cookie_ptrs)
    cookie_list.push_back(*cookie_ptr);

  return cookie_list;
}

CookieList CookieMonster::GetCookieListWithOptions(
    const GURL& url,
    const CookieOptions& options) {
  DCHECK(thread_checker_.CalledOnValidThread());

  CookieList cookies;
  if (!HasCookieableScheme(url))
    return cookies;

  std::vector<CanonicalCookie*> cookie_ptrs;
  FindCookiesForHostAndDomain(url, options, &cookie_ptrs);
  std::sort(cookie_ptrs.begin(), cookie_ptrs.end(), CookieSorter);

  cookies.reserve(cookie_ptrs.size());
  for (std::vector<CanonicalCookie*>::const_iterator it = cookie_ptrs.begin();
       it != cookie_ptrs.end(); it++)
    cookies.push_back(**it);

  return cookies;
}

int CookieMonster::DeleteAllCreatedBetween(const Time& delete_begin,
                                           const Time& delete_end) {
  DCHECK(thread_checker_.CalledOnValidThread());

  int num_deleted = 0;
  for (CookieMap::iterator it = cookies_.begin(); it != cookies_.end();) {
    CookieMap::iterator curit = it;
    CanonicalCookie* cc = curit->second.get();
    ++it;

    if (cc->CreationDate() >= delete_begin &&
        (delete_end.is_null() || cc->CreationDate() < delete_end)) {
      InternalDeleteCookie(curit, true, /*sync_to_store*/
                           DELETE_COOKIE_CREATED_BETWEEN);
      ++num_deleted;
    }
  }

  return num_deleted;
}

int CookieMonster::DeleteAllCreatedBetweenWithPredicate(
    const base::Time& delete_begin,
    const base::Time& delete_end,
    const base::Callback<bool(const CanonicalCookie&)>& predicate) {
  int num_deleted = 0;
  for (CookieMap::iterator it = cookies_.begin(); it != cookies_.end();) {
    CookieMap::iterator curit = it;
    CanonicalCookie* cc = curit->second.get();
    ++it;

    if (cc->CreationDate() >= delete_begin &&
        // The assumption that null |delete_end| is equivalent to
        // Time::Max() is confusing.
        (delete_end.is_null() || cc->CreationDate() < delete_end) &&
        predicate.Run(*cc)) {
      InternalDeleteCookie(curit, true, /*sync_to_store*/
                           DELETE_COOKIE_CREATED_BETWEEN_WITH_PREDICATE);
      ++num_deleted;
    }
  }

  return num_deleted;
}

bool CookieMonster::SetCookieWithOptions(const GURL& url,
                                         const std::string& cookie_line,
                                         const CookieOptions& options) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!HasCookieableScheme(url)) {
    return false;
  }

  return SetCookieWithCreationTimeAndOptions(url, cookie_line, Time(), options);
}

std::string CookieMonster::GetCookiesWithOptions(const GURL& url,
                                                 const CookieOptions& options) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!HasCookieableScheme(url))
    return std::string();

  std::vector<CanonicalCookie*> cookies;
  FindCookiesForHostAndDomain(url, options, &cookies);
  std::sort(cookies.begin(), cookies.end(), CookieSorter);

  std::string cookie_line = BuildCookieLine(cookies);

  VLOG(kVlogGetCookies) << "GetCookies() result: " << cookie_line;

  return cookie_line;
}

void CookieMonster::DeleteCookie(const GURL& url,
                                 const std::string& cookie_name) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!HasCookieableScheme(url))
    return;

  CookieOptions options;
  options.set_include_httponly();
  options.set_same_site_cookie_mode(
      CookieOptions::SameSiteCookieMode::INCLUDE_STRICT_AND_LAX);
  // Get the cookies for this host and its domain(s).
  std::vector<CanonicalCookie*> cookies;
  FindCookiesForHostAndDomain(url, options, &cookies);
  std::set<CanonicalCookie*> matching_cookies;

  for (auto* cookie : cookies) {
    if (cookie->Name() != cookie_name)
      continue;
    if (!cookie->IsOnPath(url.path()))
      continue;
    matching_cookies.insert(cookie);
  }

  for (CookieMap::iterator it = cookies_.begin(); it != cookies_.end();) {
    CookieMap::iterator curit = it;
    ++it;
    if (matching_cookies.find(curit->second.get()) != matching_cookies.end()) {
      InternalDeleteCookie(curit, true, DELETE_COOKIE_SINGLE);
    }
  }
}

int CookieMonster::DeleteCanonicalCookie(const CanonicalCookie& cookie) {
  DCHECK(thread_checker_.CalledOnValidThread());

  for (CookieMapItPair its = cookies_.equal_range(GetKey(cookie.Domain()));
       its.first != its.second; ++its.first) {
    // The creation date acts as the unique index...
    if (its.first->second->CreationDate() == cookie.CreationDate()) {
      InternalDeleteCookie(its.first, true, DELETE_COOKIE_CANONICAL);
      return 1;
    }
  }
  return 0;
}

bool CookieMonster::SetCookieWithCreationTime(const GURL& url,
                                              const std::string& cookie_line,
                                              const base::Time& creation_time) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!store_.get()) << "This method is only to be used by unit-tests.";

  if (!HasCookieableScheme(url)) {
    return false;
  }

  MarkCookieStoreAsInitialized();
  if (ShouldFetchAllCookiesWhenFetchingAnyCookie())
    FetchAllCookiesIfNecessary();

  return SetCookieWithCreationTimeAndOptions(url, cookie_line, creation_time,
                                             CookieOptions());
}

int CookieMonster::DeleteSessionCookies() {
  DCHECK(thread_checker_.CalledOnValidThread());

  int num_deleted = 0;
  for (CookieMap::iterator it = cookies_.begin(); it != cookies_.end();) {
    CookieMap::iterator curit = it;
    CanonicalCookie* cc = curit->second.get();
    ++it;

    if (!cc->IsPersistent()) {
      InternalDeleteCookie(curit, true, /*sync_to_store*/
                           DELETE_COOKIE_EXPIRED);
      ++num_deleted;
    }
  }

  return num_deleted;
}

void CookieMonster::MarkCookieStoreAsInitialized() {
  DCHECK(thread_checker_.CalledOnValidThread());
  initialized_ = true;
}

void CookieMonster::FetchAllCookiesIfNecessary() {
  DCHECK(thread_checker_.CalledOnValidThread());
  if (store_.get() && !started_fetching_all_cookies_) {
    started_fetching_all_cookies_ = true;
    FetchAllCookies();
  }
}

void CookieMonster::FetchAllCookies() {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(store_.get()) << "Store must exist to initialize";
  DCHECK(!finished_fetching_all_cookies_)
      << "All cookies have already been fetched.";

  // We bind in the current time so that we can report the wall-clock time for
  // loading cookies.
  store_->Load(base::Bind(&CookieMonster::OnLoaded,
                          weak_ptr_factory_.GetWeakPtr(), TimeTicks::Now()));
}

bool CookieMonster::ShouldFetchAllCookiesWhenFetchingAnyCookie() {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (fetch_strategy_ == kUnknownFetch) {
    const std::string group_name =
        base::FieldTrialList::FindFullName(kCookieMonsterFetchStrategyName);
    if (group_name == kFetchWhenNecessaryName) {
      fetch_strategy_ = kFetchWhenNecessary;
    } else if (group_name == kAlwaysFetchName) {
      fetch_strategy_ = kAlwaysFetch;
    } else {
      // The logic in the conditional is redundant, but it makes trials of
      // the Finch experiment more explicit.
      fetch_strategy_ = kAlwaysFetch;
    }
  }

  return fetch_strategy_ == kAlwaysFetch;
}

void CookieMonster::OnLoaded(
    TimeTicks beginning_time,
    std::vector<std::unique_ptr<CanonicalCookie>> cookies) {
  DCHECK(thread_checker_.CalledOnValidThread());
  StoreLoadedCookies(std::move(cookies));
  histogram_time_blocked_on_load_->AddTime(TimeTicks::Now() - beginning_time);

  // Invoke the task queue of cookie request.
  InvokeQueue();
}

void CookieMonster::OnKeyLoaded(
    const std::string& key,
    std::vector<std::unique_ptr<CanonicalCookie>> cookies) {
  DCHECK(thread_checker_.CalledOnValidThread());

  StoreLoadedCookies(std::move(cookies));

  auto tasks_pending_for_key = tasks_pending_for_key_.find(key);

  // TODO(mmenke): Can this be turned into a DCHECK?
  if (tasks_pending_for_key == tasks_pending_for_key_.end())
    return;

  // Run all tasks for the key. Note that running a task can result in multiple
  // tasks being added to the back of the deque.
  while (!tasks_pending_for_key->second.empty()) {
    scoped_refptr<CookieMonsterTask> task =
        tasks_pending_for_key->second.front();
    tasks_pending_for_key->second.pop_front();

    task->Run();
  }

  tasks_pending_for_key_.erase(tasks_pending_for_key);

  // This has to be done last, in case running a task queues a new task for the
  // key, to ensure tasks are run in the correct order.
  keys_loaded_.insert(key);
}

void CookieMonster::StoreLoadedCookies(
    std::vector<std::unique_ptr<CanonicalCookie>> cookies) {
  DCHECK(thread_checker_.CalledOnValidThread());

  // TODO(erikwright): Remove ScopedTracker below once crbug.com/457528 is
  // fixed.
  tracked_objects::ScopedTracker tracking_profile(
      FROM_HERE_WITH_EXPLICIT_FUNCTION(
          "457528 CookieMonster::StoreLoadedCookies"));

  // Even if a key is expired, insert it so it can be garbage collected,
  // removed, and sync'd.
  CookieItVector cookies_with_control_chars;

  for (auto& cookie : cookies) {
    int64_t cookie_creation_time = cookie->CreationDate().ToInternalValue();

    if (creation_times_.insert(cookie_creation_time).second) {
      CanonicalCookie* cookie_ptr = cookie.get();
      CookieMap::iterator inserted = InternalInsertCookie(
          GetKey(cookie_ptr->Domain()), std::move(cookie), GURL(), false);
      const Time cookie_access_time(cookie_ptr->LastAccessDate());
      if (earliest_access_time_.is_null() ||
          cookie_access_time < earliest_access_time_)
        earliest_access_time_ = cookie_access_time;

      if (ContainsControlCharacter(cookie_ptr->Name()) ||
          ContainsControlCharacter(cookie_ptr->Value())) {
        cookies_with_control_chars.push_back(inserted);
      }
    } else {
      LOG(ERROR) << base::StringPrintf(
          "Found cookies with duplicate creation "
          "times in backing store: "
          "{name='%s', domain='%s', path='%s'}",
          cookie->Name().c_str(), cookie->Domain().c_str(),
          cookie->Path().c_str());
    }
  }

  // Any cookies that contain control characters that we have loaded from the
  // persistent store should be deleted. See http://crbug.com/238041.
  for (CookieItVector::iterator it = cookies_with_control_chars.begin();
       it != cookies_with_control_chars.end();) {
    CookieItVector::iterator curit = it;
    ++it;

    InternalDeleteCookie(*curit, true, DELETE_COOKIE_CONTROL_CHAR);
  }

  // After importing cookies from the PersistentCookieStore, verify that
  // none of our other constraints are violated.
  // In particular, the backing store might have given us duplicate cookies.

  // This method could be called multiple times due to priority loading, thus
  // cookies loaded in previous runs will be validated again, but this is OK
  // since they are expected to be much fewer than total DB.
  EnsureCookiesMapIsValid();
}

void CookieMonster::InvokeQueue() {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Move all per-key tasks into the global queue, if there are any.  This is
  // protection about a race where the store learns about all cookies loading
  // before it learned about the cookies for a key loading.

  // Needed to prevent any recursively queued tasks from going back into the
  // per-key queues.
  seen_global_task_ = true;
  for (const auto& tasks_for_key : tasks_pending_for_key_) {
    tasks_pending_.insert(tasks_pending_.begin(), tasks_for_key.second.begin(),
                          tasks_for_key.second.end());
  }
  tasks_pending_for_key_.clear();

  while (!tasks_pending_.empty()) {
    scoped_refptr<CookieMonsterTask> request_task = tasks_pending_.front();
    tasks_pending_.pop_front();
    request_task->Run();
  }

  DCHECK(tasks_pending_for_key_.empty());

  finished_fetching_all_cookies_ = true;
  creation_times_.clear();
  keys_loaded_.clear();
}

void CookieMonster::EnsureCookiesMapIsValid() {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Iterate through all the of the cookies, grouped by host.
  CookieMap::iterator prev_range_end = cookies_.begin();
  while (prev_range_end != cookies_.end()) {
    CookieMap::iterator cur_range_begin = prev_range_end;
    const std::string key = cur_range_begin->first;  // Keep a copy.
    CookieMap::iterator cur_range_end = cookies_.upper_bound(key);
    prev_range_end = cur_range_end;

    // Ensure no equivalent cookies for this host.
    TrimDuplicateCookiesForKey(key, cur_range_begin, cur_range_end);
  }
}

void CookieMonster::TrimDuplicateCookiesForKey(const std::string& key,
                                               CookieMap::iterator begin,
                                               CookieMap::iterator end) {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Set of cookies ordered by creation time.
  typedef std::set<CookieMap::iterator, OrderByCreationTimeDesc> CookieSet;

  // Helper map we populate to find the duplicates.
  typedef std::map<CookieSignature, CookieSet> EquivalenceMap;
  EquivalenceMap equivalent_cookies;

  // The number of duplicate cookies that have been found.
  int num_duplicates = 0;

  // Iterate through all of the cookies in our range, and insert them into
  // the equivalence map.
  for (CookieMap::iterator it = begin; it != end; ++it) {
    DCHECK_EQ(key, it->first);
    CanonicalCookie* cookie = it->second.get();

    CookieSignature signature(cookie->Name(), cookie->Domain(), cookie->Path());
    CookieSet& set = equivalent_cookies[signature];

    // We found a duplicate!
    if (!set.empty())
      num_duplicates++;

    // We save the iterator into |cookies_| rather than the actual cookie
    // pointer, since we may need to delete it later.
    bool insert_success = set.insert(it).second;
    DCHECK(insert_success)
        << "Duplicate creation times found in duplicate cookie name scan.";
  }

  // If there were no duplicates, we are done!
  if (num_duplicates == 0)
    return;

  // Make sure we find everything below that we did above.
  int num_duplicates_found = 0;

  // Otherwise, delete all the duplicate cookies, both from our in-memory store
  // and from the backing store.
  for (EquivalenceMap::iterator it = equivalent_cookies.begin();
       it != equivalent_cookies.end(); ++it) {
    const CookieSignature& signature = it->first;
    CookieSet& dupes = it->second;

    if (dupes.size() <= 1)
      continue;  // This cookiename/path has no duplicates.
    num_duplicates_found += dupes.size() - 1;

    // Since |dups| is sorted by creation time (descending), the first cookie
    // is the most recent one, so we will keep it. The rest are duplicates.
    dupes.erase(dupes.begin());

    LOG(ERROR) << base::StringPrintf(
        "Found %d duplicate cookies for host='%s', "
        "with {name='%s', domain='%s', path='%s'}",
        static_cast<int>(dupes.size()), key.c_str(), signature.name.c_str(),
        signature.domain.c_str(), signature.path.c_str());

    // Remove all the cookies identified by |dupes|. It is valid to delete our
    // list of iterators one at a time, since |cookies_| is a multimap (they
    // don't invalidate existing iterators following deletion).
    for (CookieSet::iterator dupes_it = dupes.begin(); dupes_it != dupes.end();
         ++dupes_it) {
      InternalDeleteCookie(*dupes_it, true,
                           DELETE_COOKIE_DUPLICATE_IN_BACKING_STORE);
    }
  }
  DCHECK_EQ(num_duplicates, num_duplicates_found);
}

void CookieMonster::FindCookiesForHostAndDomain(
    const GURL& url,
    const CookieOptions& options,
    std::vector<CanonicalCookie*>* cookies) {
  DCHECK(thread_checker_.CalledOnValidThread());

  const Time current_time(CurrentTime());

  // Probe to save statistics relatively frequently.  We do it here rather
  // than in the set path as many websites won't set cookies, and we
  // want to collect statistics whenever the browser's being used.
  RecordPeriodicStats(current_time);

  // Can just dispatch to FindCookiesForKey
  const std::string key(GetKey(url.host()));
  FindCookiesForKey(key, url, options, current_time, cookies);
}

void CookieMonster::FindCookiesForKey(const std::string& key,
                                      const GURL& url,
                                      const CookieOptions& options,
                                      const Time& current,
                                      std::vector<CanonicalCookie*>* cookies) {
  DCHECK(thread_checker_.CalledOnValidThread());

  for (CookieMapItPair its = cookies_.equal_range(key);
       its.first != its.second;) {
    CookieMap::iterator curit = its.first;
    CanonicalCookie* cc = curit->second.get();
    ++its.first;

    // If the cookie is expired, delete it.
    if (cc->IsExpired(current)) {
      InternalDeleteCookie(curit, true, DELETE_COOKIE_EXPIRED);
      continue;
    }

    // Filter out cookies that should not be included for a request to the
    // given |url|. HTTP only cookies are filtered depending on the passed
    // cookie |options|.
    if (!cc->IncludeForRequestURL(url, options))
      continue;

    // Add this cookie to the set of matching cookies. Update the access
    // time if we've been requested to do so.
    if (options.update_access_time()) {
      InternalUpdateCookieAccessTime(cc, current);
    }
    cookies->push_back(cc);
  }
}

bool CookieMonster::DeleteAnyEquivalentCookie(const std::string& key,
                                              const CanonicalCookie& ecc,
                                              const GURL& source_url,
                                              bool skip_httponly,
                                              bool already_expired) {
  DCHECK(thread_checker_.CalledOnValidThread());

  bool found_equivalent_cookie = false;
  bool skipped_httponly = false;
  bool skipped_secure_cookie = false;

  histogram_cookie_delete_equivalent_->Add(COOKIE_DELETE_EQUIVALENT_ATTEMPT);

  for (CookieMapItPair its = cookies_.equal_range(key);
       its.first != its.second;) {
    CookieMap::iterator curit = its.first;
    CanonicalCookie* cc = curit->second.get();
    ++its.first;

    // If the cookie is being set from an insecure scheme, then if a cookie
    // already exists with the same name and it is Secure, then the cookie
    // should *not* be updated if they domain-match and ignoring the path
    // attribute.
    //
    // See: https://tools.ietf.org/html/draft-ietf-httpbis-cookie-alone
    if (cc->IsSecure() && !source_url.SchemeIsCryptographic() &&
        ecc.IsEquivalentForSecureCookieMatching(*cc)) {
      skipped_secure_cookie = true;
      histogram_cookie_delete_equivalent_->Add(
          COOKIE_DELETE_EQUIVALENT_SKIPPING_SECURE);
      // If the cookie is equivalent to the new cookie and wouldn't have been
      // skipped for being HTTP-only, record that it is a skipped secure cookie
      // that would have been deleted otherwise.
      if (ecc.IsEquivalent(*cc)) {
        found_equivalent_cookie = true;

        if (!skip_httponly || !cc->IsHttpOnly()) {
          histogram_cookie_delete_equivalent_->Add(
              COOKIE_DELETE_EQUIVALENT_WOULD_HAVE_DELETED);
        }
      }
    } else if (ecc.IsEquivalent(*cc)) {
      // We should never have more than one equivalent cookie, since they should
      // overwrite each other, unless secure cookies require secure scheme is
      // being enforced. In that case, cookies with different paths might exist
      // and be considered equivalent.
      CHECK(!found_equivalent_cookie)
          << "Duplicate equivalent cookies found, cookie store is corrupted.";
      if (skip_httponly && cc->IsHttpOnly()) {
        skipped_httponly = true;
      } else {
        histogram_cookie_delete_equivalent_->Add(
            COOKIE_DELETE_EQUIVALENT_FOUND);
        InternalDeleteCookie(curit, true, already_expired
                                              ? DELETE_COOKIE_EXPIRED_OVERWRITE
                                              : DELETE_COOKIE_OVERWRITE);
      }
      found_equivalent_cookie = true;
    }
  }
  return skipped_httponly || skipped_secure_cookie;
}

CookieMonster::CookieMap::iterator CookieMonster::InternalInsertCookie(
    const std::string& key,
    std::unique_ptr<CanonicalCookie> cc,
    const GURL& source_url,
    bool sync_to_store) {
  DCHECK(thread_checker_.CalledOnValidThread());
  CanonicalCookie* cc_ptr = cc.get();

  if ((cc_ptr->IsPersistent() || persist_session_cookies_) && store_.get() &&
      sync_to_store)
    store_->AddCookie(*cc_ptr);
  CookieMap::iterator inserted =
      cookies_.insert(CookieMap::value_type(key, std::move(cc)));
  if (delegate_.get()) {
    delegate_->OnCookieChanged(*cc_ptr, false,
                               CookieStore::ChangeCause::INSERTED);
  }

  // See InitializeHistograms() for details.
  int32_t type_sample = cc_ptr->SameSite() != CookieSameSite::NO_RESTRICTION
                            ? 1 << COOKIE_TYPE_SAME_SITE
                            : 0;
  type_sample |= cc_ptr->IsHttpOnly() ? 1 << COOKIE_TYPE_HTTPONLY : 0;
  type_sample |= cc_ptr->IsSecure() ? 1 << COOKIE_TYPE_SECURE : 0;
  histogram_cookie_type_->Add(type_sample);

  // Histogram the type of scheme used on URLs that set cookies. This
  // intentionally includes cookies that are set or overwritten by
  // http:// URLs, but not cookies that are cleared by http:// URLs, to
  // understand if the former behavior can be deprecated for Secure
  // cookies.
  if (!source_url.is_empty()) {
    CookieSource cookie_source_sample;
    if (source_url.SchemeIsCryptographic()) {
      cookie_source_sample =
          cc_ptr->IsSecure()
              ? COOKIE_SOURCE_SECURE_COOKIE_CRYPTOGRAPHIC_SCHEME
              : COOKIE_SOURCE_NONSECURE_COOKIE_CRYPTOGRAPHIC_SCHEME;
    } else {
      cookie_source_sample =
          cc_ptr->IsSecure()
              ? COOKIE_SOURCE_SECURE_COOKIE_NONCRYPTOGRAPHIC_SCHEME
              : COOKIE_SOURCE_NONSECURE_COOKIE_NONCRYPTOGRAPHIC_SCHEME;
    }
    histogram_cookie_source_scheme_->Add(cookie_source_sample);
  }

  RunCookieChangedCallbacks(*cc_ptr, CookieStore::ChangeCause::INSERTED);

  return inserted;
}

bool CookieMonster::SetCookieWithCreationTimeAndOptions(
    const GURL& url,
    const std::string& cookie_line,
    const Time& creation_time_or_null,
    const CookieOptions& options) {
  DCHECK(thread_checker_.CalledOnValidThread());

  VLOG(kVlogSetCookies) << "SetCookie() line: " << cookie_line;

  Time creation_time = creation_time_or_null;
  if (creation_time.is_null()) {
    creation_time = CurrentTime();
    last_time_seen_ = creation_time;
  }

  std::unique_ptr<CanonicalCookie> cc(
      CanonicalCookie::Create(url, cookie_line, creation_time, options));

  if (!cc.get()) {
    VLOG(kVlogSetCookies) << "WARNING: Failed to allocate CanonicalCookie";
    return false;
  }
  return SetCanonicalCookie(std::move(cc), url, options);
}

bool CookieMonster::SetCanonicalCookie(std::unique_ptr<CanonicalCookie> cc,
                                       const GURL& source_url,
                                       const CookieOptions& options) {
  DCHECK(thread_checker_.CalledOnValidThread());

  Time creation_time = cc->CreationDate();
  const std::string key(GetKey(cc->Domain()));
  bool already_expired = cc->IsExpired(creation_time);

  if (DeleteAnyEquivalentCookie(key, *cc, source_url,
                                options.exclude_httponly(), already_expired)) {
    std::string error;
    error =
        "SetCookie() not clobbering httponly cookie or secure cookie for "
        "insecure scheme";

    VLOG(kVlogSetCookies) << error;
    return false;
  }

  VLOG(kVlogSetCookies) << "SetCookie() key: " << key
                        << " cc: " << cc->DebugString();

  // Realize that we might be setting an expired cookie, and the only point
  // was to delete the cookie which we've already done.
  if (!already_expired) {
    // See InitializeHistograms() for details.
    if (cc->IsPersistent()) {
      histogram_expiration_duration_minutes_->Add(
          (cc->ExpiryDate() - creation_time).InMinutes());
    }

    InternalInsertCookie(key, std::move(cc), source_url, true);
  } else {
    VLOG(kVlogSetCookies) << "SetCookie() not storing already expired cookie.";
  }

  // We assume that hopefully setting a cookie will be less common than
  // querying a cookie.  Since setting a cookie can put us over our limits,
  // make sure that we garbage collect...  We can also make the assumption that
  // if a cookie was set, in the common case it will be used soon after,
  // and we will purge the expired cookies in GetCookies().
  GarbageCollect(creation_time, key);

  return true;
}

bool CookieMonster::SetCanonicalCookies(const CookieList& list) {
  DCHECK(thread_checker_.CalledOnValidThread());

  CookieOptions options;
  options.set_include_httponly();

  for (const auto& cookie : list) {
    // Use an empty GURL.  This method does not support setting secure cookies.
    if (!SetCanonicalCookie(base::MakeUnique<CanonicalCookie>(cookie), GURL(),
                            options)) {
      return false;
    }
  }

  return true;
}

void CookieMonster::InternalUpdateCookieAccessTime(CanonicalCookie* cc,
                                                   const Time& current) {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Based off the Mozilla code.  When a cookie has been accessed recently,
  // don't bother updating its access time again.  This reduces the number of
  // updates we do during pageload, which in turn reduces the chance our storage
  // backend will hit its batch thresholds and be forced to update.
  if ((current - cc->LastAccessDate()) < last_access_threshold_)
    return;

  cc->SetLastAccessDate(current);
  if ((cc->IsPersistent() || persist_session_cookies_) && store_.get())
    store_->UpdateCookieAccessTime(*cc);
}

// InternalDeleteCookies must not invalidate iterators other than the one being
// deleted.
void CookieMonster::InternalDeleteCookie(CookieMap::iterator it,
                                         bool sync_to_store,
                                         DeletionCause deletion_cause) {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Ideally, this would be asserted up where we define kChangeCauseMapping,
  // but DeletionCause's visibility (or lack thereof) forces us to make
  // this check here.
  static_assert(arraysize(kChangeCauseMapping) == DELETE_COOKIE_LAST_ENTRY + 1,
                "kChangeCauseMapping size should match DeletionCause size");

  // See InitializeHistograms() for details.
  DeletionCause deletion_cause_to_record = deletion_cause;
  if (deletion_cause >= DELETE_COOKIE_CREATED_BETWEEN &&
      deletion_cause <= DELETE_COOKIE_CANONICAL) {
    deletion_cause_to_record = DELETE_COOKIE_EXPLICIT;
  }
  if (deletion_cause != DELETE_COOKIE_DONT_RECORD)
    histogram_cookie_deletion_cause_->Add(deletion_cause_to_record);

  CanonicalCookie* cc = it->second.get();
  VLOG(kVlogSetCookies) << "InternalDeleteCookie()"
                        << ", cause:" << deletion_cause
                        << ", cc: " << cc->DebugString();

  if ((cc->IsPersistent() || persist_session_cookies_) && store_.get() &&
      sync_to_store)
    store_->DeleteCookie(*cc);
  ChangeCausePair mapping = kChangeCauseMapping[deletion_cause];
  if (delegate_.get() && mapping.notify)
    delegate_->OnCookieChanged(*cc, true, mapping.cause);
  RunCookieChangedCallbacks(*cc, mapping.cause);
  cookies_.erase(it);
}

// Domain expiry behavior is unchanged by key/expiry scheme (the
// meaning of the key is different, but that's not visible to this routine).
size_t CookieMonster::GarbageCollect(const Time& current,
                                     const std::string& key) {
  DCHECK(thread_checker_.CalledOnValidThread());

  size_t num_deleted = 0;
  Time safe_date(Time::Now() - TimeDelta::FromDays(kSafeFromGlobalPurgeDays));

  // Collect garbage for this key, minding cookie priorities.
  if (cookies_.count(key) > kDomainMaxCookies) {
    VLOG(kVlogGarbageCollection) << "GarbageCollect() key: " << key;

    CookieItVector* cookie_its;

    CookieItVector non_expired_cookie_its;
    cookie_its = &non_expired_cookie_its;
    num_deleted +=
        GarbageCollectExpired(current, cookies_.equal_range(key), cookie_its);

    if (cookie_its->size() > kDomainMaxCookies) {
      VLOG(kVlogGarbageCollection) << "Deep Garbage Collect domain.";
      size_t purge_goal =
          cookie_its->size() - (kDomainMaxCookies - kDomainPurgeCookies);
      DCHECK(purge_goal > kDomainPurgeCookies);

      // Sort the cookies by access date, from least-recent to most-recent.
      std::sort(cookie_its->begin(), cookie_its->end(), LRACookieSorter);

      // Remove all but the kDomainCookiesQuotaLow most-recently accessed
      // cookies with low-priority. Then, if cookies still need to be removed,
      // bump the quota and remove low- and medium-priority. Then, if cookies
      // _still_ need to be removed, bump the quota and remove cookies with
      // any priority.
      //
      // 1.  Low-priority non-secure cookies.
      // 2.  Low-priority secure cookies.
      // 3.  Medium-priority non-secure cookies.
      // 4.  High-priority non-secure cookies.
      // 5.  Medium-priority secure cookies.
      // 6.  High-priority secure cookies.
      const static struct {
        CookiePriority priority;
        bool protect_secure_cookies;
      } purge_rounds[] = {
          // 1.  Low-priority non-secure cookies.
          {COOKIE_PRIORITY_LOW, true},
          // 2.  Low-priority secure cookies.
          {COOKIE_PRIORITY_LOW, false},
          // 3.  Medium-priority non-secure cookies.
          {COOKIE_PRIORITY_MEDIUM, true},
          // 4.  High-priority non-secure cookies.
          {COOKIE_PRIORITY_HIGH, true},
          // 5.  Medium-priority secure cookies.
          {COOKIE_PRIORITY_MEDIUM, false},
          // 6.  High-priority secure cookies.
          {COOKIE_PRIORITY_HIGH, false},
      };

      size_t quota = 0;
      for (const auto& purge_round : purge_rounds) {
        // Adjust quota according to the priority of cookies. Each round should
        // protect certain number of cookies in order to avoid starvation.
        // For example, when each round starts to remove cookies, the number of
        // cookies of that priority are counted and a decision whether they
        // should be deleted or not is made. If yes, some number of cookies of
        // that priority are deleted considering the quota.
        switch (purge_round.priority) {
          case COOKIE_PRIORITY_LOW:
            quota = kDomainCookiesQuotaLow;
            break;
          case COOKIE_PRIORITY_MEDIUM:
            quota = kDomainCookiesQuotaMedium;
            break;
          case COOKIE_PRIORITY_HIGH:
            quota = kDomainCookiesQuotaHigh;
            break;
        }
        size_t just_deleted = 0u;
        // Purge up to |purge_goal| for all cookies at the given priority.  This
        // path will be taken only if the initial non-secure purge did not evict
        // enough cookies.
        if (purge_goal > 0) {
          just_deleted = PurgeLeastRecentMatches(
              cookie_its, purge_round.priority, quota, purge_goal,
              purge_round.protect_secure_cookies);
          DCHECK_LE(just_deleted, purge_goal);
          purge_goal -= just_deleted;
          num_deleted += just_deleted;
        }
      }

      DCHECK_EQ(0u, purge_goal);
    }
  }

  // Collect garbage for everything. With firefox style we want to preserve
  // cookies accessed in kSafeFromGlobalPurgeDays, otherwise evict.
  if (cookies_.size() > kMaxCookies && earliest_access_time_ < safe_date) {
    VLOG(kVlogGarbageCollection) << "GarbageCollect() everything";
    CookieItVector cookie_its;

    num_deleted += GarbageCollectExpired(
        current, CookieMapItPair(cookies_.begin(), cookies_.end()),
        &cookie_its);

    if (cookie_its.size() > kMaxCookies) {
      VLOG(kVlogGarbageCollection) << "Deep Garbage Collect everything.";
      size_t purge_goal = cookie_its.size() - (kMaxCookies - kPurgeCookies);
      DCHECK(purge_goal > kPurgeCookies);

      CookieItVector secure_cookie_its;
      CookieItVector non_secure_cookie_its;
      SplitCookieVectorIntoSecureAndNonSecure(cookie_its, &secure_cookie_its,
                                              &non_secure_cookie_its);
      size_t non_secure_purge_goal =
          std::min<size_t>(purge_goal, non_secure_cookie_its.size() - 1);

      size_t just_deleted = GarbageCollectLeastRecentlyAccessed(
          current, safe_date, non_secure_purge_goal, non_secure_cookie_its);
      num_deleted += just_deleted;

      if (just_deleted < purge_goal && secure_cookie_its.size() > 0) {
        size_t secure_purge_goal = std::min<size_t>(
            purge_goal - just_deleted, secure_cookie_its.size() - 1);
        num_deleted += GarbageCollectLeastRecentlyAccessed(
            current, safe_date, secure_purge_goal, secure_cookie_its);
      }
    }
  }

  return num_deleted;
}

size_t CookieMonster::PurgeLeastRecentMatches(CookieItVector* cookies,
                                              CookiePriority priority,
                                              size_t to_protect,
                                              size_t purge_goal,
                                              bool protect_secure_cookies) {
  DCHECK(thread_checker_.CalledOnValidThread());

  // 1. Count number of the cookies at |priority|
  size_t cookies_count_possibly_to_be_deleted = CountCookiesForPossibleDeletion(
      priority, cookies, false /* count all cookies */);

  // 2. If |cookies_count_possibly_to_be_deleted| at |priority| is less than or
  // equal |to_protect|, skip round in order to preserve the quota. This
  // involves secure and non-secure cookies at |priority|.
  if (cookies_count_possibly_to_be_deleted <= to_protect)
    return 0u;

  // 3. Calculate number of secure cookies at |priority|
  // and number of cookies at |priority| that can possibly be deleted.
  // It is guaranteed we do not delete more than |purge_goal| even if
  // |cookies_count_possibly_to_be_deleted| is higher.
  size_t secure_cookies = 0u;
  if (protect_secure_cookies) {
    secure_cookies = CountCookiesForPossibleDeletion(
        priority, cookies, protect_secure_cookies /* count secure cookies */);
    cookies_count_possibly_to_be_deleted -=
        std::max(secure_cookies, to_protect - secure_cookies);
  } else {
    cookies_count_possibly_to_be_deleted -= to_protect;
  }

  size_t removed = 0u;
  size_t current = 0u;
  while ((removed < purge_goal && current < cookies->size()) &&
         cookies_count_possibly_to_be_deleted > 0) {
    const CanonicalCookie* current_cookie = cookies->at(current)->second.get();
    // Only delete the current cookie if the priority is equal to
    // the current level.
    if (IsCookieEligibleForEviction(priority, protect_secure_cookies,
                                    current_cookie)) {
      InternalDeleteCookie(cookies->at(current), true,
                           DELETE_COOKIE_EVICTED_DOMAIN);
      cookies->erase(cookies->begin() + current);
      removed++;
      cookies_count_possibly_to_be_deleted--;
    } else {
      current++;
    }
  }
  return removed;
}

size_t CookieMonster::GarbageCollectExpired(const Time& current,
                                            const CookieMapItPair& itpair,
                                            CookieItVector* cookie_its) {
  DCHECK(thread_checker_.CalledOnValidThread());

  int num_deleted = 0;
  for (CookieMap::iterator it = itpair.first, end = itpair.second; it != end;) {
    CookieMap::iterator curit = it;
    ++it;

    if (curit->second->IsExpired(current)) {
      InternalDeleteCookie(curit, true, DELETE_COOKIE_EXPIRED);
      ++num_deleted;
    } else if (cookie_its) {
      cookie_its->push_back(curit);
    }
  }

  return num_deleted;
}

size_t CookieMonster::GarbageCollectDeleteRange(
    const Time& current,
    DeletionCause cause,
    CookieItVector::iterator it_begin,
    CookieItVector::iterator it_end) {
  DCHECK(thread_checker_.CalledOnValidThread());

  for (CookieItVector::iterator it = it_begin; it != it_end; it++) {
    histogram_evicted_last_access_minutes_->Add(
        (current - (*it)->second->LastAccessDate()).InMinutes());
    InternalDeleteCookie((*it), true, cause);
  }
  return it_end - it_begin;
}

size_t CookieMonster::GarbageCollectLeastRecentlyAccessed(
    const base::Time& current,
    const base::Time& safe_date,
    size_t purge_goal,
    CookieItVector cookie_its) {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Sorts up to *and including* |cookie_its[purge_goal]|, so
  // |earliest_access_time| will be properly assigned even if
  // |global_purge_it| == |cookie_its.begin() + purge_goal|.
  SortLeastRecentlyAccessed(cookie_its.begin(), cookie_its.end(), purge_goal);
  // Find boundary to cookies older than safe_date.
  CookieItVector::iterator global_purge_it = LowerBoundAccessDate(
      cookie_its.begin(), cookie_its.begin() + purge_goal, safe_date);
  // Only delete the old cookies and delete non-secure ones first.
  size_t num_deleted =
      GarbageCollectDeleteRange(current, DELETE_COOKIE_EVICTED_GLOBAL,
                                cookie_its.begin(), global_purge_it);
  // Set access day to the oldest cookie that wasn't deleted.
  earliest_access_time_ = (*global_purge_it)->second->LastAccessDate();
  return num_deleted;
}

// A wrapper around registry_controlled_domains::GetDomainAndRegistry
// to make clear we're creating a key for our local map.  Here and
// in FindCookiesForHostAndDomain() are the only two places where
// we need to conditionalize based on key type.
//
// Note that this key algorithm explicitly ignores the scheme.  This is
// because when we're entering cookies into the map from the backing store,
// we in general won't have the scheme at that point.
// In practical terms, this means that file cookies will be stored
// in the map either by an empty string or by UNC name (and will be
// limited by kMaxCookiesPerHost), and extension cookies will be stored
// based on the single extension id, as the extension id won't have the
// form of a DNS host and hence GetKey() will return it unchanged.
//
// Arguably the right thing to do here is to make the key
// algorithm dependent on the scheme, and make sure that the scheme is
// available everywhere the key must be obtained (specfically at backing
// store load time).  This would require either changing the backing store
// database schema to include the scheme (far more trouble than it's worth), or
// separating out file cookies into their own CookieMonster instance and
// thus restricting each scheme to a single cookie monster (which might
// be worth it, but is still too much trouble to solve what is currently a
// non-problem).
std::string CookieMonster::GetKey(const std::string& domain) const {
  DCHECK(thread_checker_.CalledOnValidThread());

  std::string effective_domain(
      registry_controlled_domains::GetDomainAndRegistry(
          domain, registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES));
  if (effective_domain.empty())
    effective_domain = domain;

  if (!effective_domain.empty() && effective_domain[0] == '.')
    return effective_domain.substr(1);
  return effective_domain;
}

bool CookieMonster::HasCookieableScheme(const GURL& url) {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Make sure the request is on a cookie-able url scheme.
  for (size_t i = 0; i < cookieable_schemes_.size(); ++i) {
    // We matched a scheme.
    if (url.SchemeIs(cookieable_schemes_[i].c_str())) {
      // We've matched a supported scheme.
      return true;
    }
  }

  // The scheme didn't match any in our whitelist.
  VLOG(kVlogPerCookieMonster)
      << "WARNING: Unsupported cookie scheme: " << url.scheme();
  return false;
}

// Test to see if stats should be recorded, and record them if so.
// The goal here is to get sampling for the average browser-hour of
// activity.  We won't take samples when the web isn't being surfed,
// and when the web is being surfed, we'll take samples about every
// kRecordStatisticsIntervalSeconds.
// last_statistic_record_time_ is initialized to Now() rather than null
// in the constructor so that we won't take statistics right after
// startup, to avoid bias from browsers that are started but not used.
void CookieMonster::RecordPeriodicStats(const base::Time& current_time) {
  DCHECK(thread_checker_.CalledOnValidThread());

  const base::TimeDelta kRecordStatisticsIntervalTime(
      base::TimeDelta::FromSeconds(kRecordStatisticsIntervalSeconds));

  // If we've taken statistics recently, return.
  if (current_time - last_statistic_record_time_ <=
      kRecordStatisticsIntervalTime) {
    return;
  }

  // See InitializeHistograms() for details.
  histogram_count_->Add(cookies_.size());

  // More detailed statistics on cookie counts at different granularities.
  last_statistic_record_time_ = current_time;
}

// Initialize all histogram counter variables used in this class.
//
// Normal histogram usage involves using the macros defined in
// histogram.h, which automatically takes care of declaring these
// variables (as statics), initializing them, and accumulating into
// them, all from a single entry point.  Unfortunately, that solution
// doesn't work for the CookieMonster, as it's vulnerable to races between
// separate threads executing the same functions and hence initializing the
// same static variables.  There isn't a race danger in the histogram
// accumulation calls; they are written to be resilient to simultaneous
// calls from multiple threads.
//
// The solution taken here is to have per-CookieMonster instance
// variables that are constructed during CookieMonster construction.
// Note that these variables refer to the same underlying histogram,
// so we still race (but safely) with other CookieMonster instances
// for accumulation.
//
// To do this we've expanded out the individual histogram macros calls,
// with declarations of the variables in the class decl, initialization here
// (done from the class constructor) and direct calls to the accumulation
// methods where needed.  The specific histogram macro calls on which the
// initialization is based are included in comments below.
void CookieMonster::InitializeHistograms() {
  DCHECK(thread_checker_.CalledOnValidThread());

  // From UMA_HISTOGRAM_CUSTOM_COUNTS
  histogram_expiration_duration_minutes_ = base::Histogram::FactoryGet(
      "Cookie.ExpirationDurationMinutes", 1, kMinutesInTenYears, 50,
      base::Histogram::kUmaTargetedHistogramFlag);
  histogram_evicted_last_access_minutes_ = base::Histogram::FactoryGet(
      "Cookie.EvictedLastAccessMinutes", 1, kMinutesInTenYears, 50,
      base::Histogram::kUmaTargetedHistogramFlag);
  histogram_count_ = base::Histogram::FactoryGet(
      "Cookie.Count", 1, 4000, 50, base::Histogram::kUmaTargetedHistogramFlag);

  // From UMA_HISTOGRAM_ENUMERATION
  histogram_cookie_deletion_cause_ = base::LinearHistogram::FactoryGet(
      "Cookie.DeletionCause", 1, DELETE_COOKIE_LAST_ENTRY - 1,
      DELETE_COOKIE_LAST_ENTRY, base::Histogram::kUmaTargetedHistogramFlag);
  histogram_cookie_type_ = base::LinearHistogram::FactoryGet(
      "Cookie.Type", 1, (1 << COOKIE_TYPE_LAST_ENTRY) - 1,
      1 << COOKIE_TYPE_LAST_ENTRY, base::Histogram::kUmaTargetedHistogramFlag);
  histogram_cookie_source_scheme_ = base::LinearHistogram::FactoryGet(
      "Cookie.CookieSourceScheme", 1, COOKIE_SOURCE_LAST_ENTRY - 1,
      COOKIE_SOURCE_LAST_ENTRY, base::Histogram::kUmaTargetedHistogramFlag);
  histogram_cookie_delete_equivalent_ = base::LinearHistogram::FactoryGet(
      "Cookie.CookieDeleteEquivalent", 1,
      COOKIE_DELETE_EQUIVALENT_LAST_ENTRY - 1,
      COOKIE_DELETE_EQUIVALENT_LAST_ENTRY,
      base::Histogram::kUmaTargetedHistogramFlag);

  // From UMA_HISTOGRAM_{CUSTOM_,}TIMES
  histogram_time_blocked_on_load_ = base::Histogram::FactoryTimeGet(
      "Cookie.TimeBlockedOnLoad", base::TimeDelta::FromMilliseconds(1),
      base::TimeDelta::FromMinutes(1), 50,
      base::Histogram::kUmaTargetedHistogramFlag);
}

// The system resolution is not high enough, so we can have multiple
// set cookies that result in the same system time.  When this happens, we
// increment by one Time unit.  Let's hope computers don't get too fast.
Time CookieMonster::CurrentTime() {
  return std::max(Time::Now(), Time::FromInternalValue(
                                   last_time_seen_.ToInternalValue() + 1));
}

void CookieMonster::DoCookieTask(
    const scoped_refptr<CookieMonsterTask>& task_item) {
  DCHECK(thread_checker_.CalledOnValidThread());

  MarkCookieStoreAsInitialized();
  FetchAllCookiesIfNecessary();
  seen_global_task_ = true;

  if (!finished_fetching_all_cookies_ && store_.get()) {
    tasks_pending_.push_back(task_item);
    return;
  }

  task_item->Run();
}

void CookieMonster::DoCookieTaskForURL(
    const scoped_refptr<CookieMonsterTask>& task_item,
    const GURL& url) {
  MarkCookieStoreAsInitialized();
  if (ShouldFetchAllCookiesWhenFetchingAnyCookie())
    FetchAllCookiesIfNecessary();

  // If cookies for the requested domain key (eTLD+1) have been loaded from DB
  // then run the task, otherwise load from DB.
  if (!finished_fetching_all_cookies_ && store_.get()) {
    // If a global task has been previously seen, queue the task as a global
    // task. Note that the CookieMonster may be in the middle of executing
    // the global queue, |tasks_pending_| may be empty, which is why another
    // bool is needed.
    if (seen_global_task_) {
      tasks_pending_.push_back(task_item);
      return;
    }

    // Checks if the domain key has been loaded.
    std::string key(cookie_util::GetEffectiveDomain(url.scheme(), url.host()));
    if (keys_loaded_.find(key) == keys_loaded_.end()) {
      std::map<std::string,
               std::deque<scoped_refptr<CookieMonsterTask>>>::iterator it =
          tasks_pending_for_key_.find(key);
      if (it == tasks_pending_for_key_.end()) {
        store_->LoadCookiesForKey(
            key, base::Bind(&CookieMonster::OnKeyLoaded,
                            weak_ptr_factory_.GetWeakPtr(), key));
        it = tasks_pending_for_key_
                 .insert(std::make_pair(
                     key, std::deque<scoped_refptr<CookieMonsterTask>>()))
                 .first;
      }
      it->second.push_back(task_item);
      return;
    }
  }

  task_item->Run();
}

void CookieMonster::ComputeCookieDiff(CookieList* old_cookies,
                                      CookieList* new_cookies,
                                      CookieList* cookies_to_add,
                                      CookieList* cookies_to_delete) {
  DCHECK(thread_checker_.CalledOnValidThread());

  DCHECK(old_cookies);
  DCHECK(new_cookies);
  DCHECK(cookies_to_add);
  DCHECK(cookies_to_delete);
  DCHECK(cookies_to_add->empty());
  DCHECK(cookies_to_delete->empty());

  // Sort both lists.
  // A set ordered by FullDiffCookieSorter is also ordered by
  // PartialDiffCookieSorter.
  std::sort(old_cookies->begin(), old_cookies->end(), FullDiffCookieSorter);
  std::sort(new_cookies->begin(), new_cookies->end(), FullDiffCookieSorter);

  // Select any old cookie for deletion if no new cookie has the same name,
  // domain, and path.
  std::set_difference(
      old_cookies->begin(), old_cookies->end(), new_cookies->begin(),
      new_cookies->end(),
      std::inserter(*cookies_to_delete, cookies_to_delete->begin()),
      PartialDiffCookieSorter);

  // Select any new cookie for addition (or update) if no old cookie is exactly
  // equivalent.
  std::set_difference(new_cookies->begin(), new_cookies->end(),
                      old_cookies->begin(), old_cookies->end(),
                      std::inserter(*cookies_to_add, cookies_to_add->begin()),
                      FullDiffCookieSorter);
}

void CookieMonster::RunCallback(const base::Closure& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  callback.Run();
}

void CookieMonster::RunCookieChangedCallbacks(const CanonicalCookie& cookie,
                                              ChangeCause cause) {
  DCHECK(thread_checker_.CalledOnValidThread());

  CookieOptions opts;
  opts.set_include_httponly();
  opts.set_same_site_cookie_mode(
      CookieOptions::SameSiteCookieMode::INCLUDE_STRICT_AND_LAX);
  // Note that the callbacks in hook_map_ are wrapped with RunAsync(), so they
  // are guaranteed to not take long - they just post a RunAsync task back to
  // the appropriate thread's message loop and return.
  // TODO(mmenke): Consider running these synchronously?
  for (CookieChangedHookMap::iterator it = hook_map_.begin();
       it != hook_map_.end(); ++it) {
    std::pair<GURL, std::string> key = it->first;
    if (cookie.IncludeForRequestURL(key.first, opts) &&
        cookie.Name() == key.second) {
      it->second->Notify(cookie, cause);
    }
  }
}

}  // namespace net
