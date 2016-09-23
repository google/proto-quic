// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cookies/cookie_store_test_helpers.h"

#include "base/bind.h"
#include "base/location.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"

using net::registry_controlled_domains::GetDomainAndRegistry;
using net::registry_controlled_domains::GetRegistryLength;
using net::registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES;
using net::registry_controlled_domains::INCLUDE_UNKNOWN_REGISTRIES;

namespace {

std::string GetRegistry(const GURL& url) {
  size_t registry_length = GetRegistryLength(url, INCLUDE_UNKNOWN_REGISTRIES,
                                             INCLUDE_PRIVATE_REGISTRIES);
  if (registry_length == 0)
    return std::string();
  return std::string(url.host(), url.host().length() - registry_length,
                     registry_length);
}

}  // namespace

namespace net {

const int kDelayedTime = 0;

DelayedCookieMonster::DelayedCookieMonster()
    : cookie_monster_(new CookieMonster(nullptr, nullptr)),
      did_run_(false),
      result_(false) {}

DelayedCookieMonster::~DelayedCookieMonster() {
}

void DelayedCookieMonster::SetCookiesInternalCallback(bool result) {
  result_ = result;
  did_run_ = true;
}

void DelayedCookieMonster::GetCookiesWithOptionsInternalCallback(
    const std::string& cookie) {
  cookie_ = cookie;
  did_run_ = true;
}

void DelayedCookieMonster::GetCookieListWithOptionsInternalCallback(
    const CookieList& cookie_list) {
  cookie_list_ = cookie_list;
  did_run_ = true;
}

void DelayedCookieMonster::SetCookieWithOptionsAsync(
    const GURL& url,
    const std::string& cookie_line,
    const CookieOptions& options,
    const CookieMonster::SetCookiesCallback& callback) {
  did_run_ = false;
  cookie_monster_->SetCookieWithOptionsAsync(
      url, cookie_line, options,
      base::Bind(&DelayedCookieMonster::SetCookiesInternalCallback,
                 base::Unretained(this)));
  DCHECK_EQ(did_run_, true);
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, base::Bind(&DelayedCookieMonster::InvokeSetCookiesCallback,
                            base::Unretained(this), callback),
      base::TimeDelta::FromMilliseconds(kDelayedTime));
}

void DelayedCookieMonster::SetCookieWithDetailsAsync(
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
    bool enforce_strict_secure,
    CookiePriority priority,
    const SetCookiesCallback& callback) {
  NOTREACHED();
}

void DelayedCookieMonster::GetCookiesWithOptionsAsync(
    const GURL& url,
    const CookieOptions& options,
    const CookieMonster::GetCookiesCallback& callback) {
  did_run_ = false;
  cookie_monster_->GetCookiesWithOptionsAsync(
      url, options,
      base::Bind(&DelayedCookieMonster::GetCookiesWithOptionsInternalCallback,
                 base::Unretained(this)));
  DCHECK_EQ(did_run_, true);
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE,
      base::Bind(&DelayedCookieMonster::InvokeGetCookieStringCallback,
                 base::Unretained(this), callback),
      base::TimeDelta::FromMilliseconds(kDelayedTime));
}

void DelayedCookieMonster::GetCookieListWithOptionsAsync(
    const GURL& url,
    const CookieOptions& options,
    const CookieMonster::GetCookieListCallback& callback) {
  did_run_ = false;
  cookie_monster_->GetCookieListWithOptionsAsync(
      url, options,
      base::Bind(
          &DelayedCookieMonster::GetCookieListWithOptionsInternalCallback,
          base::Unretained(this)));
  DCHECK_EQ(did_run_, true);
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, base::Bind(&DelayedCookieMonster::InvokeGetCookieListCallback,
                            base::Unretained(this), callback),
      base::TimeDelta::FromMilliseconds(kDelayedTime));
}

void DelayedCookieMonster::GetAllCookiesAsync(
    const GetCookieListCallback& callback) {
  cookie_monster_->GetAllCookiesAsync(callback);
}

void DelayedCookieMonster::InvokeSetCookiesCallback(
    const CookieMonster::SetCookiesCallback& callback) {
  if (!callback.is_null())
    callback.Run(result_);
}

void DelayedCookieMonster::InvokeGetCookieStringCallback(
    const CookieMonster::GetCookiesCallback& callback) {
  if (!callback.is_null())
    callback.Run(cookie_);
}

void DelayedCookieMonster::InvokeGetCookieListCallback(
    const CookieMonster::GetCookieListCallback& callback) {
  if (!callback.is_null())
    callback.Run(cookie_list_);
}

bool DelayedCookieMonster::SetCookieWithOptions(
    const GURL& url,
    const std::string& cookie_line,
    const CookieOptions& options) {
  ADD_FAILURE();
  return false;
}

std::string DelayedCookieMonster::GetCookiesWithOptions(
    const GURL& url,
    const CookieOptions& options) {
  ADD_FAILURE();
  return std::string();
}

void DelayedCookieMonster::DeleteCookie(const GURL& url,
                                        const std::string& cookie_name) {
  ADD_FAILURE();
}

void DelayedCookieMonster::DeleteCookieAsync(const GURL& url,
                                             const std::string& cookie_name,
                                             const base::Closure& callback) {
  ADD_FAILURE();
}

void DelayedCookieMonster::DeleteCanonicalCookieAsync(
    const CanonicalCookie& cookie,
    const DeleteCallback& callback) {
  ADD_FAILURE();
}

void DelayedCookieMonster::DeleteAllCreatedBetweenAsync(
    const base::Time& delete_begin,
    const base::Time& delete_end,
    const DeleteCallback& callback) {
  ADD_FAILURE();
}

void DelayedCookieMonster::DeleteAllCreatedBetweenWithPredicateAsync(
    const base::Time& delete_begin,
    const base::Time& delete_end,
    const base::Callback<bool(const CanonicalCookie&)>& predicate,
    const DeleteCallback& callback) {
  ADD_FAILURE();
}

void DelayedCookieMonster::DeleteSessionCookiesAsync(const DeleteCallback&) {
  ADD_FAILURE();
}

void DelayedCookieMonster::FlushStore(const base::Closure& callback) {
  ADD_FAILURE();
}

std::unique_ptr<CookieStore::CookieChangedSubscription>
DelayedCookieMonster::AddCallbackForCookie(
    const GURL& url,
    const std::string& name,
    const CookieChangedCallback& callback) {
  ADD_FAILURE();
  return std::unique_ptr<CookieStore::CookieChangedSubscription>();
}

bool DelayedCookieMonster::IsEphemeral() {
  return true;
}

//
// CookieURLHelper
//
CookieURLHelper::CookieURLHelper(const std::string& url_string)
    : url_(url_string),
      registry_(GetRegistry(url_)),
      domain_and_registry_(
          GetDomainAndRegistry(url_, INCLUDE_PRIVATE_REGISTRIES)) {}

const GURL CookieURLHelper::AppendPath(const std::string& path) const {
  return GURL(url_.spec() + path);
}

std::string CookieURLHelper::Format(const std::string& format_string) const {
  std::string new_string = format_string;
  base::ReplaceSubstringsAfterOffset(&new_string, 0, "%D",
                                     domain_and_registry_);
  base::ReplaceSubstringsAfterOffset(&new_string, 0, "%R", registry_);
  return new_string;
}

}  // namespace net
