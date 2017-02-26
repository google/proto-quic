// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/caching_cert_verifier.h"

#include "base/time/time.h"
#include "net/base/net_errors.h"

namespace net {

namespace {

// The maximum number of cache entries to use for the ExpiringCache.
const unsigned kMaxCacheEntries = 256;

// The number of seconds to cache entries.
const unsigned kTTLSecs = 1800;  // 30 minutes.

}  // namespace

CachingCertVerifier::CachingCertVerifier(std::unique_ptr<CertVerifier> verifier)
    : verifier_(std::move(verifier)),
      cache_(kMaxCacheEntries),
      requests_(0u),
      cache_hits_(0u) {
  CertDatabase::GetInstance()->AddObserver(this);
}

CachingCertVerifier::~CachingCertVerifier() {
  CertDatabase::GetInstance()->RemoveObserver(this);
}

int CachingCertVerifier::Verify(const CertVerifier::RequestParams& params,
                                CRLSet* crl_set,
                                CertVerifyResult* verify_result,
                                const CompletionCallback& callback,
                                std::unique_ptr<Request>* out_req,
                                const NetLogWithSource& net_log) {
  out_req->reset();

  requests_++;

  const CertVerificationCache::value_type* cached_entry =
      cache_.Get(params, CacheValidityPeriod(base::Time::Now()));
  if (cached_entry) {
    ++cache_hits_;
    *verify_result = cached_entry->result;
    return cached_entry->error;
  }

  base::Time start_time = base::Time::Now();
  CompletionCallback caching_callback = base::Bind(
      &CachingCertVerifier::OnRequestFinished, base::Unretained(this), params,
      start_time, callback, verify_result);
  int result = verifier_->Verify(params, crl_set, verify_result,
                                 caching_callback, out_req, net_log);
  if (result != ERR_IO_PENDING) {
    // Synchronous completion; add directly to cache.
    AddResultToCache(params, start_time, *verify_result, result);
  }

  return result;
}

bool CachingCertVerifier::SupportsOCSPStapling() {
  return verifier_->SupportsOCSPStapling();
}

bool CachingCertVerifier::AddEntry(const RequestParams& params,
                                   int error,
                                   const CertVerifyResult& verify_result,
                                   base::Time verification_time) {
  // If the cache is full, don't bother.
  if (cache_.size() == cache_.max_entries())
    return false;

  // If there is an existing entry, don't bother updating it.
  const CertVerificationCache::value_type* entry =
      cache_.Get(params, CacheValidityPeriod(base::Time::Now()));
  if (entry)
    return false;

  // Otherwise, go and add it.
  AddResultToCache(params, verification_time, verify_result, error);
  return true;
}

CachingCertVerifier::CachedResult::CachedResult() : error(ERR_FAILED) {}

CachingCertVerifier::CachedResult::~CachedResult() {}

CachingCertVerifier::CacheValidityPeriod::CacheValidityPeriod(base::Time now)
    : verification_time(now), expiration_time(now) {}

CachingCertVerifier::CacheValidityPeriod::CacheValidityPeriod(
    base::Time now,
    base::Time expiration)
    : verification_time(now), expiration_time(expiration) {}

bool CachingCertVerifier::CacheExpirationFunctor::operator()(
    const CacheValidityPeriod& now,
    const CacheValidityPeriod& expiration) const {
  // Ensure this functor is being used for expiration only, and not strict
  // weak ordering/sorting. |now| should only ever contain a single
  // base::Time.
  // Note: DCHECK_EQ is not used due to operator<< overloading requirements.
  DCHECK(now.verification_time == now.expiration_time);

  // |now| contains only a single time (verification_time), while |expiration|
  // contains the validity range - both when the certificate was verified and
  // when the verification result should expire.
  //
  // If the user receives a "not yet valid" message, and adjusts their clock
  // foward to the correct time, this will (typically) cause
  // now.verification_time to advance past expiration.expiration_time, thus
  // treating the cached result as an expired entry and re-verifying.
  // If the user receives a "expired" message, and adjusts their clock
  // backwards to the correct time, this will cause now.verification_time to
  // be less than expiration_verification_time, thus treating the cached
  // result as an expired entry and re-verifying.
  // If the user receives either of those messages, and does not adjust their
  // clock, then the result will be (typically) be cached until the expiration
  // TTL.
  //
  // This algorithm is only problematic if the user consistently keeps
  // adjusting their clock backwards in increments smaller than the expiration
  // TTL, in which case, cached elements continue to be added. However,
  // because the cache has a fixed upper bound, if no entries are expired, a
  // 'random' entry will be, thus keeping the memory constraints bounded over
  // time.
  return now.verification_time >= expiration.verification_time &&
         now.verification_time < expiration.expiration_time;
};

void CachingCertVerifier::OnRequestFinished(const RequestParams& params,
                                            base::Time start_time,
                                            const CompletionCallback& callback,
                                            CertVerifyResult* verify_result,
                                            int error) {
  AddResultToCache(params, start_time, *verify_result, error);

  // Now chain to the user's callback, which may delete |this|.
  callback.Run(error);
}

void CachingCertVerifier::AddResultToCache(
    const RequestParams& params,
    base::Time start_time,
    const CertVerifyResult& verify_result,
    int error) {
  // When caching, this uses the time that validation started as the
  // beginning of the validity, rather than the time that it ended (aka
  // base::Time::Now()), to account for the fact that during validation,
  // the clock may have changed.
  //
  // If the clock has changed significantly, then this result will ideally
  // be evicted and the next time the certificate is encountered, it will
  // be revalidated.
  //
  // Because of this, it's possible for situations to arise where the
  // clock was correct at the start of validation, changed to an
  // incorrect time during validation (such as too far in the past or
  // future), and then was reset to the correct time. If this happens,
  // it's likely that the result will not be a valid/correct result,
  // but will still be used from the cache because the clock was reset
  // to the correct time after the (bad) validation result completed.
  //
  // However, this solution optimizes for the case where the clock is
  // bad at the start of validation, and subsequently is corrected. In
  // that situation, the result is also incorrect, but because the clock
  // was corrected after validation, if the cache validity period was
  // computed at the end of validation, it would continue to serve an
  // invalid result for kTTLSecs.
  CachedResult cached_result;
  cached_result.error = error;
  cached_result.result = verify_result;
  cache_.Put(
      params, cached_result, CacheValidityPeriod(start_time),
      CacheValidityPeriod(start_time,
                          start_time + base::TimeDelta::FromSeconds(kTTLSecs)));
}

void CachingCertVerifier::VisitEntries(CacheVisitor* visitor) const {
  DCHECK(visitor);

  CacheValidityPeriod now(base::Time::Now());
  CacheExpirationFunctor expiration_cmp;

  for (CertVerificationCache::Iterator it(cache_); it.HasNext(); it.Advance()) {
    if (!expiration_cmp(now, it.expiration()))
      continue;
    if (!visitor->VisitEntry(it.key(), it.value().error, it.value().result,
                             it.expiration().verification_time,
                             it.expiration().expiration_time)) {
      break;
    }
  }
}

void CachingCertVerifier::OnCertDBChanged() {
  ClearCache();
}

void CachingCertVerifier::ClearCache() {
  cache_.Clear();
}

size_t CachingCertVerifier::GetCacheSize() const {
  return cache_.size();
}

}  // namespace net
