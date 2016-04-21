// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_MULTI_THREADED_CERT_VERIFIER_H_
#define NET_CERT_MULTI_THREADED_CERT_VERIFIER_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <set>
#include <string>
#include <vector>

#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/threading/non_thread_safe.h"
#include "net/base/completion_callback.h"
#include "net/base/expiring_cache.h"
#include "net/base/hash_value.h"
#include "net/base/net_export.h"
#include "net/cert/cert_database.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/x509_cert_types.h"

namespace net {

class CertTrustAnchorProvider;
class CertVerifierJob;
class CertVerifierRequest;
class CertVerifierWorker;
class CertVerifyProc;

// MultiThreadedCertVerifier is a CertVerifier implementation that runs
// synchronous CertVerifier implementations on worker threads.
class NET_EXPORT_PRIVATE MultiThreadedCertVerifier
    : public CertVerifier,
      NON_EXPORTED_BASE(public base::NonThreadSafe),
      public CertDatabase::Observer {
 public:
  explicit MultiThreadedCertVerifier(CertVerifyProc* verify_proc);

  // When the verifier is destroyed, all certificate verifications requests are
  // canceled, and their completion callbacks will not be called.
  ~MultiThreadedCertVerifier() override;

  // Configures a source of additional certificates that should be treated as
  // trust anchors during verification, provided that the underlying
  // CertVerifyProc supports additional trust beyond the default implementation.
  // The CertTrustAnchorProvider will only be accessed on the same
  // thread that Verify() is called on; that is, it will not be
  // accessed from worker threads.
  // It must outlive the MultiThreadedCertVerifier.
  void SetCertTrustAnchorProvider(
      CertTrustAnchorProvider* trust_anchor_provider);

  // CertVerifier implementation
  int Verify(X509Certificate* cert,
             const std::string& hostname,
             const std::string& ocsp_response,
             int flags,
             CRLSet* crl_set,
             CertVerifyResult* verify_result,
             const CompletionCallback& callback,
             std::unique_ptr<Request>* out_req,
             const BoundNetLog& net_log) override;

  bool SupportsOCSPStapling() override;

 private:
  struct JobToRequestParamsComparator;
  friend class CertVerifierRequest;
  friend class CertVerifierJob;
  friend class MultiThreadedCertVerifierTest;
  FRIEND_TEST_ALL_PREFIXES(MultiThreadedCertVerifierTest, CacheHit);
  FRIEND_TEST_ALL_PREFIXES(MultiThreadedCertVerifierTest, DifferentCACerts);
  FRIEND_TEST_ALL_PREFIXES(MultiThreadedCertVerifierTest, InflightJoin);
  FRIEND_TEST_ALL_PREFIXES(MultiThreadedCertVerifierTest, MultipleInflightJoin);
  FRIEND_TEST_ALL_PREFIXES(MultiThreadedCertVerifierTest, CancelRequest);
  FRIEND_TEST_ALL_PREFIXES(MultiThreadedCertVerifierTest,
                           RequestParamsComparators);
  FRIEND_TEST_ALL_PREFIXES(MultiThreadedCertVerifierTest,
                           CertTrustAnchorProvider);

  // Input parameters of a certificate verification request.
  struct NET_EXPORT_PRIVATE RequestParams {
    RequestParams(const SHA1HashValue& cert_fingerprint_arg,
                  const SHA1HashValue& ca_fingerprint_arg,
                  const std::string& hostname_arg,
                  const std::string& ocsp_response_arg,
                  int flags_arg,
                  const CertificateList& additional_trust_anchors);
    RequestParams(const RequestParams& other);
    ~RequestParams();

    bool operator<(const RequestParams& other) const;

    std::string hostname;
    int flags;
    std::vector<SHA1HashValue> hash_values;
    // The time when verification started.
    // Note: This uses base::Time, rather than base::TimeTicks, to
    // account for system clock changes.
    base::Time start_time;
  };

  // CachedResult contains the result of a certificate verification.
  struct NET_EXPORT_PRIVATE CachedResult {
    CachedResult();
    ~CachedResult();

    int error;  // The return value of CertVerifier::Verify.
    CertVerifyResult result;  // The output of CertVerifier::Verify.
  };

  // Rather than having a single validity point along a monotonically increasing
  // timeline, certificate verification is based on falling within a range of
  // the certificate's NotBefore and NotAfter and based on what the current
  // system clock says (which may advance forwards or backwards as users correct
  // clock skew). CacheValidityPeriod and CacheExpirationFunctor are helpers to
  // ensure that expiration is measured both by the 'general' case (now + cache
  // TTL) and by whether or not significant enough clock skew was introduced
  // since the last verification.
  struct CacheValidityPeriod {
    explicit CacheValidityPeriod(const base::Time& now);
    CacheValidityPeriod(const base::Time& now, const base::Time& expiration);

    base::Time verification_time;
    base::Time expiration_time;
  };

  struct CacheExpirationFunctor {
    // Returns true iff |now| is within the validity period of |expiration|.
    bool operator()(const CacheValidityPeriod& now,
                    const CacheValidityPeriod& expiration) const;
  };

  struct JobComparator {
    bool operator()(const CertVerifierJob* job1,
                    const CertVerifierJob* job2) const;
  };

  using JobSet = std::set<CertVerifierJob*, JobComparator>;

  typedef ExpiringCache<RequestParams, CachedResult, CacheValidityPeriod,
                        CacheExpirationFunctor> CertVerifierCache;

  // Saves |result| into the cache, keyed by |key|.
  void SaveResultToCache(const RequestParams& key, const CachedResult& result);

  // CertDatabase::Observer methods:
  void OnCACertChanged(const X509Certificate* cert) override;

  // Returns an inflight job for |key|. If there is no such job then returns
  // null.
  CertVerifierJob* FindJob(const RequestParams& key);

  // Removes |job| from the inflight set, and passes ownership back to the
  // caller. |job| must already be |inflight_|.
  std::unique_ptr<CertVerifierJob> RemoveJob(CertVerifierJob* job);

  // For unit testing.
  void ClearCache() { cache_.Clear(); }
  size_t GetCacheSize() const { return cache_.size(); }
  uint64_t cache_hits() const { return cache_hits_; }
  uint64_t requests() const { return requests_; }
  uint64_t inflight_joins() const { return inflight_joins_; }

  // cache_ maps from a request to a cached result.
  CertVerifierCache cache_;

  // inflight_ holds the jobs for which an active verification is taking place.
  JobSet inflight_;

  uint64_t requests_;
  uint64_t cache_hits_;
  uint64_t inflight_joins_;

  scoped_refptr<CertVerifyProc> verify_proc_;

  CertTrustAnchorProvider* trust_anchor_provider_;

  DISALLOW_COPY_AND_ASSIGN(MultiThreadedCertVerifier);
};

}  // namespace net

#endif  // NET_CERT_MULTI_THREADED_CERT_VERIFIER_H_
