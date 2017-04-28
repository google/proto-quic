// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_CERT_VERIFY_PROC_ANDROID_H_
#define NET_CERT_CERT_VERIFY_PROC_ANDROID_H_

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"
#include "net/cert/cert_verify_proc.h"

namespace net {

class CertNetFetcher;

// Performs certificate verification on Android by calling the platform
// TrustManager through JNI.
class NET_EXPORT CertVerifyProcAndroid : public CertVerifyProc {
 public:
  CertVerifyProcAndroid();

  // Sets a global CertNetFetcher to be used for AIA fetches that are required
  // by VerifyInternal(). If not called, VerifyInternal() will not do its own
  // AIA fetching and will instead rely solely on the platform TrustManager. Can
  // only be called once.
  static void SetCertNetFetcher(scoped_refptr<CertNetFetcher> cert_net_fetcher);

  // Like SetCertNetFetcher, but allows the global CertNetFetcher to be set more
  // than once. If one has already been set, shuts it down and then sets it to
  // |cert_net_fetcher|.
  static void SetCertNetFetcherForTesting(
      scoped_refptr<CertNetFetcher> cert_net_fetcher);

  // Shuts down the global CertNetFetcher used for AIA fetches required by
  // VerifyInternal(). In-progress fetches will be cancelled and subsequent
  // fetches cancelled immediately. Assumes that SetCertNetFetcher() has been
  // called previously.
  static void ShutdownCertNetFetcher();

  bool SupportsAdditionalTrustAnchors() const override;
  bool SupportsOCSPStapling() const override;

 protected:
  ~CertVerifyProcAndroid() override;

 private:
  int VerifyInternal(X509Certificate* cert,
                     const std::string& hostname,
                     const std::string& ocsp_response,
                     int flags,
                     CRLSet* crl_set,
                     const CertificateList& additional_trust_anchors,
                     CertVerifyResult* verify_result) override;

  DISALLOW_COPY_AND_ASSIGN(CertVerifyProcAndroid);
};

}  // namespace net

#endif  // NET_CERT_CERT_VERIFY_PROC_ANDROID_H_
