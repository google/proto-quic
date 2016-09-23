// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/client_cert_store_nss.h"

#include <nss.h>
#include <ssl.h>

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "base/threading/worker_pool.h"
#include "crypto/nss_crypto_module_delegate.h"
#include "net/cert/scoped_nss_types.h"
#include "net/cert/x509_util.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/third_party/nss/ssl/cmpcert.h"

namespace net {

ClientCertStoreNSS::ClientCertStoreNSS(
    const PasswordDelegateFactory& password_delegate_factory)
    : password_delegate_factory_(password_delegate_factory) {}

ClientCertStoreNSS::~ClientCertStoreNSS() {}

void ClientCertStoreNSS::GetClientCerts(const SSLCertRequestInfo& request,
                                         CertificateList* selected_certs,
                                         const base::Closure& callback) {
  std::unique_ptr<crypto::CryptoModuleBlockingPasswordDelegate>
      password_delegate;
  if (!password_delegate_factory_.is_null()) {
    password_delegate.reset(
        password_delegate_factory_.Run(request.host_and_port));
  }
  if (base::WorkerPool::PostTaskAndReply(
          FROM_HERE,
          base::Bind(&ClientCertStoreNSS::GetAndFilterCertsOnWorkerThread,
                     // Caller is responsible for keeping the ClientCertStore
                     // alive until the callback is run.
                     base::Unretained(this), base::Passed(&password_delegate),
                     &request, selected_certs),
          callback, true)) {
    return;
  }
  // If the task could not be posted, behave as if there were no certificates
  // which requires to clear |selected_certs|.
  selected_certs->clear();
  callback.Run();
}

// static
void ClientCertStoreNSS::FilterCertsOnWorkerThread(
    const CertificateList& certs,
    const SSLCertRequestInfo& request,
    CertificateList* filtered_certs) {
  DCHECK(filtered_certs);

  filtered_certs->clear();

  size_t num_raw = 0;
  for (const auto& cert : certs) {
    ++num_raw;
    X509Certificate::OSCertHandle handle = cert->os_cert_handle();

    // Only offer unexpired certificates.
    if (CERT_CheckCertValidTimes(handle, PR_Now(), PR_TRUE) !=
        secCertTimeValid) {
      DVLOG(2) << "skipped expired cert: "
               << base::StringPiece(handle->nickname);
      continue;
    }

    std::vector<ScopedCERTCertificate> intermediates;
    if (!MatchClientCertificateIssuers(handle, request.cert_authorities,
                                       &intermediates)) {
      DVLOG(2) << "skipped non-matching cert: "
               << base::StringPiece(handle->nickname);
      continue;
    }

    DVLOG(2) << "matched cert: " << base::StringPiece(handle->nickname);

    X509Certificate::OSCertHandles intermediates_raw;
    for (const auto& intermediate : intermediates) {
      intermediates_raw.push_back(intermediate.get());
    }

    // Retain a copy of the intermediates. Some deployments expect the client to
    // supply intermediates out of the local store. See
    // https://crbug.com/548631.
    filtered_certs->push_back(
        X509Certificate::CreateFromHandle(handle, intermediates_raw));
  }
  DVLOG(2) << "num_raw:" << num_raw
           << " num_filtered:" << filtered_certs->size();

  std::sort(filtered_certs->begin(), filtered_certs->end(),
            x509_util::ClientCertSorter());
}

void ClientCertStoreNSS::GetAndFilterCertsOnWorkerThread(
    std::unique_ptr<crypto::CryptoModuleBlockingPasswordDelegate>
        password_delegate,
    const SSLCertRequestInfo* request,
    CertificateList* selected_certs) {
  CertificateList platform_certs;
  GetPlatformCertsOnWorkerThread(std::move(password_delegate), &platform_certs);
  FilterCertsOnWorkerThread(platform_certs, *request, selected_certs);
}

// static
void ClientCertStoreNSS::GetPlatformCertsOnWorkerThread(
    std::unique_ptr<crypto::CryptoModuleBlockingPasswordDelegate>
        password_delegate,
    net::CertificateList* certs) {
  CERTCertList* found_certs =
      CERT_FindUserCertsByUsage(CERT_GetDefaultCertDB(), certUsageSSLClient,
                                PR_FALSE, PR_FALSE, password_delegate.get());
  if (!found_certs) {
    DVLOG(2) << "No client certs found.";
    return;
  }
  for (CERTCertListNode* node = CERT_LIST_HEAD(found_certs);
       !CERT_LIST_END(node, found_certs); node = CERT_LIST_NEXT(node)) {
    certs->push_back(X509Certificate::CreateFromHandle(
        node->cert, X509Certificate::OSCertHandles()));
  }
  CERT_DestroyCertList(found_certs);
}

}  // namespace net
