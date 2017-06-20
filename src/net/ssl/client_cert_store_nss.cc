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
#include "base/memory/ptr_util.h"
#include "base/strings/string_piece.h"
#include "base/task_runner_util.h"
#include "base/threading/worker_pool.h"
#include "crypto/nss_crypto_module_delegate.h"
#include "net/cert/scoped_nss_types.h"
#include "net/cert/x509_util.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_platform_key_nss.h"
#include "net/ssl/threaded_ssl_private_key.h"
#include "net/third_party/nss/ssl/cmpcert.h"

namespace net {

namespace {

class ClientCertIdentityNSS : public ClientCertIdentity {
 public:
  ClientCertIdentityNSS(
      scoped_refptr<net::X509Certificate> cert,
      scoped_refptr<crypto::CryptoModuleBlockingPasswordDelegate>
          password_delegate)
      : ClientCertIdentity(std::move(cert)),
        password_delegate_(std::move(password_delegate)) {}
  ~ClientCertIdentityNSS() override = default;

  void AcquirePrivateKey(
      const base::Callback<void(scoped_refptr<SSLPrivateKey>)>&
          private_key_callback) override {
    if (base::PostTaskAndReplyWithResult(
            base::WorkerPool::GetTaskRunner(true /* task_is_slow */).get(),
            FROM_HERE,
            base::Bind(&FetchClientCertPrivateKey,
                       base::RetainedRef(certificate()),
                       base::RetainedRef(password_delegate_)),
            private_key_callback)) {
      return;
    }
    // If the task could not be posted, behave as if there was no key.
    private_key_callback.Run(nullptr);
  }

 private:
  scoped_refptr<crypto::CryptoModuleBlockingPasswordDelegate>
      password_delegate_;
};

}  // namespace

ClientCertStoreNSS::ClientCertStoreNSS(
    const PasswordDelegateFactory& password_delegate_factory)
    : password_delegate_factory_(password_delegate_factory) {}

ClientCertStoreNSS::~ClientCertStoreNSS() {}

void ClientCertStoreNSS::GetClientCerts(
    const SSLCertRequestInfo& request,
    const ClientCertListCallback& callback) {
  scoped_refptr<crypto::CryptoModuleBlockingPasswordDelegate> password_delegate;
  if (!password_delegate_factory_.is_null())
    password_delegate = password_delegate_factory_.Run(request.host_and_port);
  if (base::PostTaskAndReplyWithResult(
          base::WorkerPool::GetTaskRunner(true /* task_is_slow */).get(),
          FROM_HERE,
          base::Bind(&ClientCertStoreNSS::GetAndFilterCertsOnWorkerThread,
                     // Caller is responsible for keeping the ClientCertStore
                     // alive until the callback is run.
                     base::Unretained(this), std::move(password_delegate),
                     &request),
          callback)) {
    return;
  }
  // If the task could not be posted, behave as if there were no certificates.
  callback.Run(ClientCertIdentityList());
}

// static
void ClientCertStoreNSS::FilterCertsOnWorkerThread(
    ClientCertIdentityList* identities,
    const SSLCertRequestInfo& request) {
  size_t num_raw = 0;

  auto keep_iter = identities->begin();

  for (auto examine_iter = identities->begin();
       examine_iter != identities->end(); ++examine_iter) {
    ++num_raw;
    X509Certificate::OSCertHandle handle =
        (*examine_iter)->certificate()->os_cert_handle();

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
    (*examine_iter)->SetIntermediates(intermediates_raw);

    if (examine_iter == keep_iter)
      ++keep_iter;
    else
      *keep_iter++ = std::move(*examine_iter);
  }
  identities->erase(keep_iter, identities->end());

  DVLOG(2) << "num_raw:" << num_raw << " num_filtered:" << identities->size();

  std::sort(identities->begin(), identities->end(), ClientCertIdentitySorter());
}

ClientCertIdentityList ClientCertStoreNSS::GetAndFilterCertsOnWorkerThread(
    scoped_refptr<crypto::CryptoModuleBlockingPasswordDelegate>
        password_delegate,
    const SSLCertRequestInfo* request) {
  ClientCertIdentityList selected_identities;
  GetPlatformCertsOnWorkerThread(std::move(password_delegate),
                                 &selected_identities);
  FilterCertsOnWorkerThread(&selected_identities, *request);
  return selected_identities;
}

// static
void ClientCertStoreNSS::GetPlatformCertsOnWorkerThread(
    scoped_refptr<crypto::CryptoModuleBlockingPasswordDelegate>
        password_delegate,
    ClientCertIdentityList* identities) {
  CERTCertList* found_certs =
      CERT_FindUserCertsByUsage(CERT_GetDefaultCertDB(), certUsageSSLClient,
                                PR_FALSE, PR_FALSE, password_delegate.get());
  if (!found_certs) {
    DVLOG(2) << "No client certs found.";
    return;
  }
  for (CERTCertListNode* node = CERT_LIST_HEAD(found_certs);
       !CERT_LIST_END(node, found_certs); node = CERT_LIST_NEXT(node)) {
    scoped_refptr<X509Certificate> cert = X509Certificate::CreateFromHandle(
        node->cert, X509Certificate::OSCertHandles());
    if (!cert) {
      DVLOG(2) << "X509Certificate::CreateFromHandle failed";
      continue;
    }
    identities->push_back(
        base::MakeUnique<ClientCertIdentityNSS>(cert, password_delegate));
  }
  CERT_DestroyCertList(found_certs);
}

}  // namespace net
