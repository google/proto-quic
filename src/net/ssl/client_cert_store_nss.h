// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_CLIENT_CERT_STORE_NSS_H_
#define NET_SSL_CLIENT_CERT_STORE_NSS_H_

#include <memory>

#include "base/callback.h"
#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/ssl/client_cert_store.h"

typedef struct CERTCertListStr CERTCertList;

namespace crypto {
class CryptoModuleBlockingPasswordDelegate;
}

namespace net {
class HostPortPair;
class SSLCertRequestInfo;

class NET_EXPORT ClientCertStoreNSS : public ClientCertStore {
 public:
  typedef base::Callback<crypto::CryptoModuleBlockingPasswordDelegate*(
      const HostPortPair& /* server */)> PasswordDelegateFactory;

  explicit ClientCertStoreNSS(
      const PasswordDelegateFactory& password_delegate_factory);
  ~ClientCertStoreNSS() override;

  // ClientCertStore:
  void GetClientCerts(const SSLCertRequestInfo& cert_request_info,
                      CertificateList* selected_certs,
                      const base::Closure& callback) override;

  // Examines the certificates in |certs| to find all certificates that match
  // the client certificate request in |request|, storing the matching
  // certificates in |filtered_certs|. Any previous content of |filtered_certs|
  // will be removed.
  // Must be called from a worker thread.
  static void FilterCertsOnWorkerThread(const CertificateList& certs,
                                        const SSLCertRequestInfo& request,
                                        CertificateList* filtered_certs);

  // Retrieves all client certificates that are stored by NSS and adds them to
  // |certs|. |password_delegate| is used to unlock slots if required.
  // Must be called from a worker thread.
  static void GetPlatformCertsOnWorkerThread(
      std::unique_ptr<crypto::CryptoModuleBlockingPasswordDelegate>
          password_delegate,
      net::CertificateList* certs);

 private:
  void GetAndFilterCertsOnWorkerThread(
      std::unique_ptr<crypto::CryptoModuleBlockingPasswordDelegate>
          password_delegate,
      const SSLCertRequestInfo* request,
      CertificateList* selected_certs);

  // The factory for creating the delegate for requesting a password to a
  // PKCS#11 token. May be null.
  PasswordDelegateFactory password_delegate_factory_;

  DISALLOW_COPY_AND_ASSIGN(ClientCertStoreNSS);
};

}  // namespace net

#endif  // NET_SSL_CLIENT_CERT_STORE_NSS_H_
