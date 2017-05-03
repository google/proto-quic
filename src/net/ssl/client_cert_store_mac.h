// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_CLIENT_CERT_STORE_MAC_H_
#define NET_SSL_CLIENT_CERT_STORE_MAC_H_

#include "base/callback.h"
#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/ssl/client_cert_store.h"
#include "net/ssl/ssl_cert_request_info.h"

namespace net {

class NET_EXPORT ClientCertStoreMac : public ClientCertStore {
 public:
  ClientCertStoreMac();
  ~ClientCertStoreMac() override;

  // ClientCertStore:
  void GetClientCerts(const SSLCertRequestInfo& cert_request_info,
                      const ClientCertListCallback& callback) override;

 private:
  friend class ClientCertStoreMacTest;
  friend class ClientCertStoreMacTestDelegate;

  // A hook for testing. Filters |input_certs| using the logic being used to
  // filter the system store when GetClientCerts() is called.
  // Implemented by creating a list of certificates that otherwise would be
  // extracted from the system store and filtering it using the common logic
  // (less adequate than the approach used on Windows).
  bool SelectClientCertsForTesting(const CertificateList& input_certs,
                                   const SSLCertRequestInfo& cert_request_info,
                                   CertificateList* selected_certs);

  // Testing hook specific to Mac, where the internal logic recognizes preferred
  // certificates for particular domains. If the preferred certificate is
  // present in the output list (i.e. it doesn't get filtered out), it should
  // always come first.
  bool SelectClientCertsGivenPreferredForTesting(
      const scoped_refptr<X509Certificate>& preferred_cert,
      const CertificateList& regular_certs,
      const SSLCertRequestInfo& request,
      CertificateList* selected_certs);

  DISALLOW_COPY_AND_ASSIGN(ClientCertStoreMac);
};

}  // namespace net

#endif  // NET_SSL_CLIENT_CERT_STORE_MAC_H_
