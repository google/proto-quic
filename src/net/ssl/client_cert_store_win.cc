// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/client_cert_store_win.h"

#include <algorithm>
#include <string>

#define SECURITY_WIN32  // Needs to be defined before including security.h
#include <windows.h>
#include <security.h>

#include "base/callback.h"
#include "base/logging.h"
#include "crypto/wincrypt_shim.h"
#include "net/cert/x509_util.h"

namespace net {

namespace {

// Callback required by Windows API function CertFindChainInStore(). In addition
// to filtering by extended/enhanced key usage, we do not show expired
// certificates and require digital signature usage in the key usage extension.
//
// This matches our behavior on Mac OS X and that of NSS. It also matches the
// default behavior of IE8. See http://support.microsoft.com/kb/890326 and
// http://blogs.msdn.com/b/askie/archive/2009/06/09/my-expired-client-certifica
//     tes-no-longer-display-when-connecting-to-my-web-server-using-ie8.aspx
static BOOL WINAPI ClientCertFindCallback(PCCERT_CONTEXT cert_context,
                                          void* find_arg) {
  // Verify the certificate key usage is appropriate or not specified.
  BYTE key_usage;
  if (CertGetIntendedKeyUsage(X509_ASN_ENCODING, cert_context->pCertInfo,
                              &key_usage, 1)) {
    if (!(key_usage & CERT_DIGITAL_SIGNATURE_KEY_USAGE))
      return FALSE;
  } else {
    DWORD err = GetLastError();
    // If |err| is non-zero, it's an actual error. Otherwise the extension
    // just isn't present, and we treat it as if everything was allowed.
    if (err) {
      DLOG(ERROR) << "CertGetIntendedKeyUsage failed: " << err;
      return FALSE;
    }
  }

  // Verify the current time is within the certificate's validity period.
  if (CertVerifyTimeValidity(NULL, cert_context->pCertInfo) != 0)
    return FALSE;

  // Verify private key metadata is associated with this certificate.
  // TODO(ppi): Is this really needed? Isn't it equivalent to leaving
  // CERT_CHAIN_FIND_BY_ISSUER_NO_KEY_FLAG not set in |find_flags| argument of
  // CertFindChainInStore()?
  DWORD size = 0;
  if (!CertGetCertificateContextProperty(
          cert_context, CERT_KEY_PROV_INFO_PROP_ID, NULL, &size)) {
    return FALSE;
  }

  return TRUE;
}

void GetClientCertsImpl(HCERTSTORE cert_store,
                        const SSLCertRequestInfo& request,
                        CertificateList* selected_certs) {
  selected_certs->clear();

  const size_t auth_count = request.cert_authorities.size();
  std::vector<CERT_NAME_BLOB> issuers(auth_count);
  for (size_t i = 0; i < auth_count; ++i) {
    issuers[i].cbData = static_cast<DWORD>(request.cert_authorities[i].size());
    issuers[i].pbData = reinterpret_cast<BYTE*>(
        const_cast<char*>(request.cert_authorities[i].data()));
  }

  // Enumerate the client certificates.
  CERT_CHAIN_FIND_BY_ISSUER_PARA find_by_issuer_para;
  memset(&find_by_issuer_para, 0, sizeof(find_by_issuer_para));
  find_by_issuer_para.cbSize = sizeof(find_by_issuer_para);
  find_by_issuer_para.pszUsageIdentifier = szOID_PKIX_KP_CLIENT_AUTH;
  find_by_issuer_para.cIssuer = static_cast<DWORD>(auth_count);
  find_by_issuer_para.rgIssuer =
      reinterpret_cast<CERT_NAME_BLOB*>(issuers.data());
  find_by_issuer_para.pfnFindCallback = ClientCertFindCallback;

  PCCERT_CHAIN_CONTEXT chain_context = NULL;
  DWORD find_flags = CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG |
                     CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG;
  for (;;) {
    // Find a certificate chain.
    chain_context = CertFindChainInStore(cert_store,
                                         X509_ASN_ENCODING,
                                         find_flags,
                                         CERT_CHAIN_FIND_BY_ISSUER,
                                         &find_by_issuer_para,
                                         chain_context);
    if (!chain_context) {
      if (GetLastError() != static_cast<DWORD>(CRYPT_E_NOT_FOUND))
        DPLOG(ERROR) << "CertFindChainInStore failed: ";
      break;
    }

    // Get the leaf certificate.
    PCCERT_CONTEXT cert_context =
        chain_context->rgpChain[0]->rgpElement[0]->pCertContext;
    // Copy the certificate, so that it is valid after |cert_store| is closed.
    PCCERT_CONTEXT cert_context2 = NULL;
    BOOL ok = CertAddCertificateContextToStore(NULL, cert_context,
                                               CERT_STORE_ADD_USE_EXISTING,
                                               &cert_context2);
    if (!ok) {
      NOTREACHED();
      continue;
    }

    // Grab the intermediates, if any.
    X509Certificate::OSCertHandles intermediates;
    for (DWORD i = 1; i < chain_context->rgpChain[0]->cElement; ++i) {
      PCCERT_CONTEXT chain_intermediate =
          chain_context->rgpChain[0]->rgpElement[i]->pCertContext;
      PCCERT_CONTEXT copied_intermediate = NULL;
      ok = CertAddCertificateContextToStore(NULL, chain_intermediate,
                                            CERT_STORE_ADD_USE_EXISTING,
                                            &copied_intermediate);
      if (ok)
        intermediates.push_back(copied_intermediate);
    }

    // Drop the self-signed root, if any. Match Internet Explorer in not sending
    // it. Although the root's signature is irrelevant for authentication, some
    // servers reject chains if the root is explicitly sent and has a weak
    // signature algorithm. See https://crbug.com/607264.
    //
    // The leaf or a intermediate may also have a weak signature algorithm but,
    // in that case, assume it is a configuration error.
    if (!intermediates.empty() &&
        X509Certificate::IsSelfSigned(intermediates.back())) {
      CertFreeCertificateContext(intermediates.back());
      intermediates.pop_back();
    }

    // TODO(svaldez): cert currently wraps cert_context2 which may be backed
    // by a smartcard with threading difficulties. Instead, create a fresh
    // X509Certificate with CreateFromBytes and route cert_context2 into the
    // SSLPrivateKey. Probably changing CertificateList to be a
    // pair<X509Certificate, SSLPrivateKeyCallback>.
    scoped_refptr<X509Certificate> cert = X509Certificate::CreateFromHandle(
        cert_context2, intermediates);
    selected_certs->push_back(cert);
    CertFreeCertificateContext(cert_context2);
    for (size_t i = 0; i < intermediates.size(); ++i)
      CertFreeCertificateContext(intermediates[i]);
  }

  std::sort(selected_certs->begin(), selected_certs->end(),
            x509_util::ClientCertSorter());
}

}  // namespace

ClientCertStoreWin::ClientCertStoreWin() {}

ClientCertStoreWin::ClientCertStoreWin(HCERTSTORE cert_store) {
  DCHECK(cert_store);
  cert_store_.reset(cert_store);
}

ClientCertStoreWin::~ClientCertStoreWin() {}

void ClientCertStoreWin::GetClientCerts(const SSLCertRequestInfo& request,
                                        CertificateList* selected_certs,
                                        const base::Closure& callback) {
  if (cert_store_) {
    // Use the existing client cert store. Note: Under some situations,
    // it's possible for this to return certificates that aren't usable
    // (see below).
    GetClientCertsImpl(cert_store_, request, selected_certs);
    callback.Run();
    return;
  }

  // Always open a new instance of the "MY" store, to ensure that there
  // are no previously cached certificates being reused after they're
  // no longer available (some smartcard providers fail to update the "MY"
  // store handles and instead interpose CertOpenSystemStore).
  ScopedHCERTSTORE my_cert_store(CertOpenSystemStore(NULL, L"MY"));
  if (!my_cert_store) {
    PLOG(ERROR) << "Could not open the \"MY\" system certificate store: ";
    selected_certs->clear();
    callback.Run();
    return;
  }

  GetClientCertsImpl(my_cert_store, request, selected_certs);

  callback.Run();
}

bool ClientCertStoreWin::SelectClientCertsForTesting(
    const CertificateList& input_certs,
    const SSLCertRequestInfo& request,
    CertificateList* selected_certs) {
  ScopedHCERTSTORE test_store(CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, 0,
                                            NULL));
  if (!test_store)
    return false;

  // Add available certificates to the test store.
  for (size_t i = 0; i < input_certs.size(); ++i) {
    // Add the certificate to the test store.
    PCCERT_CONTEXT cert = NULL;
    if (!CertAddCertificateContextToStore(test_store,
                                          input_certs[i]->os_cert_handle(),
                                          CERT_STORE_ADD_NEW, &cert)) {
      return false;
    }
    // Add dummy private key data to the certificate - otherwise the certificate
    // would be discarded by the filtering routines.
    CRYPT_KEY_PROV_INFO private_key_data;
    memset(&private_key_data, 0, sizeof(private_key_data));
    if (!CertSetCertificateContextProperty(cert,
                                           CERT_KEY_PROV_INFO_PROP_ID,
                                           0, &private_key_data)) {
      return false;
    }
    // Decrement the reference count of the certificate (since we requested a
    // copy).
    if (!CertFreeCertificateContext(cert))
      return false;
  }

  GetClientCertsImpl(test_store.get(), request, selected_certs);
  return true;
}

}  // namespace net
