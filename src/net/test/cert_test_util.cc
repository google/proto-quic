// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/cert_test_util.h"

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "net/cert/ev_root_ca_metadata.h"
#include "net/cert/x509_certificate.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

CertificateList CreateCertificateListFromFile(
    const base::FilePath& certs_dir,
    const std::string& cert_file,
    int format) {
  base::FilePath cert_path = certs_dir.AppendASCII(cert_file);
  std::string cert_data;
  if (!base::ReadFileToString(cert_path, &cert_data))
    return CertificateList();
  return X509Certificate::CreateCertificateListFromBytes(cert_data.data(),
                                                         cert_data.size(),
                                                         format);
}

scoped_refptr<X509Certificate> CreateCertificateChainFromFile(
    const base::FilePath& certs_dir,
    const std::string& cert_file,
    int format) {
  CertificateList certs = CreateCertificateListFromFile(
      certs_dir, cert_file, format);
  if (certs.empty())
    return NULL;

  X509Certificate::OSCertHandles intermediates;
  for (size_t i = 1; i < certs.size(); ++i)
    intermediates.push_back(certs[i]->os_cert_handle());

  scoped_refptr<X509Certificate> result(X509Certificate::CreateFromHandle(
        certs[0]->os_cert_handle(), intermediates));
  return result;
}

scoped_refptr<X509Certificate> ImportCertFromFile(
    const base::FilePath& certs_dir,
    const std::string& cert_file) {
  base::FilePath cert_path = certs_dir.AppendASCII(cert_file);
  std::string cert_data;
  if (!base::ReadFileToString(cert_path, &cert_data))
    return NULL;

  CertificateList certs_in_file =
      X509Certificate::CreateCertificateListFromBytes(
          cert_data.data(), cert_data.size(), X509Certificate::FORMAT_AUTO);
  if (certs_in_file.empty())
    return NULL;
  return certs_in_file[0];
}

ScopedTestEVPolicy::ScopedTestEVPolicy(EVRootCAMetadata* ev_root_ca_metadata,
                                       const SHA1HashValue& fingerprint,
                                       const char* policy)
    : fingerprint_(fingerprint),
      ev_root_ca_metadata_(ev_root_ca_metadata) {
  EXPECT_TRUE(ev_root_ca_metadata->AddEVCA(fingerprint, policy));
}

ScopedTestEVPolicy::~ScopedTestEVPolicy() {
  EXPECT_TRUE(ev_root_ca_metadata_->RemoveEVCA(fingerprint_));
}

}  // namespace net
