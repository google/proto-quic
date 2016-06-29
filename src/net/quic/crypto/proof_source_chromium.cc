// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/proof_source_chromium.h"

#include <openssl/digest.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "base/strings/string_number_conversions.h"
#include "crypto/openssl_util.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/ssl/scoped_openssl_types.h"

using std::string;
using std::vector;

namespace net {

ProofSourceChromium::ProofSourceChromium() {}

ProofSourceChromium::~ProofSourceChromium() {}

bool ProofSourceChromium::Initialize(const base::FilePath& cert_path,
                                     const base::FilePath& key_path,
                                     const base::FilePath& sct_path) {
  crypto::EnsureOpenSSLInit();

  std::string cert_data;
  if (!base::ReadFileToString(cert_path, &cert_data)) {
    DLOG(FATAL) << "Unable to read certificates.";
    return false;
  }

  CertificateList certs_in_file =
      X509Certificate::CreateCertificateListFromBytes(
          cert_data.data(), cert_data.size(), X509Certificate::FORMAT_AUTO);

  if (certs_in_file.empty()) {
    DLOG(FATAL) << "No certificates.";
    return false;
  }

  vector<string> certs;
  for (const scoped_refptr<X509Certificate>& cert : certs_in_file) {
    std::string der_encoded_cert;
    if (!X509Certificate::GetDEREncoded(cert->os_cert_handle(),
                                        &der_encoded_cert)) {
      return false;
    }
    certs.push_back(der_encoded_cert);
  }
  chain_ = new ProofSource::Chain(certs);

  std::string key_data;
  if (!base::ReadFileToString(key_path, &key_data)) {
    DLOG(FATAL) << "Unable to read key.";
    return false;
  }

  const uint8_t* p = reinterpret_cast<const uint8_t*>(key_data.data());
  std::vector<uint8_t> input(p, p + key_data.size());
  private_key_ = crypto::RSAPrivateKey::CreateFromPrivateKeyInfo(input);
  if (!private_key_) {
    DLOG(FATAL) << "Unable to create private key.";
    return false;
  }

  // Loading of the signed certificate timestamp is optional.
  if (sct_path.empty())
    return true;

  if (!base::ReadFileToString(sct_path, &signed_certificate_timestamp_)) {
    DLOG(FATAL) << "Unable to read signed certificate timestamp.";
    return false;
  }

  return true;
}

bool ProofSourceChromium::GetProof(const IPAddress& server_ip,
                                   const string& hostname,
                                   const string& server_config,
                                   QuicVersion quic_version,
                                   base::StringPiece chlo_hash,
                                   bool ecdsa_ok,
                                   scoped_refptr<ProofSource::Chain>* out_chain,
                                   string* out_signature,
                                   string* out_leaf_cert_sct) {
  DCHECK(private_key_.get()) << " this: " << this;

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  crypto::ScopedEVP_MD_CTX sign_context(EVP_MD_CTX_create());
  EVP_PKEY_CTX* pkey_ctx;

  if (quic_version > QUIC_VERSION_30) {
    uint32_t len = chlo_hash.length();
    if (!EVP_DigestSignInit(sign_context.get(), &pkey_ctx, EVP_sha256(),
                            nullptr, private_key_->key()) ||
        !EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) ||
        !EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) ||
        !EVP_DigestSignUpdate(
            sign_context.get(),
            reinterpret_cast<const uint8_t*>(kProofSignatureLabel),
            sizeof(kProofSignatureLabel)) ||
        !EVP_DigestSignUpdate(sign_context.get(),
                              reinterpret_cast<const uint8_t*>(&len),
                              sizeof(len)) ||
        !EVP_DigestSignUpdate(
            sign_context.get(),
            reinterpret_cast<const uint8_t*>(chlo_hash.data()), len) ||
        !EVP_DigestSignUpdate(
            sign_context.get(),
            reinterpret_cast<const uint8_t*>(server_config.data()),
            server_config.size())) {
      return false;
    }
  } else if (!EVP_DigestSignInit(sign_context.get(), &pkey_ctx, EVP_sha256(),
                                 nullptr, private_key_->key()) ||
             !EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) ||
             !EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) ||
             !EVP_DigestSignUpdate(
                 sign_context.get(),
                 reinterpret_cast<const uint8_t*>(kProofSignatureLabelOld),
                 sizeof(kProofSignatureLabelOld)) ||
             !EVP_DigestSignUpdate(
                 sign_context.get(),
                 reinterpret_cast<const uint8_t*>(server_config.data()),
                 server_config.size())) {
    return false;
  }

  // Determine the maximum length of the signature.
  size_t len = 0;
  if (!EVP_DigestSignFinal(sign_context.get(), nullptr, &len)) {
    return false;
  }
  std::vector<uint8_t> signature(len);
  // Sign it.
  if (!EVP_DigestSignFinal(sign_context.get(), signature.data(), &len)) {
    return false;
  }
  signature.resize(len);
  out_signature->assign(reinterpret_cast<const char*>(signature.data()),
                        signature.size());
  *out_chain = chain_;
  VLOG(1) << "signature: "
          << base::HexEncode(out_signature->data(), out_signature->size());
  *out_leaf_cert_sct = signed_certificate_timestamp_;
  return true;
}

}  // namespace net
