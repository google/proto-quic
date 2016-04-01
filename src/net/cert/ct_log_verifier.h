// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_CT_LOG_VERIFIER_H_
#define NET_CERT_CT_LOG_VERIFIER_H_

#include <string>

#include "base/gtest_prod_util.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/cert/signed_certificate_timestamp.h"
#include "url/gurl.h"

// Forward declare the crypto types to avoid having to include the full
// headers.
#if defined(USE_OPENSSL)
typedef struct evp_pkey_st EVP_PKEY;
#else
typedef struct SECKEYPublicKeyStr SECKEYPublicKey;
#endif

namespace net {

namespace ct {

struct SignedTreeHead;
struct MerkleConsistencyProof;

}  // namespace ct

// Class for verifying signatures of a single Certificate Transparency
// log, whose identity is provided during construction.
// Currently can verify Signed Certificate Timestamp (SCT) and Signed
// Tree Head (STH) signatures.
// Immutable: Does not hold any state beyond the log information it was
// initialized with.
class NET_EXPORT CTLogVerifier
    : public base::RefCountedThreadSafe<CTLogVerifier> {
 public:
  // Creates a new CTLogVerifier that will verify SignedCertificateTimestamps
  // using |public_key|, which is a DER-encoded SubjectPublicKeyInfo.
  // If |public_key| refers to an unsupported public key, returns NULL.
  // |description| is a textual description of the log.
  static scoped_refptr<const CTLogVerifier> Create(
      const base::StringPiece& public_key,
      const base::StringPiece& description,
      const base::StringPiece& url);

  // Returns the log's key ID (RFC6962, Section 3.2)
  const std::string& key_id() const { return key_id_; }
  // Returns the log's human-readable description.
  const std::string& description() const { return description_; }
  // Returns the log's URL
  const GURL& url() const { return url_; }

  // Verifies that |sct| is valid for |entry| and was signed by this log.
  bool Verify(const ct::LogEntry& entry,
              const ct::SignedCertificateTimestamp& sct) const;

  // Verifies that |signed_tree_head| is a valid Signed Tree Head (RFC 6962,
  // Section 3.5) for this log.
  bool VerifySignedTreeHead(const ct::SignedTreeHead& signed_tree_head) const;

  // Verifies that |proof| is a valid consistency proof (RFC 6962, Section
  // 2.1.2) for this log, and which proves that |old_tree_hash| has
  // been fully incorporated into the Merkle tree represented by
  // |new_tree_hash|.
  bool VerifyConsistencyProof(const ct::MerkleConsistencyProof& proof,
                              const std::string& old_tree_hash,
                              const std::string& new_tree_hash) const;

 private:
  FRIEND_TEST_ALL_PREFIXES(CTLogVerifierTest, VerifySignature);
  friend class base::RefCountedThreadSafe<CTLogVerifier>;

  CTLogVerifier(const base::StringPiece& description, const GURL& url);
  ~CTLogVerifier();

  // Performs crypto-library specific initialization.
  bool Init(const base::StringPiece& public_key);

  // Performs the underlying verification using the selected public key. Note
  // that |signature| contains the raw signature data (eg: without any
  // DigitallySigned struct encoding).
  bool VerifySignature(const base::StringPiece& data_to_sign,
                       const base::StringPiece& signature) const;

  // Returns true if the signature and hash algorithms in |signature|
  // match those of the log
  bool SignatureParametersMatch(const ct::DigitallySigned& signature) const;

  std::string key_id_;
  std::string description_;
  GURL url_;
  ct::DigitallySigned::HashAlgorithm hash_algorithm_;
  ct::DigitallySigned::SignatureAlgorithm signature_algorithm_;

#if defined(USE_OPENSSL)
  EVP_PKEY* public_key_;
#else
  SECKEYPublicKey* public_key_;
#endif
};

}  // namespace net

#endif  // NET_CERT_CT_LOG_VERIFIER_H_
