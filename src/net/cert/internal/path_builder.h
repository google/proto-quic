// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_PATH_BUILDER_H_
#define NET_CERT_INTERNAL_PATH_BUILDER_H_

#include <memory>
#include <string>
#include <vector>

#include "net/base/net_export.h"
#include "net/cert/internal/cert_errors.h"
#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/internal/trust_store.h"
#include "net/cert/internal/verify_certificate_chain.h"
#include "net/der/input.h"
#include "net/der/parse_values.h"

namespace net {

namespace der {
struct GeneralizedTime;
}

class CertPathIter;
class CertIssuerSource;

// CertPath describes a chain of certificates in the "forward" direction.
//
// By convention:
//   certs[0] is the target certificate
//   certs[i] was issued by certs[i+1]
//   certs.back() is the root certificate.
//
// Note that the final certificate may or may not be a trust achor -- inspect
// |last_cert_trust| to determine it (or use GetTrustedCert())
struct NET_EXPORT CertPath {
  CertPath();
  ~CertPath();

  // Contains information on whether certs.back() is trusted.
  CertificateTrust last_cert_trust;

  // Path in the forward direction (see class description).
  ParsedCertificateList certs;

  // Resets the path to empty path (same as if default constructed).
  void Clear();

  // TODO(eroman): Can we remove this? Unclear on how this relates to validity.
  bool IsEmpty() const;

  // Returns the chain's root certificate or nullptr if the chain doesn't chain
  // to a trust anchor.
  const ParsedCertificate* GetTrustedCert() const;
};

// CertPathBuilderDelegate controls policies for certificate verification and
// path building.
class NET_EXPORT CertPathBuilderDelegate
    : public VerifyCertificateChainDelegate {
 public:
  // This is called during path building on candidate paths which have already
  // been run through RFC 5280 verification. |path| may already have errors
  // and warnings set on it. Delegates can "reject" a candidate path from path
  // building by adding high severity errors.
  virtual void CheckPathAfterVerification(const CertPath& path,
                                          CertPathErrors* errors) = 0;
};

// Checks whether a certificate is trusted by building candidate paths to trust
// anchors and verifying those paths according to RFC 5280. Each instance of
// CertPathBuilder is used for a single verification.
//
// WARNING: This implementation is currently experimental.  Consult an OWNER
// before using it.
class NET_EXPORT CertPathBuilder {
 public:
  // Represents a single candidate path that was built.
  struct NET_EXPORT ResultPath {
    ResultPath();
    ~ResultPath();

    // Returns true if the candidate path is valid, false otherwise.
    bool IsValid() const;

    // The (possibly partial) certificate path. Consumers must always test
    // |errors.IsValid()| before using |path|. When invalid,
    // |path.trust_anchor| may be null, and the path may be incomplete.
    CertPath path;

    // The set of policies that the certificate is valid for (of the
    // subset of policies user requested during verification).
    std::set<der::Input> user_constrained_policy_set;

    // The errors/warnings from this path. Use |IsValid()| to determine if the
    // path is valid.
    CertPathErrors errors;
  };

  // Provides the overall result of path building. This includes the paths that
  // were attempted.
  struct NET_EXPORT Result {
    Result();
    ~Result();

    // Returns true if there was a valid path.
    bool HasValidPath() const;

    // Returns the ResultPath for the best valid path, or nullptr if there
    // was none.
    const ResultPath* GetBestValidPath() const;

    // Resets to the initial value.
    void Clear();

    // List of paths that were attempted and the result for each.
    std::vector<std::unique_ptr<ResultPath>> paths;

    // Index into |paths|. Before use, |paths.empty()| must be checked.
    // NOTE: currently the definition of "best" is fairly limited. Valid is
    // better than invalid, but otherwise nothing is guaranteed.
    size_t best_result_index = 0;

   private:
    DISALLOW_COPY_AND_ASSIGN(Result);
  };

  // Creates a CertPathBuilder that attempts to find a path from |cert| to a
  // trust anchor in |trust_store| and is valid at |time|. Details of attempted
  // path(s) are stored in |*result|.
  //
  // The caller must keep |trust_store|, |delegate| and |*result| valid for the
  // lifetime of the CertPathBuilder.
  //
  // See VerifyCertificateChain() for a more detailed explanation of the
  // same-named parameters not defined below.
  //
  // * |result|: Storage for the result of path building.
  // * |delegate|: Must be non-null. The delegate is called at various points in
  //               path building to verify specific parts of certificates or the
  //               final chain. See CertPathBuilderDelegate and
  //               VerifyCertificateChainDelegate for more information.
  CertPathBuilder(scoped_refptr<ParsedCertificate> cert,
                  TrustStore* trust_store,
                  CertPathBuilderDelegate* delegate,
                  const der::GeneralizedTime& time,
                  KeyPurpose key_purpose,
                  InitialExplicitPolicy initial_explicit_policy,
                  const std::set<der::Input>& user_initial_policy_set,
                  InitialPolicyMappingInhibit initial_policy_mapping_inhibit,
                  InitialAnyPolicyInhibit initial_any_policy_inhibit,
                  Result* result);
  ~CertPathBuilder();

  // Adds a CertIssuerSource to provide intermediates for use in path building.
  // Multiple sources may be added. Must not be called after Run is called.
  // The |*cert_issuer_source| must remain valid for the lifetime of the
  // CertPathBuilder.
  //
  // (If no issuer sources are added, the target certificate will only verify if
  // it is a trust anchor or is directly signed by a trust anchor.)
  void AddCertIssuerSource(CertIssuerSource* cert_issuer_source);

  // Executes verification of the target certificate.
  //
  // Upon return results are written to the |result| object passed into the
  // constructor. Run must not be called more than once on each CertPathBuilder
  // instance.
  void Run();

 private:
  enum State {
    STATE_NONE,
    STATE_GET_NEXT_PATH,
    STATE_GET_NEXT_PATH_COMPLETE,
  };

  void DoGetNextPath();
  void DoGetNextPathComplete();

  void AddResultPath(std::unique_ptr<ResultPath> result_path);

  std::unique_ptr<CertPathIter> cert_path_iter_;
  CertPathBuilderDelegate* delegate_;
  const der::GeneralizedTime time_;
  const KeyPurpose key_purpose_;
  const InitialExplicitPolicy initial_explicit_policy_;
  const std::set<der::Input> user_initial_policy_set_;
  const InitialPolicyMappingInhibit initial_policy_mapping_inhibit_;
  const InitialAnyPolicyInhibit initial_any_policy_inhibit_;

  // Stores the next complete path to attempt verification on. This is filled in
  // by |cert_path_iter_| during the STATE_GET_NEXT_PATH step, and thus should
  // only be accessed during the STATE_GET_NEXT_PATH_COMPLETE step.
  // (Will be empty if all paths have been tried, otherwise will be a candidate
  // path starting with the target cert and ending with a
  // certificate issued by trust anchor.)
  CertPath next_path_;
  State next_state_;

  Result* out_result_;

  DISALLOW_COPY_AND_ASSIGN(CertPathBuilder);
};

}  // namespace net

#endif  // NET_CERT_INTERNAL_PATH_BUILDER_H_
