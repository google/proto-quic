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
#include "net/der/input.h"
#include "net/der/parse_values.h"

namespace net {

namespace der {
struct GeneralizedTime;
}

class CertPathIter;
class CertIssuerSource;
class SignaturePolicy;

// CertPath describes a chain of certificates in the "forward" direction.
//
// By convention:
//   certs[0] is the target certificate
//   certs[i] was issued by certs[i+1]
//   certs.back() was issued by trust_anchor
struct NET_EXPORT CertPath {
  CertPath();
  ~CertPath();

  scoped_refptr<TrustAnchor> trust_anchor;

  // Path in the forward direction (path[0] is the target cert).
  ParsedCertificateList certs;

  // Resets the path to empty path (same as if default constructed).
  void Clear();

  // Returns true if the path is empty.
  bool IsEmpty() const;
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

    // The (possibly partial) certificate path. Consumers must always test
    // |valid| before using |path|. When |!valid| path.trust_anchor may be
    // nullptr, and the path may be otherwise incomplete/invalid.
    CertPath path;

    // The errors/warnings from this path. Note that the list of errors is
    // independent of whether the path was |valid| (a valid path may
    // contain errors/warnings, and vice versa an invalid path may not have
    // logged any errors).
    CertErrors errors;

    // True if |path| is a correct verified certificate chain.
    bool valid = false;
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

    // List of paths that were attempted and the result for each.
    std::vector<std::unique_ptr<ResultPath>> paths;

    // Index into |paths|. Before use, |paths.empty()| must be checked.
    // NOTE: currently the definition of "best" is fairly limited. Valid is
    // better than invalid, but otherwise nothing is guaranteed.
    size_t best_result_index = 0;

   private:
    DISALLOW_COPY_AND_ASSIGN(Result);
  };

  // TODO(mattm): allow caller specified hook/callback to extend path
  // verification.
  //
  // TODO(eroman): The assumption is that |result| is default initialized. Can
  // probably just internalize |result| into CertPathBuilder.
  //
  // Creates a CertPathBuilder that attempts to find a path from |cert| to a
  // trust anchor in |trust_store|, which satisfies |signature_policy| and is
  // valid at |time|.  Details of attempted path(s) are stored in |*result|.
  //
  // The caller must keep |trust_store|, |signature_policy|, and |*result| valid
  // for the lifetime of the CertPathBuilder.
  CertPathBuilder(scoped_refptr<ParsedCertificate> cert,
                  const TrustStore* trust_store,
                  const SignaturePolicy* signature_policy,
                  const der::GeneralizedTime& time,
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
  const SignaturePolicy* signature_policy_;
  const der::GeneralizedTime time_;

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
