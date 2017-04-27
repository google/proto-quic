// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_SYSTEM_TRUST_STORE_H_
#define NET_CERT_INTERNAL_SYSTEM_TRUST_STORE_H_

#include <vector>

#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"
#include "net/cert/internal/parsed_certificate.h"

namespace net {

class TrustStore;
class CertIssuerSource;
class TrustAnchor;

// The SystemTrustStore interface is used to encapsulate a TrustStore for the
// current platform, with some extra bells and whistles.
//
// This is primarily used to abstract out the platform-specific bits that
// relate to configuring the TrustStore needed for path building.
//
// Implementations of SystemTrustStore create an effective trust
// store that is the composition of:
//
//   * The platform-specific trust store
//   * A set of manually added trust anchors
//   * Test certificates added via ScopedTestRoot
class SystemTrustStore {
 public:
  virtual ~SystemTrustStore() {}

  // Returns an aggregate TrustStore that can be used by the path builder. The
  // store composes the system trust store (if implemented) with manually added
  // trust anchors added via AddTrustAnchor(). This pointer is non-owned, and
  // valid only for the lifetime of |this|.
  virtual TrustStore* GetTrustStore() = 0;

  // Returns false if the implementation of SystemTrustStore doesn't actually
  // make use of the system's trust store. This might be the case for
  // unsupported platforms. In the case where this returns false, the trust
  // store returned by GetTrustStore() is made up solely of the manually added
  // trust anchors (via AddTrustAnchor()).
  virtual bool UsesSystemTrustStore() const = 0;

  // TODO(eroman): Expose this through the TrustStore interface instead?
  //
  // Returns a CertIssuerSource that finds any intermediates that are present in
  // the system trust store. These intermediates are not necessarily trusted,
  // however may be used during path building as another means of finding
  // certificates. If the implementation of SystemTrustStore doesn't support
  // this feature may return nullptr.
  virtual CertIssuerSource* GetCertIssuerSource() = 0;

  // IsKnownRoot() returns true if the given trust anchor originated from the
  // system trust store and is a "standard" one. The meaning of "standard" is
  // that it is one of default trust anchors for the system, as opposed to a
  // user-installed one. IsKnownRoot() is only guaranteed to work for
  // TrustAnchors returned by GetTrustStore().
  virtual bool IsKnownRoot(
      const scoped_refptr<TrustAnchor>& trust_anchor) const = 0;

  // Adds a trust anchor to this particular instance of SystemTrustStore, and
  // not globally for the system.
  virtual void AddTrustAnchor(
      const scoped_refptr<TrustAnchor>& trust_anchor) = 0;

  // Returns true if |trust_anchor| was one added via |AddTrustAnchor()|. This
  // is only guaranteed to work if |trust_anchor| was one returned by
  // GetTrustStore(), as it may be implemented by pointer comparison rather than
  // SPKI comparison.
  virtual bool IsAdditionalTrustAnchor(
      const scoped_refptr<TrustAnchor>& trust_anchor) const = 0;
};

// Creates an instance of SystemTrustStore that wraps the current platform's SSL
// trust store. This canno return nullptr, even in the case where system trust
// store integration is not supported. In this latter case, the SystemTrustStore
// will only give access to the manually added trust anchors. This can be
// inspected by testing whether UsesSystemTrustStore() returns false.
NET_EXPORT std::unique_ptr<SystemTrustStore> CreateSslSystemTrustStore();

}  // namespace net

#endif  // NET_CERT_INTERNAL_SYSTEM_TRUST_STORE_H_
