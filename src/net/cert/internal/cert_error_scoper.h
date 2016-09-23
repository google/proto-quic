// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_CERT_ERROR_SCOPER_H_
#define NET_CERT_INTERNAL_CERT_ERROR_SCOPER_H_

#include <memory>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/cert/internal/cert_error_id.h"

namespace net {

class CertErrors;
struct CertErrorNode;

// CertErrorScoper is a base class for adding parent nodes into a CertErrors
// object.
class NET_EXPORT CertErrorScoper {
 public:
  explicit CertErrorScoper(CertErrors* parent_errors);
  virtual ~CertErrorScoper();

  // BuildRootNode() will be called at most once, to create the desired parent
  // node. It may never be called if no errors are added to the CertErrors
  // parent.
  virtual std::unique_ptr<CertErrorNode> BuildRootNode() = 0;

  // Returns the parent node for this scoper (the one created by
  // BuildRootNode()).
  CertErrorNode* LazyGetRootNode();

 private:
  CertErrorScoper* parent_scoper_ = nullptr;
  CertErrors* parent_errors_ = nullptr;
  CertErrorNode* root_node_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(CertErrorScoper);
};

// Implementation of CertErrorScoper that creates a simple parent node with no
// parameters (just an ID).
class NET_EXPORT CertErrorScoperNoParams : public CertErrorScoper {
 public:
  CertErrorScoperNoParams(CertErrors* parent_errors, CertErrorId id);
  std::unique_ptr<CertErrorNode> BuildRootNode() override;

 private:
  CertErrorId id_;

  DISALLOW_COPY_AND_ASSIGN(CertErrorScoperNoParams);
};

}  // namespace net

#endif  // NET_CERT_INTERNAL_CERT_ERROR_SCOPER_H_
