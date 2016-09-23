// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/cert_error_scoper.h"

#include <memory>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "net/cert/internal/cert_error_params.h"
#include "net/cert/internal/cert_errors.h"

namespace net {

CertErrorScoper::CertErrorScoper(CertErrors* parent_errors) {
  DCHECK(parent_errors);
  parent_errors_ = parent_errors;
  parent_scoper_ = parent_errors->SetScoper(this);
}

CertErrorScoper::~CertErrorScoper() {
  CertErrorScoper* prev = parent_errors_->SetScoper(parent_scoper_);
  DCHECK_EQ(prev, this);
}

CertErrorNode* CertErrorScoper::LazyGetRootNode() {
  if (!root_node_) {
    // Create the node.
    auto root_node = BuildRootNode();
    root_node_ = root_node.get();

    // Attach it to the node hiearchy (ownership of this node is passed off
    // to its parent, which is ultimately rooted in the CertErrors object).
    if (parent_scoper_) {
      parent_scoper_->LazyGetRootNode()->AddChild(std::move(root_node));
    } else {
      parent_errors_->nodes_.push_back(std::move(root_node));
    }
  }

  return root_node_;
}

CertErrorScoperNoParams::CertErrorScoperNoParams(CertErrors* parent_errors,
                                                 CertErrorId id)
    : CertErrorScoper(parent_errors), id_(id) {}

std::unique_ptr<CertErrorNode> CertErrorScoperNoParams::BuildRootNode() {
  return base::MakeUnique<CertErrorNode>(CertErrorNodeType::TYPE_CONTEXT, id_,
                                         nullptr);
}

}  // namespace net
