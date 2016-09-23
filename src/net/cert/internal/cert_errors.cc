// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/cert_errors.h"

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string_split.h"
#include "net/cert/internal/cert_error_params.h"
#include "net/cert/internal/cert_error_scoper.h"

namespace net {

namespace {

// Helpers for pretty-printing CertErrors to a string.
void AppendNodeToDebugString(CertErrorNode* node,
                             const std::string& indentation,
                             std::string* out);

void AppendChildrenToDebugString(const CertErrorNodes& children,
                                 const std::string& indentation,
                                 std::string* out) {
  for (const auto& child : children)
    AppendNodeToDebugString(child.get(), indentation, out);
}

void AppendLinesWithIndentation(const std::string& text,
                                const std::string& indentation,
                                std::string* out) {
  std::vector<base::StringPiece> lines = base::SplitStringPieceUsingSubstr(
      text, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

  for (const auto& line : lines) {
    *out += indentation;
    line.AppendToString(out);
    *out += "\n";
  }
}

const char* CertErrorNodeTypeToString(CertErrorNodeType type) {
  switch (type) {
    case CertErrorNodeType::TYPE_CONTEXT:
      return "[Context] ";
    case CertErrorNodeType::TYPE_WARNING:
      return "[Warning] ";
    case CertErrorNodeType::TYPE_ERROR:
      return "[Error] ";
  }
  return nullptr;
}

void AppendNodeToDebugString(CertErrorNode* node,
                             const std::string& indentation,
                             std::string* out) {
  std::string cur_indentation = indentation;

  *out += cur_indentation;
  *out += CertErrorNodeTypeToString(node->node_type);
  *out += CertErrorIdToDebugString(node->id);
  *out += +"\n";

  if (node->params) {
    cur_indentation += "  ";
    AppendLinesWithIndentation(node->params->ToDebugString(), cur_indentation,
                               out);
  }

  cur_indentation += "    ";

  AppendChildrenToDebugString(node->children, cur_indentation, out);
}

}  // namespace

CertErrorNode::CertErrorNode(CertErrorNodeType node_type,
                             CertErrorId id,
                             std::unique_ptr<CertErrorParams> params)
    : node_type(node_type), id(id), params(std::move(params)) {}

CertErrorNode::~CertErrorNode() = default;

void CertErrorNode::AddChild(std::unique_ptr<CertErrorNode> child) {
  DCHECK_EQ(CertErrorNodeType::TYPE_CONTEXT, node_type);
  children.push_back(std::move(child));
}

CertErrors::CertErrors() = default;

CertErrors::~CertErrors() = default;

void CertErrors::Add(CertErrorNodeType node_type,
                     CertErrorId id,
                     std::unique_ptr<CertErrorParams> params) {
  AddNode(base::MakeUnique<CertErrorNode>(node_type, id, std::move(params)));
}

void CertErrors::AddError(CertErrorId id,
                          std::unique_ptr<CertErrorParams> params) {
  Add(CertErrorNodeType::TYPE_ERROR, id, std::move(params));
}

void CertErrors::AddError(CertErrorId id) {
  AddError(id, nullptr);
}

void CertErrors::AddWarning(CertErrorId id,
                            std::unique_ptr<CertErrorParams> params) {
  Add(CertErrorNodeType::TYPE_WARNING, id, std::move(params));
}

void CertErrors::AddWarning(CertErrorId id) {
  AddWarning(id, nullptr);
}

bool CertErrors::empty() const {
  return nodes_.empty();
}

std::string CertErrors::ToDebugString() const {
  std::string result;
  AppendChildrenToDebugString(nodes_, std::string(), &result);
  return result;
}

void CertErrors::AddNode(std::unique_ptr<CertErrorNode> node) {
  if (current_scoper_)
    current_scoper_->LazyGetRootNode()->AddChild(std::move(node));
  else
    nodes_.push_back(std::move(node));
}

CertErrorScoper* CertErrors::SetScoper(CertErrorScoper* scoper) {
  CertErrorScoper* prev = current_scoper_;
  current_scoper_ = scoper;
  return prev;
}

}  // namespace net
