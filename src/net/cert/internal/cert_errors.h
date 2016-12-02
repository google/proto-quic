// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// ----------------------------
// Overview of error design
// ----------------------------
//
// Certificate path validation/parsing may emit a sequence of
// errors/warnings/context. These are represented by a tree of CertErrorNodes.
// Each node is comprised of:
//
//   * A unique identifier.
//
//     This serves similarly to an error code, and is useful for querying if a
//     particular error occurred.
//
//   * [optional] A parameters object.
//
//     Nodes may attach a heap-allocated subclass of CertErrorParams, to carry
//     extra information that is useful when reporting the error. For instance
//     a parsing error may want to describe where in the DER the failure
//     happened, or what the unexpected value was.
//
//   * [optional] Child nodes.
//
//     Error nodes are arranged in a tree. The parent/child hierarchy is used to
//     group errors that share some common state.
//     For instance during path processing it is useful to group the
//     errors/warnings that happened while processing certificate "i" as
//     children of a shared "context" node. The context node in this case
//     doesn't describe a particular error, but rather some shared event and
//     its parameters.
//
// ----------------------------
// Using errors in other APIs
// ----------------------------
//
// The top level object used in APIs is CertErrors. A pointer to a CertErrors
// object is typically given as an out-parameter for code that may generate
// errors.
//
// Note that CertErrors gives a non-hiearhical interface for emitting errors.
// In other words, it doesn't let you create parent/child relationships
// directly.
//
// To change the parent node for subsequently emitted errors in the CertErrors
// object, one constructs a CertErrorScoper on the stack.
//
// ----------------------------
// Defining new errors
// ----------------------------
//
// The error IDs are extensible and do not need to be centrally defined.
//
// To define a new error use the macro DEFINE_CERT_ERROR_ID() in a .cc file.
// If consumers are to be able to query for this error then the symbol should
// also be exposed in a header file.
//
// Error IDs are in truth string literals, whose pointer value will be unique
// per process.

#ifndef NET_CERT_INTERNAL_CERT_ERRORS_H_
#define NET_CERT_INTERNAL_CERT_ERRORS_H_

#include <memory>
#include <vector>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/cert/internal/cert_error_id.h"

namespace net {

class CertErrorParams;
class CertErrorScoper;

// The type of a particular CertErrorNode.
enum class CertErrorNodeType {
  // Note the TYPE_ prefix is to avoid compile errors. Because ERROR() is a
  // commonly used macro name.

  // Node that represents a single error.
  TYPE_ERROR,

  // Node that represents a single non-fatal error.
  TYPE_WARNING,

  // Parent node for other errors/warnings.
  TYPE_CONTEXT,
};

struct CertErrorNode;
using CertErrorNodes = std::vector<std::unique_ptr<CertErrorNode>>;

// CertErrorNode represents a node in the error tree. This could be an error,
// warning, or simply contextual parent node. See the error design overview for
// a better description of how this is used.
struct NET_EXPORT CertErrorNode {
  CertErrorNode(CertErrorNodeType node_type,
                CertErrorId id,
                std::unique_ptr<CertErrorParams> params);
  ~CertErrorNode();

  void AddChild(std::unique_ptr<CertErrorNode> child);

  CertErrorNodeType node_type;
  CertErrorId id;
  std::unique_ptr<CertErrorParams> params;
  CertErrorNodes children;
};

// CertErrors is the main object for emitting errors and internally builds up
// the error tree.
class NET_EXPORT CertErrors {
 public:
  CertErrors();
  ~CertErrors();

  // Adds a node to the current insertion point in the error tree. |params| may
  // be null.
  void Add(CertErrorNodeType node_type,
           CertErrorId id,
           std::unique_ptr<CertErrorParams> params);

  void AddError(CertErrorId id, std::unique_ptr<CertErrorParams> params);
  void AddError(CertErrorId id);

  void AddWarning(CertErrorId id, std::unique_ptr<CertErrorParams> params);
  void AddWarning(CertErrorId id);

  // Returns true if the tree is empty. Note that emptiness of the error tree
  // is NOT equivalent to success for some call, and vice versa. (For instance
  // consumers may forget to emit errors on failures, or some errors may be
  // non-fatal warnings).
  bool empty() const;

  // Dumps a textual representation of the errors for debugging purposes.
  std::string ToDebugString() const;

 private:
  // CertErrorScoper manipulates the CertErrors object.
  friend class CertErrorScoper;

  void AddNode(std::unique_ptr<CertErrorNode> node);

  // Used by CertErrorScoper to register itself as the top-level scoper.
  // Returns the previously set scoper, or nullptr if there was none.
  CertErrorScoper* SetScoper(CertErrorScoper* scoper);

  CertErrorNodes nodes_;

  // The top-most CertErrorScoper that is currently in scope (and which affects
  // the parent node for newly added errors).
  CertErrorScoper* current_scoper_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(CertErrors);
};

}  // namespace net

#endif  // NET_CERT_INTERNAL_CERT_ERRORS_H_
