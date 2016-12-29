// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_BLINK_GC_PLUGIN_CHECK_FIELDS_VISITOR_H_
#define TOOLS_BLINK_GC_PLUGIN_CHECK_FIELDS_VISITOR_H_

#include <vector>

#include "Edge.h"

class FieldPoint;

// This visitor checks that the fields of a class are "well formed".
// - OwnPtr and RefPtr must not point to a GC derived type.
// - Part objects must not be a GC derived type.
// - An on-heap class must never contain GC roots.
// - Only stack-allocated types may point to stack-allocated types.

class CheckFieldsVisitor : public RecursiveEdgeVisitor {
 public:
  enum Error {
    kRawPtrToGCManaged,
    kRefPtrToGCManaged,
    kReferencePtrToGCManaged,
    kOwnPtrToGCManaged,
    kUniquePtrToGCManaged,
    kMemberToGCUnmanaged,
    kMemberInUnmanaged,
    kPtrFromHeapToStack,
    kGCDerivedPartObject,
    kIteratorToGCManaged,
  };

  using Errors = std::vector<std::pair<FieldPoint*, Error>>;

  CheckFieldsVisitor();

  Errors& invalid_fields();

  bool ContainsInvalidFields(RecordInfo* info);

  void AtMember(Member* edge) override;
  void AtValue(Value* edge) override;
  void AtCollection(Collection* edge) override;
  void AtIterator(Iterator*) override;

 private:
  Error InvalidSmartPtr(Edge* ptr);

  FieldPoint* current_;
  bool stack_allocated_host_;
  bool managed_host_;
  Errors invalid_fields_;
};

#endif  // TOOLS_BLINK_GC_PLUGIN_CHECK_FIELDS_VISITOR_H_
