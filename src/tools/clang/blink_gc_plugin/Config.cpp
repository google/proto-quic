// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "Config.h"

#include <cassert>

#include "clang/AST/AST.h"

using namespace clang;

// Legacy names to be removed after Blink rename:
namespace legacy {
const char kCreateName[] = "create";
const char kTraceName[] = "trace";
const char kFinalizeName[] = "finalizeGarbageCollectedObject";
const char kTraceAfterDispatchName[] = "traceAfterDispatch";
const char kRegisterWeakMembersName[] = "registerWeakMembers";
const char kAdjustAndMarkName[] = "adjustAndMark";
const char kIsHeapObjectAliveName[] = "isHeapObjectAlive";
}  // namespace legacy

const char kNewOperatorName[] = "operator new";
const char* kCreateName = "Create";
const char* kTraceName = "Trace";
const char* kFinalizeName = "FinalizeGarbageCollectedObject";
const char* kTraceAfterDispatchName = "TraceAfterDispatch";
const char* kRegisterWeakMembersName = "RegisterWeakMembers";
const char kHeapAllocatorName[] = "HeapAllocator";
const char kTraceIfNeededName[] = "TraceIfNeeded";
const char kVisitorDispatcherName[] = "VisitorDispatcher";
const char kVisitorVarName[] = "visitor";
const char* kAdjustAndMarkName = "AdjustAndMark";
const char* kIsHeapObjectAliveName = "IsHeapObjectAlive";
const char kIsEagerlyFinalizedName[] = "IsEagerlyFinalizedMarker";
const char kConstIteratorName[] = "const_iterator";
const char kIteratorName[] = "iterator";
const char kConstReverseIteratorName[] = "const_reverse_iterator";
const char kReverseIteratorName[] = "reverse_iterator";

void Config::UseLegacyNames() {
  kCreateName = legacy::kCreateName;
  kTraceName = legacy::kTraceName;
  kFinalizeName = legacy::kFinalizeName;
  kTraceAfterDispatchName = legacy::kTraceAfterDispatchName;
  kRegisterWeakMembersName = legacy::kRegisterWeakMembersName;
  kAdjustAndMarkName = legacy::kAdjustAndMarkName;
  kIsHeapObjectAliveName = legacy::kIsHeapObjectAliveName;
}

bool Config::IsTemplateInstantiation(CXXRecordDecl* record) {
  ClassTemplateSpecializationDecl* spec =
      dyn_cast<clang::ClassTemplateSpecializationDecl>(record);
  if (!spec)
    return false;
  switch (spec->getTemplateSpecializationKind()) {
    case TSK_ImplicitInstantiation:
    case TSK_ExplicitInstantiationDefinition:
      return true;
    case TSK_Undeclared:
    case TSK_ExplicitSpecialization:
      return false;
    // TODO: unsupported cases.
    case TSK_ExplicitInstantiationDeclaration:
      return false;
  }
  assert(false && "Unknown template specialization kind");
  return false;
}
