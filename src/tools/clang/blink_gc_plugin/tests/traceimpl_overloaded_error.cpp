// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "traceimpl_overloaded_error.h"

namespace blink {

void ExternBase::Trace(Visitor* visitor) {
  TraceImpl(visitor);
}

void ExternBase::Trace(InlinedGlobalMarkingVisitor visitor) {
  TraceImpl(visitor);
}

template <typename VisitorDispatcher>
inline void ExternBase::TraceImpl(VisitorDispatcher visitor) {
  // Missing visitor->Trace(x_base_).
}

void ExternDerived::Trace(Visitor* visitor) {
  TraceImpl(visitor);
}

void ExternDerived::Trace(InlinedGlobalMarkingVisitor visitor) {
  TraceImpl(visitor);
}

template <typename VisitorDispatcher>
inline void ExternDerived::TraceImpl(VisitorDispatcher visitor) {
  // Missing visitor->Trace(x_derived_) and ExternBase::Trace(visitor).
}

}
