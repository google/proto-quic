// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trace_after_dispatch_impl.h"

namespace blink {

template <typename VisitorDispatcher>
inline void TraceAfterDispatchInlinedBase::TraceImpl(
    VisitorDispatcher visitor) {
  // Implement a simple form of manual dispatching, because BlinkGCPlugin
  // checks if the tracing is dispatched to all derived classes.
  //
  // This function has to be implemented out-of-line, since we need to know the
  // definition of derived classes here.
  if (tag_ == DERIVED) {
    static_cast<TraceAfterDispatchInlinedDerived*>(this)->TraceAfterDispatch(
        visitor);
  } else {
    TraceAfterDispatch(visitor);
  }
}

void TraceAfterDispatchExternBase::Trace(Visitor* visitor) {
  TraceImpl(visitor);
}

void TraceAfterDispatchExternBase::Trace(InlinedGlobalMarkingVisitor visitor) {
  TraceImpl(visitor);
}

template <typename VisitorDispatcher>
inline void TraceAfterDispatchExternBase::TraceImpl(VisitorDispatcher visitor) {
  if (tag_ == DERIVED) {
    static_cast<TraceAfterDispatchExternDerived*>(this)->TraceAfterDispatch(
        visitor);
  } else {
    TraceAfterDispatch(visitor);
  }
}

void TraceAfterDispatchExternBase::TraceAfterDispatch(Visitor* visitor) {
  TraceAfterDispatchImpl(visitor);
}

void TraceAfterDispatchExternBase::TraceAfterDispatch(
    InlinedGlobalMarkingVisitor visitor) {
  TraceAfterDispatchImpl(visitor);
}

template <typename VisitorDispatcher>
inline void TraceAfterDispatchExternBase::TraceAfterDispatchImpl(
    VisitorDispatcher visitor) {
  visitor->Trace(x_base_);
}

void TraceAfterDispatchExternDerived::TraceAfterDispatch(Visitor* visitor) {
  TraceAfterDispatchImpl(visitor);
}

void TraceAfterDispatchExternDerived::TraceAfterDispatch(
    InlinedGlobalMarkingVisitor visitor) {
  TraceAfterDispatchImpl(visitor);
}

template <typename VisitorDispatcher>
inline void TraceAfterDispatchExternDerived::TraceAfterDispatchImpl(
    VisitorDispatcher visitor) {
  visitor->Trace(x_derived_);
  TraceAfterDispatchExternBase::TraceAfterDispatch(visitor);
}

}
