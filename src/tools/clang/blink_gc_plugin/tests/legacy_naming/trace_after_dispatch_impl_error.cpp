// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trace_after_dispatch_impl_error.h"

namespace blink {

inline void TraceAfterDispatchInlinedBase::trace(Visitor* visitor) {
  // Implement a simple form of manual dispatching, because BlinkGCPlugin
  // checks if the tracing is dispatched to all derived classes.
  //
  // This function has to be implemented out-of-line, since we need to know the
  // definition of derived classes here.
  if (tag_ == DERIVED) {
    // Missing dispatch call:
    // static_cast<TraceAfterDispatchInlinedDerived*>(this)->traceAfterDispatch(
    //     visitor);
  } else {
    traceAfterDispatch(visitor);
  }
}

void TraceAfterDispatchExternBase::trace(Visitor* visitor) {
  if (tag_ == DERIVED) {
    // Missing dispatch call:
    // static_cast<TraceAfterDispatchExternDerived*>(this)->traceAfterDispatch(
    //     visitor);
  } else {
    traceAfterDispatch(visitor);
  }
}

void TraceAfterDispatchExternBase::traceAfterDispatch(Visitor* visitor) {
  // No trace call.
}

void TraceAfterDispatchExternDerived::traceAfterDispatch(Visitor* visitor) {
  // Ditto.
}

}
