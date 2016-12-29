// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "traceimpl.h"

namespace blink {

void TraceImplExtern::Trace(Visitor* visitor) {
  TraceImpl(visitor);
}

template <typename VisitorDispatcher>
inline void TraceImplExtern::TraceImpl(VisitorDispatcher visitor) {
  visitor->Trace(x_);
}

void TraceImplBaseExtern::Trace(Visitor* visitor) {
  TraceImpl(visitor);
}

template <typename VisitorDispatcher>
inline void TraceImplBaseExtern::TraceImpl(VisitorDispatcher visitor) {
  visitor->Trace(x_);
  Base::Trace(visitor);
}

}
