// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRACEIMPL_OVERLOADED_H_
#define TRACEIMPL_OVERLOADED_H_

#include "heap/stubs.h"

namespace blink {

class X : public GarbageCollected<X> {
 public:
  void Trace(Visitor*) {}
  void Trace(InlinedGlobalMarkingVisitor) {}
};

class InlinedBase : public GarbageCollected<InlinedBase> {
 public:
  virtual void Trace(Visitor* visitor) { TraceImpl(visitor); }
  virtual void Trace(InlinedGlobalMarkingVisitor visitor) {
    TraceImpl(visitor);
  }

 private:
  template <typename VisitorDispatcher>
  void TraceImpl(VisitorDispatcher visitor) { visitor->Trace(x_base_); }

  Member<X> x_base_;
};

class InlinedDerived : public InlinedBase {
 public:
  void Trace(Visitor* visitor) override { TraceImpl(visitor); }
  void Trace(InlinedGlobalMarkingVisitor visitor) override {
    TraceImpl(visitor);
  }

 private:
  template <typename VisitorDispatcher>
  void TraceImpl(VisitorDispatcher visitor) {
    visitor->Trace(x_derived_);
    InlinedBase::Trace(visitor);
  }

  Member<X> x_derived_;
};

class ExternBase : public GarbageCollected<ExternBase> {
 public:
  virtual void Trace(Visitor*);
  virtual void Trace(InlinedGlobalMarkingVisitor);

 private:
  template <typename VisitorDispatcher>
  void TraceImpl(VisitorDispatcher);

  Member<X> x_base_;
};

class ExternDerived : public ExternBase {
 public:
  void Trace(Visitor*) override;
  void Trace(InlinedGlobalMarkingVisitor) override;

 private:
  template <typename VisitorDispatcher>
  void TraceImpl(VisitorDispatcher);

  Member<X> x_derived_;
};

}

#endif  // TRACEIMPL_OVERLOADED_H_
