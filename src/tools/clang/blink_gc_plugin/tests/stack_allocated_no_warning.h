// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef STACK_ALLOCATED_H_
#define STACK_ALLOCATED_H_

#include "heap/stubs.h"

namespace blink {

class HeapObject;

class StackObject {
    STACK_ALLOCATED();

    // Redundant trace() method, but warning/error disabled.
    void Trace(Visitor* visitor) { visitor->Trace(m_obj); }

private:
    Member<HeapObject> m_obj; // Does not need tracing.
};

}

#endif
