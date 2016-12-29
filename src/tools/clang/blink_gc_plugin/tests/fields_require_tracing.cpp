// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fields_require_tracing.h"

namespace blink {

void PartObject::Trace(Visitor* visitor) {
    m_obj1->Trace(visitor); // Don't allow direct tracing.
    visitor->Trace(m_obj2);
    // Missing visitor->Trace(m_obj3);
    visitor->Trace(m_parts);
}

void PartBObject::Trace(Visitor* visitor) {
  // Missing visitor->Trace(m_set);
  visitor->Trace(m_vector);
}

void HeapObject::Trace(Visitor* visitor) {
    // Missing visitor->Trace(m_part);
    visitor->Trace(m_obj);
}

}
