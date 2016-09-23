// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fields_illegal_tracing.h"

namespace blink {

void PartObject::trace(Visitor* visitor) {
    visitor->trace(m_obj1);
    visitor->trace(m_obj2);
    visitor->trace(m_obj3);
    visitor->trace(m_obj4);
}

void HeapObject::trace(Visitor* visitor) {
    visitor->trace(m_obj1);
    visitor->trace(m_obj2);
    visitor->trace(m_obj3);
    visitor->trace(m_obj4);
}

}
