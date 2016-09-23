// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "persistent_no_trace.h"

namespace blink {

void HeapObject::trace(Visitor* visitor) {
    visitor->trace(m_crossThreadPersistent);
    visitor->trace(m_crossThreadWeakPersistent);
}

}
