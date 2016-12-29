// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ignore_class.h"

namespace blink {

void B::Trace(Visitor* visitor)
{
    // Class is ignored so no checking here.
}

void C::Trace(Visitor* visitor)
{
    // Missing Trace of m_obj.
    // Ignored base class B does not need tracing.
}

}
