// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "polymorphic_class_with_non_virtual_trace.h"

namespace blink {

void IsLeftMostPolymorphic::Trace(Visitor* visitor)
{
    visitor->Trace(m_obj);
}

void IsNotLeftMostPolymorphic::Trace(Visitor* visitor)
{
    visitor->Trace(m_obj);
}

}
