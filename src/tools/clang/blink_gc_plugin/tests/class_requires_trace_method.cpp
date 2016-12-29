// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "class_requires_trace_method.h"

namespace blink {

void Mixin2::Trace(Visitor* visitor)
{
  Mixin::Trace(visitor);
}

void Mixin3::Trace(Visitor* visitor)
{
  Mixin::Trace(visitor);
}

} // namespace blink
