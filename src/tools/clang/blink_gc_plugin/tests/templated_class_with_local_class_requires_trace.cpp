// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "templated_class_with_local_class_requires_trace.h"

namespace blink {

template<typename T>
void TemplatedObject<T>::Trace(Visitor* visitor)
{
    visitor->Trace(m_local);
    visitor->Trace(m_memberRef);
}

class Test {
public:
    static void test()
    {
        HeapObject* obj = new HeapObject();
        TemplatedObject<HeapObject>* instance =
            new TemplatedObject<HeapObject>(obj);
    }
};

} // namespace blink
