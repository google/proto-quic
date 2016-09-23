// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FIELDS_ILLEGAL_TRACING_H_
#define FIELDS_ILLEGAL_TRACING_H_

#include "heap/stubs.h"

namespace blink {

namespace bar {

// check that (only) std::unique_ptr<> is reported
// as an illegal smart pointer type.
template<typename T> class unique_ptr {
public:
    ~unique_ptr() { }
    operator T*() const { return 0; }
    T* operator->() { return 0; }

    void trace(Visitor* visitor)
    {
    }
};

}

class HeapObject;
class PartObject;

class PartObject {
    DISALLOW_NEW();
public:
    void trace(Visitor*);
private:
    OwnPtr<HeapObject> m_obj1;
    RefPtr<HeapObject> m_obj2;
    bar::unique_ptr<HeapObject> m_obj3;
    std::unique_ptr<HeapObject> m_obj4;
};

class HeapObject : public GarbageCollectedFinalized<HeapObject> {
public:
    void trace(Visitor*);
private:
    PartObject m_part;
    OwnPtr<HeapObject> m_obj1;
    RefPtr<HeapObject> m_obj2;
    bar::unique_ptr<HeapObject> m_obj3;
    std::unique_ptr<HeapObject> m_obj4;
};

}

#endif
