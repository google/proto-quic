// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef REGISTER_WEAK_MEMBERS_TEMPLATE_H_
#define REGISTER_WEAK_MEMBERS_TEMPLATE_H_

#include "heap/stubs.h"

namespace blink {

class X : public GarbageCollected<X> {
 public:
  void trace(Visitor*) {}
};

class HasUntracedWeakMembers : public GarbageCollected<HasUntracedWeakMembers> {
 public:
  void trace(Visitor* visitor) {
    visitor->registerWeakMembers<HasUntracedWeakMembers,
                                 &HasUntracedWeakMembers::clearWeakMembers>(
        this);
  }

  void clearWeakMembers(Visitor* visitor);

 private:
  WeakMember<X> x_;
};

}

#endif  // REGISTER_WEAK_MEMBERS_TEMPLATE_H_
