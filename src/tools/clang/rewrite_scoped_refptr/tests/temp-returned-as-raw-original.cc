// Copyright (c) 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "scoped_refptr.h"

struct Foo {
  int dummy;
};

class Bar {
  Foo* TestFunction();
};

scoped_refptr<Foo> CreateFoo();

// An example of an unsafe conversion--the scoped_refptr will be destroyed by
// the time function returns, since it's a temporary, so the returned raw
// pointer may point to a deleted object.
Foo* Bar::TestFunction() {
  return CreateFoo();
}
