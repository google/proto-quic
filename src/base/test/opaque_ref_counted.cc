// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/opaque_ref_counted.h"

#include "base/macros.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

class OpaqueRefCounted : public RefCounted<OpaqueRefCounted> {
 public:
  OpaqueRefCounted() = default;

  int Return42() { return 42; }

 private:
  friend class RefCounted<OpaqueRefCounted>;
  ~OpaqueRefCounted() = default;

  DISALLOW_COPY_AND_ASSIGN(OpaqueRefCounted);
};

class OpaqueRefCountedThreadSafe
    : public RefCounted<OpaqueRefCountedThreadSafe> {
 public:
  OpaqueRefCountedThreadSafe() = default;

  int Return42() { return 42; }

 private:
  friend class RefCounted<OpaqueRefCountedThreadSafe>;
  ~OpaqueRefCountedThreadSafe() = default;

  DISALLOW_COPY_AND_ASSIGN(OpaqueRefCountedThreadSafe);
};

scoped_refptr<OpaqueRefCounted> MakeOpaqueRefCounted() {
  return new OpaqueRefCounted();
}

void TestOpaqueRefCounted(scoped_refptr<OpaqueRefCounted> p) {
  EXPECT_EQ(42, p->Return42());
}

scoped_refptr<OpaqueRefCountedThreadSafe> MakeOpaqueRefCountedThreadSafe() {
  return new OpaqueRefCountedThreadSafe();
}

void TestOpaqueRefCountedThreadSafe(
    scoped_refptr<OpaqueRefCountedThreadSafe> p) {
  EXPECT_EQ(42, p->Return42());
}

}  // namespace base

template class scoped_refptr<base::OpaqueRefCounted>;
template class scoped_refptr<base::OpaqueRefCountedThreadSafe>;
