// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/win/scoped_comptr.h"

#include <objbase.h>
#include <shlobj.h>

#include <memory>

#include "base/win/scoped_com_initializer.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace win {

namespace {

struct Dummy {
  Dummy() : adds(0), releases(0) { }
  unsigned long AddRef() { return ++adds; }
  unsigned long Release() { return ++releases; }

  int adds;
  int releases;
};

}  // namespace

TEST(ScopedComPtrTest, ScopedComPtr) {
  base::win::ScopedCOMInitializer com_initializer;
  EXPECT_TRUE(com_initializer.succeeded());

  ScopedComPtr<IUnknown> unk;
  EXPECT_TRUE(SUCCEEDED(::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_ALL,
                                           IID_PPV_ARGS(&unk))));
  ScopedComPtr<IUnknown> unk2;
  unk2.Attach(unk.Detach());
  EXPECT_TRUE(unk.Get() == NULL);
  EXPECT_TRUE(unk2.Get() != NULL);

  ScopedComPtr<IMalloc> mem_alloc;
  EXPECT_TRUE(SUCCEEDED(CoGetMalloc(1, mem_alloc.GetAddressOf())));

  ScopedComPtr<IUnknown> qi_test;
  EXPECT_HRESULT_SUCCEEDED(mem_alloc.CopyTo(IID_PPV_ARGS(&qi_test)));
  EXPECT_TRUE(qi_test.Get() != NULL);
}

TEST(ScopedComPtrTest, ScopedComPtrVector) {
  // Verify we don't get error C2558.
  typedef ScopedComPtr<Dummy> Ptr;
  std::vector<Ptr> bleh;

  std::unique_ptr<Dummy> p(new Dummy);
  {
    Ptr p2(p.get());
    EXPECT_EQ(p->adds, 1);
    EXPECT_EQ(p->releases, 0);
    Ptr p3 = p2;
    EXPECT_EQ(p->adds, 2);
    EXPECT_EQ(p->releases, 0);
    p3 = p2;
    EXPECT_EQ(p->adds, 3);
    EXPECT_EQ(p->releases, 1);
    // To avoid hitting a reallocation.
    bleh.reserve(1);
    bleh.push_back(p2);
    EXPECT_EQ(p->adds, 4);
    EXPECT_EQ(p->releases, 1);
    EXPECT_EQ(bleh[0].Get(), p.get());
    bleh.pop_back();
    EXPECT_EQ(p->adds, 4);
    EXPECT_EQ(p->releases, 2);
  }
  EXPECT_EQ(p->adds, 4);
  EXPECT_EQ(p->releases, 4);
}

}  // namespace win
}  // namespace base
