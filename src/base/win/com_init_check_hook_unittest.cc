// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/win/com_init_check_hook.h"

#include <objbase.h>
#include <shlobj.h>
#include <wrl/client.h>

#include "base/test/gtest_util.h"
#include "base/win/com_init_util.h"
#include "base/win/scoped_com_initializer.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace win {

using Microsoft::WRL::ComPtr;

TEST(ComInitCheckHook, AssertNotInitialized) {
  ComInitCheckHook com_check_hook;
  AssertComApartmentType(ComApartmentType::NONE);
  ComPtr<IUnknown> shell_link;
#if COM_INIT_CHECK_HOOK_ENABLED()
  EXPECT_DCHECK_DEATH(::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_ALL,
                                         IID_PPV_ARGS(&shell_link)));
#else
  EXPECT_EQ(CO_E_NOTINITIALIZED,
            ::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_ALL,
                               IID_PPV_ARGS(&shell_link)));
#endif
}

TEST(ComInitCheckHook, HookRemoval) {
  AssertComApartmentType(ComApartmentType::NONE);
  { ComInitCheckHook com_check_hook; }
  ComPtr<IUnknown> shell_link;
  EXPECT_EQ(CO_E_NOTINITIALIZED,
            ::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_ALL,
                               IID_PPV_ARGS(&shell_link)));
}

TEST(ComInitCheckHook, NoAssertComInitialized) {
  ComInitCheckHook com_check_hook;
  ScopedCOMInitializer com_initializer;
  ComPtr<IUnknown> shell_link;
  EXPECT_TRUE(SUCCEEDED(::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_ALL,
                                           IID_PPV_ARGS(&shell_link))));
}

TEST(ComInitCheckHook, MultipleHooks) {
  ComInitCheckHook com_check_hook_1;
  ComInitCheckHook com_check_hook_2;
  AssertComApartmentType(ComApartmentType::NONE);
  ComPtr<IUnknown> shell_link;
#if COM_INIT_CHECK_HOOK_ENABLED()
  EXPECT_DCHECK_DEATH(::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_ALL,
                                         IID_PPV_ARGS(&shell_link)));
#else
  EXPECT_EQ(CO_E_NOTINITIALIZED,
            ::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_ALL,
                               IID_PPV_ARGS(&shell_link)));
#endif
}

}  // namespace win
}  // namespace base
