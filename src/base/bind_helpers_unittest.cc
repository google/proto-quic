// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/bind_helpers.h"

#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

TEST(BindHelpersTest, UnwrapUnretained) {
  int i = 0;
  auto unretained = Unretained(&i);
  EXPECT_EQ(&i, internal::Unwrap(unretained));
  EXPECT_EQ(&i, internal::Unwrap(std::move(unretained)));
}

TEST(BindHelpersTest, UnwrapConstRef) {
  int p = 0;
  auto const_ref = ConstRef(p);
  EXPECT_EQ(&p, &internal::Unwrap(const_ref));
  EXPECT_EQ(&p, &internal::Unwrap(std::move(const_ref)));
}

TEST(BindHelpersTest, UnwrapRetainedRef) {
  auto p = make_scoped_refptr(new RefCountedData<int>);
  auto retained_ref = RetainedRef(p);
  EXPECT_EQ(p.get(), internal::Unwrap(retained_ref));
  EXPECT_EQ(p.get(), internal::Unwrap(std::move(retained_ref)));
}

TEST(BindHelpersTest, UnwrapOwned) {
  int* p = new int;
  auto owned = Owned(p);
  EXPECT_EQ(p, internal::Unwrap(owned));
  EXPECT_EQ(p, internal::Unwrap(std::move(owned)));
}

TEST(BindHelpersTest, UnwrapPassed) {
  int* p = new int;
  auto passed = Passed(WrapUnique(p));
  EXPECT_EQ(p, internal::Unwrap(passed).get());

  p = new int;
  EXPECT_EQ(p, internal::Unwrap(Passed(WrapUnique(p))).get());
}

}  // namespace base
