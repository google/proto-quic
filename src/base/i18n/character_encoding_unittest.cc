// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/i18n/character_encoding.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace base {

TEST(CharacterEncodingTest, GetCanonicalEncodingNameByAliasName) {
  EXPECT_STREQ("Big5", GetCanonicalEncodingNameByAliasName("Big5"));
  EXPECT_STREQ("windows-874",
               GetCanonicalEncodingNameByAliasName("windows-874"));
  EXPECT_STREQ("ISO-8859-8", GetCanonicalEncodingNameByAliasName("ISO-8859-8"));

  // Non-canonical alias names should be converted to a canonical one.
  EXPECT_STREQ("UTF-8", GetCanonicalEncodingNameByAliasName("utf8"));
  EXPECT_STREQ("gb18030", GetCanonicalEncodingNameByAliasName("GB18030"));
  EXPECT_STREQ("windows-874", GetCanonicalEncodingNameByAliasName("tis-620"));
  EXPECT_STREQ("EUC-KR", GetCanonicalEncodingNameByAliasName("ks_c_5601-1987"));
}

}  // namespace base
