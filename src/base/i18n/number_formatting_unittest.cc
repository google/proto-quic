// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <limits>

#include "base/i18n/number_formatting.h"
#include "base/i18n/rtl.h"
#include "base/macros.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/icu_test_util.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/icu/source/i18n/unicode/usearch.h"

namespace base {
namespace {

TEST(NumberFormattingTest, FormatNumber) {
  static const struct {
    int64_t number;
    const char* expected_english;
    const char* expected_german;
  } cases[] = {
    {0, "0", "0"},
    {1024, "1,024", "1.024"},
    {std::numeric_limits<int64_t>::max(),
        "9,223,372,036,854,775,807", "9.223.372.036.854.775.807"},
    {std::numeric_limits<int64_t>::min(),
        "-9,223,372,036,854,775,808", "-9.223.372.036.854.775.808"},
    {-42, "-42", "-42"},
  };

  test::ScopedRestoreICUDefaultLocale restore_locale;

  for (size_t i = 0; i < arraysize(cases); ++i) {
    i18n::SetICUDefaultLocale("en");
    testing::ResetFormatters();
    EXPECT_EQ(cases[i].expected_english,
              UTF16ToUTF8(FormatNumber(cases[i].number)));
    i18n::SetICUDefaultLocale("de");
    testing::ResetFormatters();
    EXPECT_EQ(cases[i].expected_german,
              UTF16ToUTF8(FormatNumber(cases[i].number)));
  }
}

TEST(NumberFormattingTest, FormatDouble) {
  static const struct {
    double number;
    int frac_digits;
    const char* expected_english;
    const char* expected_german;
  } cases[] = {
    {0.0, 0, "0", "0"},
#if !defined(OS_ANDROID)
    // Bionic can't printf negative zero correctly.
    {-0.0, 4, "-0.0000", "-0,0000"},
#endif
    {1024.2, 0, "1,024", "1.024"},
    {-1024.223, 2, "-1,024.22", "-1.024,22"},
    {std::numeric_limits<double>::max(), 6,
        "179,769,313,486,232,000,000,000,000,000,000,000,000,000,000,000,000,"
        "000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,"
        "000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,"
        "000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,"
        "000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,"
        "000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,"
        "000.000000",
        "179.769.313.486.232.000.000.000.000.000.000.000.000.000.000.000.000."
        "000.000.000.000.000.000.000.000.000.000.000.000.000.000.000.000.000."
        "000.000.000.000.000.000.000.000.000.000.000.000.000.000.000.000.000."
        "000.000.000.000.000.000.000.000.000.000.000.000.000.000.000.000.000."
        "000.000.000.000.000.000.000.000.000.000.000.000.000.000.000.000.000."
        "000.000.000.000.000.000.000.000.000.000.000.000.000.000.000.000.000."
        "000,000000"},
    {std::numeric_limits<double>::min(), 2, "0.00", "0,00"},
    {-42.7, 3, "-42.700", "-42,700"},
  };

  test::ScopedRestoreICUDefaultLocale restore_locale;
  for (size_t i = 0; i < arraysize(cases); ++i) {
    i18n::SetICUDefaultLocale("en");
    testing::ResetFormatters();
    EXPECT_EQ(cases[i].expected_english,
              UTF16ToUTF8(FormatDouble(cases[i].number, cases[i].frac_digits)));
    i18n::SetICUDefaultLocale("de");
    testing::ResetFormatters();
    EXPECT_EQ(cases[i].expected_german,
              UTF16ToUTF8(FormatDouble(cases[i].number, cases[i].frac_digits)));
  }
}

TEST(NumberFormattingTest, FormatPercent) {
  static const struct {
    int64_t number;
    const char* expected_english;
    const wchar_t* expected_german;   // Note: Space before % isn't \x20.
    const wchar_t* expected_persian;  // Note: Non-Arabic numbers and %.
  } cases[] = {
    {0, "0%", L"0\xa0%", L"\x6f0\x200f\x66a"},
    {42, "42%", L"42\xa0%", L"\x6f4\x6f2\x200f\x66a"},
    {1024, "1,024%", L"1.024\xa0%", L"\x6f1\x66c\x6f0\x6f2\x6f4\x200f\x66a"},
  };

  test::ScopedRestoreICUDefaultLocale restore_locale;
  for (size_t i = 0; i < arraysize(cases); ++i) {
    i18n::SetICUDefaultLocale("en");
    EXPECT_EQ(ASCIIToUTF16(cases[i].expected_english),
              FormatPercent(cases[i].number));
    i18n::SetICUDefaultLocale("de");
    EXPECT_EQ(WideToUTF16(cases[i].expected_german),
              FormatPercent(cases[i].number));
    i18n::SetICUDefaultLocale("fa");
    EXPECT_EQ(WideToUTF16(cases[i].expected_persian),
              FormatPercent(cases[i].number));
  }
}

}  // namespace
}  // namespace base
