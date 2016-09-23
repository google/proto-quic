// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/i18n/time_formatting.h"

#include <memory>

#include "base/i18n/rtl.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/icu_test_util.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/icu/source/common/unicode/uversion.h"
#include "third_party/icu/source/i18n/unicode/calendar.h"
#include "third_party/icu/source/i18n/unicode/timezone.h"
#include "third_party/icu/source/i18n/unicode/tzfmt.h"

namespace base {
namespace {

const Time::Exploded kTestDateTimeExploded = {
  2011, 4, 6, 30, // Sat, Apr 30, 2011
  15, 42, 7, 0    // 15:42:07.000
};

// Returns difference between the local time and GMT formatted as string.
// This function gets |time| because the difference depends on time,
// see https://en.wikipedia.org/wiki/Daylight_saving_time for details.
base::string16 GetShortTimeZone(const Time& time) {
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::TimeZone> zone(icu::TimeZone::createDefault());
  std::unique_ptr<icu::TimeZoneFormat> zone_formatter(
      icu::TimeZoneFormat::createInstance(icu::Locale::getDefault(), status));
  EXPECT_TRUE(U_SUCCESS(status));
  icu::UnicodeString name;
  zone_formatter->format(UTZFMT_STYLE_SPECIFIC_SHORT, *zone,
                         static_cast<UDate>(time.ToDoubleT() * 1000),
                         name, nullptr);
  return base::string16(name.getBuffer(), name.length());
}

#if defined(OS_ANDROID)
#define MAYBE_TimeFormatTimeOfDayDefault12h \
  DISABLED_TimeFormatTimeOfDayDefault12h
#else
#define MAYBE_TimeFormatTimeOfDayDefault12h TimeFormatTimeOfDayDefault12h
#endif
TEST(TimeFormattingTest, MAYBE_TimeFormatTimeOfDayDefault12h) {
  // Test for a locale defaulted to 12h clock.
  // As an instance, we use third_party/icu/source/data/locales/en.txt.
  test::ScopedRestoreICUDefaultLocale restore_locale;
  i18n::SetICUDefaultLocale("en_US");

  Time time;
  EXPECT_TRUE(Time::FromLocalExploded(kTestDateTimeExploded, &time));
  string16 clock24h(ASCIIToUTF16("15:42"));
  string16 clock12h_pm(ASCIIToUTF16("3:42 PM"));
  string16 clock12h(ASCIIToUTF16("3:42"));
  string16 clock24h_millis(ASCIIToUTF16("15:42:07.000"));

  // The default is 12h clock.
  EXPECT_EQ(clock12h_pm, TimeFormatTimeOfDay(time));
  EXPECT_EQ(clock24h_millis, TimeFormatTimeOfDayWithMilliseconds(time));
  EXPECT_EQ(k12HourClock, GetHourClockType());
  // k{Keep,Drop}AmPm should not affect for 24h clock.
  EXPECT_EQ(clock24h,
            TimeFormatTimeOfDayWithHourClockType(time,
                                                 k24HourClock,
                                                 kKeepAmPm));
  EXPECT_EQ(clock24h,
            TimeFormatTimeOfDayWithHourClockType(time,
                                                 k24HourClock,
                                                 kDropAmPm));
  // k{Keep,Drop}AmPm affects for 12h clock.
  EXPECT_EQ(clock12h_pm,
            TimeFormatTimeOfDayWithHourClockType(time,
                                                 k12HourClock,
                                                 kKeepAmPm));
  EXPECT_EQ(clock12h,
            TimeFormatTimeOfDayWithHourClockType(time,
                                                 k12HourClock,
                                                 kDropAmPm));
}

#if defined(OS_ANDROID)
#define MAYBE_TimeFormatTimeOfDayDefault24h \
  DISABLED_TimeFormatTimeOfDayDefault24h
#else
#define MAYBE_TimeFormatTimeOfDayDefault24h TimeFormatTimeOfDayDefault24h
#endif
TEST(TimeFormattingTest, MAYBE_TimeFormatTimeOfDayDefault24h) {
  // Test for a locale defaulted to 24h clock.
  // As an instance, we use third_party/icu/source/data/locales/en_GB.txt.
  test::ScopedRestoreICUDefaultLocale restore_locale;
  i18n::SetICUDefaultLocale("en_GB");

  Time time;
  EXPECT_TRUE(Time::FromLocalExploded(kTestDateTimeExploded, &time));
  string16 clock24h(ASCIIToUTF16("15:42"));
  string16 clock12h_pm(ASCIIToUTF16("3:42 pm"));
  string16 clock12h(ASCIIToUTF16("3:42"));
  string16 clock24h_millis(ASCIIToUTF16("15:42:07.000"));

  // The default is 24h clock.
  EXPECT_EQ(clock24h, TimeFormatTimeOfDay(time));
  EXPECT_EQ(clock24h_millis, TimeFormatTimeOfDayWithMilliseconds(time));
  EXPECT_EQ(k24HourClock, GetHourClockType());
  // k{Keep,Drop}AmPm should not affect for 24h clock.
  EXPECT_EQ(clock24h,
            TimeFormatTimeOfDayWithHourClockType(time,
                                                 k24HourClock,
                                                 kKeepAmPm));
  EXPECT_EQ(clock24h,
            TimeFormatTimeOfDayWithHourClockType(time,
                                                 k24HourClock,
                                                 kDropAmPm));
  // k{Keep,Drop}AmPm affects for 12h clock.
  EXPECT_EQ(clock12h_pm,
            TimeFormatTimeOfDayWithHourClockType(time,
                                                 k12HourClock,
                                                 kKeepAmPm));
  EXPECT_EQ(clock12h,
            TimeFormatTimeOfDayWithHourClockType(time,
                                                 k12HourClock,
                                                 kDropAmPm));
}

#if defined(OS_ANDROID)
#define MAYBE_TimeFormatTimeOfDayJP DISABLED_TimeFormatTimeOfDayJP
#else
#define MAYBE_TimeFormatTimeOfDayJP TimeFormatTimeOfDayJP
#endif
TEST(TimeFormattingTest, MAYBE_TimeFormatTimeOfDayJP) {
  // Test for a locale that uses different mark than "AM" and "PM".
  // As an instance, we use third_party/icu/source/data/locales/ja.txt.
  test::ScopedRestoreICUDefaultLocale restore_locale;
  i18n::SetICUDefaultLocale("ja_JP");

  Time time;
  EXPECT_TRUE(Time::FromLocalExploded(kTestDateTimeExploded, &time));
  string16 clock24h(ASCIIToUTF16("15:42"));
  string16 clock12h_pm(WideToUTF16(L"\x5348\x5f8c" L"3:42"));
  string16 clock12h(ASCIIToUTF16("3:42"));

  // The default is 24h clock.
  EXPECT_EQ(clock24h, TimeFormatTimeOfDay(time));
  EXPECT_EQ(k24HourClock, GetHourClockType());
  // k{Keep,Drop}AmPm should not affect for 24h clock.
  EXPECT_EQ(clock24h,
            TimeFormatTimeOfDayWithHourClockType(time,
                                                 k24HourClock,
                                                 kKeepAmPm));
  EXPECT_EQ(clock24h,
            TimeFormatTimeOfDayWithHourClockType(time,
                                                 k24HourClock,
                                                 kDropAmPm));
  // k{Keep,Drop}AmPm affects for 12h clock.
  EXPECT_EQ(clock12h_pm,
            TimeFormatTimeOfDayWithHourClockType(time,
                                                 k12HourClock,
                                                 kKeepAmPm));
  EXPECT_EQ(clock12h,
            TimeFormatTimeOfDayWithHourClockType(time,
                                                 k12HourClock,
                                                 kDropAmPm));
}

#if defined(OS_ANDROID)
#define MAYBE_TimeFormatDateUS DISABLED_TimeFormatDateUS
#else
#define MAYBE_TimeFormatDateUS TimeFormatDateUS
#endif
TEST(TimeFormattingTest, MAYBE_TimeFormatDateUS) {
  // See third_party/icu/source/data/locales/en.txt.
  // The date patterns are "EEEE, MMMM d, y", "MMM d, y", and "M/d/yy".
  test::ScopedRestoreICUDefaultLocale restore_locale;
  i18n::SetICUDefaultLocale("en_US");

  Time time;
  EXPECT_TRUE(Time::FromLocalExploded(kTestDateTimeExploded, &time));

  EXPECT_EQ(ASCIIToUTF16("Apr 30, 2011"), TimeFormatShortDate(time));
  EXPECT_EQ(ASCIIToUTF16("4/30/11"), TimeFormatShortDateNumeric(time));

  EXPECT_EQ(ASCIIToUTF16("4/30/11, 3:42:07 PM"),
            TimeFormatShortDateAndTime(time));
  EXPECT_EQ(ASCIIToUTF16("4/30/11, 3:42:07 PM ") + GetShortTimeZone(time),
            TimeFormatShortDateAndTimeWithTimeZone(time));

  EXPECT_EQ(ASCIIToUTF16("Saturday, April 30, 2011 at 3:42:07 PM"),
            TimeFormatFriendlyDateAndTime(time));

  EXPECT_EQ(ASCIIToUTF16("Saturday, April 30, 2011"),
            TimeFormatFriendlyDate(time));
}

#if defined(OS_ANDROID)
#define MAYBE_TimeFormatDateGB DISABLED_TimeFormatDateGB
#else
#define MAYBE_TimeFormatDateGB TimeFormatDateGB
#endif
TEST(TimeFormattingTest, MAYBE_TimeFormatDateGB) {
  // See third_party/icu/source/data/locales/en_GB.txt.
  // The date patterns are "EEEE, d MMMM y", "d MMM y", and "dd/MM/yyyy".
  test::ScopedRestoreICUDefaultLocale restore_locale;
  i18n::SetICUDefaultLocale("en_GB");

  Time time;
  EXPECT_TRUE(Time::FromLocalExploded(kTestDateTimeExploded, &time));

  EXPECT_EQ(ASCIIToUTF16("30 Apr 2011"), TimeFormatShortDate(time));
  EXPECT_EQ(ASCIIToUTF16("30/04/2011"), TimeFormatShortDateNumeric(time));
  EXPECT_EQ(ASCIIToUTF16("30/04/2011, 15:42:07"),
            TimeFormatShortDateAndTime(time));
  EXPECT_EQ(ASCIIToUTF16("30/04/2011, 15:42:07 ") + GetShortTimeZone(time),
            TimeFormatShortDateAndTimeWithTimeZone(time));
  EXPECT_EQ(ASCIIToUTF16("Saturday, 30 April 2011 at 15:42:07"),
            TimeFormatFriendlyDateAndTime(time));
  EXPECT_EQ(ASCIIToUTF16("Saturday, 30 April 2011"),
            TimeFormatFriendlyDate(time));
}

TEST(TimeFormattingTest, TimeDurationFormat) {
  test::ScopedRestoreICUDefaultLocale restore_locale;
  TimeDelta delta = TimeDelta::FromMinutes(15 * 60 + 42);

  // US English.
  i18n::SetICUDefaultLocale("en_US");
  EXPECT_EQ(ASCIIToUTF16("15 hours, 42 minutes"),
            TimeDurationFormat(delta, DURATION_WIDTH_WIDE));
  EXPECT_EQ(ASCIIToUTF16("15 hr, 42 min"),
            TimeDurationFormat(delta, DURATION_WIDTH_SHORT));
  EXPECT_EQ(ASCIIToUTF16("15h 42m"),
            TimeDurationFormat(delta, DURATION_WIDTH_NARROW));
  EXPECT_EQ(ASCIIToUTF16("15:42"),
            TimeDurationFormat(delta, DURATION_WIDTH_NUMERIC));

  // Danish, with Latin alphabet but different abbreviations and punctuation.
  i18n::SetICUDefaultLocale("da");
  EXPECT_EQ(ASCIIToUTF16("15 timer og 42 minutter"),
            TimeDurationFormat(delta, DURATION_WIDTH_WIDE));
  EXPECT_EQ(ASCIIToUTF16("15 t og 42 min."),
            TimeDurationFormat(delta, DURATION_WIDTH_SHORT));
  EXPECT_EQ(ASCIIToUTF16("15 t og 42 min"),
            TimeDurationFormat(delta, DURATION_WIDTH_NARROW));
  EXPECT_EQ(ASCIIToUTF16("15.42"),
            TimeDurationFormat(delta, DURATION_WIDTH_NUMERIC));

  // Persian, with non-Arabic numbers.
  i18n::SetICUDefaultLocale("fa");
  string16 fa_wide = WideToUTF16(
      L"\x6f1\x6f5\x20\x633\x627\x639\x62a\x20\x648\x20\x6f4\x6f2\x20\x62f\x642"
      L"\x6cc\x642\x647");
  string16 fa_short = WideToUTF16(
      L"\x6f1\x6f5\x20\x633\x627\x639\x62a\x60c\x200f\x20\x6f4\x6f2\x20\x62f"
      L"\x642\x6cc\x642\x647");
  string16 fa_narrow = WideToUTF16(
      L"\x6f1\x6f5\x20\x633\x627\x639\x62a\x20\x6f4\x6f2\x20\x62f\x642\x6cc"
      L"\x642\x647");
  string16 fa_numeric = WideToUTF16(L"\x6f1\x6f5\x3a\x6f4\x6f2");
  EXPECT_EQ(fa_wide, TimeDurationFormat(delta, DURATION_WIDTH_WIDE));
  EXPECT_EQ(fa_short, TimeDurationFormat(delta, DURATION_WIDTH_SHORT));
  EXPECT_EQ(fa_narrow, TimeDurationFormat(delta, DURATION_WIDTH_NARROW));
  EXPECT_EQ(fa_numeric, TimeDurationFormat(delta, DURATION_WIDTH_NUMERIC));
}

}  // namespace
}  // namespace base
