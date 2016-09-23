// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/i18n/time_formatting.h"

#include <stddef.h>

#include <memory>

#include "base/logging.h"
#include "base/strings/utf_string_conversions.h"
#include "base/time/time.h"
#include "third_party/icu/source/i18n/unicode/datefmt.h"
#include "third_party/icu/source/i18n/unicode/dtptngen.h"
#include "third_party/icu/source/i18n/unicode/fmtable.h"
#include "third_party/icu/source/i18n/unicode/measfmt.h"
#include "third_party/icu/source/i18n/unicode/smpdtfmt.h"

namespace base {
namespace {

string16 TimeFormat(const icu::DateFormat* formatter,
                    const Time& time) {
  DCHECK(formatter);
  icu::UnicodeString date_string;

  formatter->format(static_cast<UDate>(time.ToDoubleT() * 1000), date_string);
  return string16(date_string.getBuffer(),
                  static_cast<size_t>(date_string.length()));
}

string16 TimeFormatWithoutAmPm(const icu::DateFormat* formatter,
                               const Time& time) {
  DCHECK(formatter);
  icu::UnicodeString time_string;

  icu::FieldPosition ampm_field(icu::DateFormat::kAmPmField);
  formatter->format(
      static_cast<UDate>(time.ToDoubleT() * 1000), time_string, ampm_field);
  int ampm_length = ampm_field.getEndIndex() - ampm_field.getBeginIndex();
  if (ampm_length) {
    int begin = ampm_field.getBeginIndex();
    // Doesn't include any spacing before the field.
    if (begin)
      begin--;
    time_string.removeBetween(begin, ampm_field.getEndIndex());
  }
  return string16(time_string.getBuffer(),
                  static_cast<size_t>(time_string.length()));
}

icu::SimpleDateFormat CreateSimpleDateFormatter(const char* pattern) {
  // Generate a locale-dependent format pattern. The generator will take
  // care of locale-dependent formatting issues like which separator to
  // use (some locales use '.' instead of ':'), and where to put the am/pm
  // marker.
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::DateTimePatternGenerator> generator(
      icu::DateTimePatternGenerator::createInstance(status));
  DCHECK(U_SUCCESS(status));
  icu::UnicodeString generated_pattern =
      generator->getBestPattern(icu::UnicodeString(pattern), status);
  DCHECK(U_SUCCESS(status));

  // Then, format the time using the generated pattern.
  icu::SimpleDateFormat formatter(generated_pattern, status);
  DCHECK(U_SUCCESS(status));

  return formatter;
}

UMeasureFormatWidth DurationWidthToMeasureWidth(DurationFormatWidth width) {
  switch (width) {
    case DURATION_WIDTH_WIDE: return UMEASFMT_WIDTH_WIDE;
    case DURATION_WIDTH_SHORT: return UMEASFMT_WIDTH_SHORT;
    case DURATION_WIDTH_NARROW: return UMEASFMT_WIDTH_NARROW;
    case DURATION_WIDTH_NUMERIC: return UMEASFMT_WIDTH_NUMERIC;
  }
  NOTREACHED();
  return UMEASFMT_WIDTH_COUNT;
}

}  // namespace

string16 TimeFormatTimeOfDay(const Time& time) {
  // We can omit the locale parameter because the default should match
  // Chrome's application locale.
  std::unique_ptr<icu::DateFormat> formatter(
      icu::DateFormat::createTimeInstance(icu::DateFormat::kShort));
  return TimeFormat(formatter.get(), time);
}

string16 TimeFormatTimeOfDayWithMilliseconds(const Time& time) {
  icu::SimpleDateFormat formatter = CreateSimpleDateFormatter("HmsSSS");
  return TimeFormatWithoutAmPm(&formatter, time);
}

string16 TimeFormatTimeOfDayWithHourClockType(const Time& time,
                                              HourClockType type,
                                              AmPmClockType ampm) {
  // Just redirect to the normal function if the default type matches the
  // given type.
  HourClockType default_type = GetHourClockType();
  if (default_type == type && (type == k24HourClock || ampm == kKeepAmPm)) {
    return TimeFormatTimeOfDay(time);
  }

  const char* base_pattern = (type == k12HourClock ? "ahm" : "Hm");
  icu::SimpleDateFormat formatter = CreateSimpleDateFormatter(base_pattern);

  if (ampm == kKeepAmPm) {
    return TimeFormat(&formatter, time);
  } else {
    return TimeFormatWithoutAmPm(&formatter, time);
  }
}

string16 TimeFormatShortDate(const Time& time) {
  std::unique_ptr<icu::DateFormat> formatter(
      icu::DateFormat::createDateInstance(icu::DateFormat::kMedium));
  return TimeFormat(formatter.get(), time);
}

string16 TimeFormatShortDateNumeric(const Time& time) {
  std::unique_ptr<icu::DateFormat> formatter(
      icu::DateFormat::createDateInstance(icu::DateFormat::kShort));
  return TimeFormat(formatter.get(), time);
}

string16 TimeFormatShortDateAndTime(const Time& time) {
  std::unique_ptr<icu::DateFormat> formatter(
      icu::DateFormat::createDateTimeInstance(icu::DateFormat::kShort));
  return TimeFormat(formatter.get(), time);
}

string16 TimeFormatShortDateAndTimeWithTimeZone(const Time& time) {
  std::unique_ptr<icu::DateFormat> formatter(
      icu::DateFormat::createDateTimeInstance(icu::DateFormat::kShort,
                                              icu::DateFormat::kLong));
  return TimeFormat(formatter.get(), time);
}

string16 TimeFormatFriendlyDateAndTime(const Time& time) {
  std::unique_ptr<icu::DateFormat> formatter(
      icu::DateFormat::createDateTimeInstance(icu::DateFormat::kFull));
  return TimeFormat(formatter.get(), time);
}

string16 TimeFormatFriendlyDate(const Time& time) {
  std::unique_ptr<icu::DateFormat> formatter(
      icu::DateFormat::createDateInstance(icu::DateFormat::kFull));
  return TimeFormat(formatter.get(), time);
}

string16 TimeDurationFormat(const TimeDelta& time,
                            const DurationFormatWidth width) {
  UErrorCode status = U_ZERO_ERROR;
  const int total_minutes = static_cast<int>(time.InSecondsF() / 60 + 0.5);
  int hours = total_minutes / 60;
  int minutes = total_minutes % 60;
  UMeasureFormatWidth u_width = DurationWidthToMeasureWidth(width);

  const icu::Measure measures[] = {
      icu::Measure(hours, icu::MeasureUnit::createHour(status), status),
      icu::Measure(minutes, icu::MeasureUnit::createMinute(status), status)};
  icu::MeasureFormat measure_format(icu::Locale::getDefault(), u_width, status);
  icu::UnicodeString formatted;
  icu::FieldPosition ignore(icu::FieldPosition::DONT_CARE);
  measure_format.formatMeasures(measures, 2, formatted, ignore, status);
  return base::string16(formatted.getBuffer(), formatted.length());
}

HourClockType GetHourClockType() {
  // TODO(satorux,jshin): Rework this with ures_getByKeyWithFallback()
  // once it becomes public. The short time format can be found at
  // "calendar/gregorian/DateTimePatterns/3" in the resources.
  std::unique_ptr<icu::SimpleDateFormat> formatter(
      static_cast<icu::SimpleDateFormat*>(
          icu::DateFormat::createTimeInstance(icu::DateFormat::kShort)));
  // Retrieve the short time format.
  icu::UnicodeString pattern_unicode;
  formatter->toPattern(pattern_unicode);

  // Determine what hour clock type the current locale uses, by checking
  // "a" (am/pm marker) in the short time format. This is reliable as "a"
  // is used by all of 12-hour clock formats, but not any of 24-hour clock
  // formats, as shown below.
  //
  // % grep -A4 DateTimePatterns third_party/icu/source/data/locales/*.txt |
  //   grep -B1 -- -- |grep -v -- '--' |
  //   perl -nle 'print $1 if /^\S+\s+"(.*)"/' |sort -u
  //
  // H.mm
  // H:mm
  // HH.mm
  // HH:mm
  // a h:mm
  // ah:mm
  // ahh:mm
  // h-mm a
  // h:mm a
  // hh:mm a
  //
  // See http://userguide.icu-project.org/formatparse/datetime for details
  // about the date/time format syntax.
  if (pattern_unicode.indexOf('a') == -1) {
    return k24HourClock;
  } else {
    return k12HourClock;
  }
}

}  // namespace base
