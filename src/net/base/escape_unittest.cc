// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <string>

#include "net/base/escape.h"

#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

struct EscapeCase {
  const char* input;
  const char* output;
};

struct UnescapeURLCase {
  const wchar_t* input;
  UnescapeRule::Type rules;
  const wchar_t* output;
};

struct UnescapeURLCaseASCII {
  const char* input;
  UnescapeRule::Type rules;
  const char* output;
};

struct UnescapeAndDecodeCase {
  const char* input;

  // The expected output when run through UnescapeURL.
  const char* url_unescaped;

  // The expected output when run through UnescapeQuery.
  const char* query_unescaped;

  // The expected output when run through UnescapeAndDecodeURLComponent.
  const wchar_t* decoded;
};

struct AdjustOffsetCase {
  const char* input;
  size_t input_offset;
  size_t output_offset;
};

struct EscapeForHTMLCase {
  const char* input;
  const char* expected_output;
};

TEST(EscapeTest, EscapeTextForFormSubmission) {
  const EscapeCase escape_cases[] = {
    {"foo", "foo"},
    {"foo bar", "foo+bar"},
    {"foo++", "foo%2B%2B"}
  };
  for (size_t i = 0; i < arraysize(escape_cases); ++i) {
    EscapeCase value = escape_cases[i];
    EXPECT_EQ(value.output, EscapeQueryParamValue(value.input, true));
  }

  const EscapeCase escape_cases_no_plus[] = {
    {"foo", "foo"},
    {"foo bar", "foo%20bar"},
    {"foo++", "foo%2B%2B"}
  };
  for (size_t i = 0; i < arraysize(escape_cases_no_plus); ++i) {
    EscapeCase value = escape_cases_no_plus[i];
    EXPECT_EQ(value.output, EscapeQueryParamValue(value.input, false));
  }

  // Test all the values in we're supposed to be escaping.
  const std::string no_escape(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "!'()*-._~");
  for (int i = 0; i < 256; ++i) {
    std::string in;
    in.push_back(i);
    std::string out = EscapeQueryParamValue(in, true);
    if (0 == i) {
      EXPECT_EQ(out, std::string("%00"));
    } else if (32 == i) {
      // Spaces are plus escaped like web forms.
      EXPECT_EQ(out, std::string("+"));
    } else if (no_escape.find(in) == std::string::npos) {
      // Check %hex escaping
      std::string expected = base::StringPrintf("%%%02X", i);
      EXPECT_EQ(expected, out);
    } else {
      // No change for things in the no_escape list.
      EXPECT_EQ(out, in);
    }
  }
}

TEST(EscapeTest, EscapePath) {
  ASSERT_EQ(
    // Most of the character space we care about, un-escaped
    EscapePath(
      "\x02\n\x1d !\"#$%&'()*+,-./0123456789:;"
      "<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "[\\]^_`abcdefghijklmnopqrstuvwxyz"
      "{|}~\x7f\x80\xff"),
    // Escaped
    "%02%0A%1D%20!%22%23$%25&'()*+,-./0123456789%3A;"
    "%3C=%3E%3F@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "%5B%5C%5D%5E_%60abcdefghijklmnopqrstuvwxyz"
    "%7B%7C%7D~%7F%80%FF");
}

TEST(EscapeTest, DataURLWithAccentedCharacters) {
  const std::string url =
      "text/html;charset=utf-8,%3Chtml%3E%3Cbody%3ETonton,%20ton%20th%C3"
      "%A9%20t'a-t-il%20%C3%B4t%C3%A9%20ta%20toux%20";

  base::OffsetAdjuster::Adjustments adjustments;
  UnescapeAndDecodeUTF8URLComponentWithAdjustments(url, UnescapeRule::SPACES,
                                                   &adjustments);
}

TEST(EscapeTest, EscapeUrlEncodedData) {
  ASSERT_EQ(
    // Most of the character space we care about, un-escaped
    EscapeUrlEncodedData(
      "\x02\n\x1d !\"#$%&'()*+,-./0123456789:;"
      "<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "[\\]^_`abcdefghijklmnopqrstuvwxyz"
      "{|}~\x7f\x80\xff", true),
    // Escaped
    "%02%0A%1D+!%22%23%24%25%26%27()*%2B,-./0123456789:%3B"
    "%3C%3D%3E%3F%40ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "%5B%5C%5D%5E_%60abcdefghijklmnopqrstuvwxyz"
    "%7B%7C%7D~%7F%80%FF");
}

TEST(EscapeTest, EscapeUrlEncodedDataSpace) {
  ASSERT_EQ(EscapeUrlEncodedData("a b", true), "a+b");
  ASSERT_EQ(EscapeUrlEncodedData("a b", false), "a%20b");
}

TEST(EscapeTest, UnescapeURLComponentASCII) {
  const UnescapeURLCaseASCII unescape_cases[] = {
      {"", UnescapeRule::NORMAL, ""},
      {"%2", UnescapeRule::NORMAL, "%2"},
      {"%%%%%%", UnescapeRule::NORMAL, "%%%%%%"},
      {"Don't escape anything", UnescapeRule::NORMAL, "Don't escape anything"},
      {"Invalid %escape %2", UnescapeRule::NORMAL, "Invalid %escape %2"},
      {"Some%20random text %25%2dOK", UnescapeRule::NONE,
       "Some%20random text %25%2dOK"},
      {"Some%20random text %25%2dOK", UnescapeRule::NORMAL,
       "Some%20random text %25-OK"},
      {"Some%20random text %25%2dOK", UnescapeRule::SPACES,
       "Some random text %25-OK"},
      {"Some%20random text %25%2dOK", UnescapeRule::PATH_SEPARATORS,
       "Some%20random text %25-OK"},
      {"Some%20random text %25%2dOK",
       UnescapeRule::URL_SPECIAL_CHARS_EXCEPT_PATH_SEPARATORS,
       "Some%20random text %-OK"},
      {"Some%20random text %25%2dOK",
       UnescapeRule::SPACES |
           UnescapeRule::URL_SPECIAL_CHARS_EXCEPT_PATH_SEPARATORS,
       "Some random text %-OK"},
      {"%A0%B1%C2%D3%E4%F5", UnescapeRule::NORMAL, "\xA0\xB1\xC2\xD3\xE4\xF5"},
      {"%Aa%Bb%Cc%Dd%Ee%Ff", UnescapeRule::NORMAL, "\xAa\xBb\xCc\xDd\xEe\xFf"},
      // Certain URL-sensitive characters should not be unescaped unless asked.
      {"Hello%20%13%10world %23# %3F? %3D= %26& %25% %2B+",
       UnescapeRule::SPACES, "Hello %13%10world %23# %3F? %3D= %26& %25% %2B+"},
      {"Hello%20%13%10world %23# %3F? %3D= %26& %25% %2B+",
       UnescapeRule::URL_SPECIAL_CHARS_EXCEPT_PATH_SEPARATORS,
       "Hello%20%13%10world ## ?? == && %% ++"},
      // We can neither escape nor unescape '@' since some websites expect it to
      // be preserved as either '@' or "%40".
      // See http://b/996720 and http://crbug.com/23933 .
      {"me@my%40example", UnescapeRule::NORMAL, "me@my%40example"},
      // Control characters.
      {"%01%02%03%04%05%06%07%08%09 %25",
       UnescapeRule::URL_SPECIAL_CHARS_EXCEPT_PATH_SEPARATORS,
       "%01%02%03%04%05%06%07%08%09 %"},
      {"%01%02%03%04%05%06%07%08%09 %25",
       UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       "\x01\x02\x03\x04\x05\x06\x07\x08\x09 %25"},
      {"Hello%20%13%10%02", UnescapeRule::SPACES, "Hello %13%10%02"},
      {"Hello%20%13%10%02", UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       "Hello%20\x13\x10\x02"},

      // '/' and '\\' should only be unescaped by PATH_SEPARATORS.
      {"%2F%5C", UnescapeRule::PATH_SEPARATORS, "/\\"},
      {"%2F%5C", UnescapeRule::SPACES |
                     UnescapeRule::URL_SPECIAL_CHARS_EXCEPT_PATH_SEPARATORS |
                     UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       "%2F%5C"},
  };

  for (size_t i = 0; i < arraysize(unescape_cases); i++) {
    std::string str(unescape_cases[i].input);
    EXPECT_EQ(std::string(unescape_cases[i].output),
              UnescapeURLComponent(str, unescape_cases[i].rules));
  }

  // Test the NULL character unescaping (which wouldn't work above since those
  // are just char pointers).
  std::string input("Null");
  input.push_back(0);  // Also have a NULL in the input.
  input.append("%00%39Test");

  // When we're unescaping NULLs
  std::string expected("Null");
  expected.push_back(0);
  expected.push_back(0);
  expected.append("9Test");
  EXPECT_EQ(expected, UnescapeURLComponent(
                          input, UnescapeRule::SPOOFING_AND_CONTROL_CHARS));

  // When we're not unescaping NULLs.
  expected = "Null";
  expected.push_back(0);
  expected.append("%009Test");
  EXPECT_EQ(expected, UnescapeURLComponent(input, UnescapeRule::NORMAL));
}

TEST(EscapeTest, UnescapeURLComponent) {
  const UnescapeURLCase unescape_cases[] = {
      {L"", UnescapeRule::NORMAL, L""},
      {L"%2", UnescapeRule::NORMAL, L"%2"},
      {L"%%%%%%", UnescapeRule::NORMAL, L"%%%%%%"},
      {L"Don't escape anything", UnescapeRule::NORMAL,
       L"Don't escape anything"},
      {L"Invalid %escape %2", UnescapeRule::NORMAL, L"Invalid %escape %2"},
      {L"Some%20random text %25%2dOK", UnescapeRule::NONE,
       L"Some%20random text %25%2dOK"},
      {L"Some%20random text %25%2dOK", UnescapeRule::NORMAL,
       L"Some%20random text %25-OK"},
      {L"Some%20random text %25%E2%80", UnescapeRule::NORMAL,
       L"Some%20random text %25\xE2\x80"},
      {L"Some%20random text %25%E2%80OK", UnescapeRule::NORMAL,
       L"Some%20random text %25\xE2\x80OK"},
      {L"Some%20random text %25%E2%80%84OK", UnescapeRule::NORMAL,
       L"Some%20random text %25\xE2\x80\x84OK"},

      // BiDi Control characters should not be unescaped unless explicity told
      // to
      // do so with UnescapeRule::SPOOFING_AND_CONTROL_CHARS
      {L"Some%20random text %25%D8%9COK", UnescapeRule::NORMAL,
       L"Some%20random text %25%D8%9COK"},
      {L"Some%20random text %25%E2%80%8EOK", UnescapeRule::NORMAL,
       L"Some%20random text %25%E2%80%8EOK"},
      {L"Some%20random text %25%E2%80%8FOK", UnescapeRule::NORMAL,
       L"Some%20random text %25%E2%80%8FOK"},
      {L"Some%20random text %25%E2%80%AAOK", UnescapeRule::NORMAL,
       L"Some%20random text %25%E2%80%AAOK"},
      {L"Some%20random text %25%E2%80%ABOK", UnescapeRule::NORMAL,
       L"Some%20random text %25%E2%80%ABOK"},
      {L"Some%20random text %25%E2%80%AEOK", UnescapeRule::NORMAL,
       L"Some%20random text %25%E2%80%AEOK"},
      {L"Some%20random text %25%E2%81%A6OK", UnescapeRule::NORMAL,
       L"Some%20random text %25%E2%81%A6OK"},
      {L"Some%20random text %25%E2%81%A9OK", UnescapeRule::NORMAL,
       L"Some%20random text %25%E2%81%A9OK"},
      // UnescapeRule::SPOOFING_AND_CONTROL_CHARS should unescape BiDi Control
      // characters.
      {L"Some%20random text %25%D8%9COK",
       UnescapeRule::NORMAL | UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       L"Some%20random text %25\xD8\x9COK"},
      {L"Some%20random text %25%E2%80%8EOK",
       UnescapeRule::NORMAL | UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       L"Some%20random text %25\xE2\x80\x8EOK"},
      {L"Some%20random text %25%E2%80%8FOK",
       UnescapeRule::NORMAL | UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       L"Some%20random text %25\xE2\x80\x8FOK"},
      {L"Some%20random text %25%E2%80%AAOK",
       UnescapeRule::NORMAL | UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       L"Some%20random text %25\xE2\x80\xAAOK"},
      {L"Some%20random text %25%E2%80%ABOK",
       UnescapeRule::NORMAL | UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       L"Some%20random text %25\xE2\x80\xABOK"},
      {L"Some%20random text %25%E2%80%AEOK",
       UnescapeRule::NORMAL | UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       L"Some%20random text %25\xE2\x80\xAEOK"},
      {L"Some%20random text %25%E2%81%A6OK",
       UnescapeRule::NORMAL | UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       L"Some%20random text %25\xE2\x81\xA6OK"},
      {L"Some%20random text %25%E2%81%A9OK",
       UnescapeRule::NORMAL | UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       L"Some%20random text %25\xE2\x81\xA9OK"},

      // Certain banned characters should not be unescaped unless explicitly
      // told
      // to do so with UnescapeRule::SPOOFING_AND_CONTROL_CHARS.
      // U+1F50F LOCK WITH INK PEN
      {L"Some%20random text %25%F0%9F%94%8FOK", UnescapeRule::NORMAL,
       L"Some%20random text %25%F0%9F%94%8FOK"},
      // U+1F510 CLOSED LOCK WITH KEY
      {L"Some%20random text %25%F0%9F%94%90OK", UnescapeRule::NORMAL,
       L"Some%20random text %25%F0%9F%94%90OK"},
      // U+1F512 LOCK
      {L"Some%20random text %25%F0%9F%94%92OK", UnescapeRule::NORMAL,
       L"Some%20random text %25%F0%9F%94%92OK"},
      // U+1F513 OPEN LOCK
      {L"Some%20random text %25%F0%9F%94%93OK", UnescapeRule::NORMAL,
       L"Some%20random text %25%F0%9F%94%93OK"},
      // UnescapeRule::SPOOFING_AND_CONTROL_CHARS should unescape banned
      // characters.
      {L"Some%20random text %25%F0%9F%94%8FOK",
       UnescapeRule::NORMAL | UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       L"Some%20random text %25\xF0\x9F\x94\x8FOK"},
      {L"Some%20random text %25%F0%9F%94%90OK",
       UnescapeRule::NORMAL | UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       L"Some%20random text %25\xF0\x9F\x94\x90OK"},
      {L"Some%20random text %25%F0%9F%94%92OK",
       UnescapeRule::NORMAL | UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       L"Some%20random text %25\xF0\x9F\x94\x92OK"},
      {L"Some%20random text %25%F0%9F%94%93OK",
       UnescapeRule::NORMAL | UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       L"Some%20random text %25\xF0\x9F\x94\x93OK"},

      {L"Some%20random text %25%2dOK", UnescapeRule::SPACES,
       L"Some random text %25-OK"},
      {L"Some%20random text %25%2dOK",
       UnescapeRule::URL_SPECIAL_CHARS_EXCEPT_PATH_SEPARATORS,
       L"Some%20random text %-OK"},
      {L"Some%20random text %25%2dOK",
       UnescapeRule::SPACES |
           UnescapeRule::URL_SPECIAL_CHARS_EXCEPT_PATH_SEPARATORS,
       L"Some random text %-OK"},
      {L"%A0%B1%C2%D3%E4%F5", UnescapeRule::NORMAL,
       L"\xA0\xB1\xC2\xD3\xE4\xF5"},
      {L"%Aa%Bb%Cc%Dd%Ee%Ff", UnescapeRule::NORMAL,
       L"\xAa\xBb\xCc\xDd\xEe\xFf"},
      // Certain URL-sensitive characters should not be unescaped unless asked.
      {L"Hello%20%13%10world %23# %3F? %3D= %26& %25% %2B+",
       UnescapeRule::SPACES,
       L"Hello %13%10world %23# %3F? %3D= %26& %25% %2B+"},
      {L"Hello%20%13%10world %23# %3F? %3D= %26& %25% %2B+",
       UnescapeRule::URL_SPECIAL_CHARS_EXCEPT_PATH_SEPARATORS,
       L"Hello%20%13%10world ## ?? == && %% ++"},
      // We can neither escape nor unescape '@' since some websites expect it to
      // be preserved as either '@' or "%40".
      // See http://b/996720 and http://crbug.com/23933 .
      {L"me@my%40example", UnescapeRule::NORMAL, L"me@my%40example"},
      // Control characters.
      {L"%01%02%03%04%05%06%07%08%09 %25",
       UnescapeRule::URL_SPECIAL_CHARS_EXCEPT_PATH_SEPARATORS,
       L"%01%02%03%04%05%06%07%08%09 %"},
      {L"%01%02%03%04%05%06%07%08%09 %25",
       UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       L"\x01\x02\x03\x04\x05\x06\x07\x08\x09 %25"},
      {L"Hello%20%13%10%02", UnescapeRule::SPACES, L"Hello %13%10%02"},
      {L"Hello%20%13%10%02", UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       L"Hello%20\x13\x10\x02"},
      {L"Hello\x9824\x9827", UnescapeRule::SPOOFING_AND_CONTROL_CHARS,
       L"Hello\x9824\x9827"},
  };

  for (size_t i = 0; i < arraysize(unescape_cases); i++) {
    base::string16 str(base::WideToUTF16(unescape_cases[i].input));
    EXPECT_EQ(base::WideToUTF16(unescape_cases[i].output),
              UnescapeURLComponent(str, unescape_cases[i].rules));
  }

  // Test the NULL character unescaping (which wouldn't work above since those
  // are just char pointers).
  base::string16 input(base::WideToUTF16(L"Null"));
  input.push_back(0);  // Also have a NULL in the input.
  input.append(base::WideToUTF16(L"%00%39Test"));

  // When we're unescaping NULLs
  base::string16 expected(base::WideToUTF16(L"Null"));
  expected.push_back(0);
  expected.push_back(0);
  expected.append(base::ASCIIToUTF16("9Test"));
  EXPECT_EQ(expected, UnescapeURLComponent(
                          input, UnescapeRule::SPOOFING_AND_CONTROL_CHARS));

  // When we're not unescaping NULLs.
  expected = base::WideToUTF16(L"Null");
  expected.push_back(0);
  expected.append(base::WideToUTF16(L"%009Test"));
  EXPECT_EQ(expected, UnescapeURLComponent(input, UnescapeRule::NORMAL));
}

TEST(EscapeTest, UnescapeAndDecodeUTF8URLComponent) {
  const UnescapeAndDecodeCase unescape_cases[] = {
    { "%",
      "%",
      "%",
     L"%"},
    { "+",
      "+",
      " ",
     L"+"},
    { "%2+",
      "%2+",
      "%2 ",
     L"%2+"},
    { "+%%%+%%%",
      "+%%%+%%%",
      " %%% %%%",
     L"+%%%+%%%"},
    { "Don't escape anything",
      "Don't escape anything",
      "Don't escape anything",
     L"Don't escape anything"},
    { "+Invalid %escape %2+",
      "+Invalid %escape %2+",
      " Invalid %escape %2 ",
     L"+Invalid %escape %2+"},
    { "Some random text %25%2dOK",
      "Some random text %25-OK",
      "Some random text %25-OK",
     L"Some random text %25-OK"},
    { "%01%02%03%04%05%06%07%08%09",
      "%01%02%03%04%05%06%07%08%09",
      "%01%02%03%04%05%06%07%08%09",
     L"%01%02%03%04%05%06%07%08%09"},
    { "%E4%BD%A0+%E5%A5%BD",
      "\xE4\xBD\xA0+\xE5\xA5\xBD",
      "\xE4\xBD\xA0 \xE5\xA5\xBD",
     L"\x4f60+\x597d"},
    { "%ED%ED",  // Invalid UTF-8.
      "\xED\xED",
      "\xED\xED",
     L"%ED%ED"},  // Invalid UTF-8 -> kept unescaped.
  };

  for (size_t i = 0; i < arraysize(unescape_cases); i++) {
    std::string unescaped = UnescapeURLComponent(unescape_cases[i].input,
                                                 UnescapeRule::NORMAL);
    EXPECT_EQ(std::string(unescape_cases[i].url_unescaped), unescaped);

    unescaped = UnescapeURLComponent(unescape_cases[i].input,
                                     UnescapeRule::REPLACE_PLUS_WITH_SPACE);
    EXPECT_EQ(std::string(unescape_cases[i].query_unescaped), unescaped);

    // TODO: Need to test unescape_spaces and unescape_percent.
    base::string16 decoded = UnescapeAndDecodeUTF8URLComponent(
        unescape_cases[i].input, UnescapeRule::NORMAL);
    EXPECT_EQ(base::WideToUTF16(unescape_cases[i].decoded), decoded);
  }
}

TEST(EscapeTest, AdjustOffset) {
  const AdjustOffsetCase adjust_cases[] = {
    {"", 0, 0},
    {"test", 0, 0},
    {"test", 2, 2},
    {"test", 4, 4},
    {"test", std::string::npos, std::string::npos},
    {"%2dtest", 6, 4},
    {"%2dtest", 3, 1},
    {"%2dtest", 2, std::string::npos},
    {"%2dtest", 1, std::string::npos},
    {"%2dtest", 0, 0},
    {"test%2d", 2, 2},
    {"%E4%BD%A0+%E5%A5%BD", 9, 1},
    {"%E4%BD%A0+%E5%A5%BD", 6, std::string::npos},
    {"%E4%BD%A0+%E5%A5%BD", 0, 0},
    {"%E4%BD%A0+%E5%A5%BD", 10, 2},
    {"%E4%BD%A0+%E5%A5%BD", 19, 3},

    {"hi%41test%E4%BD%A0+%E5%A5%BD", 18, 8},
    {"hi%41test%E4%BD%A0+%E5%A5%BD", 15, std::string::npos},
    {"hi%41test%E4%BD%A0+%E5%A5%BD", 9, 7},
    {"hi%41test%E4%BD%A0+%E5%A5%BD", 19, 9},
    {"hi%41test%E4%BD%A0+%E5%A5%BD", 28, 10},
    {"hi%41test%E4%BD%A0+%E5%A5%BD", 0, 0},
    {"hi%41test%E4%BD%A0+%E5%A5%BD", 2, 2},
    {"hi%41test%E4%BD%A0+%E5%A5%BD", 3, std::string::npos},
    {"hi%41test%E4%BD%A0+%E5%A5%BD", 5, 3},

    {"%E4%BD%A0+%E5%A5%BDhi%41test", 9, 1},
    {"%E4%BD%A0+%E5%A5%BDhi%41test", 6, std::string::npos},
    {"%E4%BD%A0+%E5%A5%BDhi%41test", 0, 0},
    {"%E4%BD%A0+%E5%A5%BDhi%41test", 10, 2},
    {"%E4%BD%A0+%E5%A5%BDhi%41test", 19, 3},
    {"%E4%BD%A0+%E5%A5%BDhi%41test", 21, 5},
    {"%E4%BD%A0+%E5%A5%BDhi%41test", 22, std::string::npos},
    {"%E4%BD%A0+%E5%A5%BDhi%41test", 24, 6},
    {"%E4%BD%A0+%E5%A5%BDhi%41test", 28, 10},

    {"%ED%B0%80+%E5%A5%BD", 6, 6},  // not convertable to UTF-8
  };

  for (size_t i = 0; i < arraysize(adjust_cases); i++) {
    size_t offset = adjust_cases[i].input_offset;
    base::OffsetAdjuster::Adjustments adjustments;
    UnescapeAndDecodeUTF8URLComponentWithAdjustments(
        adjust_cases[i].input, UnescapeRule::NORMAL, &adjustments);
    base::OffsetAdjuster::AdjustOffset(adjustments, &offset);
    EXPECT_EQ(adjust_cases[i].output_offset, offset)
        << "input=" << adjust_cases[i].input
        << " offset=" << adjust_cases[i].input_offset;
  }
}

TEST(EscapeTest, EscapeForHTML) {
  const EscapeForHTMLCase tests[] = {
    { "hello", "hello" },
    { "<hello>", "&lt;hello&gt;" },
    { "don\'t mess with me", "don&#39;t mess with me" },
  };
  for (size_t i = 0; i < arraysize(tests); ++i) {
    std::string result = EscapeForHTML(std::string(tests[i].input));
    EXPECT_EQ(std::string(tests[i].expected_output), result);
  }
}

TEST(EscapeTest, UnescapeForHTML) {
  const EscapeForHTMLCase tests[] = {
    { "", "" },
    { "&lt;hello&gt;", "<hello>" },
    { "don&#39;t mess with me", "don\'t mess with me" },
    { "&lt;&gt;&amp;&quot;&#39;", "<>&\"'" },
    { "& lt; &amp ; &; '", "& lt; &amp ; &; '" },
    { "&amp;", "&" },
    { "&quot;", "\"" },
    { "&#39;", "'" },
    { "&lt;", "<" },
    { "&gt;", ">" },
    { "&amp; &", "& &" },
  };
  for (size_t i = 0; i < arraysize(tests); ++i) {
    base::string16 result = UnescapeForHTML(base::ASCIIToUTF16(tests[i].input));
    EXPECT_EQ(base::ASCIIToUTF16(tests[i].expected_output), result);
  }
}

TEST(EscapeTest, EscapeExternalHandlerValue) {
  ASSERT_EQ(
      // Escaped
      "%02%0A%1D%20!%22#$%25&'()*+,-./0123456789:;"
      "%3C=%3E?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "[%5C]%5E_%60abcdefghijklmnopqrstuvwxyz"
      "%7B%7C%7D~%7F%80%FF",
      // Most of the character space we care about, un-escaped
      EscapeExternalHandlerValue(
          "\x02\n\x1d !\"#$%&'()*+,-./0123456789:;"
          "<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
          "[\\]^_`abcdefghijklmnopqrstuvwxyz"
          "{|}~\x7f\x80\xff"));

  ASSERT_EQ(
      "!#$&'()*+,-./0123456789:;=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]_"
      "abcdefghijklmnopqrstuvwxyz~",
      EscapeExternalHandlerValue(
          "!#$&'()*+,-./0123456789:;=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]_"
          "abcdefghijklmnopqrstuvwxyz~"));

  ASSERT_EQ("%258k", EscapeExternalHandlerValue("%8k"));
  ASSERT_EQ("a%25", EscapeExternalHandlerValue("a%"));
  ASSERT_EQ("%25a", EscapeExternalHandlerValue("%a"));
  ASSERT_EQ("a%258", EscapeExternalHandlerValue("a%8"));
  ASSERT_EQ("%ab", EscapeExternalHandlerValue("%ab"));
  ASSERT_EQ("%AB", EscapeExternalHandlerValue("%AB"));

  ASSERT_EQ("http://example.com/path/sub?q=a%7Cb%7Cc&q=1%7C2%7C3#ref%7C",
            EscapeExternalHandlerValue(
                "http://example.com/path/sub?q=a|b|c&q=1|2|3#ref|"));
  ASSERT_EQ("http://example.com/path/sub?q=a%7Cb%7Cc&q=1%7C2%7C3#ref%7C",
            EscapeExternalHandlerValue(
                "http://example.com/path/sub?q=a%7Cb%7Cc&q=1%7C2%7C3#ref%7C"));
  ASSERT_EQ("http://[2001:db8:0:1]:80",
            EscapeExternalHandlerValue("http://[2001:db8:0:1]:80"));
}

}  // namespace
}  // namespace net
