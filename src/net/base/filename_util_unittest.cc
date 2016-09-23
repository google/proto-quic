// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/filename_util.h"

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/test_file_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

struct FileCase {
  const wchar_t* file;
  const char* url;
};

struct GenerateFilenameCase {
  int lineno;
  const char* url;
  const char* content_disp_header;
  const char* referrer_charset;
  const char* suggested_filename;
  const char* mime_type;
  const wchar_t* default_filename;
  const wchar_t* expected_filename;
};

// The expected filenames are coded as wchar_t for convenience.
std::wstring FilePathAsWString(const base::FilePath& path) {
#if defined(OS_WIN)
  return path.value();
#else
  return base::UTF8ToWide(path.value());
#endif
}
base::FilePath WStringAsFilePath(const std::wstring& str) {
#if defined(OS_WIN)
  return base::FilePath(str);
#else
  return base::FilePath(base::WideToUTF8(str));
#endif
}

std::string GetLocaleWarningString() {
#if defined(OS_POSIX) && !defined(OS_ANDROID)
  // The generate filename tests can fail on certain OS_POSIX platforms when
  // LC_CTYPE is not "utf8" or "utf-8" because some of the string conversions
  // fail.
  // This warning text is appended to any test failures to save people time if
  // this happens to be the cause of failure :)
  // Note: some platforms (MACOSX, Chromecast) don't have this problem:
  // setlocale returns "c" but it functions as utf8.  And Android doesn't
  // have setlocale at all.
  std::string locale = setlocale(LC_CTYPE, NULL);
  return " this test may have failed because the current LC_CTYPE locale is "
         "not utf8 (currently set to " +
         locale + ")";
#else
  return "";
#endif
}

void RunGenerateFileNameTestCase(const GenerateFilenameCase* test_case) {
  std::string default_filename(base::WideToUTF8(test_case->default_filename));
  base::FilePath file_path = GenerateFileName(
      GURL(test_case->url), test_case->content_disp_header,
      test_case->referrer_charset, test_case->suggested_filename,
      test_case->mime_type, default_filename);
  EXPECT_EQ(test_case->expected_filename, FilePathAsWString(file_path))
      << "test case at line number: " << test_case->lineno << "; "
      << GetLocaleWarningString();
}

}  // namespace

static const base::FilePath::CharType* kSafePortableBasenames[] = {
    FILE_PATH_LITERAL("a"),
    FILE_PATH_LITERAL("a.txt"),
    FILE_PATH_LITERAL("a b.txt"),
    FILE_PATH_LITERAL("a-b.txt"),
    FILE_PATH_LITERAL("My Computer"),
};

static const base::FilePath::CharType* kUnsafePortableBasenames[] = {
    FILE_PATH_LITERAL(""),
    FILE_PATH_LITERAL("."),
    FILE_PATH_LITERAL(".."),
    FILE_PATH_LITERAL("..."),
    FILE_PATH_LITERAL("con"),
    FILE_PATH_LITERAL("con.zip"),
    FILE_PATH_LITERAL("NUL"),
    FILE_PATH_LITERAL("NUL.zip"),
    FILE_PATH_LITERAL(".a"),
    FILE_PATH_LITERAL("a."),
    FILE_PATH_LITERAL("a\"a"),
    FILE_PATH_LITERAL("a<a"),
    FILE_PATH_LITERAL("a>a"),
    FILE_PATH_LITERAL("a?a"),
    FILE_PATH_LITERAL("a/"),
    FILE_PATH_LITERAL("a\\"),
    FILE_PATH_LITERAL("a "),
    FILE_PATH_LITERAL("a . ."),
    FILE_PATH_LITERAL(" Computer"),
    FILE_PATH_LITERAL("My Computer.{a}"),
    FILE_PATH_LITERAL("My Computer.{20D04FE0-3AEA-1069-A2D8-08002B30309D}"),
#if !defined(OS_WIN)
    FILE_PATH_LITERAL("a\\a"),
#endif
};

static const base::FilePath::CharType* kUnsafePortableBasenamesForWindows[] = {
    FILE_PATH_LITERAL("con"),
    FILE_PATH_LITERAL("con.zip"),
    FILE_PATH_LITERAL("NUL"),
    FILE_PATH_LITERAL("NUL.zip"),
};

static const base::FilePath::CharType* kSafePortableRelativePaths[] = {
    FILE_PATH_LITERAL("a/a"),
#if defined(OS_WIN)
    FILE_PATH_LITERAL("a\\a"),
#endif
};

TEST(FilenameUtilTest, IsSafePortablePathComponent) {
  for (size_t i = 0; i < arraysize(kSafePortableBasenames); ++i) {
    EXPECT_TRUE(
        IsSafePortablePathComponent(base::FilePath(kSafePortableBasenames[i])))
        << kSafePortableBasenames[i];
  }
  for (size_t i = 0; i < arraysize(kUnsafePortableBasenames); ++i) {
    EXPECT_FALSE(IsSafePortablePathComponent(
        base::FilePath(kUnsafePortableBasenames[i])))
        << kUnsafePortableBasenames[i];
  }
  for (size_t i = 0; i < arraysize(kSafePortableRelativePaths); ++i) {
    EXPECT_FALSE(IsSafePortablePathComponent(
        base::FilePath(kSafePortableRelativePaths[i])))
        << kSafePortableRelativePaths[i];
  }
}

TEST(FilenameUtilTest, IsSafePortableRelativePath) {
  base::FilePath safe_dirname(FILE_PATH_LITERAL("a"));
  for (size_t i = 0; i < arraysize(kSafePortableBasenames); ++i) {
    EXPECT_TRUE(
        IsSafePortableRelativePath(base::FilePath(kSafePortableBasenames[i])))
        << kSafePortableBasenames[i];
    EXPECT_TRUE(IsSafePortableRelativePath(
        safe_dirname.Append(base::FilePath(kSafePortableBasenames[i]))))
        << kSafePortableBasenames[i];
  }
  for (size_t i = 0; i < arraysize(kSafePortableRelativePaths); ++i) {
    EXPECT_TRUE(IsSafePortableRelativePath(
        base::FilePath(kSafePortableRelativePaths[i])))
        << kSafePortableRelativePaths[i];
    EXPECT_TRUE(IsSafePortableRelativePath(
        safe_dirname.Append(base::FilePath(kSafePortableRelativePaths[i]))))
        << kSafePortableRelativePaths[i];
  }
  for (size_t i = 0; i < arraysize(kUnsafePortableBasenames); ++i) {
    EXPECT_FALSE(
        IsSafePortableRelativePath(base::FilePath(kUnsafePortableBasenames[i])))
        << kUnsafePortableBasenames[i];
    if (!base::FilePath::StringType(kUnsafePortableBasenames[i]).empty()) {
      EXPECT_FALSE(IsSafePortableRelativePath(
          safe_dirname.Append(base::FilePath(kUnsafePortableBasenames[i]))))
          << kUnsafePortableBasenames[i];
    }
  }
}

TEST(FilenameUtilTest, FileURLConversion) {
  // a list of test file names and the corresponding URLs
  const FileCase round_trip_cases[] = {
#if defined(OS_WIN)
    {L"C:\\foo\\bar.txt", "file:///C:/foo/bar.txt"},
    {L"\\\\some computer\\foo\\bar.txt",
     "file://some%20computer/foo/bar.txt"},  // UNC
    {L"D:\\Name;with%some symbols*#",
     "file:///D:/Name%3Bwith%25some%20symbols*%23"},
    // issue 14153: To be tested with the OS default codepage other than 1252.
    {L"D:\\latin1\\caf\x00E9\x00DD.txt",
     "file:///D:/latin1/caf%C3%A9%C3%9D.txt"},
    {L"D:\\otherlatin\\caf\x0119.txt", "file:///D:/otherlatin/caf%C4%99.txt"},
    {L"D:\\greek\\\x03B1\x03B2\x03B3.txt",
     "file:///D:/greek/%CE%B1%CE%B2%CE%B3.txt"},
    {L"D:\\Chinese\\\x6240\x6709\x4e2d\x6587\x7f51\x9875.doc",
     "file:///D:/Chinese/%E6%89%80%E6%9C%89%E4%B8%AD%E6%96%87%E7%BD%91"
     "%E9%A1%B5.doc"},
    {L"D:\\plane1\\\xD835\xDC00\xD835\xDC01.txt",  // Math alphabet "AB"
     "file:///D:/plane1/%F0%9D%90%80%F0%9D%90%81.txt"},
#elif defined(OS_POSIX)
    {L"/foo/bar.txt", "file:///foo/bar.txt"},
    {L"/foo/BAR.txt", "file:///foo/BAR.txt"},
    {L"/C:/foo/bar.txt", "file:///C:/foo/bar.txt"},
    {L"/foo/bar?.txt", "file:///foo/bar%3F.txt"},
    {L"/some computer/foo/bar.txt", "file:///some%20computer/foo/bar.txt"},
    {L"/Name;with%some symbols*#", "file:///Name%3Bwith%25some%20symbols*%23"},
    {L"/latin1/caf\x00E9\x00DD.txt", "file:///latin1/caf%C3%A9%C3%9D.txt"},
    {L"/otherlatin/caf\x0119.txt", "file:///otherlatin/caf%C4%99.txt"},
    {L"/greek/\x03B1\x03B2\x03B3.txt", "file:///greek/%CE%B1%CE%B2%CE%B3.txt"},
    {L"/Chinese/\x6240\x6709\x4e2d\x6587\x7f51\x9875.doc",
     "file:///Chinese/%E6%89%80%E6%9C%89%E4%B8%AD%E6%96%87%E7%BD"
     "%91%E9%A1%B5.doc"},
    {L"/plane1/\x1D400\x1D401.txt",  // Math alphabet "AB"
     "file:///plane1/%F0%9D%90%80%F0%9D%90%81.txt"},
#endif
  };

  // First, we'll test that we can round-trip all of the above cases of URLs
  base::FilePath output;
  for (size_t i = 0; i < arraysize(round_trip_cases); i++) {
    // convert to the file URL
    GURL file_url(
        FilePathToFileURL(WStringAsFilePath(round_trip_cases[i].file)));
    EXPECT_EQ(round_trip_cases[i].url, file_url.spec());

    // Back to the filename.
    EXPECT_TRUE(FileURLToFilePath(file_url, &output));
    EXPECT_EQ(round_trip_cases[i].file, FilePathAsWString(output));
  }

  // Test that various file: URLs get decoded into the correct file type
  FileCase url_cases[] = {
#if defined(OS_WIN)
    {L"C:\\foo\\bar.txt", "file:c|/foo\\bar.txt"},
    {L"C:\\foo\\bar.txt", "file:/c:/foo/bar.txt"},
    {L"\\\\foo\\bar.txt", "file://foo\\bar.txt"},
    {L"C:\\foo\\bar.txt", "file:///c:/foo/bar.txt"},
    {L"\\\\foo\\bar.txt", "file:////foo\\bar.txt"},
    {L"\\\\foo\\bar.txt", "file:/foo/bar.txt"},
    {L"\\\\foo\\bar.txt", "file://foo\\bar.txt"},
    {L"C:\\foo\\bar.txt", "file:\\\\\\c:/foo/bar.txt"},
    // %2f ('/') and %5c ('\\') are left alone by both GURL and
    // FileURLToFilePath.
    {L"C:\\foo%2f..%5cbar", "file:///C:\\foo%2f..%5cbar"},
#elif defined(OS_POSIX)
    {L"/c:/foo/bar.txt", "file:/c:/foo/bar.txt"},
    {L"/c:/foo/bar.txt", "file:///c:/foo/bar.txt"},
    {L"/foo/bar.txt", "file:/foo/bar.txt"},
    {L"/c:/foo/bar.txt", "file:\\\\\\c:/foo/bar.txt"},
    {L"/foo/bar.txt", "file:foo/bar.txt"},
    {L"/bar.txt", "file://foo/bar.txt"},
    {L"/foo/bar.txt", "file:///foo/bar.txt"},
    {L"/foo/bar.txt", "file:////foo/bar.txt"},
    {L"/foo/bar.txt", "file:////foo//bar.txt"},
    {L"/foo/bar.txt", "file:////foo///bar.txt"},
    {L"/foo/bar.txt", "file:////foo////bar.txt"},
    {L"/c:/foo/bar.txt", "file:\\\\\\c:/foo/bar.txt"},
    {L"/c:/foo/bar.txt", "file:c:/foo/bar.txt"},
    // %2f ('/') and %5c ('\\') are left alone by both GURL and
    // FileURLToFilePath.
    {L"/foo%2f..%5cbar", "file:///foo%2f..%5cbar"},
//  We get these wrong because GURL turns back slashes into forward
//  slashes.
//  {L"/foo%5Cbar.txt", "file://foo\\bar.txt"},
//  {L"/c|/foo%5Cbar.txt", "file:c|/foo\\bar.txt"},
//  {L"/foo%5Cbar.txt", "file://foo\\bar.txt"},
//  {L"/foo%5Cbar.txt", "file:////foo\\bar.txt"},
//  {L"/foo%5Cbar.txt", "file://foo\\bar.txt"},
#endif
  };
  for (size_t i = 0; i < arraysize(url_cases); i++) {
    FileURLToFilePath(GURL(url_cases[i].url), &output);
    EXPECT_EQ(url_cases[i].file, FilePathAsWString(output));
  }

// Unfortunately, UTF8ToWide discards invalid UTF8 input.
#ifdef BUG_878908_IS_FIXED
  // Test that no conversion happens if the UTF-8 input is invalid, and that
  // the input is preserved in UTF-8
  const char invalid_utf8[] = "file:///d:/Blah/\xff.doc";
  const wchar_t invalid_wide[] = L"D:\\Blah\\\xff.doc";
  EXPECT_TRUE(FileURLToFilePath(GURL(std::string(invalid_utf8)), &output));
  EXPECT_EQ(std::wstring(invalid_wide), output);
#endif

  // Test that if a file URL is malformed, we get a failure
  EXPECT_FALSE(FileURLToFilePath(GURL("filefoobar"), &output));
}

#if defined(OS_WIN)
#define JPEG_EXT L".jpg"
#define HTML_EXT L".htm"
#elif defined(OS_MACOSX)
#define JPEG_EXT L".jpeg"
#define HTML_EXT L".html"
#else
#define JPEG_EXT L".jpg"
#define HTML_EXT L".html"
#endif
#define TXT_EXT L".txt"
#define TAR_EXT L".tar"

TEST(FilenameUtilTest, GenerateSafeFileName) {
  const struct {
    const char* mime_type;
    const base::FilePath::CharType* filename;
    const base::FilePath::CharType* expected_filename;
  } safe_tests[] = {
#if defined(OS_WIN)
    {"text/html",
     FILE_PATH_LITERAL("C:\\foo\\bar.htm"),
     FILE_PATH_LITERAL("C:\\foo\\bar.htm")},
    {"text/html",
     FILE_PATH_LITERAL("C:\\foo\\bar.html"),
     FILE_PATH_LITERAL("C:\\foo\\bar.html")},
    {"text/html",
     FILE_PATH_LITERAL("C:\\foo\\bar"),
     FILE_PATH_LITERAL("C:\\foo\\bar.htm")},
    {"image/png",
     FILE_PATH_LITERAL("C:\\bar.html"),
     FILE_PATH_LITERAL("C:\\bar.html")},
    {"image/png",
     FILE_PATH_LITERAL("C:\\bar"),
     FILE_PATH_LITERAL("C:\\bar.png")},
    {"text/html",
     FILE_PATH_LITERAL("C:\\foo\\bar.exe"),
     FILE_PATH_LITERAL("C:\\foo\\bar.exe")},
    {"image/gif",
     FILE_PATH_LITERAL("C:\\foo\\bar.exe"),
     FILE_PATH_LITERAL("C:\\foo\\bar.exe")},
    {"text/html",
     FILE_PATH_LITERAL("C:\\foo\\google.com"),
     FILE_PATH_LITERAL("C:\\foo\\google.com")},
    {"text/html",
     FILE_PATH_LITERAL("C:\\foo\\con.htm"),
     FILE_PATH_LITERAL("C:\\foo\\_con.htm")},
    {"text/html",
     FILE_PATH_LITERAL("C:\\foo\\con"),
     FILE_PATH_LITERAL("C:\\foo\\_con.htm")},
    {"text/html",
     FILE_PATH_LITERAL("C:\\foo\\harmless.{not-really-this-may-be-a-guid}"),
     FILE_PATH_LITERAL("C:\\foo\\harmless.download")},
    {"text/html",
     FILE_PATH_LITERAL("C:\\foo\\harmless.local"),
     FILE_PATH_LITERAL("C:\\foo\\harmless.download")},
    {"text/html",
     FILE_PATH_LITERAL("C:\\foo\\harmless.lnk"),
     FILE_PATH_LITERAL("C:\\foo\\harmless.download")},
    {"text/html",
     FILE_PATH_LITERAL("C:\\foo\\harmless.{mismatched-"),
     FILE_PATH_LITERAL("C:\\foo\\harmless.{mismatched-")},
    // Allow extension synonyms.
    {"image/jpeg",
     FILE_PATH_LITERAL("C:\\foo\\bar.jpg"),
     FILE_PATH_LITERAL("C:\\foo\\bar.jpg")},
    {"image/jpeg",
     FILE_PATH_LITERAL("C:\\foo\\bar.jpeg"),
     FILE_PATH_LITERAL("C:\\foo\\bar.jpeg")},
#else   // !defined(OS_WIN)
    {"text/html",
     FILE_PATH_LITERAL("/foo/bar.htm"),
     FILE_PATH_LITERAL("/foo/bar.htm")},
    {"text/html",
     FILE_PATH_LITERAL("/foo/bar.html"),
     FILE_PATH_LITERAL("/foo/bar.html")},
    {"text/html",
     FILE_PATH_LITERAL("/foo/bar"),
     FILE_PATH_LITERAL("/foo/bar.html")},
    {"image/png",
     FILE_PATH_LITERAL("/bar.html"),
     FILE_PATH_LITERAL("/bar.html")},
    {"image/png", FILE_PATH_LITERAL("/bar"), FILE_PATH_LITERAL("/bar.png")},
    {"image/gif",
     FILE_PATH_LITERAL("/foo/bar.exe"),
     FILE_PATH_LITERAL("/foo/bar.exe")},
    {"text/html",
     FILE_PATH_LITERAL("/foo/google.com"),
     FILE_PATH_LITERAL("/foo/google.com")},
    {"text/html",
     FILE_PATH_LITERAL("/foo/con.htm"),
     FILE_PATH_LITERAL("/foo/con.htm")},
    {"text/html",
     FILE_PATH_LITERAL("/foo/con"),
     FILE_PATH_LITERAL("/foo/con.html")},
    // Allow extension synonyms.
    {"image/jpeg",
     FILE_PATH_LITERAL("/bar.jpg"),
     FILE_PATH_LITERAL("/bar.jpg")},
    {"image/jpeg",
     FILE_PATH_LITERAL("/bar.jpeg"),
     FILE_PATH_LITERAL("/bar.jpeg")},
#endif  // !defined(OS_WIN)
  };

  for (size_t i = 0; i < arraysize(safe_tests); ++i) {
    base::FilePath file_path(safe_tests[i].filename);
    GenerateSafeFileName(safe_tests[i].mime_type, false, &file_path);
    EXPECT_EQ(safe_tests[i].expected_filename, file_path.value())
        << "Iteration " << i;
  }
}

TEST(FilenameUtilTest, GenerateFileName) {
  // Tests whether the correct filename is selected from the the given
  // parameters and that Content-Disposition headers are properly
  // handled including failovers when the header is malformed.
  const GenerateFilenameCase selection_tests[] = {
    {__LINE__,
     "http://www.google.com/",
     "attachment; filename=test.html",
     "",
     "",
     "",
     L"",
     L"test.html"},
    {__LINE__,
     "http://www.google.com/",
     "attachment; filename=\"test.html\"",
     "",
     "",
     "",
     L"",
     L"test.html"},
    {__LINE__,
     "http://www.google.com/",
     "attachment; filename= \"test.html\"",
     "",
     "",
     "",
     L"",
     L"test.html"},
    {__LINE__,
     "http://www.google.com/",
     "attachment; filename   =   \"test.html\"",
     "",
     "",
     "",
     L"",
     L"test.html"},
    {// filename is whitespace.  Should failover to URL host
     __LINE__,
     "http://www.google.com/",
     "attachment; filename=  ",
     "",
     "",
     "",
     L"",
     L"www.google.com"},
    {// No filename.
     __LINE__,
     "http://www.google.com/path/test.html",
     "attachment",
     "",
     "",
     "",
     L"",
     L"test.html"},
    {// Ditto
     __LINE__,
     "http://www.google.com/path/test.html",
     "attachment;",
     "",
     "",
     "",
     L"",
     L"test.html"},
    {// No C-D
     __LINE__,
     "http://www.google.com/",
     "",
     "",
     "",
     "",
     L"",
     L"www.google.com"},
    {__LINE__,
     "http://www.google.com/test.html",
     "",
     "",
     "",
     "",
     L"",
     L"test.html"},
    {// Now that we use src/url's ExtractFileName, this case falls back to
     // the hostname. If this behavior is not desirable, we'd better change
     // ExtractFileName (in url_parse.cc).
     __LINE__,
     "http://www.google.com/path/",
     "",
     "",
     "",
     "",
     L"",
     L"www.google.com"},
    {__LINE__, "http://www.google.com/path", "", "", "", "", L"", L"path"},
    {__LINE__, "file:///", "", "", "", "", L"", L"download"},
    {__LINE__, "file:///path/testfile", "", "", "", "", L"", L"testfile"},
    {__LINE__, "non-standard-scheme:", "", "", "", "", L"", L"download"},
    {// C-D should override default
     __LINE__,
     "http://www.google.com/",
     "attachment; filename =\"test.html\"",
     "",
     "",
     "",
     L"download",
     L"test.html"},
    {// But the URL shouldn't
     __LINE__,
     "http://www.google.com/",
     "",
     "",
     "",
     "",
     L"download",
     L"download"},
    {__LINE__,
     "http://www.google.com/",
     "attachment; filename=\"../test.html\"",
     "",
     "",
     "",
     L"",
     L"-test.html"},
    {__LINE__,
     "http://www.google.com/",
     "attachment; filename=\"..\\test.html\"",
     "",
     "",
     "",
     L"",
     L"test.html"},
    {__LINE__,
     "http://www.google.com/",
     "attachment; filename=\"..\\\\test.html\"",
     "",
     "",
     "",
     L"",
     L"-test.html"},
    {// Filename disappears after leading and trailing periods are removed.
     __LINE__,
     "http://www.google.com/",
     "attachment; filename=\"..\"",
     "",
     "",
     "",
     L"default",
     L"default"},
    {// C-D specified filename disappears.  Failover to final filename.
     __LINE__,
     "http://www.google.com/test.html",
     "attachment; filename=\"..\"",
     "",
     "",
     "",
     L"default",
     L"default"},
    // Below is a small subset of cases taken from HttpContentDisposition tests.
    {__LINE__,
     "http://www.google.com/",
     "attachment; filename=\"%EC%98%88%EC%88%A0%20"
     "%EC%98%88%EC%88%A0.jpg\"",
     "",
     "",
     "",
     L"",
     L"\uc608\uc220 \uc608\uc220.jpg"},
    {__LINE__,
     "http://www.google.com/%EC%98%88%EC%88%A0%20%EC%98%88%EC%88%A0.jpg",
     "",
     "",
     "",
     "",
     L"download",
     L"\uc608\uc220 \uc608\uc220.jpg"},
    {__LINE__,
     "http://www.google.com/",
     "attachment;",
     "",
     "",
     "",
     L"\uB2E4\uC6B4\uB85C\uB4DC",
     L"\uB2E4\uC6B4\uB85C\uB4DC"},
    {__LINE__,
     "http://www.google.com/",
     "attachment; filename=\"=?EUC-JP?Q?=B7=DD=BD="
     "D13=2Epng?=\"",
     "",
     "",
     "",
     L"download",
     L"\u82b8\u88533.png"},
    {__LINE__,
     "http://www.example.com/images?id=3",
     "attachment; filename=caf\xc3\xa9.png",
     "iso-8859-1",
     "",
     "",
     L"",
     L"caf\u00e9.png"},
    {__LINE__,
     "http://www.example.com/images?id=3",
     "attachment; filename=caf\xe5.png",
     "windows-1253",
     "",
     "",
     L"",
     L"caf\u03b5.png"},
    {// Invalid C-D header. Name value is skipped now.
     __LINE__,
     "http://www.example.com/file?id=3",
     "attachment; name=\xcf\xc2\xd4\xd8.zip",
     "GBK",
     "",
     "",
     L"",
     L"file"},
    {// Invalid C-D header. Extracts filename from url.
     __LINE__,
     "http://www.google.com/test.html",
     "attachment; filename==?iiso88591?Q?caf=EG?=",
     "",
     "",
     "",
     L"",
     L"test.html"},
    // about: and data: URLs
    {__LINE__, "about:chrome", "", "", "", "", L"", L"download"},
    {__LINE__, "data:,looks/like/a.path", "", "", "", "", L"", L"download"},
    {__LINE__,
     "data:text/plain;base64,VG8gYmUgb3Igbm90IHRvIGJlLg=",
     "",
     "",
     "",
     "",
     L"",
     L"download"},
    {__LINE__,
     "data:,looks/like/a.path",
     "",
     "",
     "",
     "",
     L"default_filename_is_given",
     L"default_filename_is_given"},
    {__LINE__,
     "data:,looks/like/a.path",
     "",
     "",
     "",
     "",
     L"\u65e5\u672c\u8a9e",  // Japanese Kanji.
     L"\u65e5\u672c\u8a9e"},
    {// The filename encoding is specified by the referrer charset.
     __LINE__,
     "http://example.com/V%FDvojov%E1%20psychologie.doc",
     "",
     "iso-8859-1",
     "",
     "",
     L"",
     L"V\u00fdvojov\u00e1 psychologie.doc"},
    {// Suggested filename takes precedence over URL
     __LINE__,
     "http://www.google.com/test",
     "",
     "",
     "suggested",
     "",
     L"",
     L"suggested"},
    {// The content-disposition has higher precedence over the suggested name.
     __LINE__,
     "http://www.google.com/test",
     "attachment; filename=test.html",
     "",
     "suggested",
     "",
     L"",
     L"test.html"},
    {__LINE__,
     "http://www.google.com/test",
     "attachment; filename=test",
     "utf-8",
     "",
     "image/png",
     L"",
     L"test"},
#if 0
    { // The filename encoding doesn't match the referrer charset, the system
      // charset, or UTF-8.
      // TODO(jshin): we need to handle this case.
      __LINE__,
      "http://example.com/V%FDvojov%E1%20psychologie.doc",
      "",
      "utf-8",
      "",
      "",
      L"",
      L"V\u00fdvojov\u00e1 psychologie.doc",
    },
#endif
    // Raw 8bit characters in C-D
    {__LINE__,
     "http://www.example.com/images?id=3",
     "attachment; filename=caf\xc3\xa9.png",
     "iso-8859-1",
     "",
     "image/png",
     L"",
     L"caf\u00e9.png"},
    {__LINE__,
     "http://www.example.com/images?id=3",
     "attachment; filename=caf\xe5.png",
     "windows-1253",
     "",
     "image/png",
     L"",
     L"caf\u03b5.png"},
    {// No 'filename' keyword in the disposition, use the URL
     __LINE__,
     "http://www.evil.com/my_download.txt",
     "a_file_name.txt",
     "",
     "",
     "text/plain",
     L"download",
     L"my_download.txt"},
    {// Spaces in the disposition file name
     __LINE__,
     "http://www.frontpagehacker.com/a_download.exe",
     "filename=My Downloaded File.exe",
     "",
     "",
     "application/octet-stream",
     L"download",
     L"My Downloaded File.exe"},
    {// % encoded
     __LINE__,
     "http://www.examples.com/",
     "attachment; "
     "filename=\"%EC%98%88%EC%88%A0%20%EC%98%88%EC%88%A0.jpg\"",
     "",
     "",
     "image/jpeg",
     L"download",
     L"\uc608\uc220 \uc608\uc220.jpg"},
    {// Invalid C-D header. Name value is skipped now.
     __LINE__,
     "http://www.examples.com/q.cgi?id=abc",
     "attachment; name=abc de.pdf",
     "",
     "",
     "application/octet-stream",
     L"download",
     L"q.cgi"},
    {__LINE__,
     "http://www.example.com/path",
     "filename=\"=?EUC-JP?Q?=B7=DD=BD=D13=2Epng?=\"",
     "",
     "",
     "image/png",
     L"download",
     L"\x82b8\x8853"
     L"3.png"},
    {// The following two have invalid CD headers and filenames come from the
     // URL.
     __LINE__,
     "http://www.example.com/test%20123",
     "attachment; filename==?iiso88591?Q?caf=EG?=",
     "",
     "",
     "image/jpeg",
     L"download",
     L"test 123" JPEG_EXT},
    {__LINE__,
     "http://www.google.com/%EC%98%88%EC%88%A0%20%EC%98%88%EC%88%A0.jpg",
     "malformed_disposition",
     "",
     "",
     "image/jpeg",
     L"download",
     L"\uc608\uc220 \uc608\uc220.jpg"},
    {// Invalid C-D. No filename from URL. Falls back to 'download'.
     __LINE__,
     "http://www.google.com/path1/path2/",
     "attachment; filename==?iso88591?Q?caf=E3?",
     "",
     "",
     "image/jpeg",
     L"download",
     L"download" JPEG_EXT},
  };

  // Tests filename generation.  Once the correct filename is
  // selected, they should be passed through the validation steps and
  // a correct extension should be added if necessary.
  const GenerateFilenameCase generation_tests[] = {
    // Dotfiles. Ensures preceeding period(s) stripped.
    {__LINE__, "http://www.google.com/.test.html", "", "", "", "", L"",
     L"test.html"},
    {__LINE__, "http://www.google.com/.test", "", "", "", "", L"", L"test"},
    {__LINE__, "http://www.google.com/..test", "", "", "", "", L"", L"test"},
    {// Disposition has relative paths, remove directory separators
     __LINE__, "http://www.evil.com/my_download.txt",
     "filename=../../../../././../a_file_name.txt", "", "", "text/plain",
     L"download", L"-..-..-..-.-.-..-a_file_name.txt"},
    {// Disposition has parent directories, remove directory separators
     __LINE__, "http://www.evil.com/my_download.txt",
     "filename=dir1/dir2/a_file_name.txt", "", "", "text/plain", L"download",
     L"dir1-dir2-a_file_name.txt"},
    {// Disposition has relative paths, remove directory separators
     __LINE__, "http://www.evil.com/my_download.txt",
     "filename=..\\..\\..\\..\\.\\.\\..\\a_file_name.txt", "", "", "text/plain",
     L"download", L"-..-..-..-.-.-..-a_file_name.txt"},
    {// Disposition has parent directories, remove directory separators
     __LINE__, "http://www.evil.com/my_download.txt",
     "filename=dir1\\dir2\\a_file_name.txt", "", "", "text/plain", L"download",
     L"dir1-dir2-a_file_name.txt"},
    {// No useful information in disposition or URL, use default
     __LINE__, "http://www.truncated.com/path/", "", "", "", "text/plain",
     L"download", L"download" TXT_EXT},
    {// Filename looks like HTML?
     __LINE__, "http://www.evil.com/get/malware/here",
     "filename=\"<blink>Hello kitty</blink>\"", "", "", "text/plain",
     L"default", L"-blink-Hello kitty--blink-"},
    {// A normal avi should get .avi and not .avi.avi
     __LINE__, "https://blah.google.com/misc/2.avi", "", "", "",
     "video/x-msvideo", L"download", L"2.avi"},
    {// Shouldn't unescape slashes.
     __LINE__, "http://www.example.com/foo%2f..%2fbar.jpg", "", "", "",
     "text/plain", L"download", L"foo%2f..%2fbar.jpg"},
    {// Extension generation
     __LINE__, "http://www.example.com/my-cat", "filename=my-cat", "", "",
     "image/jpeg", L"download", L"my-cat"},
    {__LINE__, "http://www.example.com/my-cat", "filename=my-cat", "", "",
     "text/plain", L"download", L"my-cat"},
    {__LINE__, "http://www.example.com/my-cat", "filename=my-cat", "", "",
     "text/html", L"download", L"my-cat"},
    {// Unknown MIME type
     __LINE__, "http://www.example.com/my-cat", "filename=my-cat", "", "",
     "dance/party", L"download", L"my-cat"},
    {__LINE__, "http://www.example.com/my-cat.jpg", "filename=my-cat.jpg", "",
     "", "text/plain", L"download", L"my-cat.jpg"},
// Windows specific tests
#if defined(OS_WIN)
    {__LINE__, "http://www.goodguy.com/evil.exe", "filename=evil.exe", "", "",
     "image/jpeg", L"download", L"evil.exe"},
    {__LINE__, "http://www.goodguy.com/ok.exe", "filename=ok.exe", "", "",
     "binary/octet-stream", L"download", L"ok.exe"},
    {__LINE__, "http://www.goodguy.com/evil.dll", "filename=evil.dll", "", "",
     "dance/party", L"download", L"evil.dll"},
    {__LINE__, "http://www.goodguy.com/evil.exe", "filename=evil", "", "",
     "application/rss+xml", L"download", L"evil"},
    // Test truncation of trailing dots and spaces
    {__LINE__, "http://www.goodguy.com/evil.exe ", "filename=evil.exe ", "", "",
     "binary/octet-stream", L"download", L"evil.exe"},
    {__LINE__, "http://www.goodguy.com/evil.exe.", "filename=evil.exe.", "", "",
     "binary/octet-stream", L"download", L"evil.exe-"},
    {__LINE__, "http://www.goodguy.com/evil.exe.  .  .",
     "filename=evil.exe.  .  .", "", "", "binary/octet-stream", L"download",
     L"evil.exe-------"},
    {__LINE__, "http://www.goodguy.com/evil.", "filename=evil.", "", "",
     "binary/octet-stream", L"download", L"evil-"},
    {__LINE__, "http://www.goodguy.com/. . . . .", "filename=. . . . .", "", "",
     "binary/octet-stream", L"download", L"download"},
    {__LINE__, "http://www.badguy.com/attachment?name=meh.exe%C2%A0",
     "attachment; filename=\"meh.exe\xC2\xA0\"", "", "", "binary/octet-stream",
     L"", L"meh.exe-"},
#endif  // OS_WIN
    {__LINE__, "http://www.goodguy.com/utils.js", "filename=utils.js", "", "",
     "application/x-javascript", L"download", L"utils.js"},
    {__LINE__, "http://www.goodguy.com/contacts.js", "filename=contacts.js", "",
     "", "application/json", L"download", L"contacts.js"},
    {__LINE__, "http://www.goodguy.com/utils.js", "filename=utils.js", "", "",
     "text/javascript", L"download", L"utils.js"},
    {__LINE__, "http://www.goodguy.com/utils.js", "filename=utils.js", "", "",
     "text/javascript;version=2", L"download", L"utils.js"},
    {__LINE__, "http://www.goodguy.com/utils.js", "filename=utils.js", "", "",
     "application/ecmascript", L"download", L"utils.js"},
    {__LINE__, "http://www.goodguy.com/utils.js", "filename=utils.js", "", "",
     "application/ecmascript;version=4", L"download", L"utils.js"},
    {__LINE__, "http://www.goodguy.com/program.exe", "filename=program.exe", "",
     "", "application/foo-bar", L"download", L"program.exe"},
    {__LINE__, "http://www.evil.com/../foo.txt", "filename=../foo.txt", "", "",
     "text/plain", L"download", L"-foo.txt"},
    {__LINE__, "http://www.evil.com/..\\foo.txt", "filename=..\\foo.txt", "",
     "", "text/plain", L"download", L"-foo.txt"},
    {__LINE__, "http://www.evil.com/.hidden", "filename=.hidden", "", "",
     "text/plain", L"download", L"hidden"},
    {__LINE__, "http://www.evil.com/trailing.", "filename=trailing.", "", "",
     "dance/party", L"download",
#if defined(OS_WIN)
     L"trailing-"
#else
     L"trailing"
#endif
    },
    {__LINE__, "http://www.evil.com/trailing.", "filename=trailing.", "", "",
     "text/plain", L"download",
#if defined(OS_WIN)
     L"trailing-"
#else
     L"trailing"
#endif
    },
    {__LINE__, "http://www.evil.com/.", "filename=.", "", "", "dance/party",
     L"download", L"download"},
    {__LINE__, "http://www.evil.com/..", "filename=..", "", "", "dance/party",
     L"download", L"download"},
    {__LINE__, "http://www.evil.com/...", "filename=...", "", "", "dance/party",
     L"download", L"download"},
    {// Note that this one doesn't have "filename=" on it.
     __LINE__, "http://www.evil.com/", "a_file_name.txt", "", "", "image/jpeg",
     L"download", L"download" JPEG_EXT},
    {__LINE__, "http://www.evil.com/", "filename=", "", "", "image/jpeg",
     L"download", L"download" JPEG_EXT},
    {__LINE__, "http://www.example.com/simple", "filename=simple", "", "",
     "application/octet-stream", L"download", L"simple"},
    // Reserved words on Windows
    {__LINE__, "http://www.goodguy.com/COM1", "filename=COM1", "", "",
     "application/foo-bar", L"download",
#if defined(OS_WIN)
     L"_COM1"
#else
     L"COM1"
#endif
    },
    {__LINE__, "http://www.goodguy.com/COM4.txt", "filename=COM4.txt", "", "",
     "text/plain", L"download",
#if defined(OS_WIN)
     L"_COM4.txt"
#else
     L"COM4.txt"
#endif
    },
    {__LINE__, "http://www.goodguy.com/lpt1.TXT", "filename=lpt1.TXT", "", "",
     "text/plain", L"download",
#if defined(OS_WIN)
     L"_lpt1.TXT"
#else
     L"lpt1.TXT"
#endif
    },
    {__LINE__, "http://www.goodguy.com/clock$.txt", "filename=clock$.txt", "",
     "", "text/plain", L"download",
#if defined(OS_WIN)
     L"_clock$.txt"
#else
     L"clock$.txt"
#endif
    },
    {// Validation should also apply to sugested name
     __LINE__, "http://www.goodguy.com/blah$.txt", "filename=clock$.txt", "",
     "clock$.txt", "text/plain", L"download",
#if defined(OS_WIN)
     L"_clock$.txt"
#else
     L"clock$.txt"
#endif
    },
    {__LINE__, "http://www.goodguy.com/mycom1.foo", "filename=mycom1.foo", "",
     "", "text/plain", L"download", L"mycom1.foo"},
    {__LINE__, "http://www.badguy.com/Setup.exe.local",
     "filename=Setup.exe.local", "", "", "application/foo-bar", L"download",
#if defined(OS_WIN)
     L"Setup.exe.download"
#else
     L"Setup.exe.local"
#endif
    },
    {__LINE__, "http://www.badguy.com/Setup.exe.local",
     "filename=Setup.exe.local.local", "", "", "application/foo-bar",
     L"download",
#if defined(OS_WIN)
     L"Setup.exe.local.download"
#else
     L"Setup.exe.local.local"
#endif
    },
    {__LINE__, "http://www.badguy.com/Setup.exe.lnk", "filename=Setup.exe.lnk",
     "", "", "application/foo-bar", L"download",
#if defined(OS_WIN)
     L"Setup.exe.download"
#else
     L"Setup.exe.lnk"
#endif
    },
    {__LINE__, "http://www.badguy.com/Desktop.ini", "filename=Desktop.ini", "",
     "", "application/foo-bar", L"download",
#if defined(OS_WIN)
     L"_Desktop.ini"
#else
     L"Desktop.ini"
#endif
    },
    {__LINE__, "http://www.badguy.com/Thumbs.db", "filename=Thumbs.db", "", "",
     "application/foo-bar", L"download",
#if defined(OS_WIN)
     L"_Thumbs.db"
#else
     L"Thumbs.db"
#endif
    },
    {__LINE__, "http://www.hotmail.com", "filename=source.jpg", "", "",
     "application/x-javascript", L"download", L"source.jpg"},
    {// http://crbug.com/5772.
     __LINE__, "http://www.example.com/foo.tar.gz", "", "", "",
     "application/x-tar", L"download", L"foo.tar.gz"},
    {// http://crbug.com/52250.
     __LINE__, "http://www.example.com/foo.tgz", "", "", "",
     "application/x-tar", L"download", L"foo.tgz"},
    {// http://crbug.com/7337.
     __LINE__, "http://maged.lordaeron.org/blank.reg", "", "", "",
     "text/x-registry", L"download", L"blank.reg"},
    {__LINE__, "http://www.example.com/bar.tar", "", "", "",
     "application/x-tar", L"download", L"bar.tar"},
    {__LINE__, "http://www.example.com/bar.bogus", "", "", "",
     "application/x-tar", L"download", L"bar.bogus"},
    {// http://crbug.com/20337
     __LINE__, "http://www.example.com/.download.txt", "filename=.download.txt",
     "", "", "text/plain", L"-download", L"download.txt"},
    {// http://crbug.com/56855.
     __LINE__, "http://www.example.com/bar.sh", "", "", "", "application/x-sh",
     L"download", L"bar.sh"},
    {// http://crbug.com/61571
     __LINE__, "http://www.example.com/npdf.php?fn=foobar.pdf", "", "", "",
     "text/plain", L"download", L"npdf" TXT_EXT},
    {// Shouldn't overwrite C-D specified extension.
     __LINE__, "http://www.example.com/npdf.php?fn=foobar.pdf",
     "filename=foobar.jpg", "", "", "text/plain", L"download", L"foobar.jpg"},
    {// http://crbug.com/87719
     __LINE__, "http://www.example.com/image.aspx?id=blargh", "", "", "",
     "image/jpeg", L"download", L"image" JPEG_EXT},
    {__LINE__, "http://www.example.com/image.aspx?id=blargh", "", "", " .foo",
     "", L"download", L"-.foo"},

    // Note that the next 4 tests will not fail on all platforms on regression.
    // They only fail if application/[x-]gzip has a default extension, which
    // can vary across platforms (And even by OS install).
    {__LINE__, "http://www.example.com/goat.tar.gz?wearing_hat=true", "", "",
     "", "application/gzip", L"", L"goat.tar.gz"},
    {__LINE__, "http://www.example.com/goat.tar.gz?wearing_hat=true", "", "",
     "", "application/x-gzip", L"", L"goat.tar.gz"},
    {__LINE__, "http://www.example.com/goat.tgz?wearing_hat=true", "", "", "",
     "application/gzip", L"", L"goat.tgz"},
    {__LINE__, "http://www.example.com/goat.tgz?wearing_hat=true", "", "", "",
     "application/x-gzip", L"", L"goat.tgz"},

#if defined(OS_CHROMEOS)
    {// http://crosbug.com/26028
     __LINE__, "http://www.example.com/fooa%cc%88.txt", "", "", "",
     "image/jpeg", L"foo\xe4", L"foo\xe4.txt"},
#endif
  };

  for (size_t i = 0; i < arraysize(selection_tests); ++i)
    RunGenerateFileNameTestCase(&selection_tests[i]);

  for (size_t i = 0; i < arraysize(generation_tests); ++i)
    RunGenerateFileNameTestCase(&generation_tests[i]);

  for (size_t i = 0; i < arraysize(generation_tests); ++i) {
    GenerateFilenameCase test_case = generation_tests[i];
    test_case.referrer_charset = "GBK";
    RunGenerateFileNameTestCase(&test_case);
  }
}

TEST(FilenameUtilTest, IsReservedNameOnWindows) {
  for (size_t i = 0; i < arraysize(kSafePortableBasenames); ++i) {
    EXPECT_FALSE(IsReservedNameOnWindows(
        base::FilePath(kSafePortableBasenames[i]).value()))
        << kSafePortableBasenames[i];
  }

  for (size_t i = 0; i < arraysize(kUnsafePortableBasenamesForWindows); ++i) {
    EXPECT_TRUE(IsReservedNameOnWindows(
        base::FilePath(kUnsafePortableBasenamesForWindows[i]).value()))
        << kUnsafePortableBasenamesForWindows[i];
  }
}

}  // namespace net
