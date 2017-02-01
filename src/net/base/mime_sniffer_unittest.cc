// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/mime_sniffer.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {
namespace {

using ::testing::Range;
using ::testing::Values;
using ::net::SniffMimeType;  // It is shadowed by SniffMimeType(), below.

struct SnifferTest {
  const char* content;
  size_t content_len;
  std::string url;
  std::string type_hint;
  const char* mime_type;
};

static void TestArray(SnifferTest* tests, size_t count) {
  std::string mime_type;

  for (size_t i = 0; i < count; ++i) {
    SniffMimeType(tests[i].content,
                       tests[i].content_len,
                       GURL(tests[i].url),
                       tests[i].type_hint,
                       &mime_type);
    EXPECT_EQ(tests[i].mime_type, mime_type);
  }
}

// TODO(evanm): convert other tests to use SniffMimeType instead of TestArray,
// so the error messages produced by test failures are more useful.
static std::string SniffMimeType(const std::string& content,
                                 const std::string& url,
                                 const std::string& mime_type_hint) {
  std::string mime_type;
  SniffMimeType(content.data(), content.size(), GURL(url),
                     mime_type_hint, &mime_type);
  return mime_type;
}

TEST(MimeSnifferTest, BoundaryConditionsTest) {
  std::string mime_type;
  std::string type_hint;

  char buf[] = {
    'd', '\x1f', '\xFF'
  };

  GURL url;

  SniffMimeType(buf, 0, url, type_hint, &mime_type);
  EXPECT_EQ("text/plain", mime_type);
  SniffMimeType(buf, 1, url, type_hint, &mime_type);
  EXPECT_EQ("text/plain", mime_type);
  SniffMimeType(buf, 2, url, type_hint, &mime_type);
  EXPECT_EQ("application/octet-stream", mime_type);
}

TEST(MimeSnifferTest, BasicSniffingTest) {
  SnifferTest tests[] = {
    { "<!DOCTYPE html PUBLIC", sizeof("<!DOCTYPE html PUBLIC")-1,
      "http://www.example.com/",
      "", "text/html" },
    { "<HtMl><Body></body></htMl>", sizeof("<HtMl><Body></body></htMl>")-1,
      "http://www.example.com/foo.gif",
      "application/octet-stream", "application/octet-stream" },
    { "GIF89a\x1F\x83\x94", sizeof("GIF89a\xAF\x83\x94")-1,
      "http://www.example.com/foo",
      "text/plain", "image/gif" },
    { "Gif87a\x1F\x83\x94", sizeof("Gif87a\xAF\x83\x94")-1,
      "http://www.example.com/foo?param=tt.gif",
      "", "application/octet-stream" },
    { "%!PS-Adobe-3.0", sizeof("%!PS-Adobe-3.0")-1,
      "http://www.example.com/foo",
      "text/plain", "text/plain" },
    { "\x89" "PNG\x0D\x0A\x1A\x0A", sizeof("\x89" "PNG\x0D\x0A\x1A\x0A")-1,
      "http://www.example.com/foo",
      "application/octet-stream", "application/octet-stream" },
    { "\xFF\xD8\xFF\x23\x49\xAF", sizeof("\xFF\xD8\xFF\x23\x49\xAF")-1,
      "http://www.example.com/foo",
      "", "image/jpeg" },
  };

  TestArray(tests, arraysize(tests));
}

TEST(MimeSnifferTest, ChromeExtensionsTest) {
  SnifferTest tests[] = {
    // schemes
    { "Cr24\x02\x00\x00\x00", sizeof("Cr24\x02\x00\x00\x00")-1,
      "http://www.example.com/foo.crx",
      "", "application/x-chrome-extension" },
    { "Cr24\x02\x00\x00\x00", sizeof("Cr24\x02\x00\x00\x00")-1,
      "https://www.example.com/foo.crx",
      "", "application/x-chrome-extension" },
    { "Cr24\x02\x00\x00\x00", sizeof("Cr24\x02\x00\x00\x00")-1,
      "ftp://www.example.com/foo.crx",
      "", "application/x-chrome-extension" },

    // some other mimetypes that should get converted
    { "Cr24\x02\x00\x00\x00", sizeof("Cr24\x02\x00\x00\x00")-1,
      "http://www.example.com/foo.crx",
      "text/plain", "application/x-chrome-extension" },
    { "Cr24\x02\x00\x00\x00", sizeof("Cr24\x02\x00\x00\x00")-1,
      "http://www.example.com/foo.crx",
      "application/octet-stream", "application/x-chrome-extension" },

    // success edge cases
    { "Cr24\x02\x00\x00\x00", sizeof("Cr24\x02\x00\x00\x00")-1,
      "http://www.example.com/foo.crx?query=string",
      "", "application/x-chrome-extension" },
    { "Cr24\x02\x00\x00\x00", sizeof("Cr24\x02\x00\x00\x00")-1,
      "http://www.example.com/foo..crx",
      "", "application/x-chrome-extension" },

    // wrong file extension
    { "Cr24\x02\x00\x00\x00", sizeof("Cr24\x02\x00\x00\x00")-1,
      "http://www.example.com/foo.bin",
      "", "application/octet-stream" },
    { "Cr24\x02\x00\x00\x00", sizeof("Cr24\x02\x00\x00\x00")-1,
      "http://www.example.com/foo.bin?monkey",
      "", "application/octet-stream" },
    { "Cr24\x02\x00\x00\x00", sizeof("Cr24\x02\x00\x00\x00")-1,
      "invalid-url",
      "", "application/octet-stream" },
    { "Cr24\x02\x00\x00\x00", sizeof("Cr24\x02\x00\x00\x00")-1,
      "http://www.example.com",
      "", "application/octet-stream" },
    { "Cr24\x02\x00\x00\x00", sizeof("Cr24\x02\x00\x00\x00")-1,
      "http://www.example.com/",
      "", "application/octet-stream" },
    { "Cr24\x02\x00\x00\x00", sizeof("Cr24\x02\x00\x00\x00")-1,
      "http://www.example.com/foo",
      "", "application/octet-stream" },
    { "Cr24\x02\x00\x00\x00", sizeof("Cr24\x02\x00\x00\x00")-1,
      "http://www.example.com/foocrx",
      "", "application/octet-stream" },
    { "Cr24\x02\x00\x00\x00", sizeof("Cr24\x02\x00\x00\x00")-1,
      "http://www.example.com/foo.crx.blech",
      "", "application/octet-stream" },

    // wrong magic
    { "Cr24\x02\x00\x00\x01", sizeof("Cr24\x02\x00\x00\x01")-1,
      "http://www.example.com/foo.crx?monkey",
      "", "application/octet-stream" },
    { "PADDING_Cr24\x02\x00\x00\x00", sizeof("PADDING_Cr24\x02\x00\x00\x00")-1,
      "http://www.example.com/foo.crx?monkey",
      "", "application/octet-stream" },
  };

  TestArray(tests, arraysize(tests));
}

TEST(MimeSnifferTest, MozillaCompatibleTest) {
  SnifferTest tests[] = {
    { " \n <hTmL>\n <hea", sizeof(" \n <hTmL>\n <hea")-1,
      "http://www.example.com/",
      "", "text/html" },
    { " \n <hTmL>\n <hea", sizeof(" \n <hTmL>\n <hea")-1,
      "http://www.example.com/",
      "text/plain", "text/plain" },
    { "BMjlakdsfk", sizeof("BMjlakdsfk")-1,
      "http://www.example.com/foo",
      "", "image/bmp" },
    { "\x00\x00\x30\x00", sizeof("\x00\x00\x30\x00")-1,
      "http://www.example.com/favicon.ico",
      "", "application/octet-stream" },
    { "#!/bin/sh\nls /\n", sizeof("#!/bin/sh\nls /\n")-1,
      "http://www.example.com/foo",
      "", "text/plain" },
    { "From: Fred\nTo: Bob\n\nHi\n.\n",
      sizeof("From: Fred\nTo: Bob\n\nHi\n.\n")-1,
      "http://www.example.com/foo",
      "", "text/plain" },
    { "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
      sizeof("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")-1,
      "http://www.example.com/foo",
      "", "text/xml" },
    { "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
      sizeof("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")-1,
      "http://www.example.com/foo",
      "application/octet-stream", "application/octet-stream" },
  };

  TestArray(tests, arraysize(tests));
}

TEST(MimeSnifferTest, DontAllowPrivilegeEscalationTest) {
  SnifferTest tests[] = {
    { "GIF87a\n<html>\n<body>"
        "<script>alert('haxorzed');\n</script>"
        "</body></html>\n",
      sizeof("GIF87a\n<html>\n<body>"
        "<script>alert('haxorzed');\n</script>"
        "</body></html>\n")-1,
      "http://www.example.com/foo",
      "", "image/gif" },
    { "GIF87a\n<html>\n<body>"
        "<script>alert('haxorzed');\n</script>"
        "</body></html>\n",
      sizeof("GIF87a\n<html>\n<body>"
        "<script>alert('haxorzed');\n</script>"
        "</body></html>\n")-1,
      "http://www.example.com/foo?q=ttt.html",
      "", "image/gif" },
    { "GIF87a\n<html>\n<body>"
        "<script>alert('haxorzed');\n</script>"
        "</body></html>\n",
      sizeof("GIF87a\n<html>\n<body>"
        "<script>alert('haxorzed');\n</script>"
        "</body></html>\n")-1,
      "http://www.example.com/foo#ttt.html",
      "", "image/gif" },
    { "a\n<html>\n<body>"
        "<script>alert('haxorzed');\n</script>"
        "</body></html>\n",
      sizeof("a\n<html>\n<body>"
        "<script>alert('haxorzed');\n</script>"
        "</body></html>\n")-1,
      "http://www.example.com/foo",
      "", "text/plain" },
    { "a\n<html>\n<body>"
        "<script>alert('haxorzed');\n</script>"
        "</body></html>\n",
      sizeof("a\n<html>\n<body>"
        "<script>alert('haxorzed');\n</script>"
        "</body></html>\n")-1,
      "http://www.example.com/foo?q=ttt.html",
      "", "text/plain" },
    { "a\n<html>\n<body>"
        "<script>alert('haxorzed');\n</script>"
        "</body></html>\n",
      sizeof("a\n<html>\n<body>"
        "<script>alert('haxorzed');\n</script>"
        "</body></html>\n")-1,
      "http://www.example.com/foo#ttt.html",
      "", "text/plain" },
    { "a\n<html>\n<body>"
        "<script>alert('haxorzed');\n</script>"
        "</body></html>\n",
      sizeof("a\n<html>\n<body>"
        "<script>alert('haxorzed');\n</script>"
        "</body></html>\n")-1,
      "http://www.example.com/foo.html",
      "", "text/plain" },
  };

  TestArray(tests, arraysize(tests));
}

TEST(MimeSnifferTest, UnicodeTest) {
  SnifferTest tests[] = {
    { "\xEF\xBB\xBF" "Hi there", sizeof("\xEF\xBB\xBF" "Hi there")-1,
      "http://www.example.com/foo",
      "", "text/plain" },
    { "\xEF\xBB\xBF\xED\x7A\xAD\x7A\x0D\x79",
      sizeof("\xEF\xBB\xBF\xED\x7A\xAD\x7A\x0D\x79")-1,
      "http://www.example.com/foo",
      "", "text/plain" },
    { "\xFE\xFF\xD0\xA5\xD0\xBE\xD0\xBB\xD1\x83\xD0\xB9",
      sizeof("\xFE\xFF\xD0\xA5\xD0\xBE\xD0\xBB\xD1\x83\xD0\xB9")-1,
      "http://www.example.com/foo",
      "", "text/plain" },
    { "\xFE\xFF\x00\x41\x00\x20\xD8\x00\xDC\x00\xD8\x00\xDC\x01",
      sizeof("\xFE\xFF\x00\x41\x00\x20\xD8\x00\xDC\x00\xD8\x00\xDC\x01")-1,
      "http://www.example.com/foo",
      "", "text/plain" },
  };

  TestArray(tests, arraysize(tests));
}

TEST(MimeSnifferTest, FlashTest) {
  SnifferTest tests[] = {
    { "CWSdd\x00\xB3", sizeof("CWSdd\x00\xB3")-1,
      "http://www.example.com/foo",
      "", "application/octet-stream" },
    { "FLVjdkl*(#)0sdj\x00", sizeof("FLVjdkl*(#)0sdj\x00")-1,
      "http://www.example.com/foo?q=ttt.swf",
      "", "application/octet-stream" },
    { "FWS3$9\r\b\x00", sizeof("FWS3$9\r\b\x00")-1,
      "http://www.example.com/foo#ttt.swf",
      "", "application/octet-stream" },
    { "FLVjdkl*(#)0sdj", sizeof("FLVjdkl*(#)0sdj")-1,
      "http://www.example.com/foo.swf",
      "", "text/plain" },
    { "FLVjdkl*(#)0s\x01dj", sizeof("FLVjdkl*(#)0s\x01dj")-1,
      "http://www.example.com/foo/bar.swf",
      "", "application/octet-stream" },
    { "FWS3$9\r\b\x1A", sizeof("FWS3$9\r\b\x1A")-1,
      "http://www.example.com/foo.swf?clickTAG=http://www.adnetwork.com/bar",
      "", "application/octet-stream" },
    { "FWS3$9\r\x1C\b", sizeof("FWS3$9\r\x1C\b")-1,
      "http://www.example.com/foo.swf?clickTAG=http://www.adnetwork.com/bar",
      "text/plain", "application/octet-stream" },
  };

  TestArray(tests, arraysize(tests));
}

TEST(MimeSnifferTest, XMLTest) {
  // An easy feed to identify.
  EXPECT_EQ("application/atom+xml",
            SniffMimeType("<?xml?><feed", std::string(), "text/xml"));
  // Don't sniff out of plain text.
  EXPECT_EQ("text/plain",
            SniffMimeType("<?xml?><feed", std::string(), "text/plain"));
  // Simple RSS.
  EXPECT_EQ("application/rss+xml",
            SniffMimeType(
                "<?xml version='1.0'?>\r\n<rss", std::string(), "text/xml"));

  // The top of CNN's RSS feed, which we'd like to recognize as RSS.
  static const char kCNNRSS[] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<?xml-stylesheet href=\"http://rss.cnn.com/~d/styles/rss2full.xsl\" "
      "type=\"text/xsl\" media=\"screen\"?>"
      "<?xml-stylesheet href=\"http://rss.cnn.com/~d/styles/itemcontent.css\" "
      "type=\"text/css\" media=\"screen\"?>"
      "<rss xmlns:feedburner=\"http://rssnamespace.org/feedburner/ext/1.0\" "
      "version=\"2.0\">";
  // CNN's RSS
  EXPECT_EQ("application/rss+xml",
            SniffMimeType(kCNNRSS, std::string(), "text/xml"));
  EXPECT_EQ("text/plain", SniffMimeType(kCNNRSS, std::string(), "text/plain"));

  // Don't sniff random XML as something different.
  EXPECT_EQ("text/xml",
            SniffMimeType("<?xml?><notafeed", std::string(), "text/xml"));
  // Don't sniff random plain-text as something different.
  EXPECT_EQ("text/plain",
            SniffMimeType("<?xml?><notafeed", std::string(), "text/plain"));

  // Positive test for the two instances we upgrade to XHTML.
  EXPECT_EQ("application/xhtml+xml",
            SniffMimeType("<html xmlns=\"http://www.w3.org/1999/xhtml\">",
                          std::string(),
                          "text/xml"));
  EXPECT_EQ("application/xhtml+xml",
            SniffMimeType("<html xmlns=\"http://www.w3.org/1999/xhtml\">",
                          std::string(),
                          "application/xml"));

  // Following our behavior with HTML, don't call other mime types XHTML.
  EXPECT_EQ("text/plain",
            SniffMimeType("<html xmlns=\"http://www.w3.org/1999/xhtml\">",
                          std::string(),
                          "text/plain"));
  EXPECT_EQ("application/rss+xml",
            SniffMimeType("<html xmlns=\"http://www.w3.org/1999/xhtml\">",
                          std::string(),
                          "application/rss+xml"));

  // Don't sniff other HTML-looking bits as HTML.
  EXPECT_EQ("text/xml",
            SniffMimeType("<html><head>", std::string(), "text/xml"));
  EXPECT_EQ("text/xml",
            SniffMimeType("<foo><html xmlns=\"http://www.w3.org/1999/xhtml\">",
                          std::string(),
                          "text/xml"));
}

// Test content which is >= 1024 bytes, and includes no open angle bracket.
// http://code.google.com/p/chromium/issues/detail?id=3521
TEST(MimeSnifferTest, XMLTestLargeNoAngledBracket) {
  // Make a large input, with 1024 bytes of "x".
  std::string content;
  content.resize(1024);
  std::fill(content.begin(), content.end(), 'x');

  // content.size() >= 1024 so the sniff is unambiguous.
  std::string mime_type;
  EXPECT_TRUE(SniffMimeType(content.data(), content.size(), GURL(),
                            "text/xml", &mime_type));
  EXPECT_EQ("text/xml", mime_type);
}

// Test content which is >= 1024 bytes, and includes a binary looking byte.
// http://code.google.com/p/chromium/issues/detail?id=15314
TEST(MimeSnifferTest, LooksBinary) {
  // Make a large input, with 1024 bytes of "x" and 1 byte of 0x01.
  std::string content;
  content.resize(1024);
  std::fill(content.begin(), content.end(), 'x');
  content[1000] = 0x01;

  // content.size() >= 1024 so the sniff is unambiguous.
  std::string mime_type;
  EXPECT_TRUE(SniffMimeType(content.data(), content.size(), GURL(),
                            "text/plain", &mime_type));
  EXPECT_EQ("application/octet-stream", mime_type);
}

TEST(MimeSnifferTest, OfficeTest) {
  SnifferTest tests[] = {
    // Check for URLs incorrectly reported as Microsoft Office files.
    { "Hi there",
      sizeof("Hi there")-1,
      "http://www.example.com/foo.doc",
      "application/msword", "application/octet-stream" },
    { "Hi there",
      sizeof("Hi there")-1,
      "http://www.example.com/foo.xls",
      "application/vnd.ms-excel", "application/octet-stream" },
    { "Hi there",
      sizeof("Hi there")-1,
      "http://www.example.com/foo.ppt",
      "application/vnd.ms-powerpoint", "application/octet-stream" },
    // Check for Microsoft Office files incorrectly reported as text.
    { "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" "Hi there",
      sizeof("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" "Hi there")-1,
      "http://www.example.com/foo.doc",
      "text/plain", "application/msword" },
    { "PK\x03\x04" "Hi there",
      sizeof("PK\x03\x04" "Hi there")-1,
      "http://www.example.com/foo.doc",
      "text/plain",
      "application/vnd.openxmlformats-officedocument."
      "wordprocessingml.document" },
    { "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" "Hi there",
      sizeof("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" "Hi there")-1,
      "http://www.example.com/foo.xls",
      "text/plain", "application/vnd.ms-excel" },
    { "PK\x03\x04" "Hi there",
      sizeof("PK\x03\x04" "Hi there")-1,
      "http://www.example.com/foo.xls",
      "text/plain",
      "application/vnd.openxmlformats-officedocument."
      "spreadsheetml.sheet" },
    { "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" "Hi there",
      sizeof("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" "Hi there")-1,
      "http://www.example.com/foo.ppt",
      "text/plain", "application/vnd.ms-powerpoint" },
    { "PK\x03\x04" "Hi there",
      sizeof("PK\x03\x04" "Hi there")-1,
      "http://www.example.com/foo.ppt",
      "text/plain",
      "application/vnd.openxmlformats-officedocument."
      "presentationml.presentation" },
  };

  TestArray(tests, arraysize(tests));
}

// TODO(thestig) Add more tests for other AV formats. Add another test case for
// RAW images.
TEST(MimeSnifferTest, AudioVideoTest) {
  std::string mime_type;
  const char kOggTestData[] = "OggS\x00";
  EXPECT_TRUE(SniffMimeTypeFromLocalData(kOggTestData, sizeof(kOggTestData) - 1,
                                         &mime_type));
  EXPECT_EQ("audio/ogg", mime_type);
  mime_type.clear();
  // Check ogg header requires the terminal '\0' to be sniffed.
  EXPECT_FALSE(SniffMimeTypeFromLocalData(
      kOggTestData, sizeof(kOggTestData) - 2, &mime_type));
  EXPECT_EQ("", mime_type);
  mime_type.clear();

  const char kFlacTestData[] =
      "fLaC\x00\x00\x00\x22\x12\x00\x12\x00\x00\x00\x00\x00";
  EXPECT_TRUE(SniffMimeTypeFromLocalData(
      kFlacTestData, sizeof(kFlacTestData) - 1, &mime_type));
  EXPECT_EQ("audio/x-flac", mime_type);
  mime_type.clear();

  const char kWMATestData[] =
      "\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c";
  EXPECT_TRUE(SniffMimeTypeFromLocalData(kWMATestData, sizeof(kWMATestData) - 1,
                                         &mime_type));
  EXPECT_EQ("video/x-ms-asf", mime_type);
  mime_type.clear();

  // mp4a, m4b, m4p, and alac extension files which share the same container
  // format.
  const char kMP4TestData[] =
      "\x00\x00\x00\x20\x66\x74\x79\x70\x4d\x34\x41\x20\x00\x00\x00\x00";
  EXPECT_TRUE(SniffMimeTypeFromLocalData(kMP4TestData, sizeof(kMP4TestData) - 1,
                                         &mime_type));
  EXPECT_EQ("video/mp4", mime_type);
  mime_type.clear();

  const char kAACTestData[] =
      "\xff\xf1\x50\x80\x02\x20\xb0\x23\x0a\x83\x20\x7d\x61\x90\x3e\xb1";
  EXPECT_TRUE(SniffMimeTypeFromLocalData(kAACTestData, sizeof(kAACTestData) - 1,
                                         &mime_type));
  EXPECT_EQ("audio/mpeg", mime_type);
  mime_type.clear();
}

// The tests need char parameters, but the ranges to test include 0xFF, and some
// platforms have signed chars and are noisy about it. Using an int parameter
// and casting it to char inside the test case solves both these problems.
class MimeSnifferBinaryTest : public ::testing::TestWithParam<int> {};

// From https://mimesniff.spec.whatwg.org/#binary-data-byte :
// A binary data byte is a byte in the range 0x00 to 0x08 (NUL to BS), the byte
// 0x0B (VT), a byte in the range 0x0E to 0x1A (SO to SUB), or a byte in the
// range 0x1C to 0x1F (FS to US).
TEST_P(MimeSnifferBinaryTest, IsBinaryControlCode) {
  char param = static_cast<char>(GetParam());
  EXPECT_TRUE(LooksLikeBinary(&param, 1));
}

// ::testing::Range(a, b) tests an open-ended range, ie. "b" is not included.
INSTANTIATE_TEST_CASE_P(MimeSnifferBinaryTestRange1,
                        MimeSnifferBinaryTest,
                        Range(0x00, 0x09));

INSTANTIATE_TEST_CASE_P(MimeSnifferBinaryTestByte0x0B,
                        MimeSnifferBinaryTest,
                        Values(0x0B));

INSTANTIATE_TEST_CASE_P(MimeSnifferBinaryTestRange2,
                        MimeSnifferBinaryTest,
                        Range(0x0E, 0x1B));

INSTANTIATE_TEST_CASE_P(MimeSnifferBinaryTestRange3,
                        MimeSnifferBinaryTest,
                        Range(0x1C, 0x20));

class MimeSnifferPlainTextTest : public ::testing::TestWithParam<int> {};

TEST_P(MimeSnifferPlainTextTest, NotBinaryControlCode) {
  char param = static_cast<char>(GetParam());
  EXPECT_FALSE(LooksLikeBinary(&param, 1));
}

INSTANTIATE_TEST_CASE_P(MimeSnifferPlainTextTestPlainTextControlCodes,
                        MimeSnifferPlainTextTest,
                        Values(0x09, 0x0A, 0x0C, 0x0D, 0x1B));

INSTANTIATE_TEST_CASE_P(MimeSnifferPlainTextTestNotControlCodeRange,
                        MimeSnifferPlainTextTest,
                        Range(0x20, 0x100));

class MimeSnifferControlCodesEdgeCaseTest
    : public ::testing::TestWithParam<const char*> {};

TEST_P(MimeSnifferControlCodesEdgeCaseTest, EdgeCase) {
  const char* param = GetParam();
  EXPECT_TRUE(LooksLikeBinary(param, strlen(param)));
}

INSTANTIATE_TEST_CASE_P(MimeSnifferControlCodesEdgeCaseTest,
                        MimeSnifferControlCodesEdgeCaseTest,
                        Values("\x01__",  // first byte is binary
                               "__\x03",  // last byte is binary
                               "_\x02_"   // a byte in the middle is binary
                               ));

}  // namespace
}  // namespace net
