// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/filename_util.h"

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/path_service.h"
#include "base/strings/string_util.h"
#include "base/strings/sys_string_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_restrictions.h"
#include "net/base/escape.h"
#include "net/base/filename_util_internal.h"
#include "net/base/net_string_util.h"
#include "net/http/http_content_disposition.h"
#include "url/gurl.h"

namespace net {

// Prefix to prepend to get a file URL.
static const base::FilePath::CharType kFileURLPrefix[] =
    FILE_PATH_LITERAL("file:///");

GURL FilePathToFileURL(const base::FilePath& path) {
  // Produce a URL like "file:///C:/foo" for a regular file, or
  // "file://///server/path" for UNC. The URL canonicalizer will fix up the
  // latter case to be the canonical UNC form: "file://server/path"
  base::FilePath::StringType url_string(kFileURLPrefix);
  url_string.append(path.value());

  // Now do replacement of some characters. Since we assume the input is a
  // literal filename, anything the URL parser might consider special should
  // be escaped here.

  // must be the first substitution since others will introduce percents as the
  // escape character
  base::ReplaceSubstringsAfterOffset(
      &url_string, 0, FILE_PATH_LITERAL("%"), FILE_PATH_LITERAL("%25"));

  // semicolon is supposed to be some kind of separator according to RFC 2396
  base::ReplaceSubstringsAfterOffset(
      &url_string, 0, FILE_PATH_LITERAL(";"), FILE_PATH_LITERAL("%3B"));

  base::ReplaceSubstringsAfterOffset(
      &url_string, 0, FILE_PATH_LITERAL("#"), FILE_PATH_LITERAL("%23"));

  base::ReplaceSubstringsAfterOffset(
      &url_string, 0, FILE_PATH_LITERAL("?"), FILE_PATH_LITERAL("%3F"));

#if defined(OS_POSIX)
  base::ReplaceSubstringsAfterOffset(
      &url_string, 0, FILE_PATH_LITERAL("\\"), FILE_PATH_LITERAL("%5C"));
#endif

  return GURL(url_string);
}

bool FileURLToFilePath(const GURL& url, base::FilePath* file_path) {
  *file_path = base::FilePath();
  base::FilePath::StringType& file_path_str =
      const_cast<base::FilePath::StringType&>(file_path->value());
  file_path_str.clear();

  if (!url.is_valid())
    return false;

#if defined(OS_WIN)
  std::string path;
  std::string host = url.host();
  if (host.empty()) {
    // URL contains no host, the path is the filename. In this case, the path
    // will probably be preceeded with a slash, as in "/C:/foo.txt", so we
    // trim out that here.
    path = url.path();
    size_t first_non_slash = path.find_first_not_of("/\\");
    if (first_non_slash != std::string::npos && first_non_slash > 0)
      path.erase(0, first_non_slash);
  } else {
    // URL contains a host: this means it's UNC. We keep the preceeding slash
    // on the path.
    path = "\\\\";
    path.append(host);
    path.append(url.path());
  }
  std::replace(path.begin(), path.end(), '/', '\\');
#else  // defined(OS_WIN)
  // Firefox seems to ignore the "host" of a file url if there is one. That is,
  // file://foo/bar.txt maps to /bar.txt.
  // TODO(dhg): This should probably take into account UNCs which could
  // include a hostname other than localhost or blank
  std::string path = url.path();
#endif  // !defined(OS_WIN)

  if (path.empty())
    return false;

  // GURL stores strings as percent-encoded 8-bit, this will undo if possible.
  path = UnescapeURLComponent(
      path, UnescapeRule::SPACES |
                UnescapeRule::URL_SPECIAL_CHARS_EXCEPT_PATH_SEPARATORS);

#if defined(OS_WIN)
  if (base::IsStringUTF8(path)) {
    file_path_str.assign(base::UTF8ToWide(path));
    // We used to try too hard and see if |path| made up entirely of
    // the 1st 256 characters in the Unicode was a zero-extended UTF-16.
    // If so, we converted it to 'Latin-1' and checked if the result was UTF-8.
    // If the check passed, we converted the result to UTF-8.
    // Otherwise, we treated the result as the native OS encoding.
    // However, that led to http://crbug.com/4619 and http://crbug.com/14153
  } else {
    // Not UTF-8, assume encoding is native codepage and we're done. We know we
    // are giving the conversion function a nonempty string, and it may fail if
    // the given string is not in the current encoding and give us an empty
    // string back. We detect this and report failure.
    file_path_str = base::SysNativeMBToWide(path);
  }
#else  // defined(OS_WIN)
  // Collapse multiple path slashes into a single path slash.
  std::string new_path;
  do {
    new_path = path;
    base::ReplaceSubstringsAfterOffset(&new_path, 0, "//", "/");
    path.swap(new_path);
  } while (new_path != path);

  file_path_str.assign(path);
#endif  // !defined(OS_WIN)

  return !file_path_str.empty();
}

void GenerateSafeFileName(const std::string& mime_type,
                          bool ignore_extension,
                          base::FilePath* file_path) {
  // Make sure we get the right file extension
  EnsureSafeExtension(mime_type, ignore_extension, file_path);

#if defined(OS_WIN)
  // Prepend "_" to the file name if it's a reserved name
  base::FilePath::StringType leaf_name = file_path->BaseName().value();
  DCHECK(!leaf_name.empty());
  if (IsReservedNameOnWindows(leaf_name)) {
    leaf_name = base::FilePath::StringType(FILE_PATH_LITERAL("_")) + leaf_name;
    *file_path = file_path->DirName();
    if (file_path->value() == base::FilePath::kCurrentDirectory) {
      *file_path = base::FilePath(leaf_name);
    } else {
      *file_path = file_path->Append(leaf_name);
    }
  }
#endif
}

bool IsReservedNameOnWindows(const base::FilePath::StringType& filename) {
  // This list is taken from the MSDN article "Naming a file"
  // http://msdn2.microsoft.com/en-us/library/aa365247(VS.85).aspx
  // I also added clock$ because GetSaveFileName seems to consider it as a
  // reserved name too.
  static const char* const known_devices[] = {
      "con",  "prn",  "aux",  "nul",  "com1", "com2", "com3",  "com4",
      "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2",  "lpt3",
      "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "clock$"};
#if defined(OS_WIN)
  std::string filename_lower = base::ToLowerASCII(base::WideToUTF8(filename));
#elif defined(OS_POSIX)
  std::string filename_lower = base::ToLowerASCII(filename);
#endif

  for (size_t i = 0; i < arraysize(known_devices); ++i) {
    // Exact match.
    if (filename_lower == known_devices[i])
      return true;
    // Starts with "DEVICE.".
    if (base::StartsWith(filename_lower, std::string(known_devices[i]) + ".",
                         base::CompareCase::SENSITIVE)) {
      return true;
    }
  }

  static const char* const magic_names[] = {
      // These file names are used by the "Customize folder" feature of the
      // shell.
      "desktop.ini",
      "thumbs.db",
  };

  for (size_t i = 0; i < arraysize(magic_names); ++i) {
    if (filename_lower == magic_names[i])
      return true;
  }

  return false;
}

}  // namespace net
