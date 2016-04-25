// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <iterator>
#include <map>
#include <string>
#include <unordered_set>

#include "base/base64.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/rand_util.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "net/base/mime_util.h"
#include "net/base/platform_mime_util.h"
#include "net/http/http_util.h"

using std::string;

namespace net {

// Singleton utility class for mime types.
class MimeUtil : public PlatformMimeUtil {
 public:
  bool GetMimeTypeFromExtension(const base::FilePath::StringType& ext,
                                std::string* mime_type) const;

  bool GetMimeTypeFromFile(const base::FilePath& file_path,
                           std::string* mime_type) const;

  bool GetWellKnownMimeTypeFromExtension(const base::FilePath::StringType& ext,
                                         std::string* mime_type) const;

  bool MatchesMimeType(const std::string &mime_type_pattern,
                       const std::string &mime_type) const;

  bool ParseMimeTypeWithoutParameter(const std::string& type_string,
                                     std::string* top_level_type,
                                     std::string* subtype) const;

  bool IsValidTopLevelMimeType(const std::string& type_string) const;

 private:
  friend struct base::DefaultLazyInstanceTraits<MimeUtil>;

  MimeUtil();

  bool GetMimeTypeFromExtensionHelper(const base::FilePath::StringType& ext,
                                      bool include_platform_types,
                                      std::string* mime_type) const;
};  // class MimeUtil

// This variable is Leaky because we need to access it from WorkerPool threads.
static base::LazyInstance<MimeUtil>::Leaky g_mime_util =
    LAZY_INSTANCE_INITIALIZER;

static const MimeInfo kPrimaryMappings[] = {
    {"text/html", "html,htm,shtml,shtm"},
    {"text/css", "css"},
    {"text/xml", "xml"},
    {"image/gif", "gif"},
    {"image/jpeg", "jpeg,jpg"},
    {"image/webp", "webp"},
    {"image/png", "png"},
    {"video/mp4", "mp4,m4v"},
    {"audio/x-m4a", "m4a"},
    {"audio/mp3", "mp3"},
    {"video/ogg", "ogv,ogm"},
    {"audio/ogg", "ogg,oga,opus"},
    {"video/webm", "webm"},
    {"audio/webm", "webm"},
    {"audio/wav", "wav"},
    {"audio/flac", "flac"},
    {"application/xhtml+xml", "xhtml,xht,xhtm"},
    {"application/x-chrome-extension", "crx"},
    {"multipart/related", "mhtml,mht"}};

static const MimeInfo kSecondaryMappings[] = {
    {"application/octet-stream", "exe,com,bin"},
    {"application/gzip", "gz,tgz"},
    {"application/x-gzip", "gz,tgz"},
    {"application/pdf", "pdf"},
    {"application/postscript", "ps,eps,ai"},
    {"application/javascript", "js"},
    {"application/font-woff", "woff"},
    {"image/bmp", "bmp"},
    {"image/x-icon", "ico"},
    {"image/vnd.microsoft.icon", "ico"},
    {"image/jpeg", "jfif,pjpeg,pjp"},
    {"image/tiff", "tiff,tif"},
    {"image/x-xbitmap", "xbm"},
    {"image/svg+xml", "svg,svgz"},
    {"image/x-png", "png"},
    {"message/rfc822", "eml"},
    {"text/plain", "txt,text"},
    {"text/html", "ehtml"},
    {"application/rss+xml", "rss"},
    {"application/rdf+xml", "rdf"},
    {"text/xml", "xsl,xbl,xslt"},
    {"application/vnd.mozilla.xul+xml", "xul"},
    {"application/x-shockwave-flash", "swf,swl"},
    {"application/pkcs7-mime", "p7m,p7c,p7z"},
    {"application/pkcs7-signature", "p7s"},
    {"application/x-mpegurl", "m3u8"},
};

const char* FindMimeType(const MimeInfo* mappings,
                         size_t mappings_len,
                         const std::string& ext) {
  for (size_t i = 0; i < mappings_len; ++i) {
    const char* extensions = mappings[i].extensions;
    for (;;) {
      size_t end_pos = strcspn(extensions, ",");
      // The length check is required to prevent the StringPiece below from
      // including uninitialized memory if ext is longer than extensions.
      if (end_pos == ext.size() &&
          base::EqualsCaseInsensitiveASCII(
              base::StringPiece(extensions, ext.size()), ext))
        return mappings[i].mime_type;
      extensions += end_pos;
      if (!*extensions)
        break;
      extensions += 1;  // skip over comma
    }
  }
  return NULL;
}

bool MimeUtil::GetMimeTypeFromExtension(const base::FilePath::StringType& ext,
                                        string* result) const {
  return GetMimeTypeFromExtensionHelper(ext, true, result);
}

bool MimeUtil::GetWellKnownMimeTypeFromExtension(
    const base::FilePath::StringType& ext,
    string* result) const {
  return GetMimeTypeFromExtensionHelper(ext, false, result);
}

bool MimeUtil::GetMimeTypeFromFile(const base::FilePath& file_path,
                                   string* result) const {
  base::FilePath::StringType file_name_str = file_path.Extension();
  if (file_name_str.empty())
    return false;
  return GetMimeTypeFromExtension(file_name_str.substr(1), result);
}

bool MimeUtil::GetMimeTypeFromExtensionHelper(
    const base::FilePath::StringType& ext,
    bool include_platform_types,
    string* result) const {
  // Avoids crash when unable to handle a long file path. See crbug.com/48733.
  const unsigned kMaxFilePathSize = 65536;
  if (ext.length() > kMaxFilePathSize)
    return false;

  // Reject a string which contains null character.
  base::FilePath::StringType::size_type nul_pos =
      ext.find(FILE_PATH_LITERAL('\0'));
  if (nul_pos != base::FilePath::StringType::npos)
    return false;

  // We implement the same algorithm as Mozilla for mapping a file extension to
  // a mime type.  That is, we first check a hard-coded list (that cannot be
  // overridden), and then if not found there, we defer to the system registry.
  // Finally, we scan a secondary hard-coded list to catch types that we can
  // deduce but that we also want to allow the OS to override.

  base::FilePath path_ext(ext);
  const string ext_narrow_str = path_ext.AsUTF8Unsafe();
  const char* mime_type = FindMimeType(
      kPrimaryMappings, arraysize(kPrimaryMappings), ext_narrow_str);
  if (mime_type) {
    *result = mime_type;
    return true;
  }

  if (include_platform_types && GetPlatformMimeTypeFromExtension(ext, result))
    return true;

  mime_type = FindMimeType(kSecondaryMappings, arraysize(kSecondaryMappings),
                           ext_narrow_str);
  if (mime_type) {
    *result = mime_type;
    return true;
  }

  return false;
}

MimeUtil::MimeUtil() {
}

// Tests for MIME parameter equality. Each parameter in the |mime_type_pattern|
// must be matched by a parameter in the |mime_type|. If there are no
// parameters in the pattern, the match is a success.
//
// According rfc2045 keys of parameters are case-insensitive, while values may
// or may not be case-sensitive, but they are usually case-sensitive. So, this
// function matches values in *case-sensitive* manner, however note that this
// may produce some false negatives.
bool MatchesMimeTypeParameters(const std::string& mime_type_pattern,
                               const std::string& mime_type) {
  typedef std::map<std::string, std::string> StringPairMap;

  const std::string::size_type semicolon = mime_type_pattern.find(';');
  const std::string::size_type test_semicolon = mime_type.find(';');
  if (semicolon != std::string::npos) {
    if (test_semicolon == std::string::npos)
      return false;

    base::StringPairs pattern_parameters;
    base::SplitStringIntoKeyValuePairs(mime_type_pattern.substr(semicolon + 1),
                                       '=', ';', &pattern_parameters);
    base::StringPairs test_parameters;
    base::SplitStringIntoKeyValuePairs(mime_type.substr(test_semicolon + 1),
                                       '=', ';', &test_parameters);

    // Put the parameters to maps with the keys converted to lower case.
    StringPairMap pattern_parameter_map;
    for (const auto& pair : pattern_parameters) {
      pattern_parameter_map[base::ToLowerASCII(pair.first)] = pair.second;
    }

    StringPairMap test_parameter_map;
    for (const auto& pair : test_parameters) {
      test_parameter_map[base::ToLowerASCII(pair.first)] = pair.second;
    }

    if (pattern_parameter_map.size() > test_parameter_map.size())
      return false;

    for (const auto& parameter_pair : pattern_parameter_map) {
      const auto& test_parameter_pair_it =
          test_parameter_map.find(parameter_pair.first);
      if (test_parameter_pair_it == test_parameter_map.end())
        return false;
      if (parameter_pair.second != test_parameter_pair_it->second)
        return false;
    }
  }

  return true;
}

// This comparison handles absolute maching and also basic
// wildcards.  The plugin mime types could be:
//      application/x-foo
//      application/*
//      application/*+xml
//      *
// Also tests mime parameters -- all parameters in the pattern must be present
// in the tested type for a match to succeed.
bool MimeUtil::MatchesMimeType(const std::string& mime_type_pattern,
                               const std::string& mime_type) const {
  if (mime_type_pattern.empty())
    return false;

  std::string::size_type semicolon = mime_type_pattern.find(';');
  const std::string base_pattern(mime_type_pattern.substr(0, semicolon));
  semicolon = mime_type.find(';');
  const std::string base_type(mime_type.substr(0, semicolon));

  if (base_pattern == "*" || base_pattern == "*/*")
    return MatchesMimeTypeParameters(mime_type_pattern, mime_type);

  const std::string::size_type star = base_pattern.find('*');
  if (star == std::string::npos) {
    if (base::EqualsCaseInsensitiveASCII(base_pattern, base_type))
      return MatchesMimeTypeParameters(mime_type_pattern, mime_type);
    else
      return false;
  }

  // Test length to prevent overlap between |left| and |right|.
  if (base_type.length() < base_pattern.length() - 1)
    return false;

  base::StringPiece base_pattern_piece(base_pattern);
  base::StringPiece left(base_pattern_piece.substr(0, star));
  base::StringPiece right(base_pattern_piece.substr(star + 1));

  if (!base::StartsWith(base_type, left, base::CompareCase::INSENSITIVE_ASCII))
    return false;

  if (!right.empty() &&
      !base::EndsWith(base_type, right, base::CompareCase::INSENSITIVE_ASCII))
    return false;

  return MatchesMimeTypeParameters(mime_type_pattern, mime_type);
}

// See http://www.iana.org/assignments/media-types/media-types.xhtml
static const char* const legal_top_level_types[] = {
  "application",
  "audio",
  "example",
  "image",
  "message",
  "model",
  "multipart",
  "text",
  "video",
};

bool MimeUtil::ParseMimeTypeWithoutParameter(
    const std::string& type_string,
    std::string* top_level_type,
    std::string* subtype) const {
  std::vector<std::string> components = base::SplitString(
      type_string, "/", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (components.size() != 2 ||
      !HttpUtil::IsToken(components[0]) ||
      !HttpUtil::IsToken(components[1]))
    return false;

  if (top_level_type)
    *top_level_type = components[0];
  if (subtype)
    *subtype = components[1];
  return true;
}

bool MimeUtil::IsValidTopLevelMimeType(const std::string& type_string) const {
  std::string lower_type = base::ToLowerASCII(type_string);
  for (size_t i = 0; i < arraysize(legal_top_level_types); ++i) {
    if (lower_type.compare(legal_top_level_types[i]) == 0)
      return true;
  }

  return type_string.size() > 2 &&
         base::StartsWith(type_string, "x-",
                          base::CompareCase::INSENSITIVE_ASCII);
}

//----------------------------------------------------------------------------
// Wrappers for the singleton
//----------------------------------------------------------------------------

bool GetMimeTypeFromExtension(const base::FilePath::StringType& ext,
                              std::string* mime_type) {
  return g_mime_util.Get().GetMimeTypeFromExtension(ext, mime_type);
}

bool GetMimeTypeFromFile(const base::FilePath& file_path,
                         std::string* mime_type) {
  return g_mime_util.Get().GetMimeTypeFromFile(file_path, mime_type);
}

bool GetWellKnownMimeTypeFromExtension(const base::FilePath::StringType& ext,
                                       std::string* mime_type) {
  return g_mime_util.Get().GetWellKnownMimeTypeFromExtension(ext, mime_type);
}

bool GetPreferredExtensionForMimeType(const std::string& mime_type,
                                      base::FilePath::StringType* extension) {
  return g_mime_util.Get().GetPreferredExtensionForMimeType(mime_type,
                                                            extension);
}

bool MatchesMimeType(const std::string& mime_type_pattern,
                     const std::string& mime_type) {
  return g_mime_util.Get().MatchesMimeType(mime_type_pattern, mime_type);
}

bool ParseMimeTypeWithoutParameter(const std::string& type_string,
                                   std::string* top_level_type,
                                   std::string* subtype) {
  return g_mime_util.Get().ParseMimeTypeWithoutParameter(
      type_string, top_level_type, subtype);
}

bool IsValidTopLevelMimeType(const std::string& type_string) {
  return g_mime_util.Get().IsValidTopLevelMimeType(type_string);
}

namespace {

// From http://www.w3schools.com/media/media_mimeref.asp and
// http://plugindoc.mozdev.org/winmime.php
static const char* const kStandardImageTypes[] = {
  "image/bmp",
  "image/cis-cod",
  "image/gif",
  "image/ief",
  "image/jpeg",
  "image/webp",
  "image/pict",
  "image/pipeg",
  "image/png",
  "image/svg+xml",
  "image/tiff",
  "image/vnd.microsoft.icon",
  "image/x-cmu-raster",
  "image/x-cmx",
  "image/x-icon",
  "image/x-portable-anymap",
  "image/x-portable-bitmap",
  "image/x-portable-graymap",
  "image/x-portable-pixmap",
  "image/x-rgb",
  "image/x-xbitmap",
  "image/x-xpixmap",
  "image/x-xwindowdump"
};
static const char* const kStandardAudioTypes[] = {
  "audio/aac",
  "audio/aiff",
  "audio/amr",
  "audio/basic",
  "audio/flac",
  "audio/midi",
  "audio/mp3",
  "audio/mp4",
  "audio/mpeg",
  "audio/mpeg3",
  "audio/ogg",
  "audio/vorbis",
  "audio/wav",
  "audio/webm",
  "audio/x-m4a",
  "audio/x-ms-wma",
  "audio/vnd.rn-realaudio",
  "audio/vnd.wave"
};
static const char* const kStandardVideoTypes[] = {
  "video/avi",
  "video/divx",
  "video/flc",
  "video/mp4",
  "video/mpeg",
  "video/ogg",
  "video/quicktime",
  "video/sd-video",
  "video/webm",
  "video/x-dv",
  "video/x-m4v",
  "video/x-mpeg",
  "video/x-ms-asf",
  "video/x-ms-wmv"
};

struct StandardType {
  const char* const leading_mime_type;
  const char* const* standard_types;
  size_t standard_types_len;
};
static const StandardType kStandardTypes[] = {
  { "image/", kStandardImageTypes, arraysize(kStandardImageTypes) },
  { "audio/", kStandardAudioTypes, arraysize(kStandardAudioTypes) },
  { "video/", kStandardVideoTypes, arraysize(kStandardVideoTypes) },
  { NULL, NULL, 0 }
};

void GetExtensionsFromHardCodedMappings(
    const MimeInfo* mappings,
    size_t mappings_len,
    const std::string& leading_mime_type,
    std::unordered_set<base::FilePath::StringType>* extensions) {
  for (size_t i = 0; i < mappings_len; ++i) {
    if (base::StartsWith(mappings[i].mime_type, leading_mime_type,
                         base::CompareCase::INSENSITIVE_ASCII)) {
      for (const base::StringPiece& this_extension : base::SplitStringPiece(
               mappings[i].extensions, ",", base::TRIM_WHITESPACE,
               base::SPLIT_WANT_ALL)) {
#if defined(OS_WIN)
        extensions->insert(base::UTF8ToUTF16(this_extension));
#else
        extensions->insert(this_extension.as_string());
#endif
      }
    }
  }
}

void GetExtensionsHelper(
    const char* const* standard_types,
    size_t standard_types_len,
    const std::string& leading_mime_type,
    std::unordered_set<base::FilePath::StringType>* extensions) {
  for (size_t i = 0; i < standard_types_len; ++i) {
    g_mime_util.Get().GetPlatformExtensionsForMimeType(standard_types[i],
                                                       extensions);
  }

  // Also look up the extensions from hard-coded mappings in case that some
  // supported extensions are not registered in the system registry, like ogg.
  GetExtensionsFromHardCodedMappings(kPrimaryMappings,
                                     arraysize(kPrimaryMappings),
                                     leading_mime_type, extensions);

  GetExtensionsFromHardCodedMappings(kSecondaryMappings,
                                     arraysize(kSecondaryMappings),
                                     leading_mime_type, extensions);
}

// Note that the elements in the source set will be appended to the target
// vector.
template <class T>
void UnorderedSetToVector(std::unordered_set<T>* source,
                          std::vector<T>* target) {
  size_t old_target_size = target->size();
  target->resize(old_target_size + source->size());
  size_t i = 0;
  for (typename std::unordered_set<T>::iterator iter = source->begin();
       iter != source->end(); ++iter, ++i)
    (*target)[old_target_size + i] = *iter;
}

// Characters to be used for mime multipart boundary.
//
// TODO(rsleevi): crbug.com/575779: Follow the spec or fix the spec.
// The RFC 2046 spec says the alphanumeric characters plus the
// following characters are legal for boundaries:  '()+_,-./:=?
// However the following characters, though legal, cause some sites
// to fail: (),./:=+
const char kMimeBoundaryCharacters[] =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

// Size of mime multipart boundary.
const size_t kMimeBoundarySize = 69;

}  // namespace

void GetExtensionsForMimeType(
    const std::string& unsafe_mime_type,
    std::vector<base::FilePath::StringType>* extensions) {
  if (unsafe_mime_type == "*/*" || unsafe_mime_type == "*")
    return;

  const std::string mime_type = base::ToLowerASCII(unsafe_mime_type);
  std::unordered_set<base::FilePath::StringType> unique_extensions;

  if (base::EndsWith(mime_type, "/*", base::CompareCase::INSENSITIVE_ASCII)) {
    std::string leading_mime_type = mime_type.substr(0, mime_type.length() - 1);

    // Find the matching StandardType from within kStandardTypes, or fall
    // through to the last (default) StandardType.
    const StandardType* type = NULL;
    for (size_t i = 0; i < arraysize(kStandardTypes); ++i) {
      type = &(kStandardTypes[i]);
      if (type->leading_mime_type &&
          leading_mime_type == type->leading_mime_type)
        break;
    }
    DCHECK(type);
    GetExtensionsHelper(type->standard_types,
                        type->standard_types_len,
                        leading_mime_type,
                        &unique_extensions);
  } else {
    g_mime_util.Get().GetPlatformExtensionsForMimeType(mime_type,
                                                       &unique_extensions);

    // Also look up the extensions from hard-coded mappings in case that some
    // supported extensions are not registered in the system registry, like ogg.
    GetExtensionsFromHardCodedMappings(kPrimaryMappings,
                                       arraysize(kPrimaryMappings), mime_type,
                                       &unique_extensions);

    GetExtensionsFromHardCodedMappings(kSecondaryMappings,
                                       arraysize(kSecondaryMappings), mime_type,
                                       &unique_extensions);
  }

  UnorderedSetToVector(&unique_extensions, extensions);
}

NET_EXPORT std::string GenerateMimeMultipartBoundary() {
  // Based on RFC 1341, section "7.2.1 Multipart: The common syntax":
  //   Because encapsulation boundaries must not appear in the body parts being
  //   encapsulated, a user agent must exercise care to choose a unique
  //   boundary. The boundary in the example above could have been the result of
  //   an algorithm designed to produce boundaries with a very low probability
  //   of already existing in the data to be encapsulated without having to
  //   prescan the data.
  //   [...]
  //   the boundary parameter [...] consists of 1 to 70 characters from a set of
  //   characters known to be very robust through email gateways, and NOT ending
  //   with white space.
  //   [...]
  //   boundary := 0*69<bchars> bcharsnospace
  //   bchars := bcharsnospace / " "
  //   bcharsnospace := DIGIT / ALPHA / "'" / "(" / ")" / "+" /
  //            "_" / "," / "-" / "." / "/" / ":" / "=" / "?"

  std::string result;
  result.reserve(kMimeBoundarySize);
  result.append("----MultipartBoundary--");
  while (result.size() < (kMimeBoundarySize - 4)) {
    // Subtract 2 from the array size to 1) exclude '\0', and 2) turn the size
    // into the last index.
    const int last_char_index = sizeof(kMimeBoundaryCharacters) - 2;
    char c = kMimeBoundaryCharacters[base::RandInt(0, last_char_index)];
    result.push_back(c);
  }
  result.append("----");

  // Not a strict requirement - documentation only.
  DCHECK_EQ(kMimeBoundarySize, result.size());

  return result;
}

void AddMultipartValueForUpload(const std::string& value_name,
                                const std::string& value,
                                const std::string& mime_boundary,
                                const std::string& content_type,
                                std::string* post_data) {
  DCHECK(post_data);
  // First line is the boundary.
  post_data->append("--" + mime_boundary + "\r\n");
  // Next line is the Content-disposition.
  post_data->append("Content-Disposition: form-data; name=\"" +
                    value_name + "\"\r\n");
  if (!content_type.empty()) {
    // If Content-type is specified, the next line is that.
    post_data->append("Content-Type: " + content_type + "\r\n");
  }
  // Leave an empty line and append the value.
  post_data->append("\r\n" + value + "\r\n");
}

void AddMultipartFinalDelimiterForUpload(const std::string& mime_boundary,
                                         std::string* post_data) {
  DCHECK(post_data);
  post_data->append("--" + mime_boundary + "--\r\n");
}

}  // namespace net
