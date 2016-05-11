// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/platform_mime_util.h"

#include <string>

#include "base/logging.h"
#include "build/build_config.h"

#if defined(OS_ANDROID)
#include "net/android/network_library.h"
#elif defined(OS_CHROMEOS)
#include "net/base/mime_extension_chromeos.h"
#else
#include "base/nix/mime_util_xdg.h"
#endif

namespace net {

#if defined(OS_ANDROID)
bool PlatformMimeUtil::GetPlatformMimeTypeFromExtension(
    const base::FilePath::StringType& ext, std::string* result) const {
  return android::GetMimeTypeFromExtension(ext, result);
}
#elif defined(OS_CHROMEOS)
bool PlatformMimeUtil::GetPlatformMimeTypeFromExtension(
    const base::FilePath::StringType& ext,
    std::string* result) const {
  return chromeos::GetPlatformMimeTypeFromExtension(ext, result);
}
#else
bool PlatformMimeUtil::GetPlatformMimeTypeFromExtension(
    const base::FilePath::StringType& ext, std::string* result) const {
  base::FilePath dummy_path("foo." + ext);
  std::string out = base::nix::GetFileMimeType(dummy_path);

  // GetFileMimeType likes to return application/octet-stream
  // for everything it doesn't know - ignore that.
  if (out == "application/octet-stream" || out.empty())
    return false;

  // GetFileMimeType returns image/x-ico because that's what's in the XDG
  // mime database. That database is the merger of the Gnome and KDE mime
  // databases. Apparently someone working on KDE in 2001 decided .ico
  // resolves to image/x-ico, whereas the rest of the world uses image/x-icon.
  // FWIW, image/vnd.microsoft.icon is the official IANA assignment.
  if (out == "image/x-ico")
    out = "image/x-icon";

  *result = out;
  return true;
}

#endif  // defined(OS_ANDROID)

struct MimeToExt {
  const char* mime_type;
  const char* ext;
};

const struct MimeToExt mime_type_ext_map[] = {
  {"application/pdf", "pdf"},
  {"application/x-tar", "tar"},
  {"application/zip", "zip"},
  {"audio/mpeg", "mp3"},
  {"image/gif", "gif"},
  {"image/jpeg", "jpg"},
  {"image/png", "png"},
  {"text/html", "html"},
  {"video/mp4", "mp4"},
  {"video/mpeg", "mpg"},
  {"text/plain", "txt"},
  {"text/x-sh", "sh"},
};

bool PlatformMimeUtil::GetPreferredExtensionForMimeType(
    const std::string& mime_type, base::FilePath::StringType* ext) const {

  for (size_t x = 0;
       x < (sizeof(mime_type_ext_map) / sizeof(MimeToExt));
       x++) {
    if (mime_type_ext_map[x].mime_type == mime_type) {
      *ext = mime_type_ext_map[x].ext;
      return true;
    }
  }

  // TODO(dhg): Fix this the right way by implementing what's said below.
  // Unlike GetPlatformMimeTypeFromExtension, this method doesn't have a
  // default list that it uses, but for now we are also returning false since
  // this doesn't really matter as much under Linux.
  //
  // If we wanted to do this properly, we would read the mime.cache file which
  // has a section where they assign a glob (*.gif) to a mimetype
  // (image/gif). We look up the "heaviest" glob for a certain mime type and
  // then then try to chop off "*.".

  return false;
}

void PlatformMimeUtil::GetPlatformExtensionsForMimeType(
    const std::string& mime_type,
    std::unordered_set<base::FilePath::StringType>* extensions) const {
  base::FilePath::StringType ext;
  if (GetPreferredExtensionForMimeType(mime_type, &ext))
    extensions->insert(ext);
}

}  // namespace net
