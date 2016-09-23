// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/mime_extension_chromeos.h"

#include "base/logging.h"
#include "net/base/mime_util.h"

namespace net {
namespace chromeos {

namespace {

static const net::MimeInfo mimetype_extension_mapping[] = {
    {"application/epub+zip", "epub"},
    {"application/zip", "zip"},
    {"text/calendar", "ics"},
};
}  // namespace

// On linux, chrome uses xdgmime to read extension-mimetype database (e.g.
// /usr/share/mime) and estimate mime type from extension. However ChromeOS does
// not have such database in it, we use |mimetype_extension_mapping| to resolve
// mime type on ChromeOS.
bool GetPlatformMimeTypeFromExtension(const base::FilePath::StringType& ext,
                                      std::string* mime_type) {
  base::FilePath path_ext(ext);
  const std::string ext_narrow_str = path_ext.AsUTF8Unsafe();
  const char* result =
      net::FindMimeType(mimetype_extension_mapping,
                        arraysize(mimetype_extension_mapping), ext_narrow_str);
  if (result) {
    *mime_type = result;
    return true;
  }

  return false;
}
}  // namespace chromeos
}  // namespace net
