// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Functions used internally by filename_util, and filename_util_icu.

#ifndef NET_BASE_FILENAME_UTIL_INTERNAL_H_
#define NET_BASE_FILENAME_UTIL_INTERNAL_H_

#include <string>

#include "base/callback.h"
#include "base/files/file_path.h"
#include "base/strings/string16.h"

class GURL;

namespace net {

typedef base::Callback<
    void(base::FilePath::StringType* file_name, char replace_char)>
    ReplaceIllegalCharactersCallback;

void SanitizeGeneratedFileName(base::FilePath::StringType* filename,
                               bool replace_trailing);

bool IsShellIntegratedExtension(const base::FilePath::StringType& extension);

void EnsureSafeExtension(const std::string& mime_type,
                         bool ignore_extension,
                         base::FilePath* file_name);

bool FilePathToString16(const base::FilePath& path, base::string16* converted);

// Similar to GetSuggestedFilename(), but takes callback to replace illegal
// characters.
base::string16 GetSuggestedFilenameImpl(
    const GURL& url,
    const std::string& content_disposition,
    const std::string& referrer_charset,
    const std::string& suggested_name,
    const std::string& mime_type,
    const std::string& default_name,
    ReplaceIllegalCharactersCallback replace_illegal_characters_callback);

// Similar to GenerateFileName(), but takes callback to replace illegal
// characters.
base::FilePath GenerateFileNameImpl(
    const GURL& url,
    const std::string& content_disposition,
    const std::string& referrer_charset,
    const std::string& suggested_name,
    const std::string& mime_type,
    const std::string& default_name,
    ReplaceIllegalCharactersCallback replace_illegal_characters_callback);

}  // namespace net

#endif  // NET_BASE_FILENAME_UTIL_INTERNAL_H_
