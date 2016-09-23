// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_MIME_EXTENSION_CHROMEOS_H_
#define NET_BASE_MIME_EXTENSION_CHROMEOS_H_

#include <string>

#include "base/files/file_path.h"

namespace net {
namespace chromeos {

bool GetPlatformMimeTypeFromExtension(const base::FilePath::StringType& ext,
                                      std::string* mime_type);

}  // namespace chromeos
}  // namespace net

#endif  // NET_BASE_MIME_EXTENSION_CHROMEOS_H_
