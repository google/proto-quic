// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/test_data_directory.h"

#include "base/base_paths.h"
#include "base/path_service.h"

namespace net {

namespace {
const base::FilePath::CharType kCertificateRelativePath[] =
    FILE_PATH_LITERAL("net/data/ssl/certificates");
}  // namespace

base::FilePath GetTestCertsDirectory() {
  base::FilePath src_root;
  PathService::Get(base::DIR_SOURCE_ROOT, &src_root);
  return src_root.Append(kCertificateRelativePath);
}

base::FilePath GetTestClientCertsDirectory() {
#if defined(OS_ANDROID)
  return base::FilePath(kCertificateRelativePath);
#else
  return GetTestCertsDirectory();
#endif
}

base::FilePath GetWebSocketTestDataDirectory() {
  base::FilePath data_dir(FILE_PATH_LITERAL("net/data/websocket"));
  return data_dir;
}

}  // namespace net
