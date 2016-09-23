// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TEST_EMBEDDED_TEST_SERVER_REQUEST_HANDLER_UTIL_H_
#define NET_TEST_EMBEDDED_TEST_SERVER_REQUEST_HANDLER_UTIL_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/strings/string_split.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/embedded_test_server/http_response.h"

namespace url {
class GURL;
}

namespace net {
namespace test_server {
struct HttpRequest;

// This file is only meant for compatibility with testserver.py. No
// additional handlers should be added here that don't affect multiple
// distinct tests.

using RequestQuery = std::map<std::string, std::vector<std::string>>;

// Return whether |request| starts with a URL path of |url|.
bool ShouldHandle(const HttpRequest& request, const std::string& prefix_path);

// Calls |handler| if the |request| URL starts with |prefix|.
std::unique_ptr<HttpResponse> HandlePrefixedRequest(
    const std::string& prefix,
    const EmbeddedTestServer::HandleRequestCallback& handler,
    const HttpRequest& request);

// Parses |url| to get the query and places it into a map.
RequestQuery ParseQuery(const GURL& url);

// Returns a path that serves the contents of the file at |original_path|
// with all the text matching the elements of |text_to_replace| replaced
// with the corresponding values. The path is returned in |replacement_path|.
// The result path is only usable by HandleFileRequest which will perform the
// actual replacements of the file contents.
// TODO(svaldez): Modify to return |replacement_path| instead of passing by
// reference.
void GetFilePathWithReplacements(const std::string& original_path,
                                 const base::StringPairs& text_to_replace,
                                 std::string* replacement_path);

// Handles |request| by serving a file from under |server_root|.
std::unique_ptr<HttpResponse> HandleFileRequest(
    const base::FilePath& server_root,
    const HttpRequest& request);

}  // namespace test_server
}  // namespace net

#endif  // NET_TEST_EMBEDDED_TEST_SERVER_REQUEST_HANDLER_UTIL_H_
