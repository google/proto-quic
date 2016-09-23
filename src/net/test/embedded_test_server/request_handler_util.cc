// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/embedded_test_server/request_handler_util.h"

#include <stdlib.h>

#include <ctime>
#include <sstream>
#include <utility>

#include "base/base64.h"
#include "base/files/file_util.h"
#include "base/format_macros.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_restrictions.h"
#include "net/base/escape.h"
#include "net/base/url_util.h"
#include "net/http/http_byte_range.h"
#include "net/http/http_util.h"
#include "net/test/embedded_test_server/http_request.h"
#include "url/gurl.h"

namespace net {
namespace test_server {
namespace {

const UnescapeRule::Type kUnescapeAll =
    UnescapeRule::SPACES | UnescapeRule::PATH_SEPARATORS |
    UnescapeRule::URL_SPECIAL_CHARS_EXCEPT_PATH_SEPARATORS |
    UnescapeRule::SPOOFING_AND_CONTROL_CHARS |
    UnescapeRule::REPLACE_PLUS_WITH_SPACE;

std::string GetContentType(const base::FilePath& path) {
  if (path.MatchesExtension(FILE_PATH_LITERAL(".crx")))
    return "application/x-chrome-extension";
  if (path.MatchesExtension(FILE_PATH_LITERAL(".exe")))
    return "application/octet-stream";
  if (path.MatchesExtension(FILE_PATH_LITERAL(".gif")))
    return "image/gif";
  if (path.MatchesExtension(FILE_PATH_LITERAL(".gzip")) ||
      path.MatchesExtension(FILE_PATH_LITERAL(".gz"))) {
    return "application/x-gzip";
  }
  if (path.MatchesExtension(FILE_PATH_LITERAL(".jpeg")) ||
      path.MatchesExtension(FILE_PATH_LITERAL(".jpg"))) {
    return "image/jpeg";
  }
  if (path.MatchesExtension(FILE_PATH_LITERAL(".js")))
    return "application/javascript";
  if (path.MatchesExtension(FILE_PATH_LITERAL(".json")))
    return "application/json";
  if (path.MatchesExtension(FILE_PATH_LITERAL(".pdf")))
    return "application/pdf";
  if (path.MatchesExtension(FILE_PATH_LITERAL(".txt")))
    return "text/plain";
  if (path.MatchesExtension(FILE_PATH_LITERAL(".wav")))
    return "audio/wav";
  if (path.MatchesExtension(FILE_PATH_LITERAL(".xml")))
    return "text/xml";
  if (path.MatchesExtension(FILE_PATH_LITERAL(".html")) ||
      path.MatchesExtension(FILE_PATH_LITERAL(".htm"))) {
    return "text/html";
  }
  return "";
}

}  // namespace

bool ShouldHandle(const HttpRequest& request, const std::string& path_prefix) {
  GURL url = request.GetURL();
  return url.path() == path_prefix ||
         base::StartsWith(url.path(), path_prefix + "/",
                          base::CompareCase::SENSITIVE);
}

std::unique_ptr<HttpResponse> HandlePrefixedRequest(
    const std::string& prefix,
    const EmbeddedTestServer::HandleRequestCallback& handler,
    const HttpRequest& request) {
  if (ShouldHandle(request, prefix))
    return handler.Run(request);
  return nullptr;
}

RequestQuery ParseQuery(const GURL& url) {
  RequestQuery queries;
  for (QueryIterator it(url); !it.IsAtEnd(); it.Advance()) {
    queries[net::UnescapeURLComponent(it.GetKey(), kUnescapeAll)].push_back(
        it.GetUnescapedValue());
  }
  return queries;
}

void GetFilePathWithReplacements(const std::string& original_file_path,
                                 const base::StringPairs& text_to_replace,
                                 std::string* replacement_path) {
  std::string new_file_path = original_file_path;
  for (const auto& replacement : text_to_replace) {
    const std::string& old_text = replacement.first;
    const std::string& new_text = replacement.second;
    std::string base64_old;
    std::string base64_new;
    base::Base64Encode(old_text, &base64_old);
    base::Base64Encode(new_text, &base64_new);
    if (new_file_path == original_file_path)
      new_file_path += "?";
    else
      new_file_path += "&";
    new_file_path += "replace_text=";
    new_file_path += base64_old;
    new_file_path += ":";
    new_file_path += base64_new;
  }

  *replacement_path = new_file_path;
}

// Handles |request| by serving a file from under |server_root|.
std::unique_ptr<HttpResponse> HandleFileRequest(
    const base::FilePath& server_root,
    const HttpRequest& request) {
  // This is a test-only server. Ignore I/O thread restrictions.
  // TODO(svaldez): Figure out why thread is I/O restricted in the first place.
  base::ThreadRestrictions::ScopedAllowIO allow_io;

  // A proxy request will have an absolute path. Simulate the proxy by stripping
  // the scheme, host, and port.
  GURL request_url = request.GetURL();
  std::string relative_path(request_url.path());

  std::string post_prefix("/post/");
  if (base::StartsWith(relative_path, post_prefix,
                       base::CompareCase::SENSITIVE)) {
    if (request.method != METHOD_POST)
      return nullptr;
    relative_path = relative_path.substr(post_prefix.size() - 1);
  }

  RequestQuery query = ParseQuery(request_url);

  std::unique_ptr<BasicHttpResponse> failed_response(new BasicHttpResponse);
  failed_response->set_code(HTTP_NOT_FOUND);

  if (query.find("expected_body") != query.end()) {
    if (request.content.find(query["expected_body"].front()) ==
        std::string::npos) {
      return std::move(failed_response);
    }
  }

  if (query.find("expected_headers") != query.end()) {
    for (const auto& header : query["expected_headers"]) {
      if (header.find(":") == std::string::npos)
        return std::move(failed_response);
      std::string key = header.substr(0, header.find(":"));
      std::string value = header.substr(header.find(":") + 1);
      if (request.headers.find(key) == request.headers.end() ||
          request.headers.at(key) != value) {
        return std::move(failed_response);
      }
    }
  }

  // Trim the first byte ('/').
  DCHECK(base::StartsWith(relative_path, "/", base::CompareCase::SENSITIVE));
  std::string request_path = relative_path.substr(1);
  base::FilePath file_path(server_root.AppendASCII(request_path));
  std::string file_contents;
  if (!base::ReadFileToString(file_path, &file_contents)) {
    file_path = file_path.AppendASCII("index.html");
    if (!base::ReadFileToString(file_path, &file_contents))
      return nullptr;
  }

  if (request.method == METHOD_HEAD)
    file_contents = "";

  if (query.find("replace_text") != query.end()) {
    for (const auto& replacement : query["replace_text"]) {
      if (replacement.find(":") == std::string::npos)
        return std::move(failed_response);
      std::string find;
      std::string with;
      base::Base64Decode(replacement.substr(0, replacement.find(":")), &find);
      base::Base64Decode(replacement.substr(replacement.find(":") + 1), &with);
      base::ReplaceSubstringsAfterOffset(&file_contents, 0, find, with);
    }
  }

  base::FilePath headers_path(
      file_path.AddExtension(FILE_PATH_LITERAL("mock-http-headers")));

  if (base::PathExists(headers_path)) {
    std::string headers_contents;

    if (!base::ReadFileToString(headers_path, &headers_contents))
      return nullptr;

    return base::MakeUnique<RawHttpResponse>(headers_contents, file_contents);
  }

  std::unique_ptr<BasicHttpResponse> http_response(new BasicHttpResponse);
  http_response->set_code(HTTP_OK);

  if (request.headers.find("Range") != request.headers.end()) {
    std::vector<HttpByteRange> ranges;

    if (HttpUtil::ParseRangeHeader(request.headers.at("Range"), &ranges) &&
        ranges.size() == 1) {
      ranges[0].ComputeBounds(file_contents.size());
      size_t start = ranges[0].first_byte_position();
      size_t end = ranges[0].last_byte_position();

      http_response->set_code(HTTP_PARTIAL_CONTENT);
      http_response->AddCustomHeader(
          "Content-Range",
          base::StringPrintf("bytes %" PRIuS "-%" PRIuS "/%" PRIuS, start, end,
                             file_contents.size()));

      file_contents = file_contents.substr(start, end - start + 1);
    }
  }

  http_response->set_content_type(GetContentType(file_path));
  http_response->AddCustomHeader("Accept-Ranges", "bytes");
  http_response->AddCustomHeader("ETag", "'" + file_path.MaybeAsASCII() + "'");
  http_response->set_content(file_contents);
  return std::move(http_response);
}

}  // namespace test_server
}  // namespace net
