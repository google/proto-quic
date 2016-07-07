// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_in_memory_cache.h"

#include <utility>

#include "base/files/file_enumerator.h"
#include "base/files/file_util.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/spdy/spdy_http_utils.h"

using base::FilePath;
using base::IntToString;
using base::StringPiece;
using std::list;
using std::string;

namespace net {

namespace {

class ResourceFileImpl : public net::QuicInMemoryCache::ResourceFile {
 public:
  explicit ResourceFileImpl(const base::FilePath& file_name)
      : ResourceFile(file_name) {}

  void Read() override {
    base::ReadFileToString(FilePath(file_name_), &file_contents_);

    int file_len = static_cast<int>(file_contents_.length());
    int headers_end =
        HttpUtil::LocateEndOfHeaders(file_contents_.data(), file_len);
    if (headers_end < 1) {
      LOG(DFATAL) << "Headers invalid or empty, ignoring: "
                  << file_name_.value();
      return;
    }
    http_headers_ = new HttpResponseHeaders(
        HttpUtil::AssembleRawHeaders(file_contents_.data(), headers_end));

    if (http_headers_->GetNormalizedHeader("X-Original-Url", &url_)) {
      x_original_url_ = StringPiece(url_);
      HandleXOriginalUrl();
    }

    // X-Push-URL header is a relatively quick way to support sever push
    // in the toy server.  A production server should use link=preload
    // stuff as described in https://w3c.github.io/preload/.
    StringPiece x_push_url("X-Push-Url");
    if (http_headers_->HasHeader(x_push_url)) {
      size_t iter = 0;
      std::unique_ptr<string> push_url(new string());
      while (
          http_headers_->EnumerateHeader(&iter, x_push_url, push_url.get())) {
        push_urls_.push_back(StringPiece(*push_url));
        push_url_values_.push_back(std::move(push_url));
        push_url.reset(new string());
      }
    }

    body_ = StringPiece(file_contents_.data() + headers_end,
                        file_contents_.size() - headers_end);

    CreateSpdyHeadersFromHttpResponse(*http_headers_, HTTP2, &spdy_headers_);
  }

 private:
  scoped_refptr<HttpResponseHeaders> http_headers_;
  string url_;
  list<std::unique_ptr<string>> push_url_values_;

  DISALLOW_COPY_AND_ASSIGN(ResourceFileImpl);
};

}  // namespace

QuicInMemoryCache::ServerPushInfo::ServerPushInfo(GURL request_url,
                                                  SpdyHeaderBlock headers,
                                                  net::SpdyPriority priority,
                                                  string body)
    : request_url(request_url),
      headers(std::move(headers)),
      priority(priority),
      body(body) {}

QuicInMemoryCache::ServerPushInfo::ServerPushInfo(const ServerPushInfo& other)
    : request_url(other.request_url),
      headers(other.headers.Clone()),
      priority(other.priority),
      body(other.body) {}

QuicInMemoryCache::Response::Response() : response_type_(REGULAR_RESPONSE) {}

QuicInMemoryCache::Response::~Response() {}

QuicInMemoryCache::ResourceFile::ResourceFile(const base::FilePath& file_name)
    : file_name_(file_name), file_name_string_(file_name.AsUTF8Unsafe()) {}

QuicInMemoryCache::ResourceFile::~ResourceFile() {}

void QuicInMemoryCache::ResourceFile::SetHostPathFromBase(StringPiece base) {
  size_t path_start = base.find_first_of('/');
  DCHECK_LT(0UL, path_start);
  host_ = base.substr(0, path_start);
  size_t query_start = base.find_first_of(',');
  if (query_start > 0) {
    path_ = base.substr(path_start, query_start - 1);
  } else {
    path_ = base.substr(path_start);
  }
}

StringPiece QuicInMemoryCache::ResourceFile::RemoveScheme(StringPiece url) {
  if (url.starts_with("https://")) {
    url.remove_prefix(8);
  } else if (url.starts_with("http://")) {
    url.remove_prefix(7);
  }
  return url;
}

void QuicInMemoryCache::ResourceFile::HandleXOriginalUrl() {
  StringPiece url(x_original_url_);
  // Remove the protocol so we can add it below.
  url = RemoveScheme(url);
  SetHostPathFromBase(url);
}

// static
QuicInMemoryCache* QuicInMemoryCache::GetInstance() {
  return base::Singleton<QuicInMemoryCache>::get();
}

const QuicInMemoryCache::Response* QuicInMemoryCache::GetResponse(
    StringPiece host,
    StringPiece path) const {
  ResponseMap::const_iterator it = responses_.find(GetKey(host, path));
  if (it == responses_.end()) {
    DVLOG(1) << "Get response for resource failed: host " << host << " path "
             << path;
    if (default_response_.get()) {
      return default_response_.get();
    }
    return nullptr;
  }
  return it->second;
}

typedef QuicInMemoryCache::ServerPushInfo ServerPushInfo;

void QuicInMemoryCache::AddSimpleResponse(StringPiece host,
                                          StringPiece path,
                                          int response_code,
                                          StringPiece body) {
  SpdyHeaderBlock response_headers;
  response_headers[":status"] = IntToString(response_code);
  response_headers["content-length"] =
      IntToString(static_cast<int>(body.length()));
  AddResponse(host, path, std::move(response_headers), body);
}

void QuicInMemoryCache::AddSimpleResponseWithServerPushResources(
    StringPiece host,
    StringPiece path,
    int response_code,
    StringPiece body,
    list<ServerPushInfo> push_resources) {
  AddSimpleResponse(host, path, response_code, body);
  MaybeAddServerPushResources(host, path, push_resources);
}

void QuicInMemoryCache::AddDefaultResponse(Response* response) {
  default_response_.reset(response);
}

void QuicInMemoryCache::AddResponse(StringPiece host,
                                    StringPiece path,
                                    SpdyHeaderBlock response_headers,
                                    StringPiece response_body) {
  AddResponseImpl(host, path, REGULAR_RESPONSE, std::move(response_headers),
                  response_body, SpdyHeaderBlock());
}

void QuicInMemoryCache::AddResponse(StringPiece host,
                                    StringPiece path,
                                    SpdyHeaderBlock response_headers,
                                    StringPiece response_body,
                                    SpdyHeaderBlock response_trailers) {
  AddResponseImpl(host, path, REGULAR_RESPONSE, std::move(response_headers),
                  response_body, std::move(response_trailers));
}

void QuicInMemoryCache::AddSpecialResponse(StringPiece host,
                                           StringPiece path,
                                           SpecialResponseType response_type) {
  AddResponseImpl(host, path, response_type, SpdyHeaderBlock(), "",
                  SpdyHeaderBlock());
}

QuicInMemoryCache::QuicInMemoryCache() {}

void QuicInMemoryCache::ResetForTests() {
  STLDeleteValues(&responses_);
  server_push_resources_.clear();
}

void QuicInMemoryCache::InitializeFromDirectory(const string& cache_directory) {
  if (cache_directory.empty()) {
    QUIC_BUG << "cache_directory must not be empty.";
    return;
  }
  VLOG(1) << "Attempting to initialize QuicInMemoryCache from directory: "
          << cache_directory;
  FilePath directory(FilePath::FromUTF8Unsafe(cache_directory));
  base::FileEnumerator file_list(directory, true, base::FileEnumerator::FILES);
  list<std::unique_ptr<ResourceFile>> resource_files;
  for (FilePath file_iter = file_list.Next(); !file_iter.empty();
       file_iter = file_list.Next()) {
    // Need to skip files in .svn directories
    if (file_iter.value().find(FILE_PATH_LITERAL("/.svn/")) != string::npos) {
      continue;
    }

    std::unique_ptr<ResourceFile> resource_file(
        new ResourceFileImpl(file_iter));

    // Tease apart filename into host and path.
    StringPiece base(resource_file->file_name());
    base.remove_prefix(cache_directory.length());
    if (base[0] == '/') {
      base.remove_prefix(1);
    }

    resource_file->SetHostPathFromBase(base);
    resource_file->Read();

    AddResponse(resource_file->host(), resource_file->path(),
                resource_file->spdy_headers().Clone(), resource_file->body());

    resource_files.push_back(std::move(resource_file));
  }

  for (const auto& resource_file : resource_files) {
    list<ServerPushInfo> push_resources;
    for (const auto& push_url : resource_file->push_urls()) {
      GURL url(push_url);
      const Response* response = GetResponse(url.host(), url.path());
      if (!response) {
        QUIC_BUG << "Push URL '" << push_url << "' not found.";
        return;
      }
      push_resources.push_back(ServerPushInfo(url, response->headers().Clone(),
                                              net::kV3LowestPriority,
                                              response->body().as_string()));
    }
    MaybeAddServerPushResources(resource_file->host(), resource_file->path(),
                                push_resources);
  }
}

list<ServerPushInfo> QuicInMemoryCache::GetServerPushResources(
    string request_url) {
  list<ServerPushInfo> resources;
  auto resource_range = server_push_resources_.equal_range(request_url);
  for (auto it = resource_range.first; it != resource_range.second; ++it) {
    resources.push_back(it->second);
  }
  DVLOG(1) << "Found " << resources.size() << " push resources for "
           << request_url;
  return resources;
}

QuicInMemoryCache::~QuicInMemoryCache() {
  STLDeleteValues(&responses_);
}

void QuicInMemoryCache::AddResponseImpl(StringPiece host,
                                        StringPiece path,
                                        SpecialResponseType response_type,
                                        SpdyHeaderBlock response_headers,
                                        StringPiece response_body,
                                        SpdyHeaderBlock response_trailers) {
  DCHECK(!host.empty()) << "Host must be populated, e.g. \"www.google.com\"";
  string key = GetKey(host, path);
  if (ContainsKey(responses_, key)) {
    QUIC_BUG << "Response for '" << key << "' already exists!";
    return;
  }
  Response* new_response = new Response();
  new_response->set_response_type(response_type);
  new_response->set_headers(std::move(response_headers));
  new_response->set_body(response_body);
  new_response->set_trailers(std::move(response_trailers));
  DVLOG(1) << "Add response with key " << key;
  responses_[key] = new_response;
}

string QuicInMemoryCache::GetKey(StringPiece host, StringPiece path) const {
  return host.as_string() + path.as_string();
}

void QuicInMemoryCache::MaybeAddServerPushResources(
    StringPiece request_host,
    StringPiece request_path,
    list<ServerPushInfo> push_resources) {
  string request_url = GetKey(request_host, request_path);

  for (const auto& push_resource : push_resources) {
    if (PushResourceExistsInCache(request_url, push_resource)) {
      continue;
    }

    DVLOG(1) << "Add request-resource association: request url " << request_url
             << " push url " << push_resource.request_url
             << " response headers " << push_resource.headers.DebugString();
    server_push_resources_.insert(std::make_pair(request_url, push_resource));
    string host = push_resource.request_url.host();
    if (host.empty()) {
      host = request_host.as_string();
    }
    string path = push_resource.request_url.path();
    if (responses_.find(GetKey(host, path)) == responses_.end()) {
      // Add a server push response to responses map, if it is not in the map.
      StringPiece body = push_resource.body;
      DVLOG(1) << "Add response for push resource: host " << host << " path "
               << path;
      AddResponse(host, path, push_resource.headers.Clone(), body);
    }
  }
}

bool QuicInMemoryCache::PushResourceExistsInCache(string original_request_url,
                                                  ServerPushInfo resource) {
  auto resource_range =
      server_push_resources_.equal_range(original_request_url);
  for (auto it = resource_range.first; it != resource_range.second; ++it) {
    ServerPushInfo push_resource = it->second;
    if (push_resource.request_url.spec() == resource.request_url.spec()) {
      return true;
    }
  }
  return false;
}

}  // namespace net
