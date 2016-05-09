// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/spdy_balsa_utils.h"

#include <memory>
#include <string>

#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "net/base/linked_hash_map.h"
#include "net/quic/quic_flags.h"
#include "net/quic/spdy_utils.h"
#include "net/spdy/spdy_frame_builder.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_protocol.h"
#include "net/tools/balsa/balsa_headers.h"
#include "url/gurl.h"

using base::StringPiece;
using base::StringPieceHash;
using std::make_pair;
using std::pair;
using std::string;

namespace net {
namespace {

const char kV4Host[] = ":authority";

const char kV3Host[] = ":host";
const char kV3Path[] = ":path";
const char kV3Scheme[] = ":scheme";
const char kV3Method[] = ":method";
const char kV3Status[] = ":status";
const char kV3Version[] = ":version";

void PopulateSpdyHeaderBlock(const BalsaHeaders& headers,
                             SpdyHeaderBlock* block,
                             bool allow_empty_values) {
  using HeaderValuesMap =
      linked_hash_map<StringPiece, std::vector<StringPiece>, StringPieceHash>;
  std::deque<string> names;
  HeaderValuesMap header_values_map;
  // First, gather references to all values for each name.
  for (BalsaHeaders::const_header_lines_iterator hi =
           headers.header_lines_begin();
       hi != headers.header_lines_end(); ++hi) {
    if ((hi->second.length() == 0) && !allow_empty_values) {
      DVLOG(1) << "Dropping empty header " << hi->first.as_string()
               << " from headers";
      continue;
    }
    const string name = base::ToLowerASCII(hi->first.as_string());
    names.push_back(name);
    header_values_map[name].push_back(hi->second);
  }
  // Then, write joined representations to the header block.
  for (const auto& header : header_values_map) {
    if (header.second.size() == 1) {
      // Avoid string allocation for the single value case.
      block->ReplaceOrAppendHeader(header.first, header.second[0]);
    } else {
      StringPiece separator("\0", 1);
      auto it = header.second.begin();
      string value = it->as_string();
      ++it;
      for (; it != header.second.end(); ++it) {
        separator.AppendToString(&value);
        value.append(it->data(), it->size());
      }
      block->ReplaceOrAppendHeader(header.first, value);
    }
  }
}

void PopulateSpdy4RequestHeaderBlock(const BalsaHeaders& headers,
                                     const string& scheme,
                                     const string& host_and_port,
                                     const string& path,
                                     SpdyHeaderBlock* block) {
  PopulateSpdyHeaderBlock(headers, block, true);
  StringPiece host_header = headers.GetHeader("Host");
  if (!host_header.empty()) {
    DCHECK(host_and_port.empty() || host_header == host_and_port);
    block->insert(make_pair(kV4Host, host_header));
    // PopulateSpdyHeaderBlock already added the "host" header,
    // which is invalid for SPDY4.
    block->erase("host");
  } else {
    block->insert(make_pair(kV4Host, host_and_port));
  }
  block->insert(make_pair(kV3Path, path));
  block->insert(make_pair(kV3Scheme, scheme));

  if (!headers.request_method().empty()) {
    block->insert(make_pair(kV3Method, headers.request_method()));
  }
}

void PopulateSpdyResponseHeaderBlock(SpdyMajorVersion version,
                                     const BalsaHeaders& headers,
                                     SpdyHeaderBlock* block) {
  if (version <= SPDY3) {
    string status = headers.response_code().as_string();
    status.append(" ");
    status.append(headers.response_reason_phrase().as_string());
    (*block)[kV3Status] = status;
    (*block)[kV3Version] = headers.response_version();
  } else {
    (*block)[kV3Status] = headers.response_code();
  }

  PopulateSpdyHeaderBlock(headers, block, true);
}

bool IsSpecialSpdyHeader(SpdyHeaderBlock::const_iterator header,
                         BalsaHeaders* headers) {
  return header->first.empty() || header->second.empty() ||
         header->first[0] == ':';
}

// The reason phrase should match regexp [\d\d\d [^\r\n]+].  If not, we will
// fail to parse it.
bool ParseReasonAndStatus(StringPiece status_and_reason,
                          BalsaHeaders* headers) {
  int status;
  if (!base::StringToInt(status_and_reason, &status)) {
    return false;
  }
  headers->SetResponseCode(status_and_reason);
  headers->SetResponseCode(status_and_reason);
  headers->set_parsed_response_code(status);
  return true;
}

// static
void SpdyHeadersToResponseHeaders(const SpdyHeaderBlock& header_block,
                                  BalsaHeaders* request_headers) {
  typedef SpdyHeaderBlock::const_iterator BlockIt;

  BlockIt status_it = header_block.find(kV3Status);
  BlockIt end_it = header_block.end();
  if (status_it == end_it) {
    return;
  }

  if (!ParseReasonAndStatus(status_it->second, request_headers)) {
    return;
  }

  for (BlockIt it = header_block.begin(); it != header_block.end(); ++it) {
    if (!IsSpecialSpdyHeader(it, request_headers)) {
      request_headers->AppendHeader(it->first, it->second);
    }
  }
}

// static
void SpdyHeadersToRequestHeaders(const SpdyHeaderBlock& header_block,
                                 BalsaHeaders* request_headers) {
  typedef SpdyHeaderBlock::const_iterator BlockIt;

  BlockIt authority_it = header_block.find(kV4Host);
  BlockIt host_it = header_block.find(kV3Host);
  BlockIt method_it = header_block.find(kV3Method);
  BlockIt path_it = header_block.find(kV3Path);
  BlockIt scheme_it = header_block.find(kV3Scheme);
  BlockIt end_it = header_block.end();

  string method;
  if (method_it == end_it) {
    method = "GET";
  } else {
    method = method_it->second.as_string();
  }
  string uri;
  if (path_it == end_it) {
    uri = "/";
  } else {
    uri = path_it->second.as_string();
  }
  request_headers->SetRequestFirstlineFromStringPieces(
      method, uri, net::kHttp2VersionString);

  if (scheme_it == end_it) {
    request_headers->AppendHeader("Scheme", "https");
  } else {
    request_headers->AppendHeader("Scheme", scheme_it->second);
  }
  if (authority_it != end_it) {
    request_headers->AppendHeader("host", authority_it->second);
  } else if (host_it != end_it) {
    request_headers->AppendHeader("host", host_it->second);
  }

  for (BlockIt it = header_block.begin(); it != header_block.end(); ++it) {
    if (!IsSpecialSpdyHeader(it, request_headers)) {
      request_headers->AppendHeader(it->first, it->second);
    }
  }
}

// static
void SpdyHeadersToBalsaHeaders(const SpdyHeaderBlock& block,
                               BalsaHeaders* headers,
                               bool isResponse) {
  if (isResponse) {
    SpdyHeadersToResponseHeaders(block, headers);
    return;
  }
  SpdyHeadersToRequestHeaders(block, headers);
}

}  // namespace

// static
SpdyHeaderBlock SpdyBalsaUtils::RequestHeadersToSpdyHeaders(
    const BalsaHeaders& request_headers) {
  string scheme;
  string host_and_port;
  string path;

  string url = request_headers.request_uri().as_string();
  if (url.empty() || url[0] == '/') {
    path = url;
  } else {
    std::unique_ptr<GURL> request_uri(new GURL(url));
    if (request_headers.request_method() == "CONNECT") {
      path = url;
    } else {
      path = request_uri->path();
      if (!request_uri->query().empty()) {
        path = path + "?" + request_uri->query();
      }
      host_and_port = request_uri->host();
      scheme = request_uri->scheme();
    }
  }

  DCHECK(!scheme.empty());
  DCHECK(!host_and_port.empty());
  DCHECK(!path.empty());

  SpdyHeaderBlock block;
  PopulateSpdy4RequestHeaderBlock(request_headers, scheme, host_and_port, path,
                                  &block);
  return block;
}

// static
SpdyHeaderBlock SpdyBalsaUtils::ResponseHeadersToSpdyHeaders(
    const BalsaHeaders& response_headers) {
  SpdyHeaderBlock block;
  PopulateSpdyResponseHeaderBlock(HTTP2, response_headers, &block);
  return block;
}

// static
string SpdyBalsaUtils::SerializeResponseHeaders(
    const BalsaHeaders& response_headers) {
  SpdyHeaderBlock block = ResponseHeadersToSpdyHeaders(response_headers);

  return net::SpdyUtils::SerializeUncompressedHeaders(block);
}

// static
void SpdyBalsaUtils::SpdyHeadersToResponseHeaders(const SpdyHeaderBlock& block,
                                                  BalsaHeaders* headers) {
  SpdyHeadersToBalsaHeaders(block, headers, true);
}

// static
void SpdyBalsaUtils::SpdyHeadersToRequestHeaders(const SpdyHeaderBlock& block,
                                                 BalsaHeaders* headers) {
  SpdyHeadersToBalsaHeaders(block, headers, false);
}

}  // namespace net
