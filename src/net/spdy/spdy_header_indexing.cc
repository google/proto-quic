// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_header_indexing.h"

#include "net/spdy/spdy_bug_tracker.h"

using base::StringPiece;

namespace net {

int32_t FLAGS_gfe_spdy_indexing_set_bound = 50;
int32_t FLAGS_gfe_spdy_tracking_set_bound = 1000;

HeaderIndexing::HeaderIndexing()
    : indexing_set_bound_(FLAGS_gfe_spdy_indexing_set_bound),
      tracking_set_bound_(FLAGS_gfe_spdy_tracking_set_bound) {
  SPDY_BUG_IF(indexing_set_bound_ >= tracking_set_bound_)
      << "Tracking set should be larger than indexing set";
}

HeaderIndexing::~HeaderIndexing() {}

void HeaderIndexing::CreateInitIndexingHeaders() {
  const std::string initial_fields[] = {
      // Estimated top 100 fields.
      "alt-svc",
      "date",
      "cache-control",
      "content-type",
      "expires",
      "location",
      "x-xss-protection",
      "p3p",
      "set-cookie",
      "alternate-protocol",
      "last-modified",
      "server",
      "x-snapchat-request-id",
      "content-disposition",
      "strict-transport-security",
      "x-content-type-options",
      "content-security-policy",
      "x-frame-options",
      "x-snapchat-notice",
      "pragma",
      ":status",
      "content-length",
      "etag",
      "x-cloud-trace-context",
      "vary",
      "access-control-expose-headers",
      "content-encoding",
      "access-control-allow-origin",
      "age",
      ":protocol",
      "via",
      "x-robots-tag",
      "link",
      "access-control-allow-headers",
      "x-google-session-info",
      "x-google-backends",
      "x-google-gfe-request-trace",
      "warning",
      "x-guploader-uploadid",
      "x-cup-server-proof",
      "timing-allow-origin",
      "x-google-trace",
      "access-control-allow-credentials",
      "google-delayed-impression",
      "google-creative-id",
      "access-control-allow-methods",
      "x-ua-compatible",
      "x-google-gfe-response-code-details-trace",
      "google-lineitem-id",
      "version",
      "x-google-dos-service-trace",
      "x-google-service",
      "x-google-gfe-service-trace",
      "sane-time-millis",
      "x-google-netmon-label",
      "x-google-apiary-auth-scopes",
      "x-seed-signature",
      "content-security-policy-report-only",
      "x-auto-login",
      "x-original-content-length",
      "accept-ranges",
      "x-goog-hash",
      "x-google-gfe-response-body-transformations",
      "cf-ray",
      "x-content-security-policy-report-only",
      "x-google-shellfish-status",
      "x-amz-id-2",
      "get-dictionary",
      "grpc-message",
      "x-hw",
      "x-google-gfe-backend-request-info",
      "x-goog-upload-header-x-google-session-info",
      "x-amz-cf-id",
      "x-powered-by",
      "www-authenticate",
      "access-control-max-age",
      "x-spf-response-type",
      "x-goog-meta-encoded_request",
      "x-goog-generation",
      "x-google-gslb-service",
      "x-google-servertype",
      "x-cache",
      "x-chromium-appcache-fallback-override",
      "x-goog-upload-url",
      "x-goog-upload-control-url",
      "content-range",
      "x-seen-by",
      "x-google-apps-framework-action",
      "content-location",
      "x-daystart",
      "x-varnish",
      "fastly-debug-digest",
      "x-daynum",
      "x-goog-stored-content-encoding",
      "x-goog-storage-class",
      "x-google-cookies-blocked",
      "x-range-md5",
      "x-served-by",
      "x-client-wire-protocol",
      "content-language",
  };

  indexing_set_.clear();
  indexing_set_ =
      HeaderSet(initial_fields, initial_fields + arraysize(initial_fields));
  tracking_set_ =
      HeaderSet(initial_fields, initial_fields + arraysize(initial_fields));
}

bool HeaderIndexing::ShouldIndex(StringPiece header, StringPiece /* value */) {
  total_header_count_++;
  if (header.empty()) {
    return false;
  }
  // header is in indexing set.
  std::string header_str(header.data(), header.size());
  if (indexing_set_.find(header_str) != indexing_set_.end()) {
    return true;
  }
  // header not in indexing set. Check tracking set.
  if (tracking_set_.find(header_str) != tracking_set_.end()) {
    // Seen this header before. Add it to indexing set.
    TryInsertHeader(std::move(header_str), &indexing_set_, indexing_set_bound_);
    missed_header_in_tracking_++;
  } else {
    // Add header to tracking set.
    TryInsertHeader(std::move(header_str), &tracking_set_, tracking_set_bound_);
    missed_header_in_indexing_++;
  }
  return false;
}

void HeaderIndexing::TryInsertHeader(std::string&& header,
                                     HeaderSet* set,
                                     size_t bound) {
  std::pair<HeaderSet::iterator, bool> result = set->insert(std::move(header));
  if (set->size() > bound) {
    // Reach the size limit. Remove the header next to the newly added header.
    // If the new header is at the end, look for the "next" element at the
    // beginning.
    HeaderSet::iterator it = std::next(result.first);
    if (it != set->end()) {
      set->erase(it);
    } else {
      set->erase(set->begin());
    }
  }
}

}  // namespace net
