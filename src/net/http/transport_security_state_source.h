// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_TRANSPORT_SECURITY_STATE_SOURCE_H_
#define NET_HTTP_TRANSPORT_SECURITY_STATE_SOURCE_H_

namespace net {

struct TransportSecurityStateSource {
  struct Pinset {
    const char* const* const accepted_pins;
    const char* const* const rejected_pins;
    const char* const report_uri;
  };

  const uint8_t* huffman_tree;
  size_t huffman_tree_size;
  const uint8_t* preloaded_data;
  size_t preloaded_bits;
  size_t root_position;
  const char* const* expect_ct_report_uris;
  const char* const* expect_staple_report_uris;
  const Pinset* pinsets;
  size_t pinsets_count;
};

}  // namespace net

#endif  // NET_HTTP_TRANSPORT_SECURITY_STATE_SOURCE_H_
