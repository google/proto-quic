// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TRAFFIC_ANNOTATION_NETWORK_TRAFFIC_ANNOTATION_H_
#define NET_TRAFFIC_ANNOTATION_NETWORK_TRAFFIC_ANNOTATION_H_

namespace net {

// Defined type for network traffic annotation tags.
using NetworkTrafficAnnotationTag = const char* const;

// Function to convert a network traffic annotation's unique id and protobuf
// text into a NetworkTrafficAnnotationTag.
//
// This function serves as a tag that can be discovered and extracted via
// clang tools. This allows reviewing all network traffic that is generated
// and annotated by Chrome.
//
// |unique_id| should be a string that uniquely identifies this annotation
// across all of Chromium source code.
// |proto| is a text-encoded NetworkTrafficAnnotation protobuf (see
// tools/traffic_annotation/traffic_annotation.proto)
//
// An empty and a sample template for the text-encoded protobuf can be found in
// //tools/traffic_annotation/sample_traffic_annotation.cc.
// TODO(crbug.com/690323): Add tools to check annotation text's format during
// presubmit checks.
template <size_t N1, size_t N2>
constexpr NetworkTrafficAnnotationTag DefineNetworkTrafficAnnotation(
    const char (&unique_id)[N1],
    const char (&proto)[N2]) {
  return unique_id;
}

}  // namespace net

// Placeholder for unannotated usages.
#define NO_TRAFFIC_ANNOTATION_YET \
  net::DefineNetworkTrafficAnnotation("Undefined", "Nothing here yet.")

#endif  // NET_TRAFFIC_ANNOTATION_NETWORK_TRAFFIC_ANNOTATION_H_
