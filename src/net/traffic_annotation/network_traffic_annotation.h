// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TRAFFIC_ANNOTATION_NETWORK_TRAFFIC_ANNOTATION_H_
#define NET_TRAFFIC_ANNOTATION_NETWORK_TRAFFIC_ANNOTATION_H_

#include "base/logging.h"

namespace {

// Recursively compute hash code of the given string as a constant expression.
template <int N>
constexpr uint32_t recursive_hash(const char* str) {
  return static_cast<uint32_t>((recursive_hash<N - 1>(str) * 31 + str[N - 1]) %
                               138003713);
}

// Recursion stopper for the above function. Note that string of size 0 will
// result in compile error.
template <>
constexpr uint32_t recursive_hash<1>(const char* str) {
  return static_cast<uint32_t>(*str);
}

// Entry point to function that computes hash as constant expression.
#define COMPUTE_STRING_HASH(S) \
  static_cast<int32_t>(recursive_hash<sizeof(S) - 1>(S))

}  // namespace

namespace net {

// Defined types for network traffic annotation tags.
struct NetworkTrafficAnnotationTag {
  const int32_t unique_id_hash_code;
};
struct PartialNetworkTrafficAnnotationTag {
  const int32_t unique_id_hash_code;

#if !defined(NDEBUG) || defined(DCHECK_ALWAYS_ON)
  // |completing_id_hash_code| holds a reference to the hash coded unique id
  // of a network traffic annotation (or group id of several network traffic
  // annotations) that complete a partial network annotation. Please refer to
  // the description of DefinePartialNetworkTrafficAnnotation function for more
  // details.
  // This value is used by the clang tools to find linkage between partial
  // annotations and their completing parts, and is used in debug mode to check
  // if an intended completing part is added to a partial network annotation.
  const int32_t completing_id_hash_code;
#endif
};

// Function to convert a network traffic annotation's unique id and protobuf
// text into a NetworkTrafficAnnotationTag.
//
// This function serves as a tag that can be discovered and extracted via
// clang tools. This allows reviewing all network traffic that is generated
// and annotated by Chrome.
//
// |unique_id| should be a string that uniquely identifies this annotation
// across all of Chromium source code. |unique_id| should be kept unchanged
// as long as possible as its hashed value will be used for differnt logging,
// debugging, or auditing tasks.
// |proto| is a text-encoded NetworkTrafficAnnotation protobuf (see
// tools/traffic_annotation/traffic_annotation.proto)
//
// An empty and a sample template for the text-encoded protobuf can be found in
// tools/traffic_annotation/sample_traffic_annotation.cc.
// TODO(crbug.com/690323): Add tools to check annotation text's format during
// presubmit checks.
template <size_t N1, size_t N2>
constexpr NetworkTrafficAnnotationTag DefineNetworkTrafficAnnotation(
    const char (&unique_id)[N1],
    const char (&proto)[N2]) {
  return NetworkTrafficAnnotationTag({COMPUTE_STRING_HASH(unique_id)});
}

// There are cases where the network traffic annotation cannot be fully
// specified in one place. For example, in one place we know the trigger of a
// network request and in another place we know the data that will be sent. In
// these cases, we prefer that both parts of the annotation appear in context so
// that they are updated if code changes. The following functions help splitting
// the network traffic annotation into two pieces. Please refer to
// tools/traffic_annotation/sample_traffic_annotation.cc for usage samples.

// This function can be used to define a partial annotation that will be
// completed later. The completing annotation can be defined with either of
// 'CompleteNetworkTrafficAnnotation' or
// 'BranchedCompleteNetworkTrafficAnnotation' functions. In case of
// CompleteNetworkTrafficAnnotation, |completing_id| is the unique id of the
// annotation that will complete it. In the case of
// BranchedCompleteNetworkTrafficAnnotation, |completing_id| is the group id
// of the completing annotations.
template <size_t N1, size_t N2, size_t N3>
constexpr PartialNetworkTrafficAnnotationTag
DefinePartialNetworkTrafficAnnotation(const char (&unique_id)[N1],
                                      const char (&completing_id)[N2],
                                      const char (&proto)[N3]) {
#if !defined(NDEBUG) || defined(DCHECK_ALWAYS_ON)
  return PartialNetworkTrafficAnnotationTag(
      {COMPUTE_STRING_HASH(unique_id), COMPUTE_STRING_HASH(completing_id)});
#else
  return PartialNetworkTrafficAnnotationTag({COMPUTE_STRING_HASH(unique_id)});
#endif
}

// This function can be used to define a completing partial annotation. This
// annotation adds details to another annotation that is defined before.
// |partial_annotation| is the PartialNetworkTrafficAnnotationTag returned
// by a call to DefinePartialNetworkTrafficAnnotation().
template <size_t N1, size_t N2>
NetworkTrafficAnnotationTag CompleteNetworkTrafficAnnotation(
    const char (&unique_id)[N1],
    const PartialNetworkTrafficAnnotationTag& partial_annotation,
    const char (&proto)[N2]) {
#if !defined(NDEBUG) || defined(DCHECK_ALWAYS_ON)
  DCHECK(partial_annotation.completing_id_hash_code ==
             COMPUTE_STRING_HASH(unique_id) ||
         partial_annotation.unique_id_hash_code ==
             COMPUTE_STRING_HASH("test_partial") ||
         partial_annotation.unique_id_hash_code ==
             COMPUTE_STRING_HASH("undefined"));
#endif
  return NetworkTrafficAnnotationTag({partial_annotation.unique_id_hash_code});
}

// This function can be used to define a completing partial annotation that is
// branched into several annotations. In this case, |group_id| is a common id
// that is used by all members of the branch and referenced by partial
// annotation that is completed by them.
template <size_t N1, size_t N2, size_t N3>
NetworkTrafficAnnotationTag BranchedCompleteNetworkTrafficAnnotation(
    const char (&unique_id)[N1],
    const char (&group_id)[N2],
    const PartialNetworkTrafficAnnotationTag& partial_annotation,
    const char (&proto)[N3]) {
#if !defined(NDEBUG) || defined(DCHECK_ALWAYS_ON)
  DCHECK(partial_annotation.completing_id_hash_code ==
             COMPUTE_STRING_HASH(unique_id) ||
         partial_annotation.unique_id_hash_code ==
             COMPUTE_STRING_HASH("test_partial") ||
         partial_annotation.unique_id_hash_code ==
             COMPUTE_STRING_HASH("undefined"));
#endif
  return NetworkTrafficAnnotationTag({COMPUTE_STRING_HASH(unique_id)});
}

// Example for joining N x 1 partial annotations:
// N functions foo1(), ..., fooN() call one function bar(). Each
// foo...() function defines part of a network traffic annotation.
// These N partial annotations are combined with a second part in
// bar().
//
// void foo1() {
//   auto tag = DefinePartialNetworkTrafficAnnotation(
//       "call_by_foo1", "completion_by_bar", [partial_proto]);
//   bar(tag);
// }
// void foo2() {
//   auto tag = DefinePartialNetworkTrafficAnnotation(
//       "call_by_foo2", "completion_by_bar", [partial_proto]);
//   bar(tag);
// }
// void bar(PartialNetworkTrafficAnnotationTag tag) {
//   auto final_tag = CompleteNetworkTrafficAnnotation(
//     "completion_by_bar", tag, [rest_of_proto]);
//   // final_tag matches the value of tag (which is hash code of
//   // "call_by_fooX" where X can be 1 or 2).
//   net::URLFetcher::Create(..., final_tag);
// }

// Example for joining 1 x N partial annotations:
// A function foo() calls a function bar(bool param), that sends
// different network requests depending on param. Both functions
// define parts of the network traffic annotation.
//
// void foo(bool param) {
//   auto tag = DefinePartialNetworkTrafficAnnotation(
//       "call_by_foo1", "completion_by_bar", [partial_proto]);
//   bar(param, tag);
// }
// void bar(bool param, PartialNetworkTrafficAnnotationTag tag) {
//   if (param) {
//     auto final_tag = BranchedCompleteNetworkTrafficAnnotation(
//       "call_bool_branch_1", "completion_by_bar", tag, [rest_of_proto]);
//     // final_tag is hash code of "call_bool_branch_1".
//     net::URLFetcher::Create(url1, ..., final_tag);
//   } else {
//     auto final_tag = BranchedCompleteNetworkTrafficAnnotation(
//       "call_bool_branch_2", "completion_by_bar", tag, [rest_of_proto]);
//     // final_tag is hash code of "call_bool_branch_2".
//     net::URLFetcher::Create(url2, ..., final_tag);
//   }
// }

#define TRAFFIC_ANNOTATION_UNINITIALIZED -1

// Do not use this unless net-serialization is required.
// TODO(crbug.com/690323): Add tools to check constructor of this structure is
// used only in .mojom.cc files.
struct MutableNetworkTrafficAnnotationTag {
  MutableNetworkTrafficAnnotationTag()
      : unique_id_hash_code(TRAFFIC_ANNOTATION_UNINITIALIZED) {}
  explicit MutableNetworkTrafficAnnotationTag(
      const NetworkTrafficAnnotationTag& traffic_annotation)
      : unique_id_hash_code(traffic_annotation.unique_id_hash_code) {}

  int32_t unique_id_hash_code;

  explicit operator NetworkTrafficAnnotationTag() const {
    return NetworkTrafficAnnotationTag({unique_id_hash_code});
  }
};

struct MutablePartialNetworkTrafficAnnotationTag {
#if !defined(NDEBUG) || defined(DCHECK_ALWAYS_ON)
  MutablePartialNetworkTrafficAnnotationTag()
      : unique_id_hash_code(TRAFFIC_ANNOTATION_UNINITIALIZED),
        completing_id_hash_code(TRAFFIC_ANNOTATION_UNINITIALIZED) {}
  explicit MutablePartialNetworkTrafficAnnotationTag(
      const PartialNetworkTrafficAnnotationTag& partial_traffic_annotation)
      : unique_id_hash_code(partial_traffic_annotation.unique_id_hash_code),
        completing_id_hash_code(
            partial_traffic_annotation.completing_id_hash_code) {}

  int32_t unique_id_hash_code;
  int32_t completing_id_hash_code;

  explicit operator PartialNetworkTrafficAnnotationTag() const {
    return PartialNetworkTrafficAnnotationTag(
        {unique_id_hash_code, completing_id_hash_code});
  }
#else
  MutablePartialNetworkTrafficAnnotationTag()
      : unique_id_hash_code(TRAFFIC_ANNOTATION_UNINITIALIZED) {}
  explicit MutablePartialNetworkTrafficAnnotationTag(
      const PartialNetworkTrafficAnnotationTag& partial_traffic_annotation)
      : unique_id_hash_code(partial_traffic_annotation.unique_id_hash_code) {}

  int32_t unique_id_hash_code;

  explicit operator PartialNetworkTrafficAnnotationTag() const {
    return PartialNetworkTrafficAnnotationTag({unique_id_hash_code});
  }
#endif  // !defined(NDEBUG) || defined(DCHECK_ALWAYS_ON)
};

}  // namespace net

// Placeholder for unannotated usages.
#define NO_TRAFFIC_ANNOTATION_YET \
  net::DefineNetworkTrafficAnnotation("undefined", "Nothing here yet.")

#define NO_PARTIAL_TRAFFIC_ANNOTATION_YET                              \
  net::DefinePartialNetworkTrafficAnnotation("undefined", "undefined", \
                                             "Nothing here yet.")

#define MISSING_TRAFFIC_ANNOTATION     \
  net::DefineNetworkTrafficAnnotation( \
      "missing", "Function called without traffic annotation.")

#undef COMPUTE_STRING_HASH

#endif  // NET_TRAFFIC_ANNOTATION_NETWORK_TRAFFIC_ANNOTATION_H_
