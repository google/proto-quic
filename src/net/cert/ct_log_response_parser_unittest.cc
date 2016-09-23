// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/ct_log_response_parser.h"

#include <memory>
#include <string>

#include "base/base64.h"
#include "base/json/json_reader.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/cert/ct_serialization.h"
#include "net/cert/signed_tree_head.h"
#include "net/test/ct_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace ct {

namespace {
std::unique_ptr<base::Value> ParseJson(const std::string& json) {
  base::JSONReader json_reader;
  return json_reader.Read(json);
}
}

TEST(CTLogResponseParserTest, ParsesValidJsonSTH) {
  std::unique_ptr<base::Value> sample_sth_json =
      ParseJson(GetSampleSTHAsJson());
  SignedTreeHead tree_head;
  EXPECT_TRUE(FillSignedTreeHead(*sample_sth_json.get(), &tree_head));

  SignedTreeHead sample_sth;
  ASSERT_TRUE(GetSampleSignedTreeHead(&sample_sth));

  ASSERT_EQ(SignedTreeHead::V1, tree_head.version);
  ASSERT_EQ(sample_sth.timestamp, tree_head.timestamp);
  ASSERT_EQ(sample_sth.tree_size, tree_head.tree_size);

  // Copy the field from the SignedTreeHead because it's not null terminated
  // there and ASSERT_STREQ expects null-terminated strings.
  char actual_hash[kSthRootHashLength + 1];
  memcpy(actual_hash, tree_head.sha256_root_hash, kSthRootHashLength);
  actual_hash[kSthRootHashLength] = '\0';
  std::string expected_sha256_root_hash = GetSampleSTHSHA256RootHash();
  ASSERT_STREQ(expected_sha256_root_hash.c_str(), actual_hash);

  const DigitallySigned& expected_signature(sample_sth.signature);

  ASSERT_EQ(tree_head.signature.hash_algorithm,
            expected_signature.hash_algorithm);
  ASSERT_EQ(tree_head.signature.signature_algorithm,
            expected_signature.signature_algorithm);
  ASSERT_EQ(tree_head.signature.signature_data,
            expected_signature.signature_data);
}

TEST(CTLogResponseParserTest, FailsToParseMissingFields) {
  std::unique_ptr<base::Value> missing_signature_sth = ParseJson(
      CreateSignedTreeHeadJsonString(1 /* tree_size */, 123456u /* timestamp */,
                                     GetSampleSTHSHA256RootHash(), ""));

  SignedTreeHead tree_head;
  ASSERT_FALSE(FillSignedTreeHead(*missing_signature_sth.get(), &tree_head));

  std::unique_ptr<base::Value> missing_root_hash_sth = ParseJson(
      CreateSignedTreeHeadJsonString(1 /* tree_size */, 123456u /* timestamp */,
                                     "", GetSampleSTHTreeHeadSignature()));
  ASSERT_FALSE(FillSignedTreeHead(*missing_root_hash_sth.get(), &tree_head));
}

TEST(CTLogResponseParserTest, FailsToParseIncorrectLengthRootHash) {
  SignedTreeHead tree_head;

  std::string too_long_hash;
  base::Base64Decode(
      base::StringPiece("/WHFMgXtI/umKKuACJIN0Bb73TcILm9WkeU6qszvoArK\n"),
      &too_long_hash);
  std::unique_ptr<base::Value> too_long_hash_json =
      ParseJson(CreateSignedTreeHeadJsonString(
          1 /* tree_size */, 123456u /* timestamp */,
          GetSampleSTHSHA256RootHash(), too_long_hash));
  ASSERT_FALSE(FillSignedTreeHead(*too_long_hash_json.get(), &tree_head));

  std::string too_short_hash;
  base::Base64Decode(
      base::StringPiece("/WHFMgXtI/umKKuACJIN0Bb73TcILm9WkeU6qszvoA==\n"),
      &too_short_hash);
  std::unique_ptr<base::Value> too_short_hash_json =
      ParseJson(CreateSignedTreeHeadJsonString(
          1 /* tree_size */, 123456u /* timestamp */,
          GetSampleSTHSHA256RootHash(), too_short_hash));
  ASSERT_FALSE(FillSignedTreeHead(*too_short_hash_json.get(), &tree_head));
}

TEST(CTLogResponseParserTest, ParsesJsonSTHWithLargeTimestamp) {
  SignedTreeHead tree_head;

  std::unique_ptr<base::Value> large_timestamp_json =
      ParseJson(CreateSignedTreeHeadJsonString(
          100, INT64_C(1) << 34, GetSampleSTHSHA256RootHash(),
          GetSampleSTHTreeHeadSignature()));

  ASSERT_TRUE(FillSignedTreeHead(*large_timestamp_json.get(), &tree_head));

  base::Time expected_time =
      base::Time::UnixEpoch() +
      base::TimeDelta::FromMilliseconds(INT64_C(1) << 34);

  EXPECT_EQ(tree_head.timestamp, expected_time);
}

TEST(CTLogResponseParserTest, ParsesConsistencyProofSuccessfully) {
  std::string first(32, 'a');
  std::string second(32, 'b');
  std::string third(32, 'c');

  std::vector<std::string> raw_nodes;
  raw_nodes.push_back(first);
  raw_nodes.push_back(second);
  raw_nodes.push_back(third);
  std::unique_ptr<base::Value> sample_consistency_proof =
      ParseJson(CreateConsistencyProofJsonString(raw_nodes));

  std::vector<std::string> output;

  ASSERT_TRUE(FillConsistencyProof(*sample_consistency_proof.get(), &output));

  EXPECT_EQ(output[0], first);
  EXPECT_EQ(output[1], second);
  EXPECT_EQ(output[2], third);
}

TEST(CTLogResponseParserTest, FailsOnInvalidProofJson) {
  std::vector<std::string> output;

  std::unique_ptr<base::Value> badly_encoded =
      ParseJson(std::string("{\"consistency\": [\"notbase64\"]}"));
  EXPECT_FALSE(FillConsistencyProof(*badly_encoded.get(), &output));

  std::unique_ptr<base::Value> not_a_string =
      ParseJson(std::string("{\"consistency\": [42, 16]}"));
  EXPECT_FALSE(FillConsistencyProof(*badly_encoded.get(), &output));

  std::unique_ptr<base::Value> missing_consistency =
      ParseJson(std::string("{}"));
  EXPECT_FALSE(FillConsistencyProof(*missing_consistency.get(), &output));

  std::unique_ptr<base::Value> not_a_dict = ParseJson(std::string("[]"));
  EXPECT_FALSE(FillConsistencyProof(*not_a_dict.get(), &output));
}

TEST(CTLogResponseParserTest, ParsesProofJsonWithExtraFields) {
  std::vector<std::string> output;

  std::unique_ptr<base::Value> badly_encoded =
      ParseJson(std::string("{\"consistency\": [], \"somethingelse\": 3}"));
  EXPECT_TRUE(FillConsistencyProof(*badly_encoded.get(), &output));
}

}  // namespace ct

}  // namespace net
