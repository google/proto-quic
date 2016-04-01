// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/test_helpers.h"

#include "base/base64.h"
#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/path_service.h"
#include "net/cert/pem_tokenizer.h"
#include "net/der/parser.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace der {

void PrintTo(const Input& data, ::std::ostream* os) {
  std::string b64;
  base::Base64Encode(
      base::StringPiece(reinterpret_cast<const char*>(data.UnsafeData()),
                        data.Length()),
      &b64);

  *os << "[" << b64 << "]";
}

}  // namespace der

der::Input SequenceValueFromString(const std::string* s) {
  der::Parser parser((der::Input(s)));
  der::Input data;
  if (!parser.ReadTag(der::kSequence, &data)) {
    ADD_FAILURE();
    return der::Input();
  }
  if (parser.HasMore()) {
    ADD_FAILURE();
    return der::Input();
  }
  return data;
}

::testing::AssertionResult ReadTestDataFromPemFile(
    const std::string& file_path_ascii,
    const PemBlockMapping* mappings,
    size_t mappings_length) {
  // Compute the full path, relative to the src/ directory.
  base::FilePath src_root;
  PathService::Get(base::DIR_SOURCE_ROOT, &src_root);
  base::FilePath filepath = src_root.AppendASCII(file_path_ascii);

  // Read the full contents of the PEM file.
  std::string file_data;
  if (!base::ReadFileToString(filepath, &file_data)) {
    return ::testing::AssertionFailure() << "Couldn't read file: "
                                         << filepath.value();
  }

  // mappings_copy is used to keep track of which mappings have already been
  // satisfied (by nulling the |value| field). This is used to track when
  // blocks are mulitply defined.
  std::vector<PemBlockMapping> mappings_copy(mappings,
                                             mappings + mappings_length);

  // Build the |pem_headers| vector needed for PEMTokenzier.
  std::vector<std::string> pem_headers;
  for (const auto& mapping : mappings_copy) {
    pem_headers.push_back(mapping.block_name);
  }

  PEMTokenizer pem_tokenizer(file_data, pem_headers);
  while (pem_tokenizer.GetNext()) {
    for (auto& mapping : mappings_copy) {
      // Find the mapping for this block type.
      if (pem_tokenizer.block_type() == mapping.block_name) {
        if (!mapping.value) {
          return ::testing::AssertionFailure()
                 << "PEM block defined multiple times: " << mapping.block_name;
        }

        // Copy the data to the result.
        mapping.value->assign(pem_tokenizer.data());

        // Mark the mapping as having been satisfied.
        mapping.value = nullptr;
      }
    }
  }

  // Ensure that all specified blocks were found.
  for (const auto& mapping : mappings_copy) {
    if (mapping.value && !mapping.optional) {
      return ::testing::AssertionFailure() << "PEM block missing: "
                                           << mapping.block_name;
    }
  }

  return ::testing::AssertionSuccess();
}

}  // namespace net
