// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include "base/test/fuzzed_data_provider.h"
#include "net/ntlm/ntlm_client.h"
#include "net/ntlm/ntlm_test_data.h"

base::string16 ConsumeRandomLengthString16(
    base::FuzzedDataProvider& data_provider,
    size_t max_chars) {
  std::string bytes = data_provider.ConsumeRandomLengthString(max_chars * 2);
  return base::string16(reinterpret_cast<const base::char16*>(bytes.data()),
                        bytes.size() / 2);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  net::ntlm::NtlmClient client;

  // Generate the input strings and challenge message. The strings will have a
  // maximum length 1 character longer than the maximum that |NtlmClient| will
  // accept to allow exploring the error cases.
  base::FuzzedDataProvider fdp(data, size);
  base::string16 domain =
      ConsumeRandomLengthString16(fdp, net::ntlm::kMaxFqdnLen + 1);
  base::string16 username =
      ConsumeRandomLengthString16(fdp, net::ntlm::kMaxUsernameLen + 1);
  base::string16 password =
      ConsumeRandomLengthString16(fdp, net::ntlm::kMaxPasswordLen + 1);
  std::string hostname =
      fdp.ConsumeRandomLengthString(net::ntlm::kMaxFqdnLen + 1);
  std::string challenge_msg_bytes = fdp.ConsumeRemainingBytes();

  client.GenerateAuthenticateMessage(
      domain, username, password, hostname, net::ntlm::test::kClientChallenge,
      net::ntlm::Buffer(
          reinterpret_cast<const uint8_t*>(challenge_msg_bytes.data()),
          challenge_msg_bytes.size()));
  return 0;
}