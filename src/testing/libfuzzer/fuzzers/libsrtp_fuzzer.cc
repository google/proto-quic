// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <vector>

#include "third_party/libsrtp/srtp/include/rtp.h"
#include "third_party/libsrtp/srtp/include/rtp_priv.h"
#include "third_party/libsrtp/srtp/include/srtp.h"

// TODO(katrielc) Also test the authenticated path, which is what
// WebRTC uses.  This is nontrivial because you need to bypass the MAC
// check. Two options: add a UNSAFE_FUZZER_MODE flag to libsrtp (or
// the chromium fork of it), or compute the HMAC of whatever gibberish
// the fuzzer produces and write it into the packet manually.

namespace LibSrtpFuzzer {
enum CryptoPolicy {
  NONE,
  LIKE_WEBRTC,
  LIKE_WEBRTC_WITHOUT_AUTH,
  AES_GCM,
  NUMBER_OF_POLICIES,
};
}

struct Environment {
  srtp_policy_t GetCryptoPolicy(LibSrtpFuzzer::CryptoPolicy crypto_policy,
                                const unsigned char* replacement_key) {
    switch (crypto_policy) {
      case LibSrtpFuzzer::NUMBER_OF_POLICIES:
      case LibSrtpFuzzer::NONE:
        crypto_policy_set_null_cipher_null_auth(&policy.rtp);
        crypto_policy_set_null_cipher_null_auth(&policy.rtcp);
        break;
      case LibSrtpFuzzer::LIKE_WEBRTC:
        crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtp);
        crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);
      case LibSrtpFuzzer::LIKE_WEBRTC_WITHOUT_AUTH:
        crypto_policy_set_aes_cm_128_null_auth(&policy.rtp);
        crypto_policy_set_aes_cm_128_null_auth(&policy.rtcp);
        break;
      case LibSrtpFuzzer::AES_GCM:
        // There was a security bug in the GCM mode in libsrtp 1.5.2.
        crypto_policy_set_aes_gcm_128_8_auth(&policy.rtp);
        crypto_policy_set_aes_gcm_128_8_auth(&policy.rtcp);
        break;
    }

    memcpy(key, replacement_key, SRTP_MASTER_KEY_LEN);
    return policy;
  };

  Environment() {
    srtp_init();

    memset(&policy, 0, sizeof(policy));
    policy.allow_repeat_tx = 1;
    policy.ekt = nullptr;
    policy.key = key;
    policy.next = nullptr;
    policy.ssrc.type = ssrc_any_inbound;
    policy.ssrc.value = 0xdeadbeef;
    policy.window_size = 1024;
  }

 private:
  srtp_policy_t policy;
  unsigned char key[SRTP_MASTER_KEY_LEN] = {0};

  static void crypto_policy_set_null_cipher_null_auth(crypto_policy_t* p) {
    p->cipher_type = NULL_CIPHER;
    p->cipher_key_len = 0;
    p->auth_type = NULL_AUTH;
    p->auth_key_len = 0;
    p->auth_tag_len = 0;
    p->sec_serv = sec_serv_none;
  };
};

size_t ReadLength(const uint8_t* data, size_t size) {
  // Read one byte of input and interpret it as a length to read from
  // data. Don't return more bytes than are available.
  size_t n = static_cast<size_t>(data[0]);
  return std::min(n, size - 1);
}

Environment* env = new Environment();

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Read one byte and use it to choose a crypto policy.
  if (size <= 1)
    return 0;
  LibSrtpFuzzer::CryptoPolicy policy = static_cast<LibSrtpFuzzer::CryptoPolicy>(
      data[0] % LibSrtpFuzzer::NUMBER_OF_POLICIES);
  data += 1;
  size -= 1;

  // Read some more bytes to use as a key.
  if (size <= SRTP_MASTER_KEY_LEN)
    return 0;
  srtp_policy_t srtp_policy = env->GetCryptoPolicy(policy, data);
  data += SRTP_MASTER_KEY_LEN;
  size -= SRTP_MASTER_KEY_LEN;

  srtp_t session;
  err_status_t error = srtp_create(&session, &srtp_policy);
  assert(error == err_status_ok);

  // Read one byte as a packet length N, then feed the next N bytes
  // into srtp_unprotect. Keep going until we run out of data.
  size_t packet_size;
  while (size > 0 && (packet_size = ReadLength(data, size)) > 0) {
    // One byte was used by ReadLength.
    data++;
    size--;

    size_t header_size = std::min(sizeof(srtp_hdr_t), packet_size);
    size_t body_size = packet_size - header_size;

    // We deliberately do not initialise this struct. MSAN will catch
    // usage of the uninitialised memory.
    rtp_msg_t message;
    memcpy(&message.header, data, header_size);
    memcpy(&message.body, data + header_size, body_size);

    int out_len = static_cast<int>(packet_size);
    srtp_unprotect(session, &message, &out_len);

    // |packet_size| bytes were used above.
    data += packet_size;
    size -= packet_size;
  }

  srtp_dealloc(session);
  return 0;
}
