// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/crypto_test_utils.h"

#include "base/stl_util.h"
#include "base/strings/string_util.h"
#include "crypto/ec_private_key.h"
#include "crypto/ec_signature_creator.h"
#include "net/quic/crypto/channel_id.h"
#include "net/quic/crypto/channel_id_chromium.h"

using base::StringPiece;
using std::string;

namespace net {

namespace test {

class TestChannelIDSource : public ChannelIDSource {
 public:
  ~TestChannelIDSource() override { STLDeleteValues(&hostname_to_key_); }

  // ChannelIDSource implementation.

  QuicAsyncStatus GetChannelIDKey(
      const string& hostname,
      scoped_ptr<ChannelIDKey>* channel_id_key,
      ChannelIDSourceCallback* /*callback*/) override {
    channel_id_key->reset(new ChannelIDKeyChromium(HostnameToKey(hostname)));
    return QUIC_SUCCESS;
  }

 private:
  typedef std::map<string, crypto::ECPrivateKey*> HostnameToKeyMap;

  scoped_ptr<crypto::ECPrivateKey> HostnameToKey(const string& hostname) {
    HostnameToKeyMap::const_iterator it = hostname_to_key_.find(hostname);
    if (it != hostname_to_key_.end()) {
      return make_scoped_ptr(it->second->Copy());
    }

    crypto::ECPrivateKey* keypair = crypto::ECPrivateKey::Create();
    if (!keypair) {
      return nullptr;
    }
    hostname_to_key_[hostname] = keypair;
    return make_scoped_ptr(keypair->Copy());
  }

  HostnameToKeyMap hostname_to_key_;
};

// static
ChannelIDSource* CryptoTestUtils::ChannelIDSourceForTesting() {
  return new TestChannelIDSource();
}

}  // namespace test

}  // namespace net
