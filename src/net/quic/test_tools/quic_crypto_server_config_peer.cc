// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_crypto_server_config_peer.h"

#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/mock_random.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::pair;
using std::string;
using std::vector;

namespace net {
namespace test {

scoped_refptr<QuicCryptoServerConfig::Config>
QuicCryptoServerConfigPeer::GetPrimaryConfig() {
  base::AutoLock locked(server_config_->configs_lock_);
  return scoped_refptr<QuicCryptoServerConfig::Config>(
      server_config_->primary_config_);
}

scoped_refptr<QuicCryptoServerConfig::Config>
QuicCryptoServerConfigPeer::GetConfig(string config_id) {
  base::AutoLock locked(server_config_->configs_lock_);
  if (config_id == "<primary>") {
    return scoped_refptr<QuicCryptoServerConfig::Config>(
        server_config_->primary_config_);
  } else {
    return server_config_->GetConfigWithScid(config_id);
  }
}

string QuicCryptoServerConfigPeer::NewSourceAddressToken(
    string config_id,
    SourceAddressTokens previous_tokens,
    const IPAddress& ip,
    QuicRandom* rand,
    QuicWallTime now,
    CachedNetworkParameters* cached_network_params) {
  return server_config_->NewSourceAddressToken(*GetConfig(config_id),
                                               previous_tokens, ip, rand, now,
                                               cached_network_params);
}

HandshakeFailureReason QuicCryptoServerConfigPeer::ValidateSourceAddressTokens(
    string config_id,
    StringPiece srct,
    const IPAddress& ip,
    QuicWallTime now,
    CachedNetworkParameters* cached_network_params) {
  SourceAddressTokens tokens;
  HandshakeFailureReason reason = server_config_->ParseSourceAddressToken(
      *GetConfig(config_id), srct, &tokens);
  if (reason != HANDSHAKE_OK) {
    return reason;
  }

  return server_config_->ValidateSourceAddressTokens(tokens, ip, now,
                                                     cached_network_params);
}

HandshakeFailureReason
QuicCryptoServerConfigPeer::ValidateSingleSourceAddressToken(
    StringPiece token,
    const IPAddress& ip,
    QuicWallTime now) {
  SourceAddressTokens tokens;
  HandshakeFailureReason parse_status = server_config_->ParseSourceAddressToken(
      *GetPrimaryConfig(), token, &tokens);
  if (HANDSHAKE_OK != parse_status) {
    return parse_status;
  }
  EXPECT_EQ(1, tokens.tokens_size());
  return server_config_->ValidateSingleSourceAddressToken(tokens.tokens(0), ip,
                                                          now);
}

string QuicCryptoServerConfigPeer::NewServerNonce(QuicRandom* rand,
                                                  QuicWallTime now) const {
  return server_config_->NewServerNonce(rand, now);
}

HandshakeFailureReason QuicCryptoServerConfigPeer::ValidateServerNonce(
    StringPiece token,
    QuicWallTime now) {
  return server_config_->ValidateServerNonce(token, now);
}

base::Lock* QuicCryptoServerConfigPeer::GetStrikeRegisterClientLock() {
  return &server_config_->strike_register_client_lock_;
}

void QuicCryptoServerConfigPeer::CheckConfigs(const char* server_config_id1,
                                              ...) {
  va_list ap;
  va_start(ap, server_config_id1);

  vector<pair<ServerConfigID, bool>> expected;
  bool first = true;
  for (;;) {
    const char* server_config_id;
    if (first) {
      server_config_id = server_config_id1;
      first = false;
    } else {
      server_config_id = va_arg(ap, const char*);
    }

    if (!server_config_id) {
      break;
    }

    // varargs will promote the value to an int so we have to read that from
    // the stack and cast down.
    const bool is_primary = static_cast<bool>(va_arg(ap, int));
    expected.push_back(std::make_pair(server_config_id, is_primary));
  }

  va_end(ap);

  base::AutoLock locked(server_config_->configs_lock_);

  ASSERT_EQ(expected.size(), server_config_->configs_.size()) << ConfigsDebug();

  for (const pair<const ServerConfigID,
                  scoped_refptr<QuicCryptoServerConfig::Config>>& i :
       server_config_->configs_) {
    bool found = false;
    for (pair<ServerConfigID, bool>& j : expected) {
      if (i.first == j.first && i.second->is_primary == j.second) {
        found = true;
        j.first.clear();
        break;
      }
    }

    ASSERT_TRUE(found) << "Failed to find match for " << i.first
                       << " in configs:\n"
                       << ConfigsDebug();
  }
}

// ConfigsDebug returns a string that contains debugging information about
// the set of Configs loaded in |server_config_| and their status.
string QuicCryptoServerConfigPeer::ConfigsDebug() {
  if (server_config_->configs_.empty()) {
    return "No Configs in QuicCryptoServerConfig";
  }

  string s;

  for (const auto& i : server_config_->configs_) {
    const scoped_refptr<QuicCryptoServerConfig::Config> config = i.second;
    if (config->is_primary) {
      s += "(primary) ";
    } else {
      s += "          ";
    }
    s += config->id;
    s += "\n";
  }

  return s;
}

void QuicCryptoServerConfigPeer::SelectNewPrimaryConfig(int seconds) {
  base::AutoLock locked(server_config_->configs_lock_);
  server_config_->SelectNewPrimaryConfig(
      QuicWallTime::FromUNIXSeconds(seconds));
}

const string QuicCryptoServerConfigPeer::CompressChain(
    QuicCompressedCertsCache* compressed_certs_cache,
    const scoped_refptr<ProofSource::Chain>& chain,
    const string& client_common_set_hashes,
    const string& client_cached_cert_hashes,
    const CommonCertSets* common_sets) {
  return server_config_->CompressChain(compressed_certs_cache, chain,
                                       client_common_set_hashes,
                                       client_cached_cert_hashes, common_sets);
}

uint32_t QuicCryptoServerConfigPeer::source_address_token_future_secs() {
  return server_config_->source_address_token_future_secs_;
}

uint32_t QuicCryptoServerConfigPeer::source_address_token_lifetime_secs() {
  return server_config_->source_address_token_lifetime_secs_;
}

uint32_t
QuicCryptoServerConfigPeer::server_nonce_strike_register_max_entries() {
  return server_config_->server_nonce_strike_register_max_entries_;
}

uint32_t
QuicCryptoServerConfigPeer::server_nonce_strike_register_window_secs() {
  return server_config_->server_nonce_strike_register_window_secs_;
}

}  // namespace test
}  // namespace net
