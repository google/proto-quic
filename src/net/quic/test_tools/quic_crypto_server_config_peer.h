// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_QUIC_CRYPTO_SERVER_CONFIG_PEER_H_
#define NET_QUIC_TEST_TOOLS_QUIC_CRYPTO_SERVER_CONFIG_PEER_H_

#include "net/quic/crypto/quic_crypto_server_config.h"

namespace net {
namespace test {

// Peer for accessing otherwise private members of a QuicCryptoServerConfig.
class QuicCryptoServerConfigPeer {
 public:
  explicit QuicCryptoServerConfigPeer(
      const QuicCryptoServerConfig* server_config)
      : server_config_(server_config) {}

  // Returns the primary config.
  scoped_refptr<QuicCryptoServerConfig::Config> GetPrimaryConfig();

  // Returns the config associated with |config_id|.
  scoped_refptr<QuicCryptoServerConfig::Config> GetConfig(
      std::string config_id);

  // Generates a new valid source address token.
  std::string NewSourceAddressToken(
      std::string config_id,
      SourceAddressTokens previous_tokens,
      const IPAddress& ip,
      QuicRandom* rand,
      QuicWallTime now,
      CachedNetworkParameters* cached_network_params);

  // Attempts to validate the tokens in |tokens|.
  HandshakeFailureReason ValidateSourceAddressTokens(
      std::string config_id,
      base::StringPiece tokens,
      const IPAddress& ip,
      QuicWallTime now,
      CachedNetworkParameters* cached_network_params);

  // Attempts to validate the single source address token in |token|.
  HandshakeFailureReason ValidateSingleSourceAddressToken(
      base::StringPiece token,
      const IPAddress& ip,
      QuicWallTime now);

  // Returns a new server nonce.
  std::string NewServerNonce(QuicRandom* rand, QuicWallTime now) const;

  // Check if |nonce| is valid |now|.
  HandshakeFailureReason ValidateServerNonce(base::StringPiece nonce,
                                             QuicWallTime now);

  // Returns the mutex needed to access the strike register client.
  base::Lock* GetStrikeRegisterClientLock();

  // CheckConfigs compares the state of the Configs in |server_config_| to the
  // description given as arguments. The arguments are given as
  // nullptr-terminated std:pairs. The first of each std:pair is the server
  // config ID of
  // a Config. The second is a boolean describing whether the config is the
  // primary. For example:
  //   CheckConfigs(nullptr);  // checks that no Configs are loaded.
  //
  //   // Checks that exactly three Configs are loaded with the given IDs and
  //   // status.
  //   CheckConfigs(
  //     "id1", false,
  //     "id2", true,
  //     "id3", false,
  //     nullptr);
  void CheckConfigs(const char* server_config_id1, ...);

  // ConfigsDebug returns a std::string that contains debugging information
  // about
  // the set of Configs loaded in |server_config_| and their status.
  std::string ConfigsDebug();

  void SelectNewPrimaryConfig(int seconds);

  const std::string CompressChain(
      QuicCompressedCertsCache* compressed_certs_cache,
      const scoped_refptr<ProofSource::Chain>& chain,
      const std::string& client_common_set_hashes,
      const std::string& client_cached_cert_hashes,
      const CommonCertSets* common_sets);

  uint32_t source_address_token_future_secs();

  uint32_t source_address_token_lifetime_secs();

  uint32_t server_nonce_strike_register_max_entries();

  uint32_t server_nonce_strike_register_window_secs();

 private:
  const QuicCryptoServerConfig* server_config_;
};

}  // namespace test
}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_QUIC_CRYPTO_SERVER_CONFIG_PEER_H_
