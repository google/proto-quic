// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/quic_crypto_server_config.h"

#include <stdarg.h>

#include <memory>

#include "base/stl_util.h"
#include "net/quic/crypto/aes_128_gcm_12_encrypter.h"
#include "net/quic/crypto/cert_compressor.h"
#include "net/quic/crypto/chacha20_poly1305_rfc7539_encrypter.h"
#include "net/quic/crypto/crypto_handshake_message.h"
#include "net/quic/crypto/crypto_secret_boxer.h"
#include "net/quic/crypto/crypto_server_config_protobuf.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/crypto/strike_register_client.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_time.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::map;
using std::pair;
using std::string;
using std::vector;

namespace net {
namespace test {

class QuicCryptoServerConfigPeer {
 public:
  explicit QuicCryptoServerConfigPeer(QuicCryptoServerConfig* server_config)
      : server_config_(server_config) {}

  scoped_refptr<QuicCryptoServerConfig::Config> GetConfig(string config_id) {
    base::AutoLock locked(server_config_->configs_lock_);
    if (config_id == "<primary>") {
      return scoped_refptr<QuicCryptoServerConfig::Config>(
          server_config_->primary_config_);
    } else {
      return server_config_->GetConfigWithScid(config_id);
    }
  }

  string NewSourceAddressToken(string config_id,
                               SourceAddressTokens previous_tokens,
                               const IPAddress& ip,
                               QuicRandom* rand,
                               QuicWallTime now,
                               CachedNetworkParameters* cached_network_params) {
    return server_config_->NewSourceAddressToken(*GetConfig(config_id),
                                                 previous_tokens, ip, rand, now,
                                                 cached_network_params);
  }

  HandshakeFailureReason ValidateSourceAddressTokens(
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

  string NewServerNonce(QuicRandom* rand, QuicWallTime now) const {
    return server_config_->NewServerNonce(rand, now);
  }

  HandshakeFailureReason ValidateServerNonce(StringPiece token,
                                             QuicWallTime now) {
    return server_config_->ValidateServerNonce(token, now);
  }

  base::Lock* GetStrikeRegisterClientLock() {
    return &server_config_->strike_register_client_lock_;
  }

  // CheckConfigs compares the state of the Configs in |server_config_| to the
  // description given as arguments. The arguments are given as
  // nullptr-terminated pairs. The first of each pair is the server config ID of
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
  void CheckConfigs(const char* server_config_id1, ...) {
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

    ASSERT_EQ(expected.size(), server_config_->configs_.size())
        << ConfigsDebug();

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
  // ConfigsDebug() should be called after acquiring
  // server_config_->configs_lock_.
  string ConfigsDebug() {
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

  void SelectNewPrimaryConfig(int seconds) {
    base::AutoLock locked(server_config_->configs_lock_);
    server_config_->SelectNewPrimaryConfig(
        QuicWallTime::FromUNIXSeconds(seconds));
  }

  const string CompressChain(QuicCompressedCertsCache* compressed_certs_cache,
                             const scoped_refptr<ProofSource::Chain>& chain,
                             const string& client_common_set_hashes,
                             const string& client_cached_cert_hashes,
                             const CommonCertSets* common_sets) {
    return server_config_->CompressChain(
        compressed_certs_cache, chain, client_common_set_hashes,
        client_cached_cert_hashes, common_sets);
  }

 private:
  const QuicCryptoServerConfig* server_config_;
};

class TestStrikeRegisterClient : public StrikeRegisterClient {
 public:
  explicit TestStrikeRegisterClient(QuicCryptoServerConfig* config)
      : config_(config), is_known_orbit_called_(false) {}

  bool IsKnownOrbit(StringPiece orbit) const override {
    // Ensure that the strike register client lock is not held.
    QuicCryptoServerConfigPeer peer(config_);
    base::Lock* m = peer.GetStrikeRegisterClientLock();
    // In Chromium, we will dead lock if the lock is held by the current thread.
    // Chromium doesn't have AssertNotHeld API call.
    // m->AssertNotHeld();
    base::AutoLock lock(*m);

    is_known_orbit_called_ = true;
    return true;
  }

  void VerifyNonceIsValidAndUnique(StringPiece nonce,
                                   QuicWallTime now,
                                   ResultCallback* cb) override {
    LOG(FATAL) << "Not implemented";
  }

  bool is_known_orbit_called() { return is_known_orbit_called_; }

 private:
  QuicCryptoServerConfig* config_;
  mutable bool is_known_orbit_called_;
};

TEST(QuicCryptoServerConfigTest, ServerConfig) {
  QuicRandom* rand = QuicRandom::GetInstance();
  QuicCryptoServerConfig server(QuicCryptoServerConfig::TESTING, rand,
                                CryptoTestUtils::ProofSourceForTesting());
  MockClock clock;

  std::unique_ptr<CryptoHandshakeMessage> message(server.AddDefaultConfig(
      rand, &clock, QuicCryptoServerConfig::ConfigOptions()));

  // The default configuration should have AES-GCM and at least one ChaCha20
  // cipher.
  const QuicTag* aead_tags;
  size_t aead_len;
  ASSERT_EQ(QUIC_NO_ERROR, message->GetTaglist(kAEAD, &aead_tags, &aead_len));
  vector<QuicTag> aead(aead_tags, aead_tags + aead_len);
  EXPECT_THAT(aead, ::testing::Contains(kAESG));
  if (ChaCha20Poly1305Rfc7539Encrypter::IsSupported()) {
    EXPECT_LE(2u, aead.size());
  } else {
    EXPECT_LE(1u, aead.size());
  }
}

TEST(QuicCryptoServerConfigTest, ServerConfigDisableChaCha) {
  ValueRestore<bool> old_flag(
      &FLAGS_quic_crypto_server_config_default_has_chacha20, false);
  QuicRandom* rand = QuicRandom::GetInstance();
  QuicCryptoServerConfig server(QuicCryptoServerConfig::TESTING, rand,
                                CryptoTestUtils::ProofSourceForTesting());
  MockClock clock;

  std::unique_ptr<CryptoHandshakeMessage> message(server.AddDefaultConfig(
      rand, &clock, QuicCryptoServerConfig::ConfigOptions()));

  // The default configuration should only contain AES-GCM when ChaCha20 has
  // been disabled.
  const QuicTag* aead_tags;
  size_t aead_len;
  ASSERT_EQ(QUIC_NO_ERROR, message->GetTaglist(kAEAD, &aead_tags, &aead_len));
  vector<QuicTag> aead(aead_tags, aead_tags + aead_len);
  EXPECT_THAT(aead, ::testing::ElementsAre(kAESG));
}

TEST(QuicCryptoServerConfigTest, GetOrbitIsCalledWithoutTheStrikeRegisterLock) {
  QuicRandom* rand = QuicRandom::GetInstance();
  QuicCryptoServerConfig server(QuicCryptoServerConfig::TESTING, rand,
                                CryptoTestUtils::ProofSourceForTesting());
  MockClock clock;

  TestStrikeRegisterClient* strike_register =
      new TestStrikeRegisterClient(&server);
  server.SetStrikeRegisterClient(strike_register);

  QuicCryptoServerConfig::ConfigOptions options;
  std::unique_ptr<CryptoHandshakeMessage> message(
      server.AddDefaultConfig(rand, &clock, options));
  EXPECT_TRUE(strike_register->is_known_orbit_called());
}

TEST(QuicCryptoServerConfigTest, CompressCerts) {
  QuicCompressedCertsCache compressed_certs_cache(
      QuicCompressedCertsCache::kQuicCompressedCertsCacheSize);

  QuicRandom* rand = QuicRandom::GetInstance();
  QuicCryptoServerConfig server(QuicCryptoServerConfig::TESTING, rand,
                                CryptoTestUtils::ProofSourceForTesting());
  QuicCryptoServerConfigPeer peer(&server);

  vector<string> certs = {"testcert"};
  scoped_refptr<ProofSource::Chain> chain(new ProofSource::Chain(certs));

  string compressed =
      peer.CompressChain(&compressed_certs_cache, chain, "", "", nullptr);

  if (FLAGS_quic_use_cached_compressed_certs) {
    EXPECT_EQ(compressed_certs_cache.Size(), 1u);
  } else {
    EXPECT_EQ(compressed_certs_cache.Size(), 0u);
  }
}

TEST(QuicCryptoServerConfigTest, CompressSameCertsTwice) {
  QuicCompressedCertsCache compressed_certs_cache(
      QuicCompressedCertsCache::kQuicCompressedCertsCacheSize);

  QuicRandom* rand = QuicRandom::GetInstance();
  QuicCryptoServerConfig server(QuicCryptoServerConfig::TESTING, rand,
                                CryptoTestUtils::ProofSourceForTesting());
  QuicCryptoServerConfigPeer peer(&server);

  // Compress the certs for the first time.
  vector<string> certs = {"testcert"};
  scoped_refptr<ProofSource::Chain> chain(new ProofSource::Chain(certs));
  string common_certs = "";
  string cached_certs = "";

  string compressed = peer.CompressChain(&compressed_certs_cache, chain,
                                         common_certs, cached_certs, nullptr);
  if (FLAGS_quic_use_cached_compressed_certs) {
    EXPECT_EQ(compressed_certs_cache.Size(), 1u);
  }

  // Compress the same certs, should use cache if available.
  string compressed2 = peer.CompressChain(&compressed_certs_cache, chain,
                                          common_certs, cached_certs, nullptr);
  EXPECT_EQ(compressed, compressed2);
  if (FLAGS_quic_use_cached_compressed_certs) {
    EXPECT_EQ(compressed_certs_cache.Size(), 1u);
  }
}

TEST(QuicCryptoServerConfigTest, CompressDifferentCerts) {
  // This test compresses a set of similar but not identical certs. Cache if
  // used should return cache miss and add all the compressed certs.
  QuicCompressedCertsCache compressed_certs_cache(
      QuicCompressedCertsCache::kQuicCompressedCertsCacheSize);

  QuicRandom* rand = QuicRandom::GetInstance();
  QuicCryptoServerConfig server(QuicCryptoServerConfig::TESTING, rand,
                                CryptoTestUtils::ProofSourceForTesting());
  QuicCryptoServerConfigPeer peer(&server);

  vector<string> certs = {"testcert"};
  scoped_refptr<ProofSource::Chain> chain(new ProofSource::Chain(certs));
  string common_certs = "";
  string cached_certs = "";

  string compressed = peer.CompressChain(&compressed_certs_cache, chain,
                                         common_certs, cached_certs, nullptr);
  if (FLAGS_quic_use_cached_compressed_certs) {
    EXPECT_EQ(compressed_certs_cache.Size(), 1u);
  }

  // Compress a similar certs which only differs in the chain.
  scoped_refptr<ProofSource::Chain> chain2(new ProofSource::Chain(certs));

  string compressed2 = peer.CompressChain(&compressed_certs_cache, chain2,
                                          common_certs, cached_certs, nullptr);
  if (FLAGS_quic_use_cached_compressed_certs) {
    EXPECT_EQ(compressed_certs_cache.Size(), 2u);
  }

  // Compress a similar certs which only differs in common certs field.
  static const uint64_t set_hash = 42;
  std::unique_ptr<CommonCertSets> common_sets(
      CryptoTestUtils::MockCommonCertSets(certs[0], set_hash, 1));
  StringPiece different_common_certs(reinterpret_cast<const char*>(&set_hash),
                                     sizeof(set_hash));
  string compressed3 = peer.CompressChain(&compressed_certs_cache, chain,
                                          different_common_certs.as_string(),
                                          cached_certs, common_sets.get());
  if (FLAGS_quic_use_cached_compressed_certs) {
    EXPECT_EQ(compressed_certs_cache.Size(), 3u);
  }
}

class SourceAddressTokenTest : public ::testing::Test {
 public:
  SourceAddressTokenTest()
      : ip4_(Loopback4()),
        ip4_dual_(ConvertIPv4ToIPv4MappedIPv6(ip4_)),
        ip6_(Loopback6()),
        original_time_(QuicWallTime::Zero()),
        rand_(QuicRandom::GetInstance()),
        server_(QuicCryptoServerConfig::TESTING,
                rand_,
                CryptoTestUtils::ProofSourceForTesting()),
        peer_(&server_) {
    // Advance the clock to some non-zero time.
    clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1000000));
    original_time_ = clock_.WallNow();

    primary_config_.reset(server_.AddDefaultConfig(
        rand_, &clock_, QuicCryptoServerConfig::ConfigOptions()));

    // Add a config that overrides the default boxer.
    QuicCryptoServerConfig::ConfigOptions options;
    options.id = kOverride;
    override_config_protobuf_.reset(
        QuicCryptoServerConfig::GenerateConfig(rand_, &clock_, options));
    override_config_protobuf_->set_source_address_token_secret_override(
        "a secret key");
    // Lower priority than the default config.
    override_config_protobuf_->set_priority(1);
    override_config_.reset(
        server_.AddConfig(override_config_protobuf_.get(), original_time_));
  }

  string NewSourceAddressToken(string config_id, const IPAddress& ip) {
    return NewSourceAddressToken(config_id, ip, nullptr);
  }

  string NewSourceAddressToken(string config_id,
                               const IPAddress& ip,
                               const SourceAddressTokens& previous_tokens) {
    return peer_.NewSourceAddressToken(config_id, previous_tokens, ip, rand_,
                                       clock_.WallNow(), nullptr);
  }

  string NewSourceAddressToken(string config_id,
                               const IPAddress& ip,
                               CachedNetworkParameters* cached_network_params) {
    SourceAddressTokens previous_tokens;
    return peer_.NewSourceAddressToken(config_id, previous_tokens, ip, rand_,
                                       clock_.WallNow(), cached_network_params);
  }

  HandshakeFailureReason ValidateSourceAddressTokens(string config_id,
                                                     StringPiece srct,
                                                     const IPAddress& ip) {
    return ValidateSourceAddressTokens(config_id, srct, ip, nullptr);
  }

  HandshakeFailureReason ValidateSourceAddressTokens(
      string config_id,
      StringPiece srct,
      const IPAddress& ip,
      CachedNetworkParameters* cached_network_params) {
    return peer_.ValidateSourceAddressTokens(
        config_id, srct, ip, clock_.WallNow(), cached_network_params);
  }

  const string kPrimary = "<primary>";
  const string kOverride = "Config with custom source address token key";

  IPAddress ip4_;
  IPAddress ip4_dual_;
  IPAddress ip6_;

  MockClock clock_;
  QuicWallTime original_time_;
  QuicRandom* rand_ = QuicRandom::GetInstance();
  QuicCryptoServerConfig server_;
  QuicCryptoServerConfigPeer peer_;
  // Stores the primary config.
  std::unique_ptr<CryptoHandshakeMessage> primary_config_;
  std::unique_ptr<QuicServerConfigProtobuf> override_config_protobuf_;
  std::unique_ptr<CryptoHandshakeMessage> override_config_;
};

// Test basic behavior of source address tokens including being specific
// to a single IP address and server config.
TEST_F(SourceAddressTokenTest, NewSourceAddressToken) {
  // Primary config generates configs that validate successfully.
  const string token4 = NewSourceAddressToken(kPrimary, ip4_);
  const string token4d = NewSourceAddressToken(kPrimary, ip4_dual_);
  const string token6 = NewSourceAddressToken(kPrimary, ip6_);
  EXPECT_EQ(HANDSHAKE_OK, ValidateSourceAddressTokens(kPrimary, token4, ip4_));
  ASSERT_EQ(HANDSHAKE_OK,
            ValidateSourceAddressTokens(kPrimary, token4, ip4_dual_));
  ASSERT_EQ(SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE,
            ValidateSourceAddressTokens(kPrimary, token4, ip6_));
  ASSERT_EQ(HANDSHAKE_OK, ValidateSourceAddressTokens(kPrimary, token4d, ip4_));
  ASSERT_EQ(HANDSHAKE_OK,
            ValidateSourceAddressTokens(kPrimary, token4d, ip4_dual_));
  ASSERT_EQ(SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE,
            ValidateSourceAddressTokens(kPrimary, token4d, ip6_));
  ASSERT_EQ(HANDSHAKE_OK, ValidateSourceAddressTokens(kPrimary, token6, ip6_));

  // Override config generates configs that validate successfully.
  const string override_token4 = NewSourceAddressToken(kOverride, ip4_);
  const string override_token6 = NewSourceAddressToken(kOverride, ip6_);
  ASSERT_EQ(HANDSHAKE_OK,
            ValidateSourceAddressTokens(kOverride, override_token4, ip4_));
  ASSERT_EQ(SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE,
            ValidateSourceAddressTokens(kOverride, override_token4, ip6_));
  ASSERT_EQ(HANDSHAKE_OK,
            ValidateSourceAddressTokens(kOverride, override_token6, ip6_));

  // Tokens generated by the primary config do not validate
  // successfully against the override config, and vice versa.
  ASSERT_EQ(SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE,
            ValidateSourceAddressTokens(kOverride, token4, ip4_));
  ASSERT_EQ(SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE,
            ValidateSourceAddressTokens(kOverride, token6, ip6_));
  ASSERT_EQ(SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE,
            ValidateSourceAddressTokens(kPrimary, override_token4, ip4_));
  ASSERT_EQ(SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE,
            ValidateSourceAddressTokens(kPrimary, override_token6, ip6_));
}

TEST_F(SourceAddressTokenTest, NewSourceAddressTokenExpiration) {
  const string token = NewSourceAddressToken(kPrimary, ip4_);

  // Validation fails if the token is from the future.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(-3600 * 2));
  ASSERT_EQ(SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE,
            ValidateSourceAddressTokens(kPrimary, token, ip4_));

  // Validation fails after tokens expire.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(86400 * 7));
  ASSERT_EQ(SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE,
            ValidateSourceAddressTokens(kPrimary, token, ip4_));
}

TEST_F(SourceAddressTokenTest, NewSourceAddressTokenWithNetworkParams) {
  // Make sure that if the source address token contains CachedNetworkParameters
  // that this gets written to ValidateSourceAddressToken output argument.
  CachedNetworkParameters cached_network_params_input;
  cached_network_params_input.set_bandwidth_estimate_bytes_per_second(1234);
  const string token4_with_cached_network_params =
      NewSourceAddressToken(kPrimary, ip4_, &cached_network_params_input);

  CachedNetworkParameters cached_network_params_output;
  EXPECT_NE(cached_network_params_output.SerializeAsString(),
            cached_network_params_input.SerializeAsString());
  ValidateSourceAddressTokens(kPrimary, token4_with_cached_network_params, ip4_,
                              &cached_network_params_output);
  EXPECT_EQ(cached_network_params_output.SerializeAsString(),
            cached_network_params_input.SerializeAsString());
}

// Test the ability for a source address token to be valid for multiple
// addresses.
TEST_F(SourceAddressTokenTest, SourceAddressTokenMultipleAddresses) {
  QuicWallTime now = clock_.WallNow();

  // Now create a token which is usable for both addresses.
  SourceAddressToken previous_token;
  IPAddress ip_address = ip6_;
  if (ip6_.IsIPv4()) {
    ip_address = ConvertIPv4ToIPv4MappedIPv6(ip_address);
  }
  previous_token.set_ip(IPAddressToPackedString(ip_address));
  previous_token.set_timestamp(now.ToUNIXSeconds());
  SourceAddressTokens previous_tokens;
  (*previous_tokens.add_tokens()) = previous_token;
  const string token4or6 =
      NewSourceAddressToken(kPrimary, ip4_, previous_tokens);

  EXPECT_EQ(HANDSHAKE_OK,
            ValidateSourceAddressTokens(kPrimary, token4or6, ip4_));
  ASSERT_EQ(HANDSHAKE_OK,
            ValidateSourceAddressTokens(kPrimary, token4or6, ip6_));
}

TEST(QuicCryptoServerConfigTest, ValidateServerNonce) {
  QuicRandom* rand = QuicRandom::GetInstance();
  QuicCryptoServerConfig server(QuicCryptoServerConfig::TESTING, rand,
                                CryptoTestUtils::ProofSourceForTesting());
  QuicCryptoServerConfigPeer peer(&server);

  StringPiece message("hello world");
  const size_t key_size = CryptoSecretBoxer::GetKeySize();
  std::unique_ptr<uint8_t[]> key(new uint8_t[key_size]);
  memset(key.get(), 0x11, key_size);

  CryptoSecretBoxer boxer;
  boxer.SetKeys({string(reinterpret_cast<char*>(key.get()), key_size)});
  const string box = boxer.Box(rand, message);
  MockClock clock;
  QuicWallTime now = clock.WallNow();
  const QuicWallTime original_time = now;
  EXPECT_EQ(SERVER_NONCE_DECRYPTION_FAILURE,
            peer.ValidateServerNonce(box, now));

  string server_nonce = peer.NewServerNonce(rand, now);
  EXPECT_EQ(HANDSHAKE_OK, peer.ValidateServerNonce(server_nonce, now));
  EXPECT_EQ(SERVER_NONCE_NOT_UNIQUE_FAILURE,
            peer.ValidateServerNonce(server_nonce, now));

  now = original_time.Add(QuicTime::Delta::FromSeconds(1000 * 7));
  server_nonce = peer.NewServerNonce(rand, now);
  EXPECT_EQ(HANDSHAKE_OK, peer.ValidateServerNonce(server_nonce, now));
}

class CryptoServerConfigsTest : public ::testing::Test {
 public:
  CryptoServerConfigsTest()
      : rand_(QuicRandom::GetInstance()),
        config_(QuicCryptoServerConfig::TESTING,
                rand_,
                CryptoTestUtils::ProofSourceForTesting()),
        test_peer_(&config_) {}

  void SetUp() override {
    clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1000));
  }

  // SetConfigs constructs suitable config protobufs and calls SetConfigs on
  // |config_|. The arguments are given as nullptr-terminated pairs. The first
  // of each pair is the server config ID of a Config. The second is the
  // |primary_time| of that Config, given in epoch seconds. (Although note that,
  // in these tests, time is set to 1000 seconds since the epoch.) For example:
  //   SetConfigs(nullptr);  // calls |config_.SetConfigs| with no protobufs.
  //
  //   // Calls |config_.SetConfigs| with two protobufs: one for a Config with
  //   // a |primary_time| of 900 and priority 1, and another with
  //   // a |primary_time| of 1000 and priority 2.

  //   CheckConfigs(
  //     "id1", 900, 1,
  //     "id2", 1000, 2,
  //     nullptr);
  //
  // If the server config id starts with "INVALID" then the generated protobuf
  // will be invalid.
  void SetConfigs(const char* server_config_id1, ...) {
    const char kOrbit[] = "12345678";

    va_list ap;
    va_start(ap, server_config_id1);
    bool has_invalid = false;
    bool is_empty = true;

    vector<QuicServerConfigProtobuf*> protobufs;
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

      is_empty = false;
      int primary_time = va_arg(ap, int);
      int priority = va_arg(ap, int);

      QuicCryptoServerConfig::ConfigOptions options;
      options.id = server_config_id;
      options.orbit = kOrbit;
      QuicServerConfigProtobuf* protobuf(
          QuicCryptoServerConfig::GenerateConfig(rand_, &clock_, options));
      protobuf->set_primary_time(primary_time);
      protobuf->set_priority(priority);
      if (string(server_config_id).find("INVALID") == 0) {
        protobuf->clear_key();
        has_invalid = true;
      }
      protobufs.push_back(protobuf);
    }

    ASSERT_EQ(!has_invalid && !is_empty,
              config_.SetConfigs(protobufs, clock_.WallNow()));
    STLDeleteElements(&protobufs);
  }

 protected:
  QuicRandom* const rand_;
  MockClock clock_;
  QuicCryptoServerConfig config_;
  QuicCryptoServerConfigPeer test_peer_;
};

TEST_F(CryptoServerConfigsTest, NoConfigs) {
  test_peer_.CheckConfigs(nullptr);
}

TEST_F(CryptoServerConfigsTest, MakePrimaryFirst) {
  // Make sure that "b" is primary even though "a" comes first.
  SetConfigs("a", 1100, 1, "b", 900, 1, nullptr);
  test_peer_.CheckConfigs("a", false, "b", true, nullptr);
}

TEST_F(CryptoServerConfigsTest, MakePrimarySecond) {
  // Make sure that a remains primary after b is added.
  SetConfigs("a", 900, 1, "b", 1100, 1, nullptr);
  test_peer_.CheckConfigs("a", true, "b", false, nullptr);
}

TEST_F(CryptoServerConfigsTest, Delete) {
  // Ensure that configs get deleted when removed.
  SetConfigs("a", 800, 1, "b", 900, 1, "c", 1100, 1, nullptr);
  test_peer_.CheckConfigs("a", false, "b", true, "c", false, nullptr);
  SetConfigs("b", 900, 1, "c", 1100, 1, nullptr);
  test_peer_.CheckConfigs("b", true, "c", false, nullptr);
}

TEST_F(CryptoServerConfigsTest, DeletePrimary) {
  // Ensure that deleting the primary config works.
  SetConfigs("a", 800, 1, "b", 900, 1, "c", 1100, 1, nullptr);
  test_peer_.CheckConfigs("a", false, "b", true, "c", false, nullptr);
  SetConfigs("a", 800, 1, "c", 1100, 1, nullptr);
  test_peer_.CheckConfigs("a", true, "c", false, nullptr);
}

TEST_F(CryptoServerConfigsTest, FailIfDeletingAllConfigs) {
  // Ensure that configs get deleted when removed.
  SetConfigs("a", 800, 1, "b", 900, 1, nullptr);
  test_peer_.CheckConfigs("a", false, "b", true, nullptr);
  SetConfigs(nullptr);
  // Config change is rejected, still using old configs.
  test_peer_.CheckConfigs("a", false, "b", true, nullptr);
}

TEST_F(CryptoServerConfigsTest, ChangePrimaryTime) {
  // Check that updates to primary time get picked up.
  SetConfigs("a", 400, 1, "b", 800, 1, "c", 1200, 1, nullptr);
  test_peer_.SelectNewPrimaryConfig(500);
  test_peer_.CheckConfigs("a", true, "b", false, "c", false, nullptr);
  SetConfigs("a", 1200, 1, "b", 800, 1, "c", 400, 1, nullptr);
  test_peer_.SelectNewPrimaryConfig(500);
  test_peer_.CheckConfigs("a", false, "b", false, "c", true, nullptr);
}

TEST_F(CryptoServerConfigsTest, AllConfigsInThePast) {
  // Check that the most recent config is selected.
  SetConfigs("a", 400, 1, "b", 800, 1, "c", 1200, 1, nullptr);
  test_peer_.SelectNewPrimaryConfig(1500);
  test_peer_.CheckConfigs("a", false, "b", false, "c", true, nullptr);
}

TEST_F(CryptoServerConfigsTest, AllConfigsInTheFuture) {
  // Check that the first config is selected.
  SetConfigs("a", 400, 1, "b", 800, 1, "c", 1200, 1, nullptr);
  test_peer_.SelectNewPrimaryConfig(100);
  test_peer_.CheckConfigs("a", true, "b", false, "c", false, nullptr);
}

TEST_F(CryptoServerConfigsTest, SortByPriority) {
  // Check that priority is used to decide on a primary config when
  // configs have the same primary time.
  SetConfigs("a", 900, 1, "b", 900, 2, "c", 900, 3, nullptr);
  test_peer_.CheckConfigs("a", true, "b", false, "c", false, nullptr);
  test_peer_.SelectNewPrimaryConfig(800);
  test_peer_.CheckConfigs("a", true, "b", false, "c", false, nullptr);
  test_peer_.SelectNewPrimaryConfig(1000);
  test_peer_.CheckConfigs("a", true, "b", false, "c", false, nullptr);

  // Change priorities and expect sort order to change.
  SetConfigs("a", 900, 2, "b", 900, 1, "c", 900, 0, nullptr);
  test_peer_.CheckConfigs("a", false, "b", false, "c", true, nullptr);
  test_peer_.SelectNewPrimaryConfig(800);
  test_peer_.CheckConfigs("a", false, "b", false, "c", true, nullptr);
  test_peer_.SelectNewPrimaryConfig(1000);
  test_peer_.CheckConfigs("a", false, "b", false, "c", true, nullptr);
}

TEST_F(CryptoServerConfigsTest, AdvancePrimary) {
  // Check that a new primary config is enabled at the right time.
  SetConfigs("a", 900, 1, "b", 1100, 1, nullptr);
  test_peer_.SelectNewPrimaryConfig(1000);
  test_peer_.CheckConfigs("a", true, "b", false, nullptr);
  test_peer_.SelectNewPrimaryConfig(1101);
  test_peer_.CheckConfigs("a", false, "b", true, nullptr);
}

TEST_F(CryptoServerConfigsTest, InvalidConfigs) {
  // Ensure that invalid configs don't change anything.
  SetConfigs("a", 800, 1, "b", 900, 1, "c", 1100, 1, nullptr);
  test_peer_.CheckConfigs("a", false, "b", true, "c", false, nullptr);
  SetConfigs("a", 800, 1, "c", 1100, 1, "INVALID1", 1000, 1, nullptr);
  test_peer_.CheckConfigs("a", false, "b", true, "c", false, nullptr);
}

}  // namespace test
}  // namespace net
