// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/crypto_test_utils.h"

#include "net/quic/core/crypto/crypto_server_config_protobuf.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::string;

namespace net {
namespace test {

class ShloVerifier : public ValidateClientHelloResultCallback {
 public:
  ShloVerifier(QuicCryptoServerConfig* crypto_config,
               IPAddress server_ip,
               IPEndPoint client_addr,
               const QuicClock* clock,
               QuicCryptoProof* proof,
               QuicCompressedCertsCache* compressed_certs_cache)
      : crypto_config_(crypto_config),
        server_ip_(server_ip),
        client_addr_(client_addr),
        clock_(clock),
        proof_(proof),
        compressed_certs_cache_(compressed_certs_cache) {}

  // Verify that the output message is a SHLO.
  void RunImpl(const CryptoHandshakeMessage& chlo,
               const ValidateClientHelloResultCallback::Result& result,
               std::unique_ptr<ProofSource::Details> /* details */) override {
    QuicCryptoNegotiatedParameters params;
    string error_details;
    DiversificationNonce diversification_nonce;
    CryptoHandshakeMessage out;
    crypto_config_->ProcessClientHello(
        result, /*reject_only=*/false, /*connection_id=*/1, server_ip_,
        client_addr_, AllSupportedVersions().front(), AllSupportedVersions(),
        /*use_stateless_rejects=*/true, /*server_designated_connection_id=*/0,
        clock_, QuicRandom::GetInstance(), compressed_certs_cache_, &params,
        proof_, /*total_framing_overhead=*/50, kDefaultMaxPacketSize, &out,
        &diversification_nonce, &error_details);
    // Verify output is a SHLO.
    EXPECT_EQ(out.tag(), kSHLO) << "Fail to pass validation. Get "
                                << out.DebugString();
  }

 protected:
  QuicCryptoServerConfig* crypto_config_;
  IPAddress server_ip_;
  IPEndPoint client_addr_;
  const QuicClock* clock_;
  QuicCryptoProof* proof_;
  QuicCompressedCertsCache* compressed_certs_cache_;
};

TEST(CryptoTestUtilsTest, TestGenerateFullCHLO) {
  MockClock clock;
  QuicCryptoServerConfig crypto_config(
      QuicCryptoServerConfig::TESTING, QuicRandom::GetInstance(),
      CryptoTestUtils::ProofSourceForTesting());
  IPAddress server_ip;
  IPEndPoint client_addr(IPAddress::IPv4Localhost(), 1);
  QuicCryptoProof proof;
  QuicCompressedCertsCache compressed_certs_cache(
      QuicCompressedCertsCache::kQuicCompressedCertsCacheSize);
  CryptoHandshakeMessage full_chlo;

  QuicCryptoServerConfig::ConfigOptions old_config_options;
  old_config_options.id = "old-config-id";
  delete crypto_config.AddDefaultConfig(QuicRandom::GetInstance(), &clock,
                                        old_config_options);
  QuicCryptoServerConfig::ConfigOptions new_config_options;
  std::unique_ptr<QuicServerConfigProtobuf> primary_config(
      crypto_config.GenerateConfig(QuicRandom::GetInstance(), &clock,
                                   new_config_options));
  primary_config->set_primary_time(clock.WallNow().ToUNIXSeconds());
  std::unique_ptr<CryptoHandshakeMessage> msg(
      crypto_config.AddConfig(primary_config.get(), clock.WallNow()));
  StringPiece orbit;
  ASSERT_TRUE(msg->GetStringPiece(kORBT, &orbit));
  string nonce;
  CryptoUtils::GenerateNonce(
      clock.WallNow(), QuicRandom::GetInstance(),
      StringPiece(reinterpret_cast<const char*>(orbit.data()),
                  sizeof(orbit.size())),
      &nonce);
  string nonce_hex = "#" + QuicUtils::HexEncode(nonce);

  char public_value[32];
  memset(public_value, 42, sizeof(public_value));
  string pub_hex =
      "#" + QuicUtils::HexEncode(public_value, sizeof(public_value));

  QuicVersion version(AllSupportedVersions().front());
  // clang-format off
  CryptoHandshakeMessage inchoate_chlo = CryptoTestUtils::Message(
    "CHLO",
    "PDMD", "X509",
    "AEAD", "AESG",
    "KEXS", "C255",
    "COPT", "SREJ",
    "PUBS", pub_hex.c_str(),
    "NONC", nonce_hex.c_str(),
    "VER\0", QuicUtils::TagToString(QuicVersionToQuicTag(version)).c_str(),
    "$padding", static_cast<int>(kClientHelloMinimumSize),
    nullptr);
  // clang-format on

  CryptoTestUtils::GenerateFullCHLO(inchoate_chlo, &crypto_config, server_ip,
                                    client_addr, version, &clock, &proof,
                                    &compressed_certs_cache, &full_chlo);
  // Verify that full_chlo can pass crypto_config's verification.
  crypto_config.ValidateClientHello(
      full_chlo, client_addr.address(), server_ip, version, &clock, &proof,
      new ShloVerifier(&crypto_config, server_ip, client_addr, &clock, &proof,
                       &compressed_certs_cache));
}

}  // namespace test
}  // namespace net
