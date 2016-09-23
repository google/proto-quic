// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/stateless_rejector.h"

#include <memory>
#include <vector>

#include "base/memory/ptr_util.h"
#include "base/strings/stringprintf.h"
#include "net/quic/core/crypto/crypto_handshake_message.h"
#include "net/quic/core/crypto/proof_source.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_crypto_server_config_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"

using std::ostream;
using std::string;
using std::vector;

namespace net {
namespace test {
namespace {

const QuicConnectionId kConnectionId = 42;
const QuicConnectionId kServerDesignateConnectionId = 24;

// All four combinations of the two flags involved.
enum FlagsMode { ENABLED, STATELESS_DISABLED, CHEAP_DISABLED, BOTH_DISABLED };

const char* FlagsModeToString(FlagsMode mode) {
  switch (mode) {
    case ENABLED:
      return "ENABLED";
    case STATELESS_DISABLED:
      return "STATELESS_DISABLED";
    case CHEAP_DISABLED:
      return "CHEAP_DISABLED";
    case BOTH_DISABLED:
      return "BOTH_DISABLED";
    default:
      DLOG(FATAL) << "Unexpected FlagsMode";
      return nullptr;
  }
}

// Test various combinations of QUIC version and flag state.
struct TestParams {
  QuicVersion version;
  FlagsMode flags;
};

string TestParamToString(const testing::TestParamInfo<TestParams>& params) {
  return base::StringPrintf("v%i_%s", params.param.version,
                            FlagsModeToString(params.param.flags));
}

vector<TestParams> GetTestParams() {
  vector<TestParams> params;
  for (FlagsMode flags :
       {ENABLED, STATELESS_DISABLED, CHEAP_DISABLED, BOTH_DISABLED}) {
    for (QuicVersion version : AllSupportedVersions()) {
      TestParams param;
      param.version = version;
      param.flags = flags;
      params.push_back(param);
    }
  }
  return params;
}

class StatelessRejectorTest : public ::testing::TestWithParam<TestParams> {
 public:
  StatelessRejectorTest()
      : proof_source_(CryptoTestUtils::ProofSourceForTesting()),
        config_(QuicCryptoServerConfig::TESTING,
                QuicRandom::GetInstance(),
                CryptoTestUtils::ProofSourceForTesting()),
        config_peer_(&config_),
        compressed_certs_cache_(
            QuicCompressedCertsCache::kQuicCompressedCertsCacheSize),
        rejector_(base::MakeUnique<StatelessRejector>(
            GetParam().version,
            AllSupportedVersions(),
            &config_,
            &compressed_certs_cache_,
            &clock_,
            QuicRandom::GetInstance(),
            kDefaultMaxPacketSize,
            IPEndPoint(net::test::Loopback4(), 12345),
            IPEndPoint(net::test::Loopback4(), 443))) {
    FLAGS_enable_quic_stateless_reject_support =
        GetParam().flags == ENABLED || GetParam().flags == CHEAP_DISABLED;
    FLAGS_quic_use_cheap_stateless_rejects =
        GetParam().flags == ENABLED || GetParam().flags == STATELESS_DISABLED;

    // Add a new primary config.
    std::unique_ptr<CryptoHandshakeMessage> msg(config_.AddDefaultConfig(
        QuicRandom::GetInstance(), &clock_, config_options_));

    // Save the server config.
    scid_hex_ = "#" + QuicUtils::HexEncode(config_peer_.GetPrimaryConfig()->id);

    // Encode the QUIC version.
    ver_hex_ = QuicUtils::TagToString(QuicVersionToQuicTag(GetParam().version));

    // Generate a public value.
    char public_value[32];
    memset(public_value, 42, sizeof(public_value));
    pubs_hex_ = "#" + QuicUtils::HexEncode(public_value, sizeof(public_value));

    // Generate a client nonce.
    string nonce;
    CryptoUtils::GenerateNonce(
        clock_.WallNow(), QuicRandom::GetInstance(),
        StringPiece(
            reinterpret_cast<char*>(config_peer_.GetPrimaryConfig()->orbit),
            kOrbitSize),
        &nonce);
    nonc_hex_ = "#" + QuicUtils::HexEncode(nonce);

    // Generate a source address token.
    SourceAddressTokens previous_tokens;
    IPAddress ip = net::test::Loopback4();
    MockRandom rand;
    string stk = config_peer_.NewSourceAddressToken(
        config_peer_.GetPrimaryConfig()->id, previous_tokens, ip, &rand,
        clock_.WallNow(), nullptr);
    stk_hex_ = "#" + QuicUtils::HexEncode(stk);
  }

 protected:
  class ProcessDoneCallback : public StatelessRejector::ProcessDoneCallback {
   public:
    explicit ProcessDoneCallback(StatelessRejectorTest* test) : test_(test) {}
    void Run(std::unique_ptr<StatelessRejector> rejector) override {
      test_->rejector_ = std::move(rejector);
    }

   private:
    StatelessRejectorTest* test_;
  };

  QuicFlagSaver flags_;  // Save/restore all QUIC flag values.

  std::unique_ptr<ProofSource> proof_source_;
  MockClock clock_;
  QuicCryptoServerConfig config_;
  QuicCryptoServerConfigPeer config_peer_;
  QuicCompressedCertsCache compressed_certs_cache_;
  QuicCryptoServerConfig::ConfigOptions config_options_;
  std::unique_ptr<StatelessRejector> rejector_;

  // Values used in CHLO messages
  string scid_hex_;
  string nonc_hex_;
  string pubs_hex_;
  string ver_hex_;
  string stk_hex_;
};

INSTANTIATE_TEST_CASE_P(Flags,
                        StatelessRejectorTest,
                        ::testing::ValuesIn(GetTestParams()),
                        TestParamToString);

TEST_P(StatelessRejectorTest, InvalidChlo) {
  // clang-format off
  const CryptoHandshakeMessage client_hello = CryptoTestUtils::Message(
      "CHLO",
      "PDMD", "X509",
      "COPT", "SREJ",
      nullptr);
  // clang-format on
  rejector_->OnChlo(GetParam().version, kConnectionId,
                    kServerDesignateConnectionId, client_hello);

  if (GetParam().flags != ENABLED || GetParam().version <= QUIC_VERSION_32) {
    EXPECT_EQ(StatelessRejector::UNSUPPORTED, rejector_->state());
    return;
  }

  // The StatelessRejector is undecided - proceed with async processing
  ASSERT_EQ(StatelessRejector::UNKNOWN, rejector_->state());
  StatelessRejector::Process(std::move(rejector_),
                             base::MakeUnique<ProcessDoneCallback>(this));

  EXPECT_EQ(StatelessRejector::FAILED, rejector_->state());
  EXPECT_EQ(QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER, rejector_->error());
}

TEST_P(StatelessRejectorTest, ValidChloWithoutSrejSupport) {
  // clang-format off
  const CryptoHandshakeMessage client_hello = CryptoTestUtils::Message(
      "CHLO",
      "PDMD", "X509",
      "AEAD", "AESG",
      "KEXS", "C255",
      "PUBS", pubs_hex_.c_str(),
      "NONC", nonc_hex_.c_str(),
      "VER\0", ver_hex_.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on

  rejector_->OnChlo(GetParam().version, kConnectionId,
                    kServerDesignateConnectionId, client_hello);
  EXPECT_EQ(StatelessRejector::UNSUPPORTED, rejector_->state());
}

TEST_P(StatelessRejectorTest, RejectChlo) {
  // clang-format off
  const CryptoHandshakeMessage client_hello = CryptoTestUtils::Message(
      "CHLO",
      "PDMD", "X509",
      "AEAD", "AESG",
      "KEXS", "C255",
      "COPT", "SREJ",
      "SCID", scid_hex_.c_str(),
      "PUBS", pubs_hex_.c_str(),
      "NONC", nonc_hex_.c_str(),
      "#004b5453", stk_hex_.c_str(),
      "VER\0", ver_hex_.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on

  rejector_->OnChlo(GetParam().version, kConnectionId,
                    kServerDesignateConnectionId, client_hello);
  if (GetParam().flags != ENABLED || GetParam().version <= QUIC_VERSION_32) {
    EXPECT_EQ(StatelessRejector::UNSUPPORTED, rejector_->state());
    return;
  }

  // The StatelessRejector is undecided - proceed with async processing
  ASSERT_EQ(StatelessRejector::UNKNOWN, rejector_->state());
  StatelessRejector::Process(std::move(rejector_),
                             base::MakeUnique<ProcessDoneCallback>(this));

  ASSERT_EQ(StatelessRejector::REJECTED, rejector_->state());
  const CryptoHandshakeMessage& reply = rejector_->reply();
  EXPECT_EQ(kSREJ, reply.tag());
  const uint32_t* reject_reasons;
  size_t num_reject_reasons;
  EXPECT_EQ(QUIC_NO_ERROR,
            reply.GetTaglist(kRREJ, &reject_reasons, &num_reject_reasons));
  EXPECT_EQ(1u, num_reject_reasons);
  EXPECT_EQ(INVALID_EXPECTED_LEAF_CERTIFICATE,
            static_cast<HandshakeFailureReason>(reject_reasons[0]));
}

TEST_P(StatelessRejectorTest, AcceptChlo) {
  const uint64_t xlct = CryptoTestUtils::LeafCertHashForTesting();
  const string xlct_hex =
      "#" +
      QuicUtils::HexEncode(reinterpret_cast<const char*>(&xlct), sizeof(xlct));
  // clang-format off
  const CryptoHandshakeMessage client_hello = CryptoTestUtils::Message(
      "CHLO",
      "PDMD", "X509",
      "AEAD", "AESG",
      "KEXS", "C255",
      "COPT", "SREJ",
      "SCID", scid_hex_.c_str(),
      "PUBS", pubs_hex_.c_str(),
      "NONC", nonc_hex_.c_str(),
      "#004b5453", stk_hex_.c_str(),
      "VER\0", ver_hex_.c_str(),
      "XLCT", xlct_hex.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on

  rejector_->OnChlo(GetParam().version, kConnectionId,
                    kServerDesignateConnectionId, client_hello);
  if (GetParam().flags != ENABLED || GetParam().version <= QUIC_VERSION_32) {
    EXPECT_EQ(StatelessRejector::UNSUPPORTED, rejector_->state());
    return;
  }

  // The StatelessRejector is undecided - proceed with async processing
  ASSERT_EQ(StatelessRejector::UNKNOWN, rejector_->state());
  StatelessRejector::Process(std::move(rejector_),
                             base::MakeUnique<ProcessDoneCallback>(this));

  EXPECT_EQ(StatelessRejector::ACCEPTED, rejector_->state());
}

}  // namespace
}  // namespace test
}  // namespace net
