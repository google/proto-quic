// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <cstdint>
#include <memory>
#include <ostream>
#include <vector>

#include "base/strings/string_number_conversions.h"
#include "crypto/secure_hash.h"
#include "net/quic/crypto/cert_compressor.h"
#include "net/quic/crypto/common_cert_set.h"
#include "net/quic/crypto/crypto_handshake.h"
#include "net/quic/crypto/crypto_server_config_protobuf.h"
#include "net/quic/crypto/crypto_utils.h"
#include "net/quic/crypto/proof_source.h"
#include "net/quic/crypto/quic_crypto_server_config.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_socket_address_coder.h"
#include "net/quic/quic_utils.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/delayed_verify_strike_register_client.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/mock_random.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::endl;
using std::ostream;
using std::string;
using std::vector;

namespace net {
namespace test {

namespace {

class DummyProofVerifierCallback : public ProofVerifierCallback {
 public:
  DummyProofVerifierCallback() {}
  ~DummyProofVerifierCallback() override {}

  void Run(bool ok,
           const std::string& error_details,
           std::unique_ptr<ProofVerifyDetails>* details) override {
    // Do nothing
  }
};

const char kOldConfigId[] = "old-config-id";

}  // namespace

class QuicCryptoServerConfigPeer {
 public:
  explicit QuicCryptoServerConfigPeer(QuicCryptoServerConfig* server_config)
      : server_config_(server_config) {}

  base::Lock* GetStrikeRegisterClientLock() {
    return &server_config_->strike_register_client_lock_;
  }

 private:
  QuicCryptoServerConfig* server_config_;
};

// Run tests with both parities of
// FLAGS_use_early_return_when_verifying_chlo.
struct TestParams {
  TestParams(bool use_early_return_when_verifying_chlo,
             bool enable_stateless_rejects,
             bool use_stateless_rejects,
             QuicVersionVector supported_versions)
      : use_early_return_when_verifying_chlo(
            use_early_return_when_verifying_chlo),
        enable_stateless_rejects(enable_stateless_rejects),
        use_stateless_rejects(use_stateless_rejects),
        supported_versions(supported_versions) {}

  friend ostream& operator<<(ostream& os, const TestParams& p) {
    os << "{ use_early_return_when_verifying_chlo: "
       << p.use_early_return_when_verifying_chlo << std::endl;
    os << "  enable_stateless_rejects: " << p.enable_stateless_rejects
       << std::endl;
    os << "  use_stateless_rejects: " << p.use_stateless_rejects << std::endl;
    os << "  versions: " << QuicVersionVectorToString(p.supported_versions)
       << " }";
    return os;
  }

  bool use_early_return_when_verifying_chlo;
  // This only enables the stateless reject feature via the feature-flag.
  // It does not force the crypto server to emit stateless rejects.
  bool enable_stateless_rejects;
  // If true, this forces the server to send a stateless reject when
  // rejecting messages.  This should be a no-op if
  // enable_stateless_rejects is false.
  bool use_stateless_rejects;
  // Versions supported by client and server.
  QuicVersionVector supported_versions;
};

// Constructs various test permutations.
vector<TestParams> GetTestParams() {
  vector<TestParams> params;
  static const bool kTrueFalse[] = {true, false};
  for (bool use_early_return : kTrueFalse) {
    for (bool enable_stateless_rejects : kTrueFalse) {
      for (bool use_stateless_rejects : kTrueFalse) {
        // Start with all versions, remove highest on each iteration.
        QuicVersionVector supported_versions = QuicSupportedVersions();
        while (!supported_versions.empty()) {
          params.push_back(
              TestParams(use_early_return, enable_stateless_rejects,
                         use_stateless_rejects, supported_versions));
          supported_versions.erase(supported_versions.begin());
        }
      }
    }
  }
  return params;
}

class CryptoServerTest : public ::testing::TestWithParam<TestParams> {
 public:
  CryptoServerTest()
      : rand_(QuicRandom::GetInstance()),
        client_address_(Loopback4(), 1234),
        config_(QuicCryptoServerConfig::TESTING,
                rand_,
                CryptoTestUtils::ProofSourceForTesting()),
        compressed_certs_cache_(
            QuicCompressedCertsCache::kQuicCompressedCertsCacheSize) {
    supported_versions_ = GetParam().supported_versions;
    config_.set_enable_serving_sct(true);

    client_version_ = supported_versions_.front();
    client_version_string_ =
        QuicUtils::TagToString(QuicVersionToQuicTag(client_version_));

    FLAGS_use_early_return_when_verifying_chlo =
        GetParam().use_early_return_when_verifying_chlo;
    FLAGS_enable_quic_stateless_reject_support =
        GetParam().enable_stateless_rejects;
    use_stateless_rejects_ = GetParam().use_stateless_rejects;
  }

  void SetUp() override {
    QuicCryptoServerConfig::ConfigOptions old_config_options;
    old_config_options.id = kOldConfigId;
    delete config_.AddDefaultConfig(rand_, &clock_, old_config_options);
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1000));
    std::unique_ptr<QuicServerConfigProtobuf> primary_config(
        config_.GenerateConfig(rand_, &clock_, config_options_));
    primary_config->set_primary_time(clock_.WallNow().ToUNIXSeconds());
    std::unique_ptr<CryptoHandshakeMessage> msg(
        config_.AddConfig(primary_config.get(), clock_.WallNow()));

    StringPiece orbit;
    CHECK(msg->GetStringPiece(kORBT, &orbit));
    CHECK_EQ(sizeof(orbit_), orbit.size());
    memcpy(orbit_, orbit.data(), orbit.size());

    char public_value[32];
    memset(public_value, 42, sizeof(public_value));

    const string nonce_str = GenerateNonce();
    nonce_hex_ = "#" + base::HexEncode(nonce_str.data(), nonce_str.size());
    pub_hex_ = "#" + base::HexEncode(public_value, sizeof(public_value));

    // clang-format off
    CryptoHandshakeMessage client_hello = CryptoTestUtils::Message(
        "CHLO",
        "AEAD", "AESG",
        "KEXS", "C255",
        "PUBS", pub_hex_.c_str(),
        "NONC", nonce_hex_.c_str(),
        "CSCT", "",
        "VER\0", client_version_string_.c_str(),
        "$padding", static_cast<int>(kClientHelloMinimumSize),
        nullptr);
    // clang-format on
    ShouldSucceed(client_hello);
    // The message should be rejected because the source-address token is
    // missing.
    CheckRejectTag();
    const HandshakeFailureReason kRejectReasons[] = {
        SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
    CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
    CheckForServerDesignatedConnectionId();

    StringPiece srct;
    ASSERT_TRUE(out_.GetStringPiece(kSourceAddressTokenTag, &srct));
    srct_hex_ = "#" + base::HexEncode(srct.data(), srct.size());

    StringPiece scfg;
    ASSERT_TRUE(out_.GetStringPiece(kSCFG, &scfg));
    server_config_.reset(CryptoFramer::ParseMessage(scfg));

    StringPiece scid;
    ASSERT_TRUE(server_config_->GetStringPiece(kSCID, &scid));
    scid_hex_ = "#" + base::HexEncode(scid.data(), scid.size());
    crypto_proof_ = QuicCryptoProof();
    DCHECK(crypto_proof_.chain.get() == nullptr);
  }

  // Helper used to accept the result of ValidateClientHello and pass
  // it on to ProcessClientHello.
  class ValidateCallback : public ValidateClientHelloResultCallback {
   public:
    ValidateCallback(CryptoServerTest* test,
                     bool should_succeed,
                     const char* error_substr,
                     bool* called)
        : test_(test),
          should_succeed_(should_succeed),
          error_substr_(error_substr),
          called_(called) {
      *called_ = false;
    }

    void RunImpl(const CryptoHandshakeMessage& client_hello,
                 const Result& result) override {
      {
        // Ensure that the strike register client lock is not held.
        QuicCryptoServerConfigPeer peer(&test_->config_);
        base::Lock* m = peer.GetStrikeRegisterClientLock();
        // In Chromium, we will dead lock if the lock is held by the current
        // thread. Chromium doesn't have AssertNotHeld API call.
        // m->AssertNotHeld();
        base::AutoLock lock(*m);
      }
      ASSERT_FALSE(*called_);
      test_->ProcessValidationResult(client_hello, result, should_succeed_,
                                     error_substr_);
      *called_ = true;
    }

   private:
    CryptoServerTest* test_;
    bool should_succeed_;
    const char* error_substr_;
    bool* called_;
  };

  void CheckServerHello(const CryptoHandshakeMessage& server_hello) {
    const QuicTag* versions;
    size_t num_versions;
    server_hello.GetTaglist(kVER, &versions, &num_versions);
    ASSERT_EQ(supported_versions_.size(), num_versions);
    for (size_t i = 0; i < num_versions; ++i) {
      EXPECT_EQ(QuicVersionToQuicTag(supported_versions_[i]), versions[i]);
    }

    StringPiece address;
    ASSERT_TRUE(server_hello.GetStringPiece(kCADR, &address));
    QuicSocketAddressCoder decoder;
    ASSERT_TRUE(decoder.Decode(address.data(), address.size()));
    EXPECT_EQ(client_address_.address(), decoder.ip());
    EXPECT_EQ(client_address_.port(), decoder.port());
  }

  void ShouldSucceed(const CryptoHandshakeMessage& message) {
    bool called = false;
    IPAddress server_ip;
    config_.ValidateClientHello(message, client_address_.address(), server_ip,
                                supported_versions_.front(), &clock_,
                                &crypto_proof_,
                                new ValidateCallback(this, true, "", &called));
    EXPECT_TRUE(called);
  }

  void ShouldFailMentioning(const char* error_substr,
                            const CryptoHandshakeMessage& message) {
    bool called = false;
    ShouldFailMentioning(error_substr, message, &called);
    EXPECT_TRUE(called);
  }

  void ShouldFailMentioning(const char* error_substr,
                            const CryptoHandshakeMessage& message,
                            bool* called) {
    IPAddress server_ip;
    config_.ValidateClientHello(
        message, client_address_.address(), server_ip,
        supported_versions_.front(), &clock_, &crypto_proof_,
        new ValidateCallback(this, false, error_substr, called));
  }

  void ProcessValidationResult(const CryptoHandshakeMessage& message,
                               const ValidateCallback::Result& result,
                               bool should_succeed,
                               const char* error_substr) {
    IPAddress server_ip;
    string error_details;
    QuicConnectionId server_designated_connection_id =
        rand_for_id_generation_.RandUint64();
    QuicErrorCode error = config_.ProcessClientHello(
        result, 1 /* ConnectionId */, server_ip, client_address_,
        supported_versions_.front(), supported_versions_,
        use_stateless_rejects_, server_designated_connection_id, &clock_, rand_,
        &compressed_certs_cache_, &params_, &crypto_proof_, &out_,
        &error_details);

    if (should_succeed) {
      ASSERT_EQ(error, QUIC_NO_ERROR) << "Message failed with error "
                                      << error_details << ": "
                                      << message.DebugString();
    } else {
      ASSERT_NE(error, QUIC_NO_ERROR) << "Message didn't fail: "
                                      << message.DebugString();

      EXPECT_TRUE(error_details.find(error_substr) != string::npos)
          << error_substr << " not in " << error_details;
    }
  }

  string GenerateNonce() {
    string nonce;
    CryptoUtils::GenerateNonce(
        clock_.WallNow(), rand_,
        StringPiece(reinterpret_cast<const char*>(orbit_), sizeof(orbit_)),
        &nonce);
    return nonce;
  }

  void CheckRejectReasons(
      const HandshakeFailureReason* expected_handshake_failures,
      size_t expected_count) {
    const uint32_t* reject_reasons;
    size_t num_reject_reasons;
    static_assert(sizeof(QuicTag) == sizeof(uint32_t), "header_out_of_sync");
    QuicErrorCode error_code =
        out_.GetTaglist(kRREJ, &reject_reasons, &num_reject_reasons);
    ASSERT_EQ(QUIC_NO_ERROR, error_code);

    if (FLAGS_use_early_return_when_verifying_chlo) {
      EXPECT_EQ(1u, num_reject_reasons);
    } else {
      EXPECT_EQ(expected_count, num_reject_reasons);
    }
    for (size_t i = 0; i < num_reject_reasons; ++i) {
      EXPECT_EQ(expected_handshake_failures[i], reject_reasons[i]);
    }
  }

  // If the server is rejecting statelessly, make sure it contains a
  // server-designated connection id.  Once the check is complete,
  // allow the random id-generator to move to the next value.
  void CheckForServerDesignatedConnectionId() {
    QuicConnectionId server_designated_connection_id;
    if (!RejectsAreStateless()) {
      EXPECT_EQ(QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND,
                out_.GetUint64(kRCID, &server_designated_connection_id));
    } else {
      ASSERT_EQ(QUIC_NO_ERROR,
                out_.GetUint64(kRCID, &server_designated_connection_id));
      EXPECT_EQ(rand_for_id_generation_.RandUint64(),
                server_designated_connection_id);
    }
    rand_for_id_generation_.ChangeValue();
  }

  void CheckRejectTag() {
    if (RejectsAreStateless()) {
      ASSERT_EQ(kSREJ, out_.tag()) << QuicUtils::TagToString(out_.tag());
    } else {
      ASSERT_EQ(kREJ, out_.tag()) << QuicUtils::TagToString(out_.tag());
    }
  }

  bool RejectsAreStateless() {
    return GetParam().enable_stateless_rejects &&
           GetParam().use_stateless_rejects;
  }

  string XlctHexString() {
    scoped_refptr<ProofSource::Chain> chain;
    IPAddress server_ip;
    string sig;
    string cert_sct;
    std::unique_ptr<ProofSource> proof_source(
        CryptoTestUtils::ProofSourceForTesting());
    if (!proof_source->GetProof(server_ip, "", "", client_version_, "", false,
                                &chain, &sig, &cert_sct) ||
        chain->certs.empty()) {
      return "#0100000000000000";
    }

    std::ostringstream xlct_stream;
    uint64_t xlct = QuicUtils::FNV1a_64_Hash(chain->certs.at(0).c_str(),
                                             chain->certs.at(0).length());

    return "#" + base::HexEncode(reinterpret_cast<char*>(&xlct), sizeof(xlct));
  }

 protected:
  QuicRandom* const rand_;
  MockRandom rand_for_id_generation_;
  MockClock clock_;
  IPEndPoint client_address_;
  QuicVersionVector supported_versions_;
  QuicVersion client_version_;
  string client_version_string_;
  QuicCryptoServerConfig config_;
  QuicCompressedCertsCache compressed_certs_cache_;
  QuicCryptoServerConfig::ConfigOptions config_options_;
  QuicCryptoNegotiatedParameters params_;
  QuicCryptoProof crypto_proof_;
  CryptoHandshakeMessage out_;
  uint8_t orbit_[kOrbitSize];
  bool use_stateless_rejects_;

  // These strings contain hex escaped values from the server suitable for using
  // when constructing client hello messages.
  string nonce_hex_, pub_hex_, srct_hex_, scid_hex_;
  std::unique_ptr<CryptoHandshakeMessage> server_config_;
};

// Run all CryptoServerTest with both values of
// FLAGS_use_early_return_when_verifying_chlo.
INSTANTIATE_TEST_CASE_P(CryptoServerTests,
                        CryptoServerTest,
                        ::testing::ValuesIn(GetTestParams()));

TEST_P(CryptoServerTest, BadSNI) {
  // clang-format off
  static const char* const kBadSNIs[] = {
    "",
    "foo",
    "#00",
    "#ff00",
    "127.0.0.1",
    "ffee::1",
  };
  // clang-format on

  for (size_t i = 0; i < arraysize(kBadSNIs); i++) {
    // clang-format off
    CryptoHandshakeMessage msg = CryptoTestUtils::Message(
        "CHLO",
        "SNI", kBadSNIs[i],
        "VER\0", client_version_string_.c_str(),
        "$padding", static_cast<int>(kClientHelloMinimumSize),
        nullptr);
    // clang-format on
    ShouldFailMentioning("SNI", msg);
    const HandshakeFailureReason kRejectReasons[] = {
        SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
    CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
  }
}

TEST_P(CryptoServerTest, DefaultCert) {
  // Check that the server replies with a default certificate when no SNI is
  // specified. The CHLO is constructed to generate a REJ with certs, so must
  // not contain a valid STK, and must include PDMD.
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "PUBS", pub_hex_.c_str(),
      "NONC", nonce_hex_.c_str(),
      "PDMD", "X509",
      "VER\0", client_version_string_.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on

  ShouldSucceed(msg);
  StringPiece cert, proof, cert_sct;
  EXPECT_TRUE(out_.GetStringPiece(kCertificateTag, &cert));
  EXPECT_TRUE(out_.GetStringPiece(kPROF, &proof));
  EXPECT_EQ(client_version_ > QUIC_VERSION_29,
            out_.GetStringPiece(kCertificateSCTTag, &cert_sct));
  EXPECT_NE(0u, cert.size());
  EXPECT_NE(0u, proof.size());
  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
  CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
  EXPECT_EQ(client_version_ > QUIC_VERSION_29, cert_sct.size() > 0);
}

TEST_P(CryptoServerTest, RejectTooLarge) {
  // Check that the server replies with no certificate when a CHLO is
  // constructed with a PDMD but no SKT when the REJ would be too large.
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "PUBS", pub_hex_.c_str(),
      "NONC", nonce_hex_.c_str(),
      "PDMD", "X509",
      "VER\0", client_version_string_.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on

  // The REJ will be larger than the CHLO so no PROF or CRT will be sent.
  config_.set_chlo_multiplier(1);

  ShouldSucceed(msg);
  StringPiece cert, proof, cert_sct;
  EXPECT_FALSE(out_.GetStringPiece(kCertificateTag, &cert));
  EXPECT_FALSE(out_.GetStringPiece(kPROF, &proof));
  EXPECT_FALSE(out_.GetStringPiece(kCertificateSCTTag, &cert_sct));
  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
  CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
}

TEST_P(CryptoServerTest, RejectTooLargeButValidSTK) {
  // Check that the server replies with no certificate when a CHLO is
  // constructed with a PDMD but no SKT when the REJ would be too large.
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "PUBS", pub_hex_.c_str(),
      "NONC", nonce_hex_.c_str(),
      "#004b5453", srct_hex_.c_str(),
      "PDMD", "X509",
      "VER\0", client_version_string_.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on

  // The REJ will be larger than the CHLO so no PROF or CRT will be sent.
  config_.set_chlo_multiplier(1);

  ShouldSucceed(msg);
  StringPiece cert, proof, cert_sct;
  EXPECT_TRUE(out_.GetStringPiece(kCertificateTag, &cert));
  EXPECT_TRUE(out_.GetStringPiece(kPROF, &proof));
  EXPECT_EQ(client_version_ > QUIC_VERSION_29,
            out_.GetStringPiece(kCertificateSCTTag, &cert_sct));
  EXPECT_NE(0u, cert.size());
  EXPECT_NE(0u, proof.size());
  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
  CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
}

TEST_P(CryptoServerTest, TooSmall) {
  // clang-format off
  ShouldFailMentioning("too small", CryptoTestUtils::Message(
        "CHLO",
        "VER\0", client_version_string_.c_str(),
        nullptr));
  // clang-format on
  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
  CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
}

TEST_P(CryptoServerTest, BadSourceAddressToken) {
  // Invalid source-address tokens should be ignored.
  // clang-format off
  static const char* const kBadSourceAddressTokens[] = {
    "",
    "foo",
    "#0000",
    "#0000000000000000000000000000000000000000",
  };
  // clang-format on

  for (size_t i = 0; i < arraysize(kBadSourceAddressTokens); i++) {
    // clang-format off
    CryptoHandshakeMessage msg = CryptoTestUtils::Message(
        "CHLO",
        "STK", kBadSourceAddressTokens[i],
        "VER\0", client_version_string_.c_str(),
        "$padding", static_cast<int>(kClientHelloMinimumSize), nullptr);
    // clang-format on
    ShouldSucceed(msg);
    const HandshakeFailureReason kRejectReasons[] = {
        SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
    CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
  }
}

TEST_P(CryptoServerTest, BadClientNonce) {
  // clang-format off
  static const char* const kBadNonces[] = {
    "",
    "#0000",
    "#0000000000000000000000000000000000000000",
  };
  // clang-format on

  for (size_t i = 0; i < arraysize(kBadNonces); i++) {
    // Invalid nonces should be ignored, in an inchoate CHLO.
    // clang-format off
    CryptoHandshakeMessage msg = CryptoTestUtils::Message(
        "CHLO",
        "NONC", kBadNonces[i],
        "VER\0", client_version_string_.c_str(),
        "$padding", static_cast<int>(kClientHelloMinimumSize),
        nullptr);
    // clang-format on
    ShouldSucceed(msg);
    const HandshakeFailureReason kRejectReasons[] = {
        SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
    CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));

    // Invalid nonces should result in CLIENT_NONCE_INVALID_FAILURE.
    // clang-format off
    CryptoHandshakeMessage msg1 = CryptoTestUtils::Message(
        "CHLO",
        "AEAD", "AESG",
        "KEXS", "C255",
        "SCID", scid_hex_.c_str(),
        "#004b5453", srct_hex_.c_str(),
        "PUBS", pub_hex_.c_str(),
        "NONC", kBadNonces[i],
        "NONP", kBadNonces[i],
        "XLCT", XlctHexString().c_str(),
        "VER\0", client_version_string_.c_str(),
        "$padding", static_cast<int>(kClientHelloMinimumSize),
        nullptr);
    // clang-format on

    ShouldSucceed(msg1);

    CheckRejectTag();
    const HandshakeFailureReason kRejectReasons1[] = {
        CLIENT_NONCE_INVALID_FAILURE};
    CheckRejectReasons(kRejectReasons1, arraysize(kRejectReasons1));
  }
}

TEST_P(CryptoServerTest, NoClientNonce) {
  // No client nonces should result in INCHOATE_HELLO_FAILURE.
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "VER\0", client_version_string_.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on

  ShouldSucceed(msg);
  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
  CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));

  // clang-format off
  CryptoHandshakeMessage msg1 = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "SCID", scid_hex_.c_str(),
      "#004b5453", srct_hex_.c_str(),
      "PUBS", pub_hex_.c_str(),
      "XLCT", XlctHexString().c_str(),
      "VER\0", client_version_string_.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on

  ShouldSucceed(msg1);
  CheckRejectTag();
  const HandshakeFailureReason kRejectReasons1[] = {
      SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
  CheckRejectReasons(kRejectReasons1, arraysize(kRejectReasons1));
}

TEST_P(CryptoServerTest, DowngradeAttack) {
  if (supported_versions_.size() == 1) {
    // No downgrade attack is possible if the server only supports one version.
    return;
  }
  // Set the client's preferred version to a supported version that
  // is not the "current" version (supported_versions_.front()).
  string bad_version =
      QuicUtils::TagToString(QuicVersionToQuicTag(supported_versions_.back()));

  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "VER\0", bad_version.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on
  ShouldFailMentioning("Downgrade", msg);
  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
  CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
}

TEST_P(CryptoServerTest, CorruptServerConfig) {
  // This tests corrupted server config.
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "SCID", (string(1, 'X') + scid_hex_).c_str(),
      "#004b5453", srct_hex_.c_str(),
      "PUBS", pub_hex_.c_str(),
      "NONC", nonce_hex_.c_str(),
      "VER\0", client_version_string_.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on
  ShouldSucceed(msg);
  CheckRejectTag();
  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE};
  CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
}

TEST_P(CryptoServerTest, CorruptSourceAddressToken) {
  // This tests corrupted source address token.
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "SCID", scid_hex_.c_str(),
      "#004b5453", (string(1, 'X') + srct_hex_).c_str(),
      "PUBS", pub_hex_.c_str(),
      "NONC", nonce_hex_.c_str(),
      "XLCT", XlctHexString().c_str(),
      "VER\0", client_version_string_.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on
  ShouldSucceed(msg);
  CheckRejectTag();
  const HandshakeFailureReason kRejectReasons[] = {
      SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE};
  CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
}

TEST_P(CryptoServerTest, CorruptClientNonceAndSourceAddressToken) {
  // This test corrupts client nonce and source address token.
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "SCID", scid_hex_.c_str(),
      "#004b5453", (string(1, 'X') + srct_hex_).c_str(),
      "PUBS", pub_hex_.c_str(),
      "NONC", (string(1, 'X') + nonce_hex_).c_str(),
      "XLCT", XlctHexString().c_str(),
      "VER\0", client_version_string_.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on
  ShouldSucceed(msg);
  CheckRejectTag();
  const HandshakeFailureReason kRejectReasons[] = {
      SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE, CLIENT_NONCE_INVALID_FAILURE};
  CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
}

TEST_P(CryptoServerTest, CorruptMultipleTags) {
  // This test corrupts client nonce, server nonce and source address token.
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "SCID", scid_hex_.c_str(),
      "#004b5453", (string(1, 'X') + srct_hex_).c_str(),
      "PUBS", pub_hex_.c_str(),
      "NONC", (string(1, 'X') + nonce_hex_).c_str(),
      "NONP", (string(1, 'X') + nonce_hex_).c_str(),
      "SNO\0", (string(1, 'X') + nonce_hex_).c_str(),
      "XLCT", XlctHexString().c_str(),
      "VER\0", client_version_string_.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on
  ShouldSucceed(msg);
  CheckRejectTag();

  if (client_version_ <= QUIC_VERSION_32) {
    const HandshakeFailureReason kRejectReasons[] = {
        SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE, CLIENT_NONCE_INVALID_FAILURE,
        SERVER_NONCE_DECRYPTION_FAILURE};
    CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
  } else {
    const HandshakeFailureReason kRejectReasons[] = {
        SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE, CLIENT_NONCE_INVALID_FAILURE};
    CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
  };
}

TEST_P(CryptoServerTest, NoServerNonce) {
  // When no server nonce is present and no strike register is configured,
  // the CHLO should be rejected.
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "SCID", scid_hex_.c_str(),
      "#004b5453", srct_hex_.c_str(),
      "PUBS", pub_hex_.c_str(),
      "NONC", nonce_hex_.c_str(),
      "NONP", nonce_hex_.c_str(),
      "XLCT", XlctHexString().c_str(),
      "VER\0", client_version_string_.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on

  ShouldSucceed(msg);

  CheckRejectTag();
  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_NONCE_REQUIRED_FAILURE};
  CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
}

TEST_P(CryptoServerTest, ProofForSuppliedServerConfig) {
  client_address_ = IPEndPoint(Loopback6(), 1234);
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "PDMD", "X509",
      "SCID", kOldConfigId,
      "#004b5453", srct_hex_.c_str(),
      "PUBS", pub_hex_.c_str(),
      "NONC", nonce_hex_.c_str(),
      "VER\0", client_version_string_.c_str(),
      "XLCT", XlctHexString().c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on
  ShouldSucceed(msg);
  // The message should be rejected because the source-address token is no
  // longer valid.
  CheckRejectTag();
  const HandshakeFailureReason kRejectReasons[] = {
      SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE};
  CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));

  StringPiece cert, proof, scfg_str;
  EXPECT_TRUE(out_.GetStringPiece(kCertificateTag, &cert));
  EXPECT_TRUE(out_.GetStringPiece(kPROF, &proof));
  EXPECT_TRUE(out_.GetStringPiece(kSCFG, &scfg_str));
  std::unique_ptr<CryptoHandshakeMessage> scfg(
      CryptoFramer::ParseMessage(scfg_str));
  StringPiece scid;
  EXPECT_TRUE(scfg->GetStringPiece(kSCID, &scid));
  EXPECT_NE(scid, kOldConfigId);

  // Get certs from compressed certs.
  const CommonCertSets* common_cert_sets(CommonCertSets::GetInstanceQUIC());
  vector<string> cached_certs;

  vector<string> certs;
  ASSERT_TRUE(CertCompressor::DecompressChain(cert, cached_certs,
                                              common_cert_sets, &certs));

  // Check that the proof in the REJ message is valid.
  std::unique_ptr<ProofVerifier> proof_verifier(
      CryptoTestUtils::ProofVerifierForTesting());
  std::unique_ptr<ProofVerifyContext> verify_context(
      CryptoTestUtils::ProofVerifyContextForTesting());
  std::unique_ptr<ProofVerifyDetails> details;
  string error_details;
  DummyProofVerifierCallback callback;
  string chlo_hash;
  CryptoUtils::HashHandshakeMessage(msg, &chlo_hash);
  EXPECT_EQ(QUIC_SUCCESS,
            proof_verifier->VerifyProof(
                "test.example.com", 443, scfg_str.as_string(), client_version_,
                chlo_hash, certs, "", proof.as_string(), verify_context.get(),
                &error_details, &details, &callback));
}

TEST_P(CryptoServerTest, RejectInvalidXlct) {
  if (client_version_ <= QUIC_VERSION_25) {
    // XLCT tag introduced in QUIC_VERSION_26.
    return;
  }
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "SCID", scid_hex_.c_str(),
      "#004b5453", srct_hex_.c_str(),
      "PUBS", pub_hex_.c_str(),
      "NONC", nonce_hex_.c_str(),
      "VER\0", client_version_string_.c_str(),
      "XLCT", "#0102030405060708",
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on
  // If replay protection isn't disabled, then
  // QuicCryptoServerConfig::EvaluateClientHello will leave info.unique as false
  // and cause ProcessClientHello to exit early (and generate a REJ message).
  config_.set_replay_protection(false);

  ShouldSucceed(msg);
  // clang-format off
  const HandshakeFailureReason kRejectReasons[] = {
    INVALID_EXPECTED_LEAF_CERTIFICATE
  };
  // clang-format on
  CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
}

TEST_P(CryptoServerTest, ValidXlct) {
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "SCID", scid_hex_.c_str(),
      "#004b5453", srct_hex_.c_str(),
      "PUBS", pub_hex_.c_str(),
      "NONC", nonce_hex_.c_str(),
      "NONP", "123456789012345678901234567890",
      "VER\0", client_version_string_.c_str(),
      "XLCT", XlctHexString().c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on
  // If replay protection isn't disabled, then
  // QuicCryptoServerConfig::EvaluateClientHello will leave info.unique as false
  // and cause ProcessClientHello to exit early (and generate a REJ message).
  config_.set_replay_protection(false);

  ShouldSucceed(msg);
  EXPECT_EQ(kSHLO, out_.tag());
}

TEST_P(CryptoServerTest, NonceInSHLO) {
  // After QUIC_VERSION_27, the SHLO should contain a nonce.
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "SCID", scid_hex_.c_str(),
      "#004b5453", srct_hex_.c_str(),
      "PUBS", pub_hex_.c_str(),
      "NONC", nonce_hex_.c_str(),
      "VER\0", client_version_string_.c_str(),
      "XLCT", XlctHexString().c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on
  // If replay protection isn't disabled, then
  // QuicCryptoServerConfig::EvaluateClientHello will leave info.unique as false
  // and cause ProcessClientHello to exit early (and generate a REJ message).
  config_.set_replay_protection(false);

  ShouldSucceed(msg);
  EXPECT_EQ(kSHLO, out_.tag());

  StringPiece nonce;
  if (client_version_ <= QUIC_VERSION_26) {
    EXPECT_FALSE(out_.GetStringPiece(kServerNonceTag, &nonce));
  } else {
    EXPECT_TRUE(out_.GetStringPiece(kServerNonceTag, &nonce));
  }
}

TEST(CryptoServerConfigGenerationTest, Determinism) {
  // Test that using a deterministic PRNG causes the server-config to be
  // deterministic.

  MockRandom rand_a, rand_b;
  const QuicCryptoServerConfig::ConfigOptions options;
  MockClock clock;

  QuicCryptoServerConfig a(QuicCryptoServerConfig::TESTING, &rand_a,
                           CryptoTestUtils::ProofSourceForTesting());
  QuicCryptoServerConfig b(QuicCryptoServerConfig::TESTING, &rand_b,
                           CryptoTestUtils::ProofSourceForTesting());
  std::unique_ptr<CryptoHandshakeMessage> scfg_a(
      a.AddDefaultConfig(&rand_a, &clock, options));
  std::unique_ptr<CryptoHandshakeMessage> scfg_b(
      b.AddDefaultConfig(&rand_b, &clock, options));

  ASSERT_EQ(scfg_a->DebugString(), scfg_b->DebugString());
}

TEST(CryptoServerConfigGenerationTest, SCIDVaries) {
  // This test ensures that the server config ID varies for different server
  // configs.

  MockRandom rand_a, rand_b;
  const QuicCryptoServerConfig::ConfigOptions options;
  MockClock clock;

  QuicCryptoServerConfig a(QuicCryptoServerConfig::TESTING, &rand_a,
                           CryptoTestUtils::ProofSourceForTesting());
  rand_b.ChangeValue();
  QuicCryptoServerConfig b(QuicCryptoServerConfig::TESTING, &rand_b,
                           CryptoTestUtils::ProofSourceForTesting());
  std::unique_ptr<CryptoHandshakeMessage> scfg_a(
      a.AddDefaultConfig(&rand_a, &clock, options));
  std::unique_ptr<CryptoHandshakeMessage> scfg_b(
      b.AddDefaultConfig(&rand_b, &clock, options));

  StringPiece scid_a, scid_b;
  EXPECT_TRUE(scfg_a->GetStringPiece(kSCID, &scid_a));
  EXPECT_TRUE(scfg_b->GetStringPiece(kSCID, &scid_b));

  EXPECT_NE(scid_a, scid_b);
}

TEST(CryptoServerConfigGenerationTest, SCIDIsHashOfServerConfig) {
  MockRandom rand_a;
  const QuicCryptoServerConfig::ConfigOptions options;
  MockClock clock;

  QuicCryptoServerConfig a(QuicCryptoServerConfig::TESTING, &rand_a,
                           CryptoTestUtils::ProofSourceForTesting());
  std::unique_ptr<CryptoHandshakeMessage> scfg(
      a.AddDefaultConfig(&rand_a, &clock, options));

  StringPiece scid;
  EXPECT_TRUE(scfg->GetStringPiece(kSCID, &scid));
  // Need to take a copy of |scid| has we're about to call |Erase|.
  const string scid_str(scid.as_string());

  scfg->Erase(kSCID);
  scfg->MarkDirty();
  const QuicData& serialized(scfg->GetSerialized());

  std::unique_ptr<crypto::SecureHash> hash(
      crypto::SecureHash::Create(crypto::SecureHash::SHA256));
  hash->Update(serialized.data(), serialized.length());
  uint8_t digest[16];
  hash->Finish(digest, sizeof(digest));

  ASSERT_EQ(scid.size(), sizeof(digest));
  EXPECT_EQ(0, memcmp(digest, scid_str.c_str(), sizeof(digest)));
}

class CryptoServerTestNoConfig : public CryptoServerTest {
 public:
  void SetUp() override {
    // Deliberately don't add a config so that we can test this situation.
  }
};

TEST_P(CryptoServerTestNoConfig, DontCrash) {
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "VER\0", client_version_string_.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on
  ShouldFailMentioning("No config", msg);

  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
  CheckRejectReasons(kRejectReasons, arraysize(kRejectReasons));
}

class CryptoServerTestOldVersion : public CryptoServerTest {
 public:
  void SetUp() override {
    client_version_ = supported_versions_.back();
    client_version_string_ =
        QuicUtils::TagToString(QuicVersionToQuicTag(client_version_));
    CryptoServerTest::SetUp();
  }
};

TEST_P(CryptoServerTestOldVersion, ServerIgnoresXlct) {
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "SCID", scid_hex_.c_str(),
      "#004b5453", srct_hex_.c_str(),
      "PUBS", pub_hex_.c_str(),
      "NONC", nonce_hex_.c_str(),
      "VER\0", client_version_string_.c_str(),
      "XLCT", "#0100000000000000",
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on
  // If replay protection isn't disabled, then
  // QuicCryptoServerConfig::EvaluateClientHello will leave info.unique as false
  // and cause ProcessClientHello to exit early (and generate a REJ message).
  config_.set_replay_protection(false);

  ShouldSucceed(msg);
  EXPECT_EQ(kSHLO, out_.tag());
}

TEST_P(CryptoServerTestOldVersion, XlctNotRequired) {
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "SCID", scid_hex_.c_str(),
      "#004b5453", srct_hex_.c_str(),
      "PUBS", pub_hex_.c_str(),
      "NONC", nonce_hex_.c_str(),
      "VER\0", client_version_string_.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on
  // If replay protection isn't disabled, then
  // QuicCryptoServerConfig::EvaluateClientHello will leave info.unique as false
  // and cause ProcessClientHello to exit early (and generate a REJ message).
  config_.set_replay_protection(false);

  ShouldSucceed(msg);
  EXPECT_EQ(kSHLO, out_.tag());
}

class AsyncStrikeServerVerificationTest : public CryptoServerTest {
 protected:
  AsyncStrikeServerVerificationTest() {}

  void SetUp() override {
    const string kOrbit = "12345678";
    config_options_.orbit = kOrbit;
    strike_register_client_ = new DelayedVerifyStrikeRegisterClient(
        10000,  // strike_register_max_entries
        static_cast<uint32_t>(clock_.WallNow().ToUNIXSeconds()),
        60,  // strike_register_window_secs
        reinterpret_cast<const uint8_t*>(kOrbit.c_str()),
        StrikeRegister::NO_STARTUP_PERIOD_NEEDED);
    config_.SetStrikeRegisterClient(strike_register_client_);
    ASSERT_NO_FATAL_FAILURE(CryptoServerTest::SetUp());
    strike_register_client_->StartDelayingVerification();
  }

  DelayedVerifyStrikeRegisterClient* strike_register_client_;
};

TEST_P(AsyncStrikeServerVerificationTest, AsyncReplayProtection) {
  // This tests async validation with a strike register works.
  // clang-format off
  CryptoHandshakeMessage msg = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "SCID", scid_hex_.c_str(),
      "#004b5453", srct_hex_.c_str(),
      "PUBS", pub_hex_.c_str(),
      "NONC", nonce_hex_.c_str(),
      "VER\0", client_version_string_.c_str(),
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on

  // Clear the message tag.
  out_.set_tag(0);

  bool called = false;
  IPAddress server_ip;
  config_.ValidateClientHello(msg, client_address_.address(), server_ip,
                              client_version_, &clock_, &crypto_proof_,
                              new ValidateCallback(this, true, "", &called));
  // The verification request was queued.
  ASSERT_FALSE(called);
  EXPECT_EQ(0u, out_.tag());
  EXPECT_EQ(1, strike_register_client_->PendingVerifications());

  // Continue processing the verification request.
  strike_register_client_->RunPendingVerifications();
  ASSERT_TRUE(called);
  EXPECT_EQ(0, strike_register_client_->PendingVerifications());
  // The message should be accepted now.
  EXPECT_EQ(kSHLO, out_.tag());

  // Rejected if replayed.
  config_.ValidateClientHello(msg, client_address_.address(), server_ip,
                              client_version_, &clock_, &crypto_proof_,
                              new ValidateCallback(this, true, "", &called));
  // The verification request was queued.
  ASSERT_FALSE(called);
  EXPECT_EQ(1, strike_register_client_->PendingVerifications());

  strike_register_client_->RunPendingVerifications();
  ASSERT_TRUE(called);
  EXPECT_EQ(0, strike_register_client_->PendingVerifications());
  // The message should be rejected now.
  CheckRejectTag();
}

}  // namespace test
}  // namespace net
