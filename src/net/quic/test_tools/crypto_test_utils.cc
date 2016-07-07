// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/crypto_test_utils.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <memory>

#include "base/strings/string_util.h"
#include "crypto/openssl_util.h"
#include "crypto/scoped_openssl_types.h"
#include "crypto/secure_hash.h"
#include "net/quic/crypto/channel_id.h"
#include "net/quic/crypto/common_cert_set.h"
#include "net/quic/crypto/crypto_handshake.h"
#include "net/quic/crypto/quic_crypto_server_config.h"
#include "net/quic/crypto/quic_decrypter.h"
#include "net/quic/crypto/quic_encrypter.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_crypto_client_stream.h"
#include "net/quic/quic_crypto_server_stream.h"
#include "net/quic/quic_crypto_stream.h"
#include "net/quic/quic_server_id.h"
#include "net/quic/quic_utils.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_framer_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/simple_quic_framer.h"

using base::StringPiece;
using std::make_pair;
using std::pair;
using std::string;
using std::vector;

namespace net {
namespace test {

namespace {

// CryptoFramerVisitor is a framer visitor that records handshake messages.
class CryptoFramerVisitor : public CryptoFramerVisitorInterface {
 public:
  CryptoFramerVisitor() : error_(false) {}

  void OnError(CryptoFramer* framer) override { error_ = true; }

  void OnHandshakeMessage(const CryptoHandshakeMessage& message) override {
    messages_.push_back(message);
  }

  bool error() const { return error_; }

  const vector<CryptoHandshakeMessage>& messages() const { return messages_; }

 private:
  bool error_;
  vector<CryptoHandshakeMessage> messages_;
};

// HexChar parses |c| as a hex character. If valid, it sets |*value| to the
// value of the hex character and returns true. Otherwise it returns false.
bool HexChar(char c, uint8_t* value) {
  if (c >= '0' && c <= '9') {
    *value = c - '0';
    return true;
  }
  if (c >= 'a' && c <= 'f') {
    *value = c - 'a' + 10;
    return true;
  }
  if (c >= 'A' && c <= 'F') {
    *value = c - 'A' + 10;
    return true;
  }
  return false;
}

// A ChannelIDSource that works in asynchronous mode unless the |callback|
// argument to GetChannelIDKey is nullptr.
class AsyncTestChannelIDSource : public ChannelIDSource,
                                 public CryptoTestUtils::CallbackSource {
 public:
  // Takes ownership of |sync_source|, a synchronous ChannelIDSource.
  explicit AsyncTestChannelIDSource(ChannelIDSource* sync_source)
      : sync_source_(sync_source) {}
  ~AsyncTestChannelIDSource() override {}

  // ChannelIDSource implementation.
  QuicAsyncStatus GetChannelIDKey(const string& hostname,
                                  std::unique_ptr<ChannelIDKey>* channel_id_key,
                                  ChannelIDSourceCallback* callback) override {
    // Synchronous mode.
    if (!callback) {
      return sync_source_->GetChannelIDKey(hostname, channel_id_key, nullptr);
    }

    // Asynchronous mode.
    QuicAsyncStatus status =
        sync_source_->GetChannelIDKey(hostname, &channel_id_key_, nullptr);
    if (status != QUIC_SUCCESS) {
      return QUIC_FAILURE;
    }
    callback_.reset(callback);
    return QUIC_PENDING;
  }

  // CallbackSource implementation.
  void RunPendingCallbacks() override {
    if (callback_.get()) {
      callback_->Run(&channel_id_key_);
      callback_.reset();
    }
  }

 private:
  std::unique_ptr<ChannelIDSource> sync_source_;
  std::unique_ptr<ChannelIDSourceCallback> callback_;
  std::unique_ptr<ChannelIDKey> channel_id_key_;
};

class TestChannelIDKey : public ChannelIDKey {
 public:
  explicit TestChannelIDKey(EVP_PKEY* ecdsa_key) : ecdsa_key_(ecdsa_key) {}
  ~TestChannelIDKey() override {}

  // ChannelIDKey implementation.

  bool Sign(StringPiece signed_data, string* out_signature) const override {
    crypto::ScopedEVP_MD_CTX md_ctx(EVP_MD_CTX_create());
    if (!md_ctx ||
        EVP_DigestSignInit(md_ctx.get(), nullptr, EVP_sha256(), nullptr,
                           ecdsa_key_.get()) != 1) {
      return false;
    }

    EVP_DigestUpdate(md_ctx.get(), ChannelIDVerifier::kContextStr,
                     strlen(ChannelIDVerifier::kContextStr) + 1);
    EVP_DigestUpdate(md_ctx.get(), ChannelIDVerifier::kClientToServerStr,
                     strlen(ChannelIDVerifier::kClientToServerStr) + 1);
    EVP_DigestUpdate(md_ctx.get(), signed_data.data(), signed_data.size());

    size_t sig_len;
    if (!EVP_DigestSignFinal(md_ctx.get(), nullptr, &sig_len)) {
      return false;
    }

    std::unique_ptr<uint8_t[]> der_sig(new uint8_t[sig_len]);
    if (!EVP_DigestSignFinal(md_ctx.get(), der_sig.get(), &sig_len)) {
      return false;
    }

    uint8_t* derp = der_sig.get();
    crypto::ScopedECDSA_SIG sig(
        d2i_ECDSA_SIG(nullptr, const_cast<const uint8_t**>(&derp), sig_len));
    if (sig.get() == nullptr) {
      return false;
    }

    // The signature consists of a pair of 32-byte numbers.
    static const size_t kSignatureLength = 32 * 2;
    std::unique_ptr<uint8_t[]> signature(new uint8_t[kSignatureLength]);
    if (!BN_bn2bin_padded(&signature[0], 32, sig->r) ||
        !BN_bn2bin_padded(&signature[32], 32, sig->s)) {
      return false;
    }

    *out_signature =
        string(reinterpret_cast<char*>(signature.get()), kSignatureLength);

    return true;
  }

  string SerializeKey() const override {
    // i2d_PublicKey will produce an ANSI X9.62 public key which, for a P-256
    // key, is 0x04 (meaning uncompressed) followed by the x and y field
    // elements as 32-byte, big-endian numbers.
    static const int kExpectedKeyLength = 65;

    int len = i2d_PublicKey(ecdsa_key_.get(), nullptr);
    if (len != kExpectedKeyLength) {
      return "";
    }

    uint8_t buf[kExpectedKeyLength];
    uint8_t* derp = buf;
    i2d_PublicKey(ecdsa_key_.get(), &derp);

    return string(reinterpret_cast<char*>(buf + 1), kExpectedKeyLength - 1);
  }

 private:
  crypto::ScopedEVP_PKEY ecdsa_key_;
};

class TestChannelIDSource : public ChannelIDSource {
 public:
  ~TestChannelIDSource() override {}

  // ChannelIDSource implementation.

  QuicAsyncStatus GetChannelIDKey(
      const string& hostname,
      std::unique_ptr<ChannelIDKey>* channel_id_key,
      ChannelIDSourceCallback* /*callback*/) override {
    channel_id_key->reset(new TestChannelIDKey(HostnameToKey(hostname)));
    return QUIC_SUCCESS;
  }

 private:
  static EVP_PKEY* HostnameToKey(const string& hostname) {
    // In order to generate a deterministic key for a given hostname the
    // hostname is hashed with SHA-256 and the resulting digest is treated as a
    // big-endian number. The most-significant bit is cleared to ensure that
    // the resulting value is less than the order of the group and then it's
    // taken as a private key. Given the private key, the public key is
    // calculated with a group multiplication.
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, hostname.data(), hostname.size());

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(digest, &sha256);

    // Ensure that the digest is less than the order of the P-256 group by
    // clearing the most-significant bit.
    digest[0] &= 0x7f;

    crypto::ScopedBIGNUM k(BN_new());
    CHECK(BN_bin2bn(digest, sizeof(digest), k.get()) != nullptr);

    crypto::ScopedEC_GROUP p256(
        EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    CHECK(p256);

    crypto::ScopedEC_KEY ecdsa_key(EC_KEY_new());
    CHECK(ecdsa_key && EC_KEY_set_group(ecdsa_key.get(), p256.get()));

    crypto::ScopedEC_POINT point(EC_POINT_new(p256.get()));
    CHECK(EC_POINT_mul(p256.get(), point.get(), k.get(), nullptr, nullptr,
                       nullptr));

    EC_KEY_set_private_key(ecdsa_key.get(), k.get());
    EC_KEY_set_public_key(ecdsa_key.get(), point.get());

    crypto::ScopedEVP_PKEY pkey(EVP_PKEY_new());
    // EVP_PKEY_set1_EC_KEY takes a reference so no |release| here.
    EVP_PKEY_set1_EC_KEY(pkey.get(), ecdsa_key.get());

    return pkey.release();
  }
};

}  // anonymous namespace

CryptoTestUtils::FakeServerOptions::FakeServerOptions()
    : token_binding_enabled(false) {}

CryptoTestUtils::FakeClientOptions::FakeClientOptions()
    : channel_id_enabled(false),
      channel_id_source_async(false),
      token_binding_enabled(false) {}

// static
int CryptoTestUtils::HandshakeWithFakeServer(
    QuicConfig* server_quic_config,
    MockQuicConnectionHelper* helper,
    MockAlarmFactory* alarm_factory,
    PacketSavingConnection* client_conn,
    QuicCryptoClientStream* client,
    const FakeServerOptions& options) {
  PacketSavingConnection* server_conn =
      new PacketSavingConnection(helper, alarm_factory, Perspective::IS_SERVER,
                                 client_conn->supported_versions());

  QuicCryptoServerConfig crypto_config(QuicCryptoServerConfig::TESTING,
                                       QuicRandom::GetInstance(),
                                       ProofSourceForTesting());
  QuicCompressedCertsCache compressed_certs_cache(
      QuicCompressedCertsCache::kQuicCompressedCertsCacheSize);
  SetupCryptoServerConfigForTest(server_conn->clock(),
                                 server_conn->random_generator(),
                                 server_quic_config, &crypto_config, options);

  TestQuicSpdyServerSession server_session(server_conn, *server_quic_config,
                                           &crypto_config,
                                           &compressed_certs_cache);

  // The client's handshake must have been started already.
  CHECK_NE(0u, client_conn->encrypted_packets_.size());

  CommunicateHandshakeMessages(client_conn, client, server_conn,
                               server_session.GetCryptoStream());
  CompareClientAndServerKeys(client, server_session.GetCryptoStream());

  return client->num_sent_client_hellos();
}

// static
int CryptoTestUtils::HandshakeWithFakeClient(
    MockQuicConnectionHelper* helper,
    MockAlarmFactory* alarm_factory,
    PacketSavingConnection* server_conn,
    QuicCryptoServerStream* server,
    const QuicServerId& server_id,
    const FakeClientOptions& options) {
  PacketSavingConnection* client_conn =
      new PacketSavingConnection(helper, alarm_factory, Perspective::IS_CLIENT);
  // Advance the time, because timers do not like uninitialized times.
  client_conn->AdvanceTime(QuicTime::Delta::FromSeconds(1));

  QuicCryptoClientConfig crypto_config(ProofVerifierForTesting());
  AsyncTestChannelIDSource* async_channel_id_source = nullptr;
  if (options.channel_id_enabled) {
    ChannelIDSource* source = ChannelIDSourceForTesting();
    if (options.channel_id_source_async) {
      async_channel_id_source = new AsyncTestChannelIDSource(source);
      source = async_channel_id_source;
    }
    crypto_config.SetChannelIDSource(source);
  }
  if (options.token_binding_enabled) {
    crypto_config.tb_key_params.push_back(kP256);
  }
  TestQuicSpdyClientSession client_session(client_conn, DefaultQuicConfig(),
                                           server_id, &crypto_config);

  EXPECT_CALL(client_session, OnProofValid(testing::_))
      .Times(testing::AnyNumber());
  client_session.GetCryptoStream()->CryptoConnect();
  CHECK_EQ(1u, client_conn->encrypted_packets_.size());

  CommunicateHandshakeMessagesAndRunCallbacks(
      client_conn, client_session.GetCryptoStream(), server_conn, server,
      async_channel_id_source);

  CompareClientAndServerKeys(client_session.GetCryptoStream(), server);

  if (options.channel_id_enabled) {
    std::unique_ptr<ChannelIDKey> channel_id_key;
    QuicAsyncStatus status = crypto_config.channel_id_source()->GetChannelIDKey(
        server_id.host(), &channel_id_key, nullptr);
    EXPECT_EQ(QUIC_SUCCESS, status);
    EXPECT_EQ(channel_id_key->SerializeKey(),
              server->crypto_negotiated_params().channel_id);
    EXPECT_EQ(
        options.channel_id_source_async,
        client_session.GetCryptoStream()->WasChannelIDSourceCallbackRun());
  }

  return client_session.GetCryptoStream()->num_sent_client_hellos();
}

// static
void CryptoTestUtils::SetupCryptoServerConfigForTest(
    const QuicClock* clock,
    QuicRandom* rand,
    QuicConfig* config,
    QuicCryptoServerConfig* crypto_config,
    const FakeServerOptions& fake_options) {
  QuicCryptoServerConfig::ConfigOptions options;
  options.channel_id_enabled = true;
  options.token_binding_enabled = fake_options.token_binding_enabled;
  std::unique_ptr<CryptoHandshakeMessage> scfg(
      crypto_config->AddDefaultConfig(rand, clock, options));
}

// static
void CryptoTestUtils::CommunicateHandshakeMessages(
    PacketSavingConnection* client_conn,
    QuicCryptoStream* client,
    PacketSavingConnection* server_conn,
    QuicCryptoStream* server) {
  CommunicateHandshakeMessagesAndRunCallbacks(client_conn, client, server_conn,
                                              server, nullptr);
}

// static
void CryptoTestUtils::CommunicateHandshakeMessagesAndRunCallbacks(
    PacketSavingConnection* client_conn,
    QuicCryptoStream* client,
    PacketSavingConnection* server_conn,
    QuicCryptoStream* server,
    CallbackSource* callback_source) {
  size_t client_i = 0, server_i = 0;
  while (!client->handshake_confirmed()) {
    ASSERT_GT(client_conn->encrypted_packets_.size(), client_i);
    VLOG(1) << "Processing "
            << client_conn->encrypted_packets_.size() - client_i
            << " packets client->server";
    MovePackets(client_conn, &client_i, server, server_conn,
                Perspective::IS_SERVER);
    if (callback_source) {
      callback_source->RunPendingCallbacks();
    }

    ASSERT_GT(server_conn->encrypted_packets_.size(), server_i);
    VLOG(1) << "Processing "
            << server_conn->encrypted_packets_.size() - server_i
            << " packets server->client";
    MovePackets(server_conn, &server_i, client, client_conn,
                Perspective::IS_CLIENT);
    if (callback_source) {
      callback_source->RunPendingCallbacks();
    }
  }
}

// static
pair<size_t, size_t> CryptoTestUtils::AdvanceHandshake(
    PacketSavingConnection* client_conn,
    QuicCryptoStream* client,
    size_t client_i,
    PacketSavingConnection* server_conn,
    QuicCryptoStream* server,
    size_t server_i) {
  VLOG(1) << "Processing " << client_conn->encrypted_packets_.size() - client_i
          << " packets client->server";
  MovePackets(client_conn, &client_i, server, server_conn,
              Perspective::IS_SERVER);

  VLOG(1) << "Processing " << server_conn->encrypted_packets_.size() - server_i
          << " packets server->client";
  if (server_conn->encrypted_packets_.size() - server_i == 2) {
    VLOG(1) << "here";
  }
  MovePackets(server_conn, &server_i, client, client_conn,
              Perspective::IS_CLIENT);

  return std::make_pair(client_i, server_i);
}

// static
string CryptoTestUtils::GetValueForTag(const CryptoHandshakeMessage& message,
                                       QuicTag tag) {
  QuicTagValueMap::const_iterator it = message.tag_value_map().find(tag);
  if (it == message.tag_value_map().end()) {
    return string();
  }
  return it->second;
}

uint64_t CryptoTestUtils::LeafCertHashForTesting() {
  scoped_refptr<ProofSource::Chain> chain;
  IPAddress server_ip;
  string sig;
  string cert_sct;
  std::unique_ptr<ProofSource> proof_source(
      CryptoTestUtils::ProofSourceForTesting());
  if (!proof_source->GetProof(server_ip, "", "",
                              QuicSupportedVersions().front(), "", false,
                              &chain, &sig, &cert_sct) ||
      chain->certs.empty()) {
    DCHECK(false) << "Proof generation failed";
    return 0;
  }

  return QuicUtils::FNV1a_64_Hash(chain->certs.at(0).c_str(),
                                  chain->certs.at(0).length());
}

class MockCommonCertSets : public CommonCertSets {
 public:
  MockCommonCertSets(StringPiece cert, uint64_t hash, uint32_t index)
      : cert_(cert.as_string()), hash_(hash), index_(index) {}

  StringPiece GetCommonHashes() const override {
    CHECK(false) << "not implemented";
    return StringPiece();
  }

  StringPiece GetCert(uint64_t hash, uint32_t index) const override {
    if (hash == hash_ && index == index_) {
      return cert_;
    }
    return StringPiece();
  }

  bool MatchCert(StringPiece cert,
                 StringPiece common_set_hashes,
                 uint64_t* out_hash,
                 uint32_t* out_index) const override {
    if (cert != cert_) {
      return false;
    }

    if (common_set_hashes.size() % sizeof(uint64_t) != 0) {
      return false;
    }
    bool client_has_set = false;
    for (size_t i = 0; i < common_set_hashes.size(); i += sizeof(uint64_t)) {
      uint64_t hash;
      memcpy(&hash, common_set_hashes.data() + i, sizeof(hash));
      if (hash == hash_) {
        client_has_set = true;
        break;
      }
    }

    if (!client_has_set) {
      return false;
    }

    *out_hash = hash_;
    *out_index = index_;
    return true;
  }

 private:
  const string cert_;
  const uint64_t hash_;
  const uint32_t index_;
};

CommonCertSets* CryptoTestUtils::MockCommonCertSets(StringPiece cert,
                                                    uint64_t hash,
                                                    uint32_t index) {
  return new class MockCommonCertSets(cert, hash, index);
}

// static
void CryptoTestUtils::FillInDummyReject(CryptoHandshakeMessage* rej,
                                        bool reject_is_stateless) {
  if (reject_is_stateless) {
    rej->set_tag(kSREJ);
  } else {
    rej->set_tag(kREJ);
  }

  // Minimum SCFG that passes config validation checks.
  // clang-format off
  unsigned char scfg[] = {
    // SCFG
    0x53, 0x43, 0x46, 0x47,
    // num entries
    0x01, 0x00,
    // padding
    0x00, 0x00,
    // EXPY
    0x45, 0x58, 0x50, 0x59,
    // EXPY end offset
    0x08, 0x00, 0x00, 0x00,
    // Value
    '1',  '2',  '3',  '4',
    '5',  '6',  '7',  '8'
  };
  // clang-format on
  rej->SetValue(kSCFG, scfg);
  rej->SetStringPiece(kServerNonceTag, "SERVER_NONCE");
  vector<QuicTag> reject_reasons;
  reject_reasons.push_back(CLIENT_NONCE_INVALID_FAILURE);
  rej->SetVector(kRREJ, reject_reasons);
}

void CryptoTestUtils::CompareClientAndServerKeys(
    QuicCryptoClientStream* client,
    QuicCryptoServerStream* server) {
  QuicFramer* client_framer =
      QuicConnectionPeer::GetFramer(client->session()->connection());
  QuicFramer* server_framer =
      QuicConnectionPeer::GetFramer(server->session()->connection());
  const QuicEncrypter* client_encrypter(
      QuicFramerPeer::GetEncrypter(client_framer, ENCRYPTION_INITIAL));
  const QuicDecrypter* client_decrypter(
      client->session()->connection()->decrypter());
  const QuicEncrypter* client_forward_secure_encrypter(
      QuicFramerPeer::GetEncrypter(client_framer, ENCRYPTION_FORWARD_SECURE));
  const QuicDecrypter* client_forward_secure_decrypter(
      client->session()->connection()->alternative_decrypter());
  const QuicEncrypter* server_encrypter(
      QuicFramerPeer::GetEncrypter(server_framer, ENCRYPTION_INITIAL));
  const QuicDecrypter* server_decrypter(
      server->session()->connection()->decrypter());
  const QuicEncrypter* server_forward_secure_encrypter(
      QuicFramerPeer::GetEncrypter(server_framer, ENCRYPTION_FORWARD_SECURE));
  const QuicDecrypter* server_forward_secure_decrypter(
      server->session()->connection()->alternative_decrypter());

  StringPiece client_encrypter_key = client_encrypter->GetKey();
  StringPiece client_encrypter_iv = client_encrypter->GetNoncePrefix();
  StringPiece client_decrypter_key = client_decrypter->GetKey();
  StringPiece client_decrypter_iv = client_decrypter->GetNoncePrefix();
  StringPiece client_forward_secure_encrypter_key =
      client_forward_secure_encrypter->GetKey();
  StringPiece client_forward_secure_encrypter_iv =
      client_forward_secure_encrypter->GetNoncePrefix();
  StringPiece client_forward_secure_decrypter_key =
      client_forward_secure_decrypter->GetKey();
  StringPiece client_forward_secure_decrypter_iv =
      client_forward_secure_decrypter->GetNoncePrefix();
  StringPiece server_encrypter_key = server_encrypter->GetKey();
  StringPiece server_encrypter_iv = server_encrypter->GetNoncePrefix();
  StringPiece server_decrypter_key = server_decrypter->GetKey();
  StringPiece server_decrypter_iv = server_decrypter->GetNoncePrefix();
  StringPiece server_forward_secure_encrypter_key =
      server_forward_secure_encrypter->GetKey();
  StringPiece server_forward_secure_encrypter_iv =
      server_forward_secure_encrypter->GetNoncePrefix();
  StringPiece server_forward_secure_decrypter_key =
      server_forward_secure_decrypter->GetKey();
  StringPiece server_forward_secure_decrypter_iv =
      server_forward_secure_decrypter->GetNoncePrefix();

  StringPiece client_subkey_secret =
      client->crypto_negotiated_params().subkey_secret;
  StringPiece server_subkey_secret =
      server->crypto_negotiated_params().subkey_secret;

  const char kSampleLabel[] = "label";
  const char kSampleContext[] = "context";
  const size_t kSampleOutputLength = 32;
  string client_key_extraction;
  string server_key_extraction;
  string client_tb_ekm;
  string server_tb_ekm;
  EXPECT_TRUE(client->ExportKeyingMaterial(kSampleLabel, kSampleContext,
                                           kSampleOutputLength,
                                           &client_key_extraction));
  EXPECT_TRUE(server->ExportKeyingMaterial(kSampleLabel, kSampleContext,
                                           kSampleOutputLength,
                                           &server_key_extraction));
  EXPECT_TRUE(client->ExportTokenBindingKeyingMaterial(&client_tb_ekm));
  EXPECT_TRUE(server->ExportTokenBindingKeyingMaterial(&server_tb_ekm));

  CompareCharArraysWithHexError("client write key", client_encrypter_key.data(),
                                client_encrypter_key.length(),
                                server_decrypter_key.data(),
                                server_decrypter_key.length());
  CompareCharArraysWithHexError("client write IV", client_encrypter_iv.data(),
                                client_encrypter_iv.length(),
                                server_decrypter_iv.data(),
                                server_decrypter_iv.length());
  CompareCharArraysWithHexError("server write key", server_encrypter_key.data(),
                                server_encrypter_key.length(),
                                client_decrypter_key.data(),
                                client_decrypter_key.length());
  CompareCharArraysWithHexError("server write IV", server_encrypter_iv.data(),
                                server_encrypter_iv.length(),
                                client_decrypter_iv.data(),
                                client_decrypter_iv.length());
  CompareCharArraysWithHexError("client forward secure write key",
                                client_forward_secure_encrypter_key.data(),
                                client_forward_secure_encrypter_key.length(),
                                server_forward_secure_decrypter_key.data(),
                                server_forward_secure_decrypter_key.length());
  CompareCharArraysWithHexError("client forward secure write IV",
                                client_forward_secure_encrypter_iv.data(),
                                client_forward_secure_encrypter_iv.length(),
                                server_forward_secure_decrypter_iv.data(),
                                server_forward_secure_decrypter_iv.length());
  CompareCharArraysWithHexError("server forward secure write key",
                                server_forward_secure_encrypter_key.data(),
                                server_forward_secure_encrypter_key.length(),
                                client_forward_secure_decrypter_key.data(),
                                client_forward_secure_decrypter_key.length());
  CompareCharArraysWithHexError("server forward secure write IV",
                                server_forward_secure_encrypter_iv.data(),
                                server_forward_secure_encrypter_iv.length(),
                                client_forward_secure_decrypter_iv.data(),
                                client_forward_secure_decrypter_iv.length());
  CompareCharArraysWithHexError("subkey secret", client_subkey_secret.data(),
                                client_subkey_secret.length(),
                                server_subkey_secret.data(),
                                server_subkey_secret.length());
  CompareCharArraysWithHexError(
      "sample key extraction", client_key_extraction.data(),
      client_key_extraction.length(), server_key_extraction.data(),
      server_key_extraction.length());

  CompareCharArraysWithHexError("token binding key extraction",
                                client_tb_ekm.data(), client_tb_ekm.length(),
                                server_tb_ekm.data(), server_tb_ekm.length());
}

// static
QuicTag CryptoTestUtils::ParseTag(const char* tagstr) {
  const size_t len = strlen(tagstr);
  CHECK_NE(0u, len);

  QuicTag tag = 0;

  if (tagstr[0] == '#') {
    CHECK_EQ(static_cast<size_t>(1 + 2 * 4), len);
    tagstr++;

    for (size_t i = 0; i < 8; i++) {
      tag <<= 4;

      uint8_t v = 0;
      CHECK(HexChar(tagstr[i], &v));
      tag |= v;
    }

    return tag;
  }

  CHECK_LE(len, 4u);
  for (size_t i = 0; i < 4; i++) {
    tag >>= 8;
    if (i < len) {
      tag |= static_cast<uint32_t>(tagstr[i]) << 24;
    }
  }

  return tag;
}

// static
CryptoHandshakeMessage CryptoTestUtils::Message(const char* message_tag, ...) {
  va_list ap;
  va_start(ap, message_tag);

  CryptoHandshakeMessage msg;
  msg.set_tag(ParseTag(message_tag));

  for (;;) {
    const char* tagstr = va_arg(ap, const char*);
    if (tagstr == nullptr) {
      break;
    }

    if (tagstr[0] == '$') {
      // Special value.
      const char* const special = tagstr + 1;
      if (strcmp(special, "padding") == 0) {
        const int min_bytes = va_arg(ap, int);
        msg.set_minimum_size(min_bytes);
      } else {
        CHECK(false) << "Unknown special value: " << special;
      }

      continue;
    }

    const QuicTag tag = ParseTag(tagstr);
    const char* valuestr = va_arg(ap, const char*);

    size_t len = strlen(valuestr);
    if (len > 0 && valuestr[0] == '#') {
      valuestr++;
      len--;

      CHECK_EQ(0u, len % 2);
      std::unique_ptr<uint8_t[]> buf(new uint8_t[len / 2]);

      for (size_t i = 0; i < len / 2; i++) {
        uint8_t v = 0;
        CHECK(HexChar(valuestr[i * 2], &v));
        buf[i] = v << 4;
        CHECK(HexChar(valuestr[i * 2 + 1], &v));
        buf[i] |= v;
      }

      msg.SetStringPiece(
          tag, StringPiece(reinterpret_cast<char*>(buf.get()), len / 2));
      continue;
    }

    msg.SetStringPiece(tag, valuestr);
  }

  // The CryptoHandshakeMessage needs to be serialized and parsed to ensure
  // that any padding is included.
  std::unique_ptr<QuicData> bytes(CryptoFramer::ConstructHandshakeMessage(msg));
  std::unique_ptr<CryptoHandshakeMessage> parsed(
      CryptoFramer::ParseMessage(bytes->AsStringPiece()));
  CHECK(parsed.get());

  va_end(ap);
  return *parsed;
}

// static
ChannelIDSource* CryptoTestUtils::ChannelIDSourceForTesting() {
  return new TestChannelIDSource();
}

// static
void CryptoTestUtils::MovePackets(PacketSavingConnection* source_conn,
                                  size_t* inout_packet_index,
                                  QuicCryptoStream* dest_stream,
                                  PacketSavingConnection* dest_conn,
                                  Perspective dest_perspective) {
  SimpleQuicFramer framer(source_conn->supported_versions(), dest_perspective);
  CryptoFramer crypto_framer;
  CryptoFramerVisitor crypto_visitor;

  // In order to properly test the code we need to perform encryption and
  // decryption so that the crypters latch when expected. The crypters are in
  // |dest_conn|, but we don't want to try and use them there. Instead we swap
  // them into |framer|, perform the decryption with them, and then swap ther
  // back.
  QuicConnectionPeer::SwapCrypters(dest_conn, framer.framer());

  crypto_framer.set_visitor(&crypto_visitor);

  size_t index = *inout_packet_index;
  for (; index < source_conn->encrypted_packets_.size(); index++) {
    if (!framer.ProcessPacket(*source_conn->encrypted_packets_[index])) {
      // The framer will be unable to decrypt forward-secure packets sent after
      // the handshake is complete. Don't treat them as handshake packets.
      break;
    }

    for (const QuicStreamFrame* stream_frame : framer.stream_frames()) {
      ASSERT_TRUE(crypto_framer.ProcessInput(
          StringPiece(stream_frame->data_buffer, stream_frame->data_length)));
      ASSERT_FALSE(crypto_visitor.error());
    }
  }
  *inout_packet_index = index;

  QuicConnectionPeer::SwapCrypters(dest_conn, framer.framer());

  ASSERT_EQ(0u, crypto_framer.InputBytesRemaining());

  for (const CryptoHandshakeMessage& message : crypto_visitor.messages()) {
    dest_stream->OnHandshakeMessage(message);
  }
}

}  // namespace test
}  // namespace net
