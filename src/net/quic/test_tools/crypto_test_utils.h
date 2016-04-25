// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_CRYPTO_TEST_UTILS_H_
#define NET_QUIC_TEST_TOOLS_CRYPTO_TEST_UTILS_H_

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/quic/crypto/crypto_framer.h"
#include "net/quic/quic_framer.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/test_tools/quic_test_utils.h"

namespace net {

class ChannelIDSource;
class CommonCertSets;
class ProofSource;
class ProofVerifier;
class ProofVerifyContext;
class QuicClock;
class QuicConfig;
class QuicCryptoClientStream;
class QuicCryptoServerConfig;
class QuicCryptoServerStream;
class QuicCryptoStream;
class QuicRandom;
class QuicServerId;

namespace test {

class PacketSavingConnection;

class CryptoTestUtils {
 public:
  // An interface for a source of callbacks. This is used for invoking
  // callbacks asynchronously.
  //
  // Call the RunPendingCallbacks method regularly to run the callbacks from
  // this source.
  class CallbackSource {
   public:
    virtual ~CallbackSource() {}

    // Runs pending callbacks from this source. If there is no pending
    // callback, does nothing.
    virtual void RunPendingCallbacks() = 0;
  };

  // FakeServerOptions bundles together a number of options for configuring the
  // server in HandshakeWithFakeServer.
  struct FakeServerOptions {
    FakeServerOptions();

    // If token_binding_enabled is true, then the server will attempt to
    // negotiate Token Binding.
    bool token_binding_enabled;
  };

  // FakeClientOptions bundles together a number of options for configuring
  // HandshakeWithFakeClient.
  struct FakeClientOptions {
    FakeClientOptions();

    // If channel_id_enabled is true then the client will attempt to send a
    // ChannelID.
    bool channel_id_enabled;

    // If channel_id_source_async is true then the client will use an async
    // ChannelIDSource for testing. Ignored if channel_id_enabled is false.
    bool channel_id_source_async;

    // If token_binding_enabled is true, then the client will attempt to
    // negotiate Token Binding.
    bool token_binding_enabled;
  };

  // returns: the number of client hellos that the client sent.
  static int HandshakeWithFakeServer(MockConnectionHelper* helper,
                                     MockAlarmFactory* alarm_factory,
                                     PacketSavingConnection* client_conn,
                                     QuicCryptoClientStream* client,
                                     const FakeServerOptions& options);

  // returns: the number of client hellos that the client sent.
  static int HandshakeWithFakeClient(MockConnectionHelper* helper,

                                     MockAlarmFactory* alarm_factory,

                                     PacketSavingConnection* server_conn,
                                     QuicCryptoServerStream* server,
                                     const QuicServerId& server_id,
                                     const FakeClientOptions& options);

  // SetupCryptoServerConfigForTest configures |config| and |crypto_config|
  // with sensible defaults for testing.
  static void SetupCryptoServerConfigForTest(
      const QuicClock* clock,
      QuicRandom* rand,
      QuicConfig* config,
      QuicCryptoServerConfig* crypto_config,
      const FakeServerOptions& options);

  // CommunicateHandshakeMessages moves messages from |a| to |b| and back until
  // |a|'s handshake has completed.
  static void CommunicateHandshakeMessages(PacketSavingConnection* a_conn,
                                           QuicCryptoStream* a,
                                           PacketSavingConnection* b_conn,
                                           QuicCryptoStream* b);

  // CommunicateHandshakeMessagesAndRunCallbacks moves messages from |a| to |b|
  // and back until |a|'s handshake has completed. If |callback_source| is not
  // nullptr, CommunicateHandshakeMessagesAndRunCallbacks also runs callbacks
  // from
  // |callback_source| between processing messages.
  static void CommunicateHandshakeMessagesAndRunCallbacks(
      PacketSavingConnection* a_conn,
      QuicCryptoStream* a,
      PacketSavingConnection* b_conn,
      QuicCryptoStream* b,
      CallbackSource* callback_source);

  // AdvanceHandshake attempts to moves messages from |a| to |b| and |b| to |a|.
  // Returns the number of messages moved.
  static std::pair<size_t, size_t> AdvanceHandshake(
      PacketSavingConnection* a_conn,
      QuicCryptoStream* a,
      size_t a_i,
      PacketSavingConnection* b_conn,
      QuicCryptoStream* b,
      size_t b_i);

  // Returns the value for the tag |tag| in the tag value map of |message|.
  static std::string GetValueForTag(const CryptoHandshakeMessage& message,
                                    QuicTag tag);

  // Returns a |ProofSource| that serves up test certificates.
  static ProofSource* ProofSourceForTesting();

  // Returns a |ProofVerifier| that uses the QUIC testing root CA.
  static ProofVerifier* ProofVerifierForTesting();

  // Returns a real ProofVerifier (not a fake proof verifier) for testing.
  static ProofVerifier* RealProofVerifierForTesting();

  // Returns a |ProofVerifyContext| that must be used with the verifier
  // returned by |ProofVerifierForTesting|.
  static ProofVerifyContext* ProofVerifyContextForTesting();

  // MockCommonCertSets returns a CommonCertSets that contains a single set with
  // hash |hash|, consisting of the certificate |cert| at index |index|.
  static CommonCertSets* MockCommonCertSets(base::StringPiece cert,
                                            uint64_t hash,
                                            uint32_t index);

  // Creates a minimal dummy reject message that will pass the client-config
  // validation tests. This will include a server config, but no certs, proof
  // source address token, or server nonce.
  static void FillInDummyReject(CryptoHandshakeMessage* rej,
                                bool reject_is_stateless);

  // ParseTag returns a QuicTag from parsing |tagstr|. |tagstr| may either be
  // in the format "EXMP" (i.e. ASCII format), or "#11223344" (an explicit hex
  // format). It CHECK fails if there's a parse error.
  static QuicTag ParseTag(const char* tagstr);

  // Message constructs a handshake message from a variable number of
  // arguments. |message_tag| is passed to |ParseTag| and used as the tag of
  // the resulting message. The arguments are taken in pairs and nullptr
  // terminated. The first of each pair is the tag of a tag/value and is given
  // as an argument to |ParseTag|. The second is the value of the tag/value
  // pair and is either a hex dump, preceeded by a '#', or a raw value.
  //
  //   Message(
  //       "CHLO",
  //       "NOCE", "#11223344",
  //       "SNI", "www.example.com",
  //       nullptr);
  static CryptoHandshakeMessage Message(const char* message_tag, ...);

  // ChannelIDSourceForTesting returns a ChannelIDSource that generates keys
  // deterministically based on the hostname given in the GetChannelIDKey call.
  // This ChannelIDSource works in synchronous mode, i.e., its GetChannelIDKey
  // method never returns QUIC_PENDING.
  static ChannelIDSource* ChannelIDSourceForTesting();

  // MovePackets parses crypto handshake messages from packet number
  // |*inout_packet_index| through to the last packet (or until a packet fails
  // to decrypt) and has |dest_stream| process them. |*inout_packet_index| is
  // updated with an index one greater than the last packet processed.
  static void MovePackets(PacketSavingConnection* source_conn,
                          size_t* inout_packet_index,
                          QuicCryptoStream* dest_stream,
                          PacketSavingConnection* dest_conn);

 private:
  static void CompareClientAndServerKeys(QuicCryptoClientStream* client,
                                         QuicCryptoServerStream* server);

  DISALLOW_COPY_AND_ASSIGN(CryptoTestUtils);
};

}  // namespace test

}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_CRYPTO_TEST_UTILS_H_
