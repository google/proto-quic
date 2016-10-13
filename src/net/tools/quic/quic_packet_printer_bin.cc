// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// clang-format off

// Dumps out the decryptable contents of a QUIC packet in a human-readable way.
// If the packet is null encrypted, this will dump full packet contents.
// Otherwise it will dump the public header, and fail with an error that the
// packet is undecryptable.
//
// Usage: quic_packet_printer server|client <hex dump of packet>
//
// Example input:
// quic_packet_printer server 0c6b810308320f24c004a939a38a2e3fd6ca589917f200400
// 201b80b0100501c0700060003023d0000001c00556e656e637279707465642073747265616d2
// 064617461207365656e
//
// Example output:
// OnPacket
// OnUnauthenticatedPublicHeader
// OnUnauthenticatedHeader: { connection_id: 13845207862000976235,
// connection_id_length:8, packet_number_length:1, multipath_flag: 0,
// reset_flag: 0, version_flag: 0, entropy_flag: 0, entropy hash: 0, path_id: ,
// packet_number: 4}
// OnDecryptedPacket
// OnPacketHeader
// OnAckFrame:  entropy_hash: 2 largest_observed: 1 ack_delay_time: 3000
// missing_packets: [  ] is_truncated: 0 received_packets: [ 1 at 466016  ]
// OnStopWaitingFrame
// OnConnectionCloseFrame: error_code { 61 } error_details { Unencrypted stream
// data seen }

// clang-format on

#include <iostream>
#include <string>

#include "base/command_line.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "net/quic/core/quic_framer.h"
#include "net/quic/core/quic_utils.h"

using std::cerr;
using std::string;

// If set, specify the QUIC version to use.
string FLAGS_quic_version = "";

namespace {

string ArgToString(base::CommandLine::StringType arg) {
#if defined(OS_WIN)
  return base::UTF16ToASCII(arg);
#else
  return arg;
#endif
}
}

namespace net {

class QuicPacketPrinter : public QuicFramerVisitorInterface {
 public:
  explicit QuicPacketPrinter(QuicFramer* framer) : framer_(framer) {}

  void OnError(QuicFramer* framer) override {
    cerr << "OnError: " << QuicUtils::ErrorToString(framer->error())
         << " detail: " << framer->detailed_error() << "\n";
  }
  bool OnProtocolVersionMismatch(QuicVersion received_version) override {
    framer_->set_version(received_version);
    cerr << "OnProtocolVersionMismatch: "
         << QuicVersionToString(received_version) << "\n";
    return true;
  }
  void OnPacket() override { cerr << "OnPacket\n"; }
  void OnPublicResetPacket(const QuicPublicResetPacket& packet) override {
    cerr << "OnPublicResetPacket\n";
  }
  void OnVersionNegotiationPacket(
      const QuicVersionNegotiationPacket& packet) override {
    cerr << "OnVersionNegotiationPacket\n";
  }
  bool OnUnauthenticatedPublicHeader(
      const QuicPacketPublicHeader& header) override {
    cerr << "OnUnauthenticatedPublicHeader\n";
    return true;
  }
  bool OnUnauthenticatedHeader(const QuicPacketHeader& header) override {
    cerr << "OnUnauthenticatedHeader: " << header;
    return true;
  }
  void OnDecryptedPacket(EncryptionLevel level) override {
    // This only currently supports "decrypting" null encrypted packets.
    DCHECK_EQ(ENCRYPTION_NONE, level);
    cerr << "OnDecryptedPacket\n";
  }
  bool OnPacketHeader(const QuicPacketHeader& header) override {
    cerr << "OnPacketHeader\n";
    return true;
  }
  bool OnStreamFrame(const QuicStreamFrame& frame) override {
    cerr << "OnStreamFrame: " << frame;
    cerr << "         data: { "
         << QuicUtils::HexEncode(frame.data_buffer, frame.data_length)
         << " }\n";
    return true;
  }
  bool OnAckFrame(const QuicAckFrame& frame) override {
    cerr << "OnAckFrame: " << frame;
    return true;
  }
  bool OnStopWaitingFrame(const QuicStopWaitingFrame& frame) override {
    cerr << "OnStopWaitingFrame: " << frame;
    return true;
  }
  bool OnPaddingFrame(const QuicPaddingFrame& frame) override {
    cerr << "OnPaddingFrame: " << frame;
    return true;
  }
  bool OnPingFrame(const QuicPingFrame& frame) override {
    cerr << "OnPingFrame\n";
    return true;
  }
  bool OnRstStreamFrame(const QuicRstStreamFrame& frame) override {
    cerr << "OnRstStreamFrame: " << frame;
    return true;
  }
  bool OnConnectionCloseFrame(const QuicConnectionCloseFrame& frame) override {
    cerr << "OnConnectionCloseFrame: " << frame;
    return true;
  }
  bool OnGoAwayFrame(const QuicGoAwayFrame& frame) override {
    cerr << "OnGoAwayFrame: " << frame;
    return true;
  }
  bool OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) override {
    cerr << "OnWindowUpdateFrame: " << frame;
    return true;
  }
  bool OnBlockedFrame(const QuicBlockedFrame& frame) override {
    cerr << "OnBlockedFrame: " << frame;
    return true;
  }
  bool OnPathCloseFrame(const QuicPathCloseFrame& frame) override {
    cerr << "OnPathCloseFrame:" << frame;
    return true;
  }
  void OnPacketComplete() override { cerr << "OnPacketComplete\n"; }

 private:
  QuicFramer* framer_;  // Unowned.
};

}  // namespace net

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* line = base::CommandLine::ForCurrentProcess();
  const base::CommandLine::StringVector& args = line->GetArgs();

  if (args.size() != 3) {
    cerr << "Missing argument " << argc << ". (Usage: " << argv[0]
         << " client|server <hex>\n";
    return 1;
  }

  if (line->HasSwitch("quic_version")) {
    FLAGS_quic_version = line->GetSwitchValueASCII("quic_version");
  }

  string perspective_string = ArgToString(args[0]);
  net::Perspective perspective;
  if (perspective_string == "client") {
    perspective = net::Perspective::IS_CLIENT;
  } else if (perspective_string == "server") {
    perspective = net::Perspective::IS_SERVER;
  } else {
    cerr << "Invalid perspective. " << perspective_string
         << " Usage: " << args[0] << " client|server <hex>\n";
    return 1;
  }
  string hex = net::QuicUtils::HexDecode(ArgToString(args[1]));
  net::QuicVersionVector versions = net::AllSupportedVersions();
  // Fake a time since we're not actually generating acks.
  net::QuicTime start(net::QuicTime::Zero());
  net::QuicFramer framer(versions, start, perspective);
  if (!FLAGS_quic_version.empty()) {
    for (net::QuicVersion version : versions) {
      if (net::QuicVersionToString(version) == FLAGS_quic_version) {
        framer.set_version(version);
      }
    }
  }
  net::QuicPacketPrinter visitor(&framer);
  framer.set_visitor(&visitor);
  net::QuicEncryptedPacket encrypted(hex.c_str(), hex.length());
  return framer.ProcessPacket(encrypted);
}
