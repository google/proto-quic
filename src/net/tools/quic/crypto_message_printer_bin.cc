// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Dumps the contents of a QUIC crypto handshake message in a human readable
// format.
//
// Usage: crypto_message_printer_bin <hex of message>

#include <iostream>

#include "base/command_line.h"
#include "net/quic/core/crypto/crypto_framer.h"
#include "net/quic/platform/api/quic_text_utils.h"

using std::cerr;
using std::cout;
using std::endl;

namespace net {

class CryptoMessagePrinter : public net::CryptoFramerVisitorInterface {
 public:
  void OnHandshakeMessage(const CryptoHandshakeMessage& message) override {
    cout << message.DebugString() << endl;
  }

  void OnError(CryptoFramer* framer) override {
    cerr << "Error code: " << framer->error() << endl;
    cerr << "Error details: " << framer->error_detail() << endl;
  }
};

}  // namespace net

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);

  if (argc != 2) {
    cerr << "Usage: " << argv[0] << " <hex of message>\n";
    return 1;
  }

  net::CryptoMessagePrinter printer;
  net::CryptoFramer framer;
  framer.set_visitor(&printer);
  std::string input = net::QuicTextUtils::HexDecode(argv[1]);
  if (!framer.ProcessInput(input)) {
    return 1;
  }
  if (framer.InputBytesRemaining() != 0) {
    cerr << "Input partially consumed. " << framer.InputBytesRemaining()
         << " bytes remaining." << endl;
    return 2;
  }
  return 0;
}
