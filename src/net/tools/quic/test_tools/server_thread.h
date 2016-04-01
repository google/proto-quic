// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_QUIC_TEST_TOOLS_SERVER_THREAD_H_
#define NET_TOOLS_QUIC_TEST_TOOLS_SERVER_THREAD_H_

#include "base/macros.h"
#include "base/threading/simple_thread.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/quic_config.h"
#include "net/tools/quic/quic_server.h"

namespace net {
namespace test {

// Simple wrapper class to run QuicServer in a dedicated thread.
class ServerThread : public base::SimpleThread {
 public:
  ServerThread(QuicServer* server,
               const IPEndPoint& address,
               bool strike_register_no_startup_period);

  ~ServerThread() override;

  // Prepares the server, but does not start accepting connections. Useful for
  // injecting mocks.
  void Initialize();

  // Runs the event loop. Will initialize if necessary.
  void Run() override;

  // Waits for the handshake to be confirmed for the first session created.
  void WaitForCryptoHandshakeConfirmed();

  // Pauses execution of the server until Resume() is called.  May only be
  // called once.
  void Pause();

  // Resumes execution of the server after Pause() has been called.  May only
  // be called once.
  void Resume();

  // Stops the server from executing and shuts it down, destroying all
  // server objects.
  void Quit();

  // Returns the underlying server.  Care must be taken to avoid data races
  // when accessing the server.  It is always safe to access the server
  // after calling Pause() and before calling Resume().
  QuicServer* server() { return server_.get(); }

  // Returns the port that the server is listening on.
  int GetPort();

 private:
  void MaybeNotifyOfHandshakeConfirmation();

  base::WaitableEvent confirmed_;  // Notified when the first handshake is
                                   // confirmed.
  base::WaitableEvent pause_;      // Notified when the server should pause.
  base::WaitableEvent paused_;     // Notitied when the server has paused
  base::WaitableEvent resume_;     // Notified when the server should resume.
  base::WaitableEvent quit_;       // Notified when the server should quit.

  scoped_ptr<QuicServer> server_;
  IPEndPoint address_;
  base::Lock port_lock_;
  int port_;

  bool initialized_;

  DISALLOW_COPY_AND_ASSIGN(ServerThread);
};

}  // namespace test
}  // namespace net

#endif  // NET_TOOLS_QUIC_TEST_TOOLS_SERVER_THREAD_H_
