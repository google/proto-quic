// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TEST_EMBEDDED_TEST_SERVER_EMBEDDED_TEST_SERVER_CONNECTION_LISTENER_H_
#define NET_TEST_EMBEDDED_TEST_SERVER_EMBEDDED_TEST_SERVER_CONNECTION_LISTENER_H_

namespace net {

class StreamSocket;

namespace test_server {

// An interface for connection event notifications.
class EmbeddedTestServerConnectionListener {
 public:
  // Notified when a socket was accepted by the EmbeddedTestServer.
  virtual void AcceptedSocket(const StreamSocket& socket) = 0;

  // Notified when a socket was read from by the EmbeddedTestServer.
  virtual void ReadFromSocket(const StreamSocket& socket, int rv) = 0;

 protected:
  EmbeddedTestServerConnectionListener() {}

  virtual ~EmbeddedTestServerConnectionListener() {}
};

}  // test_server
}  // net

#endif  // NET_TEST_EMBEDDED_TEST_SERVER_EMBEDDED_TEST_SERVER_CONNECTION_LISTENER_H_
