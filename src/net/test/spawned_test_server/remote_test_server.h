// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TEST_SPAWNED_TEST_SERVER_REMOTE_TEST_SERVER_H_
#define NET_TEST_SPAWNED_TEST_SERVER_REMOTE_TEST_SERVER_H_

#include <string>

#include "base/macros.h"
#include "net/test/spawned_test_server/base_test_server.h"

namespace net {

class SpawnerCommunicator;

// The RemoteTestServer runs an external Python-based test server in another
// machine that is different from the machine in which RemoteTestServer runs.
class RemoteTestServer : public BaseTestServer {
 public:
  // Initialize a TestServer listening on a specific host (IP or hostname).
  // |document_root| must be a relative path under the root tree.
  RemoteTestServer(Type type,
                   const std::string& host,
                   const base::FilePath& document_root);

  // Initialize a TestServer with a specific set of SSLOptions.
  // |document_root| must be a relative path under the root tree.
  RemoteTestServer(Type type,
                   const SSLOptions& ssl_options,
                   const base::FilePath& document_root);

  ~RemoteTestServer() override;

  // Starts the Python test server on the host, instead of on the device, and
  // blocks until the server is ready.
  bool Start() WARN_UNUSED_RESULT;

  // These are currently unused and unimplemented for RemoteTestServer. See
  // the same methods in LocalTestServer for more information.
  bool StartInBackground() WARN_UNUSED_RESULT;
  bool BlockUntilStarted() WARN_UNUSED_RESULT;

  // Stops the Python test server that is running on the host machine.
  bool Stop();

  // Returns the actual path of document root for the test cases. This function
  // should be called by test cases to retrieve the actual document root path
  // on the Android device, otherwise document_root() function is used to get
  // the document root.
  base::FilePath GetDocumentRoot() const;

 private:
  bool Init(const base::FilePath& document_root);

  // The local port used to communicate with the TestServer spawner. This is
  // used to control the startup and shutdown of the Python TestServer running
  // on the remote machine. On Android, this port will be redirected to the
  // same port on the host machine.
  int spawner_server_port_;

  // Helper to start and stop instances of the Python test server that runs on
  // the host machine.
  std::unique_ptr<SpawnerCommunicator> spawner_communicator_;

  DISALLOW_COPY_AND_ASSIGN(RemoteTestServer);
};

}  // namespace net

#endif  // NET_TEST_SPAWNED_TEST_SERVER_REMOTE_TEST_SERVER_H_
