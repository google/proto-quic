// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TEST_SPAWNED_TEST_SERVER_SPAWNER_COMMUNICATOR_H_
#define NET_TEST_SPAWNED_TEST_SERVER_SPAWNER_COMMUNICATOR_H_

#include <stdint.h>

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "net/url_request/url_request.h"

namespace net {

class ScopedPortException;

// SpawnerCommunicator communicates with a spawner server that runs on a
// remote system.
//
// The test server used by unit tests is written in Python. However, Android
// does not support running Python code, so the test server cannot run on the
// same device running unit tests.
//
// The actual test server is executed on the host machine, while the unit tests
// themselves continue running on the device. To control the test server on the
// host machine, a second HTTP server is started, the spawner server, which
// controls the life cycle of remote test servers. Calls to start/kill the
// SpawnedTestServer are then redirected to the spawner server via
// this spawner communicator.
//
// Currently only three commands are supported by spawner.
//
// (1) Start Python test server, format is:
// Path: "/start".
// Method: "POST".
// Data to server: all arguments needed to launch the Python test server, in
//   JSON format.
// Data from server: a JSON dict includes the following two field if success,
//   "port": the port the Python test server actually listen on that.
//   "message": must be "started".
//
// (2) Kill Python test server, format is:
// Path: "/kill".
// Method: "GET".
// Data to server: None.
// Data from server: String "killed" returned if success.
//
// (3) Ping Python test server to see whether it is alive, format is:
// Path: "/ping".
// Method: "GET".
// Data to server: None.
// Data from server: String "ready" returned if success.
//
// The internal I/O thread is required by net stack to perform net I/O.
// The Start/StopServer methods block the caller thread until result is
// fetched from spawner server or timed-out.
class SpawnerCommunicator : public URLRequest::Delegate {
 public:
  explicit SpawnerCommunicator(uint16_t port);
  ~SpawnerCommunicator() override;

  // Starts an instance of the Python test server on the host/ machine.
  // If successfully started, returns true, setting |*port| to the port
  // on the local machine that can be used to communicate with the remote
  // test server.
  bool StartServer(const std::string& arguments,
                   uint16_t* port) WARN_UNUSED_RESULT;

  bool StopServer() WARN_UNUSED_RESULT;

 private:
  // Starts the IO thread. Called on the user thread.
  void StartIOThread();

  // Shuts down the remote test server spawner. Called on the user thread.
  void Shutdown();

  // Waits for the server response on IO thread. Called on the user thread.
  void WaitForResponse();

  // Sends a command to the test server over HTTP, returning the result code
  // |*result_code| and response data in |*data_received|, those two arguments
  // must be not NULL, otherwise the method returns immediately without sending
  // the |command|. If |post_data| is empty, HTTP GET will be used to send
  // |command|. If |post_data| is non-empty, performs an HTTP POST.
  // This method is called on the user thread.
  void SendCommandAndWaitForResult(const std::string& command,
                                   const std::string& post_data,
                                   int* result_code,
                                   std::string* data_received);

  // Performs the command sending on the IO thread. Called on the IO thread.
  void SendCommandAndWaitForResultOnIOThread(const std::string& command,
                                             const std::string& post_data,
                                             int* result_code,
                                             std::string* data_received);

  // URLRequest::Delegate methods. Called on the IO thread.
  void OnResponseStarted(URLRequest* request, int net_error) override;
  void OnReadCompleted(URLRequest* request, int num_bytes) override;

  // Reads Result from the response. Called on the IO thread.
  void ReadResult(URLRequest* request);

  // Called on the IO thread upon completion of the spawner command.
  void OnSpawnerCommandCompleted(URLRequest* request, int net_error);

  // Callback on the IO thread for time-out task of request with id |id|.
  void OnTimeout(int id);

  // A thread to communicate with test_spawner server.
  base::Thread io_thread_;

  // WaitableEvent to notify whether the communication is done.
  base::WaitableEvent event_;

  // The local port used to communicate with the TestServer spawner. This is
  // used to control the startup and shutdown of the Python TestServer running
  // on the remote machine. On Android, this port will be redirected to the
  // same port on the host machine.
  const uint16_t port_;

  // Helper to add |port_| to the list of the globally explicitly allowed ports.
  std::unique_ptr<ScopedPortException> allowed_port_;

  // The next ID to use for |cur_request_| (monotonically increasing).
  int next_id_;

  // Request context used by |cur_request_|.
  std::unique_ptr<URLRequestContext> context_;

  // The current (in progress) request, or NULL.
  std::unique_ptr<URLRequest> cur_request_;

  // Only gets/sets |is_running_| on user's thread to avoid race-condition.
  bool is_running_;

  // Factory for creating the time-out task. This takes care of revoking
  // outstanding tasks when |this| is deleted.
  base::WeakPtrFactory<SpawnerCommunicator> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(SpawnerCommunicator);
};

}  // namespace net

#endif  // NET_TEST_SPAWNED_TEST_SERVER_SPAWNER_COMMUNICATOR_H_
