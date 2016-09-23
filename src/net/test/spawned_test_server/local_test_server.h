// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TEST_SPAWNED_TEST_SERVER_LOCAL_TEST_SERVER_H_
#define NET_TEST_SPAWNED_TEST_SERVER_LOCAL_TEST_SERVER_H_

#include <string>

#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/macros.h"
#include "base/process/process.h"
#include "net/test/spawned_test_server/base_test_server.h"

#if defined(OS_WIN)
#include "base/win/scoped_handle.h"
#endif

namespace base {
class CommandLine;
}

namespace net {

// The LocalTestServer runs an external Python-based test server in the
// same machine in which the LocalTestServer runs.
class LocalTestServer : public BaseTestServer {
 public:
  // Initialize a TestServer listening on a specific host (IP or hostname).
  // |document_root| must be a relative path under the root tree.
  LocalTestServer(Type type,
                  const std::string& host,
                  const base::FilePath& document_root);

  // Initialize a TestServer with a specific set of SSLOptions.
  // |document_root| must be a relative path under the root tree.
  LocalTestServer(Type type,
                  const SSLOptions& ssl_options,
                  const base::FilePath& document_root);

  ~LocalTestServer() override;

  // Start the test server and block until it's ready. Returns true on success.
  bool Start() WARN_UNUSED_RESULT;

  // Start the test server without blocking. Use this if you need multiple test
  // servers (such as WebSockets and HTTP, or HTTP and HTTPS). You must call
  // BlockUntilStarted on all servers your test requires before executing the
  // test. For example:
  //
  //   // Start the servers in parallel.
  //   ASSERT_TRUE(http_server.StartInBackground());
  //   ASSERT_TRUE(websocket_server.StartInBackground());
  //   // Wait for both servers to be ready.
  //   ASSERT_TRUE(http_server.BlockUntilStarted());
  //   ASSERT_TRUE(websocket_server.BlockUntilStarted());
  //   RunMyTest();
  //
  // Returns true on success.
  bool StartInBackground() WARN_UNUSED_RESULT;

  // Block until ths test server is ready. Returns true on success. See
  // StartInBackground() documentation for more information.
  bool BlockUntilStarted() WARN_UNUSED_RESULT;

  // Stop the server started by Start().
  bool Stop();

  // Modify PYTHONPATH to contain libraries we need.
  virtual bool SetPythonPath() const WARN_UNUSED_RESULT;

  // Returns true if the base::FilePath for the testserver python script is
  // successfully stored  in |*testserver_path|.
  virtual bool GetTestServerPath(base::FilePath* testserver_path) const
      WARN_UNUSED_RESULT;

  // Adds the command line arguments for the Python test server to
  // |command_line|. Returns true on success.
  virtual bool AddCommandLineArguments(base::CommandLine* command_line) const
      WARN_UNUSED_RESULT;

  // Returns the actual path of document root for test cases. This function
  // should be called by test cases to retrieve the actual document root path.
  base::FilePath GetDocumentRoot() const { return document_root(); };

 private:
  bool Init(const base::FilePath& document_root);

  // Launches the Python test server. Returns true on success.
  bool LaunchPython(const base::FilePath& testserver_path) WARN_UNUSED_RESULT;

  // Waits for the server to start. Returns true on success.
  bool WaitToStart() WARN_UNUSED_RESULT;

  // The Python process running the test server.
  base::Process process_;

#if defined(OS_WIN)
  // The pipe file handle we read from.
  base::win::ScopedHandle child_read_fd_;

  // The pipe file handle the child and we write to.
  base::win::ScopedHandle child_write_fd_;
#endif

#if defined(OS_POSIX)
  // The file descriptor the child writes to when it starts.
  base::ScopedFD child_fd_;
#endif

  DISALLOW_COPY_AND_ASSIGN(LocalTestServer);
};

}  // namespace net

#endif  // NET_TEST_SPAWNED_TEST_SERVER_LOCAL_TEST_SERVER_H_
