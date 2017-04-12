// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/spawned_test_server/remote_test_server.h"

#include <stdint.h>

#include <limits>
#include <vector>

#include "base/base_paths.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/json/json_writer.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/path_service.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/values.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_errors.h"
#include "net/test/spawned_test_server/spawner_communicator.h"
#include "url/gurl.h"

namespace net {

namespace {

// Based on how the Android runner sets things up, it is only valid for one
// RemoteTestServer to be active on the device at a time.
class RemoteTestServerTracker {
 public:
  void StartingServer() {
    base::AutoLock l(lock_);
    CHECK_EQ(count_, 0);
    count_++;
  }

  void StoppingServer() {
    base::AutoLock l(lock_);
    CHECK_EQ(count_, 1);
    count_--;
  }

 private:
  // |lock_| protects access to |count_|.
  base::Lock lock_;
  int count_ = 0;
};

base::LazyInstance<RemoteTestServerTracker>::Leaky tracker =
    LAZY_INSTANCE_INITIALIZER;

// To reduce the running time of tests, tests may be sharded across several
// devices. This means that it may be necessary to support multiple instances
// of the test server spawner and the Python test server simultaneously on the
// same host. Each pair of (test server spawner, Python test server) correspond
// to a single testing device.
// The mapping between the test server spawner and the individual Python test
// servers is written to a file on the device prior to executing any tests.
base::FilePath GetTestServerPortInfoFile() {
#if !defined(OS_ANDROID)
  return base::FilePath("/tmp/net-test-server-ports");
#else
  base::FilePath test_data_dir;
  PathService::Get(base::DIR_ANDROID_EXTERNAL_STORAGE, &test_data_dir);
  return test_data_dir.Append("net-test-server-ports");
#endif
}

// Please keep it sync with dictionary SERVER_TYPES in testserver.py
std::string GetServerTypeString(BaseTestServer::Type type) {
  switch (type) {
    case BaseTestServer::TYPE_FTP:
      return "ftp";
    case BaseTestServer::TYPE_HTTP:
    case BaseTestServer::TYPE_HTTPS:
      return "http";
    case BaseTestServer::TYPE_WS:
    case BaseTestServer::TYPE_WSS:
      return "ws";
    case BaseTestServer::TYPE_TCP_ECHO:
      return "tcpecho";
    case BaseTestServer::TYPE_UDP_ECHO:
      return "udpecho";
    default:
      NOTREACHED();
  }
  return std::string();
}

}  // namespace

RemoteTestServer::RemoteTestServer(Type type,
                                   const std::string& host,
                                   const base::FilePath& document_root)
    : BaseTestServer(type, host),
      spawner_server_port_(0) {
  if (!Init(document_root))
    NOTREACHED();
}

RemoteTestServer::RemoteTestServer(Type type,
                                   const SSLOptions& ssl_options,
                                   const base::FilePath& document_root)
    : BaseTestServer(type, ssl_options),
      spawner_server_port_(0) {
  if (!Init(document_root))
    NOTREACHED();
}

RemoteTestServer::~RemoteTestServer() {
  Stop();
}

bool RemoteTestServer::Start() {
  if (spawner_communicator_.get())
    return true;

  tracker.Get().StartingServer();

  spawner_communicator_.reset(new SpawnerCommunicator(spawner_server_port_));

  base::DictionaryValue arguments_dict;
  if (!GenerateArguments(&arguments_dict))
    return false;

  arguments_dict.Set("on-remote-server", base::MakeUnique<base::Value>());

  // Append the 'server-type' argument which is used by spawner server to
  // pass right server type to Python test server.
  arguments_dict.SetString("server-type", GetServerTypeString(type()));

  // Generate JSON-formatted argument string.
  std::string arguments_string;
  base::JSONWriter::Write(arguments_dict, &arguments_string);
  if (arguments_string.empty())
    return false;

  // Start the Python test server on the remote machine.
  uint16_t test_server_port;
  if (!spawner_communicator_->StartServer(arguments_string,
                                          &test_server_port)) {
    return false;
  }
  if (0 == test_server_port)
    return false;

  // Construct server data to initialize BaseTestServer::server_data_.
  base::DictionaryValue server_data_dict;
  // At this point, the test server should be spawned on the host. Update the
  // local port to real port of Python test server, which will be forwarded to
  // the remote server.
  server_data_dict.SetInteger("port", test_server_port);
  std::string server_data;
  base::JSONWriter::Write(server_data_dict, &server_data);
  if (server_data.empty() || !ParseServerData(server_data)) {
    LOG(ERROR) << "Could not parse server_data: " << server_data;
    return false;
  }

  return SetupWhenServerStarted();
}

bool RemoteTestServer::StartInBackground() {
  NOTIMPLEMENTED();
  return false;
}

bool RemoteTestServer::BlockUntilStarted() {
  NOTIMPLEMENTED();
  return false;
}

bool RemoteTestServer::Stop() {
  if (!spawner_communicator_.get())
    return true;

  tracker.Get().StoppingServer();

  CleanUpWhenStoppingServer();
  bool stopped = spawner_communicator_->StopServer();

  if (!stopped)
    LOG(ERROR) << "Failed stopping RemoteTestServer";

  // Explicitly reset |spawner_communicator_| to avoid reusing the stopped one.
  spawner_communicator_.reset(NULL);
  return stopped;
}

// On Android, the document root in the device is not the same as the document
// root in the host machine where the test server is launched. So prepend
// DIR_SOURCE_ROOT here to get the actual path of document root on the Android
// device.
base::FilePath RemoteTestServer::GetDocumentRoot() const {
  base::FilePath src_dir;
  PathService::Get(base::DIR_SOURCE_ROOT, &src_dir);
  return src_dir.Append(document_root());
}

bool RemoteTestServer::Init(const base::FilePath& document_root) {
  if (document_root.IsAbsolute())
    return false;

  // Gets ports information used by test server spawner and Python test server.
  int test_server_port = 0;

  // Parse file to extract the ports information.
  std::string port_info;
  if (!base::ReadFileToString(GetTestServerPortInfoFile(), &port_info) ||
      port_info.empty()) {
    return false;
  }

  std::vector<std::string> ports = base::SplitString(
      port_info, ":", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (ports.size() != 2u)
    return false;

  // Verify the ports information.
  base::StringToInt(ports[0], &spawner_server_port_);
  if (!spawner_server_port_ ||
      static_cast<uint32_t>(spawner_server_port_) >=
          std::numeric_limits<uint16_t>::max())
    return false;

  // Allow the test_server_port to be 0, which means the test server spawner
  // will pick up a random port to run the test server.
  base::StringToInt(ports[1], &test_server_port);
  if (static_cast<uint32_t>(test_server_port) >=
      std::numeric_limits<uint16_t>::max())
    return false;
  SetPort(test_server_port);

  // Unlike LocalTestServer, RemoteTestServer passes relative paths to the test
  // server. The test server fails on empty strings in some configurations.
  base::FilePath fixed_root = document_root;
  if (fixed_root.empty())
    fixed_root = base::FilePath(base::FilePath::kCurrentDirectory);
  SetResourcePath(fixed_root, base::FilePath().AppendASCII("net")
                                           .AppendASCII("data")
                                           .AppendASCII("ssl")
                                           .AppendASCII("certificates"));
  return true;
}

}  // namespace net
