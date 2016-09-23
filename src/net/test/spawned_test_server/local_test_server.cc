// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/spawned_test_server/local_test_server.h"

#include "base/command_line.h"
#include "base/json/json_reader.h"
#include "base/logging.h"
#include "base/path_service.h"
#include "base/strings/string_number_conversions.h"
#include "base/threading/thread_restrictions.h"
#include "base/values.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_errors.h"
#include "net/test/python_utils.h"
#include "url/gurl.h"

namespace net {

namespace {

bool AppendArgumentFromJSONValue(const std::string& key,
                                 const base::Value& value_node,
                                 base::CommandLine* command_line) {
  std::string argument_name = "--" + key;
  switch (value_node.GetType()) {
    case base::Value::TYPE_NULL:
      command_line->AppendArg(argument_name);
      break;
    case base::Value::TYPE_INTEGER: {
      int value;
      bool result = value_node.GetAsInteger(&value);
      DCHECK(result);
      command_line->AppendArg(argument_name + "=" + base::IntToString(value));
      break;
    }
    case base::Value::TYPE_STRING: {
      std::string value;
      bool result = value_node.GetAsString(&value);
      if (!result || value.empty())
        return false;
      command_line->AppendArg(argument_name + "=" + value);
      break;
    }
    case base::Value::TYPE_BOOLEAN:
    case base::Value::TYPE_DOUBLE:
    case base::Value::TYPE_LIST:
    case base::Value::TYPE_DICTIONARY:
    case base::Value::TYPE_BINARY:
    default:
      NOTREACHED() << "improper json type";
      return false;
  }
  return true;
}

}  // namespace

LocalTestServer::LocalTestServer(Type type,
                                 const std::string& host,
                                 const base::FilePath& document_root)
    : BaseTestServer(type, host) {
  if (!Init(document_root))
    NOTREACHED();
}

LocalTestServer::LocalTestServer(Type type,
                                 const SSLOptions& ssl_options,
                                 const base::FilePath& document_root)
    : BaseTestServer(type, ssl_options) {
  if (!Init(document_root))
    NOTREACHED();
}

LocalTestServer::~LocalTestServer() {
  Stop();
}

bool LocalTestServer::GetTestServerPath(base::FilePath* testserver_path) const {
  base::FilePath testserver_dir;
  if (!PathService::Get(base::DIR_SOURCE_ROOT, &testserver_dir)) {
    LOG(ERROR) << "Failed to get DIR_SOURCE_ROOT";
    return false;
  }
  testserver_dir = testserver_dir.Append(FILE_PATH_LITERAL("net"))
                                 .Append(FILE_PATH_LITERAL("tools"))
                                 .Append(FILE_PATH_LITERAL("testserver"));
  *testserver_path = testserver_dir.Append(FILE_PATH_LITERAL("testserver.py"));
  return true;
}

bool LocalTestServer::Start() {
  return StartInBackground() && BlockUntilStarted();
}

bool LocalTestServer::StartInBackground() {
  base::ThreadRestrictions::ScopedAllowIO allow_io_from_test_code;

  // Get path to Python server script.
  base::FilePath testserver_path;
  if (!GetTestServerPath(&testserver_path))
    return false;

  if (!SetPythonPath())
    return false;

  if (!LaunchPython(testserver_path))
    return false;

  return true;
}

bool LocalTestServer::BlockUntilStarted() {
  if (!WaitToStart()) {
    Stop();
    return false;
  }

  return SetupWhenServerStarted();
}

bool LocalTestServer::Stop() {
  CleanUpWhenStoppingServer();

  if (!process_.IsValid())
    return true;

  // First check if the process has already terminated.
  int exit_code;
  bool ret = process_.WaitForExitWithTimeout(base::TimeDelta(), &exit_code);
  if (!ret)
    ret = process_.Terminate(1, true);

  if (ret)
    process_.Close();
  else
    VLOG(1) << "Kill failed?";

  return ret;
}

bool LocalTestServer::Init(const base::FilePath& document_root) {
  if (document_root.IsAbsolute())
    return false;

  // At this point, the port that the test server will listen on is unknown.
  // The test server will listen on an ephemeral port, and write the port
  // number out over a pipe that this TestServer object will read from. Once
  // that is complete, the host port pair will contain the actual port.
  DCHECK(!GetPort());

  base::FilePath src_dir;
  if (!PathService::Get(base::DIR_SOURCE_ROOT, &src_dir))
    return false;
  SetResourcePath(src_dir.Append(document_root),
                  src_dir.AppendASCII("net")
                         .AppendASCII("data")
                         .AppendASCII("ssl")
                         .AppendASCII("certificates"));
  return true;
}

bool LocalTestServer::SetPythonPath() const {
  base::FilePath third_party_dir;
  if (!PathService::Get(base::DIR_SOURCE_ROOT, &third_party_dir)) {
    LOG(ERROR) << "Failed to get DIR_SOURCE_ROOT";
    return false;
  }
  third_party_dir = third_party_dir.AppendASCII("third_party");

  // For simplejson. (simplejson, unlike all the other Python modules
  // we include, doesn't have an extra 'simplejson' directory, so we
  // need to include its parent directory, i.e. third_party_dir).
  AppendToPythonPath(third_party_dir);

  AppendToPythonPath(third_party_dir.AppendASCII("tlslite"));
  AppendToPythonPath(
      third_party_dir.AppendASCII("pyftpdlib").AppendASCII("src"));
  AppendToPythonPath(
      third_party_dir.AppendASCII("pywebsocket").AppendASCII("src"));

  // Locate the Python code generated by the protocol buffers compiler.
  base::FilePath pyproto_dir;
  if (!GetPyProtoPath(&pyproto_dir)) {
    LOG(WARNING) << "Cannot find pyproto dir for generated code. "
                 << "Testserver features that rely on it will not work";
    return true;
  }
  AppendToPythonPath(pyproto_dir);

  return true;
}

bool LocalTestServer::AddCommandLineArguments(
    base::CommandLine* command_line) const {
  base::DictionaryValue arguments_dict;
  if (!GenerateArguments(&arguments_dict))
    return false;

  // Serialize the argument dictionary into CommandLine.
  for (base::DictionaryValue::Iterator it(arguments_dict); !it.IsAtEnd();
       it.Advance()) {
    const base::Value& value = it.value();
    const std::string& key = it.key();

    // Add arguments from a list.
    if (value.IsType(base::Value::TYPE_LIST)) {
      const base::ListValue* list = NULL;
      if (!value.GetAsList(&list) || !list || list->empty())
        return false;
      for (base::ListValue::const_iterator list_it = list->begin();
           list_it != list->end(); ++list_it) {
        if (!AppendArgumentFromJSONValue(key, *(*list_it), command_line))
          return false;
      }
    } else if (!AppendArgumentFromJSONValue(key, value, command_line)) {
        return false;
    }
  }

  // Append the appropriate server type argument.
  switch (type()) {
    case TYPE_HTTP:  // The default type is HTTP, no argument required.
      break;
    case TYPE_HTTPS:
      command_line->AppendArg("--https");
      break;
    case TYPE_WS:
    case TYPE_WSS:
      command_line->AppendArg("--websocket");
      break;
    case TYPE_FTP:
      command_line->AppendArg("--ftp");
      break;
    case TYPE_TCP_ECHO:
      command_line->AppendArg("--tcp-echo");
      break;
    case TYPE_UDP_ECHO:
      command_line->AppendArg("--udp-echo");
      break;
    case TYPE_BASIC_AUTH_PROXY:
      command_line->AppendArg("--basic-auth-proxy");
      break;
    default:
      NOTREACHED();
      return false;
  }

  return true;
}

}  // namespace net
