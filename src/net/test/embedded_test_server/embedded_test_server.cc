// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/embedded_test_server/embedded_test_server.h"

#include <utility>

#include "base/bind.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/path_service.h"
#include "base/process/process_metrics.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "crypto/rsa_private_key.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/cert/pem_tokenizer.h"
#include "net/cert/test_root_certs.h"
#include "net/socket/ssl_server_socket.h"
#include "net/socket/stream_socket.h"
#include "net/socket/tcp_server_socket.h"
#include "net/ssl/ssl_server_config.h"
#include "net/test/cert_test_util.h"
#include "net/test/embedded_test_server/default_handlers.h"
#include "net/test/embedded_test_server/embedded_test_server_connection_listener.h"
#include "net/test/embedded_test_server/http_connection.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/test/embedded_test_server/request_handler_util.h"
#include "net/test/test_data_directory.h"

namespace net {
namespace test_server {

EmbeddedTestServer::EmbeddedTestServer() : EmbeddedTestServer(TYPE_HTTP) {}

EmbeddedTestServer::EmbeddedTestServer(Type type)
    : is_using_ssl_(type == TYPE_HTTPS),
      connection_listener_(nullptr),
      port_(0),
      cert_(CERT_OK),
      weak_factory_(this) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (is_using_ssl_) {
    base::ThreadRestrictions::ScopedAllowIO allow_io_for_importing_test_cert;
    TestRootCerts* root_certs = TestRootCerts::GetInstance();
    base::FilePath certs_dir(GetTestCertsDirectory());
    root_certs->AddFromFile(certs_dir.AppendASCII("root_ca_cert.pem"));
  }
}

EmbeddedTestServer::~EmbeddedTestServer() {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (Started() && !ShutdownAndWaitUntilComplete()) {
    LOG(ERROR) << "EmbeddedTestServer failed to shut down.";
  }

  {
    // Thread::Join induced by test code should cause an assert.
    base::ThreadRestrictions::ScopedAllowIO allow_io_for_thread_join;

    io_thread_.reset();
  }
}

void EmbeddedTestServer::SetConnectionListener(
    EmbeddedTestServerConnectionListener* listener) {
  DCHECK(!Started());
  connection_listener_ = listener;
}

bool EmbeddedTestServer::Start() {
  bool success = InitializeAndListen();
  if (!success)
    return false;
  StartAcceptingConnections();
  return true;
}

bool EmbeddedTestServer::InitializeAndListen() {
  DCHECK(!Started());

  listen_socket_.reset(new TCPServerSocket(nullptr, NetLog::Source()));

  int result = listen_socket_->ListenWithAddressAndPort("127.0.0.1", 0, 10);
  if (result) {
    LOG(ERROR) << "Listen failed: " << ErrorToString(result);
    listen_socket_.reset();
    return false;
  }

  result = listen_socket_->GetLocalAddress(&local_endpoint_);
  if (result != OK) {
    LOG(ERROR) << "GetLocalAddress failed: " << ErrorToString(result);
    listen_socket_.reset();
    return false;
  }

  if (is_using_ssl_) {
    base_url_ = GURL("https://" + local_endpoint_.ToString());
    if (cert_ == CERT_MISMATCHED_NAME || cert_ == CERT_COMMON_NAME_IS_DOMAIN) {
      base_url_ = GURL(
          base::StringPrintf("https://localhost:%d", local_endpoint_.port()));
    }
  } else {
    base_url_ = GURL("http://" + local_endpoint_.ToString());
  }
  port_ = local_endpoint_.port();

  listen_socket_->DetachFromThread();

  if (is_using_ssl_)
    InitializeSSLServerContext();
  return true;
}

void EmbeddedTestServer::InitializeSSLServerContext() {
  base::ThreadRestrictions::ScopedAllowIO allow_io_for_ssl_initialization;
  base::FilePath certs_dir(GetTestCertsDirectory());
  std::string cert_name = GetCertificateName();

  base::FilePath key_path = certs_dir.AppendASCII(cert_name);
  std::string key_string;
  CHECK(base::ReadFileToString(key_path, &key_string));
  std::vector<std::string> headers;
  headers.push_back("PRIVATE KEY");
  PEMTokenizer pem_tokenizer(key_string, headers);
  pem_tokenizer.GetNext();
  std::vector<uint8_t> key_vector;
  key_vector.assign(pem_tokenizer.data().begin(), pem_tokenizer.data().end());

  std::unique_ptr<crypto::RSAPrivateKey> server_key(
      crypto::RSAPrivateKey::CreateFromPrivateKeyInfo(key_vector));
  context_ =
      CreateSSLServerContext(GetCertificate().get(), *server_key, ssl_config_);
}

void EmbeddedTestServer::StartAcceptingConnections() {
  DCHECK(!io_thread_.get());
  base::Thread::Options thread_options;
  thread_options.message_loop_type = base::MessageLoop::TYPE_IO;
  io_thread_.reset(new base::Thread("EmbeddedTestServer IO Thread"));
  CHECK(io_thread_->StartWithOptions(thread_options));
  CHECK(io_thread_->WaitUntilThreadStarted());

  io_thread_->task_runner()->PostTask(
      FROM_HERE,
      base::Bind(&EmbeddedTestServer::DoAcceptLoop, base::Unretained(this)));
}

bool EmbeddedTestServer::ShutdownAndWaitUntilComplete() {
  DCHECK(thread_checker_.CalledOnValidThread());

  return PostTaskToIOThreadAndWait(base::Bind(
      &EmbeddedTestServer::ShutdownOnIOThread, base::Unretained(this)));
}

void EmbeddedTestServer::ShutdownOnIOThread() {
  DCHECK(io_thread_->task_runner()->BelongsToCurrentThread());
  weak_factory_.InvalidateWeakPtrs();
  listen_socket_.reset();
  connections_.clear();
}

void EmbeddedTestServer::HandleRequest(HttpConnection* connection,
                                       std::unique_ptr<HttpRequest> request) {
  DCHECK(io_thread_->task_runner()->BelongsToCurrentThread());

  for (const auto& monitor : request_monitors_)
    monitor.Run(*request);

  std::unique_ptr<HttpResponse> response;

  for (const auto& handler : request_handlers_) {
    response = handler.Run(*request);
    if (response)
      break;
  }

  if (!response) {
    for (const auto& handler : default_request_handlers_) {
      response = handler.Run(*request);
      if (response)
        break;
    }
  }

  if (!response) {
    LOG(WARNING) << "Request not handled. Returning 404: "
                 << request->relative_url;
    std::unique_ptr<BasicHttpResponse> not_found_response(
        new BasicHttpResponse);
    not_found_response->set_code(HTTP_NOT_FOUND);
    response = std::move(not_found_response);
  }

  response->SendResponse(
      base::Bind(&HttpConnection::SendResponseBytes, connection->GetWeakPtr()),
      base::Bind(&EmbeddedTestServer::DidClose, weak_factory_.GetWeakPtr(),
                 connection));
}

GURL EmbeddedTestServer::GetURL(const std::string& relative_url) const {
  DCHECK(Started()) << "You must start the server first.";
  DCHECK(base::StartsWith(relative_url, "/", base::CompareCase::SENSITIVE))
      << relative_url;
  return base_url_.Resolve(relative_url);
}

GURL EmbeddedTestServer::GetURL(
    const std::string& hostname,
    const std::string& relative_url) const {
  GURL local_url = GetURL(relative_url);
  GURL::Replacements replace_host;
  replace_host.SetHostStr(hostname);
  return local_url.ReplaceComponents(replace_host);
}

bool EmbeddedTestServer::GetAddressList(AddressList* address_list) const {
  *address_list = AddressList(local_endpoint_);
  return true;
}

void EmbeddedTestServer::SetSSLConfig(ServerCertificate cert,
                                      const SSLServerConfig& ssl_config) {
  DCHECK(!Started());
  cert_ = cert;
  ssl_config_ = ssl_config;
}

void EmbeddedTestServer::SetSSLConfig(ServerCertificate cert) {
  SetSSLConfig(cert, SSLServerConfig());
}

std::string EmbeddedTestServer::GetCertificateName() const {
  DCHECK(is_using_ssl_);
  switch (cert_) {
    case CERT_OK:
    case CERT_MISMATCHED_NAME:
      return "ok_cert.pem";
    case CERT_COMMON_NAME_IS_DOMAIN:
      return "localhost_cert.pem";
    case CERT_EXPIRED:
      return "expired_cert.pem";
    case CERT_CHAIN_WRONG_ROOT:
      return "redundant-server-chain.pem";
    case CERT_BAD_VALIDITY:
      return "bad_validity.pem";
  }

  return "ok_cert.pem";
}

scoped_refptr<X509Certificate> EmbeddedTestServer::GetCertificate() const {
  DCHECK(is_using_ssl_);
  base::FilePath certs_dir(GetTestCertsDirectory());

  base::ThreadRestrictions::ScopedAllowIO allow_io_for_importing_test_cert;
  return ImportCertFromFile(certs_dir, GetCertificateName());
}

void EmbeddedTestServer::ServeFilesFromDirectory(
    const base::FilePath& directory) {
  RegisterRequestHandler(base::Bind(&HandleFileRequest, directory));
}

void EmbeddedTestServer::ServeFilesFromSourceDirectory(
    const std::string& relative) {
  base::FilePath test_data_dir;
  CHECK(PathService::Get(base::DIR_SOURCE_ROOT, &test_data_dir));
  ServeFilesFromDirectory(test_data_dir.AppendASCII(relative));
}

void EmbeddedTestServer::ServeFilesFromSourceDirectory(
    const base::FilePath& relative) {
  base::FilePath test_data_dir;
  CHECK(PathService::Get(base::DIR_SOURCE_ROOT, &test_data_dir));
  ServeFilesFromDirectory(test_data_dir.Append(relative));
}

void EmbeddedTestServer::AddDefaultHandlers(const base::FilePath& directory) {
  RegisterDefaultHandlers(this);
  ServeFilesFromSourceDirectory(directory);
}

void EmbeddedTestServer::RegisterRequestHandler(
    const HandleRequestCallback& callback) {
  // TODO(svaldez): Add check to prevent RegisterRequestHandler from being
  // called after the server has started. https://crbug.com/546060
  request_handlers_.push_back(callback);
}

void EmbeddedTestServer::RegisterRequestMonitor(
    const MonitorRequestCallback& callback) {
  // TODO(svaldez): Add check to prevent RegisterRequestMonitor from being
  // called after the server has started. https://crbug.com/546060
  request_monitors_.push_back(callback);
}

void EmbeddedTestServer::RegisterDefaultHandler(
    const HandleRequestCallback& callback) {
  // TODO(svaldez): Add check to prevent RegisterDefaultHandler from being
  // called after the server has started. https://crbug.com/546060
  default_request_handlers_.push_back(callback);
}

std::unique_ptr<StreamSocket> EmbeddedTestServer::DoSSLUpgrade(
    std::unique_ptr<StreamSocket> connection) {
  DCHECK(io_thread_->task_runner()->BelongsToCurrentThread());

  return context_->CreateSSLServerSocket(std::move(connection));
}

void EmbeddedTestServer::DoAcceptLoop() {
  int rv = OK;
  while (rv == OK) {
    rv = listen_socket_->Accept(
        &accepted_socket_, base::Bind(&EmbeddedTestServer::OnAcceptCompleted,
                                      base::Unretained(this)));
    if (rv == ERR_IO_PENDING)
      return;
    HandleAcceptResult(std::move(accepted_socket_));
  }
}

bool EmbeddedTestServer::FlushAllSocketsAndConnectionsOnUIThread() {
  return PostTaskToIOThreadAndWait(
      base::Bind(&EmbeddedTestServer::FlushAllSocketsAndConnections,
                 base::Unretained(this)));
}

void EmbeddedTestServer::FlushAllSocketsAndConnections() {
  connections_.clear();
}

void EmbeddedTestServer::OnAcceptCompleted(int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);
  HandleAcceptResult(std::move(accepted_socket_));
  DoAcceptLoop();
}

void EmbeddedTestServer::OnHandshakeDone(HttpConnection* connection, int rv) {
  if (connection->socket_->IsConnected())
    ReadData(connection);
  else
    DidClose(connection);
}

void EmbeddedTestServer::HandleAcceptResult(
    std::unique_ptr<StreamSocket> socket) {
  DCHECK(io_thread_->task_runner()->BelongsToCurrentThread());
  if (connection_listener_)
    connection_listener_->AcceptedSocket(*socket);

  if (is_using_ssl_)
    socket = DoSSLUpgrade(std::move(socket));

  std::unique_ptr<HttpConnection> http_connection_ptr =
      base::MakeUnique<HttpConnection>(
          std::move(socket), base::Bind(&EmbeddedTestServer::HandleRequest,
                                        base::Unretained(this)));
  HttpConnection* http_connection = http_connection_ptr.get();
  connections_[http_connection->socket_.get()] = std::move(http_connection_ptr);

  if (is_using_ssl_) {
    SSLServerSocket* ssl_socket =
        static_cast<SSLServerSocket*>(http_connection->socket_.get());
    int rv = ssl_socket->Handshake(
        base::Bind(&EmbeddedTestServer::OnHandshakeDone, base::Unretained(this),
                   http_connection));
    if (rv != ERR_IO_PENDING)
      OnHandshakeDone(http_connection, rv);
  } else {
    ReadData(http_connection);
  }
}

void EmbeddedTestServer::ReadData(HttpConnection* connection) {
  while (true) {
    int rv =
        connection->ReadData(base::Bind(&EmbeddedTestServer::OnReadCompleted,
                                        base::Unretained(this), connection));
    if (rv == ERR_IO_PENDING)
      return;
    if (!HandleReadResult(connection, rv))
      return;
  }
}

void EmbeddedTestServer::OnReadCompleted(HttpConnection* connection, int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);
  if (HandleReadResult(connection, rv))
    ReadData(connection);
}

bool EmbeddedTestServer::HandleReadResult(HttpConnection* connection, int rv) {
  DCHECK(io_thread_->task_runner()->BelongsToCurrentThread());
  if (connection_listener_)
    connection_listener_->ReadFromSocket(*connection->socket_, rv);
  if (rv <= 0) {
    DidClose(connection);
    return false;
  }

  // Once a single complete request has been received, there is no further need
  // for the connection and it may be destroyed once the response has been sent.
  if (connection->ConsumeData(rv))
    return false;

  return true;
}

void EmbeddedTestServer::DidClose(HttpConnection* connection) {
  DCHECK(io_thread_->task_runner()->BelongsToCurrentThread());
  DCHECK(connection);
  DCHECK_EQ(1u, connections_.count(connection->socket_.get()));

  connections_.erase(connection->socket_.get());
}

HttpConnection* EmbeddedTestServer::FindConnection(StreamSocket* socket) {
  DCHECK(io_thread_->task_runner()->BelongsToCurrentThread());

  auto it = connections_.find(socket);
  if (it == connections_.end()) {
    return nullptr;
  }
  return it->second.get();
}

bool EmbeddedTestServer::PostTaskToIOThreadAndWait(
    const base::Closure& closure) {
  // Note that PostTaskAndReply below requires
  // base::ThreadTaskRunnerHandle::Get() to return a task runner for posting
  // the reply task. However, in order to make EmbeddedTestServer universally
  // usable, it needs to cope with the situation where it's running on a thread
  // on which a message loop is not (yet) available or as has been destroyed
  // already.
  //
  // To handle this situation, create temporary message loop to support the
  // PostTaskAndReply operation if the current thread as no message loop.
  std::unique_ptr<base::MessageLoop> temporary_loop;
  if (!base::MessageLoop::current())
    temporary_loop.reset(new base::MessageLoop());

  base::RunLoop run_loop;
  if (!io_thread_->task_runner()->PostTaskAndReply(FROM_HERE, closure,
                                                   run_loop.QuitClosure())) {
    return false;
  }
  run_loop.Run();

  return true;
}

}  // namespace test_server
}  // namespace net
