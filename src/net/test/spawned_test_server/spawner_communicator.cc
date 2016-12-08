// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/spawned_test_server/spawner_communicator.h"

#include <limits>
#include <utility>

#include "base/json/json_reader.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/stringprintf.h"
#include "base/supports_user_data.h"
#include "base/test/test_timeouts.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "base/values.h"
#include "build/build_config.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/port_util.h"
#include "net/base/request_priority.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/http/http_response_headers.h"
#include "net/url_request/url_request_test_util.h"
#include "url/gurl.h"

namespace net {

namespace {

GURL GenerateSpawnerCommandURL(const std::string& command, uint16_t port) {
  // Always performs HTTP request for sending command to the spawner server.
  return GURL(base::StringPrintf("%s:%u/%s", "http://127.0.0.1", port,
                                 command.c_str()));
}

int kBufferSize = 2048;

// A class to hold all data needed to send a command to spawner server.
class SpawnerRequestData : public base::SupportsUserData::Data {
 public:
  SpawnerRequestData(int id, int* result_code, std::string* data_received)
      : request_id_(id),
        buf_(new IOBuffer(kBufferSize)),
        result_code_(result_code),
        data_received_(data_received),
        response_started_count_(0) {
    DCHECK(result_code);
    *result_code_ = OK;
    DCHECK(data_received);
    data_received_->clear();
  }

  ~SpawnerRequestData() override {}

  bool DoesRequestIdMatch(int request_id) const {
    return request_id_ == request_id;
  }

  IOBuffer* buf() const { return buf_.get(); }

  bool IsResultOK() const { return *result_code_ == OK; }

  void ClearReceivedData() { data_received_->clear(); }

  void SetResultCode(int result_code) { *result_code_ = result_code; }

  void IncreaseResponseStartedCount() { response_started_count_++; }

  int response_started_count() const { return response_started_count_; }

  // Write data read from URLRequest::Read() to |data_received_|. Returns true
  // if |num_bytes| is great than 0. |num_bytes| is 0 for EOF, < 0 on errors.
  bool ConsumeBytesRead(int num_bytes) {
    // Error while reading, or EOF.
    if (num_bytes <= 0)
      return false;

    data_received_->append(buf_->data(), num_bytes);
    return true;
  }

 private:
  // Unique ID for the current request.
  int request_id_;

  // Buffer that URLRequest writes into.
  scoped_refptr<IOBuffer> buf_;

  // Holds the error condition that was hit on the current request, or OK.
  int* result_code_;

  // Data received from server;
  std::string* data_received_;

  // Used to track how many times the OnResponseStarted get called after
  // sending a command to spawner server.
  int response_started_count_;

  DISALLOW_COPY_AND_ASSIGN(SpawnerRequestData);
};

}  // namespace

SpawnerCommunicator::SpawnerCommunicator(uint16_t port)
    : io_thread_("spawner_communicator"),
      event_(base::WaitableEvent::ResetPolicy::AUTOMATIC,
             base::WaitableEvent::InitialState::NOT_SIGNALED),
      port_(port),
      next_id_(0),
      is_running_(false),
      weak_factory_(this) {}

SpawnerCommunicator::~SpawnerCommunicator() {
  DCHECK(!is_running_);
}

void SpawnerCommunicator::WaitForResponse() {
  DCHECK_NE(base::MessageLoop::current(), io_thread_.message_loop());
  event_.Wait();
  event_.Reset();
}

void SpawnerCommunicator::StartIOThread() {
  DCHECK_NE(base::MessageLoop::current(), io_thread_.message_loop());
  if (is_running_)
    return;

  allowed_port_.reset(new ScopedPortException(port_));
  base::Thread::Options options;
  options.message_loop_type = base::MessageLoop::TYPE_IO;
  is_running_ = io_thread_.StartWithOptions(options);
  DCHECK(is_running_);
}

void SpawnerCommunicator::Shutdown() {
  DCHECK_NE(base::MessageLoop::current(), io_thread_.message_loop());
  DCHECK(is_running_);
  // The request and its context should be created and destroyed only on the
  // IO thread.
  DCHECK(!cur_request_.get());
  DCHECK(!context_.get());
  is_running_ = false;
  io_thread_.Stop();
  allowed_port_.reset();
}

void SpawnerCommunicator::SendCommandAndWaitForResult(
    const std::string& command,
    const std::string& post_data,
    int* result_code,
    std::string* data_received) {
  if (!result_code || !data_received)
    return;
  // Start the communicator thread to talk to test server spawner.
  StartIOThread();
  DCHECK(io_thread_.message_loop());

  // Since the method will be blocked until SpawnerCommunicator gets result
  // from the spawner server or timed-out. It's safe to use base::Unretained
  // when using base::Bind.
  io_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::Bind(&SpawnerCommunicator::SendCommandAndWaitForResultOnIOThread,
                 base::Unretained(this), command, post_data, result_code,
                 data_received));
  WaitForResponse();
}

void SpawnerCommunicator::SendCommandAndWaitForResultOnIOThread(
    const std::string& command,
    const std::string& post_data,
    int* result_code,
    std::string* data_received) {
  base::MessageLoop* loop = io_thread_.message_loop();
  DCHECK(loop);
  DCHECK(loop->task_runner()->BelongsToCurrentThread());

  // Prepare the URLRequest for sending the command.
  DCHECK(!cur_request_.get());
  context_.reset(new TestURLRequestContext);
  cur_request_ = context_->CreateRequest(
      GenerateSpawnerCommandURL(command, port_), DEFAULT_PRIORITY, this);
  DCHECK(cur_request_);
  int current_request_id = ++next_id_;
  SpawnerRequestData* data = new SpawnerRequestData(current_request_id,
                                                    result_code,
                                                    data_received);
  DCHECK(data);
  cur_request_->SetUserData(this, data);

  if (post_data.empty()) {
    cur_request_->set_method("GET");
  } else {
    cur_request_->set_method("POST");
    std::unique_ptr<UploadElementReader> reader(
        UploadOwnedBytesElementReader::CreateWithString(post_data));
    cur_request_->set_upload(
        ElementsUploadDataStream::CreateWithReader(std::move(reader), 0));
    HttpRequestHeaders headers;
    headers.SetHeader(HttpRequestHeaders::kContentType,
                      "application/json");
    cur_request_->SetExtraRequestHeaders(headers);
  }

  // Post a task to timeout this request if it takes too long.
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, base::Bind(&SpawnerCommunicator::OnTimeout,
                            weak_factory_.GetWeakPtr(), current_request_id),
      TestTimeouts::action_max_timeout());

  // Start the request.
  cur_request_->Start();
}

void SpawnerCommunicator::OnTimeout(int id) {
  // Timeout tasks may outlive the URLRequest they reference. Make sure it
  // is still applicable.
  if (!cur_request_.get())
    return;
  SpawnerRequestData* data =
      static_cast<SpawnerRequestData*>(cur_request_->GetUserData(this));
  DCHECK(data);

  if (!data->DoesRequestIdMatch(id))
    return;
  // Set the result code and cancel the timed-out task.
  int result = cur_request_->CancelWithError(ERR_TIMED_OUT);
  OnSpawnerCommandCompleted(cur_request_.get(), result);
}

void SpawnerCommunicator::OnSpawnerCommandCompleted(URLRequest* request,
                                                    int net_error) {
  DCHECK_NE(ERR_IO_PENDING, net_error);

  if (!cur_request_.get())
    return;
  DCHECK_EQ(request, cur_request_.get());
  SpawnerRequestData* data =
      static_cast<SpawnerRequestData*>(cur_request_->GetUserData(this));
  DCHECK(data);

  // If request is faild,return the error code.
  if (net_error != OK)
    data->SetResultCode(net_error);

  if (!data->IsResultOK()) {
    LOG(ERROR) << "request failed, error: " << net_error;
    // Clear the buffer of received data if any net error happened.
    data->ClearReceivedData();
  } else {
    DCHECK_EQ(1, data->response_started_count());
  }

  // Clear current request to indicate the completion of sending a command
  // to spawner server and getting the result.
  cur_request_.reset();
  context_.reset();
  // Invalidate the weak pointers on the IO thread.
  weak_factory_.InvalidateWeakPtrs();

  // Wakeup the caller in user thread.
  event_.Signal();
}

void SpawnerCommunicator::ReadResult(URLRequest* request) {
  DCHECK_EQ(request, cur_request_.get());
  SpawnerRequestData* data =
      static_cast<SpawnerRequestData*>(cur_request_->GetUserData(this));
  DCHECK(data);

  IOBuffer* buf = data->buf();
  // Read as many bytes as are available synchronously.
  while (true) {
    int rv = request->Read(buf, kBufferSize);
    if (rv == ERR_IO_PENDING)
      return;

    if (rv < 0) {
      OnSpawnerCommandCompleted(request, rv);
      return;
    }

    if (!data->ConsumeBytesRead(rv)) {
      OnSpawnerCommandCompleted(request, rv);
      return;
    }
  }
}

void SpawnerCommunicator::OnResponseStarted(URLRequest* request,
                                            int net_error) {
  DCHECK_EQ(request, cur_request_.get());
  DCHECK_NE(ERR_IO_PENDING, net_error);

  SpawnerRequestData* data =
      static_cast<SpawnerRequestData*>(cur_request_->GetUserData(this));
  DCHECK(data);

  data->IncreaseResponseStartedCount();

  if (net_error != OK) {
    OnSpawnerCommandCompleted(request, net_error);
    return;
  }

  // Require HTTP responses to have a success status code.
  if (request->GetResponseCode() != 200) {
    LOG(ERROR) << "Spawner server returned bad status: "
               << request->response_headers()->GetStatusLine();
    data->SetResultCode(ERR_FAILED);
    request->Cancel();
    OnSpawnerCommandCompleted(request, ERR_ABORTED);
    return;
  }

  ReadResult(request);
}

void SpawnerCommunicator::OnReadCompleted(URLRequest* request, int num_bytes) {
  DCHECK_NE(ERR_IO_PENDING, num_bytes);

  if (!cur_request_.get())
    return;
  DCHECK_EQ(request, cur_request_.get());
  SpawnerRequestData* data =
      static_cast<SpawnerRequestData*>(cur_request_->GetUserData(this));
  DCHECK(data);

  if (data->ConsumeBytesRead(num_bytes)) {
    // Keep reading.
    ReadResult(request);
  } else {
    // |bytes_read| < 0
    int net_error = num_bytes;
    OnSpawnerCommandCompleted(request, net_error);
  }
}

bool SpawnerCommunicator::StartServer(const std::string& arguments,
                                      uint16_t* port) {
  *port = 0;
  // Send the start command to spawner server to start the Python test server
  // on remote machine.
  std::string server_return_data;
  int result_code;
  SendCommandAndWaitForResult("start", arguments, &result_code,
                              &server_return_data);
  if (OK != result_code || server_return_data.empty())
    return false;

  // Check whether the data returned from spawner server is JSON-formatted.
  std::unique_ptr<base::Value> value =
      base::JSONReader::Read(server_return_data);
  if (!value.get() || !value->IsType(base::Value::Type::DICTIONARY)) {
    LOG(ERROR) << "Invalid server data: " << server_return_data.c_str();
    return false;
  }

  // Check whether spawner server returns valid data.
  base::DictionaryValue* server_data =
      static_cast<base::DictionaryValue*>(value.get());
  std::string message;
  if (!server_data->GetString("message", &message) || message != "started") {
    LOG(ERROR) << "Invalid message in server data: ";
    return false;
  }
  int int_port;
  if (!server_data->GetInteger("port", &int_port) || int_port <= 0 ||
      int_port > std::numeric_limits<uint16_t>::max()) {
    LOG(ERROR) << "Invalid port value: " << int_port;
    return false;
  }
  *port = static_cast<uint16_t>(int_port);
  return true;
}

bool SpawnerCommunicator::StopServer() {
  // It's OK to stop the SpawnerCommunicator without starting it. Some tests
  // have test server on their test fixture but do not actually use it.
  if (!is_running_)
    return true;

  // When the test is done, ask the test server spawner to kill the test server
  // on the remote machine.
  std::string server_return_data;
  int result_code;
  SendCommandAndWaitForResult("kill", "", &result_code, &server_return_data);
  Shutdown();
  if (OK != result_code || server_return_data != "killed")
    return false;
  return true;
}

}  // namespace net
