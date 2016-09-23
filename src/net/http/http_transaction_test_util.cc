// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_transaction_test_util.h"

#include <algorithm>
#include <unordered_map>
#include <utility>

#include "base/bind.h"
#include "base/location.h"
#include "base/message_loop/message_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/clock.h"
#include "base/time/time.h"
#include "net/base/load_flags.h"
#include "net/base/load_timing_info.h"
#include "net/base/net_errors.h"
#include "net/cert/x509_certificate.h"
#include "net/disk_cache/disk_cache.h"
#include "net/http/http_cache.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_info.h"
#include "net/http/http_transaction.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {
using MockTransactionMap =
    std::unordered_map<std::string, const MockTransaction*>;
static MockTransactionMap mock_transactions;
}  // namespace

//-----------------------------------------------------------------------------
// mock transaction data

const MockTransaction kSimpleGET_Transaction = {
    "http://www.google.com/",
    "GET",
    base::Time(),
    "",
    LOAD_NORMAL,
    "HTTP/1.1 200 OK",
    "Cache-Control: max-age=10000\n",
    base::Time(),
    "<html><body>Google Blah Blah</body></html>",
    TEST_MODE_NORMAL,
    nullptr,
    nullptr,
    nullptr,
    0,
    0,
    OK};

const MockTransaction kSimplePOST_Transaction = {
    "http://bugdatabase.com/edit",
    "POST",
    base::Time(),
    "",
    LOAD_NORMAL,
    "HTTP/1.1 200 OK",
    "",
    base::Time(),
    "<html><body>Google Blah Blah</body></html>",
    TEST_MODE_NORMAL,
    nullptr,
    nullptr,
    nullptr,
    0,
    0,
    OK};

const MockTransaction kTypicalGET_Transaction = {
    "http://www.example.com/~foo/bar.html", "GET", base::Time(), "",
    LOAD_NORMAL, "HTTP/1.1 200 OK",
    "Date: Wed, 28 Nov 2007 09:40:09 GMT\n"
    "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n",
    base::Time(), "<html><body>Google Blah Blah</body></html>",
    TEST_MODE_NORMAL, nullptr, nullptr, nullptr, 0, 0, OK};

const MockTransaction kETagGET_Transaction = {
    "http://www.google.com/foopy", "GET", base::Time(), "", LOAD_NORMAL,
    "HTTP/1.1 200 OK",
    "Cache-Control: max-age=10000\n"
    "Etag: \"foopy\"\n",
    base::Time(), "<html><body>Google Blah Blah</body></html>",
    TEST_MODE_NORMAL, nullptr, nullptr, nullptr, 0, 0, OK};

const MockTransaction kRangeGET_Transaction = {
    "http://www.google.com/",
    "GET",
    base::Time(),
    "Range: 0-100\r\n",
    LOAD_NORMAL,
    "HTTP/1.1 200 OK",
    "Cache-Control: max-age=10000\n",
    base::Time(),
    "<html><body>Google Blah Blah</body></html>",
    TEST_MODE_NORMAL,
    nullptr,
    nullptr,
    nullptr,
    0,
    0,
    OK};

static const MockTransaction* const kBuiltinMockTransactions[] = {
  &kSimpleGET_Transaction,
  &kSimplePOST_Transaction,
  &kTypicalGET_Transaction,
  &kETagGET_Transaction,
  &kRangeGET_Transaction
};

const MockTransaction* FindMockTransaction(const GURL& url) {
  // look for overrides:
  MockTransactionMap::const_iterator it = mock_transactions.find(url.spec());
  if (it != mock_transactions.end())
    return it->second;

  // look for builtins:
  for (size_t i = 0; i < arraysize(kBuiltinMockTransactions); ++i) {
    if (url == GURL(kBuiltinMockTransactions[i]->url))
      return kBuiltinMockTransactions[i];
  }
  return nullptr;
}

void AddMockTransaction(const MockTransaction* trans) {
  mock_transactions[GURL(trans->url).spec()] = trans;
}

void RemoveMockTransaction(const MockTransaction* trans) {
  mock_transactions.erase(GURL(trans->url).spec());
}

MockHttpRequest::MockHttpRequest(const MockTransaction& t) {
  url = GURL(t.url);
  method = t.method;
  extra_headers.AddHeadersFromString(t.request_headers);
  load_flags = t.load_flags;
}

//-----------------------------------------------------------------------------

// static
int TestTransactionConsumer::quit_counter_ = 0;

TestTransactionConsumer::TestTransactionConsumer(
    RequestPriority priority,
    HttpTransactionFactory* factory)
    : state_(IDLE), error_(OK) {
  // Disregard the error code.
  factory->CreateTransaction(priority, &trans_);
  ++quit_counter_;
}

TestTransactionConsumer::~TestTransactionConsumer() {
}

void TestTransactionConsumer::Start(const HttpRequestInfo* request,
                                    const NetLogWithSource& net_log) {
  state_ = STARTING;
  int result = trans_->Start(
      request, base::Bind(&TestTransactionConsumer::OnIOComplete,
                          base::Unretained(this)), net_log);
  if (result != ERR_IO_PENDING)
    DidStart(result);
}

void TestTransactionConsumer::DidStart(int result) {
  if (result != OK) {
    DidFinish(result);
  } else {
    Read();
  }
}

void TestTransactionConsumer::DidRead(int result) {
  if (result <= 0) {
    DidFinish(result);
  } else {
    content_.append(read_buf_->data(), result);
    Read();
  }
}

void TestTransactionConsumer::DidFinish(int result) {
  state_ = DONE;
  error_ = result;
  if (--quit_counter_ == 0)
    base::MessageLoop::current()->QuitWhenIdle();
}

void TestTransactionConsumer::Read() {
  state_ = READING;
  read_buf_ = new IOBuffer(1024);
  int result = trans_->Read(read_buf_.get(),
                            1024,
                            base::Bind(&TestTransactionConsumer::OnIOComplete,
                                       base::Unretained(this)));
  if (result != ERR_IO_PENDING)
    DidRead(result);
}

void TestTransactionConsumer::OnIOComplete(int result) {
  switch (state_) {
    case STARTING:
      DidStart(result);
      break;
    case READING:
      DidRead(result);
      break;
    default:
      NOTREACHED();
  }
}

MockNetworkTransaction::MockNetworkTransaction(RequestPriority priority,
                                               MockNetworkLayer* factory)
    : request_(nullptr),
      data_cursor_(0),
      content_length_(0),
      priority_(priority),
      read_handler_(nullptr),
      websocket_handshake_stream_create_helper_(nullptr),
      transaction_factory_(factory->AsWeakPtr()),
      received_bytes_(0),
      sent_bytes_(0),
      socket_log_id_(NetLog::Source::kInvalidId),
      done_reading_called_(false),
      weak_factory_(this) {}

MockNetworkTransaction::~MockNetworkTransaction() {}

int MockNetworkTransaction::Start(const HttpRequestInfo* request,
                                  const CompletionCallback& callback,
                                  const NetLogWithSource& net_log) {
  if (request_)
    return ERR_FAILED;

  request_ = request;
  return StartInternal(request, callback, net_log);
}

int MockNetworkTransaction::RestartIgnoringLastError(
    const CompletionCallback& callback) {
  return ERR_FAILED;
}

int MockNetworkTransaction::RestartWithCertificate(
    X509Certificate* client_cert,
    SSLPrivateKey* client_private_key,
    const CompletionCallback& callback) {
  return ERR_FAILED;
}

int MockNetworkTransaction::RestartWithAuth(
    const AuthCredentials& credentials,
    const CompletionCallback& callback) {
  if (!IsReadyToRestartForAuth())
    return ERR_FAILED;

  HttpRequestInfo auth_request_info = *request_;
  auth_request_info.extra_headers.SetHeader("Authorization", "Bar");

  // Let the MockTransactionHandler worry about this: the only way for this
  // test to succeed is by using an explicit handler for the transaction so
  // that server behavior can be simulated.
  return StartInternal(&auth_request_info, callback, NetLogWithSource());
}

void MockNetworkTransaction::PopulateNetErrorDetails(
    NetErrorDetails* /*details*/) const {
  NOTIMPLEMENTED();
}

bool MockNetworkTransaction::IsReadyToRestartForAuth() {
  if (!request_)
    return false;

  if (!request_->extra_headers.HasHeader("X-Require-Mock-Auth"))
    return false;

  // Allow the mock server to decide whether authentication is required or not.
  std::string status_line = response_.headers->GetStatusLine();
  return status_line.find(" 401 ") != std::string::npos ||
      status_line.find(" 407 ") != std::string::npos;
}

int MockNetworkTransaction::Read(net::IOBuffer* buf,
                                 int buf_len,
                                 const CompletionCallback& callback) {
  CHECK(!done_reading_called_);
  int num = 0;
  if (read_handler_) {
    num = (*read_handler_)(content_length_, data_cursor_, buf, buf_len);
    data_cursor_ += num;
  } else {
    int data_len = static_cast<int>(data_.size());
    num = std::min(static_cast<int64_t>(buf_len), data_len - data_cursor_);
    if (test_mode_ & TEST_MODE_SLOW_READ)
      num = std::min(num, 1);
    if (num) {
      memcpy(buf->data(), data_.data() + data_cursor_, num);
      data_cursor_ += num;
    }
  }
  if (test_mode_ & TEST_MODE_SYNC_NET_READ)
    return num;

  CallbackLater(callback, num);
  return ERR_IO_PENDING;
}

void MockNetworkTransaction::StopCaching() {
  if (transaction_factory_.get())
    transaction_factory_->TransactionStopCaching();
}

bool MockNetworkTransaction::GetFullRequestHeaders(
    HttpRequestHeaders* headers) const {
  return false;
}

int64_t MockNetworkTransaction::GetTotalReceivedBytes() const {
  return received_bytes_;
}

int64_t MockNetworkTransaction::GetTotalSentBytes() const {
  return sent_bytes_;
}

void MockNetworkTransaction::DoneReading() {
  CHECK(!done_reading_called_);
  done_reading_called_ = true;
  if (transaction_factory_.get())
    transaction_factory_->TransactionDoneReading();
}

const HttpResponseInfo* MockNetworkTransaction::GetResponseInfo() const {
  return &response_;
}

LoadState MockNetworkTransaction::GetLoadState() const {
  if (data_cursor_)
    return LOAD_STATE_READING_RESPONSE;
  return LOAD_STATE_IDLE;
}

void MockNetworkTransaction::SetQuicServerInfo(
    QuicServerInfo* quic_server_info) {
}

bool MockNetworkTransaction::GetLoadTimingInfo(
    LoadTimingInfo* load_timing_info) const {
  if (socket_log_id_ != NetLog::Source::kInvalidId) {
    // The minimal set of times for a request that gets a response, assuming it
    // gets a new socket.
    load_timing_info->socket_reused = false;
    load_timing_info->socket_log_id = socket_log_id_;
    load_timing_info->connect_timing.connect_start = base::TimeTicks::Now();
    load_timing_info->connect_timing.connect_end = base::TimeTicks::Now();
    load_timing_info->send_start = base::TimeTicks::Now();
    load_timing_info->send_end = base::TimeTicks::Now();
  } else {
    // If there's no valid socket ID, just use the generic socket reused values.
    // No tests currently depend on this, just should not match the values set
    // by a cache hit.
    load_timing_info->socket_reused = true;
    load_timing_info->send_start = base::TimeTicks::Now();
    load_timing_info->send_end = base::TimeTicks::Now();
  }
  return true;
}

bool MockNetworkTransaction::GetRemoteEndpoint(IPEndPoint* endpoint) const {
  *endpoint = IPEndPoint(IPAddress(127, 0, 0, 1), 80);
  return true;
}

void MockNetworkTransaction::SetPriority(RequestPriority priority) {
  priority_ = priority;
}

void MockNetworkTransaction::SetWebSocketHandshakeStreamCreateHelper(
    WebSocketHandshakeStreamBase::CreateHelper* create_helper) {
  websocket_handshake_stream_create_helper_ = create_helper;
}

// static
const int64_t MockNetworkTransaction::kTotalReceivedBytes = 1000;

// static
const int64_t MockNetworkTransaction::kTotalSentBytes = 100;

int MockNetworkTransaction::StartInternal(const HttpRequestInfo* request,
                                          const CompletionCallback& callback,
                                          const NetLogWithSource& net_log) {
  const MockTransaction* t = FindMockTransaction(request->url);
  if (!t)
    return ERR_FAILED;

  if (!before_network_start_callback_.is_null()) {
    bool defer = false;
    before_network_start_callback_.Run(&defer);
    if (defer)
      return net::ERR_IO_PENDING;
  }

  test_mode_ = t->test_mode;

  // Return immediately if we're returning an error.
  if (OK != t->return_code) {
    if (test_mode_ & TEST_MODE_SYNC_NET_START)
      return t->return_code;
    CallbackLater(callback, t->return_code);
    return ERR_IO_PENDING;
  }

  sent_bytes_ = kTotalSentBytes;
  received_bytes_ = kTotalReceivedBytes;

  std::string resp_status = t->status;
  std::string resp_headers = t->response_headers;
  std::string resp_data = t->data;
  if (t->handler)
    (t->handler)(request, &resp_status, &resp_headers, &resp_data);
  if (t->read_handler)
    read_handler_ = t->read_handler;

  std::string header_data = base::StringPrintf(
      "%s\n%s\n", resp_status.c_str(), resp_headers.c_str());
  std::replace(header_data.begin(), header_data.end(), '\n', '\0');

  response_.request_time = transaction_factory_->Now();
  if (!t->request_time.is_null())
    response_.request_time = t->request_time;

  response_.was_cached = false;
  response_.network_accessed = true;

  response_.response_time = transaction_factory_->Now();
  if (!t->response_time.is_null())
    response_.response_time = t->response_time;

  response_.headers = new HttpResponseHeaders(header_data);
  response_.vary_data.Init(*request, *response_.headers.get());
  response_.ssl_info.cert = t->cert;
  response_.ssl_info.cert_status = t->cert_status;
  response_.ssl_info.connection_status = t->ssl_connection_status;
  data_ = resp_data;
  content_length_ = response_.headers->GetContentLength();

  if (net_log.net_log())
    socket_log_id_ = net_log.net_log()->NextID();

  if (request_->load_flags & LOAD_PREFETCH)
    response_.unused_since_prefetch = true;

  if (test_mode_ & TEST_MODE_SYNC_NET_START)
    return OK;

  CallbackLater(callback, OK);
  return ERR_IO_PENDING;
}

void MockNetworkTransaction::SetBeforeNetworkStartCallback(
    const BeforeNetworkStartCallback& callback) {
  before_network_start_callback_ = callback;
}

void MockNetworkTransaction::SetBeforeHeadersSentCallback(
    const BeforeHeadersSentCallback& callback) {}

int MockNetworkTransaction::ResumeNetworkStart() {
  // Should not get here.
  return ERR_FAILED;
}

void MockNetworkTransaction::GetConnectionAttempts(
    ConnectionAttempts* out) const {
  NOTIMPLEMENTED();
}

void MockNetworkTransaction::CallbackLater(const CompletionCallback& callback,
                                           int result) {
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&MockNetworkTransaction::RunCallback,
                            weak_factory_.GetWeakPtr(), callback, result));
}

void MockNetworkTransaction::RunCallback(const CompletionCallback& callback,
                                         int result) {
  callback.Run(result);
}

MockNetworkLayer::MockNetworkLayer()
    : transaction_count_(0),
      done_reading_called_(false),
      stop_caching_called_(false),
      last_create_transaction_priority_(DEFAULT_PRIORITY),
      clock_(nullptr) {
}

MockNetworkLayer::~MockNetworkLayer() {}

void MockNetworkLayer::TransactionDoneReading() {
  CHECK(!done_reading_called_);
  done_reading_called_ = true;
}

void MockNetworkLayer::TransactionStopCaching() {
  stop_caching_called_ = true;
}

void MockNetworkLayer::ResetTransactionCount() {
  transaction_count_ = 0;
}

int MockNetworkLayer::CreateTransaction(
    RequestPriority priority,
    std::unique_ptr<HttpTransaction>* trans) {
  transaction_count_++;
  last_create_transaction_priority_ = priority;
  std::unique_ptr<MockNetworkTransaction> mock_transaction(
      new MockNetworkTransaction(priority, this));
  last_transaction_ = mock_transaction->AsWeakPtr();
  *trans = std::move(mock_transaction);
  return OK;
}

HttpCache* MockNetworkLayer::GetCache() {
  return NULL;
}

HttpNetworkSession* MockNetworkLayer::GetSession() {
  return NULL;
}

void MockNetworkLayer::SetClock(base::Clock* clock) {
  DCHECK(!clock_);
  clock_ = clock;
}

base::Time MockNetworkLayer::Now() {
  if (clock_)
    return clock_->Now();
  return base::Time::Now();
}

//-----------------------------------------------------------------------------
// helpers

int ReadTransaction(HttpTransaction* trans, std::string* result) {
  int rv;

  TestCompletionCallback callback;

  std::string content;
  do {
    scoped_refptr<IOBuffer> buf(new IOBuffer(256));
    rv = trans->Read(buf.get(), 256, callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = callback.WaitForResult();

    if (rv > 0)
      content.append(buf->data(), rv);
    else if (rv < 0)
      return rv;
  } while (rv > 0);

  result->swap(content);
  return OK;
}

}  // namespace net
