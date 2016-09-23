// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_cache.h"

#include <stdint.h>

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/format_macros.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/test/simple_test_clock.h"
#include "net/base/cache_type.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_endpoint.h"
#include "net/base/load_flags.h"
#include "net/base/load_timing_info.h"
#include "net/base/load_timing_info_test_util.h"
#include "net/base/net_errors.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/x509_certificate.h"
#include "net/disk_cache/disk_cache.h"
#include "net/http/http_byte_range.h"
#include "net/http/http_cache_transaction.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_transaction.h"
#include "net/http/http_transaction_test_util.h"
#include "net/http/http_util.h"
#include "net/http/mock_http_cache.h"
#include "net/log/net_log_event_type.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/log/test_net_log_util.h"
#include "net/socket/client_socket_handle.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/websockets/websocket_handshake_stream_base.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

using base::Time;

namespace net {

using CacheEntryStatus = HttpResponseInfo::CacheEntryStatus;

namespace {

// Tests the load timing values of a request that goes through a
// MockNetworkTransaction.
void TestLoadTimingNetworkRequest(const LoadTimingInfo& load_timing_info) {
  EXPECT_FALSE(load_timing_info.socket_reused);
  EXPECT_NE(NetLog::Source::kInvalidId, load_timing_info.socket_log_id);

  EXPECT_TRUE(load_timing_info.proxy_resolve_start.is_null());
  EXPECT_TRUE(load_timing_info.proxy_resolve_end.is_null());

  ExpectConnectTimingHasTimes(load_timing_info.connect_timing,
                              CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);
  EXPECT_LE(load_timing_info.connect_timing.connect_end,
            load_timing_info.send_start);

  EXPECT_LE(load_timing_info.send_start, load_timing_info.send_end);

  // Set by URLRequest / URLRequestHttpJob, at a higher level.
  EXPECT_TRUE(load_timing_info.request_start_time.is_null());
  EXPECT_TRUE(load_timing_info.request_start.is_null());
  EXPECT_TRUE(load_timing_info.receive_headers_end.is_null());
}

// Tests the load timing values of a request that receives a cached response.
void TestLoadTimingCachedResponse(const LoadTimingInfo& load_timing_info) {
  EXPECT_FALSE(load_timing_info.socket_reused);
  EXPECT_EQ(NetLog::Source::kInvalidId, load_timing_info.socket_log_id);

  EXPECT_TRUE(load_timing_info.proxy_resolve_start.is_null());
  EXPECT_TRUE(load_timing_info.proxy_resolve_end.is_null());

  ExpectConnectTimingHasNoTimes(load_timing_info.connect_timing);

  // Only the send start / end times should be sent, and they should have the
  // same value.
  EXPECT_FALSE(load_timing_info.send_start.is_null());
  EXPECT_EQ(load_timing_info.send_start, load_timing_info.send_end);

  // Set by URLRequest / URLRequestHttpJob, at a higher level.
  EXPECT_TRUE(load_timing_info.request_start_time.is_null());
  EXPECT_TRUE(load_timing_info.request_start.is_null());
  EXPECT_TRUE(load_timing_info.receive_headers_end.is_null());
}

class DeleteCacheCompletionCallback : public TestCompletionCallbackBase {
 public:
  explicit DeleteCacheCompletionCallback(MockHttpCache* cache)
      : cache_(cache),
        callback_(base::Bind(&DeleteCacheCompletionCallback::OnComplete,
                             base::Unretained(this))) {
  }

  const CompletionCallback& callback() const { return callback_; }

 private:
  void OnComplete(int result) {
    delete cache_;
    SetResult(result);
  }

  MockHttpCache* cache_;
  CompletionCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(DeleteCacheCompletionCallback);
};

//-----------------------------------------------------------------------------
// helpers

void ReadAndVerifyTransaction(HttpTransaction* trans,
                              const MockTransaction& trans_info) {
  std::string content;
  int rv = ReadTransaction(trans, &content);

  EXPECT_THAT(rv, IsOk());
  std::string expected(trans_info.data);
  EXPECT_EQ(expected, content);
}

void RunTransactionTestBase(HttpCache* cache,
                            const MockTransaction& trans_info,
                            const MockHttpRequest& request,
                            HttpResponseInfo* response_info,
                            const NetLogWithSource& net_log,
                            LoadTimingInfo* load_timing_info,
                            int64_t* sent_bytes,
                            int64_t* received_bytes,
                            IPEndPoint* remote_endpoint) {
  TestCompletionCallback callback;

  // write to the cache

  std::unique_ptr<HttpTransaction> trans;
  int rv = cache->CreateTransaction(DEFAULT_PRIORITY, &trans);
  EXPECT_THAT(rv, IsOk());
  ASSERT_TRUE(trans.get());

  rv = trans->Start(&request, callback.callback(), net_log);
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  ASSERT_EQ(trans_info.return_code, rv);

  if (OK != rv)
    return;

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);

  if (response_info)
    *response_info = *response;

  if (load_timing_info) {
    // If a fake network connection is used, need a NetLog to get a fake socket
    // ID.
    EXPECT_TRUE(net_log.net_log());
    *load_timing_info = LoadTimingInfo();
    trans->GetLoadTimingInfo(load_timing_info);
  }

  if (remote_endpoint)
    ASSERT_TRUE(trans->GetRemoteEndpoint(remote_endpoint));

  ReadAndVerifyTransaction(trans.get(), trans_info);

  if (sent_bytes)
    *sent_bytes = trans->GetTotalSentBytes();
  if (received_bytes)
    *received_bytes = trans->GetTotalReceivedBytes();
}

void RunTransactionTestWithRequest(HttpCache* cache,
                                   const MockTransaction& trans_info,
                                   const MockHttpRequest& request,
                                   HttpResponseInfo* response_info) {
  RunTransactionTestBase(cache, trans_info, request, response_info,
                         NetLogWithSource(), nullptr, nullptr, nullptr,
                         nullptr);
}

void RunTransactionTestAndGetTiming(HttpCache* cache,
                                    const MockTransaction& trans_info,
                                    const NetLogWithSource& log,
                                    LoadTimingInfo* load_timing_info) {
  RunTransactionTestBase(cache, trans_info, MockHttpRequest(trans_info),
                         nullptr, log, load_timing_info, nullptr, nullptr,
                         nullptr);
}

void RunTransactionTestAndGetTimingAndConnectedSocketAddress(
    HttpCache* cache,
    const MockTransaction& trans_info,
    const NetLogWithSource& log,
    LoadTimingInfo* load_timing_info,
    IPEndPoint* remote_endpoint) {
  RunTransactionTestBase(cache, trans_info, MockHttpRequest(trans_info),
                         nullptr, log, load_timing_info, nullptr, nullptr,
                         remote_endpoint);
}

void RunTransactionTest(HttpCache* cache, const MockTransaction& trans_info) {
  RunTransactionTestAndGetTiming(cache, trans_info, NetLogWithSource(),
                                 nullptr);
}

void RunTransactionTestWithLog(HttpCache* cache,
                               const MockTransaction& trans_info,
                               const NetLogWithSource& log) {
  RunTransactionTestAndGetTiming(cache, trans_info, log, nullptr);
}

void RunTransactionTestWithResponseInfo(HttpCache* cache,
                                        const MockTransaction& trans_info,
                                        HttpResponseInfo* response) {
  RunTransactionTestWithRequest(cache, trans_info, MockHttpRequest(trans_info),
                                response);
}

void RunTransactionTestWithResponseInfoAndGetTiming(
    HttpCache* cache,
    const MockTransaction& trans_info,
    HttpResponseInfo* response,
    const NetLogWithSource& log,
    LoadTimingInfo* load_timing_info) {
  RunTransactionTestBase(cache, trans_info, MockHttpRequest(trans_info),
                         response, log, load_timing_info, nullptr, nullptr,
                         nullptr);
}

void RunTransactionTestWithResponse(HttpCache* cache,
                                    const MockTransaction& trans_info,
                                    std::string* response_headers) {
  HttpResponseInfo response;
  RunTransactionTestWithResponseInfo(cache, trans_info, &response);
  response.headers->GetNormalizedHeaders(response_headers);
}

void RunTransactionTestWithResponseAndGetTiming(
    HttpCache* cache,
    const MockTransaction& trans_info,
    std::string* response_headers,
    const NetLogWithSource& log,
    LoadTimingInfo* load_timing_info) {
  HttpResponseInfo response;
  RunTransactionTestBase(cache, trans_info, MockHttpRequest(trans_info),
                         &response, log, load_timing_info, nullptr, nullptr,
                         nullptr);
  response.headers->GetNormalizedHeaders(response_headers);
}

// This class provides a handler for kFastNoStoreGET_Transaction so that the
// no-store header can be included on demand.
class FastTransactionServer {
 public:
  FastTransactionServer() {
    no_store = false;
  }
  ~FastTransactionServer() {}

  void set_no_store(bool value) { no_store = value; }

  static void FastNoStoreHandler(const HttpRequestInfo* request,
                                 std::string* response_status,
                                 std::string* response_headers,
                                 std::string* response_data) {
    if (no_store)
      *response_headers = "Cache-Control: no-store\n";
  }

 private:
  static bool no_store;
  DISALLOW_COPY_AND_ASSIGN(FastTransactionServer);
};
bool FastTransactionServer::no_store;

const MockTransaction kFastNoStoreGET_Transaction = {
    "http://www.google.com/nostore",
    "GET",
    base::Time(),
    "",
    LOAD_VALIDATE_CACHE,
    "HTTP/1.1 200 OK",
    "Cache-Control: max-age=10000\n",
    base::Time(),
    "<html><body>Google Blah Blah</body></html>",
    TEST_MODE_SYNC_NET_START,
    &FastTransactionServer::FastNoStoreHandler,
    nullptr,
    nullptr,
    0,
    0,
    OK};

// This class provides a handler for kRangeGET_TransactionOK so that the range
// request can be served on demand.
class RangeTransactionServer {
 public:
  RangeTransactionServer() {
    not_modified_ = false;
    modified_ = false;
    bad_200_ = false;
  }
  ~RangeTransactionServer() {
    not_modified_ = false;
    modified_ = false;
    bad_200_ = false;
  }

  // Returns only 416 or 304 when set.
  void set_not_modified(bool value) { not_modified_ = value; }

  // Returns 206 when revalidating a range (instead of 304).
  void set_modified(bool value) { modified_ = value; }

  // Returns 200 instead of 206 (a malformed response overall).
  void set_bad_200(bool value) { bad_200_ = value; }

  // Other than regular range related behavior (and the flags mentioned above),
  // the server reacts to requests headers like so:
  //   X-Require-Mock-Auth -> return 401.
  //   X-Require-Mock-Auth-Alt -> return 401.
  //   X-Return-Default-Range -> assume 40-49 was requested.
  // The -Alt variant doesn't cause the MockNetworkTransaction to
  // report that it IsReadyToRestartForAuth().
  static void RangeHandler(const HttpRequestInfo* request,
                           std::string* response_status,
                           std::string* response_headers,
                           std::string* response_data);

 private:
  static bool not_modified_;
  static bool modified_;
  static bool bad_200_;
  DISALLOW_COPY_AND_ASSIGN(RangeTransactionServer);
};
bool RangeTransactionServer::not_modified_ = false;
bool RangeTransactionServer::modified_ = false;
bool RangeTransactionServer::bad_200_ = false;

// A dummy extra header that must be preserved on a given request.

// EXTRA_HEADER_LINE doesn't include a line terminator because it
// will be passed to AddHeaderFromString() which doesn't accept them.
#define EXTRA_HEADER_LINE "Extra: header"

// EXTRA_HEADER contains a line terminator, as expected by
// AddHeadersFromString() (_not_ AddHeaderFromString()).
#define EXTRA_HEADER EXTRA_HEADER_LINE "\r\n"

static const char kExtraHeaderKey[] = "Extra";

// Static.
void RangeTransactionServer::RangeHandler(const HttpRequestInfo* request,
                                          std::string* response_status,
                                          std::string* response_headers,
                                          std::string* response_data) {
  if (request->extra_headers.IsEmpty()) {
    response_status->assign("HTTP/1.1 416 Requested Range Not Satisfiable");
    response_data->clear();
    return;
  }

  // We want to make sure we don't delete extra headers.
  EXPECT_TRUE(request->extra_headers.HasHeader(kExtraHeaderKey));

  bool require_auth =
      request->extra_headers.HasHeader("X-Require-Mock-Auth") ||
      request->extra_headers.HasHeader("X-Require-Mock-Auth-Alt");

  if (require_auth && !request->extra_headers.HasHeader("Authorization")) {
    response_status->assign("HTTP/1.1 401 Unauthorized");
    response_data->assign("WWW-Authenticate: Foo\n");
    return;
  }

  if (not_modified_) {
    response_status->assign("HTTP/1.1 304 Not Modified");
    response_data->clear();
    return;
  }

  std::vector<HttpByteRange> ranges;
  std::string range_header;
  if (!request->extra_headers.GetHeader(HttpRequestHeaders::kRange,
                                        &range_header) ||
      !HttpUtil::ParseRangeHeader(range_header, &ranges) || bad_200_ ||
      ranges.size() != 1) {
    // This is not a byte range request. We return 200.
    response_status->assign("HTTP/1.1 200 OK");
    response_headers->assign("Date: Wed, 28 Nov 2007 09:40:09 GMT");
    response_data->assign("Not a range");
    return;
  }

  // We can handle this range request.
  HttpByteRange byte_range = ranges[0];

  if (request->extra_headers.HasHeader("X-Return-Default-Range")) {
    byte_range.set_first_byte_position(40);
    byte_range.set_last_byte_position(49);
  }

  if (byte_range.first_byte_position() > 79) {
    response_status->assign("HTTP/1.1 416 Requested Range Not Satisfiable");
    response_data->clear();
    return;
  }

  EXPECT_TRUE(byte_range.ComputeBounds(80));
  int start = static_cast<int>(byte_range.first_byte_position());
  int end = static_cast<int>(byte_range.last_byte_position());

  EXPECT_LT(end, 80);

  std::string content_range = base::StringPrintf(
      "Content-Range: bytes %d-%d/80\n", start, end);
  response_headers->append(content_range);

  if (!request->extra_headers.HasHeader("If-None-Match") || modified_) {
    std::string data;
    if (end == start) {
      EXPECT_EQ(0, end % 10);
      data = "r";
    } else {
      EXPECT_EQ(9, (end - start) % 10);
      for (int block_start = start; block_start < end; block_start += 10) {
        base::StringAppendF(&data, "rg: %02d-%02d ",
                            block_start, block_start + 9);
      }
    }
    *response_data = data;

    if (end - start != 9) {
      // We also have to fix content-length.
      int len = end - start + 1;
      std::string content_length = base::StringPrintf("Content-Length: %d\n",
                                                      len);
      response_headers->replace(response_headers->find("Content-Length:"),
                                content_length.size(), content_length);
    }
  } else {
    response_status->assign("HTTP/1.1 304 Not Modified");
    response_data->clear();
  }
}

const MockTransaction kRangeGET_TransactionOK = {
    "http://www.google.com/range", "GET", base::Time(),
    "Range: bytes = 40-49\r\n" EXTRA_HEADER, LOAD_NORMAL,
    "HTTP/1.1 206 Partial Content",
    "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
    "ETag: \"foo\"\n"
    "Accept-Ranges: bytes\n"
    "Content-Length: 10\n",
    base::Time(), "rg: 40-49 ", TEST_MODE_NORMAL,
    &RangeTransactionServer::RangeHandler, nullptr, nullptr, 0, 0, OK};

const char kFullRangeData[] =
    "rg: 00-09 rg: 10-19 rg: 20-29 rg: 30-39 "
    "rg: 40-49 rg: 50-59 rg: 60-69 rg: 70-79 ";

// Verifies the response headers (|response|) match a partial content
// response for the range starting at |start| and ending at |end|.
void Verify206Response(const std::string& response, int start, int end) {
  std::string raw_headers(
      HttpUtil::AssembleRawHeaders(response.data(), response.size()));
  scoped_refptr<HttpResponseHeaders> headers(
      new HttpResponseHeaders(raw_headers));

  ASSERT_EQ(206, headers->response_code());

  int64_t range_start, range_end, object_size;
  ASSERT_TRUE(
      headers->GetContentRange(&range_start, &range_end, &object_size));
  int64_t content_length = headers->GetContentLength();

  int length = end - start + 1;
  ASSERT_EQ(length, content_length);
  ASSERT_EQ(start, range_start);
  ASSERT_EQ(end, range_end);
}

// Creates a truncated entry that can be resumed using byte ranges.
void CreateTruncatedEntry(std::string raw_headers, MockHttpCache* cache) {
  // Create a disk cache entry that stores an incomplete resource.
  disk_cache::Entry* entry;
  ASSERT_TRUE(cache->CreateBackendEntry(kRangeGET_TransactionOK.url, &entry,
                                        NULL));

  raw_headers =
      HttpUtil::AssembleRawHeaders(raw_headers.data(), raw_headers.size());

  HttpResponseInfo response;
  response.response_time = base::Time::Now();
  response.request_time = base::Time::Now();
  response.headers = new HttpResponseHeaders(raw_headers);
  // Set the last argument for this to be an incomplete request.
  EXPECT_TRUE(MockHttpCache::WriteResponseInfo(entry, &response, true, true));

  scoped_refptr<IOBuffer> buf(new IOBuffer(100));
  int len = static_cast<int>(base::strlcpy(buf->data(),
                                           "rg: 00-09 rg: 10-19 ", 100));
  TestCompletionCallback cb;
  int rv = entry->WriteData(1, 0, buf.get(), len, cb.callback(), true);
  EXPECT_EQ(len, cb.GetResult(rv));
  entry->Close();
}

// Verifies that there's an entry with this |key| with the truncated flag set to
// |flag_value|, and with an optional |data_size| (if not zero).
void VerifyTruncatedFlag(MockHttpCache* cache,
                         const std::string& key,
                         bool flag_value,
                         int data_size) {
  disk_cache::Entry* entry;
  ASSERT_TRUE(cache->OpenBackendEntry(key, &entry));
  disk_cache::ScopedEntryPtr closer(entry);

  HttpResponseInfo response;
  bool truncated = !flag_value;
  EXPECT_TRUE(MockHttpCache::ReadResponseInfo(entry, &response, &truncated));
  EXPECT_EQ(flag_value, truncated);
  if (data_size)
    EXPECT_EQ(data_size, entry->GetDataSize(1));
}

// Helper to represent a network HTTP response.
struct Response {
  // Set this response into |trans|.
  void AssignTo(MockTransaction* trans) const {
    trans->status = status;
    trans->response_headers = headers;
    trans->data = body;
  }

  std::string status_and_headers() const {
    return std::string(status) + "\n" + std::string(headers);
  }

  const char* status;
  const char* headers;
  const char* body;
};

struct Context {
  Context() : result(ERR_IO_PENDING) {}

  int result;
  TestCompletionCallback callback;
  std::unique_ptr<HttpTransaction> trans;
};

class FakeWebSocketHandshakeStreamCreateHelper
    : public WebSocketHandshakeStreamBase::CreateHelper {
 public:
  ~FakeWebSocketHandshakeStreamCreateHelper() override {}
  WebSocketHandshakeStreamBase* CreateBasicStream(
      std::unique_ptr<ClientSocketHandle> connect,
      bool using_proxy) override {
    return NULL;
  }
  WebSocketHandshakeStreamBase* CreateSpdyStream(
      const base::WeakPtr<SpdySession>& session,
      bool use_relative_url) override {
    return NULL;
  }
};

// Returns true if |entry| is not one of the log types paid attention to in this
// test. Note that HTTP_CACHE_WRITE_INFO and HTTP_CACHE_*_DATA are
// ignored.
bool ShouldIgnoreLogEntry(const TestNetLogEntry& entry) {
  switch (entry.type) {
    case NetLogEventType::HTTP_CACHE_GET_BACKEND:
    case NetLogEventType::HTTP_CACHE_OPEN_ENTRY:
    case NetLogEventType::HTTP_CACHE_CREATE_ENTRY:
    case NetLogEventType::HTTP_CACHE_ADD_TO_ENTRY:
    case NetLogEventType::HTTP_CACHE_DOOM_ENTRY:
    case NetLogEventType::HTTP_CACHE_READ_INFO:
      return false;
    default:
      return true;
  }
}

// Modifies |entries| to only include log entries created by the cache layer and
// asserted on in these tests.
void FilterLogEntries(TestNetLogEntry::List* entries) {
  entries->erase(std::remove_if(entries->begin(), entries->end(),
                                &ShouldIgnoreLogEntry),
                 entries->end());
}

bool LogContainsEventType(const BoundTestNetLog& log,
                          NetLogEventType expected) {
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  for (size_t i = 0; i < entries.size(); i++) {
    if (entries[i].type == expected)
      return true;
  }
  return false;
}

}  // namespace


//-----------------------------------------------------------------------------
// Tests.

TEST(HttpCache, CreateThenDestroy) {
  MockHttpCache cache;

  std::unique_ptr<HttpTransaction> trans;
  EXPECT_THAT(cache.CreateTransaction(&trans), IsOk());
  ASSERT_TRUE(trans.get());
}

TEST(HttpCache, GetBackend) {
  MockHttpCache cache(HttpCache::DefaultBackend::InMemory(0));

  disk_cache::Backend* backend;
  TestCompletionCallback cb;
  // This will lazily initialize the backend.
  int rv = cache.http_cache()->GetBackend(&backend, cb.callback());
  EXPECT_THAT(cb.GetResult(rv), IsOk());
}

TEST(HttpCache, SimpleGET) {
  MockHttpCache cache;
  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;

  // Write to the cache.
  RunTransactionTestAndGetTiming(cache.http_cache(), kSimpleGET_Transaction,
                                 log.bound(), &load_timing_info);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

TEST(HttpCache, SimpleGETNoDiskCache) {
  MockHttpCache cache;

  cache.disk_cache()->set_fail_requests();

  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;

  // Read from the network, and don't use the cache.
  RunTransactionTestAndGetTiming(cache.http_cache(), kSimpleGET_Transaction,
                                 log.bound(), &load_timing_info);

  // Check that the NetLog was filled as expected.
  // (We attempted to both Open and Create entries, but both failed).
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  FilterLogEntries(&entries);

  EXPECT_EQ(6u, entries.size());
  EXPECT_TRUE(LogContainsBeginEvent(entries, 0,
                                    NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 1, NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 2,
                                    NetLogEventType::HTTP_CACHE_OPEN_ENTRY));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 3, NetLogEventType::HTTP_CACHE_OPEN_ENTRY));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 4,
                                    NetLogEventType::HTTP_CACHE_CREATE_ENTRY));
  EXPECT_TRUE(LogContainsEndEvent(entries, 5,
                                  NetLogEventType::HTTP_CACHE_CREATE_ENTRY));

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

TEST(HttpCache, SimpleGETNoDiskCache2) {
  // This will initialize a cache object with NULL backend.
  std::unique_ptr<MockBlockingBackendFactory> factory(
      new MockBlockingBackendFactory());
  factory->set_fail(true);
  factory->FinishCreation();  // We'll complete synchronously.
  MockHttpCache cache(std::move(factory));

  // Read from the network, and don't use the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_FALSE(cache.http_cache()->GetCurrentBackend());
}

// Tests that IOBuffers are not referenced after IO completes.
TEST(HttpCache, ReleaseBuffer) {
  MockHttpCache cache;

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  MockHttpRequest request(kSimpleGET_Transaction);
  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

  const int kBufferSize = 10;
  scoped_refptr<IOBuffer> buffer(new IOBuffer(kBufferSize));
  ReleaseBufferCompletionCallback cb(buffer.get());

  int rv = trans->Start(&request, cb.callback(), NetLogWithSource());
  EXPECT_THAT(cb.GetResult(rv), IsOk());

  rv = trans->Read(buffer.get(), kBufferSize, cb.callback());
  EXPECT_EQ(kBufferSize, cb.GetResult(rv));
}

TEST(HttpCache, SimpleGETWithDiskFailures) {
  MockHttpCache cache;

  cache.disk_cache()->set_soft_failures(true);

  // Read from the network, and fail to write to the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // This one should see an empty cache again.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that disk failures after the transaction has started don't cause the
// request to fail.
TEST(HttpCache, SimpleGETWithDiskFailures2) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  std::unique_ptr<Context> c(new Context());
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = c->callback.WaitForResult();

  // Start failing request now.
  cache.disk_cache()->set_soft_failures(true);

  // We have to open the entry again to propagate the failure flag.
  disk_cache::Entry* en;
  ASSERT_TRUE(cache.OpenBackendEntry(kSimpleGET_Transaction.url, &en));
  en->Close();

  ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
  c.reset();

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // This one should see an empty cache again.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we handle failures to read from the cache.
TEST(HttpCache, SimpleGETWithDiskFailures3) {
  MockHttpCache cache;

  // Read from the network, and write to the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  cache.disk_cache()->set_soft_failures(true);

  // Now fail to read from the cache.
  std::unique_ptr<Context> c(new Context());
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  MockHttpRequest request(kSimpleGET_Transaction);
  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(c->callback.GetResult(rv), IsOk());

  // Now verify that the entry was removed from the cache.
  cache.disk_cache()->set_soft_failures(false);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(3, cache.disk_cache()->create_count());
}

TEST(HttpCache, SimpleGET_LoadOnlyFromCache_Hit) {
  MockHttpCache cache;

  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;

  // Write to the cache.
  RunTransactionTestAndGetTiming(cache.http_cache(), kSimpleGET_Transaction,
                                 log.bound(), &load_timing_info);

  // Check that the NetLog was filled as expected.
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  FilterLogEntries(&entries);

  EXPECT_EQ(8u, entries.size());
  EXPECT_TRUE(LogContainsBeginEvent(entries, 0,
                                    NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 1, NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 2,
                                    NetLogEventType::HTTP_CACHE_OPEN_ENTRY));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 3, NetLogEventType::HTTP_CACHE_OPEN_ENTRY));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 4,
                                    NetLogEventType::HTTP_CACHE_CREATE_ENTRY));
  EXPECT_TRUE(LogContainsEndEvent(entries, 5,
                                  NetLogEventType::HTTP_CACHE_CREATE_ENTRY));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 6,
                                    NetLogEventType::HTTP_CACHE_ADD_TO_ENTRY));
  EXPECT_TRUE(LogContainsEndEvent(entries, 7,
                                  NetLogEventType::HTTP_CACHE_ADD_TO_ENTRY));

  TestLoadTimingNetworkRequest(load_timing_info);

  // Force this transaction to read from the cache.
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE;

  log.Clear();

  RunTransactionTestAndGetTiming(cache.http_cache(), transaction, log.bound(),
                                 &load_timing_info);

  // Check that the NetLog was filled as expected.
  log.GetEntries(&entries);
  FilterLogEntries(&entries);

  EXPECT_EQ(8u, entries.size());
  EXPECT_TRUE(LogContainsBeginEvent(entries, 0,
                                    NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 1, NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 2,
                                    NetLogEventType::HTTP_CACHE_OPEN_ENTRY));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 3, NetLogEventType::HTTP_CACHE_OPEN_ENTRY));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 4,
                                    NetLogEventType::HTTP_CACHE_ADD_TO_ENTRY));
  EXPECT_TRUE(LogContainsEndEvent(entries, 5,
                                  NetLogEventType::HTTP_CACHE_ADD_TO_ENTRY));
  EXPECT_TRUE(
      LogContainsBeginEvent(entries, 6, NetLogEventType::HTTP_CACHE_READ_INFO));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 7, NetLogEventType::HTTP_CACHE_READ_INFO));

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingCachedResponse(load_timing_info);
}

TEST(HttpCache, SimpleGET_LoadOnlyFromCache_Miss) {
  MockHttpCache cache;

  // force this transaction to read from the cache
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE;

  MockHttpRequest request(transaction);
  TestCompletionCallback callback;

  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_CACHE_MISS));

  trans.reset();

  EXPECT_EQ(0, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

TEST(HttpCache, SimpleGET_LoadPreferringCache_Hit) {
  MockHttpCache cache;

  // write to the cache
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // force this transaction to read from the cache if valid
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_PREFERRING_CACHE;

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

TEST(HttpCache, SimpleGET_LoadPreferringCache_Miss) {
  MockHttpCache cache;

  // force this transaction to read from the cache if valid
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_PREFERRING_CACHE;

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests LOAD_PREFERRING_CACHE in the presence of vary headers.
TEST(HttpCache, SimpleGET_LoadPreferringCache_VaryMatch) {
  MockHttpCache cache;

  // Write to the cache.
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers = "Cache-Control: max-age=10000\n"
                                 "Vary: Foo\n";
  AddMockTransaction(&transaction);
  RunTransactionTest(cache.http_cache(), transaction);

  // Read from the cache.
  transaction.load_flags |= LOAD_PREFERRING_CACHE;
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

// Tests LOAD_PREFERRING_CACHE in the presence of vary headers.
TEST(HttpCache, SimpleGET_LoadPreferringCache_VaryMismatch) {
  MockHttpCache cache;

  // Write to the cache.
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers = "Cache-Control: max-age=10000\n"
                                 "Vary: Foo\n";
  AddMockTransaction(&transaction);
  RunTransactionTest(cache.http_cache(), transaction);

  // Attempt to read from the cache... this is a vary mismatch that must reach
  // the network again.
  transaction.load_flags |= LOAD_PREFERRING_CACHE;
  transaction.request_headers = "Foo: none\r\n";
  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;
  RunTransactionTestAndGetTiming(cache.http_cache(), transaction, log.bound(),
                                 &load_timing_info);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
  RemoveMockTransaction(&transaction);
}

// Tests that was_cached was set properly on a failure, even if the cached
// response wasn't returned.
TEST(HttpCache, SimpleGET_CacheSignal_Failure) {
  MockHttpCache cache;

  // Prime cache.
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers = "Cache-Control: no-cache\n";

  AddMockTransaction(&transaction);
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);

  // Network failure with error; should fail but have was_cached set.
  transaction.return_code = ERR_FAILED;
  AddMockTransaction(&transaction);

  MockHttpRequest request(transaction);
  TestCompletionCallback callback;
  std::unique_ptr<HttpTransaction> trans;
  int rv = cache.http_cache()->CreateTransaction(DEFAULT_PRIORITY, &trans);
  EXPECT_THAT(rv, IsOk());
  ASSERT_TRUE(trans.get());
  rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_FAILED));

  const HttpResponseInfo* response_info = trans->GetResponseInfo();
  ASSERT_TRUE(response_info);
  EXPECT_TRUE(response_info->was_cached);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());

  RemoveMockTransaction(&transaction);
}

// Confirm if we have an empty cache, a read is marked as network verified.
TEST(HttpCache, SimpleGET_NetworkAccessed_Network) {
  MockHttpCache cache;

  // write to the cache
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), kSimpleGET_Transaction,
                                     &response_info);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  EXPECT_TRUE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_NOT_IN_CACHE,
            response_info.cache_entry_status);
}

// Confirm if we have a fresh entry in cache, it isn't marked as
// network verified.
TEST(HttpCache, SimpleGET_NetworkAccessed_Cache) {
  MockHttpCache cache;

  // Prime cache.
  MockTransaction transaction(kSimpleGET_Transaction);

  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Re-run transaction; make sure we don't mark the network as accessed.
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), transaction,
                                     &response_info);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_FALSE(response_info.server_data_unavailable);
  EXPECT_FALSE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_USED, response_info.cache_entry_status);
}

TEST(HttpCache, SimpleGET_LoadBypassCache) {
  MockHttpCache cache;

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // Force this transaction to write to the cache again.
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_BYPASS_CACHE;

  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;

  // Write to the cache.
  RunTransactionTestAndGetTiming(cache.http_cache(), transaction, log.bound(),
                                 &load_timing_info);

  // Check that the NetLog was filled as expected.
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  FilterLogEntries(&entries);

  EXPECT_EQ(8u, entries.size());
  EXPECT_TRUE(LogContainsBeginEvent(entries, 0,
                                    NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 1, NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 2,
                                    NetLogEventType::HTTP_CACHE_DOOM_ENTRY));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 3, NetLogEventType::HTTP_CACHE_DOOM_ENTRY));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 4,
                                    NetLogEventType::HTTP_CACHE_CREATE_ENTRY));
  EXPECT_TRUE(LogContainsEndEvent(entries, 5,
                                  NetLogEventType::HTTP_CACHE_CREATE_ENTRY));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 6,
                                    NetLogEventType::HTTP_CACHE_ADD_TO_ENTRY));
  EXPECT_TRUE(LogContainsEndEvent(entries, 7,
                                  NetLogEventType::HTTP_CACHE_ADD_TO_ENTRY));

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

TEST(HttpCache, SimpleGET_LoadBypassCache_Implicit) {
  MockHttpCache cache;

  // write to the cache
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // force this transaction to write to the cache again
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "pragma: no-cache\r\n";

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

TEST(HttpCache, SimpleGET_LoadBypassCache_Implicit2) {
  MockHttpCache cache;

  // write to the cache
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // force this transaction to write to the cache again
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "cache-control: no-cache\r\n";

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

TEST(HttpCache, SimpleGET_LoadValidateCache) {
  MockHttpCache cache;

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // Read from the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // Force this transaction to validate the cache.
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_VALIDATE_CACHE;

  HttpResponseInfo response_info;
  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), transaction, &response_info, log.bound(),
      &load_timing_info);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  EXPECT_TRUE(response_info.network_accessed);
  TestLoadTimingNetworkRequest(load_timing_info);
}

TEST(HttpCache, SimpleGET_LoadValidateCache_Implicit) {
  MockHttpCache cache;

  // write to the cache
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // read from the cache
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // force this transaction to validate the cache
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "cache-control: max-age=0\r\n";

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

static void PreserveRequestHeaders_Handler(const HttpRequestInfo* request,
                                           std::string* response_status,
                                           std::string* response_headers,
                                           std::string* response_data) {
  EXPECT_TRUE(request->extra_headers.HasHeader(kExtraHeaderKey));
}

// Tests that we don't remove extra headers for simple requests.
TEST(HttpCache, SimpleGET_PreserveRequestHeaders) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.handler = PreserveRequestHeaders_Handler;
  transaction.request_headers = EXTRA_HEADER;
  transaction.response_headers = "Cache-Control: max-age=0\n";
  AddMockTransaction(&transaction);

  // Write, then revalidate the entry.
  RunTransactionTest(cache.http_cache(), transaction);
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

// Tests that we don't remove extra headers for conditionalized requests.
TEST(HttpCache, ConditionalizedGET_PreserveRequestHeaders) {
  MockHttpCache cache;

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), kETagGET_Transaction);

  MockTransaction transaction(kETagGET_Transaction);
  transaction.handler = PreserveRequestHeaders_Handler;
  transaction.request_headers = "If-None-Match: \"foopy\"\r\n"
                                EXTRA_HEADER;
  AddMockTransaction(&transaction);

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

TEST(HttpCache, SimpleGET_ManyReaders) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  std::vector<Context*> context_list;
  const int kNumTransactions = 5;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(new Context());
    Context* c = context_list[i];

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());

    c->result =
        c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  }

  // All requests are waiting for the active entry.
  for (int i = 0; i < kNumTransactions; ++i) {
    Context* c = context_list[i];
    EXPECT_EQ(LOAD_STATE_WAITING_FOR_CACHE, c->trans->GetLoadState());
  }

  // Allow all requests to move from the Create queue to the active entry.
  base::RunLoop().RunUntilIdle();

  // The first request should be a writer at this point, and the subsequent
  // requests should be pending.

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // All requests depend on the writer, and the writer is between Start and
  // Read, i.e. idle.
  for (int i = 0; i < kNumTransactions; ++i) {
    Context* c = context_list[i];
    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());
  }

  for (int i = 0; i < kNumTransactions; ++i) {
    Context* c = context_list[i];
    if (c->result == ERR_IO_PENDING)
      c->result = c->callback.WaitForResult();
    ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
  }

  // We should not have had to re-open the disk entry

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  for (int i = 0; i < kNumTransactions; ++i) {
    Context* c = context_list[i];
    delete c;
  }
}

// This is a test for http://code.google.com/p/chromium/issues/detail?id=4769.
// If cancelling a request is racing with another request for the same resource
// finishing, we have to make sure that we remove both transactions from the
// entry.
TEST(HttpCache, SimpleGET_RacingReaders) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);
  MockHttpRequest reader_request(kSimpleGET_Transaction);
  reader_request.load_flags = LOAD_ONLY_FROM_CACHE;

  std::vector<Context*> context_list;
  const int kNumTransactions = 5;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(new Context());
    Context* c = context_list[i];

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    MockHttpRequest* this_request = &request;
    if (i == 1 || i == 2)
      this_request = &reader_request;

    c->result = c->trans->Start(this_request, c->callback.callback(),
                                NetLogWithSource());
  }

  // Allow all requests to move from the Create queue to the active entry.
  base::RunLoop().RunUntilIdle();

  // The first request should be a writer at this point, and the subsequent
  // requests should be pending.

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  Context* c = context_list[0];
  ASSERT_THAT(c->result, IsError(ERR_IO_PENDING));
  c->result = c->callback.WaitForResult();
  ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);

  // Now we have 2 active readers and two queued transactions.

  EXPECT_EQ(LOAD_STATE_IDLE, context_list[2]->trans->GetLoadState());
  EXPECT_EQ(LOAD_STATE_WAITING_FOR_CACHE,
            context_list[3]->trans->GetLoadState());

  c = context_list[1];
  ASSERT_THAT(c->result, IsError(ERR_IO_PENDING));
  c->result = c->callback.WaitForResult();
  if (c->result == OK)
    ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);

  // At this point we have one reader, two pending transactions and a task on
  // the queue to move to the next transaction. Now we cancel the request that
  // is the current reader, and expect the queued task to be able to start the
  // next request.

  c = context_list[2];
  c->trans.reset();

  for (int i = 3; i < kNumTransactions; ++i) {
    Context* c = context_list[i];
    if (c->result == ERR_IO_PENDING)
      c->result = c->callback.WaitForResult();
    if (c->result == OK)
      ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
  }

  // We should not have had to re-open the disk entry.

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  for (int i = 0; i < kNumTransactions; ++i) {
    Context* c = context_list[i];
    delete c;
  }
}

// Tests that we can doom an entry with pending transactions and delete one of
// the pending transactions before the first one completes.
// See http://code.google.com/p/chromium/issues/detail?id=25588
TEST(HttpCache, SimpleGET_DoomWithPending) {
  // We need simultaneous doomed / not_doomed entries so let's use a real cache.
  MockHttpCache cache(HttpCache::DefaultBackend::InMemory(1024 * 1024));

  MockHttpRequest request(kSimpleGET_Transaction);
  MockHttpRequest writer_request(kSimpleGET_Transaction);
  writer_request.load_flags = LOAD_BYPASS_CACHE;

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 4;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(base::WrapUnique(new Context()));
    Context* c = context_list[i].get();

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    MockHttpRequest* this_request = &request;
    if (i == 3)
      this_request = &writer_request;

    c->result = c->trans->Start(this_request, c->callback.callback(),
                                NetLogWithSource());
  }

  // The first request should be a writer at this point, and the two subsequent
  // requests should be pending. The last request doomed the first entry.

  EXPECT_EQ(2, cache.network_layer()->transaction_count());

  // Cancel the first queued transaction.
  context_list[1].reset();

  for (int i = 0; i < kNumTransactions; ++i) {
    if (i == 1)
      continue;
    Context* c = context_list[i].get();
    ASSERT_THAT(c->result, IsError(ERR_IO_PENDING));
    c->result = c->callback.WaitForResult();
    ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
  }
}

// This is a test for http://code.google.com/p/chromium/issues/detail?id=4731.
// We may attempt to delete an entry synchronously with the act of adding a new
// transaction to said entry.
TEST(HttpCache, FastNoStoreGET_DoneWithPending) {
  MockHttpCache cache;

  // The headers will be served right from the call to Start() the request.
  MockHttpRequest request(kFastNoStoreGET_Transaction);
  FastTransactionServer request_handler;
  AddMockTransaction(&kFastNoStoreGET_Transaction);

  std::vector<Context*> context_list;
  const int kNumTransactions = 3;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(new Context());
    Context* c = context_list[i];

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    c->result =
        c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  }

  // Allow all requests to move from the Create queue to the active entry.
  base::RunLoop().RunUntilIdle();

  // The first request should be a writer at this point, and the subsequent
  // requests should be pending.

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now, make sure that the second request asks for the entry not to be stored.
  request_handler.set_no_store(true);

  for (int i = 0; i < kNumTransactions; ++i) {
    Context* c = context_list[i];
    if (c->result == ERR_IO_PENDING)
      c->result = c->callback.WaitForResult();
    ReadAndVerifyTransaction(c->trans.get(), kFastNoStoreGET_Transaction);
    delete c;
  }

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  RemoveMockTransaction(&kFastNoStoreGET_Transaction);
}

TEST(HttpCache, SimpleGET_ManyWriters_CancelFirst) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  std::vector<Context*> context_list;
  const int kNumTransactions = 2;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(new Context());
    Context* c = context_list[i];

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    c->result =
        c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  }

  // Allow all requests to move from the Create queue to the active entry.
  base::RunLoop().RunUntilIdle();

  // The first request should be a writer at this point, and the subsequent
  // requests should be pending.

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  for (int i = 0; i < kNumTransactions; ++i) {
    Context* c = context_list[i];
    if (c->result == ERR_IO_PENDING)
      c->result = c->callback.WaitForResult();
    // Destroy only the first transaction.
    if (i == 0) {
      delete c;
      context_list[i] = NULL;
    }
  }

  // Complete the rest of the transactions.
  for (int i = 1; i < kNumTransactions; ++i) {
    Context* c = context_list[i];
    ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
  }

  // We should have had to re-open the disk entry.

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  for (int i = 1; i < kNumTransactions; ++i) {
    Context* c = context_list[i];
    delete c;
  }
}

// Tests that we can cancel requests that are queued waiting to open the disk
// cache entry.
TEST(HttpCache, SimpleGET_ManyWriters_CancelCreate) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  std::vector<Context*> context_list;
  const int kNumTransactions = 5;

  for (int i = 0; i < kNumTransactions; i++) {
    context_list.push_back(new Context());
    Context* c = context_list[i];

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    c->result =
        c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  }

  // The first request should be creating the disk cache entry and the others
  // should be pending.

  EXPECT_EQ(0, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Cancel a request from the pending queue.
  delete context_list[3];
  context_list[3] = NULL;

  // Cancel the request that is creating the entry. This will force the pending
  // operations to restart.
  delete context_list[0];
  context_list[0] = NULL;

  // Complete the rest of the transactions.
  for (int i = 1; i < kNumTransactions; i++) {
    Context* c = context_list[i];
    if (c) {
      c->result = c->callback.GetResult(c->result);
      ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
    }
  }

  // We should have had to re-create the disk entry.

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  for (int i = 1; i < kNumTransactions; ++i) {
    delete context_list[i];
  }
}

// Tests that we can cancel a single request to open a disk cache entry.
TEST(HttpCache, SimpleGET_CancelCreate) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  Context* c = new Context();

  c->result = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(c->result, IsOk());

  c->result =
      c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(c->result, IsError(ERR_IO_PENDING));

  // Release the reference that the mock disk cache keeps for this entry, so
  // that we test that the http cache handles the cancellation correctly.
  cache.disk_cache()->ReleaseAll();
  delete c;

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we delete/create entries even if multiple requests are queued.
TEST(HttpCache, SimpleGET_ManyWriters_BypassCache) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);
  request.load_flags = LOAD_BYPASS_CACHE;

  std::vector<Context*> context_list;
  const int kNumTransactions = 5;

  for (int i = 0; i < kNumTransactions; i++) {
    context_list.push_back(new Context());
    Context* c = context_list[i];

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    c->result =
        c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  }

  // The first request should be deleting the disk cache entry and the others
  // should be pending.

  EXPECT_EQ(0, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());

  // Complete the transactions.
  for (int i = 0; i < kNumTransactions; i++) {
    Context* c = context_list[i];
    c->result = c->callback.GetResult(c->result);
    ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
  }

  // We should have had to re-create the disk entry multiple times.

  EXPECT_EQ(5, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(5, cache.disk_cache()->create_count());

  for (int i = 0; i < kNumTransactions; ++i) {
    delete context_list[i];
  }
}

// Tests that a (simulated) timeout allows transactions waiting on the cache
// lock to continue.
TEST(HttpCache, SimpleGET_WriterTimeout) {
  MockHttpCache cache;
  cache.BypassCacheLock();

  MockHttpRequest request(kSimpleGET_Transaction);
  Context c1, c2;
  ASSERT_THAT(cache.CreateTransaction(&c1.trans), IsOk());
  ASSERT_EQ(ERR_IO_PENDING, c1.trans->Start(&request, c1.callback.callback(),
                                            NetLogWithSource()));
  ASSERT_THAT(cache.CreateTransaction(&c2.trans), IsOk());
  ASSERT_EQ(ERR_IO_PENDING, c2.trans->Start(&request, c2.callback.callback(),
                                            NetLogWithSource()));

  // The second request is queued after the first one.

  c2.callback.WaitForResult();
  ReadAndVerifyTransaction(c2.trans.get(), kSimpleGET_Transaction);

  // Complete the first transaction.
  c1.callback.WaitForResult();
  ReadAndVerifyTransaction(c1.trans.get(), kSimpleGET_Transaction);
}

TEST(HttpCache, SimpleGET_AbandonedCacheRead) {
  MockHttpCache cache;

  // write to the cache
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  MockHttpRequest request(kSimpleGET_Transaction);
  TestCompletionCallback callback;

  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  scoped_refptr<IOBuffer> buf(new IOBuffer(256));
  rv = trans->Read(buf.get(), 256, callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Test that destroying the transaction while it is reading from the cache
  // works properly.
  trans.reset();

  // Make sure we pump any pending events, which should include a call to
  // HttpCache::Transaction::OnCacheReadCompleted.
  base::RunLoop().RunUntilIdle();
}

// Tests that we can delete the HttpCache and deal with queued transactions
// ("waiting for the backend" as opposed to Active or Doomed entries).
TEST(HttpCache, SimpleGET_ManyWriters_DeleteCache) {
  std::unique_ptr<MockHttpCache> cache(
      new MockHttpCache(base::WrapUnique(new MockBackendNoCbFactory())));

  MockHttpRequest request(kSimpleGET_Transaction);

  std::vector<Context*> context_list;
  const int kNumTransactions = 5;

  for (int i = 0; i < kNumTransactions; i++) {
    context_list.push_back(new Context());
    Context* c = context_list[i];

    c->result = cache->CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    c->result =
        c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  }

  // The first request should be creating the disk cache entry and the others
  // should be pending.

  EXPECT_EQ(0, cache->network_layer()->transaction_count());
  EXPECT_EQ(0, cache->disk_cache()->open_count());
  EXPECT_EQ(0, cache->disk_cache()->create_count());

  cache.reset();

  // There is not much to do with the transactions at this point... they are
  // waiting for a callback that will not fire.
  for (int i = 0; i < kNumTransactions; ++i) {
    delete context_list[i];
  }
}

// Tests that we queue requests when initializing the backend.
TEST(HttpCache, SimpleGET_WaitForBackend) {
  MockBlockingBackendFactory* factory = new MockBlockingBackendFactory();
  MockHttpCache cache(base::WrapUnique(factory));

  MockHttpRequest request0(kSimpleGET_Transaction);
  MockHttpRequest request1(kTypicalGET_Transaction);
  MockHttpRequest request2(kETagGET_Transaction);

  std::vector<Context*> context_list;
  const int kNumTransactions = 3;

  for (int i = 0; i < kNumTransactions; i++) {
    context_list.push_back(new Context());
    Context* c = context_list[i];

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
  }

  context_list[0]->result = context_list[0]->trans->Start(
      &request0, context_list[0]->callback.callback(), NetLogWithSource());
  context_list[1]->result = context_list[1]->trans->Start(
      &request1, context_list[1]->callback.callback(), NetLogWithSource());
  context_list[2]->result = context_list[2]->trans->Start(
      &request2, context_list[2]->callback.callback(), NetLogWithSource());

  // Just to make sure that everything is still pending.
  base::RunLoop().RunUntilIdle();

  // The first request should be creating the disk cache.
  EXPECT_FALSE(context_list[0]->callback.have_result());

  factory->FinishCreation();

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(3, cache.disk_cache()->create_count());

  for (int i = 0; i < kNumTransactions; ++i) {
    EXPECT_TRUE(context_list[i]->callback.have_result());
    delete context_list[i];
  }
}

// Tests that we can cancel requests that are queued waiting for the backend
// to be initialized.
TEST(HttpCache, SimpleGET_WaitForBackend_CancelCreate) {
  MockBlockingBackendFactory* factory = new MockBlockingBackendFactory();
  MockHttpCache cache(base::WrapUnique(factory));

  MockHttpRequest request0(kSimpleGET_Transaction);
  MockHttpRequest request1(kTypicalGET_Transaction);
  MockHttpRequest request2(kETagGET_Transaction);

  std::vector<Context*> context_list;
  const int kNumTransactions = 3;

  for (int i = 0; i < kNumTransactions; i++) {
    context_list.push_back(new Context());
    Context* c = context_list[i];

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
  }

  context_list[0]->result = context_list[0]->trans->Start(
      &request0, context_list[0]->callback.callback(), NetLogWithSource());
  context_list[1]->result = context_list[1]->trans->Start(
      &request1, context_list[1]->callback.callback(), NetLogWithSource());
  context_list[2]->result = context_list[2]->trans->Start(
      &request2, context_list[2]->callback.callback(), NetLogWithSource());

  // Just to make sure that everything is still pending.
  base::RunLoop().RunUntilIdle();

  // The first request should be creating the disk cache.
  EXPECT_FALSE(context_list[0]->callback.have_result());

  // Cancel a request from the pending queue.
  delete context_list[1];
  context_list[1] = NULL;

  // Cancel the request that is creating the entry.
  delete context_list[0];
  context_list[0] = NULL;

  // Complete the last transaction.
  factory->FinishCreation();

  context_list[2]->result =
      context_list[2]->callback.GetResult(context_list[2]->result);
  ReadAndVerifyTransaction(context_list[2]->trans.get(), kETagGET_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  delete context_list[2];
}

// Tests that we can delete the cache while creating the backend.
TEST(HttpCache, DeleteCacheWaitingForBackend) {
  MockBlockingBackendFactory* factory = new MockBlockingBackendFactory();
  std::unique_ptr<MockHttpCache> cache(
      new MockHttpCache(base::WrapUnique(factory)));

  MockHttpRequest request(kSimpleGET_Transaction);

  std::unique_ptr<Context> c(new Context());
  c->result = cache->CreateTransaction(&c->trans);
  ASSERT_THAT(c->result, IsOk());

  c->trans->Start(&request, c->callback.callback(), NetLogWithSource());

  // Just to make sure that everything is still pending.
  base::RunLoop().RunUntilIdle();

  // The request should be creating the disk cache.
  EXPECT_FALSE(c->callback.have_result());

  // We cannot call FinishCreation because the factory itself will go away with
  // the cache, so grab the callback and attempt to use it.
  CompletionCallback callback = factory->callback();
  std::unique_ptr<disk_cache::Backend>* backend = factory->backend();

  cache.reset();
  base::RunLoop().RunUntilIdle();

  backend->reset();
  callback.Run(ERR_ABORTED);
}

// Tests that we can delete the cache while creating the backend, from within
// one of the callbacks.
TEST(HttpCache, DeleteCacheWaitingForBackend2) {
  MockBlockingBackendFactory* factory = new MockBlockingBackendFactory();
  MockHttpCache* cache = new MockHttpCache(base::WrapUnique(factory));

  DeleteCacheCompletionCallback cb(cache);
  disk_cache::Backend* backend;
  int rv = cache->http_cache()->GetBackend(&backend, cb.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Now let's queue a regular transaction
  MockHttpRequest request(kSimpleGET_Transaction);

  std::unique_ptr<Context> c(new Context());
  c->result = cache->CreateTransaction(&c->trans);
  ASSERT_THAT(c->result, IsOk());

  c->trans->Start(&request, c->callback.callback(), NetLogWithSource());

  // And another direct backend request.
  TestCompletionCallback cb2;
  rv = cache->http_cache()->GetBackend(&backend, cb2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Just to make sure that everything is still pending.
  base::RunLoop().RunUntilIdle();

  // The request should be queued.
  EXPECT_FALSE(c->callback.have_result());

  // Generate the callback.
  factory->FinishCreation();
  rv = cb.WaitForResult();

  // The cache should be gone by now.
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(c->callback.GetResult(c->result), IsOk());
  EXPECT_FALSE(cb2.have_result());
}

// Fails only on bots. crbug.com/533640
#if defined(OS_ANDROID)
#define MAYBE_TypicalGET_ConditionalRequest \
  DISABLED_TypicalGET_ConditionalRequest
#else
#define MAYBE_TypicalGET_ConditionalRequest TypicalGET_ConditionalRequest
#endif
TEST(HttpCache, MAYBE_TypicalGET_ConditionalRequest) {
  MockHttpCache cache;

  // write to the cache
  RunTransactionTest(cache.http_cache(), kTypicalGET_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Get the same URL again, but this time we expect it to result
  // in a conditional request.
  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;
  RunTransactionTestAndGetTiming(cache.http_cache(), kTypicalGET_Transaction,
                                 log.bound(), &load_timing_info);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

static void ETagGet_ConditionalRequest_Handler(const HttpRequestInfo* request,
                                               std::string* response_status,
                                               std::string* response_headers,
                                               std::string* response_data) {
  EXPECT_TRUE(
      request->extra_headers.HasHeader(HttpRequestHeaders::kIfNoneMatch));
  response_status->assign("HTTP/1.1 304 Not Modified");
  response_headers->assign(kETagGET_Transaction.response_headers);
  response_data->clear();
}

TEST(HttpCache, ETagGET_ConditionalRequest_304) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kETagGET_Transaction);

  // write to the cache
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Get the same URL again, but this time we expect it to result
  // in a conditional request.
  transaction.load_flags = LOAD_VALIDATE_CACHE;
  transaction.handler = ETagGet_ConditionalRequest_Handler;
  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;
  IPEndPoint remote_endpoint;
  RunTransactionTestAndGetTimingAndConnectedSocketAddress(
      cache.http_cache(), transaction, log.bound(), &load_timing_info,
      &remote_endpoint);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);

  EXPECT_FALSE(remote_endpoint.address().empty());
}

class RevalidationServer {
 public:
  RevalidationServer() {
    s_etag_used_ = false;
    s_last_modified_used_ = false;
  }

  bool EtagUsed() { return s_etag_used_; }
  bool LastModifiedUsed() { return s_last_modified_used_; }

  static void Handler(const HttpRequestInfo* request,
                      std::string* response_status,
                      std::string* response_headers,
                      std::string* response_data);

 private:
  static bool s_etag_used_;
  static bool s_last_modified_used_;
};
bool RevalidationServer::s_etag_used_ = false;
bool RevalidationServer::s_last_modified_used_ = false;

void RevalidationServer::Handler(const HttpRequestInfo* request,
                                 std::string* response_status,
                                 std::string* response_headers,
                                 std::string* response_data) {
  if (request->extra_headers.HasHeader(HttpRequestHeaders::kIfNoneMatch))
      s_etag_used_ = true;

  if (request->extra_headers.HasHeader(HttpRequestHeaders::kIfModifiedSince)) {
      s_last_modified_used_ = true;
  }

  if (s_etag_used_ || s_last_modified_used_) {
    response_status->assign("HTTP/1.1 304 Not Modified");
    response_headers->assign(kTypicalGET_Transaction.response_headers);
    response_data->clear();
  } else {
    response_status->assign(kTypicalGET_Transaction.status);
    response_headers->assign(kTypicalGET_Transaction.response_headers);
    response_data->assign(kTypicalGET_Transaction.data);
  }
}

// Tests revalidation after a vary match.
TEST(HttpCache, GET_ValidateCache_VaryMatch) {
  MockHttpCache cache;

  // Write to the cache.
  MockTransaction transaction(kTypicalGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers =
      "Date: Wed, 28 Nov 2007 09:40:09 GMT\n"
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=0\n"
      "Vary: Foo\n";
  AddMockTransaction(&transaction);
  RunTransactionTest(cache.http_cache(), transaction);

  // Read from the cache.
  RevalidationServer server;
  transaction.handler = server.Handler;
  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;
  RunTransactionTestAndGetTiming(cache.http_cache(), transaction, log.bound(),
                                 &load_timing_info);

  EXPECT_TRUE(server.EtagUsed());
  EXPECT_TRUE(server.LastModifiedUsed());
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
  RemoveMockTransaction(&transaction);
}

// Tests revalidation after a vary mismatch if etag is present.
TEST(HttpCache, GET_ValidateCache_VaryMismatch) {
  MockHttpCache cache;

  // Write to the cache.
  MockTransaction transaction(kTypicalGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers =
      "Date: Wed, 28 Nov 2007 09:40:09 GMT\n"
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=0\n"
      "Vary: Foo\n";
  AddMockTransaction(&transaction);
  RunTransactionTest(cache.http_cache(), transaction);

  // Read from the cache and revalidate the entry.
  RevalidationServer server;
  transaction.handler = server.Handler;
  transaction.request_headers = "Foo: none\r\n";
  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;
  RunTransactionTestAndGetTiming(cache.http_cache(), transaction, log.bound(),
                                 &load_timing_info);

  EXPECT_TRUE(server.EtagUsed());
  EXPECT_FALSE(server.LastModifiedUsed());
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
  RemoveMockTransaction(&transaction);
}

// Tests lack of revalidation after a vary mismatch and no etag.
TEST(HttpCache, GET_DontValidateCache_VaryMismatch) {
  MockHttpCache cache;

  // Write to the cache.
  MockTransaction transaction(kTypicalGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers =
      "Date: Wed, 28 Nov 2007 09:40:09 GMT\n"
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Cache-Control: max-age=0\n"
      "Vary: Foo\n";
  AddMockTransaction(&transaction);
  RunTransactionTest(cache.http_cache(), transaction);

  // Read from the cache and don't revalidate the entry.
  RevalidationServer server;
  transaction.handler = server.Handler;
  transaction.request_headers = "Foo: none\r\n";
  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;
  RunTransactionTestAndGetTiming(cache.http_cache(), transaction, log.bound(),
                                 &load_timing_info);

  EXPECT_FALSE(server.EtagUsed());
  EXPECT_FALSE(server.LastModifiedUsed());
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
  RemoveMockTransaction(&transaction);
}

// Tests that a new vary header provided when revalidating an entry is saved.
TEST(HttpCache, GET_ValidateCache_VaryMatch_UpdateVary) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kTypicalGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n Name: bar\r\n";
  transaction.response_headers =
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=0\n"
      "Vary: Foo\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Validate the entry and change the vary field in the response.
  transaction.request_headers = "Foo: bar\r\n Name: none\r\n";
  transaction.status = "HTTP/1.1 304 Not Modified";
  transaction.response_headers =
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=3600\n"
      "Vary: Name\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Generate a vary mismatch.
  transaction.request_headers = "Foo: bar\r\n Name: bar\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that new request headers causing a vary mismatch are paired with the
// new response when the server says the old response can be used.
TEST(HttpCache, GET_ValidateCache_VaryMismatch_UpdateRequestHeader) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kTypicalGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers =
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=3600\n"
      "Vary: Foo\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Vary-mismatch validation receives 304.
  transaction.request_headers = "Foo: none\r\n";
  transaction.status = "HTTP/1.1 304 Not Modified";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Generate a vary mismatch.
  transaction.request_headers = "Foo: bar\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that a 304 without vary headers doesn't delete the previously stored
// vary data after a vary match revalidation.
TEST(HttpCache, GET_ValidateCache_VaryMatch_DontDeleteVary) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kTypicalGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers =
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=0\n"
      "Vary: Foo\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Validate the entry and remove the vary field in the response.
  transaction.status = "HTTP/1.1 304 Not Modified";
  transaction.response_headers =
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=3600\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Generate a vary mismatch.
  transaction.request_headers = "Foo: none\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that a 304 without vary headers doesn't delete the previously stored
// vary data after a vary mismatch.
TEST(HttpCache, GET_ValidateCache_VaryMismatch_DontDeleteVary) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kTypicalGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers =
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=3600\n"
      "Vary: Foo\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Vary-mismatch validation receives 304 and no vary header.
  transaction.request_headers = "Foo: none\r\n";
  transaction.status = "HTTP/1.1 304 Not Modified";
  transaction.response_headers =
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=3600\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Generate a vary mismatch.
  transaction.request_headers = "Foo: bar\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

static void ETagGet_UnconditionalRequest_Handler(const HttpRequestInfo* request,
                                                 std::string* response_status,
                                                 std::string* response_headers,
                                                 std::string* response_data) {
  EXPECT_FALSE(
      request->extra_headers.HasHeader(HttpRequestHeaders::kIfNoneMatch));
}

TEST(HttpCache, ETagGET_Http10) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kETagGET_Transaction);
  transaction.status = "HTTP/1.0 200 OK";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Get the same URL again, without generating a conditional request.
  transaction.load_flags = LOAD_VALIDATE_CACHE;
  transaction.handler = ETagGet_UnconditionalRequest_Handler;
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

TEST(HttpCache, ETagGET_Http10_Range) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kETagGET_Transaction);
  transaction.status = "HTTP/1.0 200 OK";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Get the same URL again, but use a byte range request.
  transaction.load_flags = LOAD_VALIDATE_CACHE;
  transaction.handler = ETagGet_UnconditionalRequest_Handler;
  transaction.request_headers = "Range: bytes = 5-\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

static void ETagGet_ConditionalRequest_NoStore_Handler(
    const HttpRequestInfo* request,
    std::string* response_status,
    std::string* response_headers,
    std::string* response_data) {
  EXPECT_TRUE(
      request->extra_headers.HasHeader(HttpRequestHeaders::kIfNoneMatch));
  response_status->assign("HTTP/1.1 304 Not Modified");
  response_headers->assign("Cache-Control: no-store\n");
  response_data->clear();
}

TEST(HttpCache, ETagGET_ConditionalRequest_304_NoStore) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kETagGET_Transaction);

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Get the same URL again, but this time we expect it to result
  // in a conditional request.
  transaction.load_flags = LOAD_VALIDATE_CACHE;
  transaction.handler = ETagGet_ConditionalRequest_NoStore_Handler;
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  ScopedMockTransaction transaction2(kETagGET_Transaction);

  // Write to the cache again. This should create a new entry.
  RunTransactionTest(cache.http_cache(), transaction2);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Helper that does 4 requests using HttpCache:
//
// (1) loads |kUrl| -- expects |net_response_1| to be returned.
// (2) loads |kUrl| from cache only -- expects |net_response_1| to be returned.
// (3) loads |kUrl| using |extra_request_headers| -- expects |net_response_2| to
//     be returned.
// (4) loads |kUrl| from cache only -- expects |cached_response_2| to be
//     returned.
static void ConditionalizedRequestUpdatesCacheHelper(
    const Response& net_response_1,
    const Response& net_response_2,
    const Response& cached_response_2,
    const char* extra_request_headers) {
  MockHttpCache cache;

  // The URL we will be requesting.
  const char kUrl[] = "http://foobar.com/main.css";

  // Junk network response.
  static const Response kUnexpectedResponse = {
    "HTTP/1.1 500 Unexpected",
    "Server: unexpected_header",
    "unexpected body"
  };

  // We will control the network layer's responses for |kUrl| using
  // |mock_network_response|.
  MockTransaction mock_network_response = { 0 };
  mock_network_response.url = kUrl;
  AddMockTransaction(&mock_network_response);

  // Request |kUrl| for the first time. It should hit the network and
  // receive |kNetResponse1|, which it saves into the HTTP cache.

  MockTransaction request = { 0 };
  request.url = kUrl;
  request.method = "GET";
  request.request_headers = "";

  net_response_1.AssignTo(&mock_network_response);  // Network mock.
  net_response_1.AssignTo(&request);                // Expected result.

  std::string response_headers;
  RunTransactionTestWithResponse(
      cache.http_cache(), request, &response_headers);

  EXPECT_EQ(net_response_1.status_and_headers(), response_headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Request |kUrl| a second time. Now |kNetResponse1| it is in the HTTP
  // cache, so we don't hit the network.

  request.load_flags = LOAD_ONLY_FROM_CACHE;

  kUnexpectedResponse.AssignTo(&mock_network_response);  // Network mock.
  net_response_1.AssignTo(&request);                     // Expected result.

  RunTransactionTestWithResponse(
      cache.http_cache(), request, &response_headers);

  EXPECT_EQ(net_response_1.status_and_headers(), response_headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Request |kUrl| yet again, but this time give the request an
  // "If-Modified-Since" header. This will cause the request to re-hit the
  // network. However now the network response is going to be
  // different -- this simulates a change made to the CSS file.

  request.request_headers = extra_request_headers;
  request.load_flags = LOAD_NORMAL;

  net_response_2.AssignTo(&mock_network_response);  // Network mock.
  net_response_2.AssignTo(&request);                // Expected result.

  RunTransactionTestWithResponse(
      cache.http_cache(), request, &response_headers);

  EXPECT_EQ(net_response_2.status_and_headers(), response_headers);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Finally, request |kUrl| again. This request should be serviced from
  // the cache. Moreover, the value in the cache should be |kNetResponse2|
  // and NOT |kNetResponse1|. The previous step should have replaced the
  // value in the cache with the modified response.

  request.request_headers = "";
  request.load_flags = LOAD_ONLY_FROM_CACHE;

  kUnexpectedResponse.AssignTo(&mock_network_response);  // Network mock.
  cached_response_2.AssignTo(&request);                  // Expected result.

  RunTransactionTestWithResponse(
      cache.http_cache(), request, &response_headers);

  EXPECT_EQ(cached_response_2.status_and_headers(), response_headers);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RemoveMockTransaction(&mock_network_response);
}

// Check that when an "if-modified-since" header is attached
// to the request, the result still updates the cached entry.
TEST(HttpCache, ConditionalizedRequestUpdatesCache1) {
  // First network response for |kUrl|.
  static const Response kNetResponse1 = {
    "HTTP/1.1 200 OK",
    "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
    "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
    "body1"
  };

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
    "HTTP/1.1 200 OK",
    "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
    "Last-Modified: Fri, 03 Jul 2009 02:14:27 GMT\n",
    "body2"
  };

  const char extra_headers[] =
      "If-Modified-Since: Wed, 06 Feb 2008 22:38:21 GMT\r\n";

  ConditionalizedRequestUpdatesCacheHelper(
      kNetResponse1, kNetResponse2, kNetResponse2, extra_headers);
}

// Check that when an "if-none-match" header is attached
// to the request, the result updates the cached entry.
TEST(HttpCache, ConditionalizedRequestUpdatesCache2) {
  // First network response for |kUrl|.
  static const Response kNetResponse1 = {
    "HTTP/1.1 200 OK",
    "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
    "Etag: \"ETAG1\"\n"
    "Expires: Wed, 7 Sep 2033 21:46:42 GMT\n",  // Should never expire.
    "body1"
  };

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
    "HTTP/1.1 200 OK",
    "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
    "Etag: \"ETAG2\"\n"
    "Expires: Wed, 7 Sep 2033 21:46:42 GMT\n",  // Should never expire.
    "body2"
  };

  const char extra_headers[] = "If-None-Match: \"ETAG1\"\r\n";

  ConditionalizedRequestUpdatesCacheHelper(
      kNetResponse1, kNetResponse2, kNetResponse2, extra_headers);
}

// Check that when an "if-modified-since" header is attached
// to a request, the 304 (not modified result) result updates the cached
// headers, and the 304 response is returned rather than the cached response.
TEST(HttpCache, ConditionalizedRequestUpdatesCache3) {
  // First network response for |kUrl|.
  static const Response kNetResponse1 = {
    "HTTP/1.1 200 OK",
    "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
    "Server: server1\n"
    "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
    "body1"
  };

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
    "HTTP/1.1 304 Not Modified",
    "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
    "Server: server2\n"
    "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
    ""
  };

  static const Response kCachedResponse2 = {
    "HTTP/1.1 200 OK",
    "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
    "Server: server2\n"
    "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
    "body1"
  };

  const char extra_headers[] =
      "If-Modified-Since: Wed, 06 Feb 2008 22:38:21 GMT\r\n";

  ConditionalizedRequestUpdatesCacheHelper(
      kNetResponse1, kNetResponse2, kCachedResponse2, extra_headers);
}

// Test that when doing an externally conditionalized if-modified-since
// and there is no corresponding cache entry, a new cache entry is NOT
// created (304 response).
TEST(HttpCache, ConditionalizedRequestUpdatesCache4) {
  MockHttpCache cache;

  const char kUrl[] = "http://foobar.com/main.css";

  static const Response kNetResponse = {
    "HTTP/1.1 304 Not Modified",
    "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
    "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
    ""
  };

  const char kExtraRequestHeaders[] =
      "If-Modified-Since: Wed, 06 Feb 2008 22:38:21 GMT\r\n";

  // We will control the network layer's responses for |kUrl| using
  // |mock_network_response|.
  MockTransaction mock_network_response = { 0 };
  mock_network_response.url = kUrl;
  AddMockTransaction(&mock_network_response);

  MockTransaction request = { 0 };
  request.url = kUrl;
  request.method = "GET";
  request.request_headers = kExtraRequestHeaders;

  kNetResponse.AssignTo(&mock_network_response);  // Network mock.
  kNetResponse.AssignTo(&request);                // Expected result.

  std::string response_headers;
  RunTransactionTestWithResponse(
      cache.http_cache(), request, &response_headers);

  EXPECT_EQ(kNetResponse.status_and_headers(), response_headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());

  RemoveMockTransaction(&mock_network_response);
}

// Test that when doing an externally conditionalized if-modified-since
// and there is no corresponding cache entry, a new cache entry is NOT
// created (200 response).
TEST(HttpCache, ConditionalizedRequestUpdatesCache5) {
  MockHttpCache cache;

  const char kUrl[] = "http://foobar.com/main.css";

  static const Response kNetResponse = {
    "HTTP/1.1 200 OK",
    "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
    "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
    "foobar!!!"
  };

  const char kExtraRequestHeaders[] =
      "If-Modified-Since: Wed, 06 Feb 2008 22:38:21 GMT\r\n";

  // We will control the network layer's responses for |kUrl| using
  // |mock_network_response|.
  MockTransaction mock_network_response = { 0 };
  mock_network_response.url = kUrl;
  AddMockTransaction(&mock_network_response);

  MockTransaction request = { 0 };
  request.url = kUrl;
  request.method = "GET";
  request.request_headers = kExtraRequestHeaders;

  kNetResponse.AssignTo(&mock_network_response);  // Network mock.
  kNetResponse.AssignTo(&request);                // Expected result.

  std::string response_headers;
  RunTransactionTestWithResponse(
      cache.http_cache(), request, &response_headers);

  EXPECT_EQ(kNetResponse.status_and_headers(), response_headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());

  RemoveMockTransaction(&mock_network_response);
}

// Test that when doing an externally conditionalized if-modified-since
// if the date does not match the cache entry's last-modified date,
// then we do NOT use the response (304) to update the cache.
// (the if-modified-since date is 2 days AFTER the cache's modification date).
TEST(HttpCache, ConditionalizedRequestUpdatesCache6) {
  static const Response kNetResponse1 = {
    "HTTP/1.1 200 OK",
    "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
    "Server: server1\n"
    "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
    "body1"
  };

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
    "HTTP/1.1 304 Not Modified",
    "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
    "Server: server2\n"
    "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
    ""
  };

  // This is two days in the future from the original response's last-modified
  // date!
  const char kExtraRequestHeaders[] =
      "If-Modified-Since: Fri, 08 Feb 2008 22:38:21 GMT\r\n";

  ConditionalizedRequestUpdatesCacheHelper(
      kNetResponse1, kNetResponse2, kNetResponse1, kExtraRequestHeaders);
}

// Test that when doing an externally conditionalized if-none-match
// if the etag does not match the cache entry's etag, then we do not use the
// response (304) to update the cache.
TEST(HttpCache, ConditionalizedRequestUpdatesCache7) {
  static const Response kNetResponse1 = {
    "HTTP/1.1 200 OK",
    "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
    "Etag: \"Foo1\"\n"
    "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
    "body1"
  };

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
    "HTTP/1.1 304 Not Modified",
    "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
    "Etag: \"Foo2\"\n"
    "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
    ""
  };

  // Different etag from original response.
  const char kExtraRequestHeaders[] = "If-None-Match: \"Foo2\"\r\n";

  ConditionalizedRequestUpdatesCacheHelper(
      kNetResponse1, kNetResponse2, kNetResponse1, kExtraRequestHeaders);
}

// Test that doing an externally conditionalized request with both if-none-match
// and if-modified-since updates the cache.
TEST(HttpCache, ConditionalizedRequestUpdatesCache8) {
  static const Response kNetResponse1 = {
    "HTTP/1.1 200 OK",
    "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
    "Etag: \"Foo1\"\n"
    "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
    "body1"
  };

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
    "HTTP/1.1 200 OK",
    "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
    "Etag: \"Foo2\"\n"
    "Last-Modified: Fri, 03 Jul 2009 02:14:27 GMT\n",
    "body2"
  };

  const char kExtraRequestHeaders[] =
      "If-Modified-Since: Wed, 06 Feb 2008 22:38:21 GMT\r\n"
      "If-None-Match: \"Foo1\"\r\n";

  ConditionalizedRequestUpdatesCacheHelper(
      kNetResponse1, kNetResponse2, kNetResponse2, kExtraRequestHeaders);
}

// Test that doing an externally conditionalized request with both if-none-match
// and if-modified-since does not update the cache with only one match.
TEST(HttpCache, ConditionalizedRequestUpdatesCache9) {
  static const Response kNetResponse1 = {
    "HTTP/1.1 200 OK",
    "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
    "Etag: \"Foo1\"\n"
    "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
    "body1"
  };

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
    "HTTP/1.1 200 OK",
    "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
    "Etag: \"Foo2\"\n"
    "Last-Modified: Fri, 03 Jul 2009 02:14:27 GMT\n",
    "body2"
  };

  // The etag doesn't match what we have stored.
  const char kExtraRequestHeaders[] =
      "If-Modified-Since: Wed, 06 Feb 2008 22:38:21 GMT\r\n"
      "If-None-Match: \"Foo2\"\r\n";

  ConditionalizedRequestUpdatesCacheHelper(
      kNetResponse1, kNetResponse2, kNetResponse1, kExtraRequestHeaders);
}

// Test that doing an externally conditionalized request with both if-none-match
// and if-modified-since does not update the cache with only one match.
TEST(HttpCache, ConditionalizedRequestUpdatesCache10) {
  static const Response kNetResponse1 = {
    "HTTP/1.1 200 OK",
    "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
    "Etag: \"Foo1\"\n"
    "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
    "body1"
  };

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
    "HTTP/1.1 200 OK",
    "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
    "Etag: \"Foo2\"\n"
    "Last-Modified: Fri, 03 Jul 2009 02:14:27 GMT\n",
    "body2"
  };

  // The modification date doesn't match what we have stored.
  const char kExtraRequestHeaders[] =
      "If-Modified-Since: Fri, 08 Feb 2008 22:38:21 GMT\r\n"
      "If-None-Match: \"Foo1\"\r\n";

  ConditionalizedRequestUpdatesCacheHelper(
      kNetResponse1, kNetResponse2, kNetResponse1, kExtraRequestHeaders);
}

TEST(HttpCache, UrlContainingHash) {
  MockHttpCache cache;

  // Do a typical GET request -- should write an entry into our cache.
  MockTransaction trans(kTypicalGET_Transaction);
  RunTransactionTest(cache.http_cache(), trans);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Request the same URL, but this time with a reference section (hash).
  // Since the cache key strips the hash sections, this should be a cache hit.
  std::string url_with_hash = std::string(trans.url) + "#multiple#hashes";
  trans.url = url_with_hash.c_str();
  trans.load_flags = LOAD_ONLY_FROM_CACHE;

  RunTransactionTest(cache.http_cache(), trans);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we skip the cache for POST requests that do not have an upload
// identifier.
TEST(HttpCache, SimplePOST_SkipsCache) {
  MockHttpCache cache;

  RunTransactionTest(cache.http_cache(), kSimplePOST_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

// Tests POST handling with a disabled cache (no DCHECK).
TEST(HttpCache, SimplePOST_DisabledCache) {
  MockHttpCache cache;
  cache.http_cache()->set_mode(HttpCache::Mode::DISABLE);

  RunTransactionTest(cache.http_cache(), kSimplePOST_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

TEST(HttpCache, SimplePOST_LoadOnlyFromCache_Miss) {
  MockHttpCache cache;

  MockTransaction transaction(kSimplePOST_Transaction);
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE;

  MockHttpRequest request(transaction);
  TestCompletionCallback callback;

  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());
  ASSERT_TRUE(trans.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  ASSERT_THAT(callback.GetResult(rv), IsError(ERR_CACHE_MISS));

  trans.reset();

  EXPECT_EQ(0, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

TEST(HttpCache, SimplePOST_LoadOnlyFromCache_Hit) {
  MockHttpCache cache;

  // Test that we hit the cache for POST requests.

  MockTransaction transaction(kSimplePOST_Transaction);

  const int64_t kUploadId = 1;  // Just a dummy value.

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::MakeUnique<UploadBytesElementReader>("hello", 5));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers),
                                              kUploadId);
  MockHttpRequest request(transaction);
  request.upload_data_stream = &upload_data_stream;

  // Populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, request, NULL);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Load from cache.
  request.load_flags |= LOAD_ONLY_FROM_CACHE;
  RunTransactionTestWithRequest(cache.http_cache(), transaction, request, NULL);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Test that we don't hit the cache for POST requests if there is a byte range.
TEST(HttpCache, SimplePOST_WithRanges) {
  MockHttpCache cache;

  MockTransaction transaction(kSimplePOST_Transaction);
  transaction.request_headers = "Range: bytes = 0-4\r\n";

  const int64_t kUploadId = 1;  // Just a dummy value.

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::WrapUnique(new UploadBytesElementReader("hello", 5)));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers),
                                              kUploadId);

  MockHttpRequest request(transaction);
  request.upload_data_stream = &upload_data_stream;

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, request, NULL);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

// Tests that a POST is cached separately from a GET.
TEST(HttpCache, SimplePOST_SeparateCache) {
  MockHttpCache cache;

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::WrapUnique(new UploadBytesElementReader("hello", 5)));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 1);

  MockTransaction transaction(kSimplePOST_Transaction);
  MockHttpRequest req1(transaction);
  req1.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, NULL);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  transaction.method = "GET";
  MockHttpRequest req2(transaction);

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, NULL);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that a successful POST invalidates a previously cached GET.
TEST(HttpCache, SimplePOST_Invalidate_205) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  AddMockTransaction(&transaction);
  MockHttpRequest req1(transaction);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, NULL);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::WrapUnique(new UploadBytesElementReader("hello", 5)));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 1);

  transaction.method = "POST";
  transaction.status = "HTTP/1.1 205 No Content";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, NULL);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, NULL);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(3, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

// Tests that a successful POST invalidates a previously cached GET, even when
// there is no upload identifier.
TEST(HttpCache, SimplePOST_NoUploadId_Invalidate_205) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  AddMockTransaction(&transaction);
  MockHttpRequest req1(transaction);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, NULL);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::WrapUnique(new UploadBytesElementReader("hello", 5)));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  transaction.method = "POST";
  transaction.status = "HTTP/1.1 205 No Content";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, NULL);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, NULL);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

// Tests that processing a POST before creating the backend doesn't crash.
TEST(HttpCache, SimplePOST_NoUploadId_NoBackend) {
  // This will initialize a cache object with NULL backend.
  std::unique_ptr<MockBlockingBackendFactory> factory(
      new MockBlockingBackendFactory());
  factory->set_fail(true);
  factory->FinishCreation();
  MockHttpCache cache(std::move(factory));

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::WrapUnique(new UploadBytesElementReader("hello", 5)));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  MockTransaction transaction(kSimplePOST_Transaction);
  AddMockTransaction(&transaction);
  MockHttpRequest req(transaction);
  req.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req, NULL);

  RemoveMockTransaction(&transaction);
}

// Tests that we don't invalidate entries as a result of a failed POST.
TEST(HttpCache, SimplePOST_DontInvalidate_100) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  AddMockTransaction(&transaction);
  MockHttpRequest req1(transaction);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, NULL);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::WrapUnique(new UploadBytesElementReader("hello", 5)));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 1);

  transaction.method = "POST";
  transaction.status = "HTTP/1.1 100 Continue";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, NULL);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, NULL);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

// Tests that a HEAD request is not cached by itself.
TEST(HttpCache, SimpleHEAD_LoadOnlyFromCache_Miss) {
  MockHttpCache cache;
  MockTransaction transaction(kSimplePOST_Transaction);
  AddMockTransaction(&transaction);
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE;
  transaction.method = "HEAD";

  MockHttpRequest request(transaction);
  TestCompletionCallback callback;

  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());
  ASSERT_TRUE(trans.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  ASSERT_THAT(callback.GetResult(rv), IsError(ERR_CACHE_MISS));

  trans.reset();

  EXPECT_EQ(0, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

// Tests that a HEAD request is served from a cached GET.
TEST(HttpCache, SimpleHEAD_LoadOnlyFromCache_Hit) {
  MockHttpCache cache;
  MockTransaction transaction(kSimpleGET_Transaction);
  AddMockTransaction(&transaction);

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Load from cache.
  transaction.method = "HEAD";
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE;
  transaction.data = "";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

// Tests that a read-only request served from the cache preserves CL.
TEST(HttpCache, SimpleHEAD_ContentLengthOnHit_Read) {
  MockHttpCache cache;
  MockTransaction transaction(kSimpleGET_Transaction);
  AddMockTransaction(&transaction);
  transaction.response_headers = "Content-Length: 42\n";

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  // Load from cache.
  transaction.method = "HEAD";
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE;
  transaction.data = "";
  std::string headers;

  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ("HTTP/1.1 200 OK\nContent-Length: 42\n", headers);
  RemoveMockTransaction(&transaction);
}

// Tests that a read-write request served from the cache preserves CL.
TEST(HttpCache, ETagHEAD_ContentLengthOnHit_ReadWrite) {
  MockHttpCache cache;
  MockTransaction transaction(kETagGET_Transaction);
  AddMockTransaction(&transaction);
  std::string server_headers(kETagGET_Transaction.response_headers);
  server_headers.append("Content-Length: 42\n");
  transaction.response_headers = server_headers.data();

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  // Load from cache.
  transaction.method = "HEAD";
  transaction.data = "";
  std::string headers;

  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_NE(std::string::npos, headers.find("Content-Length: 42\n"));
  RemoveMockTransaction(&transaction);
}

// Tests that a HEAD request that includes byte ranges bypasses the cache.
TEST(HttpCache, SimpleHEAD_WithRanges) {
  MockHttpCache cache;
  MockTransaction transaction(kSimpleGET_Transaction);
  AddMockTransaction(&transaction);

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  // Load from cache.
  transaction.method = "HEAD";
  transaction.request_headers = "Range: bytes = 0-4\r\n";
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE;
  transaction.return_code = ERR_CACHE_MISS;
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

// Tests that a HEAD request can be served from a partialy cached resource.
TEST(HttpCache, SimpleHEAD_WithCachedRanges) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);

  // Write to the cache (40-49).
  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  RemoveMockTransaction(&kRangeGET_TransactionOK);

  MockTransaction transaction(kSimpleGET_Transaction);

  transaction.url = kRangeGET_TransactionOK.url;
  transaction.method = "HEAD";
  transaction.data = "";
  AddMockTransaction(&transaction);
  std::string headers;

  // Load from cache.
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_NE(std::string::npos, headers.find("HTTP/1.1 200 OK\n"));
  EXPECT_NE(std::string::npos, headers.find("Content-Length: 80\n"));
  EXPECT_EQ(std::string::npos, headers.find("Content-Range"));
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

// Tests that a HEAD request can be served from a truncated resource.
TEST(HttpCache, SimpleHEAD_WithTruncatedEntry) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);

  std::string raw_headers("HTTP/1.1 200 OK\n"
                          "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
                          "ETag: \"foo\"\n"
                          "Accept-Ranges: bytes\n"
                          "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);
  RemoveMockTransaction(&kRangeGET_TransactionOK);

  MockTransaction transaction(kSimpleGET_Transaction);

  transaction.url = kRangeGET_TransactionOK.url;
  transaction.method = "HEAD";
  transaction.data = "";
  AddMockTransaction(&transaction);
  std::string headers;

  // Load from cache.
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_NE(std::string::npos, headers.find("HTTP/1.1 200 OK\n"));
  EXPECT_NE(std::string::npos, headers.find("Content-Length: 80\n"));
  EXPECT_EQ(std::string::npos, headers.find("Content-Range"));
  EXPECT_EQ(0, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

// Tests that a HEAD request updates the cached response.
TEST(HttpCache, TypicalHEAD_UpdatesResponse) {
  MockHttpCache cache;
  MockTransaction transaction(kTypicalGET_Transaction);
  AddMockTransaction(&transaction);

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  // Update the cache.
  transaction.method = "HEAD";
  transaction.response_headers = "Foo: bar\n";
  transaction.data = "";
  transaction.status = "HTTP/1.1 304 Not Modified\n";
  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);
  RemoveMockTransaction(&transaction);

  EXPECT_NE(std::string::npos, headers.find("HTTP/1.1 200 OK\n"));
  EXPECT_EQ(2, cache.network_layer()->transaction_count());

  MockTransaction transaction2(kTypicalGET_Transaction);
  AddMockTransaction(&transaction2);

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Load from the cache.
  transaction2.load_flags |= LOAD_ONLY_FROM_CACHE;
  RunTransactionTestWithResponse(cache.http_cache(), transaction2, &headers);

  EXPECT_NE(std::string::npos, headers.find("Foo: bar\n"));
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction2);
}

// Tests that an externally conditionalized HEAD request updates the cache.
TEST(HttpCache, TypicalHEAD_ConditionalizedRequestUpdatesResponse) {
  MockHttpCache cache;
  MockTransaction transaction(kTypicalGET_Transaction);
  AddMockTransaction(&transaction);

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  // Update the cache.
  transaction.method = "HEAD";
  transaction.request_headers =
      "If-Modified-Since: Wed, 28 Nov 2007 00:40:09 GMT\r\n";
  transaction.response_headers = "Foo: bar\n";
  transaction.data = "";
  transaction.status = "HTTP/1.1 304 Not Modified\n";
  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);
  RemoveMockTransaction(&transaction);

  EXPECT_NE(std::string::npos, headers.find("HTTP/1.1 304 Not Modified\n"));
  EXPECT_EQ(2, cache.network_layer()->transaction_count());

  MockTransaction transaction2(kTypicalGET_Transaction);
  AddMockTransaction(&transaction2);

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Load from the cache.
  transaction2.load_flags |= LOAD_ONLY_FROM_CACHE;
  RunTransactionTestWithResponse(cache.http_cache(), transaction2, &headers);

  EXPECT_NE(std::string::npos, headers.find("Foo: bar\n"));
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction2);
}

// Tests that a HEAD request invalidates an old cached entry.
TEST(HttpCache, SimpleHEAD_InvalidatesEntry) {
  MockHttpCache cache;
  MockTransaction transaction(kTypicalGET_Transaction);
  AddMockTransaction(&transaction);

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  // Update the cache.
  transaction.method = "HEAD";
  transaction.data = "";
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());

  // Load from the cache.
  transaction.method = "GET";
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE;
  transaction.return_code = ERR_CACHE_MISS;
  RunTransactionTest(cache.http_cache(), transaction);

  RemoveMockTransaction(&transaction);
}

// Tests that we do not cache the response of a PUT.
TEST(HttpCache, SimplePUT_Miss) {
  MockHttpCache cache;

  MockTransaction transaction(kSimplePOST_Transaction);
  transaction.method = "PUT";

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::WrapUnique(new UploadBytesElementReader("hello", 5)));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  MockHttpRequest request(transaction);
  request.upload_data_stream = &upload_data_stream;

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, request, NULL);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

// Tests that we invalidate entries as a result of a PUT.
TEST(HttpCache, SimplePUT_Invalidate) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  MockHttpRequest req1(transaction);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, NULL);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::WrapUnique(new UploadBytesElementReader("hello", 5)));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  transaction.method = "PUT";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, NULL);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, NULL);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we invalidate entries as a result of a PUT.
TEST(HttpCache, SimplePUT_Invalidate_305) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  AddMockTransaction(&transaction);
  MockHttpRequest req1(transaction);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, NULL);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::WrapUnique(new UploadBytesElementReader("hello", 5)));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  transaction.method = "PUT";
  transaction.status = "HTTP/1.1 305 Use Proxy";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, NULL);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, NULL);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

// Tests that we don't invalidate entries as a result of a failed PUT.
TEST(HttpCache, SimplePUT_DontInvalidate_404) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  AddMockTransaction(&transaction);
  MockHttpRequest req1(transaction);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, NULL);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::WrapUnique(new UploadBytesElementReader("hello", 5)));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  transaction.method = "PUT";
  transaction.status = "HTTP/1.1 404 Not Found";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, NULL);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, NULL);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

// Tests that we do not cache the response of a DELETE.
TEST(HttpCache, SimpleDELETE_Miss) {
  MockHttpCache cache;

  MockTransaction transaction(kSimplePOST_Transaction);
  transaction.method = "DELETE";

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::WrapUnique(new UploadBytesElementReader("hello", 5)));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  MockHttpRequest request(transaction);
  request.upload_data_stream = &upload_data_stream;

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, request, NULL);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

// Tests that we invalidate entries as a result of a DELETE.
TEST(HttpCache, SimpleDELETE_Invalidate) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  MockHttpRequest req1(transaction);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, NULL);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::WrapUnique(new UploadBytesElementReader("hello", 5)));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  transaction.method = "DELETE";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, NULL);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, NULL);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we invalidate entries as a result of a DELETE.
TEST(HttpCache, SimpleDELETE_Invalidate_301) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  AddMockTransaction(&transaction);

  // Attempt to populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  transaction.method = "DELETE";
  transaction.status = "HTTP/1.1 301 Moved Permanently ";

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  transaction.method = "GET";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

// Tests that we don't invalidate entries as a result of a failed DELETE.
TEST(HttpCache, SimpleDELETE_DontInvalidate_416) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  AddMockTransaction(&transaction);

  // Attempt to populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  transaction.method = "DELETE";
  transaction.status = "HTTP/1.1 416 Requested Range Not Satisfiable";

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  transaction.method = "GET";
  transaction.status = "HTTP/1.1 200 OK";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

// Tests that we don't invalidate entries after a failed network transaction.
TEST(HttpCache, SimpleGET_DontInvalidateOnFailure) {
  MockHttpCache cache;

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // Fail the network request.
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.return_code = ERR_FAILED;
  transaction.load_flags |= LOAD_VALIDATE_CACHE;

  AddMockTransaction(&transaction);
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  RemoveMockTransaction(&transaction);

  transaction.load_flags = LOAD_ONLY_FROM_CACHE;
  transaction.return_code = OK;
  AddMockTransaction(&transaction);
  RunTransactionTest(cache.http_cache(), transaction);

  // Make sure the transaction didn't reach the network.
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  RemoveMockTransaction(&transaction);
}

TEST(HttpCache, RangeGET_SkipsCache) {
  MockHttpCache cache;

  // Test that we skip the cache for range GET requests.  Eventually, we will
  // want to cache these, but we'll still have cases where skipping the cache
  // makes sense, so we want to make sure that it works properly.

  RunTransactionTest(cache.http_cache(), kRangeGET_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());

  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "If-None-Match: foo\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());

  transaction.request_headers =
      "If-Modified-Since: Wed, 28 Nov 2007 00:45:20 GMT\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

// Test that we skip the cache for range requests that include a validation
// header.
TEST(HttpCache, RangeGET_SkipsCache2) {
  MockHttpCache cache;

  MockTransaction transaction(kRangeGET_Transaction);
  transaction.request_headers = "If-None-Match: foo\r\n"
                                EXTRA_HEADER
                                "Range: bytes = 40-49\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());

  transaction.request_headers =
      "If-Modified-Since: Wed, 28 Nov 2007 00:45:20 GMT\r\n"
      EXTRA_HEADER
      "Range: bytes = 40-49\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());

  transaction.request_headers = "If-Range: bla\r\n"
                                EXTRA_HEADER
                                "Range: bytes = 40-49\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

TEST(HttpCache, SimpleGET_DoesntLogHeaders) {
  MockHttpCache cache;

  BoundTestNetLog log;
  RunTransactionTestWithLog(cache.http_cache(), kSimpleGET_Transaction,
                            log.bound());

  EXPECT_FALSE(LogContainsEventType(
      log, NetLogEventType::HTTP_CACHE_CALLER_REQUEST_HEADERS));
}

TEST(HttpCache, RangeGET_LogsHeaders) {
  MockHttpCache cache;

  BoundTestNetLog log;
  RunTransactionTestWithLog(cache.http_cache(), kRangeGET_Transaction,
                            log.bound());

  EXPECT_TRUE(LogContainsEventType(
      log, NetLogEventType::HTTP_CACHE_CALLER_REQUEST_HEADERS));
}

TEST(HttpCache, ExternalValidation_LogsHeaders) {
  MockHttpCache cache;

  BoundTestNetLog log;
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "If-None-Match: foo\r\n" EXTRA_HEADER;
  RunTransactionTestWithLog(cache.http_cache(), transaction, log.bound());

  EXPECT_TRUE(LogContainsEventType(
      log, NetLogEventType::HTTP_CACHE_CALLER_REQUEST_HEADERS));
}

TEST(HttpCache, SpecialHeaders_LogsHeaders) {
  MockHttpCache cache;

  BoundTestNetLog log;
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "cache-control: no-cache\r\n" EXTRA_HEADER;
  RunTransactionTestWithLog(cache.http_cache(), transaction, log.bound());

  EXPECT_TRUE(LogContainsEventType(
      log, NetLogEventType::HTTP_CACHE_CALLER_REQUEST_HEADERS));
}

// Tests that receiving 206 for a regular request is handled correctly.
TEST(HttpCache, GET_Crazy206) {
  MockHttpCache cache;

  // Write to the cache.
  MockTransaction transaction(kRangeGET_TransactionOK);
  AddMockTransaction(&transaction);
  transaction.request_headers = EXTRA_HEADER;
  transaction.handler = NULL;
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // This should read again from the net.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
  RemoveMockTransaction(&transaction);
}

// Tests that receiving 416 for a regular request is handled correctly.
TEST(HttpCache, GET_Crazy416) {
  MockHttpCache cache;

  // Write to the cache.
  MockTransaction transaction(kSimpleGET_Transaction);
  AddMockTransaction(&transaction);
  transaction.status = "HTTP/1.1 416 Requested Range Not Satisfiable";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RemoveMockTransaction(&transaction);
}

// Tests that we don't store partial responses that can't be validated.
TEST(HttpCache, RangeGET_NoStrongValidators) {
  MockHttpCache cache;
  std::string headers;

  // Attempt to write to the cache (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.response_headers = "Content-Length: 10\n"
                                 "Cache-Control: max-age=3600\n"
                                 "ETag: w/\"foo\"\n";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now verify that there's no cached data.
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests failures to conditionalize byte range requests.
TEST(HttpCache, RangeGET_NoConditionalization) {
  MockHttpCache cache;
  cache.FailConditionalizations();
  std::string headers;

  // Write to the cache (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.response_headers = "Content-Length: 10\n"
                                 "ETag: \"foo\"\n";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now verify that the cached data is not used.
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that restarting a partial request when the cached data cannot be
// revalidated logs an event.
TEST(HttpCache, RangeGET_NoValidation_LogsRestart) {
  MockHttpCache cache;
  cache.FailConditionalizations();

  // Write to the cache (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.response_headers = "Content-Length: 10\n"
                                 "ETag: \"foo\"\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Now verify that the cached data is not used.
  BoundTestNetLog log;
  RunTransactionTestWithLog(cache.http_cache(), kRangeGET_TransactionOK,
                            log.bound());

  EXPECT_TRUE(LogContainsEventType(
      log, NetLogEventType::HTTP_CACHE_RESTART_PARTIAL_REQUEST));
}

// Tests that a failure to conditionalize a regular request (no range) with a
// sparse entry results in a full response.
TEST(HttpCache, GET_NoConditionalization) {
  MockHttpCache cache;
  cache.FailConditionalizations();
  std::string headers;

  // Write to the cache (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.response_headers = "Content-Length: 10\n"
                                 "ETag: \"foo\"\n";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now verify that the cached data is not used.
  // Don't ask for a range. The cache will attempt to use the cached data but
  // should discard it as it cannot be validated. A regular request should go
  // to the server and a new entry should be created.
  transaction.request_headers = EXTRA_HEADER;
  transaction.data = "Not a range";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(0U, headers.find("HTTP/1.1 200 OK\n"));
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  // The last response was saved.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Verifies that conditionalization failures when asking for a range that would
// require the cache to modify the range to ask, result in a network request
// that matches the user's one.
TEST(HttpCache, RangeGET_NoConditionalization2) {
  MockHttpCache cache;
  cache.FailConditionalizations();
  std::string headers;

  // Write to the cache (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.response_headers = "Content-Length: 10\n"
                                 "ETag: \"foo\"\n";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now verify that the cached data is not used.
  // Ask for a range that extends before and after the cached data so that the
  // cache would normally mix data from three sources. After deleting the entry,
  // the response will come from a single network request.
  transaction.request_headers = "Range: bytes = 20-59\r\n" EXTRA_HEADER;
  transaction.data = "rg: 20-29 rg: 30-39 rg: 40-49 rg: 50-59 ";
  transaction.response_headers = kRangeGET_TransactionOK.response_headers;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 20, 59);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  // The last response was saved.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we cache partial responses that lack content-length.
TEST(HttpCache, RangeGET_NoContentLength) {
  MockHttpCache cache;
  std::string headers;

  // Attempt to write to the cache (40-49).
  MockTransaction transaction(kRangeGET_TransactionOK);
  AddMockTransaction(&transaction);
  transaction.response_headers = "ETag: \"foo\"\n"
                                 "Accept-Ranges: bytes\n"
                                 "Content-Range: bytes 40-49/80\n";
  transaction.handler = NULL;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now verify that there's no cached data.
  transaction.handler = &RangeTransactionServer::RangeHandler;
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RemoveMockTransaction(&transaction);
}

// Fails only on bots. crbug.com/533640
#if defined(OS_ANDROID)
#define MAYBE_RangeGET_OK DISABLED_RangeGET_OK
#else
#define MAYBE_RangeGET_OK RangeGET_OK
#endif
// Tests that we can cache range requests and fetch random blocks from the
// cache and the network.
TEST(HttpCache, MAYBE_RangeGET_OK) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);
  std::string headers;

  // Write to the cache (40-49).
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Read from the cache (40-49).
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Write to the cache (30-39).
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 30-39\r\n" EXTRA_HEADER;
  transaction.data = "rg: 30-39 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 30, 39);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Write and read from the cache (20-59).
  transaction.request_headers = "Range: bytes = 20-59\r\n" EXTRA_HEADER;
  transaction.data = "rg: 20-29 rg: 30-39 rg: 40-49 rg: 50-59 ";
  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), transaction, &headers, log.bound(),
      &load_timing_info);

  Verify206Response(headers, 20, 59);
  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(3, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Fails only on bots. crbug.com/533640
#if defined(OS_ANDROID)
#define MAYBE_RangeGET_SyncOK DISABLED_RangeGET_SyncOK
#else
#define MAYBE_RangeGET_SyncOK RangeGET_SyncOK
#endif
// Tests that we can cache range requests and fetch random blocks from the
// cache and the network, with synchronous responses.
TEST(HttpCache, MAYBE_RangeGET_SyncOK) {
  MockHttpCache cache;

  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.test_mode = TEST_MODE_SYNC_ALL;
  AddMockTransaction(&transaction);

  // Write to the cache (40-49).
  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Read from the cache (40-49).
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Write to the cache (30-39).
  transaction.request_headers = "Range: bytes = 30-39\r\n" EXTRA_HEADER;
  transaction.data = "rg: 30-39 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 30, 39);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Write and read from the cache (20-59).
  transaction.request_headers = "Range: bytes = 20-59\r\n" EXTRA_HEADER;
  transaction.data = "rg: 20-29 rg: 30-39 rg: 40-49 rg: 50-59 ";
  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), transaction, &headers, log.bound(),
      &load_timing_info);

  Verify206Response(headers, 20, 59);
  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);

  RemoveMockTransaction(&transaction);
}

// Tests that if the previous transaction is cancelled while busy (doing sparse
// IO), a new transaction (that reuses that same ActiveEntry) waits until the
// entry is ready again.
TEST(HttpCache, Sparse_WaitForEntry) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);

  // Create a sparse entry.
  RunTransactionTest(cache.http_cache(), transaction);

  // Simulate a previous transaction being cancelled.
  disk_cache::Entry* entry;
  ASSERT_TRUE(cache.OpenBackendEntry(kRangeGET_TransactionOK.url, &entry));
  entry->CancelSparseIO();

  // Test with a range request.
  RunTransactionTest(cache.http_cache(), transaction);

  // Now test with a regular request.
  entry->CancelSparseIO();
  transaction.request_headers = EXTRA_HEADER;
  transaction.data = kFullRangeData;
  RunTransactionTest(cache.http_cache(), transaction);

  entry->Close();
}

// Tests that we don't revalidate an entry unless we are required to do so.
TEST(HttpCache, RangeGET_Revalidate1) {
  MockHttpCache cache;
  std::string headers;

  // Write to the cache (40-49).
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2009 01:10:43 GMT\n"
      "Expires: Wed, 7 Sep 2033 21:46:42 GMT\n"  // Should never expire.
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 10\n";
  AddMockTransaction(&transaction);
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Read from the cache (40-49).
  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), transaction, &headers, log.bound(),
      &load_timing_info);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingCachedResponse(load_timing_info);

  // Read again forcing the revalidation.
  transaction.load_flags |= LOAD_VALIDATE_CACHE;
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), transaction, &headers, log.bound(),
      &load_timing_info);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);

  RemoveMockTransaction(&transaction);
}

// Fails only on bots. crbug.com/533640
#if defined(OS_ANDROID)
#define MAYBE_RangeGET_Revalidate2 DISABLED_RangeGET_Revalidate2
#else
#define MAYBE_RangeGET_Revalidate2 RangeGET_Revalidate2
#endif
// Checks that we revalidate an entry when the headers say so.
TEST(HttpCache, MAYBE_RangeGET_Revalidate2) {
  MockHttpCache cache;
  std::string headers;

  // Write to the cache (40-49).
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2009 01:10:43 GMT\n"
      "Expires: Sat, 18 Apr 2009 01:10:43 GMT\n"  // Expired.
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 10\n";
  AddMockTransaction(&transaction);
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Read from the cache (40-49).
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);
  Verify206Response(headers, 40, 49);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RemoveMockTransaction(&transaction);
}

// Tests that we deal with 304s for range requests.
TEST(HttpCache, RangeGET_304) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);
  std::string headers;

  // Write to the cache (40-49).
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Read from the cache (40-49).
  RangeTransactionServer handler;
  handler.set_not_modified(true);
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.load_flags |= LOAD_VALIDATE_CACHE;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Tests that we deal with 206s when revalidating range requests.
TEST(HttpCache, RangeGET_ModifiedResult) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);
  std::string headers;

  // Write to the cache (40-49).
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Attempt to read from the cache (40-49).
  RangeTransactionServer handler;
  handler.set_modified(true);
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.load_flags |= LOAD_VALIDATE_CACHE;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // And the entry should be gone.
  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Tests that when a server returns 206 with a sub-range of the requested range,
// and there is nothing stored in the cache, the returned response is passed to
// the caller as is. In this context, a subrange means a response that starts
// with the same byte that was requested, but that is not the whole range that
// was requested.
TEST(HttpCache, RangeGET_206ReturnsSubrangeRange_NoCachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Request a large range (40-59). The server sends 40-49.
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 40-59\r\n" EXTRA_HEADER;
  transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 10\n"
      "Content-Range: bytes 40-49/80\n";
  transaction.handler = nullptr;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that when a server returns 206 with a sub-range of the requested range,
// and there was an entry stored in the cache, the cache gets out of the way.
TEST(HttpCache, RangeGET_206ReturnsSubrangeRange_CachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Write to the cache (70-79).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 70-79\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);
  Verify206Response(headers, 70, 79);

  // Request a large range (40-79). The cache will ask the server for 40-59.
  // The server returns 40-49. The cache should consider the server confused and
  // abort caching, restarting the request without caching.
  transaction.request_headers = "Range: bytes = 40-79\r\n" EXTRA_HEADER;
  transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 10\n"
      "Content-Range: bytes 40-49/80\n";
  transaction.handler = nullptr;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  // Two new network requests were issued, one from the cache and another after
  // deleting the entry.
  Verify206Response(headers, 40, 49);
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The entry was deleted.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that when a server returns 206 with a sub-range of the requested range,
// and there was an entry stored in the cache, the cache gets out of the way,
// when the caller is not using ranges.
TEST(HttpCache, GET_206ReturnsSubrangeRange_CachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Write to the cache (70-79).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 70-79\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);
  Verify206Response(headers, 70, 79);

  // Don't ask for a range. The cache will ask the server for 0-69.
  // The server returns 40-49. The cache should consider the server confused and
  // abort caching, restarting the request.
  // The second network request should not be a byte range request so the server
  // should return 200 + "Not a range"
  transaction.request_headers = "X-Return-Default-Range:\r\n" EXTRA_HEADER;
  transaction.data = "Not a range";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(0U, headers.find("HTTP/1.1 200 OK\n"));
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The entry was deleted.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that when a server returns 206 with a random range and there is
// nothing stored in the cache, the returned response is passed to the caller
// as is. In this context, a WrongRange means that the returned range may or may
// not have any relationship with the requested range (may or may not be
// contained). The important part is that the first byte doesn't match the first
// requested byte.
TEST(HttpCache, RangeGET_206ReturnsWrongRange_NoCachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Request a large range (30-59). The server sends (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 30-59\r\n" EXTRA_HEADER;
  transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 10\n"
      "Content-Range: bytes 40-49/80\n";
  transaction.handler = nullptr;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The entry was deleted.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that when a server returns 206 with a random range and there is
// an entry stored in the cache, the cache gets out of the way.
TEST(HttpCache, RangeGET_206ReturnsWrongRange_CachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Write to the cache (70-79).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 70-79\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);
  Verify206Response(headers, 70, 79);

  // Request a large range (30-79). The cache will ask the server for 30-69.
  // The server returns 40-49. The cache should consider the server confused and
  // abort caching, returning the weird range to the caller.
  transaction.request_headers = "Range: bytes = 30-79\r\n" EXTRA_HEADER;
  transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 10\n"
      "Content-Range: bytes 40-49/80\n";
  transaction.handler = nullptr;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The entry was deleted.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that when a caller asks for a range beyond EOF, with an empty cache,
// the response matches the one provided by the server.
TEST(HttpCache, RangeGET_206ReturnsSmallerFile_NoCachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Request a large range (70-99). The server sends 70-79.
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 70-99\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 70, 79);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  EXPECT_EQ(1, cache.disk_cache()->open_count());
}

// Tests that when a caller asks for a range beyond EOF, with a cached entry,
// the cache automatically fixes the request.
TEST(HttpCache, RangeGET_206ReturnsSmallerFile_CachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Write to the cache (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  // Request a large range (70-99). The server sends 70-79.
  transaction.request_headers = "Range: bytes = 70-99\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 70, 79);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The entry was not deleted (the range was automatically fixed).
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that when a caller asks for a not-satisfiable range, the server's
// response is forwarded to the caller.
TEST(HttpCache, RangeGET_416_NoCachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Request a range beyond EOF (80-99).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 80-99\r\n" EXTRA_HEADER;
  transaction.data = "";
  transaction.status = "HTTP/1.1 416 Requested Range Not Satisfiable";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(0U, headers.find(transaction.status));
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The entry was deleted.
  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we cache 301s for range requests.
TEST(HttpCache, RangeGET_301) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.status = "HTTP/1.1 301 Moved Permanently";
  transaction.response_headers = "Location: http://www.bar.com/\n";
  transaction.data = "";
  transaction.handler = NULL;

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Read from the cache.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we can cache range requests when the start or end is unknown.
// We start with one suffix request, followed by a request from a given point.
TEST(HttpCache, UnknownRangeGET_1) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);
  std::string headers;

  // Write to the cache (70-79).
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = -10\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 70, 79);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Write and read from the cache (60-79).
  transaction.request_headers = "Range: bytes = 60-\r\n" EXTRA_HEADER;
  transaction.data = "rg: 60-69 rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 60, 79);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Tests that we can cache range requests when the start or end is unknown.
// We start with one request from a given point, followed by a suffix request.
// We'll also verify that synchronous cache responses work as intended.
TEST(HttpCache, UnknownRangeGET_2) {
  MockHttpCache cache;
  std::string headers;

  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.test_mode = TEST_MODE_SYNC_CACHE_START |
                          TEST_MODE_SYNC_CACHE_READ |
                          TEST_MODE_SYNC_CACHE_WRITE;
  AddMockTransaction(&transaction);

  // Write to the cache (70-79).
  transaction.request_headers = "Range: bytes = 70-\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 70, 79);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Write and read from the cache (60-79).
  transaction.request_headers = "Range: bytes = -20\r\n" EXTRA_HEADER;
  transaction.data = "rg: 60-69 rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 60, 79);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RemoveMockTransaction(&transaction);
}

// Tests that receiving Not Modified when asking for an open range doesn't mess
// up things.
TEST(HttpCache, UnknownRangeGET_304) {
  MockHttpCache cache;
  std::string headers;

  MockTransaction transaction(kRangeGET_TransactionOK);
  AddMockTransaction(&transaction);

  RangeTransactionServer handler;
  handler.set_not_modified(true);

  // Ask for the end of the file, without knowing the length.
  transaction.request_headers = "Range: bytes = 70-\r\n" EXTRA_HEADER;
  transaction.data = "";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  // We just bypass the cache.
  EXPECT_EQ(0U, headers.find("HTTP/1.1 304 Not Modified\n"));
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  RemoveMockTransaction(&transaction);
}

// Tests that we can handle non-range requests when we have cached a range.
TEST(HttpCache, GET_Previous206) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);
  std::string headers;
  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;

  // Write to the cache (40-49).
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), kRangeGET_TransactionOK, &headers, log.bound(),
      &load_timing_info);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);

  // Write and read from the cache (0-79), when not asked for a range.
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = EXTRA_HEADER;
  transaction.data = kFullRangeData;
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), transaction, &headers, log.bound(),
      &load_timing_info);

  EXPECT_EQ(0U, headers.find("HTTP/1.1 200 OK\n"));
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Tests that we can handle non-range requests when we have cached the first
// part of the object and the server replies with 304 (Not Modified).
TEST(HttpCache, GET_Previous206_NotModified) {
  MockHttpCache cache;

  MockTransaction transaction(kRangeGET_TransactionOK);
  AddMockTransaction(&transaction);
  std::string headers;
  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;

  // Write to the cache (0-9).
  transaction.request_headers = "Range: bytes = 0-9\r\n" EXTRA_HEADER;
  transaction.data = "rg: 00-09 ";
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), transaction, &headers, log.bound(),
      &load_timing_info);
  Verify206Response(headers, 0, 9);
  TestLoadTimingNetworkRequest(load_timing_info);

  // Write to the cache (70-79).
  transaction.request_headers = "Range: bytes = 70-79\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), transaction, &headers, log.bound(),
      &load_timing_info);
  Verify206Response(headers, 70, 79);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);

  // Read from the cache (0-9), write and read from cache (10 - 79).
  transaction.load_flags |= LOAD_VALIDATE_CACHE;
  transaction.request_headers = "Foo: bar\r\n" EXTRA_HEADER;
  transaction.data = kFullRangeData;
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), transaction, &headers, log.bound(),
      &load_timing_info);

  EXPECT_EQ(0U, headers.find("HTTP/1.1 200 OK\n"));
  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);

  RemoveMockTransaction(&transaction);
}

// Tests that we can handle a regular request to a sparse entry, that results in
// new content provided by the server (206).
TEST(HttpCache, GET_Previous206_NewContent) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);
  std::string headers;

  // Write to the cache (0-9).
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 0-9\r\n" EXTRA_HEADER;
  transaction.data = "rg: 00-09 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 0, 9);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now we'll issue a request without any range that should result first in a
  // 206 (when revalidating), and then in a weird standard answer: the test
  // server will not modify the response so we'll get the default range... a
  // real server will answer with 200.
  MockTransaction transaction2(kRangeGET_TransactionOK);
  transaction2.request_headers = EXTRA_HEADER;
  transaction2.load_flags |= LOAD_VALIDATE_CACHE;
  transaction2.data = "Not a range";
  RangeTransactionServer handler;
  handler.set_modified(true);
  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), transaction2, &headers, log.bound(),
      &load_timing_info);

  EXPECT_EQ(0U, headers.find("HTTP/1.1 200 OK\n"));
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);

  // Verify that the previous request deleted the entry.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  RemoveMockTransaction(&transaction);
}

// Tests that we can handle cached 206 responses that are not sparse.
TEST(HttpCache, GET_Previous206_NotSparse) {
  MockHttpCache cache;

  // Create a disk cache entry that stores 206 headers while not being sparse.
  disk_cache::Entry* entry;
  ASSERT_TRUE(cache.CreateBackendEntry(kSimpleGET_Transaction.url, &entry,
                                       NULL));

  std::string raw_headers(kRangeGET_TransactionOK.status);
  raw_headers.append("\n");
  raw_headers.append(kRangeGET_TransactionOK.response_headers);
  raw_headers =
      HttpUtil::AssembleRawHeaders(raw_headers.data(), raw_headers.size());

  HttpResponseInfo response;
  response.headers = new HttpResponseHeaders(raw_headers);
  EXPECT_TRUE(MockHttpCache::WriteResponseInfo(entry, &response, true, false));

  scoped_refptr<IOBuffer> buf(new IOBuffer(500));
  int len = static_cast<int>(base::strlcpy(buf->data(),
                                           kRangeGET_TransactionOK.data, 500));
  TestCompletionCallback cb;
  int rv = entry->WriteData(1, 0, buf.get(), len, cb.callback(), true);
  EXPECT_EQ(len, cb.GetResult(rv));
  entry->Close();

  // Now see that we don't use the stored entry.
  std::string headers;
  BoundTestNetLog log;
  LoadTimingInfo load_timing_info;
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), kSimpleGET_Transaction, &headers, log.bound(),
      &load_timing_info);

  // We are expecting a 200.
  std::string expected_headers(kSimpleGET_Transaction.status);
  expected_headers.append("\n");
  expected_headers.append(kSimpleGET_Transaction.response_headers);
  EXPECT_EQ(expected_headers, headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

// Tests that we can handle cached 206 responses that are not sparse. This time
// we issue a range request and expect to receive a range.
TEST(HttpCache, RangeGET_Previous206_NotSparse_2) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);

  // Create a disk cache entry that stores 206 headers while not being sparse.
  disk_cache::Entry* entry;
  ASSERT_TRUE(cache.CreateBackendEntry(kRangeGET_TransactionOK.url, &entry,
                                       NULL));

  std::string raw_headers(kRangeGET_TransactionOK.status);
  raw_headers.append("\n");
  raw_headers.append(kRangeGET_TransactionOK.response_headers);
  raw_headers =
      HttpUtil::AssembleRawHeaders(raw_headers.data(), raw_headers.size());

  HttpResponseInfo response;
  response.headers = new HttpResponseHeaders(raw_headers);
  EXPECT_TRUE(MockHttpCache::WriteResponseInfo(entry, &response, true, false));

  scoped_refptr<IOBuffer> buf(new IOBuffer(500));
  int len = static_cast<int>(base::strlcpy(buf->data(),
                                           kRangeGET_TransactionOK.data, 500));
  TestCompletionCallback cb;
  int rv = entry->WriteData(1, 0, buf.get(), len, cb.callback(), true);
  EXPECT_EQ(len, cb.GetResult(rv));
  entry->Close();

  // Now see that we don't use the stored entry.
  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  // We are expecting a 206.
  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Tests that we can handle cached 206 responses that can't be validated.
TEST(HttpCache, GET_Previous206_NotValidation) {
  MockHttpCache cache;

  // Create a disk cache entry that stores 206 headers.
  disk_cache::Entry* entry;
  ASSERT_TRUE(cache.CreateBackendEntry(kSimpleGET_Transaction.url, &entry,
                                       NULL));

  // Make sure that the headers cannot be validated with the server.
  std::string raw_headers(kRangeGET_TransactionOK.status);
  raw_headers.append("\n");
  raw_headers.append("Content-Length: 80\n");
  raw_headers =
      HttpUtil::AssembleRawHeaders(raw_headers.data(), raw_headers.size());

  HttpResponseInfo response;
  response.headers = new HttpResponseHeaders(raw_headers);
  EXPECT_TRUE(MockHttpCache::WriteResponseInfo(entry, &response, true, false));

  scoped_refptr<IOBuffer> buf(new IOBuffer(500));
  int len = static_cast<int>(base::strlcpy(buf->data(),
                                           kRangeGET_TransactionOK.data, 500));
  TestCompletionCallback cb;
  int rv = entry->WriteData(1, 0, buf.get(), len, cb.callback(), true);
  EXPECT_EQ(len, cb.GetResult(rv));
  entry->Close();

  // Now see that we don't use the stored entry.
  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), kSimpleGET_Transaction,
                                 &headers);

  // We are expecting a 200.
  std::string expected_headers(kSimpleGET_Transaction.status);
  expected_headers.append("\n");
  expected_headers.append(kSimpleGET_Transaction.response_headers);
  EXPECT_EQ(expected_headers, headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Fails only on bots. crbug.com/533640
#if defined(OS_ANDROID)
#define MAYBE_RangeGET_Previous200 DISABLED_RangeGET_Previous200
#else
#define MAYBE_RangeGET_Previous200 RangeGET_Previous200
#endif
// Tests that we can handle range requests with cached 200 responses.
TEST(HttpCache, MAYBE_RangeGET_Previous200) {
  MockHttpCache cache;

  // Store the whole thing with status 200.
  MockTransaction transaction(kTypicalGET_Transaction);
  transaction.url = kRangeGET_TransactionOK.url;
  transaction.data = kFullRangeData;
  AddMockTransaction(&transaction);
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RemoveMockTransaction(&transaction);
  AddMockTransaction(&kRangeGET_TransactionOK);

  // Now see that we use the stored entry.
  std::string headers;
  MockTransaction transaction2(kRangeGET_TransactionOK);
  RangeTransactionServer handler;
  handler.set_not_modified(true);
  RunTransactionTestWithResponse(cache.http_cache(), transaction2, &headers);

  // We are expecting a 206.
  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The last transaction has finished so make sure the entry is deactivated.
  base::RunLoop().RunUntilIdle();

  // Make a request for an invalid range.
  MockTransaction transaction3(kRangeGET_TransactionOK);
  transaction3.request_headers = "Range: bytes = 80-90\r\n" EXTRA_HEADER;
  transaction3.data = transaction.data;
  transaction3.load_flags = LOAD_PREFERRING_CACHE;
  RunTransactionTestWithResponse(cache.http_cache(), transaction3, &headers);
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(0U, headers.find("HTTP/1.1 200 "));
  EXPECT_EQ(std::string::npos, headers.find("Content-Range:"));
  EXPECT_EQ(std::string::npos, headers.find("Content-Length: 80"));

  // Make sure the entry is deactivated.
  base::RunLoop().RunUntilIdle();

  // Even though the request was invalid, we should have the entry.
  RunTransactionTest(cache.http_cache(), transaction2);
  EXPECT_EQ(3, cache.disk_cache()->open_count());

  // Make sure the entry is deactivated.
  base::RunLoop().RunUntilIdle();

  // Now we should receive a range from the server and drop the stored entry.
  handler.set_not_modified(false);
  transaction2.request_headers = kRangeGET_TransactionOK.request_headers;
  RunTransactionTestWithResponse(cache.http_cache(), transaction2, &headers);
  Verify206Response(headers, 40, 49);
  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(4, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTest(cache.http_cache(), transaction2);
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Tests that we can handle a 200 response when dealing with sparse entries.
TEST(HttpCache, RangeRequestResultsIn200) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);
  std::string headers;

  // Write to the cache (70-79).
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = -10\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 70, 79);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now we'll issue a request that results in a plain 200 response, but to
  // the to the same URL that we used to store sparse data, and making sure
  // that we ask for a range.
  RemoveMockTransaction(&kRangeGET_TransactionOK);
  MockTransaction transaction2(kSimpleGET_Transaction);
  transaction2.url = kRangeGET_TransactionOK.url;
  transaction2.request_headers = kRangeGET_TransactionOK.request_headers;
  AddMockTransaction(&transaction2);

  RunTransactionTestWithResponse(cache.http_cache(), transaction2, &headers);

  std::string expected_headers(kSimpleGET_Transaction.status);
  expected_headers.append("\n");
  expected_headers.append(kSimpleGET_Transaction.response_headers);
  EXPECT_EQ(expected_headers, headers);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RemoveMockTransaction(&transaction2);
}

// Tests that a range request that falls outside of the size that we know about
// only deletes the entry if the resource has indeed changed.
TEST(HttpCache, RangeGET_MoreThanCurrentSize) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);
  std::string headers;

  // Write to the cache (40-49).
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // A weird request should not delete this entry. Ask for bytes 120-.
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 120-\r\n" EXTRA_HEADER;
  transaction.data = "";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(0U, headers.find("HTTP/1.1 416 "));
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Fails only on bots. crbug.com/533640
#if defined(OS_ANDROID)
#define MAYBE_RangeGET_Cancel DISABLED_RangeGET_Cancel
#else
#define MAYBE_RangeGET_Cancel RangeGET_Cancel
#endif
// Tests that we don't delete a sparse entry when we cancel a request.
TEST(HttpCache, MAYBE_RangeGET_Cancel) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);

  MockHttpRequest request(kRangeGET_TransactionOK);

  Context* c = new Context();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING)
    rv = c->callback.WaitForResult();

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the entry has some data stored.
  scoped_refptr<IOBufferWithSize> buf(new IOBufferWithSize(10));
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  if (rv == ERR_IO_PENDING)
    rv = c->callback.WaitForResult();
  EXPECT_EQ(buf->size(), rv);

  // Destroy the transaction.
  delete c;

  // Verify that the entry has not been deleted.
  disk_cache::Entry* entry;
  ASSERT_TRUE(cache.OpenBackendEntry(kRangeGET_TransactionOK.url, &entry));
  entry->Close();
  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Fails only on bots. crbug.com/533640
#if defined(OS_ANDROID)
#define MAYBE_RangeGET_Cancel2 DISABLED_RangeGET_Cancel2
#else
#define MAYBE_RangeGET_Cancel2 RangeGET_Cancel2
#endif
// Tests that we don't delete a sparse entry when we start a new request after
// cancelling the previous one.
TEST(HttpCache, MAYBE_RangeGET_Cancel2) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);

  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  MockHttpRequest request(kRangeGET_TransactionOK);
  request.load_flags |= LOAD_VALIDATE_CACHE;

  Context* c = new Context();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING)
    rv = c->callback.WaitForResult();

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that we revalidate the entry and read from the cache (a single
  // read will return while waiting for the network).
  scoped_refptr<IOBufferWithSize> buf(new IOBufferWithSize(5));
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  EXPECT_EQ(5, c->callback.GetResult(rv));
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Destroy the transaction before completing the read.
  delete c;

  // We have the read and the delete (OnProcessPendingQueue) waiting on the
  // message loop. This means that a new transaction will just reuse the same
  // active entry (no open or create).

  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// A slight variation of the previous test, this time we cancel two requests in
// a row, making sure that the second is waiting for the entry to be ready.
TEST(HttpCache, RangeGET_Cancel3) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);

  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  MockHttpRequest request(kRangeGET_TransactionOK);
  request.load_flags |= LOAD_VALIDATE_CACHE;

  Context* c = new Context();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = c->callback.WaitForResult();

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that we revalidate the entry and read from the cache (a single
  // read will return while waiting for the network).
  scoped_refptr<IOBufferWithSize> buf(new IOBufferWithSize(5));
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  EXPECT_EQ(5, c->callback.GetResult(rv));
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Destroy the transaction before completing the read.
  delete c;

  // We have the read and the delete (OnProcessPendingQueue) waiting on the
  // message loop. This means that a new transaction will just reuse the same
  // active entry (no open or create).

  c = new Context();
  rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  MockDiskEntry::IgnoreCallbacks(true);
  base::RunLoop().RunUntilIdle();
  MockDiskEntry::IgnoreCallbacks(false);

  // The new transaction is waiting for the query range callback.
  delete c;

  // And we should not crash when the callback is delivered.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Tests that an invalid range response results in no cached entry.
TEST(HttpCache, RangeGET_InvalidResponse1) {
  MockHttpCache cache;
  std::string headers;

  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.handler = NULL;
  transaction.response_headers = "Content-Range: bytes 40-49/45\n"
                                 "Content-Length: 10\n";
  AddMockTransaction(&transaction);
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  std::string expected(transaction.status);
  expected.append("\n");
  expected.append(transaction.response_headers);
  EXPECT_EQ(expected, headers);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that we don't have a cached entry.
  disk_cache::Entry* entry;
  EXPECT_FALSE(cache.OpenBackendEntry(kRangeGET_TransactionOK.url, &entry));

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Tests that we reject a range that doesn't match the content-length.
TEST(HttpCache, RangeGET_InvalidResponse2) {
  MockHttpCache cache;
  std::string headers;

  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.handler = NULL;
  transaction.response_headers = "Content-Range: bytes 40-49/80\n"
                                 "Content-Length: 20\n";
  AddMockTransaction(&transaction);
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  std::string expected(transaction.status);
  expected.append("\n");
  expected.append(transaction.response_headers);
  EXPECT_EQ(expected, headers);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that we don't have a cached entry.
  disk_cache::Entry* entry;
  EXPECT_FALSE(cache.OpenBackendEntry(kRangeGET_TransactionOK.url, &entry));

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Tests that if a server tells us conflicting information about a resource we
// drop the entry.
TEST(HttpCache, RangeGET_InvalidResponse3) {
  MockHttpCache cache;
  std::string headers;

  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.handler = NULL;
  transaction.request_headers = "Range: bytes = 50-59\r\n" EXTRA_HEADER;
  std::string response_headers(transaction.response_headers);
  response_headers.append("Content-Range: bytes 50-59/160\n");
  transaction.response_headers = response_headers.c_str();
  AddMockTransaction(&transaction);
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 50, 59);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RemoveMockTransaction(&transaction);
  AddMockTransaction(&kRangeGET_TransactionOK);

  // This transaction will report a resource size of 80 bytes, and we think it's
  // 160 so we should ignore the response.
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that the entry is gone.
  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Tests that we handle large range values properly.
TEST(HttpCache, RangeGET_LargeValues) {
  // We need a real sparse cache for this test.
  MockHttpCache cache(HttpCache::DefaultBackend::InMemory(1024 * 1024));
  std::string headers;

  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.handler = NULL;
  transaction.request_headers = "Range: bytes = 4294967288-4294967297\r\n"
                                EXTRA_HEADER;
  transaction.response_headers =
      "ETag: \"foo\"\n"
      "Content-Range: bytes 4294967288-4294967297/4294967299\n"
      "Content-Length: 10\n";
  AddMockTransaction(&transaction);
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  std::string expected(transaction.status);
  expected.append("\n");
  expected.append(transaction.response_headers);
  EXPECT_EQ(expected, headers);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // Verify that we have a cached entry.
  disk_cache::Entry* en;
  ASSERT_TRUE(cache.OpenBackendEntry(kRangeGET_TransactionOK.url, &en));
  en->Close();

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Tests that we don't crash with a range request if the disk cache was not
// initialized properly.
TEST(HttpCache, RangeGET_NoDiskCache) {
  std::unique_ptr<MockBlockingBackendFactory> factory(
      new MockBlockingBackendFactory());
  factory->set_fail(true);
  factory->FinishCreation();  // We'll complete synchronously.
  MockHttpCache cache(std::move(factory));

  AddMockTransaction(&kRangeGET_TransactionOK);

  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Tests that we handle byte range requests that skip the cache.
TEST(HttpCache, RangeHEAD) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);

  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = -10\r\n" EXTRA_HEADER;
  transaction.method = "HEAD";
  transaction.data = "rg: 70-79 ";

  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 70, 79);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Tests that we don't crash when after reading from the cache we issue a
// request for the next range and the server gives us a 200 synchronously.
TEST(HttpCache, RangeGET_FastFlakyServer) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 40-\r\n" EXTRA_HEADER;
  transaction.test_mode = TEST_MODE_SYNC_NET_START;
  transaction.load_flags |= LOAD_VALIDATE_CACHE;

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);

  // And now read from the cache and the network.
  RangeTransactionServer handler;
  handler.set_bad_200(true);
  transaction.data = "Not a range";
  BoundTestNetLog log;
  RunTransactionTestWithLog(cache.http_cache(), transaction, log.bound());

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  EXPECT_TRUE(LogContainsEventType(
      log, NetLogEventType::HTTP_CACHE_RE_SEND_PARTIAL_REQUEST));
}

// Tests that when the server gives us less data than expected, we don't keep
// asking for more data.
TEST(HttpCache, RangeGET_FastFlakyServer2) {
  MockHttpCache cache;

  // First, check with an empty cache (WRITE mode).
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 40-49\r\n" EXTRA_HEADER;
  transaction.data = "rg: 40-";  // Less than expected.
  transaction.handler = NULL;
  std::string headers(transaction.response_headers);
  headers.append("Content-Range: bytes 40-49/80\n");
  transaction.response_headers = headers.c_str();

  AddMockTransaction(&transaction);

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now verify that even in READ_WRITE mode, we forward the bad response to
  // the caller.
  transaction.request_headers = "Range: bytes = 60-69\r\n" EXTRA_HEADER;
  transaction.data = "rg: 60-";  // Less than expected.
  headers = kRangeGET_TransactionOK.response_headers;
  headers.append("Content-Range: bytes 60-69/80\n");
  transaction.response_headers = headers.c_str();

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RemoveMockTransaction(&transaction);
}

#if defined(NDEBUG) && !defined(DCHECK_ALWAYS_ON)
// This test hits a NOTREACHED so it is a release mode only test.
TEST(HttpCache, RangeGET_OK_LoadOnlyFromCache) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);

  // Write to the cache (40-49).
  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Force this transaction to read from the cache.
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE;

  MockHttpRequest request(transaction);
  TestCompletionCallback callback;

  std::unique_ptr<HttpTransaction> trans;
  int rv = cache.http_cache()->CreateTransaction(DEFAULT_PRIORITY, &trans);
  EXPECT_THAT(rv, IsOk());
  ASSERT_TRUE(trans.get());

  rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_CACHE_MISS));

  trans.reset();

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}
#endif

// Tests the handling of the "truncation" flag.
TEST(HttpCache, WriteResponseInfo_Truncated) {
  MockHttpCache cache;
  disk_cache::Entry* entry;
  ASSERT_TRUE(cache.CreateBackendEntry("http://www.google.com", &entry,
                                       NULL));

  std::string headers("HTTP/1.1 200 OK");
  headers = HttpUtil::AssembleRawHeaders(headers.data(), headers.size());
  HttpResponseInfo response;
  response.headers = new HttpResponseHeaders(headers);

  // Set the last argument for this to be an incomplete request.
  EXPECT_TRUE(MockHttpCache::WriteResponseInfo(entry, &response, true, true));
  bool truncated = false;
  EXPECT_TRUE(MockHttpCache::ReadResponseInfo(entry, &response, &truncated));
  EXPECT_TRUE(truncated);

  // And now test the opposite case.
  EXPECT_TRUE(MockHttpCache::WriteResponseInfo(entry, &response, true, false));
  truncated = true;
  EXPECT_TRUE(MockHttpCache::ReadResponseInfo(entry, &response, &truncated));
  EXPECT_FALSE(truncated);
  entry->Close();
}

// Tests basic pickling/unpickling of HttpResponseInfo.
TEST(HttpCache, PersistHttpResponseInfo) {
  // Set some fields (add more if needed.)
  HttpResponseInfo response1;
  response1.was_cached = false;
  response1.socket_address = HostPortPair("1.2.3.4", 80);
  response1.headers = new HttpResponseHeaders("HTTP/1.1 200 OK");

  // Pickle.
  base::Pickle pickle;
  response1.Persist(&pickle, false, false);

  // Unpickle.
  HttpResponseInfo response2;
  bool response_truncated;
  EXPECT_TRUE(response2.InitFromPickle(pickle, &response_truncated));
  EXPECT_FALSE(response_truncated);

  // Verify fields.
  EXPECT_TRUE(response2.was_cached);  // InitFromPickle sets this flag.
  EXPECT_EQ("1.2.3.4", response2.socket_address.host());
  EXPECT_EQ(80, response2.socket_address.port());
  EXPECT_EQ("HTTP/1.1 200 OK", response2.headers->GetStatusLine());
}

// Tests that we delete an entry when the request is cancelled before starting
// to read from the network.
TEST(HttpCache, DoomOnDestruction) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  Context* c = new Context();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING)
    c->result = c->callback.WaitForResult();

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Destroy the transaction. We only have the headers so we should delete this
  // entry.
  delete c;

  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we delete an entry when the request is cancelled if the response
// does not have content-length and strong validators.
TEST(HttpCache, DoomOnDestruction2) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  Context* c = new Context();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING)
    rv = c->callback.WaitForResult();

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the entry has some data stored.
  scoped_refptr<IOBufferWithSize> buf(new IOBufferWithSize(10));
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  if (rv == ERR_IO_PENDING)
    rv = c->callback.WaitForResult();
  EXPECT_EQ(buf->size(), rv);

  // Destroy the transaction.
  delete c;

  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we delete an entry when the request is cancelled if the response
// has an "Accept-Ranges: none" header.
TEST(HttpCache, DoomOnDestruction3) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers =
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Content-Length: 22\n"
      "Accept-Ranges: none\n"
      "Etag: \"foopy\"\n";
  AddMockTransaction(&transaction);
  MockHttpRequest request(transaction);

  Context* c = new Context();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING)
    rv = c->callback.WaitForResult();

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the entry has some data stored.
  scoped_refptr<IOBufferWithSize> buf(new IOBufferWithSize(10));
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  if (rv == ERR_IO_PENDING)
    rv = c->callback.WaitForResult();
  EXPECT_EQ(buf->size(), rv);

  // Destroy the transaction.
  delete c;

  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  RemoveMockTransaction(&transaction);
}

// Tests that we mark an entry as incomplete when the request is cancelled.
TEST(HttpCache, SetTruncatedFlag) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers =
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Content-Length: 22\n"
      "Etag: \"foopy\"\n";
  MockHttpRequest request(transaction);

  std::unique_ptr<Context> c(new Context());

  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING)
    rv = c->callback.WaitForResult();

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the entry has some data stored.
  scoped_refptr<IOBufferWithSize> buf(new IOBufferWithSize(10));
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  if (rv == ERR_IO_PENDING)
    rv = c->callback.WaitForResult();
  EXPECT_EQ(buf->size(), rv);

  // We want to cancel the request when the transaction is busy.
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_FALSE(c->callback.have_result());

  MockHttpCache::SetTestMode(TEST_MODE_SYNC_ALL);

  // Destroy the transaction.
  c->trans.reset();
  MockHttpCache::SetTestMode(0);


  // Make sure that we don't invoke the callback. We may have an issue if the
  // UrlRequestJob is killed directly (without cancelling the UrlRequest) so we
  // could end up with the transaction being deleted twice if we send any
  // notification from the transaction destructor (see http://crbug.com/31723).
  EXPECT_FALSE(c->callback.have_result());

  // Verify that the entry is marked as incomplete.
  VerifyTruncatedFlag(&cache, kSimpleGET_Transaction.url, true, 0);
}

// Tests that we don't mark an entry as truncated when we read everything.
TEST(HttpCache, DontSetTruncatedFlag) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers =
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Content-Length: 22\n"
      "Etag: \"foopy\"\n";
  MockHttpRequest request(transaction);

  std::unique_ptr<Context> c(new Context());
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(c->callback.GetResult(rv), IsOk());

  // Read everything.
  scoped_refptr<IOBufferWithSize> buf(new IOBufferWithSize(22));
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  EXPECT_EQ(buf->size(), c->callback.GetResult(rv));

  // Destroy the transaction.
  c->trans.reset();

  // Verify that the entry is not marked as truncated.
  VerifyTruncatedFlag(&cache, kSimpleGET_Transaction.url, false, 0);
}

// Tests that sparse entries don't set the truncate flag.
TEST(HttpCache, RangeGET_DontTruncate) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 0-19\r\n" EXTRA_HEADER;

  std::unique_ptr<MockHttpRequest> request(new MockHttpRequest(transaction));
  std::unique_ptr<HttpTransaction> trans;

  int rv = cache.http_cache()->CreateTransaction(DEFAULT_PRIORITY, &trans);
  EXPECT_THAT(rv, IsOk());

  TestCompletionCallback cb;
  rv = trans->Start(request.get(), cb.callback(), NetLogWithSource());
  EXPECT_EQ(0, cb.GetResult(rv));

  scoped_refptr<IOBuffer> buf(new IOBuffer(10));
  rv = trans->Read(buf.get(), 10, cb.callback());
  EXPECT_EQ(10, cb.GetResult(rv));

  // Should not trigger any DCHECK.
  trans.reset();
  VerifyTruncatedFlag(&cache, kRangeGET_TransactionOK.url, false, 0);
}

// Tests that sparse entries don't set the truncate flag (when the byte range
//  starts after 0).
TEST(HttpCache, RangeGET_DontTruncate2) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 30-49\r\n" EXTRA_HEADER;

  std::unique_ptr<MockHttpRequest> request(new MockHttpRequest(transaction));
  std::unique_ptr<HttpTransaction> trans;

  int rv = cache.http_cache()->CreateTransaction(DEFAULT_PRIORITY, &trans);
  EXPECT_THAT(rv, IsOk());

  TestCompletionCallback cb;
  rv = trans->Start(request.get(), cb.callback(), NetLogWithSource());
  EXPECT_EQ(0, cb.GetResult(rv));

  scoped_refptr<IOBuffer> buf(new IOBuffer(10));
  rv = trans->Read(buf.get(), 10, cb.callback());
  EXPECT_EQ(10, cb.GetResult(rv));

  // Should not trigger any DCHECK.
  trans.reset();
  VerifyTruncatedFlag(&cache, kRangeGET_TransactionOK.url, false, 0);
}

// Tests that we can continue with a request that was interrupted.
TEST(HttpCache, GET_IncompleteResource) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);

  std::string raw_headers("HTTP/1.1 200 OK\n"
                          "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
                          "ETag: \"foo\"\n"
                          "Accept-Ranges: bytes\n"
                          "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);

  // Now make a regular request.
  std::string headers;
  transaction.request_headers = EXTRA_HEADER;
  transaction.data = kFullRangeData;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  // We update the headers with the ones received while revalidating.
  std::string expected_headers(
      "HTTP/1.1 200 OK\n"
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "Accept-Ranges: bytes\n"
      "ETag: \"foo\"\n"
      "Content-Length: 80\n");

  EXPECT_EQ(expected_headers, headers);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that the disk entry was updated.
  VerifyTruncatedFlag(&cache, kRangeGET_TransactionOK.url, false, 80);
}

// Tests the handling of no-store when revalidating a truncated entry.
TEST(HttpCache, GET_IncompleteResource_NoStore) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);

  std::string raw_headers("HTTP/1.1 200 OK\n"
                          "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
                          "ETag: \"foo\"\n"
                          "Accept-Ranges: bytes\n"
                          "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);
  RemoveMockTransaction(&kRangeGET_TransactionOK);

  // Now make a regular request.
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = EXTRA_HEADER;
  std::string response_headers(transaction.response_headers);
  response_headers += ("Cache-Control: no-store\n");
  transaction.response_headers = response_headers.c_str();
  transaction.data = kFullRangeData;
  AddMockTransaction(&transaction);

  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  // We update the headers with the ones received while revalidating.
  std::string expected_headers(
      "HTTP/1.1 200 OK\n"
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "Accept-Ranges: bytes\n"
      "Cache-Control: no-store\n"
      "ETag: \"foo\"\n"
      "Content-Length: 80\n");

  EXPECT_EQ(expected_headers, headers);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that the disk entry was deleted.
  disk_cache::Entry* entry;
  EXPECT_FALSE(cache.OpenBackendEntry(kRangeGET_TransactionOK.url, &entry));
  RemoveMockTransaction(&transaction);
}

// Tests cancelling a request after the server sent no-store.
TEST(HttpCache, GET_IncompleteResource_Cancel) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);

  std::string raw_headers("HTTP/1.1 200 OK\n"
                          "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
                          "ETag: \"foo\"\n"
                          "Accept-Ranges: bytes\n"
                          "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);
  RemoveMockTransaction(&kRangeGET_TransactionOK);

  // Now make a regular request.
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = EXTRA_HEADER;
  std::string response_headers(transaction.response_headers);
  response_headers += ("Cache-Control: no-store\n");
  transaction.response_headers = response_headers.c_str();
  transaction.data = kFullRangeData;
  AddMockTransaction(&transaction);

  MockHttpRequest request(transaction);
  Context* c = new Context();

  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  // Queue another request to this transaction. We have to start this request
  // before the first one gets the response from the server and dooms the entry,
  // otherwise it will just create a new entry without being queued to the first
  // request.
  Context* pending = new Context();
  ASSERT_THAT(cache.CreateTransaction(&pending->trans), IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_EQ(ERR_IO_PENDING,
            pending->trans->Start(&request, pending->callback.callback(),
                                  NetLogWithSource()));
  EXPECT_THAT(c->callback.GetResult(rv), IsOk());

  // Make sure that the entry has some data stored.
  scoped_refptr<IOBufferWithSize> buf(new IOBufferWithSize(5));
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  EXPECT_EQ(5, c->callback.GetResult(rv));

  // Cancel the requests.
  delete c;
  delete pending;

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  base::RunLoop().RunUntilIdle();
  RemoveMockTransaction(&transaction);
}

// Tests that we delete truncated entries if the server changes its mind midway.
TEST(HttpCache, GET_IncompleteResource2) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);

  // Content-length will be intentionally bad.
  std::string raw_headers("HTTP/1.1 200 OK\n"
                          "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
                          "ETag: \"foo\"\n"
                          "Accept-Ranges: bytes\n"
                          "Content-Length: 50\n");
  CreateTruncatedEntry(raw_headers, &cache);

  // Now make a regular request. We expect the code to fail the validation and
  // retry the request without using byte ranges.
  std::string headers;
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = EXTRA_HEADER;
  transaction.data = "Not a range";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  // The server will return 200 instead of a byte range.
  std::string expected_headers(
      "HTTP/1.1 200 OK\n"
      "Date: Wed, 28 Nov 2007 09:40:09 GMT\n");

  EXPECT_EQ(expected_headers, headers);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that the disk entry was deleted.
  disk_cache::Entry* entry;
  ASSERT_FALSE(cache.OpenBackendEntry(kRangeGET_TransactionOK.url, &entry));
  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Tests that we always validate a truncated request.
TEST(HttpCache, GET_IncompleteResource3) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);

  // This should not require validation for 10 hours.
  std::string raw_headers("HTTP/1.1 200 OK\n"
                          "Last-Modified: Sat, 18 Apr 2009 01:10:43 GMT\n"
                          "ETag: \"foo\"\n"
                          "Cache-Control: max-age= 36000\n"
                          "Accept-Ranges: bytes\n"
                          "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);

  // Now make a regular request.
  std::string headers;
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = EXTRA_HEADER;
  transaction.data = kFullRangeData;

  std::unique_ptr<Context> c(new Context);
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  MockHttpRequest request(transaction);
  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(c->callback.GetResult(rv), IsOk());

  // We should have checked with the server before finishing Start().
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Tests that we handle 401s for truncated resources.
TEST(HttpCache, GET_IncompleteResourceWithAuth) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);

  std::string raw_headers("HTTP/1.1 200 OK\n"
                          "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
                          "ETag: \"foo\"\n"
                          "Accept-Ranges: bytes\n"
                          "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);

  // Now make a regular request.
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "X-Require-Mock-Auth: dummy\r\n"
                                EXTRA_HEADER;
  transaction.data = kFullRangeData;
  RangeTransactionServer handler;

  std::unique_ptr<Context> c(new Context);
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  MockHttpRequest request(transaction);
  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(c->callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = c->trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_EQ(401, response->headers->response_code());
  rv = c->trans->RestartWithAuth(AuthCredentials(), c->callback.callback());
  EXPECT_THAT(c->callback.GetResult(rv), IsOk());
  response = c->trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_EQ(200, response->headers->response_code());

  ReadAndVerifyTransaction(c->trans.get(), transaction);
  c.reset();  // The destructor could delete the entry.
  EXPECT_EQ(2, cache.network_layer()->transaction_count());

  // Verify that the entry was not deleted.
  disk_cache::Entry* entry;
  ASSERT_TRUE(cache.OpenBackendEntry(kRangeGET_TransactionOK.url, &entry));
  entry->Close();

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

// Test that the transaction won't retry failed partial requests
// after it starts reading data.  http://crbug.com/474835
TEST(HttpCache, TransactionRetryLimit) {
  MockHttpCache cache;

  // Cache 0-9, so that we have data to read before failing.
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 0-9\r\n" EXTRA_HEADER;
  transaction.data = "rg: 00-09 ";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // And now read from the cache and the network.  10-19 will get a
  // 401, but will have already returned 0-9.
  // We do not set X-Require-Mock-Auth because that causes the mock
  // network transaction to become IsReadyToRestartForAuth().
  transaction.request_headers =
      "Range: bytes = 0-79\r\n"
      "X-Require-Mock-Auth-Alt: dummy\r\n" EXTRA_HEADER;

  std::unique_ptr<Context> c(new Context);
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  MockHttpRequest request(transaction);

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING)
    rv = c->callback.WaitForResult();
  std::string content;
  rv = ReadTransaction(c->trans.get(), &content);
  EXPECT_THAT(rv, IsError(ERR_CACHE_AUTH_FAILURE_AFTER_READ));
}

// Tests that we cache a 200 response to the validation request.
TEST(HttpCache, GET_IncompleteResource4) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);

  std::string raw_headers("HTTP/1.1 200 OK\n"
                          "Last-Modified: Sat, 18 Apr 2009 01:10:43 GMT\n"
                          "ETag: \"foo\"\n"
                          "Accept-Ranges: bytes\n"
                          "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);

  // Now make a regular request.
  std::string headers;
  transaction.request_headers = EXTRA_HEADER;
  transaction.data = "Not a range";
  RangeTransactionServer handler;
  handler.set_bad_200(true);
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that the disk entry was updated.
  VerifyTruncatedFlag(&cache, kRangeGET_TransactionOK.url, false, 11);
}

// Tests that when we cancel a request that was interrupted, we mark it again
// as truncated.
TEST(HttpCache, GET_CancelIncompleteResource) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);

  std::string raw_headers("HTTP/1.1 200 OK\n"
                          "Last-Modified: Sat, 18 Apr 2009 01:10:43 GMT\n"
                          "ETag: \"foo\"\n"
                          "Accept-Ranges: bytes\n"
                          "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);

  // Now make a regular request.
  transaction.request_headers = EXTRA_HEADER;

  MockHttpRequest request(transaction);
  Context* c = new Context();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(c->callback.GetResult(rv), IsOk());

  // Read 20 bytes from the cache, and 10 from the net.
  scoped_refptr<IOBuffer> buf(new IOBuffer(100));
  rv = c->trans->Read(buf.get(), 20, c->callback.callback());
  EXPECT_EQ(20, c->callback.GetResult(rv));
  rv = c->trans->Read(buf.get(), 10, c->callback.callback());
  EXPECT_EQ(10, c->callback.GetResult(rv));

  // At this point, we are already reading so canceling the request should leave
  // a truncated one.
  delete c;

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that the disk entry was updated: now we have 30 bytes.
  VerifyTruncatedFlag(&cache, kRangeGET_TransactionOK.url, true, 30);
}

// Tests that we can handle range requests when we have a truncated entry.
TEST(HttpCache, RangeGET_IncompleteResource) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);

  // Content-length will be intentionally bogus.
  std::string raw_headers("HTTP/1.1 200 OK\n"
                          "Last-Modified: something\n"
                          "ETag: \"foo\"\n"
                          "Accept-Ranges: bytes\n"
                          "Content-Length: 10\n");
  CreateTruncatedEntry(raw_headers, &cache);

  // Now make a range request.
  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

TEST(HttpCache, SyncRead) {
  MockHttpCache cache;

  // This test ensures that a read that completes synchronously does not cause
  // any problems.

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.test_mode |= (TEST_MODE_SYNC_CACHE_START |
                            TEST_MODE_SYNC_CACHE_READ |
                            TEST_MODE_SYNC_CACHE_WRITE);

  MockHttpRequest r1(transaction),
                  r2(transaction),
                  r3(transaction);

  TestTransactionConsumer c1(DEFAULT_PRIORITY, cache.http_cache()),
      c2(DEFAULT_PRIORITY, cache.http_cache()),
      c3(DEFAULT_PRIORITY, cache.http_cache());

  c1.Start(&r1, NetLogWithSource());

  r2.load_flags |= LOAD_ONLY_FROM_CACHE;
  c2.Start(&r2, NetLogWithSource());

  r3.load_flags |= LOAD_ONLY_FROM_CACHE;
  c3.Start(&r3, NetLogWithSource());

  base::RunLoop().Run();

  EXPECT_TRUE(c1.is_done());
  EXPECT_TRUE(c2.is_done());
  EXPECT_TRUE(c3.is_done());

  EXPECT_THAT(c1.error(), IsOk());
  EXPECT_THAT(c2.error(), IsOk());
  EXPECT_THAT(c3.error(), IsOk());
}

TEST(HttpCache, ValidationResultsIn200) {
  MockHttpCache cache;

  // This test ensures that a conditional request, which results in a 200
  // instead of a 304, properly truncates the existing response data.

  // write to the cache
  RunTransactionTest(cache.http_cache(), kETagGET_Transaction);

  // force this transaction to validate the cache
  MockTransaction transaction(kETagGET_Transaction);
  transaction.load_flags |= LOAD_VALIDATE_CACHE;
  RunTransactionTest(cache.http_cache(), transaction);

  // read from the cache
  RunTransactionTest(cache.http_cache(), kETagGET_Transaction);
}

TEST(HttpCache, CachedRedirect) {
  MockHttpCache cache;

  ScopedMockTransaction kTestTransaction(kSimpleGET_Transaction);
  kTestTransaction.status = "HTTP/1.1 301 Moved Permanently";
  kTestTransaction.response_headers = "Location: http://www.bar.com/\n";

  MockHttpRequest request(kTestTransaction);
  TestCompletionCallback callback;

  // Write to the cache.
  {
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    if (rv == ERR_IO_PENDING)
      rv = callback.WaitForResult();
    ASSERT_THAT(rv, IsOk());

    const HttpResponseInfo* info = trans->GetResponseInfo();
    ASSERT_TRUE(info);

    EXPECT_EQ(info->headers->response_code(), 301);

    std::string location;
    info->headers->EnumerateHeader(NULL, "Location", &location);
    EXPECT_EQ(location, "http://www.bar.com/");

    // Mark the transaction as completed so it is cached.
    trans->DoneReading();

    // Destroy transaction when going out of scope. We have not actually
    // read the response body -- want to test that it is still getting cached.
  }
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Active entries in the cache are not retired synchronously. Make
  // sure the next run hits the MockHttpCache and open_count is
  // correct.
  base::RunLoop().RunUntilIdle();

  // Read from the cache.
  {
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    if (rv == ERR_IO_PENDING)
      rv = callback.WaitForResult();
    ASSERT_THAT(rv, IsOk());

    const HttpResponseInfo* info = trans->GetResponseInfo();
    ASSERT_TRUE(info);

    EXPECT_EQ(info->headers->response_code(), 301);

    std::string location;
    info->headers->EnumerateHeader(NULL, "Location", &location);
    EXPECT_EQ(location, "http://www.bar.com/");

    // Mark the transaction as completed so it is cached.
    trans->DoneReading();

    // Destroy transaction when going out of scope. We have not actually
    // read the response body -- want to test that it is still getting cached.
  }
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Verify that no-cache resources are stored in cache, but are not fetched from
// cache during normal loads.
TEST(HttpCache, CacheControlNoCacheNormalLoad) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers = "cache-control: no-cache\n";

  // Initial load.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Try loading again; it should result in a network fetch.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  disk_cache::Entry* entry;
  EXPECT_TRUE(cache.OpenBackendEntry(transaction.url, &entry));
  entry->Close();
}

// Verify that no-cache resources are stored in cache and fetched from cache
// when the LOAD_PREFERRING_CACHE flag is set.
TEST(HttpCache, CacheControlNoCacheHistoryLoad) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers = "cache-control: no-cache\n";

  // Initial load.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Try loading again with LOAD_PREFERRING_CACHE.
  transaction.load_flags = LOAD_PREFERRING_CACHE;
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  disk_cache::Entry* entry;
  EXPECT_TRUE(cache.OpenBackendEntry(transaction.url, &entry));
  entry->Close();
}

TEST(HttpCache, CacheControlNoStore) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers = "cache-control: no-store\n";

  // initial load
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // try loading again; it should result in a network fetch
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  disk_cache::Entry* entry;
  EXPECT_FALSE(cache.OpenBackendEntry(transaction.url, &entry));
}

TEST(HttpCache, CacheControlNoStore2) {
  // this test is similar to the above test, except that the initial response
  // is cachable, but when it is validated, no-store is received causing the
  // cached document to be deleted.
  MockHttpCache cache;

  ScopedMockTransaction transaction(kETagGET_Transaction);

  // initial load
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // try loading again; it should result in a network fetch
  transaction.load_flags = LOAD_VALIDATE_CACHE;
  transaction.response_headers = "cache-control: no-store\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  disk_cache::Entry* entry;
  EXPECT_FALSE(cache.OpenBackendEntry(transaction.url, &entry));
}

TEST(HttpCache, CacheControlNoStore3) {
  // this test is similar to the above test, except that the response is a 304
  // instead of a 200.  this should never happen in practice, but it seems like
  // a good thing to verify that we still destroy the cache entry.
  MockHttpCache cache;

  ScopedMockTransaction transaction(kETagGET_Transaction);

  // initial load
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // try loading again; it should result in a network fetch
  transaction.load_flags = LOAD_VALIDATE_CACHE;
  transaction.response_headers = "cache-control: no-store\n";
  transaction.status = "HTTP/1.1 304 Not Modified";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  disk_cache::Entry* entry;
  EXPECT_FALSE(cache.OpenBackendEntry(transaction.url, &entry));
}

// Ensure that we don't cache requests served over bad HTTPS.
TEST(HttpCache, SimpleGET_SSLError) {
  MockHttpCache cache;

  MockTransaction transaction = kSimpleGET_Transaction;
  transaction.cert_status = CERT_STATUS_REVOKED;
  ScopedMockTransaction scoped_transaction(transaction);

  // write to the cache
  RunTransactionTest(cache.http_cache(), transaction);

  // Test that it was not cached.
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE;

  MockHttpRequest request(transaction);
  TestCompletionCallback callback;

  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_CACHE_MISS));
}

// Ensure that we don't crash by if left-behind transactions.
TEST(HttpCache, OutlivedTransactions) {
  MockHttpCache* cache = new MockHttpCache;

  std::unique_ptr<HttpTransaction> trans;
  EXPECT_THAT(cache->CreateTransaction(&trans), IsOk());

  delete cache;
  trans.reset();
}

// Test that the disabled mode works.
TEST(HttpCache, CacheDisabledMode) {
  MockHttpCache cache;

  // write to the cache
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // go into disabled mode
  cache.http_cache()->set_mode(HttpCache::DISABLE);

  // force this transaction to write to the cache again
  MockTransaction transaction(kSimpleGET_Transaction);

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Other tests check that the response headers of the cached response
// get updated on 304. Here we specifically check that the
// HttpResponseHeaders::request_time and HttpResponseHeaders::response_time
// fields also gets updated.
// http://crbug.com/20594.
TEST(HttpCache, UpdatesRequestResponseTimeOn304) {
  MockHttpCache cache;

  const char kUrl[] = "http://foobar";
  const char kData[] = "body";

  MockTransaction mock_network_response = { 0 };
  mock_network_response.url = kUrl;

  AddMockTransaction(&mock_network_response);

  // Request |kUrl|, causing |kNetResponse1| to be written to the cache.

  MockTransaction request = { 0 };
  request.url = kUrl;
  request.method = "GET";
  request.request_headers = "\r\n";
  request.data = kData;

  static const Response kNetResponse1 = {
    "HTTP/1.1 200 OK",
    "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
    "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
    kData
  };

  kNetResponse1.AssignTo(&mock_network_response);

  RunTransactionTest(cache.http_cache(), request);

  // Request |kUrl| again, this time validating the cache and getting
  // a 304 back.

  request.load_flags = LOAD_VALIDATE_CACHE;

  static const Response kNetResponse2 = {
    "HTTP/1.1 304 Not Modified",
    "Date: Wed, 22 Jul 2009 03:15:26 GMT\n",
    ""
  };

  kNetResponse2.AssignTo(&mock_network_response);

  base::Time request_time = base::Time() + base::TimeDelta::FromHours(1234);
  base::Time response_time = base::Time() + base::TimeDelta::FromHours(1235);

  mock_network_response.request_time = request_time;
  mock_network_response.response_time = response_time;

  HttpResponseInfo response;
  RunTransactionTestWithResponseInfo(cache.http_cache(), request, &response);

  // The request and response times should have been updated.
  EXPECT_EQ(request_time.ToInternalValue(),
            response.request_time.ToInternalValue());
  EXPECT_EQ(response_time.ToInternalValue(),
            response.response_time.ToInternalValue());

  std::string headers;
  response.headers->GetNormalizedHeaders(&headers);

  EXPECT_EQ("HTTP/1.1 200 OK\n"
            "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
            "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
            headers);

  RemoveMockTransaction(&mock_network_response);
}

// Tests that we can write metadata to an entry.
TEST(HttpCache, WriteMetadata_OK) {
  MockHttpCache cache;

  // Write to the cache
  HttpResponseInfo response;
  RunTransactionTestWithResponseInfo(cache.http_cache(), kSimpleGET_Transaction,
                                     &response);
  EXPECT_TRUE(response.metadata.get() == NULL);

  // Trivial call.
  cache.http_cache()->WriteMetadata(GURL("foo"), DEFAULT_PRIORITY, Time::Now(),
                                    NULL, 0);

  // Write meta data to the same entry.
  scoped_refptr<IOBufferWithSize> buf(new IOBufferWithSize(50));
  memset(buf->data(), 0, buf->size());
  base::strlcpy(buf->data(), "Hi there", buf->size());
  cache.http_cache()->WriteMetadata(GURL(kSimpleGET_Transaction.url),
                                    DEFAULT_PRIORITY, response.response_time,
                                    buf.get(), buf->size());

  // Release the buffer before the operation takes place.
  buf = NULL;

  // Makes sure we finish pending operations.
  base::RunLoop().RunUntilIdle();

  RunTransactionTestWithResponseInfo(cache.http_cache(), kSimpleGET_Transaction,
                                     &response);
  ASSERT_TRUE(response.metadata.get() != NULL);
  EXPECT_EQ(50, response.metadata->size());
  EXPECT_EQ(0, strcmp(response.metadata->data(), "Hi there"));

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we only write metadata to an entry if the time stamp matches.
TEST(HttpCache, WriteMetadata_Fail) {
  MockHttpCache cache;

  // Write to the cache
  HttpResponseInfo response;
  RunTransactionTestWithResponseInfo(cache.http_cache(), kSimpleGET_Transaction,
                                     &response);
  EXPECT_TRUE(response.metadata.get() == NULL);

  // Attempt to write meta data to the same entry.
  scoped_refptr<IOBufferWithSize> buf(new IOBufferWithSize(50));
  memset(buf->data(), 0, buf->size());
  base::strlcpy(buf->data(), "Hi there", buf->size());
  base::Time expected_time = response.response_time -
                             base::TimeDelta::FromMilliseconds(20);
  cache.http_cache()->WriteMetadata(GURL(kSimpleGET_Transaction.url),
                                    DEFAULT_PRIORITY, expected_time, buf.get(),
                                    buf->size());

  // Makes sure we finish pending operations.
  base::RunLoop().RunUntilIdle();

  RunTransactionTestWithResponseInfo(cache.http_cache(), kSimpleGET_Transaction,
                                     &response);
  EXPECT_TRUE(response.metadata.get() == NULL);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we can read metadata after validating the entry and with READ mode
// transactions.
TEST(HttpCache, ReadMetadata) {
  MockHttpCache cache;

  // Write to the cache
  HttpResponseInfo response;
  RunTransactionTestWithResponseInfo(cache.http_cache(),
                                     kTypicalGET_Transaction, &response);
  EXPECT_TRUE(response.metadata.get() == NULL);

  // Write meta data to the same entry.
  scoped_refptr<IOBufferWithSize> buf(new IOBufferWithSize(50));
  memset(buf->data(), 0, buf->size());
  base::strlcpy(buf->data(), "Hi there", buf->size());
  cache.http_cache()->WriteMetadata(GURL(kTypicalGET_Transaction.url),
                                    DEFAULT_PRIORITY, response.response_time,
                                    buf.get(), buf->size());

  // Makes sure we finish pending operations.
  base::RunLoop().RunUntilIdle();

  // Start with a READ mode transaction.
  MockTransaction trans1(kTypicalGET_Transaction);
  trans1.load_flags = LOAD_ONLY_FROM_CACHE;

  RunTransactionTestWithResponseInfo(cache.http_cache(), trans1, &response);
  ASSERT_TRUE(response.metadata.get() != NULL);
  EXPECT_EQ(50, response.metadata->size());
  EXPECT_EQ(0, strcmp(response.metadata->data(), "Hi there"));

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  base::RunLoop().RunUntilIdle();

  // Now make sure that the entry is re-validated with the server.
  trans1.load_flags = LOAD_VALIDATE_CACHE;
  trans1.status = "HTTP/1.1 304 Not Modified";
  AddMockTransaction(&trans1);

  response.metadata = NULL;
  RunTransactionTestWithResponseInfo(cache.http_cache(), trans1, &response);
  EXPECT_TRUE(response.metadata.get() != NULL);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(3, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  base::RunLoop().RunUntilIdle();
  RemoveMockTransaction(&trans1);

  // Now return 200 when validating the entry so the metadata will be lost.
  MockTransaction trans2(kTypicalGET_Transaction);
  trans2.load_flags = LOAD_VALIDATE_CACHE;
  RunTransactionTestWithResponseInfo(cache.http_cache(), trans2, &response);
  EXPECT_TRUE(response.metadata.get() == NULL);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(4, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we don't mark entries as truncated when a filter detects the end
// of the stream.
TEST(HttpCache, FilterCompletion) {
  MockHttpCache cache;
  TestCompletionCallback callback;

  {
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    MockHttpRequest request(kSimpleGET_Transaction);
    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    scoped_refptr<IOBuffer> buf(new IOBuffer(256));
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_GT(callback.GetResult(rv), 0);

    // Now make sure that the entry is preserved.
    trans->DoneReading();
  }

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Read from the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we don't mark entries as truncated and release the cache
// entry when DoneReading() is called before any Read() calls, such as
// for a redirect.
TEST(HttpCache, DoneReading) {
  MockHttpCache cache;
  TestCompletionCallback callback;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.data = "";

  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

  MockHttpRequest request(transaction);
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  trans->DoneReading();
  // Leave the transaction around.

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Read from the cache. This should not deadlock.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we stop caching when told.
TEST(HttpCache, StopCachingDeletesEntry) {
  MockHttpCache cache;
  TestCompletionCallback callback;
  MockHttpRequest request(kSimpleGET_Transaction);

  {
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    scoped_refptr<IOBuffer> buf(new IOBuffer(256));
    rv = trans->Read(buf.get(), 10, callback.callback());
    EXPECT_EQ(10, callback.GetResult(rv));

    trans->StopCaching();

    // We should be able to keep reading.
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_GT(callback.GetResult(rv), 0);
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_EQ(0, callback.GetResult(rv));
  }

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Verify that the entry is gone.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we stop caching when told, even if DoneReading is called
// after StopCaching.
TEST(HttpCache, StopCachingThenDoneReadingDeletesEntry) {
  MockHttpCache cache;
  TestCompletionCallback callback;
  MockHttpRequest request(kSimpleGET_Transaction);

  {
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    scoped_refptr<IOBuffer> buf(new IOBuffer(256));
    rv = trans->Read(buf.get(), 10, callback.callback());
    EXPECT_EQ(10, callback.GetResult(rv));

    trans->StopCaching();

    // We should be able to keep reading.
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_GT(callback.GetResult(rv), 0);
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_EQ(0, callback.GetResult(rv));

    // We should be able to call DoneReading.
    trans->DoneReading();
  }

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Verify that the entry is gone.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we stop caching when told, when using auth.
TEST(HttpCache, StopCachingWithAuthDeletesEntry) {
  MockHttpCache cache;
  TestCompletionCallback callback;
  MockTransaction mock_transaction(kSimpleGET_Transaction);
  mock_transaction.status = "HTTP/1.1 401 Unauthorized";
  AddMockTransaction(&mock_transaction);
  MockHttpRequest request(mock_transaction);

  {
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    trans->StopCaching();

    scoped_refptr<IOBuffer> buf(new IOBuffer(256));
    rv = trans->Read(buf.get(), 10, callback.callback());
    EXPECT_EQ(callback.GetResult(rv), 10);
  }
  RemoveMockTransaction(&mock_transaction);

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Verify that the entry is gone.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that when we are told to stop caching we don't throw away valid data.
TEST(HttpCache, StopCachingSavesEntry) {
  MockHttpCache cache;
  TestCompletionCallback callback;
  MockHttpRequest request(kSimpleGET_Transaction);

  {
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    // Force a response that can be resumed.
    ScopedMockTransaction mock_transaction(kSimpleGET_Transaction);
    AddMockTransaction(&mock_transaction);
    mock_transaction.response_headers = "Cache-Control: max-age=10000\n"
                                        "Content-Length: 42\n"
                                        "Etag: \"foo\"\n";

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    scoped_refptr<IOBuffer> buf(new IOBuffer(256));
    rv = trans->Read(buf.get(), 10, callback.callback());
    EXPECT_EQ(callback.GetResult(rv), 10);

    trans->StopCaching();

    // We should be able to keep reading.
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_GT(callback.GetResult(rv), 0);
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_EQ(callback.GetResult(rv), 0);
  }

  // Verify that the entry is marked as incomplete.
  VerifyTruncatedFlag(&cache, kSimpleGET_Transaction.url, true, 0);
}

// Tests that we handle truncated enries when StopCaching is called.
TEST(HttpCache, StopCachingTruncatedEntry) {
  MockHttpCache cache;
  TestCompletionCallback callback;
  MockHttpRequest request(kRangeGET_TransactionOK);
  request.extra_headers.Clear();
  request.extra_headers.AddHeaderFromString(EXTRA_HEADER_LINE);
  AddMockTransaction(&kRangeGET_TransactionOK);

  std::string raw_headers("HTTP/1.1 200 OK\n"
                          "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
                          "ETag: \"foo\"\n"
                          "Accept-Ranges: bytes\n"
                          "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);

  {
    // Now make a regular request.
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    scoped_refptr<IOBuffer> buf(new IOBuffer(256));
    rv = trans->Read(buf.get(), 10, callback.callback());
    EXPECT_EQ(callback.GetResult(rv), 10);

    // This is actually going to do nothing.
    trans->StopCaching();

    // We should be able to keep reading.
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_GT(callback.GetResult(rv), 0);
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_GT(callback.GetResult(rv), 0);
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_EQ(callback.GetResult(rv), 0);
  }

  // Verify that the disk entry was updated.
  VerifyTruncatedFlag(&cache, kRangeGET_TransactionOK.url, false, 80);
  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

namespace {

enum class TransactionPhase {
  BEFORE_FIRST_READ,
  AFTER_FIRST_READ,
  AFTER_NETWORK_READ
};

using CacheInitializer = void (*)(MockHttpCache*);
using HugeCacheTestConfiguration =
    std::pair<TransactionPhase, CacheInitializer>;

class HttpCacheHugeResourceTest
    : public ::testing::TestWithParam<HugeCacheTestConfiguration> {
 public:
  static std::list<HugeCacheTestConfiguration> GetTestModes();
  static std::list<HugeCacheTestConfiguration> kTestModes;

  // CacheInitializer callbacks. These are used to initialize the cache
  // depending on the test run configuration.

  // Initializes a cache containing a truncated entry containing the first 20
  // bytes of the reponse body.
  static void SetupTruncatedCacheEntry(MockHttpCache* cache);

  // Initializes a cache containing a sparse entry. The first 10 bytes are
  // present in the cache.
  static void SetupPrefixSparseCacheEntry(MockHttpCache* cache);

  // Initializes a cache containing a sparse entry. The 10 bytes at offset
  // 99990 are present in the cache.
  static void SetupInfixSparseCacheEntry(MockHttpCache* cache);

 protected:
  static void LargeResourceTransactionHandler(
      const net::HttpRequestInfo* request,
      std::string* response_status,
      std::string* response_headers,
      std::string* response_data);
  static int LargeBufferReader(int64_t content_length,
                               int64_t offset,
                               net::IOBuffer* buf,
                               int buf_len);

  static void SetFlagOnBeforeNetworkStart(bool* started, bool* /* defer */);

  // Size of resource to be tested.
  static const int64_t kTotalSize = 5000LL * 1000 * 1000;
};

const int64_t HttpCacheHugeResourceTest::kTotalSize;

// static
void HttpCacheHugeResourceTest::LargeResourceTransactionHandler(
    const net::HttpRequestInfo* request,
    std::string* response_status,
    std::string* response_headers,
    std::string* response_data) {
  std::string if_range;
  if (!request->extra_headers.GetHeader(net::HttpRequestHeaders::kIfRange,
                                        &if_range)) {
    // If there were no range headers in the request, we are going to just
    // return the entire response body.
    *response_status = "HTTP/1.1 200 Success";
    *response_headers = base::StringPrintf("Content-Length: %" PRId64
                                           "\n"
                                           "ETag: \"foo\"\n"
                                           "Accept-Ranges: bytes\n",
                                           kTotalSize);
    return;
  }

  // From this point on, we should be processing a valid byte-range request.
  EXPECT_EQ("\"foo\"", if_range);

  std::string range_header;
  EXPECT_TRUE(request->extra_headers.GetHeader(net::HttpRequestHeaders::kRange,
                                               &range_header));
  std::vector<net::HttpByteRange> ranges;

  EXPECT_TRUE(net::HttpUtil::ParseRangeHeader(range_header, &ranges));
  ASSERT_EQ(1u, ranges.size());

  net::HttpByteRange range = ranges[0];
  EXPECT_TRUE(range.HasFirstBytePosition());
  int64_t last_byte_position =
      range.HasLastBytePosition() ? range.last_byte_position() : kTotalSize - 1;

  *response_status = "HTTP/1.1 206 Partial";
  *response_headers = base::StringPrintf(
      "Content-Range: bytes %" PRId64 "-%" PRId64 "/%" PRId64
      "\n"
      "Content-Length: %" PRId64 "\n",
      range.first_byte_position(), last_byte_position, kTotalSize,
      last_byte_position - range.first_byte_position() + 1);
}

// static
int HttpCacheHugeResourceTest::LargeBufferReader(int64_t content_length,
                                                 int64_t offset,
                                                 net::IOBuffer* buf,
                                                 int buf_len) {
  // This test involves reading multiple gigabytes of data. To make it run in a
  // reasonable amount of time, we are going to skip filling the buffer with
  // data. Instead the test relies on verifying that the count of bytes expected
  // at the end is correct.
  EXPECT_LT(0, content_length);
  EXPECT_LE(offset, content_length);
  int num = std::min(static_cast<int64_t>(buf_len), content_length - offset);
  return num;
}

// static
void HttpCacheHugeResourceTest::SetFlagOnBeforeNetworkStart(bool* started,
                                                            bool* /* defer */) {
  *started = true;
}

// static
void HttpCacheHugeResourceTest::SetupTruncatedCacheEntry(MockHttpCache* cache) {
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);
  std::string cached_headers = base::StringPrintf(
      "HTTP/1.1 200 OK\n"
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: %" PRId64 "\n",
      kTotalSize);
  CreateTruncatedEntry(cached_headers, cache);
}

// static
void HttpCacheHugeResourceTest::SetupPrefixSparseCacheEntry(
    MockHttpCache* cache) {
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.handler = nullptr;
  transaction.request_headers = "Range: bytes = 0-9\r\n" EXTRA_HEADER;
  transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Range: bytes 0-9/5000000000\n"
      "Content-Length: 10\n";
  AddMockTransaction(&transaction);
  std::string headers;
  RunTransactionTestWithResponse(cache->http_cache(), transaction, &headers);
  RemoveMockTransaction(&transaction);
}

// static
void HttpCacheHugeResourceTest::SetupInfixSparseCacheEntry(
    MockHttpCache* cache) {
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.handler = nullptr;
  transaction.request_headers = "Range: bytes = 99990-99999\r\n" EXTRA_HEADER;
  transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Range: bytes 99990-99999/5000000000\n"
      "Content-Length: 10\n";
  AddMockTransaction(&transaction);
  std::string headers;
  RunTransactionTestWithResponse(cache->http_cache(), transaction, &headers);
  RemoveMockTransaction(&transaction);
}

// static
std::list<HugeCacheTestConfiguration>
HttpCacheHugeResourceTest::GetTestModes() {
  std::list<HugeCacheTestConfiguration> test_modes;
  const TransactionPhase kTransactionPhases[] = {
      TransactionPhase::BEFORE_FIRST_READ, TransactionPhase::AFTER_FIRST_READ,
      TransactionPhase::AFTER_NETWORK_READ};
  const CacheInitializer kInitializers[] = {&SetupTruncatedCacheEntry,
                                            &SetupPrefixSparseCacheEntry,
                                            &SetupInfixSparseCacheEntry};

  for (const auto phase : kTransactionPhases)
    for (const auto initializer : kInitializers)
      test_modes.push_back(std::make_pair(phase, initializer));

  return test_modes;
}

// static
std::list<HugeCacheTestConfiguration> HttpCacheHugeResourceTest::kTestModes =
    HttpCacheHugeResourceTest::GetTestModes();

INSTANTIATE_TEST_CASE_P(
    _,
    HttpCacheHugeResourceTest,
    ::testing::ValuesIn(HttpCacheHugeResourceTest::kTestModes));

}  // namespace

// Test what happens when StopCaching() is called while reading a huge resource
// fetched via GET. Various combinations of cache state and when StopCaching()
// is called is controlled by the parameter passed into the test via the
// INSTANTIATE_TEST_CASE_P invocation above.
TEST_P(HttpCacheHugeResourceTest,
       StopCachingFollowedByReadForHugeTruncatedResource) {
  // This test is going to be repeated for all combinations of TransactionPhase
  // and CacheInitializers returned by GetTestModes().
  const TransactionPhase stop_caching_phase = GetParam().first;
  const CacheInitializer cache_initializer = GetParam().second;

  MockHttpCache cache;
  (*cache_initializer)(&cache);

  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.url = kRangeGET_TransactionOK.url;
  transaction.handler = &LargeResourceTransactionHandler;
  transaction.read_handler = &LargeBufferReader;
  ScopedMockTransaction scoped_transaction(transaction);

  MockHttpRequest request(transaction);
  net::TestCompletionCallback callback;
  std::unique_ptr<net::HttpTransaction> http_transaction;
  int rv = cache.http_cache()->CreateTransaction(net::DEFAULT_PRIORITY,
                                                 &http_transaction);
  ASSERT_EQ(net::OK, rv);
  ASSERT_TRUE(http_transaction.get());

  bool network_transaction_started = false;
  if (stop_caching_phase == TransactionPhase::AFTER_NETWORK_READ) {
    http_transaction->SetBeforeNetworkStartCallback(
        base::Bind(&SetFlagOnBeforeNetworkStart, &network_transaction_started));
  }

  rv = http_transaction->Start(&request, callback.callback(),
                               NetLogWithSource());
  rv = callback.GetResult(rv);
  ASSERT_EQ(net::OK, rv);

  if (stop_caching_phase == TransactionPhase::BEFORE_FIRST_READ)
    http_transaction->StopCaching();

  int64_t total_bytes_received = 0;

  EXPECT_EQ(kTotalSize,
            http_transaction->GetResponseInfo()->headers->GetContentLength());
  do {
    // This test simulates reading gigabytes of data. Buffer size is set to 10MB
    // to reduce the number of reads and speed up the test.
    const int kBufferSize = 1024 * 1024 * 10;
    scoped_refptr<net::IOBuffer> buf(new net::IOBuffer(kBufferSize));
    rv = http_transaction->Read(buf.get(), kBufferSize, callback.callback());
    rv = callback.GetResult(rv);

    if (stop_caching_phase == TransactionPhase::AFTER_FIRST_READ &&
        total_bytes_received == 0) {
      http_transaction->StopCaching();
    }

    if (rv > 0)
      total_bytes_received += rv;

    if (network_transaction_started &&
        stop_caching_phase == TransactionPhase::AFTER_NETWORK_READ) {
      http_transaction->StopCaching();
      network_transaction_started = false;
    }
  } while (rv > 0);

  // The only verification we are going to do is that the received resource has
  // the correct size. This is sufficient to verify that the state machine
  // didn't terminate abruptly due to the StopCaching() call.
  EXPECT_EQ(kTotalSize, total_bytes_received);
}

// Tests that we detect truncated resources from the net when there is
// a Content-Length header.
TEST(HttpCache, TruncatedByContentLength) {
  MockHttpCache cache;
  TestCompletionCallback callback;

  MockTransaction transaction(kSimpleGET_Transaction);
  AddMockTransaction(&transaction);
  transaction.response_headers = "Cache-Control: max-age=10000\n"
                                 "Content-Length: 100\n";
  RunTransactionTest(cache.http_cache(), transaction);
  RemoveMockTransaction(&transaction);

  // Read from the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we actually flag entries as truncated when we detect an error
// from the net.
TEST(HttpCache, TruncatedByContentLength2) {
  MockHttpCache cache;
  TestCompletionCallback callback;

  MockTransaction transaction(kSimpleGET_Transaction);
  AddMockTransaction(&transaction);
  transaction.response_headers = "Cache-Control: max-age=10000\n"
                                 "Content-Length: 100\n"
                                 "Etag: \"foo\"\n";
  RunTransactionTest(cache.http_cache(), transaction);
  RemoveMockTransaction(&transaction);

  // Verify that the entry is marked as incomplete.
  VerifyTruncatedFlag(&cache, kSimpleGET_Transaction.url, true, 0);
}

// Make sure that calling SetPriority on a cache transaction passes on
// its priority updates to its underlying network transaction.
TEST(HttpCache, SetPriority) {
  MockHttpCache cache;

  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.http_cache()->CreateTransaction(IDLE, &trans), IsOk());

  // Shouldn't crash, but doesn't do anything either.
  trans->SetPriority(LOW);

  EXPECT_FALSE(cache.network_layer()->last_transaction());
  EXPECT_EQ(DEFAULT_PRIORITY,
            cache.network_layer()->last_create_transaction_priority());

  HttpRequestInfo info;
  info.url = GURL(kSimpleGET_Transaction.url);
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            trans->Start(&info, callback.callback(), NetLogWithSource()));

  EXPECT_TRUE(cache.network_layer()->last_transaction());
  if (cache.network_layer()->last_transaction()) {
    EXPECT_EQ(LOW, cache.network_layer()->last_create_transaction_priority());
    EXPECT_EQ(LOW, cache.network_layer()->last_transaction()->priority());
  }

  trans->SetPriority(HIGHEST);

  if (cache.network_layer()->last_transaction()) {
    EXPECT_EQ(LOW, cache.network_layer()->last_create_transaction_priority());
    EXPECT_EQ(HIGHEST, cache.network_layer()->last_transaction()->priority());
  }

  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Make sure that calling SetWebSocketHandshakeStreamCreateHelper on a cache
// transaction passes on its argument to the underlying network transaction.
TEST(HttpCache, SetWebSocketHandshakeStreamCreateHelper) {
  MockHttpCache cache;

  FakeWebSocketHandshakeStreamCreateHelper create_helper;
  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.http_cache()->CreateTransaction(IDLE, &trans), IsOk());

  EXPECT_FALSE(cache.network_layer()->last_transaction());

  HttpRequestInfo info;
  info.url = GURL(kSimpleGET_Transaction.url);
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            trans->Start(&info, callback.callback(), NetLogWithSource()));

  ASSERT_TRUE(cache.network_layer()->last_transaction());
  EXPECT_FALSE(cache.network_layer()->last_transaction()->
               websocket_handshake_stream_create_helper());
  trans->SetWebSocketHandshakeStreamCreateHelper(&create_helper);
  EXPECT_EQ(&create_helper,
            cache.network_layer()->last_transaction()->
            websocket_handshake_stream_create_helper());
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Make sure that a cache transaction passes on its priority to
// newly-created network transactions.
TEST(HttpCache, SetPriorityNewTransaction) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);

  std::string raw_headers("HTTP/1.1 200 OK\n"
                          "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
                          "ETag: \"foo\"\n"
                          "Accept-Ranges: bytes\n"
                          "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);

  // Now make a regular request.
  std::string headers;
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = EXTRA_HEADER;
  transaction.data = kFullRangeData;

  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.http_cache()->CreateTransaction(MEDIUM, &trans), IsOk());
  EXPECT_EQ(DEFAULT_PRIORITY,
            cache.network_layer()->last_create_transaction_priority());

  MockHttpRequest info(transaction);
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            trans->Start(&info, callback.callback(), NetLogWithSource()));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  EXPECT_EQ(MEDIUM, cache.network_layer()->last_create_transaction_priority());

  trans->SetPriority(HIGHEST);
  // Should trigger a new network transaction and pick up the new
  // priority.
  ReadAndVerifyTransaction(trans.get(), transaction);

  EXPECT_EQ(HIGHEST, cache.network_layer()->last_create_transaction_priority());

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

namespace {

void RunTransactionAndGetNetworkBytes(MockHttpCache& cache,
                                      const MockTransaction& trans_info,
                                      int64_t* sent_bytes,
                                      int64_t* received_bytes) {
  RunTransactionTestBase(
      cache.http_cache(), trans_info, MockHttpRequest(trans_info), nullptr,
      NetLogWithSource(), nullptr, sent_bytes, received_bytes, nullptr);
}

}  // namespace

TEST(HttpCache, NetworkBytesCacheMissAndThenHit) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  int64_t sent, received;
  RunTransactionAndGetNetworkBytes(cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes, received);

  RunTransactionAndGetNetworkBytes(cache, transaction, &sent, &received);
  EXPECT_EQ(0, sent);
  EXPECT_EQ(0, received);
}

TEST(HttpCache, NetworkBytesConditionalRequest304) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kETagGET_Transaction);
  int64_t sent, received;
  RunTransactionAndGetNetworkBytes(cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes, received);

  transaction.load_flags = LOAD_VALIDATE_CACHE;
  transaction.handler = ETagGet_ConditionalRequest_Handler;
  RunTransactionAndGetNetworkBytes(cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes, received);
}

TEST(HttpCache, NetworkBytesConditionalRequest200) {
  MockHttpCache cache;

  MockTransaction transaction(kTypicalGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers =
      "Date: Wed, 28 Nov 2007 09:40:09 GMT\n"
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=0\n"
      "Vary: Foo\n";
  AddMockTransaction(&transaction);
  int64_t sent, received;
  RunTransactionAndGetNetworkBytes(cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes, received);

  RevalidationServer server;
  transaction.handler = server.Handler;
  transaction.request_headers = "Foo: none\r\n";
  RunTransactionAndGetNetworkBytes(cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes, received);

  RemoveMockTransaction(&transaction);
}

TEST(HttpCache, NetworkBytesRange) {
  MockHttpCache cache;
  AddMockTransaction(&kRangeGET_TransactionOK);
  MockTransaction transaction(kRangeGET_TransactionOK);

  // Read bytes 40-49 from the network.
  int64_t sent, received;
  RunTransactionAndGetNetworkBytes(cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes, received);

  // Read bytes 40-49 from the cache.
  RunTransactionAndGetNetworkBytes(cache, transaction, &sent, &received);
  EXPECT_EQ(0, sent);
  EXPECT_EQ(0, received);
  base::RunLoop().RunUntilIdle();

  // Read bytes 30-39 from the network.
  transaction.request_headers = "Range: bytes = 30-39\r\n" EXTRA_HEADER;
  transaction.data = "rg: 30-39 ";
  RunTransactionAndGetNetworkBytes(cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes, received);
  base::RunLoop().RunUntilIdle();

  // Read bytes 20-29 and 50-59 from the network, bytes 30-49 from the cache.
  transaction.request_headers = "Range: bytes = 20-59\r\n" EXTRA_HEADER;
  transaction.data = "rg: 20-29 rg: 30-39 rg: 40-49 rg: 50-59 ";
  RunTransactionAndGetNetworkBytes(cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes * 2, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes * 2, received);

  RemoveMockTransaction(&kRangeGET_TransactionOK);
}

class HttpCachePrefetchValidationTest : public ::testing::Test {
 protected:
  static const int kMaxAgeSecs = 100;
  static const int kRequireValidationSecs = kMaxAgeSecs + 1;

  HttpCachePrefetchValidationTest() : transaction_(kSimpleGET_Transaction) {
    DCHECK_LT(kMaxAgeSecs, prefetch_reuse_mins() * kNumSecondsPerMinute);

    clock_ = new base::SimpleTestClock();
    cache_.http_cache()->SetClockForTesting(base::WrapUnique(clock_));
    cache_.network_layer()->SetClock(clock_);

    transaction_.response_headers = "Cache-Control: max-age=100\n";
  }

  bool TransactionRequiredNetwork(int load_flags) {
    int pre_transaction_count = transaction_count();
    transaction_.load_flags = load_flags;
    RunTransactionTest(cache_.http_cache(), transaction_);
    return pre_transaction_count != transaction_count();
  }

  void AdvanceTime(int seconds) {
    clock_->Advance(base::TimeDelta::FromSeconds(seconds));
  }

  int prefetch_reuse_mins() { return HttpCache::kPrefetchReuseMins; }

  // How many times this test has sent requests to the (fake) origin
  // server. Every test case needs to make at least one request to initialise
  // the cache.
  int transaction_count() {
    return cache_.network_layer()->transaction_count();
  }

  MockHttpCache cache_;
  ScopedMockTransaction transaction_;
  std::string response_headers_;
  base::SimpleTestClock* clock_;
};

TEST_F(HttpCachePrefetchValidationTest, SkipValidationShortlyAfterPrefetch) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest, ValidateLongAfterPrefetch) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(prefetch_reuse_mins() * kNumSecondsPerMinute);
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest, SkipValidationOnceOnly) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_NORMAL));
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest, SkipValidationOnceReadOnly) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_ONLY_FROM_CACHE));
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest, BypassCacheOverwritesPrefetch) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_BYPASS_CACHE));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest,
       SkipValidationOnExistingEntryThatNeedsValidation) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_NORMAL));
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest,
       SkipValidationOnExistingEntryThatDoesNotNeedValidation) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_NORMAL));
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest, PrefetchMultipleTimes) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest, ValidateOnDelayedSecondPrefetch) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_NORMAL));
}

static void CheckResourceFreshnessHeader(const HttpRequestInfo* request,
                                         std::string* response_status,
                                         std::string* response_headers,
                                         std::string* response_data) {
  std::string value;
  EXPECT_TRUE(request->extra_headers.GetHeader("Resource-Freshness", &value));
  EXPECT_EQ("max-age=3600,stale-while-revalidate=7200,age=10801", value);
}

// Verify that the Resource-Freshness header is sent on a revalidation if the
// stale-while-revalidate directive was on the response.
TEST(HttpCache, ResourceFreshnessHeaderSent) {
  MockHttpCache cache;

  ScopedMockTransaction stale_while_revalidate_transaction(
      kSimpleGET_Transaction);
  stale_while_revalidate_transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "Age: 10801\n"
      "Cache-Control: max-age=3600,stale-while-revalidate=7200\n";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), stale_while_revalidate_transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // Send the request again and check that Resource-Freshness header is added.
  stale_while_revalidate_transaction.handler = CheckResourceFreshnessHeader;

  RunTransactionTest(cache.http_cache(), stale_while_revalidate_transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
}

static void CheckResourceFreshnessAbsent(const HttpRequestInfo* request,
                                         std::string* response_status,
                                         std::string* response_headers,
                                         std::string* response_data) {
  EXPECT_FALSE(request->extra_headers.HasHeader("Resource-Freshness"));
}

// Verify that the Resource-Freshness header is not sent when
// stale-while-revalidate is 0.
TEST(HttpCache, ResourceFreshnessHeaderNotSent) {
  MockHttpCache cache;

  ScopedMockTransaction stale_while_revalidate_transaction(
      kSimpleGET_Transaction);
  stale_while_revalidate_transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "Age: 10801\n"
      "Cache-Control: max-age=3600,stale-while-revalidate=0\n";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), stale_while_revalidate_transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // Send the request again and check that Resource-Freshness header is absent.
  stale_while_revalidate_transaction.handler = CheckResourceFreshnessAbsent;

  RunTransactionTest(cache.http_cache(), stale_while_revalidate_transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
}

TEST(HttpCache, StaleContentNotUsedWhenLoadFlagNotSet) {
  MockHttpCache cache;

  ScopedMockTransaction stale_while_revalidate_transaction(
      kSimpleGET_Transaction);

  stale_while_revalidate_transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "Age: 10801\n"
      "Cache-Control: max-age=0,stale-while-revalidate=86400\n";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), stale_while_revalidate_transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // Send the request again and check that it is sent to the network again.
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(
      cache.http_cache(), stale_while_revalidate_transaction, &response_info);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_FALSE(response_info.async_revalidation_required);
}

TEST(HttpCache, StaleContentUsedWhenLoadFlagSetAndUsable) {
  MockHttpCache cache;

  ScopedMockTransaction stale_while_revalidate_transaction(
      kSimpleGET_Transaction);
  stale_while_revalidate_transaction.load_flags |=
      LOAD_SUPPORT_ASYNC_REVALIDATION;
  stale_while_revalidate_transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "Age: 10801\n"
      "Cache-Control: max-age=0,stale-while-revalidate=86400\n";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), stale_while_revalidate_transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // Send the request again and check that it is not sent to the network again.
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(
      cache.http_cache(), stale_while_revalidate_transaction, &response_info);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_TRUE(response_info.async_revalidation_required);
}

TEST(HttpCache, StaleContentNotUsedWhenUnusable) {
  MockHttpCache cache;

  ScopedMockTransaction stale_while_revalidate_transaction(
      kSimpleGET_Transaction);
  stale_while_revalidate_transaction.load_flags |=
      LOAD_SUPPORT_ASYNC_REVALIDATION;
  stale_while_revalidate_transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "Age: 10801\n"
      "Cache-Control: max-age=0,stale-while-revalidate=1800\n";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), stale_while_revalidate_transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // Send the request again and check that it is sent to the network again.
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(
      cache.http_cache(), stale_while_revalidate_transaction, &response_info);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_FALSE(response_info.async_revalidation_required);
}

// Tests that we allow multiple simultaneous, non-overlapping transactions to
// take place on a sparse entry.
TEST(HttpCache, RangeGET_MultipleRequests) {
  MockHttpCache cache;

  // Create a transaction for bytes 0-9.
  MockHttpRequest request(kRangeGET_TransactionOK);
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 0-9\r\n" EXTRA_HEADER;
  transaction.data = "rg: 00-09 ";
  AddMockTransaction(&transaction);

  TestCompletionCallback callback;
  std::unique_ptr<HttpTransaction> trans;
  int rv = cache.http_cache()->CreateTransaction(DEFAULT_PRIORITY, &trans);
  EXPECT_THAT(rv, IsOk());
  ASSERT_TRUE(trans.get());

  // Start our transaction.
  trans->Start(&request, callback.callback(), NetLogWithSource());

  // A second transaction on a different part of the file (the default
  // kRangeGET_TransactionOK requests 40-49) should not be blocked by
  // the already pending transaction.
  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);

  // Let the first transaction complete.
  callback.WaitForResult();

  RemoveMockTransaction(&transaction);
}

// Makes sure that a request stops using the cache when the response headers
// with "Cache-Control: no-store" arrives. That means that another request for
// the same URL can be processed before the response body of the original
// request arrives.
TEST(HttpCache, NoStoreResponseShouldNotBlockFollowingRequests) {
  MockHttpCache cache;
  ScopedMockTransaction mock_transaction(kSimpleGET_Transaction);
  mock_transaction.response_headers = "Cache-Control: no-store\n";
  MockHttpRequest request(mock_transaction);

  std::unique_ptr<Context> first(new Context);
  first->result = cache.CreateTransaction(&first->trans);
  ASSERT_THAT(first->result, IsOk());
  EXPECT_EQ(LOAD_STATE_IDLE, first->trans->GetLoadState());
  first->result = first->trans->Start(&request, first->callback.callback(),
                                      NetLogWithSource());
  EXPECT_EQ(LOAD_STATE_WAITING_FOR_CACHE, first->trans->GetLoadState());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(LOAD_STATE_IDLE, first->trans->GetLoadState());
  ASSERT_TRUE(first->trans->GetResponseInfo());
  EXPECT_TRUE(first->trans->GetResponseInfo()->headers->HasHeaderValue(
      "Cache-Control", "no-store"));
  // Here we have read the response header but not read the response body yet.

  // Let us create the second (read) transaction.
  std::unique_ptr<Context> second(new Context);
  second->result = cache.CreateTransaction(&second->trans);
  ASSERT_THAT(second->result, IsOk());
  EXPECT_EQ(LOAD_STATE_IDLE, second->trans->GetLoadState());
  second->result = second->trans->Start(&request, second->callback.callback(),
                                        NetLogWithSource());

  // Here the second transaction proceeds without reading the first body.
  EXPECT_EQ(LOAD_STATE_WAITING_FOR_CACHE, second->trans->GetLoadState());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(LOAD_STATE_IDLE, second->trans->GetLoadState());
  ASSERT_TRUE(second->trans->GetResponseInfo());
  EXPECT_TRUE(second->trans->GetResponseInfo()->headers->HasHeaderValue(
      "Cache-Control", "no-store"));
  ReadAndVerifyTransaction(second->trans.get(), kSimpleGET_Transaction);
}

// Tests that serving a response entirely from cache replays the previous
// SSLInfo.
TEST(HttpCache, CachePreservesSSLInfo) {
  static const uint16_t kTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f;
  int status = 0;
  SSLConnectionStatusSetCipherSuite(kTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                    &status);
  SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_TLS1_2, &status);

  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");

  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.cert = cert;
  transaction.ssl_connection_status = status;

  // Fetch the resource.
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), transaction,
                                     &response_info);

  // The request should have hit the network and a cache entry created.
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The expected SSL state was reported.
  EXPECT_EQ(transaction.ssl_connection_status,
            response_info.ssl_info.connection_status);
  EXPECT_TRUE(cert->Equals(response_info.ssl_info.cert.get()));

  // Fetch the resource again.
  RunTransactionTestWithResponseInfo(cache.http_cache(), transaction,
                                     &response_info);

  // The request should have been reused without hitting the network.
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The SSL state was preserved.
  EXPECT_EQ(status, response_info.ssl_info.connection_status);
  EXPECT_TRUE(cert->Equals(response_info.ssl_info.cert.get()));
}

// Tests that SSLInfo gets updated when revalidating a cached response.
TEST(HttpCache, RevalidationUpdatesSSLInfo) {
  static const uint16_t kTLS_RSA_WITH_RC4_128_MD5 = 0x0004;
  static const uint16_t kTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f;

  int status1 = 0;
  SSLConnectionStatusSetCipherSuite(kTLS_RSA_WITH_RC4_128_MD5, &status1);
  SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_TLS1, &status1);
  int status2 = 0;
  SSLConnectionStatusSetCipherSuite(kTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                    &status2);
  SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_TLS1_2, &status2);

  scoped_refptr<X509Certificate> cert1 =
      ImportCertFromFile(GetTestCertsDirectory(), "expired_cert.pem");
  scoped_refptr<X509Certificate> cert2 =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");

  MockHttpCache cache;

  ScopedMockTransaction transaction(kTypicalGET_Transaction);
  transaction.cert = cert1;
  transaction.ssl_connection_status = status1;

  // Fetch the resource.
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), transaction,
                                     &response_info);

  // The request should have hit the network and a cache entry created.
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  EXPECT_FALSE(response_info.was_cached);

  // The expected SSL state was reported.
  EXPECT_EQ(status1, response_info.ssl_info.connection_status);
  EXPECT_TRUE(cert1->Equals(response_info.ssl_info.cert.get()));

  // The server deploys a more modern configuration but reports 304 on the
  // revalidation attempt.
  transaction.status = "HTTP/1.1 304 Not Modified";
  transaction.cert = cert2;
  transaction.ssl_connection_status = status2;

  // Fetch the resource again, forcing a revalidation.
  transaction.request_headers = "Cache-Control: max-age=0\r\n";
  RunTransactionTestWithResponseInfo(cache.http_cache(), transaction,
                                     &response_info);

  // The request should have been successfully revalidated.
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  EXPECT_TRUE(response_info.was_cached);

  // The new SSL state is reported.
  EXPECT_EQ(status2, response_info.ssl_info.connection_status);
  EXPECT_TRUE(cert2->Equals(response_info.ssl_info.cert.get()));
}

TEST(HttpCache, CacheEntryStatusOther) {
  MockHttpCache cache;

  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), kRangeGET_Transaction,
                                     &response_info);

  EXPECT_FALSE(response_info.was_cached);
  EXPECT_TRUE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_OTHER, response_info.cache_entry_status);
}

TEST(HttpCache, CacheEntryStatusNotInCache) {
  MockHttpCache cache;

  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), kSimpleGET_Transaction,
                                     &response_info);

  EXPECT_FALSE(response_info.was_cached);
  EXPECT_TRUE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_NOT_IN_CACHE,
            response_info.cache_entry_status);
}

TEST(HttpCache, CacheEntryStatusUsed) {
  MockHttpCache cache;
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), kSimpleGET_Transaction,
                                     &response_info);

  EXPECT_TRUE(response_info.was_cached);
  EXPECT_FALSE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_USED, response_info.cache_entry_status);
}

TEST(HttpCache, CacheEntryStatusValidated) {
  MockHttpCache cache;
  RunTransactionTest(cache.http_cache(), kETagGET_Transaction);

  ScopedMockTransaction still_valid(kETagGET_Transaction);
  still_valid.load_flags = LOAD_VALIDATE_CACHE;  // Force a validation.
  still_valid.handler = ETagGet_ConditionalRequest_Handler;

  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), still_valid,
                                     &response_info);

  EXPECT_TRUE(response_info.was_cached);
  EXPECT_TRUE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_VALIDATED,
            response_info.cache_entry_status);
}

TEST(HttpCache, CacheEntryStatusUpdated) {
  MockHttpCache cache;
  RunTransactionTest(cache.http_cache(), kETagGET_Transaction);

  ScopedMockTransaction update(kETagGET_Transaction);
  update.load_flags = LOAD_VALIDATE_CACHE;  // Force a validation.

  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), update,
                                     &response_info);

  EXPECT_FALSE(response_info.was_cached);
  EXPECT_TRUE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_UPDATED, response_info.cache_entry_status);
}

TEST(HttpCache, CacheEntryStatusCantConditionalize) {
  MockHttpCache cache;
  cache.FailConditionalizations();
  RunTransactionTest(cache.http_cache(), kTypicalGET_Transaction);

  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(),
                                     kTypicalGET_Transaction, &response_info);

  EXPECT_FALSE(response_info.was_cached);
  EXPECT_TRUE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_CANT_CONDITIONALIZE,
            response_info.cache_entry_status);
}

}  // namespace net
