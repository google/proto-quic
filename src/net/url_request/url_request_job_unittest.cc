// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_job.h"

#include <memory>

#include "base/run_loop.h"
#include "net/base/request_priority.h"
#include "net/http/http_transaction_test_util.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

// Data encoded in kBrotliHelloData.
const char kBrotliDecodedHelloData[] = "hello, world!\n";
// kBrotliDecodedHelloData encoded with brotli.
const char kBrotliHelloData[] =
    "\033\015\0\0\244\024\102\152\020\111\152\072\235\126\034";

// This is a header that signals the end of the data.
const char kGzipData[] = "\x1f\x08b\x08\0\0\0\0\0\0\3\3\0\0\0\0\0\0\0\0";
const char kGzipDataWithName[] =
    "\x1f\x08b\x08\x08\0\0\0\0\0\0name\0\3\0\0\0\0\0\0\0\0";
// Gzip data that contains the word hello with a newline character.
const char kGzipHelloData[] =
    "\x1f\x8b\x08\x08\x46\x7d\x4e\x56\x00\x03\x67\x7a\x69\x70\x2e\x74\x78\x74"
    "\x00\xcb\x48\xcd\xc9\xc9\xe7\x02\x00\x20\x30\x3a\x36\x06\x00\x00\x00";

void GZipServer(const HttpRequestInfo* request,
                std::string* response_status,
                std::string* response_headers,
                std::string* response_data) {
  response_data->assign(kGzipData, sizeof(kGzipData));
}

void GZipHelloServer(const HttpRequestInfo* request,
                     std::string* response_status,
                     std::string* response_headers,
                     std::string* response_data) {
  response_data->assign(kGzipHelloData, sizeof(kGzipHelloData));
}

void BigGZipServer(const HttpRequestInfo* request,
                   std::string* response_status,
                   std::string* response_headers,
                   std::string* response_data) {
  response_data->assign(kGzipDataWithName, sizeof(kGzipDataWithName));
  response_data->insert(10, 64 * 1024, 'a');
}

void BrotliHelloServer(const HttpRequestInfo* request,
                       std::string* response_status,
                       std::string* response_headers,
                       std::string* response_data) {
  response_data->assign(kBrotliHelloData, sizeof(kBrotliHelloData) - 1);
}

void MakeMockReferrerPolicyTransaction(const char* original_url,
                                       const char* referer_header,
                                       const char* response_headers,
                                       MockTransaction* transaction) {
  transaction->url = original_url;
  transaction->method = "GET";
  transaction->request_time = base::Time();
  transaction->request_headers = referer_header;
  transaction->load_flags = LOAD_NORMAL;
  transaction->status = "HTTP/1.1 302 Found";
  transaction->response_headers = response_headers;
  transaction->response_time = base::Time();
  transaction->data = "hello";
  transaction->test_mode = TEST_MODE_NORMAL;
  transaction->handler = nullptr;
  transaction->read_handler = nullptr;
  if (GURL(original_url).SchemeIsCryptographic()) {
    transaction->cert =
        net::ImportCertFromFile(net::GetTestCertsDirectory(), "ok_cert.pem");
  } else {
    transaction->cert = nullptr;
  }
  transaction->cert_status = 0;
  transaction->ssl_connection_status = 0;
  transaction->return_code = OK;
}

const MockTransaction kGZip_Transaction = {
    "http://www.google.com/gzyp", "GET", base::Time(), "", LOAD_NORMAL,
    "HTTP/1.1 200 OK",
    "Cache-Control: max-age=10000\n"
    "Content-Encoding: gzip\n"
    "Content-Length: 30\n",  // Intentionally wrong.
    base::Time(),
    "", TEST_MODE_NORMAL, &GZipServer, nullptr, nullptr, 0, 0, OK,
};

const MockTransaction kGzip_Slow_Transaction = {
    "http://www.google.com/gzyp", "GET", base::Time(), "", LOAD_NORMAL,
    "HTTP/1.1 200 OK",
    "Cache-Control: max-age=10000\n"
    "Content-Encoding: gzip\n",
    base::Time(), "", TEST_MODE_SLOW_READ, &GZipHelloServer, nullptr, nullptr,
    0, 0, OK,
};

const MockTransaction kRedirect_Transaction = {
    "http://www.google.com/redirect", "GET", base::Time(), "", LOAD_NORMAL,
    "HTTP/1.1 302 Found",
    "Cache-Control: max-age=10000\n"
    "Location: http://www.google.com/destination\n"
    "Content-Length: 5\n",
    base::Time(), "hello", TEST_MODE_NORMAL, nullptr, nullptr, nullptr, 0, 0,
    OK,
};

const MockTransaction kEmptyBodyGzip_Transaction = {
    "http://www.google.com/empty_body",
    "GET",
    base::Time(),
    "",
    LOAD_NORMAL,
    "HTTP/1.1 200 OK",
    "Content-Encoding: gzip\n",
    base::Time(),
    "",
    TEST_MODE_NORMAL,
    nullptr,
    nullptr,
    nullptr,
    0,
    0,
    OK,
};

const MockTransaction kInvalidContentGZip_Transaction = {
    "http://www.google.com/gzyp", "GET", base::Time(), "", LOAD_NORMAL,
    "HTTP/1.1 200 OK",
    "Content-Encoding: gzip\n"
    "Content-Length: 21\n",
    base::Time(), "not a valid gzip body", TEST_MODE_NORMAL, nullptr, nullptr,
    nullptr, 0, 0, OK,
};

const MockTransaction kBrotli_Slow_Transaction = {
    "http://www.google.com/brotli", "GET", base::Time(), "", LOAD_NORMAL,
    "HTTP/1.1 200 OK",
    "Cache-Control: max-age=10000\n"
    "Content-Encoding: br\n",
    base::Time(), "", TEST_MODE_SLOW_READ, &BrotliHelloServer, nullptr, nullptr,
    0, 0, OK,
};

}  // namespace

TEST(URLRequestJob, TransactionNotifiedWhenDone) {
  MockNetworkLayer network_layer;
  TestURLRequestContext context;
  context.set_http_transaction_factory(&network_layer);

  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context.CreateRequest(GURL(kGZip_Transaction.url), DEFAULT_PRIORITY, &d));
  AddMockTransaction(&kGZip_Transaction);

  req->set_method("GET");
  req->Start();

  base::RunLoop().Run();

  EXPECT_TRUE(network_layer.done_reading_called());

  RemoveMockTransaction(&kGZip_Transaction);
}

TEST(URLRequestJob, SyncTransactionNotifiedWhenDone) {
  MockNetworkLayer network_layer;
  TestURLRequestContext context;
  context.set_http_transaction_factory(&network_layer);

  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context.CreateRequest(GURL(kGZip_Transaction.url), DEFAULT_PRIORITY, &d));
  MockTransaction transaction(kGZip_Transaction);
  transaction.test_mode = TEST_MODE_SYNC_ALL;
  AddMockTransaction(&transaction);

  req->set_method("GET");
  req->Start();

  base::RunLoop().Run();

  EXPECT_TRUE(network_layer.done_reading_called());

  RemoveMockTransaction(&transaction);
}

// Tests processing a large gzip header one byte at a time.
TEST(URLRequestJob, SyncSlowTransaction) {
  MockNetworkLayer network_layer;
  TestURLRequestContext context;
  context.set_http_transaction_factory(&network_layer);

  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context.CreateRequest(GURL(kGZip_Transaction.url), DEFAULT_PRIORITY, &d));
  MockTransaction transaction(kGZip_Transaction);
  transaction.test_mode = TEST_MODE_SYNC_ALL | TEST_MODE_SLOW_READ;
  transaction.handler = &BigGZipServer;
  AddMockTransaction(&transaction);

  req->set_method("GET");
  req->Start();

  base::RunLoop().Run();

  EXPECT_TRUE(network_layer.done_reading_called());

  RemoveMockTransaction(&transaction);
}

TEST(URLRequestJob, RedirectTransactionNotifiedWhenDone) {
  MockNetworkLayer network_layer;
  TestURLRequestContext context;
  context.set_http_transaction_factory(&network_layer);

  TestDelegate d;
  std::unique_ptr<URLRequest> req(context.CreateRequest(
      GURL(kRedirect_Transaction.url), DEFAULT_PRIORITY, &d));
  AddMockTransaction(&kRedirect_Transaction);

  req->set_method("GET");
  req->Start();

  base::RunLoop().Run();

  EXPECT_TRUE(network_layer.done_reading_called());

  RemoveMockTransaction(&kRedirect_Transaction);
}

TEST(URLRequestJob, RedirectTransactionWithReferrerPolicyHeader) {
  struct TestCase {
    const char* original_url;
    const char* original_referrer;
    const char* response_headers;
    URLRequest::ReferrerPolicy original_referrer_policy;
    URLRequest::ReferrerPolicy expected_final_referrer_policy;
    const char* expected_final_referrer;
  };

  const TestCase kTests[] = {
      // If a redirect serves 'Referrer-Policy: no-referrer', then the referrer
      // should be cleared.
      {"http://foo.test/one" /* original url */,
       "http://foo.test/one" /* original referrer */,
       "Location: http://foo.test/test\n"
       "Referrer-Policy: no-referrer\n",
       // original policy
       URLRequest::CLEAR_REFERRER_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       URLRequest::NO_REFERRER /* expected final policy */,
       "" /* expected final referrer */},

      // Same as above but for the legacy keyword 'never', which should
      // not be supported.
      {"http://foo.test/one" /* original url */,
       "http://foo.test/one" /* original referrer */,
       "Location: http://foo.test/test\nReferrer-Policy: never\n",
       // original policy
       URLRequest::CLEAR_REFERRER_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       // expected final policy
       URLRequest::CLEAR_REFERRER_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       "http://foo.test/one" /* expected final referrer */},

      // If a redirect serves 'Referrer-Policy:
      // no-referrer-when-downgrade', then the referrer should be cleared
      // on downgrade, even if the original request's policy specified
      // that the referrer should never be cleared.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: http://foo.test\n"
       "Referrer-Policy: no-referrer-when-downgrade\n",
       URLRequest::NEVER_CLEAR_REFERRER /* original policy */,
       // expected final policy
       URLRequest::CLEAR_REFERRER_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       "" /* expected final referrer */},

      // Same as above but for the legacy keyword 'default', which
      // should not be supported.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: http://foo.test\n"
       "Referrer-Policy: default\n",
       URLRequest::NEVER_CLEAR_REFERRER /* original policy */,
       // expected final policy
       URLRequest::NEVER_CLEAR_REFERRER,
       "https://foo.test/one" /* expected final referrer */},

      // If a redirect serves 'Referrer-Policy: origin', then the referrer
      // should be stripped to its origin, even if the original request's
      // policy specified that the referrer should never be cleared.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: https://foo.test/two\n"
       "Referrer-Policy: origin\n",
       URLRequest::NEVER_CLEAR_REFERRER /* original policy */,
       URLRequest::ORIGIN /* expected final policy */,
       "https://foo.test/" /* expected final referrer */},

      // If a redirect serves 'Referrer-Policy: origin-when-cross-origin',
      // then the referrer should be untouched for a same-origin redirect...
      {"https://foo.test/one" /* original url */,
       "https://foo.test/referrer" /* original referrer */,
       "Location: https://foo.test/two\n"
       "Referrer-Policy: origin-when-cross-origin\n",
       URLRequest::NEVER_CLEAR_REFERRER /* original policy */,
       URLRequest::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* expected final policy */,
       "https://foo.test/referrer" /* expected final referrer */},

      // ... but should be stripped to the origin for a cross-origin redirect.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: https://bar.test/two\n"
       "Referrer-Policy: origin-when-cross-origin\n",
       URLRequest::NEVER_CLEAR_REFERRER /* original policy */,
       URLRequest::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* expected final policy */,
       "https://foo.test/" /* expected final referrer */},

      // If a redirect serves 'Referrer-Policy: unsafe-url', then the
      // referrer should remain, even if originally set to clear on
      // downgrade.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: https://bar.test/two\n"
       "Referrer-Policy: unsafe-url\n",
       URLRequest::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* original policy */,
       URLRequest::NEVER_CLEAR_REFERRER /* expected final policy */,
       "https://foo.test/one" /* expected final referrer */},

      // Same as above but for the legacy keyword 'always', which should
      // not be supported.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: https://bar.test/two\n"
       "Referrer-Policy: always\n",
       URLRequest::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* original policy */,
       URLRequest::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* expected final policy */,
       "https://foo.test/" /* expected final referrer */},

      // An invalid keyword should leave the policy untouched.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: https://bar.test/two\n"
       "Referrer-Policy: not-a-valid-policy\n",
       URLRequest::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* original policy */,
       URLRequest::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* expected final policy */,
       "https://foo.test/" /* expected final referrer */},

      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: http://bar.test/two\n"
       "Referrer-Policy: not-a-valid-policy\n",
       // original policy
       URLRequest::CLEAR_REFERRER_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       // expected final policy
       URLRequest::CLEAR_REFERRER_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       "" /* expected final referrer */},

      // The last valid keyword should take precedence.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: https://bar.test/two\n"
       "Referrer-Policy: unsafe-url\n"
       "Referrer-Policy: not-a-valid-policy\n",
       URLRequest::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* original policy */,
       URLRequest::NEVER_CLEAR_REFERRER /* expected final policy */,
       "https://foo.test/one" /* expected final referrer */},

      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: https://bar.test/two\n"
       "Referrer-Policy: unsafe-url\n"
       "Referrer-Policy: origin\n",
       URLRequest::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* original policy */,
       URLRequest::ORIGIN /* expected final policy */,
       "https://foo.test/" /* expected final referrer */},

      // An empty header should not affect the request.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: https://bar.test/two\n"
       "Referrer-Policy: \n",
       URLRequest::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* original policy */,
       URLRequest::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* expected final policy */,
       "https://foo.test/" /* expected final referrer */},
  };

  for (const auto& test : kTests) {
    MockTransaction transaction;
    std::string request_headers =
        "Referer: " + std::string(test.original_referrer) + "\n";
    MakeMockReferrerPolicyTransaction(test.original_url,
                                      request_headers.c_str(),
                                      test.response_headers, &transaction);

    MockNetworkLayer network_layer;
    TestURLRequestContext context;
    context.set_enable_referrer_policy_header(true);
    context.set_http_transaction_factory(&network_layer);

    TestDelegate d;
    std::unique_ptr<URLRequest> req(
        context.CreateRequest(GURL(transaction.url), DEFAULT_PRIORITY, &d));
    AddMockTransaction(&transaction);

    req->set_referrer_policy(test.original_referrer_policy);
    req->SetReferrer(test.original_referrer);

    req->set_method("GET");
    req->Start();

    base::RunLoop().Run();

    EXPECT_TRUE(network_layer.done_reading_called());

    RemoveMockTransaction(&transaction);

    // Test that the referrer policy and referrer were set correctly
    // according to the header received during the redirect.
    EXPECT_EQ(test.expected_final_referrer_policy, req->referrer_policy());
    EXPECT_EQ(test.expected_final_referrer, req->referrer());
  }
}

TEST(URLRequestJob, TransactionNotCachedWhenNetworkDelegateRedirects) {
  MockNetworkLayer network_layer;
  TestNetworkDelegate network_delegate;
  network_delegate.set_redirect_on_headers_received_url(GURL("http://foo"));
  TestURLRequestContext context;
  context.set_http_transaction_factory(&network_layer);
  context.set_network_delegate(&network_delegate);

  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context.CreateRequest(GURL(kGZip_Transaction.url), DEFAULT_PRIORITY, &d));
  AddMockTransaction(&kGZip_Transaction);

  req->set_method("GET");
  req->Start();

  base::RunLoop().Run();

  EXPECT_TRUE(network_layer.stop_caching_called());

  RemoveMockTransaction(&kGZip_Transaction);
}

// Makes sure that ReadRawDataComplete correctly updates request status before
// calling ReadFilteredData.
// Regression test for crbug.com/553300.
TEST(URLRequestJob, EmptyBodySkipFilter) {
  MockNetworkLayer network_layer;
  TestURLRequestContext context;
  context.set_http_transaction_factory(&network_layer);

  TestDelegate d;
  std::unique_ptr<URLRequest> req(context.CreateRequest(
      GURL(kEmptyBodyGzip_Transaction.url), DEFAULT_PRIORITY, &d));
  AddMockTransaction(&kEmptyBodyGzip_Transaction);

  req->set_method("GET");
  req->Start();

  base::RunLoop().Run();

  EXPECT_FALSE(d.request_failed());
  EXPECT_EQ(200, req->GetResponseCode());
  EXPECT_TRUE(d.data_received().empty());
  EXPECT_TRUE(network_layer.done_reading_called());

  RemoveMockTransaction(&kEmptyBodyGzip_Transaction);
}

// Regression test for crbug.com/575213.
TEST(URLRequestJob, InvalidContentGZipTransaction) {
  MockNetworkLayer network_layer;
  TestURLRequestContext context;
  context.set_http_transaction_factory(&network_layer);

  TestDelegate d;
  std::unique_ptr<URLRequest> req(context.CreateRequest(
      GURL(kInvalidContentGZip_Transaction.url), DEFAULT_PRIORITY, &d));
  AddMockTransaction(&kInvalidContentGZip_Transaction);

  req->set_method("GET");
  req->Start();

  base::RunLoop().Run();

  // Request failed indicates the request failed before headers were received,
  // so should be false.
  EXPECT_FALSE(d.request_failed());
  EXPECT_EQ(200, req->GetResponseCode());
  EXPECT_EQ(ERR_CONTENT_DECODING_FAILED, d.request_status());
  EXPECT_TRUE(d.data_received().empty());
  EXPECT_FALSE(network_layer.done_reading_called());

  RemoveMockTransaction(&kInvalidContentGZip_Transaction);
}

// Regression test for crbug.com/553300.
TEST(URLRequestJob, SlowFilterRead) {
  MockNetworkLayer network_layer;
  TestURLRequestContext context;
  context.set_http_transaction_factory(&network_layer);

  TestDelegate d;
  std::unique_ptr<URLRequest> req(context.CreateRequest(
      GURL(kGzip_Slow_Transaction.url), DEFAULT_PRIORITY, &d));
  AddMockTransaction(&kGzip_Slow_Transaction);

  req->set_method("GET");
  req->Start();

  base::RunLoop().Run();

  EXPECT_FALSE(d.request_failed());
  EXPECT_EQ(200, req->GetResponseCode());
  EXPECT_EQ("hello\n", d.data_received());
  EXPECT_TRUE(network_layer.done_reading_called());

  RemoveMockTransaction(&kGzip_Slow_Transaction);
}

TEST(URLRequestJob, SlowBrotliRead) {
  MockNetworkLayer network_layer;
  TestURLRequestContext context;
  context.set_http_transaction_factory(&network_layer);

  TestDelegate d;
  std::unique_ptr<URLRequest> req(context.CreateRequest(
      GURL(kBrotli_Slow_Transaction.url), DEFAULT_PRIORITY, &d));
  AddMockTransaction(&kBrotli_Slow_Transaction);

  req->set_method("GET");
  req->Start();

  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(d.request_failed());
  EXPECT_EQ(200, req->GetResponseCode());
  EXPECT_EQ(kBrotliDecodedHelloData, d.data_received());
  EXPECT_TRUE(network_layer.done_reading_called());

  RemoveMockTransaction(&kBrotli_Slow_Transaction);
}

}  // namespace net
