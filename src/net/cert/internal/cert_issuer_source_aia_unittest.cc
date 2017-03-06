// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/cert_issuer_source_aia.h"

#include "base/bind.h"
#include "base/memory/ptr_util.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cert/internal/cert_errors.h"
#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/internal/test_helpers.h"
#include "net/cert/x509_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

using ::testing::ByMove;
using ::testing::Mock;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::_;

::testing::AssertionResult ReadTestPem(const std::string& file_name,
                                       const std::string& block_name,
                                       std::string* result) {
  const PemBlockMapping mappings[] = {
      {block_name.c_str(), result},
  };

  return ReadTestDataFromPemFile(file_name, mappings);
}

::testing::AssertionResult ReadTestCert(
    const std::string& file_name,
    scoped_refptr<ParsedCertificate>* result) {
  std::string der;
  ::testing::AssertionResult r =
      ReadTestPem("net/data/cert_issuer_source_aia_unittest/" + file_name,
                  "CERTIFICATE", &der);
  if (!r)
    return r;
  CertErrors errors;
  *result = ParsedCertificate::Create(x509_util::CreateCryptoBuffer(der), {},
                                      &errors);
  if (!*result) {
    return ::testing::AssertionFailure()
           << "ParsedCertificate::Create() failed:\n"
           << errors.ToDebugString();
  }
  return ::testing::AssertionSuccess();
}

std::vector<uint8_t> CertDataVector(const ParsedCertificate* cert) {
  std::vector<uint8_t> data(
      cert->der_cert().UnsafeData(),
      cert->der_cert().UnsafeData() + cert->der_cert().Length());
  return data;
}

// MockCertNetFetcher is an implementation of CertNetFetcher for testing.
class MockCertNetFetcher : public CertNetFetcher {
 public:
  MockCertNetFetcher() {}
  MOCK_METHOD0(Shutdown, void());
  MOCK_METHOD3(FetchCaIssuers,
               std::unique_ptr<Request>(const GURL& url,
                                        int timeout_milliseconds,
                                        int max_response_bytes));
  MOCK_METHOD3(FetchCrl,
               std::unique_ptr<Request>(const GURL& url,
                                        int timeout_milliseconds,
                                        int max_response_bytes));

  MOCK_METHOD3(FetchOcsp,
               std::unique_ptr<Request>(const GURL& url,
                                        int timeout_milliseconds,
                                        int max_response_bytes));

 protected:
  ~MockCertNetFetcher() override {}
};

// MockCertNetFetcherRequest gives back the indicated error and bytes.
class MockCertNetFetcherRequest : public CertNetFetcher::Request {
 public:
  MockCertNetFetcherRequest(Error error, std::vector<uint8_t> bytes)
      : error_(error), bytes_(std::move(bytes)) {}

  void WaitForResult(Error* error, std::vector<uint8_t>* bytes) override {
    DCHECK(!did_consume_result_);
    *error = error_;
    *bytes = std::move(bytes_);
    did_consume_result_ = true;
  }

 private:
  Error error_;
  std::vector<uint8_t> bytes_;
  bool did_consume_result_ = false;
};

// Creates a CertNetFetcher::Request that completes with an error.
std::unique_ptr<CertNetFetcher::Request> CreateMockRequest(Error error) {
  return base::MakeUnique<MockCertNetFetcherRequest>(error,
                                                     std::vector<uint8_t>());
}

// Creates a CertNetFetcher::Request that completes with the specified error
// code and bytes.
std::unique_ptr<CertNetFetcher::Request> CreateMockRequest(
    const std::vector<uint8_t>& bytes) {
  return base::MakeUnique<MockCertNetFetcherRequest>(OK, bytes);
}

// CertIssuerSourceAia does not return results for SyncGetIssuersOf.
TEST(CertIssuerSourceAiaTest, NoSyncResults) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_two_aia.pem", &cert));

  // No methods on |mock_fetcher| should be called.
  auto mock_fetcher = make_scoped_refptr(new StrictMock<MockCertNetFetcher>());
  CertIssuerSourceAia aia_source(mock_fetcher);
  ParsedCertificateList issuers;
  aia_source.SyncGetIssuersOf(cert.get(), &issuers);
  EXPECT_EQ(0U, issuers.size());
}

// If the AuthorityInfoAccess extension is not present, AsyncGetIssuersOf should
// synchronously indicate no results.
TEST(CertIssuerSourceAiaTest, NoAia) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_no_aia.pem", &cert));

  // No methods on |mock_fetcher| should be called.
  auto mock_fetcher = make_scoped_refptr(new StrictMock<MockCertNetFetcher>());
  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> request;
  aia_source.AsyncGetIssuersOf(cert.get(), &request);
  EXPECT_EQ(nullptr, request);
}

// If the AuthorityInfoAccess extension only contains non-HTTP URIs,
// AsyncGetIssuersOf should create a Request object. The URL scheme check is
// part of the specific CertNetFetcher implementation, this tests that we handle
// ERR_DISALLOWED_URL_SCHEME properly. If FetchCaIssuers is modified to fail
// synchronously in that case, this test will be more interesting.
TEST(CertIssuerSourceAiaTest, FileAia) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_file_aia.pem", &cert));

  auto mock_fetcher = make_scoped_refptr(new StrictMock<MockCertNetFetcher>());
  EXPECT_CALL(*mock_fetcher, FetchCaIssuers(GURL("file:///dev/null"), _, _))
      .WillOnce(Return(ByMove(CreateMockRequest(ERR_DISALLOWED_URL_SCHEME))));

  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(), &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  // No results.
  ParsedCertificateList result_certs;
  cert_source_request->GetNext(&result_certs);
  EXPECT_TRUE(result_certs.empty());
}

// If the AuthorityInfoAccess extension contains an invalid URL,
// AsyncGetIssuersOf should synchronously indicate no results.
TEST(CertIssuerSourceAiaTest, OneInvalidURL) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_invalid_url_aia.pem", &cert));

  auto mock_fetcher = make_scoped_refptr(new StrictMock<MockCertNetFetcher>());
  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> request;
  aia_source.AsyncGetIssuersOf(cert.get(), &request);
  EXPECT_EQ(nullptr, request);
}

// AuthorityInfoAccess with a single HTTP url pointing to a single DER cert.
TEST(CertIssuerSourceAiaTest, OneAia) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_one_aia.pem", &cert));
  scoped_refptr<ParsedCertificate> intermediate_cert;
  ASSERT_TRUE(ReadTestCert("i.pem", &intermediate_cert));

  auto mock_fetcher = make_scoped_refptr(new StrictMock<MockCertNetFetcher>());

  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia/I.cer"), _, _))
      .WillOnce(Return(
          ByMove(CreateMockRequest(CertDataVector(intermediate_cert.get())))));

  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(), &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  ParsedCertificateList result_certs;
  cert_source_request->GetNext(&result_certs);
  ASSERT_EQ(1u, result_certs.size());
  ASSERT_EQ(result_certs.front()->der_cert(), intermediate_cert->der_cert());

  result_certs.clear();
  cert_source_request->GetNext(&result_certs);
  EXPECT_TRUE(result_certs.empty());
}

// AuthorityInfoAccess with two URIs, one a FILE, the other a HTTP.
// Simulate a ERR_DISALLOWED_URL_SCHEME for the file URL. If FetchCaIssuers is
// modified to synchronously reject disallowed schemes, this test will be more
// interesting.
TEST(CertIssuerSourceAiaTest, OneFileOneHttpAia) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_file_and_http_aia.pem", &cert));
  scoped_refptr<ParsedCertificate> intermediate_cert;
  ASSERT_TRUE(ReadTestCert("i2.pem", &intermediate_cert));

  auto mock_fetcher = make_scoped_refptr(new StrictMock<MockCertNetFetcher>());

  EXPECT_CALL(*mock_fetcher, FetchCaIssuers(GURL("file:///dev/null"), _, _))
      .WillOnce(Return(ByMove(CreateMockRequest(ERR_DISALLOWED_URL_SCHEME))));

  EXPECT_CALL(*mock_fetcher,
              FetchCaIssuers(GURL("http://url-for-aia2/I2.foo"), _, _))
      .WillOnce(Return(
          ByMove(CreateMockRequest(CertDataVector(intermediate_cert.get())))));

  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(), &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  ParsedCertificateList result_certs;
  cert_source_request->GetNext(&result_certs);
  ASSERT_EQ(1u, result_certs.size());
  ASSERT_EQ(result_certs.front()->der_cert(), intermediate_cert->der_cert());

  cert_source_request->GetNext(&result_certs);
  EXPECT_EQ(1u, result_certs.size());
}

// TODO(eroman): Re-enable these tests!
#if 0
// AuthorityInfoAccess with two URIs, one is invalid, the other HTTP.
TEST(CertIssuerSourceAiaTest, OneInvalidOneHttpAia) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_invalid_and_http_aia.pem", &cert));
  scoped_refptr<ParsedCertificate> intermediate_cert;
  ASSERT_TRUE(ReadTestCert("i2.pem", &intermediate_cert));

  StrictMock<MockIssuerCallback> mock_callback;
  scoped_refptr<StrictMock<MockCertNetFetcherImpl>> mock_fetcher(
      new StrictMock<MockCertNetFetcherImpl>());
  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(),
                               base::Bind(&MockIssuerCallback::Callback,
                                          base::Unretained(&mock_callback)),
                               &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  RequestManager* req_manager =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia2/I2.foo"));
  ASSERT_TRUE(req_manager);
  ASSERT_TRUE(req_manager->is_request_alive());

  EXPECT_CALL(mock_callback, Callback(cert_source_request.get()));
  req_manager->get_callback().Run(OK, CertDataVector(intermediate_cert.get()));
  Mock::VerifyAndClearExpectations(&mock_callback);

  scoped_refptr<ParsedCertificate> result_cert;
  CompletionStatus status = cert_source_request->GetNext(&result_cert);
  EXPECT_EQ(CompletionStatus::SYNC, status);
  ASSERT_TRUE(result_cert.get());
  ASSERT_EQ(result_cert->der_cert(), intermediate_cert->der_cert());

  status = cert_source_request->GetNext(&result_cert);
  EXPECT_EQ(CompletionStatus::SYNC, status);
  EXPECT_FALSE(result_cert.get());

  EXPECT_TRUE(req_manager->is_request_alive());
  cert_source_request.reset();
  EXPECT_FALSE(req_manager->is_request_alive());
}

// AuthorityInfoAccess with two HTTP urls, each pointing to a single DER cert.
// One request completes, results are retrieved, then the next request completes
// and the results are retrieved.
TEST(CertIssuerSourceAiaTest, TwoAiaCompletedInSeries) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_two_aia.pem", &cert));
  scoped_refptr<ParsedCertificate> intermediate_cert;
  ASSERT_TRUE(ReadTestCert("i.pem", &intermediate_cert));
  scoped_refptr<ParsedCertificate> intermediate_cert2;
  ASSERT_TRUE(ReadTestCert("i2.pem", &intermediate_cert2));

  StrictMock<MockIssuerCallback> mock_callback;
  scoped_refptr<StrictMock<MockCertNetFetcherImpl>> mock_fetcher(
      new StrictMock<MockCertNetFetcherImpl>());
  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(),
                               base::Bind(&MockIssuerCallback::Callback,
                                          base::Unretained(&mock_callback)),
                               &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  RequestManager* req_manager =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia/I.cer"));
  ASSERT_TRUE(req_manager);
  ASSERT_TRUE(req_manager->is_request_alive());

  RequestManager* req_manager2 =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia2/I2.foo"));
  ASSERT_TRUE(req_manager2);
  ASSERT_TRUE(req_manager2->is_request_alive());

  // Request for I.cer completes first.
  EXPECT_CALL(mock_callback, Callback(cert_source_request.get()));
  req_manager->get_callback().Run(OK, CertDataVector(intermediate_cert.get()));
  Mock::VerifyAndClearExpectations(&mock_callback);

  // Results are retrieved before the other request completes.
  scoped_refptr<ParsedCertificate> result_cert;
  CompletionStatus status = cert_source_request->GetNext(&result_cert);
  EXPECT_EQ(CompletionStatus::SYNC, status);
  ASSERT_TRUE(result_cert.get());
  ASSERT_EQ(result_cert->der_cert(), intermediate_cert->der_cert());

  status = cert_source_request->GetNext(&result_cert);
  // The other http request is still pending, status should be ASYNC to signify
  // the need to wait for another callback.
  ASSERT_EQ(CompletionStatus::ASYNC, status);
  EXPECT_FALSE(result_cert.get());

  // Request for I2.foo completes.
  ASSERT_TRUE(req_manager2->is_request_alive());
  EXPECT_CALL(mock_callback, Callback(cert_source_request.get()));
  req_manager2->get_callback().Run(OK,
                                   CertDataVector(intermediate_cert2.get()));
  Mock::VerifyAndClearExpectations(&mock_callback);

  // Results from the second http request are retrieved.
  status = cert_source_request->GetNext(&result_cert);
  EXPECT_EQ(CompletionStatus::SYNC, status);
  ASSERT_TRUE(result_cert.get());
  ASSERT_EQ(result_cert->der_cert(), intermediate_cert2->der_cert());

  // No more results.
  status = cert_source_request->GetNext(&result_cert);
  ASSERT_EQ(CompletionStatus::SYNC, status);
  EXPECT_FALSE(result_cert.get());

  EXPECT_TRUE(req_manager->is_request_alive());
  EXPECT_TRUE(req_manager2->is_request_alive());
  cert_source_request.reset();
  EXPECT_FALSE(req_manager->is_request_alive());
  EXPECT_FALSE(req_manager2->is_request_alive());
}

// AuthorityInfoAccess with two HTTP urls, each pointing to a single DER cert.
// Both HTTP requests complete before the results are retrieved from the
// CertIssuerSourceAia. There should only be a single callback since the 2nd
// HTTP request completed before GetNext was called, so both requests can be
// supplied to the caller in the same batch.
TEST(CertIssuerSourceAiaTest, TwoAiaCompletedBeforeGetNext) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_two_aia.pem", &cert));
  scoped_refptr<ParsedCertificate> intermediate_cert;
  ASSERT_TRUE(ReadTestCert("i.pem", &intermediate_cert));
  scoped_refptr<ParsedCertificate> intermediate_cert2;
  ASSERT_TRUE(ReadTestCert("i2.pem", &intermediate_cert2));

  StrictMock<MockIssuerCallback> mock_callback;
  scoped_refptr<StrictMock<MockCertNetFetcherImpl>> mock_fetcher(
      new StrictMock<MockCertNetFetcherImpl>());
  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(),
                               base::Bind(&MockIssuerCallback::Callback,
                                          base::Unretained(&mock_callback)),
                               &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  RequestManager* req_manager =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia/I.cer"));
  ASSERT_TRUE(req_manager);
  ASSERT_TRUE(req_manager->is_request_alive());

  RequestManager* req_manager2 =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia2/I2.foo"));
  ASSERT_TRUE(req_manager2);
  ASSERT_TRUE(req_manager2->is_request_alive());

  // First HTTP request completes. Callback is called as soon as the first
  // request completes.
  EXPECT_CALL(mock_callback, Callback(cert_source_request.get()));
  req_manager->get_callback().Run(OK, CertDataVector(intermediate_cert.get()));
  Mock::VerifyAndClearExpectations(&mock_callback);

  // Second HTTP request completes before any results were retrieved from the
  // CertIssuerSourceAia. The callback should not be called again.
  ASSERT_TRUE(req_manager2->is_request_alive());
  req_manager2->get_callback().Run(OK,
                                   CertDataVector(intermediate_cert2.get()));

  // Caller retrieves results. Both certs should be supplied.
  scoped_refptr<ParsedCertificate> result_cert;
  CompletionStatus status = cert_source_request->GetNext(&result_cert);
  EXPECT_EQ(CompletionStatus::SYNC, status);
  ASSERT_TRUE(result_cert.get());
  ASSERT_EQ(result_cert->der_cert(), intermediate_cert->der_cert());

  // 2nd cert is retrieved.
  status = cert_source_request->GetNext(&result_cert);
  EXPECT_EQ(CompletionStatus::SYNC, status);
  ASSERT_TRUE(result_cert.get());
  ASSERT_EQ(result_cert->der_cert(), intermediate_cert2->der_cert());

  // All results are done, SYNC signals completion.
  status = cert_source_request->GetNext(&result_cert);
  ASSERT_EQ(CompletionStatus::SYNC, status);
  EXPECT_FALSE(result_cert.get());
}

// AuthorityInfoAccess with three HTTP urls, each pointing to a single DER cert.
//
// 1) Two HTTP requests complete before the results are retrieved from the
// CertIssuerSourceAia.
// 2) A single cert result is retrieved via GetNext.
// 3) The third HTTP request completes.
// 4) The remaining two certs are retrieved.
//
// Only one callback should occur (after the first HTTP request completed),
// since the pending cert results weren't exhausted before the 3rd request
// completed.
TEST(CertIssuerSourceAiaTest, AiaRequestCompletesDuringGetNextSequence) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_three_aia.pem", &cert));
  scoped_refptr<ParsedCertificate> intermediate_cert;
  ASSERT_TRUE(ReadTestCert("i.pem", &intermediate_cert));
  scoped_refptr<ParsedCertificate> intermediate_cert2;
  ASSERT_TRUE(ReadTestCert("i2.pem", &intermediate_cert2));
  scoped_refptr<ParsedCertificate> intermediate_cert3;
  ASSERT_TRUE(ReadTestCert("i3.pem", &intermediate_cert3));

  StrictMock<MockIssuerCallback> mock_callback;
  scoped_refptr<StrictMock<MockCertNetFetcherImpl>> mock_fetcher(
      new StrictMock<MockCertNetFetcherImpl>());
  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(),
                               base::Bind(&MockIssuerCallback::Callback,
                                          base::Unretained(&mock_callback)),
                               &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  RequestManager* req_manager =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia/I.cer"));
  ASSERT_TRUE(req_manager);
  ASSERT_TRUE(req_manager->is_request_alive());

  RequestManager* req_manager2 =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia2/I2.foo"));
  ASSERT_TRUE(req_manager2);
  ASSERT_TRUE(req_manager2->is_request_alive());

  RequestManager* req_manager3 =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia3/I3.foo"));
  ASSERT_TRUE(req_manager3);
  ASSERT_TRUE(req_manager3->is_request_alive());

  // First HTTP request completes. Callback is called as soon as the first
  // request completes.
  EXPECT_CALL(mock_callback, Callback(cert_source_request.get()));
  req_manager->get_callback().Run(OK, CertDataVector(intermediate_cert.get()));
  Mock::VerifyAndClearExpectations(&mock_callback);

  // Second HTTP request completes before any results were retrieved from the
  // CertIssuerSourceAia. The callback should not be called again.
  ASSERT_TRUE(req_manager2->is_request_alive());
  req_manager2->get_callback().Run(OK,
                                   CertDataVector(intermediate_cert2.get()));

  // Caller retrieves a single result.
  scoped_refptr<ParsedCertificate> result_cert;
  CompletionStatus status = cert_source_request->GetNext(&result_cert);
  EXPECT_EQ(CompletionStatus::SYNC, status);
  ASSERT_TRUE(result_cert.get());
  ASSERT_EQ(result_cert->der_cert(), intermediate_cert->der_cert());

  // Third HTTP request completes.
  // The callback should not be called again, since the last GetNext call had
  // indicated more results were pending still.
  ASSERT_TRUE(req_manager3->is_request_alive());
  req_manager3->get_callback().Run(OK,
                                   CertDataVector(intermediate_cert3.get()));

  // 2nd cert is retrieved.
  status = cert_source_request->GetNext(&result_cert);
  EXPECT_EQ(CompletionStatus::SYNC, status);
  ASSERT_TRUE(result_cert.get());
  ASSERT_EQ(result_cert->der_cert(), intermediate_cert2->der_cert());

  // 3rd cert is retrieved.
  status = cert_source_request->GetNext(&result_cert);
  EXPECT_EQ(CompletionStatus::SYNC, status);
  ASSERT_TRUE(result_cert.get());
  ASSERT_EQ(result_cert->der_cert(), intermediate_cert3->der_cert());

  // All results are done, SYNC signals completion.
  status = cert_source_request->GetNext(&result_cert);
  ASSERT_EQ(CompletionStatus::SYNC, status);
  EXPECT_FALSE(result_cert.get());
}

// AuthorityInfoAccess with a single HTTP url pointing to a single DER cert,
// CertNetFetcher request fails.  The callback should be called to indicate the
// request is complete, but no results should be provided.
TEST(CertIssuerSourceAiaTest, OneAiaHttpError) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_one_aia.pem", &cert));

  StrictMock<MockIssuerCallback> mock_callback;
  scoped_refptr<StrictMock<MockCertNetFetcherImpl>> mock_fetcher(
      new StrictMock<MockCertNetFetcherImpl>());
  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(),
                               base::Bind(&MockIssuerCallback::Callback,
                                          base::Unretained(&mock_callback)),
                               &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  RequestManager* req_manager =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia/I.cer"));
  ASSERT_TRUE(req_manager);
  ASSERT_TRUE(req_manager->is_request_alive());

  EXPECT_CALL(mock_callback, Callback(cert_source_request.get()));
  // HTTP request returns with an error.
  req_manager->get_callback().Run(ERR_FAILED, std::vector<uint8_t>());
  Mock::VerifyAndClearExpectations(&mock_callback);

  scoped_refptr<ParsedCertificate> result_cert;
  CompletionStatus status = cert_source_request->GetNext(&result_cert);
  EXPECT_EQ(CompletionStatus::SYNC, status);
  EXPECT_FALSE(result_cert.get());
}

// AuthorityInfoAccess with a single HTTP url pointing to a single DER cert,
// CertNetFetcher request completes, but the DER cert fails to parse.  The
// callback should be called to indicate the request is complete, but no results
// should be provided.
TEST(CertIssuerSourceAiaTest, OneAiaParseError) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_one_aia.pem", &cert));

  StrictMock<MockIssuerCallback> mock_callback;
  scoped_refptr<StrictMock<MockCertNetFetcherImpl>> mock_fetcher(
      new StrictMock<MockCertNetFetcherImpl>());
  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(),
                               base::Bind(&MockIssuerCallback::Callback,
                                          base::Unretained(&mock_callback)),
                               &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  RequestManager* req_manager =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia/I.cer"));
  ASSERT_TRUE(req_manager);
  ASSERT_TRUE(req_manager->is_request_alive());

  EXPECT_CALL(mock_callback, Callback(cert_source_request.get()));
  // HTTP request returns with an error.
  req_manager->get_callback().Run(OK, std::vector<uint8_t>({1, 2, 3, 4, 5}));
  Mock::VerifyAndClearExpectations(&mock_callback);

  scoped_refptr<ParsedCertificate> result_cert;
  CompletionStatus status = cert_source_request->GetNext(&result_cert);
  EXPECT_EQ(CompletionStatus::SYNC, status);
  EXPECT_FALSE(result_cert.get());
}

// AuthorityInfoAccess with two HTTP urls, each pointing to a single DER cert.
// One request fails. No callback should be generated yet. Once the second
// request completes, the callback should occur.
TEST(CertIssuerSourceAiaTest, TwoAiaCompletedInSeriesFirstFails) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_two_aia.pem", &cert));
  scoped_refptr<ParsedCertificate> intermediate_cert2;
  ASSERT_TRUE(ReadTestCert("i2.pem", &intermediate_cert2));

  StrictMock<MockIssuerCallback> mock_callback;
  scoped_refptr<StrictMock<MockCertNetFetcherImpl>> mock_fetcher(
      new StrictMock<MockCertNetFetcherImpl>());
  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(),
                               base::Bind(&MockIssuerCallback::Callback,
                                          base::Unretained(&mock_callback)),
                               &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  RequestManager* req_manager =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia/I.cer"));
  ASSERT_TRUE(req_manager);
  ASSERT_TRUE(req_manager->is_request_alive());

  RequestManager* req_manager2 =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia2/I2.foo"));
  ASSERT_TRUE(req_manager2);
  ASSERT_TRUE(req_manager2->is_request_alive());

  // Request for I.cer completes first, but fails. Callback is NOT called.
  req_manager->get_callback().Run(ERR_INVALID_RESPONSE, std::vector<uint8_t>());
  Mock::VerifyAndClearExpectations(&mock_callback);

  // Request for I2.foo completes. Callback should be called now.
  ASSERT_TRUE(req_manager2->is_request_alive());
  EXPECT_CALL(mock_callback, Callback(cert_source_request.get()));
  req_manager2->get_callback().Run(OK,
                                   CertDataVector(intermediate_cert2.get()));
  Mock::VerifyAndClearExpectations(&mock_callback);

  // Results from the second http request are retrieved.
  scoped_refptr<ParsedCertificate> result_cert;
  CompletionStatus status = cert_source_request->GetNext(&result_cert);
  EXPECT_EQ(CompletionStatus::SYNC, status);
  ASSERT_TRUE(result_cert.get());
  ASSERT_EQ(result_cert->der_cert(), intermediate_cert2->der_cert());

  // No more results.
  status = cert_source_request->GetNext(&result_cert);
  ASSERT_EQ(CompletionStatus::SYNC, status);
  EXPECT_FALSE(result_cert.get());
}

// AuthorityInfoAccess with two HTTP urls, each pointing to a single DER cert.
// First request completes, result is retrieved, then the second request fails.
// The second callback should occur to indicate that the results are exhausted,
// even though no more results are available.
TEST(CertIssuerSourceAiaTest, TwoAiaCompletedInSeriesSecondFails) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_two_aia.pem", &cert));
  scoped_refptr<ParsedCertificate> intermediate_cert;
  ASSERT_TRUE(ReadTestCert("i.pem", &intermediate_cert));

  StrictMock<MockIssuerCallback> mock_callback;
  scoped_refptr<StrictMock<MockCertNetFetcherImpl>> mock_fetcher(
      new StrictMock<MockCertNetFetcherImpl>());
  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(),
                               base::Bind(&MockIssuerCallback::Callback,
                                          base::Unretained(&mock_callback)),
                               &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  RequestManager* req_manager =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia/I.cer"));
  ASSERT_TRUE(req_manager);
  ASSERT_TRUE(req_manager->is_request_alive());

  RequestManager* req_manager2 =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia2/I2.foo"));
  ASSERT_TRUE(req_manager2);
  ASSERT_TRUE(req_manager2->is_request_alive());

  // Request for I.cer completes first.
  EXPECT_CALL(mock_callback, Callback(cert_source_request.get()));
  req_manager->get_callback().Run(OK, CertDataVector(intermediate_cert.get()));
  Mock::VerifyAndClearExpectations(&mock_callback);

  // Results are retrieved before the other request completes.
  scoped_refptr<ParsedCertificate> result_cert;
  CompletionStatus status = cert_source_request->GetNext(&result_cert);
  EXPECT_EQ(CompletionStatus::SYNC, status);
  ASSERT_TRUE(result_cert.get());
  ASSERT_EQ(result_cert->der_cert(), intermediate_cert->der_cert());

  status = cert_source_request->GetNext(&result_cert);
  // The other http request is still pending, status should be ASYNC to signify
  // the need to wait for another callback.
  ASSERT_EQ(CompletionStatus::ASYNC, status);
  EXPECT_FALSE(result_cert.get());

  // Request for I2.foo fails. Callback should be called to indicate that
  // results are exhausted.
  ASSERT_TRUE(req_manager2->is_request_alive());
  EXPECT_CALL(mock_callback, Callback(cert_source_request.get()));
  req_manager2->get_callback().Run(ERR_INVALID_RESPONSE,
                                   std::vector<uint8_t>());
  Mock::VerifyAndClearExpectations(&mock_callback);

  // GetNext has no more results.
  status = cert_source_request->GetNext(&result_cert);
  ASSERT_EQ(CompletionStatus::SYNC, status);
  EXPECT_FALSE(result_cert.get());
}

// AuthorityInfoAccess with two HTTP urls. Request is cancelled before any HTTP
// requests finish.
TEST(CertIssuerSourceAiaTest, CertSourceRequestCancelled) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_two_aia.pem", &cert));

  StrictMock<MockIssuerCallback> mock_callback;
  scoped_refptr<StrictMock<MockCertNetFetcherImpl>> mock_fetcher(
      new StrictMock<MockCertNetFetcherImpl>());
  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(),
                               base::Bind(&MockIssuerCallback::Callback,
                                          base::Unretained(&mock_callback)),
                               &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  RequestManager* req_manager =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia/I.cer"));
  ASSERT_TRUE(req_manager);
  ASSERT_TRUE(req_manager->is_request_alive());

  RequestManager* req_manager2 =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia2/I2.foo"));
  ASSERT_TRUE(req_manager2);
  ASSERT_TRUE(req_manager2->is_request_alive());

  // Delete The CertIssuerSource::Request, cancelling it.
  cert_source_request.reset();
  // Both CertNetFetcher::Requests should be cancelled.
  EXPECT_FALSE(req_manager->is_request_alive());
  EXPECT_FALSE(req_manager2->is_request_alive());
}

// AuthorityInfoAccess with two HTTP urls, each pointing to a single DER cert.
// One request completes, results are retrieved, then request is cancelled
// before the second HTTP request completes.
TEST(CertIssuerSourceAiaTest, TwoAiaOneCompletedThenRequestCancelled) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_two_aia.pem", &cert));
  scoped_refptr<ParsedCertificate> intermediate_cert;
  ASSERT_TRUE(ReadTestCert("i.pem", &intermediate_cert));

  StrictMock<MockIssuerCallback> mock_callback;
  scoped_refptr<StrictMock<MockCertNetFetcherImpl>> mock_fetcher(
      new StrictMock<MockCertNetFetcherImpl>());
  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(),
                               base::Bind(&MockIssuerCallback::Callback,
                                          base::Unretained(&mock_callback)),
                               &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  RequestManager* req_manager =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia/I.cer"));
  ASSERT_TRUE(req_manager);
  ASSERT_TRUE(req_manager->is_request_alive());

  RequestManager* req_manager2 =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia2/I2.foo"));
  ASSERT_TRUE(req_manager2);
  ASSERT_TRUE(req_manager2->is_request_alive());

  // Request for I.cer completes first.
  EXPECT_CALL(mock_callback, Callback(cert_source_request.get()));
  req_manager->get_callback().Run(OK, CertDataVector(intermediate_cert.get()));
  Mock::VerifyAndClearExpectations(&mock_callback);

  // Results are retrieved before the other request completes.
  scoped_refptr<ParsedCertificate> result_cert;
  CompletionStatus status = cert_source_request->GetNext(&result_cert);
  EXPECT_EQ(CompletionStatus::SYNC, status);
  ASSERT_TRUE(result_cert.get());
  ASSERT_EQ(result_cert->der_cert(), intermediate_cert->der_cert());

  status = cert_source_request->GetNext(&result_cert);
  // The other http request is still pending, status should be ASYNC to signify
  // the need to wait for another callback.
  ASSERT_EQ(CompletionStatus::ASYNC, status);
  EXPECT_FALSE(result_cert.get());

  // Delete The CertIssuerSource::Request, cancelling it.
  cert_source_request.reset();
  // Both CertNetFetcher::Requests should be cancelled.
  EXPECT_FALSE(req_manager->is_request_alive());
  EXPECT_FALSE(req_manager2->is_request_alive());
}

// AuthorityInfoAccess with six HTTP URLs.  kMaxFetchesPerCert is 5, so the
// sixth URL should be ignored.
TEST(CertIssuerSourceAiaTest, MaxFetchesPerCert) {
  scoped_refptr<ParsedCertificate> cert;
  ASSERT_TRUE(ReadTestCert("target_six_aia.pem", &cert));

  StrictMock<MockIssuerCallback> mock_callback;
  scoped_refptr<StrictMock<MockCertNetFetcherImpl>> mock_fetcher(
      new StrictMock<MockCertNetFetcherImpl>());
  CertIssuerSourceAia aia_source(mock_fetcher);
  std::unique_ptr<CertIssuerSource::Request> cert_source_request;
  aia_source.AsyncGetIssuersOf(cert.get(),
                               base::Bind(&MockIssuerCallback::Callback,
                                          base::Unretained(&mock_callback)),
                               &cert_source_request);
  ASSERT_NE(nullptr, cert_source_request);

  RequestManager* req_manager =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia/I.cer"));
  ASSERT_TRUE(req_manager);
  EXPECT_TRUE(req_manager->is_request_alive());

  RequestManager* req_manager2 =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia2/I2.foo"));
  ASSERT_TRUE(req_manager2);
  EXPECT_TRUE(req_manager2->is_request_alive());

  RequestManager* req_manager3 =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia3/I3.foo"));
  ASSERT_TRUE(req_manager3);
  EXPECT_TRUE(req_manager3->is_request_alive());

  RequestManager* req_manager4 =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia4/I4.foo"));
  ASSERT_TRUE(req_manager4);
  EXPECT_TRUE(req_manager4->is_request_alive());

  RequestManager* req_manager5 =
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia5/I5.foo"));
  ASSERT_TRUE(req_manager5);
  EXPECT_TRUE(req_manager5->is_request_alive());

  // Sixth URL should not have created a request.
  EXPECT_FALSE(
      mock_fetcher.GetRequestManagerForURL(GURL("http://url-for-aia6/I6.foo")));
}

#endif

}  // namespace

}  // namespace net
