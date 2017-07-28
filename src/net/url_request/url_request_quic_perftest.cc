// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <inttypes.h>

#include <memory>

#include "base/callback.h"
#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted_memory.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/trace_event/memory_dump_manager_test_utils.h"
#include "base/trace_event/memory_dump_request_args.h"
#include "base/trace_event/process_memory_dump.h"
#include "base/trace_event/trace_config.h"
#include "base/trace_event/trace_event_argument.h"
#include "net/base/load_timing_info.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/dns/mapped_host_resolver.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_status_code.h"
#include "net/quic/chromium/crypto/proof_source_chromium.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/test/cert_test_util.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/tools/quic/quic_http_response_cache.h"
#include "net/tools/quic/quic_simple_server.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/perf/perf_test.h"
#include "url/gurl.h"

using testing::_;
using testing::Invoke;
using base::trace_event::MemoryAllocatorDump;

namespace net {

namespace {

const int kAltSvcPort = 6121;
const char kOriginHost[] = "mail.example.com";
const char kAltSvcHost[] = "test.example.com";
// Used as a simple response from the server.
const char kHelloPath[] = "/hello.txt";
const char kHelloAltSvcResponse[] = "Hello from QUIC Server";
const char kHelloOriginResponse[] = "Hello from TCP Server";
const int kHelloStatus = 200;

std::unique_ptr<test_server::HttpResponse> HandleRequest(
    const test_server::HttpRequest& request) {
  std::unique_ptr<test_server::BasicHttpResponse> http_response(
      new test_server::BasicHttpResponse());
  http_response->AddCustomHeader(
      "Alt-Svc", base::StringPrintf(
                     "quic=\"%s:%d\"; v=\"%u\"", kAltSvcHost, kAltSvcPort,
                     HttpNetworkSession::Params().quic_supported_versions[0]));
  http_response->set_code(HTTP_OK);
  http_response->set_content(kHelloOriginResponse);
  http_response->set_content_type("text/plain");
  return std::move(http_response);
}

void PrintPerfTest(const std::string& name,
                   int value,
                   const std::string& unit) {
  const ::testing::TestInfo* test_info =
      ::testing::UnitTest::GetInstance()->current_test_info();
  perf_test::PrintResult(test_info->test_case_name(),
                         std::string(".") + test_info->name(), name,
                         static_cast<double>(value), unit, true);
}

class URLRequestQuicPerfTest : public ::testing::Test {
 protected:
  URLRequestQuicPerfTest() : message_loop_(new base::MessageLoopForIO()) {
    memory_dump_manager_ =
        base::trace_event::MemoryDumpManager::CreateInstanceForTesting();
    base::trace_event::InitializeMemoryDumpManagerForInProcessTesting(
        /*is_coordinator_process=*/false);
    memory_dump_manager_->set_dumper_registrations_ignored_for_testing(false);
    context_ = base::MakeUnique<TestURLRequestContext>(true);
    memory_dump_manager_->set_dumper_registrations_ignored_for_testing(true);
    StartTcpServer();
    StartQuicServer();

    // Host mapping.
    std::unique_ptr<MockHostResolver> resolver(new MockHostResolver());
    resolver->rules()->AddRule(kAltSvcHost, "127.0.0.1");
    host_resolver_.reset(new MappedHostResolver(std::move(resolver)));
    std::string map_rule = base::StringPrintf("MAP %s 127.0.0.1:%d",
                                              kOriginHost, tcp_server_->port());
    EXPECT_TRUE(host_resolver_->AddRuleFromString(map_rule));

    net::HttpNetworkSession::Context network_session_context;
    network_session_context.cert_verifier = &cert_verifier_;
    std::unique_ptr<HttpNetworkSession::Params> params(
        new HttpNetworkSession::Params);
    params->enable_quic = true;
    params->enable_user_alternate_protocol_ports = true;
    context_->set_host_resolver(host_resolver_.get());
    context_->set_http_network_session_params(std::move(params));
    context_->set_cert_verifier(&cert_verifier_);
    context_->Init();
  }

  void TearDown() override {
    if (quic_server_) {
      quic_server_->Shutdown();
      // If possible, deliver the conncetion close packet to the client before
      // destruct the TestURLRequestContext.
      base::RunLoop().RunUntilIdle();
    }
    // |tcp_server_| shuts down in EmbeddedTestServer destructor.
    memory_dump_manager_.reset();
    message_loop_.reset();
  }

  std::unique_ptr<URLRequest> CreateRequest(const GURL& url,
                                            RequestPriority priority,
                                            URLRequest::Delegate* delegate) {
    return context_->CreateRequest(url, priority, delegate,
                                   TRAFFIC_ANNOTATION_FOR_TESTS);
  }

  URLRequestContext* context() const { return context_.get(); }

 private:
  void StartQuicServer() {
    net::QuicConfig config;
    response_cache_.AddSimpleResponse(kOriginHost, kHelloPath, kHelloStatus,
                                      kHelloAltSvcResponse);
    quic_server_.reset(new QuicSimpleServer(
        test::crypto_test_utils::ProofSourceForTesting(), config,
        net::QuicCryptoServerConfig::ConfigOptions(), AllSupportedVersions(),
        &response_cache_));
    int rv = quic_server_->Listen(
        net::IPEndPoint(net::IPAddress::IPv4AllZeros(), kAltSvcPort));
    ASSERT_GE(rv, 0) << "Quic server fails to start";

    CertVerifyResult verify_result;
    verify_result.verified_cert = ImportCertFromFile(
        GetTestCertsDirectory(), "quic_test.example.com.crt");
    cert_verifier_.AddResultForCert(verify_result.verified_cert.get(),
                                    verify_result, OK);
  }

  void StartTcpServer() {
    tcp_server_ = base::MakeUnique<EmbeddedTestServer>(
        net::EmbeddedTestServer::TYPE_HTTPS);
    tcp_server_->RegisterRequestHandler(base::Bind(&HandleRequest));
    ASSERT_TRUE(tcp_server_->Start()) << "HTTP/1.1 server fails to start";

    CertVerifyResult verify_result;
    verify_result.verified_cert = tcp_server_->GetCertificate();
    cert_verifier_.AddResultForCert(tcp_server_->GetCertificate(),
                                    verify_result, OK);
  }

  std::unique_ptr<base::trace_event::MemoryDumpManager> memory_dump_manager_;
  std::unique_ptr<MappedHostResolver> host_resolver_;
  std::unique_ptr<EmbeddedTestServer> tcp_server_;
  std::unique_ptr<QuicSimpleServer> quic_server_;
  std::unique_ptr<base::MessageLoop> message_loop_;
  std::unique_ptr<TestURLRequestContext> context_;
  QuicHttpResponseCache response_cache_;
  MockCertVerifier cert_verifier_;
};

void CheckScalarInDump(const MemoryAllocatorDump* dump,
                       const std::string& name,
                       const char* expected_units,
                       uint64_t expected_value) {
  std::string attr_str_value;
  std::unique_ptr<base::Value> raw_attrs =
      dump->attributes_for_testing()->ToBaseValue();
  base::DictionaryValue* args = nullptr;
  base::DictionaryValue* arg = nullptr;
  std::string arg_value;
  EXPECT_TRUE(raw_attrs->GetAsDictionary(&args));
  EXPECT_TRUE(args->GetDictionary(name, &arg));
  EXPECT_TRUE(arg->GetString("type", &arg_value));
  EXPECT_EQ(MemoryAllocatorDump::kTypeScalar, arg_value);
  EXPECT_TRUE(arg->GetString("units", &arg_value));
  EXPECT_EQ(expected_units, arg_value);
  const base::Value* attr_value = nullptr;
  EXPECT_TRUE(arg->Get("value", &attr_value));
  EXPECT_TRUE(attr_value->GetAsString(&attr_str_value));
  EXPECT_EQ(base::StringPrintf("%" PRIx64, expected_value), attr_str_value);
}

}  // namespace

TEST_F(URLRequestQuicPerfTest, TestGetRequest) {
  bool quic_succeeded = false;
  GURL url(base::StringPrintf("https://%s%s", kOriginHost, kHelloPath));
  base::TimeTicks start = base::TimeTicks::Now();
  const int kNumRequest = 1000;
  for (int i = 0; i < kNumRequest; ++i) {
    TestDelegate delegate;
    std::unique_ptr<URLRequest> request =
        CreateRequest(url, DEFAULT_PRIORITY, &delegate);

    request->Start();
    EXPECT_TRUE(request->is_pending());
    base::RunLoop().Run();

    EXPECT_TRUE(request->status().is_success());
    if (delegate.data_received() == kHelloAltSvcResponse) {
      quic_succeeded = true;
    } else {
      EXPECT_EQ(kHelloOriginResponse, delegate.data_received());
    }
  }
  base::TimeTicks end = base::TimeTicks::Now();
  PrintPerfTest("time", (end - start).InMilliseconds() / kNumRequest, "ms");

  EXPECT_TRUE(quic_succeeded);
  base::trace_event::MemoryDumpManager::GetInstance()->SetupForTracing(
      base::trace_event::TraceConfig::MemoryDumpConfig());

  base::RunLoop run_loop;
  base::trace_event::MemoryDumpRequestArgs args{
      1 /* dump_guid*/, base::trace_event::MemoryDumpType::EXPLICITLY_TRIGGERED,
      base::trace_event::MemoryDumpLevelOfDetail::LIGHT};

  auto on_memory_dump_done =
      [](base::Closure quit_closure, const URLRequestContext* context,
         bool success, uint64_t dump_guid,
         const base::trace_event::ProcessMemoryDumpsMap& dumps) {
        ASSERT_TRUE(success);
        ASSERT_EQ(1u, dumps.size());
        const auto& allocator_dumps = dumps.begin()->second->allocator_dumps();

        auto it = allocator_dumps.find(
            base::StringPrintf("net/url_request_context/unknown/0x%" PRIxPTR,
                               reinterpret_cast<uintptr_t>(context)));
        ASSERT_NE(allocator_dumps.end(), it);
        MemoryAllocatorDump* url_request_context_dump = it->second.get();
        CheckScalarInDump(
            url_request_context_dump,
            base::trace_event::MemoryAllocatorDump::kNameObjectCount,
            base::trace_event::MemoryAllocatorDump::kUnitsObjects, 0);

        it = allocator_dumps.find(base::StringPrintf(
            "net/http_network_session_0x%" PRIxPTR "/quic_stream_factory",
            reinterpret_cast<uintptr_t>(
                context->http_transaction_factory()->GetSession())));
        ASSERT_NE(allocator_dumps.end(), it);
        MemoryAllocatorDump* quic_stream_factory_dump = it->second.get();
        CheckScalarInDump(quic_stream_factory_dump, "active_jobs",
                          base::trace_event::MemoryAllocatorDump::kUnitsObjects,
                          0);

        PrintPerfTest("active_quic_jobs", 0, "count");
        CheckScalarInDump(quic_stream_factory_dump, "all_sessions",
                          base::trace_event::MemoryAllocatorDump::kUnitsObjects,
                          1);
        PrintPerfTest("active_quic_sessions", 1, "count");

        std::string stream_factory_dump_name = base::StringPrintf(
            "net/http_network_session_0x%" PRIxPTR "/stream_factory",
            reinterpret_cast<uintptr_t>(
                context->http_transaction_factory()->GetSession()));
        ASSERT_EQ(0u, allocator_dumps.count(stream_factory_dump_name));
        quit_closure.Run();

      };
  base::trace_event::MemoryDumpManager::GetInstance()->CreateProcessDump(
      args, base::Bind(on_memory_dump_done, run_loop.QuitClosure(), context()));
  run_loop.Run();
  base::trace_event::MemoryDumpManager::GetInstance()->TeardownForTracing();
}

}  // namespace net
