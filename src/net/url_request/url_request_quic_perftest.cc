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
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/test/trace_event_analyzer.h"
#include "base/time/time.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/trace_event/memory_dump_request_args.h"
#include "base/trace_event/process_memory_dump.h"
#include "base/trace_event/trace_buffer.h"
#include "base/trace_event/trace_config.h"
#include "base/trace_event/trace_config_memory_test_util.h"
#include "base/trace_event/trace_log.h"
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

void RequestGlobalDumpCallback(base::Closure quit_closure,
                               uint64_t,
                               bool success) {
  base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, quit_closure);
  ASSERT_TRUE(success);
}

void ProcessDumpCallbackAdapter(
    base::trace_event::GlobalMemoryDumpCallback callback,
    uint64_t dump_guid,
    bool success,
    const base::Optional<base::trace_event::MemoryDumpCallbackResult>&) {
  callback.Run(dump_guid, success);
}

void RequestGlobalMemoryDumpCallback(
    const base::trace_event::MemoryDumpRequestArgs& args,
    const base::trace_event::GlobalMemoryDumpCallback& callback) {
  base::trace_event::ProcessMemoryDumpCallback process_callback =
      base::Bind(&ProcessDumpCallbackAdapter, callback);
  base::trace_event::MemoryDumpManager::GetInstance()->CreateProcessDump(
      args, process_callback);
}

class URLRequestQuicPerfTest : public ::testing::Test {
 protected:
  URLRequestQuicPerfTest() : message_loop_(new base::MessageLoopForIO()) {
    memory_dump_manager_ =
        base::trace_event::MemoryDumpManager::CreateInstanceForTesting();
    memory_dump_manager_->Initialize(
        base::BindRepeating(&RequestGlobalMemoryDumpCallback),
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
  std::vector<base::trace_event::MemoryDumpCallbackResult> results_;
  QuicHttpResponseCache response_cache_;
  MockCertVerifier cert_verifier_;
};

void OnTraceDataCollected(base::Closure quit_closure,
                          base::trace_event::TraceResultBuffer* buffer,
                          const scoped_refptr<base::RefCountedString>& json,
                          bool has_more_events) {
  buffer->AddFragment(json->data());
  if (!has_more_events)
    quit_closure.Run();
}

std::unique_ptr<trace_analyzer::TraceAnalyzer> GetDeserializedTrace() {
  // Flush the trace into JSON.
  base::trace_event::TraceResultBuffer buffer;
  base::trace_event::TraceResultBuffer::SimpleOutput trace_output;
  buffer.SetOutputCallback(trace_output.GetCallback());
  base::RunLoop run_loop;
  buffer.Start();
  base::trace_event::TraceLog::GetInstance()->Flush(
      Bind(&OnTraceDataCollected, run_loop.QuitClosure(),
           base::Unretained(&buffer)));
  run_loop.Run();
  buffer.Finish();

  // Analyze the JSON.
  return base::WrapUnique(
      trace_analyzer::TraceAnalyzer::Create(trace_output.json_output));
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
  base::trace_event::TraceLog::GetInstance()->SetEnabled(
      base::trace_event::TraceConfig(
          base::trace_event::MemoryDumpManager::kTraceCategory, ""),
      base::trace_event::TraceLog::RECORDING_MODE);

  base::RunLoop run_loop;
  base::trace_event::MemoryDumpManager::GetInstance()->RequestGlobalDump(
      base::trace_event::MemoryDumpType::EXPLICITLY_TRIGGERED,
      base::trace_event::MemoryDumpLevelOfDetail::LIGHT,
      base::Bind(&RequestGlobalDumpCallback, run_loop.QuitClosure()));

  run_loop.Run();
  base::trace_event::TraceLog::GetInstance()->SetDisabled();
  std::unique_ptr<trace_analyzer::TraceAnalyzer> analyzer =
      GetDeserializedTrace();

  trace_analyzer::TraceEventVector events;
  analyzer->FindEvents(
      trace_analyzer::Query::EventPhaseIs(TRACE_EVENT_PHASE_MEMORY_DUMP),
      &events);
  EXPECT_EQ(
      1u,
      trace_analyzer::CountMatches(
          events,
          trace_analyzer::Query::EventNameIs(
              base::trace_event::MemoryDumpTypeToString(
                  base::trace_event::MemoryDumpType::EXPLICITLY_TRIGGERED))));

  const trace_analyzer::TraceEvent* event = events[0];
  std::unique_ptr<base::Value> dumps;
  event->GetArgAsValue("dumps", &dumps);
  base::DictionaryValue* allocator_dumps;
  ASSERT_TRUE(dumps->GetAsDictionary(&allocator_dumps));
  ASSERT_TRUE(allocator_dumps->GetDictionary("allocators", &allocator_dumps));

  base::DictionaryValue* url_request_context_dump;
  ASSERT_TRUE(allocator_dumps->GetDictionary(
      base::StringPrintf("net/url_request_context/unknown/0x%" PRIxPTR,
                         reinterpret_cast<uintptr_t>(context())),
      &url_request_context_dump));
  base::DictionaryValue* attrs;
  ASSERT_TRUE(url_request_context_dump->GetDictionary("attrs", &attrs));
  base::DictionaryValue* object_count_attrs;
  ASSERT_TRUE(attrs->GetDictionary(
      base::trace_event::MemoryAllocatorDump::kNameObjectCount,
      &object_count_attrs));
  std::string object_count_str;
  ASSERT_TRUE(object_count_attrs->GetString("value", &object_count_str));
  EXPECT_EQ("0", object_count_str);

  base::DictionaryValue* quic_stream_factory_dump;
  ASSERT_TRUE(allocator_dumps->GetDictionary(
      base::StringPrintf(
          "net/http_network_session_0x%" PRIxPTR "/quic_stream_factory",
          reinterpret_cast<uintptr_t>(
              context()->http_transaction_factory()->GetSession())),
      &quic_stream_factory_dump));
  ASSERT_TRUE(quic_stream_factory_dump->GetDictionary("attrs", &attrs));
  ASSERT_TRUE(attrs->GetDictionary("active_jobs", &object_count_attrs));
  ASSERT_TRUE(object_count_attrs->GetString("value", &object_count_str));
  EXPECT_EQ("0", object_count_str);
  int object_count = -1;
  ASSERT_TRUE(base::HexStringToInt(object_count_str, &object_count));
  PrintPerfTest("active_quic_jobs", object_count, "count");
  ASSERT_TRUE(attrs->GetDictionary("all_sessions", &object_count_attrs));
  ASSERT_TRUE(object_count_attrs->GetString("value", &object_count_str));
  EXPECT_EQ("1", object_count_str);
  ASSERT_TRUE(base::HexStringToInt(object_count_str, &object_count));
  PrintPerfTest("active_quic_sessions", object_count, "count");

  base::DictionaryValue* http_stream_factory_dump;
  ASSERT_FALSE(allocator_dumps->GetDictionary(
      base::StringPrintf(
          "net/http_network_session_0x%" PRIxPTR "/stream_factory",
          reinterpret_cast<uintptr_t>(
              context()->http_transaction_factory()->GetSession())),
      &http_stream_factory_dump));
}

}  // namespace net
