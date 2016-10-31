// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include "base/base_paths.h"
#include "base/compiler_specific.h"
#include "base/files/file_util.h"
#include "base/macros.h"
#include "base/message_loop/message_loop.h"
#include "base/path_service.h"
#include "base/strings/string_util.h"
#include "base/test/perf_time_logger.h"
#include "net/base/net_errors.h"
#include "net/dns/mock_host_resolver.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_resolver.h"
#include "net/proxy/proxy_resolver_factory.h"
#include "net/proxy/proxy_resolver_v8.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

#if defined(OS_WIN)
#include "net/proxy/proxy_resolver_winhttp.h"
#elif defined(OS_MACOSX)
#include "net/proxy/proxy_resolver_mac.h"
#endif

using net::test::IsOk;

namespace net {

namespace {

// This class holds the URL to use for resolving, and the expected result.
// We track the expected result in order to make sure the performance
// test is actually resolving URLs properly, otherwise the perf numbers
// are meaningless :-)
struct PacQuery {
  const char* query_url;
  const char* expected_result;
};

// Entry listing which PAC scripts to load, and which URLs to try resolving.
// |queries| should be terminated by {NULL, NULL}. A sentinel is used
// rather than a length, to simplify using initializer lists.
struct PacPerfTest {
  const char* pac_name;
  PacQuery queries[100];

  // Returns the actual number of entries in |queries| (assumes NULL sentinel).
  int NumQueries() const;
};

// List of performance tests.
static PacPerfTest kPerfTests[] = {
  // This test uses an ad-blocker PAC script. This script is very heavily
  // regular expression oriented, and has no dependencies on the current
  // IP address, or DNS resolving of hosts.
  { "no-ads.pac",
    { // queries:
      {"http://www.google.com", "DIRECT"},
      {"http://www.imdb.com/photos/cmsicons/x", "PROXY 0.0.0.0:3421"},
      {"http://www.imdb.com/x", "DIRECT"},
      {"http://www.staples.com/", "DIRECT"},
      {"http://www.staples.com/pixeltracker/x", "PROXY 0.0.0.0:3421"},
      {"http://www.staples.com/pixel/x", "DIRECT"},
      {"http://www.foobar.com", "DIRECT"},
      {"http://www.foobarbaz.com/x/y/z", "DIRECT"},
      {"http://www.testurl1.com/index.html", "DIRECT"},
      {"http://www.testurl2.com", "DIRECT"},
      {"https://www.sample/pirate/arrrrrr", "DIRECT"},
      {NULL, NULL}
    },
  },
};

int PacPerfTest::NumQueries() const {
  for (size_t i = 0; i < arraysize(queries); ++i) {
    if (queries[i].query_url == NULL)
      return i;
  }
  NOTREACHED();  // Bad definition.
  return 0;
}

// The number of URLs to resolve when testing a PAC script.
const int kNumIterations = 500;

// Helper class to run through all the performance tests using the specified
// proxy resolver implementation.
class PacPerfSuiteRunner {
 public:
  // |resolver_name| is the label used when logging the results.
  PacPerfSuiteRunner(ProxyResolverFactory* factory,
                     const std::string& resolver_name)
      : factory_(factory), resolver_name_(resolver_name) {
    test_server_.ServeFilesFromSourceDirectory(
        "net/data/proxy_resolver_perftest");
  }

  void RunAllTests() {
    ASSERT_TRUE(test_server_.Start());
    for (size_t i = 0; i < arraysize(kPerfTests); ++i) {
      const PacPerfTest& test_data = kPerfTests[i];
      RunTest(test_data.pac_name,
              test_data.queries,
              test_data.NumQueries());
    }
  }

 private:
  void RunTest(const std::string& script_name,
               const PacQuery* queries,
               int queries_len) {
    std::unique_ptr<ProxyResolver> resolver;
    if (!factory_->expects_pac_bytes()) {
      GURL pac_url = test_server_.GetURL(std::string("/") + script_name);
      int rv = factory_->CreateProxyResolver(
          ProxyResolverScriptData::FromURL(pac_url), &resolver,
          CompletionCallback(), nullptr);
      EXPECT_THAT(rv, IsOk());
    } else {
      resolver = LoadPacScriptAndCreateResolver(script_name);
    }
    ASSERT_TRUE(resolver);

    // Do a query to warm things up. In the case of internal-fetch proxy
    // resolvers, the first resolve will be slow since it has to download
    // the PAC script.
    {
      ProxyInfo proxy_info;
      int result = resolver->GetProxyForURL(GURL("http://www.warmup.com"),
                                            &proxy_info, CompletionCallback(),
                                            NULL, NetLogWithSource());
      ASSERT_THAT(result, IsOk());
    }

    // Start the perf timer.
    std::string perf_test_name = resolver_name_ + "_" + script_name;
    base::PerfTimeLogger timer(perf_test_name.c_str());

    for (int i = 0; i < kNumIterations; ++i) {
      // Round-robin between URLs to resolve.
      const PacQuery& query = queries[i % queries_len];

      // Resolve.
      ProxyInfo proxy_info;
      int result = resolver->GetProxyForURL(GURL(query.query_url), &proxy_info,
                                            CompletionCallback(), NULL,
                                            NetLogWithSource());

      // Check that the result was correct. Note that ToPacString() and
      // ASSERT_EQ() are fast, so they won't skew the results.
      ASSERT_THAT(result, IsOk());
      ASSERT_EQ(query.expected_result, proxy_info.ToPacString());
    }

    // Print how long the test ran for.
    timer.Done();
  }

  // Read the PAC script from disk and initialize the proxy resolver with it.
  std::unique_ptr<ProxyResolver> LoadPacScriptAndCreateResolver(
      const std::string& script_name) {
    base::FilePath path;
    PathService::Get(base::DIR_SOURCE_ROOT, &path);
    path = path.AppendASCII("net");
    path = path.AppendASCII("data");
    path = path.AppendASCII("proxy_resolver_perftest");
    path = path.AppendASCII(script_name);

    // Try to read the file from disk.
    std::string file_contents;
    bool ok = base::ReadFileToString(path, &file_contents);

    // If we can't load the file from disk, something is misconfigured.
    LOG_IF(ERROR, !ok) << "Failed to read file: " << path.value();
    if (!ok)
      return nullptr;

    // Load the PAC script into the ProxyResolver.
    std::unique_ptr<ProxyResolver> resolver;
    int rv = factory_->CreateProxyResolver(
        ProxyResolverScriptData::FromUTF8(file_contents), &resolver,
        CompletionCallback(), nullptr);
    EXPECT_THAT(rv, IsOk());
    return resolver;
  }

  ProxyResolverFactory* factory_;
  std::string resolver_name_;
  EmbeddedTestServer test_server_;
};

#if defined(OS_WIN)
TEST(ProxyResolverPerfTest, ProxyResolverWinHttp) {
  ProxyResolverFactoryWinHttp factory;
  PacPerfSuiteRunner runner(&factory, "ProxyResolverWinHttp");
  runner.RunAllTests();
}
#elif defined(OS_MACOSX)
TEST(ProxyResolverPerfTest, ProxyResolverMac) {
  ProxyResolverFactoryMac factory;
  PacPerfSuiteRunner runner(&factory, "ProxyResolverMac");
  runner.RunAllTests();
}
#endif

class MockJSBindings : public ProxyResolverV8::JSBindings {
 public:
  MockJSBindings() {}

  void Alert(const base::string16& message) override { CHECK(false); }

  bool ResolveDns(const std::string& host,
                  ResolveDnsOperation op,
                  std::string* output,
                  bool* terminate) override {
    CHECK(false);
    return false;
  }

  void OnError(int line_number, const base::string16& message) override {
    CHECK(false);
  }
};

class ProxyResolverV8Wrapper : public ProxyResolver {
 public:
  ProxyResolverV8Wrapper(std::unique_ptr<ProxyResolverV8> resolver,
                         std::unique_ptr<MockJSBindings> bindings)
      : resolver_(std::move(resolver)), bindings_(std::move(bindings)) {}

  int GetProxyForURL(const GURL& url,
                     ProxyInfo* results,
                     const CompletionCallback& /*callback*/,
                     std::unique_ptr<Request>* /*request*/,
                     const NetLogWithSource& net_log) override {
    return resolver_->GetProxyForURL(url, results, bindings_.get());
  }

 private:
  std::unique_ptr<ProxyResolverV8> resolver_;
  std::unique_ptr<MockJSBindings> bindings_;

  DISALLOW_COPY_AND_ASSIGN(ProxyResolverV8Wrapper);
};

class ProxyResolverV8Factory : public ProxyResolverFactory {
 public:
  ProxyResolverV8Factory() : ProxyResolverFactory(true) {}
  int CreateProxyResolver(
      const scoped_refptr<ProxyResolverScriptData>& pac_script,
      std::unique_ptr<ProxyResolver>* resolver,
      const net::CompletionCallback& callback,
      std::unique_ptr<Request>* request) override {
    std::unique_ptr<ProxyResolverV8> v8_resolver;
    std::unique_ptr<MockJSBindings> js_bindings_(new MockJSBindings);
    int result =
        ProxyResolverV8::Create(pac_script, js_bindings_.get(), &v8_resolver);
    if (result == OK) {
      resolver->reset(new ProxyResolverV8Wrapper(std::move(v8_resolver),
                                                 std::move(js_bindings_)));
    }
    return result;
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(ProxyResolverV8Factory);
};

TEST(ProxyResolverPerfTest, ProxyResolverV8) {
  base::MessageLoop message_loop;
  ProxyResolverV8Factory factory;
  PacPerfSuiteRunner runner(&factory, "ProxyResolverV8");
  runner.RunAllTests();
}

}  // namespace

}  // namespace net
