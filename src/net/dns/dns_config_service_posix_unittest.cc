// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <resolv.h>

#include <memory>

#include "base/cancelable_callback.h"
#include "base/files/file_util.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/sys_byteorder.h"
#include "base/test/test_timeouts.h"
#include "base/threading/platform_thread.h"
#include "net/base/ip_address.h"
#include "net/dns/dns_config_service_posix.h"
#include "net/dns/dns_protocol.h"

#include "testing/gtest/include/gtest/gtest.h"

#if defined(OS_ANDROID)
#include "base/android/path_utils.h"
#endif  // defined(OS_ANDROID)

// Required for inet_pton()
#if defined(OS_WIN)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace net {

#if !defined(OS_ANDROID)

namespace {

// MAXNS is normally 3, but let's test 4 if possible.
const char* const kNameserversIPv4[] = {
    "8.8.8.8",
    "192.168.1.1",
    "63.1.2.4",
    "1.0.0.1",
};

#if defined(OS_LINUX)
const char* const kNameserversIPv6[] = {
    NULL,
    "2001:DB8:0::42",
    NULL,
    "::FFFF:129.144.52.38",
};
#endif

void DummyConfigCallback(const DnsConfig& config) {
  // Do nothing
}

// Fills in |res| with sane configuration.
void InitializeResState(res_state res) {
  memset(res, 0, sizeof(*res));
  res->options = RES_INIT | RES_RECURSE | RES_DEFNAMES | RES_DNSRCH |
                 RES_ROTATE;
  res->ndots = 2;
  res->retrans = 4;
  res->retry = 7;

  const char kDnsrch[] = "chromium.org" "\0" "example.com";
  memcpy(res->defdname, kDnsrch, sizeof(kDnsrch));
  res->dnsrch[0] = res->defdname;
  res->dnsrch[1] = res->defdname + sizeof("chromium.org");

  for (unsigned i = 0; i < arraysize(kNameserversIPv4) && i < MAXNS; ++i) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = base::HostToNet16(NS_DEFAULTPORT + i);
    inet_pton(AF_INET, kNameserversIPv4[i], &sa.sin_addr);
    res->nsaddr_list[i] = sa;
    ++res->nscount;
  }

#if defined(OS_LINUX)
  // Install IPv6 addresses, replacing the corresponding IPv4 addresses.
  unsigned nscount6 = 0;
  for (unsigned i = 0; i < arraysize(kNameserversIPv6) && i < MAXNS; ++i) {
    if (!kNameserversIPv6[i])
      continue;
    // Must use malloc to mimick res_ninit.
    struct sockaddr_in6 *sa6;
    sa6 = (struct sockaddr_in6 *)malloc(sizeof(*sa6));
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = base::HostToNet16(NS_DEFAULTPORT - i);
    inet_pton(AF_INET6, kNameserversIPv6[i], &sa6->sin6_addr);
    res->_u._ext.nsaddrs[i] = sa6;
    memset(&res->nsaddr_list[i], 0, sizeof res->nsaddr_list[i]);
    ++nscount6;
  }
  res->_u._ext.nscount6 = nscount6;
#endif
}

void CloseResState(res_state res) {
#if defined(OS_LINUX)
  for (int i = 0; i < res->nscount; ++i) {
    if (res->_u._ext.nsaddrs[i] != NULL)
      free(res->_u._ext.nsaddrs[i]);
  }
#endif
}

void InitializeExpectedConfig(DnsConfig* config) {
  config->ndots = 2;
  config->timeout = base::TimeDelta::FromSeconds(4);
  config->attempts = 7;
  config->rotate = true;
  config->edns0 = false;
  config->append_to_multi_label_name = true;
  config->search.clear();
  config->search.push_back("chromium.org");
  config->search.push_back("example.com");

  config->nameservers.clear();
  for (unsigned i = 0; i < arraysize(kNameserversIPv4) && i < MAXNS; ++i) {
    IPAddress ip;
    EXPECT_TRUE(ip.AssignFromIPLiteral(kNameserversIPv4[i]));
    config->nameservers.push_back(IPEndPoint(ip, NS_DEFAULTPORT + i));
  }

#if defined(OS_LINUX)
  for (unsigned i = 0; i < arraysize(kNameserversIPv6) && i < MAXNS; ++i) {
    if (!kNameserversIPv6[i])
      continue;
    IPAddress ip;
    EXPECT_TRUE(ip.AssignFromIPLiteral(kNameserversIPv6[i]));
    config->nameservers[i] = IPEndPoint(ip, NS_DEFAULTPORT - i);
  }
#endif
}

TEST(DnsConfigServicePosixTest, ConvertResStateToDnsConfig) {
  struct __res_state res;
  DnsConfig config;
  EXPECT_FALSE(config.IsValid());
  InitializeResState(&res);
  ASSERT_EQ(internal::CONFIG_PARSE_POSIX_OK,
            internal::ConvertResStateToDnsConfig(res, &config));
  CloseResState(&res);
  EXPECT_TRUE(config.IsValid());

  DnsConfig expected_config;
  EXPECT_FALSE(expected_config.EqualsIgnoreHosts(config));
  InitializeExpectedConfig(&expected_config);
  EXPECT_TRUE(expected_config.EqualsIgnoreHosts(config));
}

TEST(DnsConfigServicePosixTest, RejectEmptyNameserver) {
  struct __res_state res = {};
  res.options = RES_INIT | RES_RECURSE | RES_DEFNAMES | RES_DNSRCH;
  const char kDnsrch[] = "chromium.org";
  memcpy(res.defdname, kDnsrch, sizeof(kDnsrch));
  res.dnsrch[0] = res.defdname;

  struct sockaddr_in sa = {};
  sa.sin_family = AF_INET;
  sa.sin_port = base::HostToNet16(NS_DEFAULTPORT);
  sa.sin_addr.s_addr = INADDR_ANY;
  res.nsaddr_list[0] = sa;
  sa.sin_addr.s_addr = 0xCAFE1337;
  res.nsaddr_list[1] = sa;
  res.nscount = 2;

  DnsConfig config;
  EXPECT_EQ(internal::CONFIG_PARSE_POSIX_NULL_ADDRESS,
            internal::ConvertResStateToDnsConfig(res, &config));

  sa.sin_addr.s_addr = 0xDEADBEEF;
  res.nsaddr_list[0] = sa;
  EXPECT_EQ(internal::CONFIG_PARSE_POSIX_OK,
            internal::ConvertResStateToDnsConfig(res, &config));
}

TEST(DnsConfigServicePosixTest, DestroyWhileJobsWorking) {
  // Regression test to verify crash does not occur if DnsConfigServicePosix
  // instance is destroyed while SerialWorker jobs have posted to worker pool.
  std::unique_ptr<internal::DnsConfigServicePosix> service(
      new internal::DnsConfigServicePosix());
  service->ReadConfig(base::Bind(&DummyConfigCallback));
  service.reset();
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(1000));
}

}  // namespace

#else  // OS_ANDROID

namespace internal {

const char kTempHosts1[] = "127.0.0.1 localhost";
// kTempHosts2 is only used by SeenChangeSinceHostsChange, which doesn't run
// on Android.
#if !defined(OS_ANDROID)
const char kTempHosts2[] = "127.0.0.2 localhost";
#endif  // !defined(OS_ANDROID)

class DnsConfigServicePosixTest : public testing::Test {
 public:
  DnsConfigServicePosixTest() : seen_config_(false) {}
  ~DnsConfigServicePosixTest() override {}

  void OnConfigChanged(const DnsConfig& config) {
    EXPECT_TRUE(config.IsValid());
    seen_config_ = true;
    run_loop_->QuitWhenIdle();
  }

  void WriteMockHostsFile(const char* hosts_string) {
    ASSERT_EQ(base::WriteFile(temp_file_, hosts_string, strlen(hosts_string)),
              static_cast<int>(strlen(hosts_string)));
  }

  void MockDNSConfig(const char* dns_server) {
    IPAddress dns_address;
    ASSERT_TRUE(dns_address.AssignFromIPLiteral(dns_server));
    test_config_.nameservers.clear();
    test_config_.nameservers.push_back(
        IPEndPoint(dns_address, dns_protocol::kDefaultPort));
    service_->SetDnsConfigForTesting(&test_config_);
  }

  void MockHostsFilePath(const char* file_path) {
    service_->SetHostsFilePathForTesting(file_path);
  }

  void SetUp() override {
    // TODO(pauljensen): Get rid of GetExternalStorageDirectory() when
    // crbug.com/475568 is fixed.  For now creating a temp file in the
    // default temp directory (/data/data/...) will cause FilePathWatcher
    // to fail, so create the temp file in /sdcard.
    base::FilePath parent_dir;
    ASSERT_TRUE(base::android::GetExternalStorageDirectory(&parent_dir));
    ASSERT_TRUE(base::CreateTemporaryFileInDir(parent_dir, &temp_file_));
    WriteMockHostsFile(kTempHosts1);
    // Set the time on the hosts file back so it appears older than the
    // 1s safety offset in DnsConfigServicePosix::SeenChangeSince().
    // TODO(pauljensen): Switch from Sleep() to TouchFile() when
    // crbug.com/475568 is fixed.  For now TouchFile() will fail in /sdcard.
    base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(1100));
    // // Copy real hosts file's last modified time to mock hosts file.
    // base::File hosts(base::FilePath(DnsConfigServicePosix::kFilePathHosts),
    //                 base::File::FLAG_OPEN | base::File::FLAG_READ);
    // base::File::Info hosts_info;
    // ASSERT_TRUE(hosts.GetInfo(&hosts_info));
    // ASSERT_TRUE(base::TouchFile(temp_file_, hosts_info.last_modified,
    //                            hosts_info.last_accessed));
  }

  void TearDown() override { ASSERT_TRUE(base::DeleteFile(temp_file_, false)); }

  void StartWatching() {
    creation_time_ = base::Time::Now();
    service_.reset(new DnsConfigServicePosix());
    MockHostsFilePath(temp_file_.value().c_str());
    MockDNSConfig("8.8.8.8");
    seen_config_ = false;
    service_->WatchConfig(base::Bind(
        &DnsConfigServicePosixTest::OnConfigChanged, base::Unretained(this)));
    ExpectChange();
  }

  void ExpectChange() {
    EXPECT_FALSE(seen_config_);
    run_loop_ = base::MakeUnique<base::RunLoop>();
    run_loop_->Run();
    EXPECT_TRUE(seen_config_);
    seen_config_ = false;
  }

  bool seen_config_;
  base::Time creation_time_;
  base::FilePath temp_file_;
  std::unique_ptr<DnsConfigServicePosix> service_;
  DnsConfig test_config_;
  std::unique_ptr<base::RunLoop> run_loop_;
};

TEST_F(DnsConfigServicePosixTest, SeenChangeSinceNetworkChange) {
  // Verify SeenChangeSince() returns false if no changes
  StartWatching();
  EXPECT_FALSE(service_->SeenChangeSince(creation_time_));
  // Verify SeenChangeSince() returns true if network change
  MockDNSConfig("8.8.4.4");
  service_->OnNetworkChanged(NetworkChangeNotifier::CONNECTION_WIFI);
  EXPECT_TRUE(service_->SeenChangeSince(creation_time_));
  ExpectChange();
}

}  // namespace internal

#endif  // OS_ANDROID

}  // namespace net
