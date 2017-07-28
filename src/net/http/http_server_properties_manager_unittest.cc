// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_server_properties_manager.h"

#include <memory>
#include <utility>

#include "base/bind.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/test/scoped_mock_time_message_loop_task_runner.h"
#include "base/test/test_mock_time_task_runner.h"
#include "base/test/test_simple_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/values.h"
#include "net/base/ip_address.h"
#include "net/http/http_network_session.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

using base::StringPrintf;
using base::TestMockTimeTaskRunner;
using ::testing::_;
using ::testing::AtLeast;
using ::testing::Invoke;
using ::testing::Mock;
using ::testing::StrictMock;

class MockPrefDelegate : public net::HttpServerPropertiesManager::PrefDelegate {
 public:
  MockPrefDelegate() {}
  ~MockPrefDelegate() override {}

  // HttpServerPropertiesManager::PrefDelegate implementation.
  bool HasServerProperties() override { return true; }
  const base::DictionaryValue& GetServerProperties() const override {
    return prefs_;
  }
  void SetServerProperties(const base::DictionaryValue& value) override {
    prefs_.Clear();
    prefs_.MergeDictionary(&value);
    if (!prefs_changed_callback_.is_null())
      prefs_changed_callback_.Run();
  }
  void StartListeningForUpdates(const base::Closure& callback) override {
    CHECK(prefs_changed_callback_.is_null());
    prefs_changed_callback_ = callback;
  }
  void StopListeningForUpdates() override {
    CHECK(!prefs_changed_callback_.is_null());
    prefs_changed_callback_ = base::Closure();
  }

  void SetPrefs(const base::DictionaryValue& value) {
    // prefs_ = value;
    prefs_.Clear();
    prefs_.MergeDictionary(&value);
    if (!prefs_changed_callback_.is_null())
      prefs_changed_callback_.Run();
  }

 private:
  base::DictionaryValue prefs_;
  base::Closure prefs_changed_callback_;

  DISALLOW_COPY_AND_ASSIGN(MockPrefDelegate);
};

class TestingHttpServerPropertiesManager : public HttpServerPropertiesManager {
 public:
  TestingHttpServerPropertiesManager(
      HttpServerPropertiesManager::PrefDelegate* pref_delegate,
      scoped_refptr<TestMockTimeTaskRunner> pref_task_runner,
      scoped_refptr<TestMockTimeTaskRunner> net_task_runner,
      base::TickClock* clock)
      : HttpServerPropertiesManager(pref_delegate,
                                    pref_task_runner,
                                    net_task_runner,
                                    nullptr,
                                    clock),
        pref_task_runner_(std::move(pref_task_runner)),
        net_task_runner_(std::move(net_task_runner)) {
    // This call must run in the context of |net_task_runner_|.
    TestMockTimeTaskRunner::ScopedContext scoped_context(net_task_runner_);
    HttpServerPropertiesManager::InitializeOnNetworkSequence();
  }

  ~TestingHttpServerPropertiesManager() override {}

  // Make these methods public for testing.
  using HttpServerPropertiesManager::ScheduleUpdateCacheOnPrefThread;

  void UpdateCacheFromPrefsOnUIConcrete() {
    TestMockTimeTaskRunner::ScopedContext scoped_context(pref_task_runner_);
    HttpServerPropertiesManager::UpdateCacheFromPrefsOnPrefSequence();
  }

  void UpdatePrefsFromCacheOnNetworkSequenceConcrete(
      const base::Closure& callback) {
    TestMockTimeTaskRunner::ScopedContext scoped_context(net_task_runner_);
    HttpServerPropertiesManager::UpdatePrefsFromCacheOnNetworkSequence(
        callback);
  }

  void ScheduleUpdatePrefsOnNetworkSequenceConcrete(Location location) {
    TestMockTimeTaskRunner::ScopedContext scoped_context(net_task_runner_);
    HttpServerPropertiesManager::ScheduleUpdatePrefsOnNetworkSequence(location);
  }

  void ScheduleUpdatePrefsOnNetworkSequenceDefault() {
    TestMockTimeTaskRunner::ScopedContext scoped_context(net_task_runner_);
    // Picked a random Location as caller.
    HttpServerPropertiesManager::ScheduleUpdatePrefsOnNetworkSequence(
        DETECTED_CORRUPTED_PREFS);
  }

  MOCK_METHOD0(UpdateCacheFromPrefsOnPrefSequence, void());
  MOCK_METHOD1(UpdatePrefsFromCacheOnNetworkSequence,
               void(const base::Closure&));
  MOCK_METHOD1(ScheduleUpdatePrefsOnNetworkSequence, void(Location location));
  MOCK_METHOD6(UpdateCacheFromPrefsOnNetworkSequence,
               void(std::vector<std::string>* spdy_servers,
                    AlternativeServiceMap* alternative_service_map,
                    IPAddress* last_quic_address,
                    ServerNetworkStatsMap* server_network_stats_map,
                    QuicServerInfoMap* quic_server_info_map,
                    bool detected_corrupted_prefs));
  MOCK_METHOD6(UpdatePrefsOnPrefThread,
               void(base::ListValue* spdy_server_list,
                    AlternativeServiceMap* alternative_service_map,
                    IPAddress* last_quic_address,
                    ServerNetworkStatsMap* server_network_stats_map,
                    QuicServerInfoMap* quic_server_info_map,
                    const base::Closure& completion));

 private:
  // References to the underlying task runners, used to simulate running in
  // their contexts where required.
  scoped_refptr<TestMockTimeTaskRunner> pref_task_runner_;
  scoped_refptr<TestMockTimeTaskRunner> net_task_runner_;

  DISALLOW_COPY_AND_ASSIGN(TestingHttpServerPropertiesManager);
};

}  // namespace

// TODO(rtenneti): After we stop supporting version 3 and everyone has migrated
// to version 4, delete the following code.
static const int kHttpServerPropertiesVersions[] = {3, 4, 5};

class HttpServerPropertiesManagerTest : public testing::TestWithParam<int> {
 protected:
  HttpServerPropertiesManagerTest() = default;

  void SetUp() override {
    one_day_from_now_ = base::Time::Now() + base::TimeDelta::FromDays(1);
    advertised_versions_ = HttpNetworkSession::Params().quic_supported_versions;
    pref_delegate_ = new MockPrefDelegate;
    net_test_task_runner_clock_ = net_test_task_runner_->GetMockTickClock();
    http_server_props_manager_.reset(
        new StrictMock<TestingHttpServerPropertiesManager>(
            pref_delegate_, pref_test_task_runner_.task_runner(),
            net_test_task_runner_, net_test_task_runner_clock_.get()));

    EXPECT_FALSE(http_server_props_manager_->IsInitialized());
    ExpectCacheUpdate();
    EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
    pref_test_task_runner_->RunUntilIdle();
    net_test_task_runner_->RunUntilIdle();
    EXPECT_TRUE(http_server_props_manager_->IsInitialized());
    EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
    EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  }

  void TearDown() override {
    if (http_server_props_manager_.get())
      http_server_props_manager_->ShutdownOnPrefSequence();
    // Run pending non-delayed tasks but don't FastForwardUntilNoTasksRemain()
    // as some delayed tasks may forever repost (e.g. because impl doesn't use a
    // mock clock and doesn't see timings as having expired, ref.
    // HttpServerPropertiesImpl::
    //     ScheduleBrokenAlternateProtocolMappingsExpiration()).
    pref_test_task_runner_->RunUntilIdle();
    net_test_task_runner_->RunUntilIdle();
    http_server_props_manager_.reset();
  }

  void ExpectCacheUpdate() {
    EXPECT_CALL(*http_server_props_manager_,
                UpdateCacheFromPrefsOnPrefSequence())
        .WillOnce(Invoke(http_server_props_manager_.get(),
                         &TestingHttpServerPropertiesManager::
                             UpdateCacheFromPrefsOnUIConcrete));
  }

  void ExpectScheduleUpdatePrefsOnNetworkSequence() {
    EXPECT_CALL(*http_server_props_manager_,
                ScheduleUpdatePrefsOnNetworkSequence(_))
        .WillOnce(Invoke(http_server_props_manager_.get(),
                         &TestingHttpServerPropertiesManager::
                             ScheduleUpdatePrefsOnNetworkSequenceConcrete));
  }

  void ExpectScheduleUpdatePrefsOnNetworkSequenceRepeatedly(int times) {
    EXPECT_CALL(*http_server_props_manager_,
                ScheduleUpdatePrefsOnNetworkSequence(_))
        .Times(AtLeast(times))
        .WillRepeatedly(
            Invoke(http_server_props_manager_.get(),
                   &TestingHttpServerPropertiesManager::
                       ScheduleUpdatePrefsOnNetworkSequenceConcrete));
  }

  void ExpectPrefsUpdate(int times) {
    EXPECT_CALL(*http_server_props_manager_,
                UpdatePrefsFromCacheOnNetworkSequence(_))
        .Times(times)
        .WillRepeatedly(
            Invoke(http_server_props_manager_.get(),
                   &TestingHttpServerPropertiesManager::
                       UpdatePrefsFromCacheOnNetworkSequenceConcrete));
  }

  bool HasAlternativeService(const url::SchemeHostPort& server) {
    const AlternativeServiceInfoVector alternative_service_info_vector =
        http_server_props_manager_->GetAlternativeServiceInfos(server);
    return !alternative_service_info_vector.empty();
  }

  MockPrefDelegate* pref_delegate_;  // Owned by HttpServerPropertiesManager.
  std::unique_ptr<TestingHttpServerPropertiesManager>
      http_server_props_manager_;
  base::Time one_day_from_now_;
  QuicVersionVector advertised_versions_;

  // Overrides the main thread's message loop with a mock tick clock. Making the
  // main thread the |pref_test_task_runner_| matches expectations better than
  // having an independent TestMockTimeTaskRunner and makes tests easier to
  // write.
  base::ScopedMockTimeMessageLoopTaskRunner pref_test_task_runner_;

  // Mock the net task runner as well.
  scoped_refptr<TestMockTimeTaskRunner> net_test_task_runner_ =
      new TestMockTimeTaskRunner;

  std::unique_ptr<base::TickClock> net_test_task_runner_clock_;

 private:
  DISALLOW_COPY_AND_ASSIGN(HttpServerPropertiesManagerTest);
};

INSTANTIATE_TEST_CASE_P(/* no prefix */,
                        HttpServerPropertiesManagerTest,
                        ::testing::ValuesIn(kHttpServerPropertiesVersions));

TEST_P(HttpServerPropertiesManagerTest,
       SingleUpdateForTwoSpdyServerPrefChanges) {
  ExpectCacheUpdate();

  // Set up the prefs for https://www.google.com and https://mail.google.com and
  // then set it twice. Only expect a single cache update.

  auto server_pref_dict = base::MakeUnique<base::DictionaryValue>();
  url::SchemeHostPort google_server("https", "www.google.com", 443);
  url::SchemeHostPort mail_server("https", "mail.google.com", 443);

  // Set supports_spdy for https://www.google.com:443.
  server_pref_dict->SetBoolean("supports_spdy", true);

  // Set up alternative_services for https://www.google.com.
  auto alternative_service_dict0 = base::MakeUnique<base::DictionaryValue>();
  alternative_service_dict0->SetInteger("port", 443);
  alternative_service_dict0->SetString("protocol_str", "h2");
  auto alternative_service_dict1 = base::MakeUnique<base::DictionaryValue>();
  alternative_service_dict1->SetInteger("port", 1234);
  alternative_service_dict1->SetString("protocol_str", "quic");
  auto alternative_service_list0 = base::MakeUnique<base::ListValue>();
  alternative_service_list0->Append(std::move(alternative_service_dict0));
  alternative_service_list0->Append(std::move(alternative_service_dict1));
  server_pref_dict->SetWithoutPathExpansion(
      "alternative_service", std::move(alternative_service_list0));

  // Set up ServerNetworkStats for https://www.google.com.
  auto stats = base::MakeUnique<base::DictionaryValue>();
  stats->SetInteger("srtt", 10);
  server_pref_dict->SetWithoutPathExpansion("network_stats", std::move(stats));

  // Set the server preference for https://www.google.com.
  auto servers_dict = base::MakeUnique<base::DictionaryValue>();
  servers_dict->SetWithoutPathExpansion(
      GetParam() >= 5 ? "https://www.google.com" : "www.google.com:443",
      std::move(server_pref_dict));
  std::unique_ptr<base::ListValue> servers_list;
  if (GetParam() >= 4) {
    servers_list = base::MakeUnique<base::ListValue>();
    servers_list->Append(std::move(servers_dict));
    servers_dict = base::MakeUnique<base::DictionaryValue>();
  }

  // Set the preference for mail.google.com server.
  auto server_pref_dict1 = base::MakeUnique<base::DictionaryValue>();

  // Set supports_spdy for https://mail.google.com.
  server_pref_dict1->SetBoolean("supports_spdy", true);

  // Set up alternative_services for https://mail.google.com.
  auto alternative_service_dict2 = base::MakeUnique<base::DictionaryValue>();
  alternative_service_dict2->SetString("protocol_str", "h2");
  alternative_service_dict2->SetInteger("port", 444);
  auto alternative_service_list1 = base::MakeUnique<base::ListValue>();
  alternative_service_list1->Append(std::move(alternative_service_dict2));
  server_pref_dict1->SetWithoutPathExpansion(
      "alternative_service", std::move(alternative_service_list1));

  // Set up ServerNetworkStats for https://mail.google.com and it is the MRU
  // server.
  auto stats1 = base::MakeUnique<base::DictionaryValue>();
  stats1->SetInteger("srtt", 20);
  server_pref_dict1->SetWithoutPathExpansion("network_stats",
                                             std::move(stats1));
  // Set the server preference for https://mail.google.com.
  servers_dict->SetWithoutPathExpansion(
      GetParam() >= 5 ? "https://mail.google.com" : "mail.google.com:443",
      std::move(server_pref_dict1));
  base::DictionaryValue http_server_properties_dict;
  if (GetParam() >= 4) {
    servers_list->AppendIfNotPresent(std::move(servers_dict));
    if (GetParam() == 5) {
      HttpServerPropertiesManager::SetVersion(&http_server_properties_dict, -1);
    } else {
      HttpServerPropertiesManager::SetVersion(&http_server_properties_dict,
                                              GetParam());
    }
    http_server_properties_dict.SetWithoutPathExpansion(
        "servers", std::move(servers_list));
  } else {
    HttpServerPropertiesManager::SetVersion(&http_server_properties_dict,
                                            GetParam());
    http_server_properties_dict.SetWithoutPathExpansion(
        "servers", std::move(servers_dict));
  }
  auto supports_quic = base::MakeUnique<base::DictionaryValue>();
  supports_quic->SetBoolean("used_quic", true);
  supports_quic->SetString("address", "127.0.0.1");
  http_server_properties_dict.SetWithoutPathExpansion("supports_quic",
                                                      std::move(supports_quic));

  // Set quic_server_info for https://www.google.com, https://mail.google.com
  // and https://play.google.com and verify the MRU.
  http_server_props_manager_->SetMaxServerConfigsStoredInProperties(3);
  auto quic_servers_dict = base::MakeUnique<base::DictionaryValue>();
  auto quic_server_pref_dict1 = base::MakeUnique<base::DictionaryValue>();
  std::string quic_server_info1("quic_server_info1");
  quic_server_pref_dict1->SetStringWithoutPathExpansion("server_info",
                                                        quic_server_info1);
  auto quic_server_pref_dict2 = base::MakeUnique<base::DictionaryValue>();
  std::string quic_server_info2("quic_server_info2");
  quic_server_pref_dict2->SetStringWithoutPathExpansion("server_info",
                                                        quic_server_info2);
  auto quic_server_pref_dict3 = base::MakeUnique<base::DictionaryValue>();
  std::string quic_server_info3("quic_server_info3");
  quic_server_pref_dict3->SetStringWithoutPathExpansion("server_info",
                                                        quic_server_info3);
  // Set the quic_server_info1 for https://www.google.com.
  QuicServerId google_quic_server_id("www.google.com", 443);
  quic_servers_dict->SetWithoutPathExpansion(google_quic_server_id.ToString(),
                                             std::move(quic_server_pref_dict1));
  // Set the quic_server_info2 for https://mail.google.com.
  QuicServerId mail_quic_server_id("mail.google.com", 443);
  quic_servers_dict->SetWithoutPathExpansion(mail_quic_server_id.ToString(),
                                             std::move(quic_server_pref_dict2));
  // Set the quic_server_info3 for https://play.google.com.
  QuicServerId play_quic_server_id("play.google.com", 443);
  quic_servers_dict->SetWithoutPathExpansion(play_quic_server_id.ToString(),
                                             std::move(quic_server_pref_dict3));
  http_server_properties_dict.SetWithoutPathExpansion(
      "quic_servers", std::move(quic_servers_dict));

  // Set the same value for kHttpServerProperties multiple times.
  pref_delegate_->SetPrefs(http_server_properties_dict);
  pref_delegate_->SetPrefs(http_server_properties_dict);

  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());

  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());

  // Verify SupportsSpdy.
  EXPECT_TRUE(
      http_server_props_manager_->SupportsRequestPriority(google_server));
  EXPECT_TRUE(http_server_props_manager_->SupportsRequestPriority(mail_server));
  HostPortPair foo_host_port_pair =
      HostPortPair::FromString("foo.google.com:1337");
  url::SchemeHostPort foo_server("http", foo_host_port_pair.host(),
                                 foo_host_port_pair.port());

  EXPECT_FALSE(http_server_props_manager_->SupportsRequestPriority(foo_server));

  // Verify alternative service.
  const AlternativeServiceMap& map =
      http_server_props_manager_->alternative_service_map();
  ASSERT_EQ(2u, map.size());

  AlternativeServiceMap::const_iterator map_it = map.begin();
  EXPECT_EQ("www.google.com", map_it->first.host());
  ASSERT_EQ(2u, map_it->second.size());
  EXPECT_EQ(kProtoHTTP2, map_it->second[0].alternative_service().protocol);
  EXPECT_TRUE(map_it->second[0].alternative_service().host.empty());
  EXPECT_EQ(443, map_it->second[0].alternative_service().port);
  EXPECT_EQ(kProtoQUIC, map_it->second[1].alternative_service().protocol);
  EXPECT_TRUE(map_it->second[1].alternative_service().host.empty());
  EXPECT_EQ(1234, map_it->second[1].alternative_service().port);
  ++map_it;
  EXPECT_EQ("mail.google.com", map_it->first.host());
  ASSERT_EQ(1u, map_it->second.size());
  EXPECT_EQ(kProtoHTTP2, map_it->second[0].alternative_service().protocol);
  EXPECT_TRUE(map_it->second[0].alternative_service().host.empty());
  EXPECT_EQ(444, map_it->second[0].alternative_service().port);

  // Verify SupportsQuic.
  IPAddress last_address;
  EXPECT_TRUE(http_server_props_manager_->GetSupportsQuic(&last_address));
  EXPECT_EQ("127.0.0.1", last_address.ToString());

  // Verify ServerNetworkStats.
  const ServerNetworkStats* stats2 =
      http_server_props_manager_->GetServerNetworkStats(google_server);
  EXPECT_EQ(10, stats2->srtt.ToInternalValue());
  const ServerNetworkStats* stats3 =
      http_server_props_manager_->GetServerNetworkStats(mail_server);
  EXPECT_EQ(20, stats3->srtt.ToInternalValue());

  // Verify QuicServerInfo.
  EXPECT_EQ(quic_server_info1, *http_server_props_manager_->GetQuicServerInfo(
                                   google_quic_server_id));
  EXPECT_EQ(quic_server_info2, *http_server_props_manager_->GetQuicServerInfo(
                                   mail_quic_server_id));
  EXPECT_EQ(quic_server_info3, *http_server_props_manager_->GetQuicServerInfo(
                                   play_quic_server_id));

  // Verify the MRU order.
  http_server_props_manager_->SetMaxServerConfigsStoredInProperties(2);
  EXPECT_EQ(nullptr, http_server_props_manager_->GetQuicServerInfo(
                         google_quic_server_id));
  EXPECT_EQ(quic_server_info2, *http_server_props_manager_->GetQuicServerInfo(
                                   mail_quic_server_id));
  EXPECT_EQ(quic_server_info3, *http_server_props_manager_->GetQuicServerInfo(
                                   play_quic_server_id));
}

TEST_P(HttpServerPropertiesManagerTest, BadCachedHostPortPair) {
  ExpectCacheUpdate();
  // The prefs are automatically updated in the case corruption is detected.
  ExpectPrefsUpdate(1);
  ExpectScheduleUpdatePrefsOnNetworkSequence();

  auto server_pref_dict = base::MakeUnique<base::DictionaryValue>();

  // Set supports_spdy for www.google.com:65536.
  server_pref_dict->SetBoolean("supports_spdy", true);

  // Set up alternative_service for www.google.com:65536.
  auto alternative_service_dict = base::MakeUnique<base::DictionaryValue>();
  alternative_service_dict->SetString("protocol_str", "h2");
  alternative_service_dict->SetInteger("port", 80);
  auto alternative_service_list = base::MakeUnique<base::ListValue>();
  alternative_service_list->Append(std::move(alternative_service_dict));
  server_pref_dict->SetWithoutPathExpansion(
      "alternative_service", std::move(alternative_service_list));

  // Set up ServerNetworkStats for www.google.com:65536.
  auto stats = base::MakeUnique<base::DictionaryValue>();
  stats->SetInteger("srtt", 10);
  server_pref_dict->SetWithoutPathExpansion("network_stats", std::move(stats));

  // Set the server preference for www.google.com:65536.
  auto servers_dict = base::MakeUnique<base::DictionaryValue>();
  servers_dict->SetWithoutPathExpansion("www.google.com:65536",
                                        std::move(server_pref_dict));
  base::DictionaryValue http_server_properties_dict;
  if (GetParam() >= 4) {
    auto servers_list = base::MakeUnique<base::ListValue>();
    servers_list->Append(std::move(servers_dict));
    if (GetParam() == 5) {
      HttpServerPropertiesManager::SetVersion(&http_server_properties_dict, -1);
    } else {
      HttpServerPropertiesManager::SetVersion(&http_server_properties_dict,
                                              GetParam());
    }
    http_server_properties_dict.SetWithoutPathExpansion(
        "servers", std::move(servers_list));
  } else {
    HttpServerPropertiesManager::SetVersion(&http_server_properties_dict,
                                            GetParam());
    http_server_properties_dict.SetWithoutPathExpansion(
        "servers", std::move(servers_dict));
  }

  // Set quic_server_info for www.google.com:65536.
  auto quic_servers_dict = base::MakeUnique<base::DictionaryValue>();
  auto quic_server_pref_dict1 = base::MakeUnique<base::DictionaryValue>();
  quic_server_pref_dict1->SetStringWithoutPathExpansion("server_info",
                                                        "quic_server_info1");
  quic_servers_dict->SetWithoutPathExpansion("http://mail.google.com:65536",
                                             std::move(quic_server_pref_dict1));

  http_server_properties_dict.SetWithoutPathExpansion(
      "quic_servers", std::move(quic_servers_dict));

  // Set up the pref.
  pref_delegate_->SetPrefs(http_server_properties_dict);

  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());

  // Verify that nothing is set.
  HostPortPair google_host_port_pair =
      HostPortPair::FromString("www.google.com:65536");
  url::SchemeHostPort gooler_server("http", google_host_port_pair.host(),
                                    google_host_port_pair.port());

  EXPECT_FALSE(
      http_server_props_manager_->SupportsRequestPriority(gooler_server));
  EXPECT_FALSE(HasAlternativeService(gooler_server));
  const ServerNetworkStats* stats1 =
      http_server_props_manager_->GetServerNetworkStats(gooler_server);
  EXPECT_EQ(nullptr, stats1);
  EXPECT_EQ(0u, http_server_props_manager_->quic_server_info_map().size());
}

TEST_P(HttpServerPropertiesManagerTest, BadCachedAltProtocolPort) {
  ExpectCacheUpdate();
  // The prefs are automatically updated in the case corruption is detected.
  ExpectPrefsUpdate(1);
  ExpectScheduleUpdatePrefsOnNetworkSequence();

  auto server_pref_dict = base::MakeUnique<base::DictionaryValue>();

  // Set supports_spdy for www.google.com:80.
  server_pref_dict->SetBoolean("supports_spdy", true);

  // Set up alternative_service for www.google.com:80.
  auto alternative_service_dict = base::MakeUnique<base::DictionaryValue>();
  alternative_service_dict->SetString("protocol_str", "h2");
  alternative_service_dict->SetInteger("port", 65536);
  auto alternative_service_list = base::MakeUnique<base::ListValue>();
  alternative_service_list->Append(std::move(alternative_service_dict));
  server_pref_dict->SetWithoutPathExpansion(
      "alternative_service", std::move(alternative_service_list));

  // Set the server preference for www.google.com:80.
  auto servers_dict = base::MakeUnique<base::DictionaryValue>();
  servers_dict->SetWithoutPathExpansion("www.google.com:80",
                                        std::move(server_pref_dict));
  base::DictionaryValue http_server_properties_dict;
  if (GetParam() >= 4) {
    auto servers_list = base::MakeUnique<base::ListValue>();
    servers_list->Append(std::move(servers_dict));
    if (GetParam() == 5) {
      HttpServerPropertiesManager::SetVersion(&http_server_properties_dict, -1);
    } else {
      HttpServerPropertiesManager::SetVersion(&http_server_properties_dict,
                                              GetParam());
    }
    http_server_properties_dict.SetWithoutPathExpansion(
        "servers", std::move(servers_list));
  } else {
    HttpServerPropertiesManager::SetVersion(&http_server_properties_dict,
                                            GetParam());
    http_server_properties_dict.SetWithoutPathExpansion(
        "servers", std::move(servers_dict));
  }

  // Set up the pref.
  pref_delegate_->SetPrefs(http_server_properties_dict);

  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());

  // Verify alternative service is not set.
  EXPECT_FALSE(
      HasAlternativeService(url::SchemeHostPort("http", "www.google.com", 80)));
}

TEST_P(HttpServerPropertiesManagerTest, SupportsSpdy) {
  ExpectPrefsUpdate(1);
  ExpectScheduleUpdatePrefsOnNetworkSequence();

  // Post an update task to the network thread. SetSupportsSpdy calls
  // ScheduleUpdatePrefsOnNetworkSequence.

  // Add mail.google.com:443 as a supporting spdy server.
  url::SchemeHostPort spdy_server("https", "mail.google.com", 443);
  EXPECT_FALSE(
      http_server_props_manager_->SupportsRequestPriority(spdy_server));
  http_server_props_manager_->SetSupportsSpdy(spdy_server, true);
  // ExpectScheduleUpdatePrefsOnNetworkSequence() should be called only once.
  http_server_props_manager_->SetSupportsSpdy(spdy_server, true);

  // Run the task.
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  EXPECT_TRUE(http_server_props_manager_->SupportsRequestPriority(spdy_server));
  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());
}

// Regression test for crbug.com/670519. Test that there is only one pref update
// scheduled if multiple updates happen in a given time period. Subsequent pref
// update could also be scheduled once the previous scheduled update is
// completed.
TEST_P(HttpServerPropertiesManagerTest,
       SinglePrefUpdateForTwoSpdyServerCacheChanges) {
  ExpectPrefsUpdate(2);
  ExpectScheduleUpdatePrefsOnNetworkSequenceRepeatedly(3);

  // Post an update task to the network thread. SetSupportsSpdy calls
  // ScheduleUpdatePrefsOnNetworkSequence with a delay of 60ms.
  url::SchemeHostPort spdy_server("https", "mail.google.com", 443);
  EXPECT_FALSE(
      http_server_props_manager_->SupportsRequestPriority(spdy_server));
  http_server_props_manager_->SetSupportsSpdy(spdy_server, true);
  // The pref update task should be scheduled to network thread.
  EXPECT_EQ(1u, net_test_task_runner_->GetPendingTaskCount());

  // Move forward the task runner short by 20ms.
  net_test_task_runner_->FastForwardBy(
      HttpServerPropertiesManager::GetUpdatePrefsDelayForTesting() -
      base::TimeDelta::FromMilliseconds(20));

  // Set another spdy server to trigger another call to
  // ScheduleUpdatePrefsOnNetworkSequence. There should be no new update posted
  // to the network thread.
  url::SchemeHostPort spdy_server2("https", "drive.google.com", 443);
  http_server_props_manager_->SetSupportsSpdy(spdy_server2, true);
  EXPECT_EQ(1u, net_test_task_runner_->GetPendingTaskCount());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  // Move forward the extra 20ms. The pref update should be executed.
  net_test_task_runner_->FastForwardBy(base::TimeDelta::FromMilliseconds(20));
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  EXPECT_TRUE(http_server_props_manager_->SupportsRequestPriority(spdy_server));
  EXPECT_TRUE(
      http_server_props_manager_->SupportsRequestPriority(spdy_server2));
  // Set the third spdy server to trigger one more call to
  // ScheduleUpdatePrefsOnNetworkSequence. A new update task should be posted to
  // network thread now since the previous one is completed.
  url::SchemeHostPort spdy_server3("https", "maps.google.com", 443);
  http_server_props_manager_->SetSupportsSpdy(spdy_server3, true);
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_EQ(1u, net_test_task_runner_->GetPendingTaskCount());

  // Run the task.
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());
}

TEST_P(HttpServerPropertiesManagerTest, GetAlternativeServiceInfos) {
  ExpectPrefsUpdate(1);
  ExpectScheduleUpdatePrefsOnNetworkSequence();

  url::SchemeHostPort spdy_server_mail("http", "mail.google.com", 80);
  EXPECT_FALSE(HasAlternativeService(spdy_server_mail));
  const AlternativeService alternative_service(kProtoHTTP2, "mail.google.com",
                                               443);
  http_server_props_manager_->SetHttp2AlternativeService(
      spdy_server_mail, alternative_service, one_day_from_now_);
  // ExpectScheduleUpdatePrefsOnNetworkSequence() should be called only once.
  http_server_props_manager_->SetHttp2AlternativeService(
      spdy_server_mail, alternative_service, one_day_from_now_);

  // Run the task.
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());

  AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_props_manager_->GetAlternativeServiceInfos(spdy_server_mail);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service,
            alternative_service_info_vector[0].alternative_service());
}

TEST_P(HttpServerPropertiesManagerTest, SetAlternativeServices) {
  ExpectPrefsUpdate(1);
  ExpectScheduleUpdatePrefsOnNetworkSequence();

  url::SchemeHostPort spdy_server_mail("http", "mail.google.com", 80);
  EXPECT_FALSE(HasAlternativeService(spdy_server_mail));
  AlternativeServiceInfoVector alternative_service_info_vector;
  const AlternativeService alternative_service1(kProtoHTTP2, "mail.google.com",
                                                443);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service1, one_day_from_now_));
  const AlternativeService alternative_service2(kProtoQUIC, "mail.google.com",
                                                1234);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service2, one_day_from_now_, advertised_versions_));
  http_server_props_manager_->SetAlternativeServices(
      spdy_server_mail, alternative_service_info_vector);
  // ExpectScheduleUpdatePrefsOnNetworkSequence() should be called only once.
  http_server_props_manager_->SetAlternativeServices(
      spdy_server_mail, alternative_service_info_vector);

  // Run the task.
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());

  AlternativeServiceInfoVector alternative_service_info_vector2 =
      http_server_props_manager_->GetAlternativeServiceInfos(spdy_server_mail);
  ASSERT_EQ(2u, alternative_service_info_vector2.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector2[0].alternative_service());
  EXPECT_EQ(alternative_service2,
            alternative_service_info_vector2[1].alternative_service());
}

TEST_P(HttpServerPropertiesManagerTest, SetAlternativeServicesEmpty) {
  url::SchemeHostPort spdy_server_mail("http", "mail.google.com", 80);
  EXPECT_FALSE(HasAlternativeService(spdy_server_mail));
  const AlternativeService alternative_service(kProtoHTTP2, "mail.google.com",
                                               443);
  http_server_props_manager_->SetAlternativeServices(
      spdy_server_mail, AlternativeServiceInfoVector());

  // ExpectScheduleUpdatePrefsOnNetworkSequence() should not be called.
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());

  EXPECT_FALSE(HasAlternativeService(spdy_server_mail));
}

TEST_P(HttpServerPropertiesManagerTest, ConfirmAlternativeService) {
  ExpectPrefsUpdate(1);

  url::SchemeHostPort spdy_server_mail;
  AlternativeService alternative_service;

  {
    TestMockTimeTaskRunner::ScopedContext scoped_context(net_test_task_runner_);

    spdy_server_mail = url::SchemeHostPort("http", "mail.google.com", 80);
    EXPECT_FALSE(HasAlternativeService(spdy_server_mail));
    alternative_service =
        AlternativeService(kProtoHTTP2, "mail.google.com", 443);

    ExpectScheduleUpdatePrefsOnNetworkSequence();
    http_server_props_manager_->SetHttp2AlternativeService(
        spdy_server_mail, alternative_service, one_day_from_now_);

    EXPECT_FALSE(http_server_props_manager_->IsAlternativeServiceBroken(
        alternative_service));
    EXPECT_FALSE(
        http_server_props_manager_->WasAlternativeServiceRecentlyBroken(
            alternative_service));

    ExpectScheduleUpdatePrefsOnNetworkSequence();
    http_server_props_manager_->MarkAlternativeServiceBroken(
        alternative_service);
    EXPECT_TRUE(http_server_props_manager_->IsAlternativeServiceBroken(
        alternative_service));
    EXPECT_TRUE(http_server_props_manager_->WasAlternativeServiceRecentlyBroken(
        alternative_service));

    ExpectScheduleUpdatePrefsOnNetworkSequence();
    http_server_props_manager_->ConfirmAlternativeService(alternative_service);
    EXPECT_FALSE(http_server_props_manager_->IsAlternativeServiceBroken(
        alternative_service));
    EXPECT_FALSE(
        http_server_props_manager_->WasAlternativeServiceRecentlyBroken(
            alternative_service));
    // ExpectScheduleUpdatePrefsOnNetworkSequence() should be called only once.
    http_server_props_manager_->ConfirmAlternativeService(alternative_service);
    EXPECT_FALSE(http_server_props_manager_->IsAlternativeServiceBroken(
        alternative_service));
    EXPECT_FALSE(
        http_server_props_manager_->WasAlternativeServiceRecentlyBroken(
            alternative_service));
  }

  // Run the task.
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());

  {
    TestMockTimeTaskRunner::ScopedContext scoped_context(net_test_task_runner_);
    EXPECT_FALSE(http_server_props_manager_->IsAlternativeServiceBroken(
        alternative_service));
    EXPECT_FALSE(
        http_server_props_manager_->WasAlternativeServiceRecentlyBroken(
            alternative_service));
  }
}

TEST_P(HttpServerPropertiesManagerTest, SupportsQuic) {
  ExpectPrefsUpdate(1);
  ExpectScheduleUpdatePrefsOnNetworkSequence();

  IPAddress address;
  EXPECT_FALSE(http_server_props_manager_->GetSupportsQuic(&address));

  IPAddress actual_address(127, 0, 0, 1);
  http_server_props_manager_->SetSupportsQuic(true, actual_address);
  // ExpectScheduleUpdatePrefsOnNetworkSequence() should be called only once.
  http_server_props_manager_->SetSupportsQuic(true, actual_address);

  // Run the task.
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());

  EXPECT_TRUE(http_server_props_manager_->GetSupportsQuic(&address));
  EXPECT_EQ(actual_address, address);
}

TEST_P(HttpServerPropertiesManagerTest, ServerNetworkStats) {
  ExpectPrefsUpdate(1);
  ExpectScheduleUpdatePrefsOnNetworkSequence();

  url::SchemeHostPort mail_server("http", "mail.google.com", 80);
  const ServerNetworkStats* stats =
      http_server_props_manager_->GetServerNetworkStats(mail_server);
  EXPECT_EQ(nullptr, stats);
  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromMicroseconds(10);
  http_server_props_manager_->SetServerNetworkStats(mail_server, stats1);
  // ExpectScheduleUpdatePrefsOnNetworkSequence() should be called only once.
  http_server_props_manager_->SetServerNetworkStats(mail_server, stats1);

  // Run the task.
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());

  const ServerNetworkStats* stats2 =
      http_server_props_manager_->GetServerNetworkStats(mail_server);
  EXPECT_EQ(10, stats2->srtt.ToInternalValue());

  ExpectPrefsUpdate(1);
  ExpectScheduleUpdatePrefsOnNetworkSequence();

  http_server_props_manager_->ClearServerNetworkStats(mail_server);

  // Run the task.
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());
  EXPECT_EQ(nullptr,
            http_server_props_manager_->GetServerNetworkStats(mail_server));
}

TEST_P(HttpServerPropertiesManagerTest, QuicServerInfo) {
  ExpectPrefsUpdate(1);
  ExpectScheduleUpdatePrefsOnNetworkSequence();

  QuicServerId mail_quic_server_id("mail.google.com", 80);
  EXPECT_EQ(nullptr,
            http_server_props_manager_->GetQuicServerInfo(mail_quic_server_id));
  std::string quic_server_info1("quic_server_info1");
  http_server_props_manager_->SetQuicServerInfo(mail_quic_server_id,
                                                quic_server_info1);
  // ExpectScheduleUpdatePrefsOnNetworkSequence() should be called only once.
  http_server_props_manager_->SetQuicServerInfo(mail_quic_server_id,
                                                quic_server_info1);

  // Run the task.
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());

  EXPECT_EQ(quic_server_info1, *http_server_props_manager_->GetQuicServerInfo(
                                   mail_quic_server_id));
}

TEST_P(HttpServerPropertiesManagerTest, Clear) {
  ExpectPrefsUpdate(1);
  ExpectScheduleUpdatePrefsOnNetworkSequenceRepeatedly(5);

  const url::SchemeHostPort spdy_server("https", "mail.google.com", 443);
  const IPAddress actual_address(127, 0, 0, 1);
  const QuicServerId mail_quic_server_id("mail.google.com", 80);
  const std::string quic_server_info1("quic_server_info1");

  {
    TestMockTimeTaskRunner::ScopedContext scoped_context(net_test_task_runner_);

    http_server_props_manager_->SetSupportsSpdy(spdy_server, true);
    AlternativeService alternative_service(kProtoHTTP2, "mail.google.com",
                                           1234);
    http_server_props_manager_->SetHttp2AlternativeService(
        spdy_server, alternative_service, one_day_from_now_);
    http_server_props_manager_->SetSupportsQuic(true, actual_address);
    ServerNetworkStats stats;
    stats.srtt = base::TimeDelta::FromMicroseconds(10);
    http_server_props_manager_->SetServerNetworkStats(spdy_server, stats);

    http_server_props_manager_->SetQuicServerInfo(mail_quic_server_id,
                                                  quic_server_info1);
  }

  // Run the task.
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());

  EXPECT_TRUE(http_server_props_manager_->SupportsRequestPriority(spdy_server));
  EXPECT_TRUE(HasAlternativeService(spdy_server));
  IPAddress address;
  EXPECT_TRUE(http_server_props_manager_->GetSupportsQuic(&address));
  EXPECT_EQ(actual_address, address);
  const ServerNetworkStats* stats1 =
      http_server_props_manager_->GetServerNetworkStats(spdy_server);
  EXPECT_EQ(10, stats1->srtt.ToInternalValue());
  EXPECT_EQ(quic_server_info1, *http_server_props_manager_->GetQuicServerInfo(
                                   mail_quic_server_id));

  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());

  ExpectPrefsUpdate(1);

  // Clear http server data and run the ensuing non-delayed prefs update.
  {
    TestMockTimeTaskRunner::ScopedContext scoped_context(net_test_task_runner_);
    http_server_props_manager_->Clear();
  }
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->RunUntilIdle();
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());

  EXPECT_FALSE(
      http_server_props_manager_->SupportsRequestPriority(spdy_server));
  EXPECT_FALSE(HasAlternativeService(spdy_server));
  EXPECT_FALSE(http_server_props_manager_->GetSupportsQuic(&address));
  const ServerNetworkStats* stats2 =
      http_server_props_manager_->GetServerNetworkStats(spdy_server);
  EXPECT_EQ(nullptr, stats2);
  EXPECT_EQ(nullptr,
            http_server_props_manager_->GetQuicServerInfo(mail_quic_server_id));

  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());
}

// https://crbug.com/444956: Add 200 alternative_service servers followed by
// supports_quic and verify we have read supports_quic from prefs.
TEST_P(HttpServerPropertiesManagerTest, BadSupportsQuic) {
  ExpectCacheUpdate();

  auto servers_dict = base::MakeUnique<base::DictionaryValue>();
  std::unique_ptr<base::ListValue> servers_list;
  if (GetParam() >= 4)
    servers_list = base::MakeUnique<base::ListValue>();

  for (int i = 1; i <= 200; ++i) {
    // Set up alternative_service for www.google.com:i.
    auto alternative_service_dict = base::MakeUnique<base::DictionaryValue>();
    alternative_service_dict->SetString("protocol_str", "quic");
    alternative_service_dict->SetInteger("port", i);
    auto alternative_service_list = base::MakeUnique<base::ListValue>();
    alternative_service_list->Append(std::move(alternative_service_dict));
    auto server_pref_dict = base::MakeUnique<base::DictionaryValue>();
    server_pref_dict->SetWithoutPathExpansion(
        "alternative_service", std::move(alternative_service_list));
    if (GetParam() >= 5) {
      servers_dict->SetWithoutPathExpansion(
          StringPrintf("https://www.google.com:%d", i),
          std::move(server_pref_dict));
    } else {
      servers_dict->SetWithoutPathExpansion(
          StringPrintf("www.google.com:%d", i), std::move(server_pref_dict));
    }
    if (GetParam() >= 4) {
      servers_list->AppendIfNotPresent(std::move(servers_dict));
      servers_dict = base::MakeUnique<base::DictionaryValue>();
    }
  }

  // Set the server preference for http://mail.google.com server.
  auto server_pref_dict1 = base::MakeUnique<base::DictionaryValue>();
  if (GetParam() >= 5) {
    servers_dict->SetWithoutPathExpansion("https://mail.google.com",
                                          std::move(server_pref_dict1));
  } else {
    servers_dict->SetWithoutPathExpansion("mail.google.com:80",
                                          std::move(server_pref_dict1));
  }
  base::DictionaryValue http_server_properties_dict;
  if (GetParam() >= 4) {
    servers_list->AppendIfNotPresent(std::move(servers_dict));
    if (GetParam() == 5) {
      HttpServerPropertiesManager::SetVersion(&http_server_properties_dict, -1);
    } else {
      HttpServerPropertiesManager::SetVersion(&http_server_properties_dict,
                                              GetParam());
    }
    http_server_properties_dict.SetWithoutPathExpansion(
        "servers", std::move(servers_list));
  } else {
    HttpServerPropertiesManager::SetVersion(&http_server_properties_dict,
                                            GetParam());
    http_server_properties_dict.SetWithoutPathExpansion(
        "servers", std::move(servers_dict));
  }

  // Set up SupportsQuic for 127.0.0.1
  auto supports_quic = base::MakeUnique<base::DictionaryValue>();
  supports_quic->SetBoolean("used_quic", true);
  supports_quic->SetString("address", "127.0.0.1");
  http_server_properties_dict.SetWithoutPathExpansion("supports_quic",
                                                      std::move(supports_quic));

  // Set up the pref.
  pref_delegate_->SetPrefs(http_server_properties_dict);

  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());

  // Verify alternative service.
  for (int i = 1; i <= 200; ++i) {
    GURL server_gurl;
    if (GetParam() >= 5) {
      server_gurl = GURL(StringPrintf("https://www.google.com:%d", i));
    } else {
      server_gurl = GURL(StringPrintf("https://www.google.com:%d", i));
    }
    url::SchemeHostPort server(server_gurl);
    AlternativeServiceInfoVector alternative_service_info_vector =
        http_server_props_manager_->GetAlternativeServiceInfos(server);
    ASSERT_EQ(1u, alternative_service_info_vector.size());
    EXPECT_EQ(
        kProtoQUIC,
        alternative_service_info_vector[0].alternative_service().protocol);
    EXPECT_EQ(i, alternative_service_info_vector[0].alternative_service().port);
  }

  // Verify SupportsQuic.
  IPAddress address;
  ASSERT_TRUE(http_server_props_manager_->GetSupportsQuic(&address));
  EXPECT_EQ("127.0.0.1", address.ToString());
}

TEST_P(HttpServerPropertiesManagerTest, UpdatePrefsWithCache) {
  ExpectScheduleUpdatePrefsOnNetworkSequenceRepeatedly(7);

  const url::SchemeHostPort server_www("https", "www.google.com", 80);
  const url::SchemeHostPort server_mail("https", "mail.google.com", 80);

  // #1 & #2: Set alternate protocol.
  AlternativeServiceInfoVector alternative_service_info_vector;
  AlternativeService www_alternative_service1(kProtoHTTP2, "", 443);
  base::Time expiration1;
  ASSERT_TRUE(base::Time::FromUTCString("2036-12-01 10:00:00", &expiration1));
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          www_alternative_service1, expiration1));

  AlternativeService www_alternative_service2(kProtoHTTP2, "www.google.com",
                                              1234);
  base::Time expiration2;
  ASSERT_TRUE(base::Time::FromUTCString("2036-12-31 10:00:00", &expiration2));
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          www_alternative_service2, expiration2));
  ASSERT_TRUE(http_server_props_manager_->SetAlternativeServices(
      server_www, alternative_service_info_vector));

  AlternativeService mail_alternative_service(kProtoHTTP2, "foo.google.com",
                                              444);
  base::Time expiration3 = base::Time::Max();
  ASSERT_TRUE(http_server_props_manager_->SetHttp2AlternativeService(
      server_mail, mail_alternative_service, expiration3));

  // #3 & #4: Mark alternate protocol broken/recently broken.
  {
    base::TestMockTimeTaskRunner::ScopedContext net_test_task_runner_context(
        net_test_task_runner_);

    http_server_props_manager_->MarkAlternativeServiceBroken(
        www_alternative_service2);
    http_server_props_manager_->MarkAlternativeServiceRecentlyBroken(
        mail_alternative_service);
  }

  // #5: Set ServerNetworkStats.
  ServerNetworkStats stats;
  stats.srtt = base::TimeDelta::FromInternalValue(42);
  http_server_props_manager_->SetServerNetworkStats(server_mail, stats);

  // #6: Set quic_server_info string.
  QuicServerId mail_quic_server_id("mail.google.com", 80);
  std::string quic_server_info1("quic_server_info1");
  http_server_props_manager_->SetQuicServerInfo(mail_quic_server_id,
                                                quic_server_info1);

  // #7: Set SupportsQuic.
  IPAddress actual_address(127, 0, 0, 1);
  http_server_props_manager_->SetSupportsQuic(true, actual_address);

  base::Time time_before_prefs_update = base::Time::Now();

  // Update Prefs.
  // |net_test_task_runner_| has a remaining pending task to expire
  // |www_alternative_service2| in 5 minutes. Fast forward enough such
  // that the prefs update task is executed but not the task to expire
  // |broken_alternative_service|.
  ExpectPrefsUpdate(1);
  EXPECT_EQ(2u, net_test_task_runner_->GetPendingTaskCount());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardBy(
      HttpServerPropertiesManager::GetUpdatePrefsDelayForTesting());
  EXPECT_EQ(1u, net_test_task_runner_->GetPendingTaskCount());
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1u, net_test_task_runner_->GetPendingTaskCount());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  base::Time time_after_prefs_update = base::Time::Now();

  // Verify |pref_delegate_|'s server dict.
  // In HttpServerPropertiesManager, broken alternative services' expiration
  // times are converted from TimeTicks to Time before being written to JSON by
  // using the difference between Time::Now() and TimeTicks::Now().
  // To verify these expiration times, |time_before_prefs_update| and
  // |time_after_prefs_update| provide lower and upper bounds for the
  // Time::Now() value used by the manager for this conversion.
  //
  // A copy of |pref_delegate_|'s server dict will be created, and the broken
  // alternative service's "broken_until" field is removed and verified
  // separately. The rest of the server dict copy is verified afterwards.
  base::Value server_value_copy(pref_delegate_->GetServerProperties());

  // Extract and remove the "broken_until" string for "www.google.com:1234".
  base::DictionaryValue* server_dict;
  ASSERT_TRUE(server_value_copy.GetAsDictionary(&server_dict));
  base::ListValue* broken_alt_svc_list;
  ASSERT_TRUE(server_dict->GetList("broken_alternative_services",
                                   &broken_alt_svc_list));
  ASSERT_EQ(2u, broken_alt_svc_list->GetSize());
  base::DictionaryValue* broken_alt_svcs_list_entry;
  ASSERT_TRUE(
      broken_alt_svc_list->GetDictionary(0, &broken_alt_svcs_list_entry));
  ASSERT_TRUE(broken_alt_svcs_list_entry->HasKey("broken_until"));
  std::string expiration_string;
  ASSERT_TRUE(broken_alt_svcs_list_entry->GetStringWithoutPathExpansion(
      "broken_until", &expiration_string));
  broken_alt_svcs_list_entry->RemoveWithoutPathExpansion("broken_until",
                                                         nullptr);

  // Expiration time of "www.google.com:1234" should be 5 minutes minus the
  // update-prefs-delay from when the prefs were written.
  int64_t expiration_int64;
  ASSERT_TRUE(base::StringToInt64(expiration_string, &expiration_int64));
  base::TimeDelta expiration_delta =
      base::TimeDelta::FromMinutes(5) -
      HttpServerPropertiesManager::GetUpdatePrefsDelayForTesting();
  time_t time_t_of_prefs_update = static_cast<time_t>(expiration_int64);
  EXPECT_LE((time_before_prefs_update + expiration_delta).ToTimeT(),
            time_t_of_prefs_update);
  EXPECT_GE((time_after_prefs_update + expiration_delta).ToTimeT(),
            time_t_of_prefs_update);

  // Verify all other preferences.
  const char expected_json[] =
      "{"
      "\"broken_alternative_services\":"
      "[{\"broken_count\":1,\"host\":\"www.google.com\",\"port\":1234,"
      "\"protocol_str\":\"h2\"},"
      "{\"broken_count\":1,\"host\":\"foo.google.com\",\"port\":444,"
      "\"protocol_str\":\"h2\"}],"
      "\"quic_servers\":"
      "{\"https://mail.google.com:80\":"
      "{\"server_info\":\"quic_server_info1\"}},"
      "\"servers\":["
      "{\"https://www.google.com:80\":{"
      "\"alternative_service\":[{\"advertised_versions\":[],"
      "\"expiration\":\"13756212000000000\",\"port\":443,"
      "\"protocol_str\":\"h2\"},"
      "{\"advertised_versions\":[],\"expiration\":\"13758804000000000\","
      "\"host\":\"www.google.com\",\"port\":1234,\"protocol_str\":\"h2\"}]}},"
      "{\"https://mail.google.com:80\":{"
      "\"alternative_service\":[{\"advertised_versions\":[],"
      "\"expiration\":\"9223372036854775807\",\"host\":\"foo.google.com\","
      "\"port\":444,\"protocol_str\":\"h2\"}],"
      "\"network_stats\":{\"srtt\":42}}}],"
      "\"supports_quic\":{\"address\":\"127.0.0.1\",\"used_quic\":true},"
      "\"version\":5}";

  std::string preferences_json;
  EXPECT_TRUE(base::JSONWriter::Write(server_value_copy, &preferences_json));
  EXPECT_EQ(expected_json, preferences_json);
}

TEST_P(HttpServerPropertiesManagerTest,
       SingleCacheUpdateForMultipleUpdatesScheduled) {
  // Update cache.
  ExpectCacheUpdate();

  EXPECT_EQ(0u, pref_test_task_runner_->GetPendingTaskCount());
  // Update cache.
  http_server_props_manager_->ScheduleUpdateCacheOnPrefThread();
  EXPECT_EQ(1u, pref_test_task_runner_->GetPendingTaskCount());

  // Move forward the task runner short by 20ms.
  pref_test_task_runner_->FastForwardBy(
      HttpServerPropertiesManager::GetUpdateCacheDelayForTesting() -
      base::TimeDelta::FromMilliseconds(20));
  // Schedule a new cache update within the time window should be a no-op.
  http_server_props_manager_->ScheduleUpdateCacheOnPrefThread();
  EXPECT_EQ(1u, pref_test_task_runner_->GetPendingTaskCount());

  // Move forward the task runner the extra 20ms, now the cache update should be
  // executed.
  pref_test_task_runner_->FastForwardBy(base::TimeDelta::FromMilliseconds(20));

  // Since this test has no pref corruption, there shouldn't be any pref update.
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  // Schedule one more cache update. The task should be successfully scheduled
  // on pref task runner.
  ExpectCacheUpdate();
  http_server_props_manager_->ScheduleUpdateCacheOnPrefThread();
  EXPECT_EQ(1u, pref_test_task_runner_->GetPendingTaskCount());

  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
}

TEST_P(HttpServerPropertiesManagerTest, AddToAlternativeServiceMap) {
  std::unique_ptr<base::Value> server_value = base::JSONReader::Read(
      "{\"alternative_service\":[{\"port\":443,\"protocol_str\":\"h2\"},"
      "{\"port\":123,\"protocol_str\":\"quic\","
      "\"expiration\":\"9223372036854775807\"},{\"host\":\"example.org\","
      "\"port\":1234,\"protocol_str\":\"h2\","
      "\"expiration\":\"13758804000000000\"}]}");
  ASSERT_TRUE(server_value);
  base::DictionaryValue* server_dict;
  ASSERT_TRUE(server_value->GetAsDictionary(&server_dict));

  const url::SchemeHostPort server("https", "example.com", 443);
  AlternativeServiceMap alternative_service_map(/*max_size=*/5);
  EXPECT_TRUE(http_server_props_manager_->AddToAlternativeServiceMap(
      server, *server_dict, &alternative_service_map));

  AlternativeServiceMap::iterator it = alternative_service_map.Get(server);
  ASSERT_NE(alternative_service_map.end(), it);
  AlternativeServiceInfoVector alternative_service_info_vector = it->second;
  ASSERT_EQ(3u, alternative_service_info_vector.size());

  EXPECT_EQ(kProtoHTTP2,
            alternative_service_info_vector[0].alternative_service().protocol);
  EXPECT_EQ("", alternative_service_info_vector[0].alternative_service().host);
  EXPECT_EQ(443, alternative_service_info_vector[0].alternative_service().port);
  // Expiration defaults to one day from now, testing with tolerance.
  const base::Time now = base::Time::Now();
  const base::Time expiration = alternative_service_info_vector[0].expiration();
  EXPECT_LE(now + base::TimeDelta::FromHours(23), expiration);
  EXPECT_GE(now + base::TimeDelta::FromDays(1), expiration);

  EXPECT_EQ(kProtoQUIC,
            alternative_service_info_vector[1].alternative_service().protocol);
  EXPECT_EQ("", alternative_service_info_vector[1].alternative_service().host);
  EXPECT_EQ(123, alternative_service_info_vector[1].alternative_service().port);
  // numeric_limits<int64_t>::max() represents base::Time::Max().
  EXPECT_EQ(base::Time::Max(), alternative_service_info_vector[1].expiration());

  EXPECT_EQ(kProtoHTTP2,
            alternative_service_info_vector[2].alternative_service().protocol);
  EXPECT_EQ("example.org",
            alternative_service_info_vector[2].alternative_service().host);
  EXPECT_EQ(1234,
            alternative_service_info_vector[2].alternative_service().port);
  base::Time expected_expiration;
  ASSERT_TRUE(
      base::Time::FromUTCString("2036-12-31 10:00:00", &expected_expiration));
  EXPECT_EQ(expected_expiration,
            alternative_service_info_vector[2].expiration());
}

// Regression test for https://crbug.com/615497.
TEST_P(HttpServerPropertiesManagerTest, DoNotLoadAltSvcForInsecureOrigins) {
  std::unique_ptr<base::Value> server_value = base::JSONReader::Read(
      "{\"alternative_service\":[{\"port\":443,\"protocol_str\":\"h2\","
      "\"expiration\":\"9223372036854775807\"}]}");
  ASSERT_TRUE(server_value);
  base::DictionaryValue* server_dict;
  ASSERT_TRUE(server_value->GetAsDictionary(&server_dict));

  const url::SchemeHostPort server("http", "example.com", 80);
  AlternativeServiceMap alternative_service_map(/*max_size=*/5);
  EXPECT_FALSE(http_server_props_manager_->AddToAlternativeServiceMap(
      server, *server_dict, &alternative_service_map));

  AlternativeServiceMap::iterator it = alternative_service_map.Get(server);
  EXPECT_EQ(alternative_service_map.end(), it);
}

// Do not persist expired alternative service entries to disk.
TEST_P(HttpServerPropertiesManagerTest, DoNotPersistExpiredAlternativeService) {
  ExpectScheduleUpdatePrefsOnNetworkSequenceRepeatedly(2);

  {
    TestMockTimeTaskRunner::ScopedContext scoped_context(net_test_task_runner_);

    AlternativeServiceInfoVector alternative_service_info_vector;

    const AlternativeService broken_alternative_service(
        kProtoHTTP2, "broken.example.com", 443);
    const base::Time time_one_day_later =
        base::Time::Now() + base::TimeDelta::FromDays(1);
    alternative_service_info_vector.push_back(
        AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
            broken_alternative_service, time_one_day_later));
    // #1: MarkAlternativeServiceBroken().
    http_server_props_manager_->MarkAlternativeServiceBroken(
        broken_alternative_service);

    const AlternativeService expired_alternative_service(
        kProtoHTTP2, "expired.example.com", 443);
    const base::Time time_one_day_ago =
        base::Time::Now() - base::TimeDelta::FromDays(1);
    alternative_service_info_vector.push_back(
        AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
            expired_alternative_service, time_one_day_ago));

    const AlternativeService valid_alternative_service(
        kProtoHTTP2, "valid.example.com", 443);
    alternative_service_info_vector.push_back(
        AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
            valid_alternative_service, time_one_day_later));

    const url::SchemeHostPort server("https", "www.example.com", 443);
    // #2: SetAlternativeServices().
    ASSERT_TRUE(http_server_props_manager_->SetAlternativeServices(
        server, alternative_service_info_vector));
  }

  // Update cache.
  ExpectPrefsUpdate(1);

  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  // |net_test_task_runner_| has a remaining pending task to expire
  // |broken_alternative_service| at |time_one_day_later|. Fast forward enough
  // such that the prefs update task is executed but not the task to expire
  // |broken_alternative_service|.
  EXPECT_EQ(2U, net_test_task_runner_->GetPendingTaskCount());
  net_test_task_runner_->FastForwardBy(
      HttpServerPropertiesManager::GetUpdatePrefsDelayForTesting());
  EXPECT_EQ(1U, net_test_task_runner_->GetPendingTaskCount());

  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1U, net_test_task_runner_->GetPendingTaskCount());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  const base::DictionaryValue& pref_dict =
      pref_delegate_->GetServerProperties();

  const base::ListValue* servers_list = nullptr;
  ASSERT_TRUE(pref_dict.GetListWithoutPathExpansion("servers", &servers_list));
  base::ListValue::const_iterator it = servers_list->begin();
  const base::DictionaryValue* server_pref_dict;
  ASSERT_TRUE(it->GetAsDictionary(&server_pref_dict));

  const base::DictionaryValue* example_pref_dict;

  ASSERT_TRUE(server_pref_dict->GetDictionaryWithoutPathExpansion(
      "https://www.example.com", &example_pref_dict));

  const base::ListValue* altsvc_list;
  ASSERT_TRUE(example_pref_dict->GetList("alternative_service", &altsvc_list));

  ASSERT_EQ(2u, altsvc_list->GetSize());

  const base::DictionaryValue* altsvc_entry;
  std::string hostname;

  ASSERT_TRUE(altsvc_list->GetDictionary(0, &altsvc_entry));
  ASSERT_TRUE(altsvc_entry->GetString("host", &hostname));
  EXPECT_EQ("broken.example.com", hostname);

  ASSERT_TRUE(altsvc_list->GetDictionary(1, &altsvc_entry));
  ASSERT_TRUE(altsvc_entry->GetString("host", &hostname));
  EXPECT_EQ("valid.example.com", hostname);
}

// Test that expired alternative service entries on disk are ignored.
TEST_P(HttpServerPropertiesManagerTest, DoNotLoadExpiredAlternativeService) {
  auto alternative_service_list = base::MakeUnique<base::ListValue>();
  auto expired_dict = base::MakeUnique<base::DictionaryValue>();
  expired_dict->SetString("protocol_str", "h2");
  expired_dict->SetString("host", "expired.example.com");
  expired_dict->SetInteger("port", 443);
  base::Time time_one_day_ago =
      base::Time::Now() - base::TimeDelta::FromDays(1);
  expired_dict->SetString(
      "expiration", base::Int64ToString(time_one_day_ago.ToInternalValue()));
  alternative_service_list->Append(std::move(expired_dict));

  auto valid_dict = base::MakeUnique<base::DictionaryValue>();
  valid_dict->SetString("protocol_str", "h2");
  valid_dict->SetString("host", "valid.example.com");
  valid_dict->SetInteger("port", 443);
  valid_dict->SetString(
      "expiration", base::Int64ToString(one_day_from_now_.ToInternalValue()));
  alternative_service_list->Append(std::move(valid_dict));

  base::DictionaryValue server_pref_dict;
  server_pref_dict.SetWithoutPathExpansion("alternative_service",
                                           std::move(alternative_service_list));

  const url::SchemeHostPort server("https", "example.com", 443);
  AlternativeServiceMap alternative_service_map(/*max_size=*/5);
  ASSERT_TRUE(http_server_props_manager_->AddToAlternativeServiceMap(
      server, server_pref_dict, &alternative_service_map));

  AlternativeServiceMap::iterator it = alternative_service_map.Get(server);
  ASSERT_NE(alternative_service_map.end(), it);
  AlternativeServiceInfoVector alternative_service_info_vector = it->second;
  ASSERT_EQ(1u, alternative_service_info_vector.size());

  EXPECT_EQ(kProtoHTTP2,
            alternative_service_info_vector[0].alternative_service().protocol);
  EXPECT_EQ("valid.example.com",
            alternative_service_info_vector[0].alternative_service().host);
  EXPECT_EQ(443, alternative_service_info_vector[0].alternative_service().port);
  EXPECT_EQ(one_day_from_now_, alternative_service_info_vector[0].expiration());
}

TEST_P(HttpServerPropertiesManagerTest, ShutdownWithPendingUpdateCache0) {
  // Post an update task to the UI thread.
  http_server_props_manager_->ScheduleUpdateCacheOnPrefThread();
  // Shutdown comes before the task is executed.
  http_server_props_manager_->ShutdownOnPrefSequence();
  http_server_props_manager_.reset();
  // Run the task after shutdown and deletion.
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
}

TEST_P(HttpServerPropertiesManagerTest, ShutdownWithPendingUpdateCache1) {
  // Post an update task.
  http_server_props_manager_->ScheduleUpdateCacheOnPrefThread();
  // Shutdown comes before the task is executed.
  http_server_props_manager_->ShutdownOnPrefSequence();
  // Run the task after shutdown, but before deletion.
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());
  http_server_props_manager_.reset();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
}

TEST_P(HttpServerPropertiesManagerTest, ShutdownWithPendingUpdateCache2) {
  http_server_props_manager_->UpdateCacheFromPrefsOnUIConcrete();
  // Shutdown comes before the task is executed.
  http_server_props_manager_->ShutdownOnPrefSequence();
  // There should be no tasks to run.
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());
  http_server_props_manager_.reset();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
}

//
// Tests for shutdown when updating prefs.
//
TEST_P(HttpServerPropertiesManagerTest, ShutdownWithPendingUpdatePrefs0) {
  // Post an update task to the IO thread.
  http_server_props_manager_->ScheduleUpdatePrefsOnNetworkSequenceDefault();
  // Shutdown comes before the task is executed.
  http_server_props_manager_->ShutdownOnPrefSequence();
  http_server_props_manager_.reset();
  // Run the task after shutdown and deletion.
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
}

TEST_P(HttpServerPropertiesManagerTest, ShutdownWithPendingUpdatePrefs1) {
  ExpectPrefsUpdate(1);
  // Post an update task.
  http_server_props_manager_->ScheduleUpdatePrefsOnNetworkSequenceDefault();
  // Shutdown comes before the task is executed.
  http_server_props_manager_->ShutdownOnPrefSequence();
  // Run the task after shutdown, but before deletion.
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());
  http_server_props_manager_.reset();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
}

TEST_P(HttpServerPropertiesManagerTest, ShutdownWithPendingUpdatePrefs2) {
  // This posts a task to the UI thread.
  http_server_props_manager_->UpdatePrefsFromCacheOnNetworkSequenceConcrete(
      base::Closure());
  // Shutdown comes before the task is executed.
  http_server_props_manager_->ShutdownOnPrefSequence();
  // Run the task after shutdown, but before deletion.
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());
  http_server_props_manager_.reset();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
}

TEST_P(HttpServerPropertiesManagerTest, PersistAdvertisedVersionsToPref) {
  ExpectScheduleUpdatePrefsOnNetworkSequenceRepeatedly(5);

  const url::SchemeHostPort server_www("https", "www.google.com", 80);
  const url::SchemeHostPort server_mail("https", "mail.google.com", 80);

  // #1 & #2: Set alternate protocol.
  AlternativeServiceInfoVector alternative_service_info_vector;
  // Quic alternative service set with two advertised QUIC versions.
  AlternativeService quic_alternative_service1(kProtoQUIC, "", 443);
  base::Time expiration1;
  ASSERT_TRUE(base::Time::FromUTCString("2036-12-01 10:00:00", &expiration1));
  QuicVersionVector advertised_versions = {QUIC_VERSION_37, QUIC_VERSION_35};
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          quic_alternative_service1, expiration1, advertised_versions));
  // HTTP/2 alternative service should not set any advertised version.
  AlternativeService h2_alternative_service(kProtoHTTP2, "www.google.com",
                                            1234);
  base::Time expiration2;
  ASSERT_TRUE(base::Time::FromUTCString("2036-12-31 10:00:00", &expiration2));
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          h2_alternative_service, expiration2));
  ASSERT_TRUE(http_server_props_manager_->SetAlternativeServices(
      server_www, alternative_service_info_vector));

  // Set another QUIC alternative service with a single advertised QUIC version.
  AlternativeService mail_alternative_service(kProtoQUIC, "foo.google.com",
                                              444);
  base::Time expiration3 = base::Time::Max();
  ASSERT_TRUE(http_server_props_manager_->SetQuicAlternativeService(
      server_mail, mail_alternative_service, expiration3,
      advertised_versions_));
  // #3: Set ServerNetworkStats.
  ServerNetworkStats stats;
  stats.srtt = base::TimeDelta::FromInternalValue(42);
  http_server_props_manager_->SetServerNetworkStats(server_mail, stats);

  // #4: Set quic_server_info string.
  QuicServerId mail_quic_server_id("mail.google.com", 80);
  std::string quic_server_info1("quic_server_info1");
  http_server_props_manager_->SetQuicServerInfo(mail_quic_server_id,
                                                quic_server_info1);

  // #5: Set SupportsQuic.
  IPAddress actual_address(127, 0, 0, 1);
  http_server_props_manager_->SetSupportsQuic(true, actual_address);

  // Update Prefs.
  ExpectPrefsUpdate(1);
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  // Verify preferences with correct advertised version field.
  const char expected_json[] =
      "{\"quic_servers\":{\"https://mail.google.com:80\":{"
      "\"server_info\":\"quic_server_info1\"}},\"servers\":["
      "{\"https://www.google.com:80\":{\"alternative_service\":[{"
      "\"advertised_versions\":[35,37],\"expiration\":\"13756212000000000\","
      "\"port\":443,\"protocol_str\":\"quic\"},{\"advertised_versions\":[],"
      "\"expiration\":\"13758804000000000\",\"host\":\"www.google.com\","
      "\"port\":1234,\"protocol_str\":\"h2\"}]}},"
      "{\"https://mail.google.com:80\":{\"alternative_service\":[{"
      "\"advertised_versions\":[39],\"expiration\":\"9223372036854775807\","
      "\"host\":\"foo.google.com\",\"port\":444,\"protocol_str\":\"quic\"}],"
      "\"network_stats\":{\"srtt\":42}}}],\"supports_quic\":{"
      "\"address\":\"127.0.0.1\",\"used_quic\":true},\"version\":5}";

  const base::Value* http_server_properties =
      &pref_delegate_->GetServerProperties();
  std::string preferences_json;
  EXPECT_TRUE(
      base::JSONWriter::Write(*http_server_properties, &preferences_json));
  EXPECT_EQ(expected_json, preferences_json);
}

TEST_P(HttpServerPropertiesManagerTest, ReadAdvertisedVersionsFromPref) {
  std::unique_ptr<base::Value> server_value = base::JSONReader::Read(
      "{\"alternative_service\":["
      "{\"port\":443,\"protocol_str\":\"quic\"},"
      "{\"port\":123,\"protocol_str\":\"quic\","
      "\"expiration\":\"9223372036854775807\","
      "\"advertised_versions\":[37,35]}]}");
  ASSERT_TRUE(server_value);
  base::DictionaryValue* server_dict;
  ASSERT_TRUE(server_value->GetAsDictionary(&server_dict));

  const url::SchemeHostPort server("https", "example.com", 443);
  AlternativeServiceMap alternative_service_map(/*max_size=*/5);
  EXPECT_TRUE(http_server_props_manager_->AddToAlternativeServiceMap(
      server, *server_dict, &alternative_service_map));

  AlternativeServiceMap::iterator it = alternative_service_map.Get(server);
  ASSERT_NE(alternative_service_map.end(), it);
  AlternativeServiceInfoVector alternative_service_info_vector = it->second;
  ASSERT_EQ(2u, alternative_service_info_vector.size());

  // Verify the first alternative service with no advertised version listed.
  EXPECT_EQ(kProtoQUIC,
            alternative_service_info_vector[0].alternative_service().protocol);
  EXPECT_EQ("", alternative_service_info_vector[0].alternative_service().host);
  EXPECT_EQ(443, alternative_service_info_vector[0].alternative_service().port);
  // Expiration defaults to one day from now, testing with tolerance.
  const base::Time now = base::Time::Now();
  const base::Time expiration = alternative_service_info_vector[0].expiration();
  EXPECT_LE(now + base::TimeDelta::FromHours(23), expiration);
  EXPECT_GE(now + base::TimeDelta::FromDays(1), expiration);
  EXPECT_TRUE(alternative_service_info_vector[0].advertised_versions().empty());

  // Verify the second alterntaive service with two advertised versions.
  EXPECT_EQ(kProtoQUIC,
            alternative_service_info_vector[1].alternative_service().protocol);
  EXPECT_EQ("", alternative_service_info_vector[1].alternative_service().host);
  EXPECT_EQ(123, alternative_service_info_vector[1].alternative_service().port);
  EXPECT_EQ(base::Time::Max(), alternative_service_info_vector[1].expiration());
  // Verify advertised versions.
  const QuicVersionVector loaded_advertised_versions =
      alternative_service_info_vector[1].advertised_versions();
  EXPECT_EQ(2u, loaded_advertised_versions.size());
  EXPECT_EQ(QUIC_VERSION_35, loaded_advertised_versions[0]);
  EXPECT_EQ(QUIC_VERSION_37, loaded_advertised_versions[1]);
}

TEST_P(HttpServerPropertiesManagerTest,
       UpdatePrefWhenAdvertisedVersionsChange) {
  ExpectScheduleUpdatePrefsOnNetworkSequenceRepeatedly(4);

  const url::SchemeHostPort server_www("https", "www.google.com", 80);

  // #1: Set alternate protocol.
  AlternativeServiceInfoVector alternative_service_info_vector;
  // Quic alternative service set with a single QUIC version: QUIC_VERSION_37.
  AlternativeService quic_alternative_service1(kProtoQUIC, "", 443);
  base::Time expiration1;
  ASSERT_TRUE(base::Time::FromUTCString("2036-12-01 10:00:00", &expiration1));
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          quic_alternative_service1, expiration1, advertised_versions_));
  ASSERT_TRUE(http_server_props_manager_->SetAlternativeServices(
      server_www, alternative_service_info_vector));

  // Set quic_server_info string.
  QuicServerId mail_quic_server_id("mail.google.com", 80);
  std::string quic_server_info1("quic_server_info1");
  http_server_props_manager_->SetQuicServerInfo(mail_quic_server_id,
                                                quic_server_info1);

  // Set SupportsQuic.
  IPAddress actual_address(127, 0, 0, 1);
  http_server_props_manager_->SetSupportsQuic(true, actual_address);

  // Update Prefs.
  ExpectPrefsUpdate(1);
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  // Verify preferences with correct advertised version field.
  const char expected_json[] =
      "{\"quic_servers\":{\"https://mail.google.com:80\":"
      "{\"server_info\":\"quic_server_info1\"}},\"servers\":["
      "{\"https://www.google.com:80\":"
      "{\"alternative_service\":[{\"advertised_versions\":[39],"
      "\"expiration\":\"13756212000000000\",\"port\":443,"
      "\"protocol_str\":\"quic\"}]}}],\"supports_quic\":"
      "{\"address\":\"127.0.0.1\",\"used_quic\":true},\"version\":5}";

  const base::Value* http_server_properties =
      &pref_delegate_->GetServerProperties();
  std::string preferences_json;
  EXPECT_TRUE(
      base::JSONWriter::Write(*http_server_properties, &preferences_json));
  EXPECT_EQ(expected_json, preferences_json);

  // #2: Set AlternativeService with different advertised_versions for the same
  // AlternativeService.
  AlternativeServiceInfoVector alternative_service_info_vector_2;
  // Quic alternative service set with two advertised QUIC versions.
  QuicVersionVector advertised_versions = {QUIC_VERSION_37, QUIC_VERSION_35};
  alternative_service_info_vector_2.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          quic_alternative_service1, expiration1, advertised_versions));
  ASSERT_TRUE(http_server_props_manager_->SetAlternativeServices(
      server_www, alternative_service_info_vector_2));

  // Update Prefs.
  ExpectPrefsUpdate(1);
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  // Verify preferences updated with new advertised versions.
  const char expected_json_updated[] =
      "{\"quic_servers\":{\"https://mail.google.com:80\":"
      "{\"server_info\":\"quic_server_info1\"}},\"servers\":["
      "{\"https://www.google.com:80\":"
      "{\"alternative_service\":[{\"advertised_versions\":[35,37],"
      "\"expiration\":\"13756212000000000\",\"port\":443,"
      "\"protocol_str\":\"quic\"}]}}],\"supports_quic\":"
      "{\"address\":\"127.0.0.1\",\"used_quic\":true},\"version\":5}";
  EXPECT_TRUE(
      base::JSONWriter::Write(*http_server_properties, &preferences_json));
  EXPECT_EQ(expected_json_updated, preferences_json);

  // #3: Set AlternativeService with same advertised_versions.
  AlternativeServiceInfoVector alternative_service_info_vector_3;
  // A same set of QUIC versions but listed in a different order.
  QuicVersionVector advertised_versions_2 = {QUIC_VERSION_35, QUIC_VERSION_37};
  alternative_service_info_vector_3.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          quic_alternative_service1, expiration1, advertised_versions_2));
  ASSERT_FALSE(http_server_props_manager_->SetAlternativeServices(
      server_www, alternative_service_info_vector_3));

  // No Prefs update.
  EXPECT_FALSE(net_test_task_runner_->HasPendingTask());
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());
}

TEST_P(HttpServerPropertiesManagerTest, UpdateCacheWithPrefs) {
  ExpectScheduleUpdatePrefsOnNetworkSequenceRepeatedly(3);

  AlternativeService cached_broken_service(kProtoQUIC, "cached_broken", 443);
  AlternativeService cached_broken_service2(kProtoQUIC, "cached_broken2", 443);
  AlternativeService cached_recently_broken_service(kProtoQUIC,
                                                    "cached_rbroken", 443);

  {
    TestMockTimeTaskRunner::ScopedContext scoped_context(net_test_task_runner_);

    http_server_props_manager_->MarkAlternativeServiceBroken(
        cached_broken_service);
    http_server_props_manager_->MarkAlternativeServiceBroken(
        cached_broken_service2);
    http_server_props_manager_->MarkAlternativeServiceRecentlyBroken(
        cached_recently_broken_service);
  }
  ExpectPrefsUpdate(1);
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  // Run the prefs update task but not the expiration task for
  // |cached_broken_service|.
  net_test_task_runner_->FastForwardBy(
      HttpServerPropertiesManager::GetUpdatePrefsDelayForTesting());
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(pref_test_task_runner_->HasPendingTask());

  // Load the |pref_delegate_| with some JSON to verify updating the cache from
  // prefs. For the broken alternative services "www.google.com:1234" and
  // "cached_broken", the expiration time will be one day from now.

  std::string expiration_str =
      base::Int64ToString(static_cast<int64_t>(one_day_from_now_.ToTimeT()));

  std::unique_ptr<base::Value> server_value = base::JSONReader::Read(
      "{"
      "\"broken_alternative_services\":["
      "{\"broken_until\":\"" +
      expiration_str +
      "\","
      "\"host\":\"www.google.com\",\"port\":1234,\"protocol_str\":\"h2\"},"
      "{\"broken_count\":2,\"broken_until\":\"" +
      expiration_str +
      "\","
      "\"host\":\"cached_broken\",\"port\":443,\"protocol_str\":\"quic\"},"
      "{\"broken_count\":3,"
      "\"host\":\"cached_rbroken\",\"port\":443,\"protocol_str\":\"quic\"}],"
      "\"quic_servers\":{"
      "\"https://mail.google.com:80\":{"
      "\"server_info\":\"quic_server_info1\"}"
      "},"
      "\"servers\":["
      "{\"https://www.google.com:80\":{"
      "\"alternative_service\":["
      "{\"expiration\":\"13756212000000000\",\"port\":443,"
      "\"protocol_str\":\"h2\"},"
      "{\"expiration\":\"13758804000000000\",\"host\":\"www.google.com\","
      "\"port\":1234,\"protocol_str\":\"h2\"}"
      "]"
      "}},"
      "{\"https://mail.google.com:80\":{"
      "\"alternative_service\":["
      "{\"expiration\":\"9223372036854775807\",\"host\":\"foo.google.com\","
      "\"port\":444,\"protocol_str\":\"h2\"}"
      "],"
      "\"network_stats\":{\"srtt\":42}"
      "}}"
      "],"
      "\"supports_quic\":"
      "{\"address\":\"127.0.0.1\",\"used_quic\":true},"
      "\"version\":5"
      "}");
  ASSERT_TRUE(server_value);
  base::DictionaryValue* server_dict;
  ASSERT_TRUE(server_value->GetAsDictionary(&server_dict));

  pref_delegate_->SetPrefs(*server_dict);

  ExpectCacheUpdate();
  EXPECT_TRUE(pref_test_task_runner_->HasPendingTask());
  pref_test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  // Run the cache update task but not the expiration task for
  // |cached_broken_service|.
  net_test_task_runner_->FastForwardBy(
      net_test_task_runner_->NextPendingTaskDelay());
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());

  //
  // Verify alternative service info for https://www.google.com
  //
  AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_props_manager_->GetAlternativeServiceInfos(
          url::SchemeHostPort("https", "www.google.com", 80));
  ASSERT_EQ(2u, alternative_service_info_vector.size());

  EXPECT_EQ(kProtoHTTP2,
            alternative_service_info_vector[0].alternative_service().protocol);
  EXPECT_EQ("www.google.com",
            alternative_service_info_vector[0].alternative_service().host);
  EXPECT_EQ(443, alternative_service_info_vector[0].alternative_service().port);
  EXPECT_EQ(
      "13756212000000000",
      base::Int64ToString(
          alternative_service_info_vector[0].expiration().ToInternalValue()));

  EXPECT_EQ(kProtoHTTP2,
            alternative_service_info_vector[1].alternative_service().protocol);
  EXPECT_EQ("www.google.com",
            alternative_service_info_vector[1].alternative_service().host);
  EXPECT_EQ(1234,
            alternative_service_info_vector[1].alternative_service().port);
  EXPECT_EQ(
      "13758804000000000",
      base::Int64ToString(
          alternative_service_info_vector[1].expiration().ToInternalValue()));

  //
  // Verify alternative service info for https://mail.google.com
  //
  alternative_service_info_vector =
      http_server_props_manager_->GetAlternativeServiceInfos(
          url::SchemeHostPort("https", "mail.google.com", 80));
  ASSERT_EQ(1u, alternative_service_info_vector.size());

  EXPECT_EQ(kProtoHTTP2,
            alternative_service_info_vector[0].alternative_service().protocol);
  EXPECT_EQ("foo.google.com",
            alternative_service_info_vector[0].alternative_service().host);
  EXPECT_EQ(444, alternative_service_info_vector[0].alternative_service().port);
  EXPECT_EQ(
      "9223372036854775807",
      base::Int64ToString(
          alternative_service_info_vector[0].expiration().ToInternalValue()));

  //
  // Verify broken alternative services.
  //
  AlternativeService prefs_broken_service(kProtoHTTP2, "www.google.com", 1234);
  EXPECT_TRUE(http_server_props_manager_->IsAlternativeServiceBroken(
      cached_broken_service));
  EXPECT_TRUE(http_server_props_manager_->IsAlternativeServiceBroken(
      cached_broken_service2));
  EXPECT_TRUE(http_server_props_manager_->IsAlternativeServiceBroken(
      prefs_broken_service));
  // Verify brokenness expiration times.
  // |cached_broken_service|'s expiration time should've been overwritten by the
  // prefs to be approximately 1 day from now. |cached_broken_service2|'s
  // expiration time should still be 5 minutes due to being marked broken.
  // |prefs_broken_service|'s expiration time should be approximately 1 day from
  // now which comes from the prefs.
  net_test_task_runner_->FastForwardBy(base::TimeDelta::FromMinutes(4));
  EXPECT_TRUE(http_server_props_manager_->IsAlternativeServiceBroken(
      cached_broken_service));
  EXPECT_FALSE(http_server_props_manager_->IsAlternativeServiceBroken(
      cached_broken_service2));
  EXPECT_TRUE(http_server_props_manager_->IsAlternativeServiceBroken(
      prefs_broken_service));
  net_test_task_runner_->FastForwardBy(base::TimeDelta::FromDays(1));
  EXPECT_FALSE(http_server_props_manager_->IsAlternativeServiceBroken(
      cached_broken_service));
  EXPECT_FALSE(http_server_props_manager_->IsAlternativeServiceBroken(
      cached_broken_service2));
  EXPECT_FALSE(http_server_props_manager_->IsAlternativeServiceBroken(
      prefs_broken_service));

  // Now that |prefs_broken_service|'s brokenness has expired, it should've
  // been removed from the alternative services info vectors of all servers.
  alternative_service_info_vector =
      http_server_props_manager_->GetAlternativeServiceInfos(
          url::SchemeHostPort("https", "www.google.com", 80));
  ASSERT_EQ(1u, alternative_service_info_vector.size());

  //
  // Verify recently broken alternative services.
  //

  // If an entry is already in cache, the broken count in the prefs should
  // overwrite the one in the cache.
  // |prefs_broken_service| should have broken-count 1 from prefs.
  // |cached_recently_broken_service| should have broken-count 3 from prefs.
  // |cached_broken_service| should have broken-count 2 from prefs.
  // |cached_broken_service2| should have broken-count 1 from being marked
  // broken.
  ExpectScheduleUpdatePrefsOnNetworkSequenceRepeatedly(4);
  ExpectPrefsUpdate(4);

  EXPECT_TRUE(http_server_props_manager_->WasAlternativeServiceRecentlyBroken(
      prefs_broken_service));
  EXPECT_TRUE(http_server_props_manager_->WasAlternativeServiceRecentlyBroken(
      cached_recently_broken_service));
  EXPECT_TRUE(http_server_props_manager_->WasAlternativeServiceRecentlyBroken(
      cached_broken_service));
  EXPECT_TRUE(http_server_props_manager_->WasAlternativeServiceRecentlyBroken(
      cached_broken_service2));
  // Make sure |prefs_broken_service| has the right expiration delay when marked
  // broken. Since |prefs_broken_service| had no broken_count specified in the
  // prefs, a broken_count value of 1 should have been assumed by
  // |http_server_props_manager_|.
  {
    TestMockTimeTaskRunner::ScopedContext scoped_context(net_test_task_runner_);
    http_server_props_manager_->MarkAlternativeServiceBroken(
        prefs_broken_service);
  }
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardBy(base::TimeDelta::FromMinutes(10) -
                                       base::TimeDelta::FromInternalValue(1));
  EXPECT_TRUE(http_server_props_manager_->IsAlternativeServiceBroken(
      prefs_broken_service));
  net_test_task_runner_->FastForwardBy(base::TimeDelta::FromInternalValue(1));
  EXPECT_FALSE(http_server_props_manager_->IsAlternativeServiceBroken(
      prefs_broken_service));
  // Make sure |cached_recently_broken_service| has the right expiration delay
  // when marked broken.
  {
    TestMockTimeTaskRunner::ScopedContext scoped_context(net_test_task_runner_);
    http_server_props_manager_->MarkAlternativeServiceBroken(
        cached_recently_broken_service);
  }
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardBy(base::TimeDelta::FromMinutes(40) -
                                       base::TimeDelta::FromInternalValue(1));
  EXPECT_TRUE(http_server_props_manager_->IsAlternativeServiceBroken(
      cached_recently_broken_service));
  net_test_task_runner_->FastForwardBy(base::TimeDelta::FromInternalValue(1));
  EXPECT_FALSE(http_server_props_manager_->IsAlternativeServiceBroken(
      cached_recently_broken_service));
  // Make sure |cached_broken_service| has the right expiration delay when
  // marked broken.
  {
    TestMockTimeTaskRunner::ScopedContext scoped_context(net_test_task_runner_);
    http_server_props_manager_->MarkAlternativeServiceBroken(
        cached_broken_service);
  }
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardBy(base::TimeDelta::FromMinutes(20) -
                                       base::TimeDelta::FromInternalValue(1));
  EXPECT_TRUE(http_server_props_manager_->IsAlternativeServiceBroken(
      cached_broken_service));
  net_test_task_runner_->FastForwardBy(base::TimeDelta::FromInternalValue(1));
  EXPECT_FALSE(http_server_props_manager_->IsAlternativeServiceBroken(
      cached_broken_service));
  // Make sure |cached_broken_service2| has the right expiration delay when
  // marked broken.
  {
    TestMockTimeTaskRunner::ScopedContext scoped_context(net_test_task_runner_);
    http_server_props_manager_->MarkAlternativeServiceBroken(
        cached_broken_service2);
  }
  EXPECT_TRUE(net_test_task_runner_->HasPendingTask());
  net_test_task_runner_->FastForwardBy(base::TimeDelta::FromMinutes(10) -
                                       base::TimeDelta::FromInternalValue(1));
  EXPECT_TRUE(http_server_props_manager_->IsAlternativeServiceBroken(
      cached_broken_service2));
  net_test_task_runner_->FastForwardBy(base::TimeDelta::FromInternalValue(1));
  EXPECT_FALSE(http_server_props_manager_->IsAlternativeServiceBroken(
      cached_broken_service2));

  Mock::VerifyAndClearExpectations(http_server_props_manager_.get());

  //
  // Verify ServerNetworkStats.
  //
  const ServerNetworkStats* server_network_stats =
      http_server_props_manager_->GetServerNetworkStats(
          url::SchemeHostPort("https", "mail.google.com", 80));
  EXPECT_TRUE(server_network_stats);
  EXPECT_EQ(server_network_stats->srtt, base::TimeDelta::FromInternalValue(42));

  //
  // Verify QUIC server info.
  //
  const std::string* quic_server_info =
      http_server_props_manager_->GetQuicServerInfo(
          QuicServerId("mail.google.com", 80));
  EXPECT_EQ("quic_server_info1", *quic_server_info);

  //
  // Verify supports QUIC.
  //
  IPAddress actual_address(127, 0, 0, 1);
  EXPECT_TRUE(http_server_props_manager_->GetSupportsQuic(&actual_address));
}

}  // namespace net
