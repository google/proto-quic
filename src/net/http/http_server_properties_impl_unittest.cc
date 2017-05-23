// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_server_properties_impl.h"

#include <memory>
#include <string>
#include <vector>

#include "base/logging.h"
#include "base/values.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace base {
class ListValue;
}

namespace net {

class HttpServerPropertiesImplPeer {
 public:
  static void AddBrokenAlternativeServiceWithExpirationTime(
      HttpServerPropertiesImpl& impl,
      AlternativeService alternative_service,
      base::TimeTicks when) {
    impl.broken_alternative_services_.insert(
        std::make_pair(alternative_service, when));
    auto it =
        impl.recently_broken_alternative_services_.Get(alternative_service);
    if (it == impl.recently_broken_alternative_services_.end()) {
      impl.recently_broken_alternative_services_.Put(alternative_service, 1);
    } else {
      it->second++;
    }
  }

  static void ExpireBrokenAlternateProtocolMappings(
      HttpServerPropertiesImpl& impl) {
    impl.ExpireBrokenAlternateProtocolMappings();
  }
};

namespace {

const int kMaxSupportsSpdyServerHosts = 500;

class HttpServerPropertiesImplTest : public testing::Test {
 protected:
  bool HasAlternativeService(const url::SchemeHostPort& origin) {
    const AlternativeServiceInfoVector alternative_service_info_vector =
        impl_.GetAlternativeServiceInfos(origin);
    return !alternative_service_info_vector.empty();
  }

  bool SetAlternativeService(const url::SchemeHostPort& origin,
                             const AlternativeService& alternative_service) {
    const base::Time expiration =
        base::Time::Now() + base::TimeDelta::FromDays(1);
    return impl_.SetAlternativeService(origin, alternative_service, expiration);
  }

  HttpServerPropertiesImpl impl_;
};

typedef HttpServerPropertiesImplTest SpdyServerPropertiesTest;

TEST_F(SpdyServerPropertiesTest, SetWithSchemeHostPort) {
  // Check spdy servers are correctly set with SchemeHostPort key.
  url::SchemeHostPort https_www_server("https", "www.google.com", 443);
  url::SchemeHostPort http_photo_server("http", "photos.google.com", 80);
  // Servers with port equal to default port in scheme will drop port components
  // when calling Serialize().
  std::string spdy_server_g = https_www_server.Serialize();
  std::string spdy_server_p = http_photo_server.Serialize();

  url::SchemeHostPort http_google_server("http", "www.google.com", 443);
  url::SchemeHostPort https_photos_server("https", "photos.google.com", 443);
  url::SchemeHostPort valid_google_server((GURL("https://www.google.com")));

  // Initializing https://www.google.com:443 and https://photos.google.com:443
  // as spdy servers.
  std::vector<std::string> spdy_servers1;
  spdy_servers1.push_back(spdy_server_g);  // Will be 0th index.
  spdy_servers1.push_back(spdy_server_p);  // Will be 1st index.
  impl_.SetSpdyServers(&spdy_servers1, true);
  EXPECT_TRUE(impl_.SupportsRequestPriority(http_photo_server));
  EXPECT_TRUE(impl_.SupportsRequestPriority(https_www_server));
  EXPECT_FALSE(impl_.SupportsRequestPriority(http_google_server));
  EXPECT_FALSE(impl_.SupportsRequestPriority(https_photos_server));
  EXPECT_TRUE(impl_.SupportsRequestPriority(valid_google_server));
}

TEST_F(SpdyServerPropertiesTest, Set) {
  url::SchemeHostPort spdy_server_google("https", "www.google.com", 443);
  std::string spdy_server_g = spdy_server_google.Serialize();

  url::SchemeHostPort spdy_server_photos("https", "photos.google.com", 443);
  std::string spdy_server_p = spdy_server_photos.Serialize();

  url::SchemeHostPort spdy_server_docs("https", "docs.google.com", 443);
  std::string spdy_server_d = spdy_server_docs.Serialize();

  url::SchemeHostPort spdy_server_mail("https", "mail.google.com", 443);
  std::string spdy_server_m = spdy_server_mail.Serialize();

  // Check by initializing NULL spdy servers.
  impl_.SetSpdyServers(NULL, true);
  EXPECT_FALSE(impl_.SupportsRequestPriority(spdy_server_google));

  // Check by initializing empty spdy servers.
  std::vector<std::string> spdy_servers;
  impl_.SetSpdyServers(&spdy_servers, true);
  EXPECT_FALSE(impl_.SupportsRequestPriority(spdy_server_google));

  // Check by initializing www.google.com:443 and photos.google.com:443 as spdy
  // servers.
  std::vector<std::string> spdy_servers1;
  spdy_servers1.push_back(spdy_server_g);  // Will be 0th index.
  spdy_servers1.push_back(spdy_server_p);  // Will be 1st index.
  impl_.SetSpdyServers(&spdy_servers1, true);
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_photos));
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_google));

  // Verify spdy_server_g and spdy_server_d are in the list in the same order.
  base::ListValue spdy_server_list;
  impl_.GetSpdyServerList(&spdy_server_list, kMaxSupportsSpdyServerHosts);
  EXPECT_EQ(2U, spdy_server_list.GetSize());
  std::string string_value_g;
  ASSERT_TRUE(spdy_server_list.GetString(0, &string_value_g));  // 0th index.
  ASSERT_EQ(spdy_server_g, string_value_g);
  std::string string_value_p;
  ASSERT_TRUE(spdy_server_list.GetString(1, &string_value_p));  // 1st index.
  ASSERT_EQ(spdy_server_p, string_value_p);

  // Check by initializing mail.google.com:443 and docs.google.com:443 as spdy
  // servers.
  std::vector<std::string> spdy_servers2;
  spdy_servers2.push_back(spdy_server_m);  // Will be 2nd index.
  spdy_servers2.push_back(spdy_server_d);  // Will be 3rd index.
  impl_.SetSpdyServers(&spdy_servers2, true);

  // Verify all the servers are in the list in the same order.
  spdy_server_list.Clear();
  impl_.GetSpdyServerList(&spdy_server_list, kMaxSupportsSpdyServerHosts);
  EXPECT_EQ(4U, spdy_server_list.GetSize());

  ASSERT_TRUE(spdy_server_list.GetString(0, &string_value_g));
  ASSERT_EQ(spdy_server_g, string_value_g);
  ASSERT_TRUE(spdy_server_list.GetString(1, &string_value_p));
  ASSERT_EQ(spdy_server_p, string_value_p);
  std::string string_value_m;
  ASSERT_TRUE(spdy_server_list.GetString(2, &string_value_m));
  ASSERT_EQ(spdy_server_m, string_value_m);
  std::string string_value_d;
  ASSERT_TRUE(spdy_server_list.GetString(3, &string_value_d));
  ASSERT_EQ(spdy_server_d, string_value_d);

  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_docs));
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_mail));
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_photos));
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_google));

  // Verify new data that is being initialized overwrites what is already in the
  // memory and also verify the recency list order.
  //
  // Change supports SPDY value for photos and mails servers and order of
  // initalization shouldn't matter.
  std::vector<std::string> spdy_servers3;
  spdy_servers3.push_back(spdy_server_m);
  spdy_servers3.push_back(spdy_server_p);
  impl_.SetSpdyServers(&spdy_servers3, false);

  // Verify the entries are in the same order.
  ASSERT_TRUE(spdy_server_list.GetString(0, &string_value_g));
  ASSERT_EQ(spdy_server_g, string_value_g);
  ASSERT_TRUE(spdy_server_list.GetString(1, &string_value_p));
  ASSERT_EQ(spdy_server_p, string_value_p);
  ASSERT_TRUE(spdy_server_list.GetString(2, &string_value_m));
  ASSERT_EQ(spdy_server_m, string_value_m);
  ASSERT_TRUE(spdy_server_list.GetString(3, &string_value_d));
  ASSERT_EQ(spdy_server_d, string_value_d);

  // Verify photos and mail servers don't support SPDY and other servers support
  // SPDY.
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_docs));
  EXPECT_FALSE(impl_.SupportsRequestPriority(spdy_server_mail));
  EXPECT_FALSE(impl_.SupportsRequestPriority(spdy_server_photos));
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_google));
}

TEST_F(SpdyServerPropertiesTest, SupportsRequestPriorityTest) {
  url::SchemeHostPort spdy_server_empty("https", std::string(), 443);
  EXPECT_FALSE(impl_.SupportsRequestPriority(spdy_server_empty));

  // Add www.google.com:443 as supporting SPDY.
  url::SchemeHostPort spdy_server_google("https", "www.google.com", 443);
  impl_.SetSupportsSpdy(spdy_server_google, true);
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_google));

  // Add mail.google.com:443 as not supporting SPDY.
  url::SchemeHostPort spdy_server_mail("https", "mail.google.com", 443);
  EXPECT_FALSE(impl_.SupportsRequestPriority(spdy_server_mail));

  // Add docs.google.com:443 as supporting SPDY.
  url::SchemeHostPort spdy_server_docs("https", "docs.google.com", 443);
  impl_.SetSupportsSpdy(spdy_server_docs, true);
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_docs));

  // Add www.youtube.com:443 as supporting QUIC.
  url::SchemeHostPort youtube_server("https", "www.youtube.com", 443);
  const AlternativeService alternative_service1(kProtoQUIC, "www.youtube.com",
                                                443);
  SetAlternativeService(youtube_server, alternative_service1);
  EXPECT_TRUE(impl_.SupportsRequestPriority(youtube_server));

  // Add www.example.com:443 with two alternative services, one supporting QUIC.
  url::SchemeHostPort example_server("https", "www.example.com", 443);
  const AlternativeService alternative_service2(kProtoHTTP2, "", 443);
  SetAlternativeService(example_server, alternative_service2);
  SetAlternativeService(example_server, alternative_service1);
  EXPECT_TRUE(impl_.SupportsRequestPriority(example_server));

  // Verify all the entries are the same after additions.
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_google));
  EXPECT_FALSE(impl_.SupportsRequestPriority(spdy_server_mail));
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_docs));
  EXPECT_TRUE(impl_.SupportsRequestPriority(youtube_server));
  EXPECT_TRUE(impl_.SupportsRequestPriority(example_server));
}

TEST_F(SpdyServerPropertiesTest, Clear) {
  // Add www.google.com:443 and mail.google.com:443 as supporting SPDY.
  url::SchemeHostPort spdy_server_google("https", "www.google.com", 443);
  impl_.SetSupportsSpdy(spdy_server_google, true);
  url::SchemeHostPort spdy_server_mail("https", "mail.google.com", 443);
  impl_.SetSupportsSpdy(spdy_server_mail, true);

  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_google));
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_mail));

  impl_.Clear();
  EXPECT_FALSE(impl_.SupportsRequestPriority(spdy_server_google));
  EXPECT_FALSE(impl_.SupportsRequestPriority(spdy_server_mail));
}

TEST_F(SpdyServerPropertiesTest, GetSpdyServerList) {
  base::ListValue spdy_server_list;

  // Check there are no spdy_servers.
  impl_.GetSpdyServerList(&spdy_server_list, kMaxSupportsSpdyServerHosts);
  EXPECT_EQ(0U, spdy_server_list.GetSize());

  // Check empty server is not added.
  url::SchemeHostPort spdy_server_empty("https", std::string(), 443);
  impl_.SetSupportsSpdy(spdy_server_empty, true);
  impl_.GetSpdyServerList(&spdy_server_list, kMaxSupportsSpdyServerHosts);
  EXPECT_EQ(0U, spdy_server_list.GetSize());

  std::string string_value_g;
  std::string string_value_m;
  url::SchemeHostPort spdy_server_google("https", "www.google.com", 443);
  std::string spdy_server_g = spdy_server_google.Serialize();
  url::SchemeHostPort spdy_server_mail("https", "mail.google.com", 443);
  std::string spdy_server_m = spdy_server_mail.Serialize();

  // Add www.google.com:443 as not supporting SPDY.
  impl_.SetSupportsSpdy(spdy_server_google, false);
  impl_.GetSpdyServerList(&spdy_server_list, kMaxSupportsSpdyServerHosts);
  EXPECT_EQ(0U, spdy_server_list.GetSize());

  // Add www.google.com:443 as supporting SPDY.
  impl_.SetSupportsSpdy(spdy_server_google, true);
  impl_.GetSpdyServerList(&spdy_server_list, kMaxSupportsSpdyServerHosts);
  ASSERT_EQ(1U, spdy_server_list.GetSize());
  ASSERT_TRUE(spdy_server_list.GetString(0, &string_value_g));
  ASSERT_EQ(spdy_server_g, string_value_g);

  // Add mail.google.com:443 as not supporting SPDY.
  impl_.SetSupportsSpdy(spdy_server_mail, false);
  impl_.GetSpdyServerList(&spdy_server_list, kMaxSupportsSpdyServerHosts);
  ASSERT_EQ(1U, spdy_server_list.GetSize());
  ASSERT_TRUE(spdy_server_list.GetString(0, &string_value_g));
  ASSERT_EQ(spdy_server_g, string_value_g);

  // Add mail.google.com:443 as supporting SPDY.
  impl_.SetSupportsSpdy(spdy_server_mail, true);
  impl_.GetSpdyServerList(&spdy_server_list, kMaxSupportsSpdyServerHosts);
  ASSERT_EQ(2U, spdy_server_list.GetSize());

  // Verify www.google.com:443 and mail.google.com:443 are in the list.
  ASSERT_TRUE(spdy_server_list.GetString(0, &string_value_m));
  ASSERT_EQ(spdy_server_m, string_value_m);
  ASSERT_TRUE(spdy_server_list.GetString(1, &string_value_g));
  ASSERT_EQ(spdy_server_g, string_value_g);

  // Request for only one server and verify that we get only one server.
  impl_.GetSpdyServerList(&spdy_server_list, 1);
  ASSERT_EQ(1U, spdy_server_list.GetSize());
  ASSERT_TRUE(spdy_server_list.GetString(0, &string_value_m));
  ASSERT_EQ(spdy_server_m, string_value_m);
}

TEST_F(SpdyServerPropertiesTest, MRUOfGetSpdyServerList) {
  base::ListValue spdy_server_list;

  std::string string_value_g;
  std::string string_value_m;
  url::SchemeHostPort spdy_server_google("https", "www.google.com", 443);
  std::string spdy_server_g = spdy_server_google.Serialize();
  url::SchemeHostPort spdy_server_mail("https", "mail.google.com", 443);
  std::string spdy_server_m = spdy_server_mail.Serialize();

  // Add www.google.com:443 as supporting SPDY.
  impl_.SetSupportsSpdy(spdy_server_google, true);
  impl_.GetSpdyServerList(&spdy_server_list, kMaxSupportsSpdyServerHosts);
  ASSERT_EQ(1U, spdy_server_list.GetSize());
  ASSERT_TRUE(spdy_server_list.GetString(0, &string_value_g));
  ASSERT_EQ(spdy_server_g, string_value_g);

  // Add mail.google.com:443 as supporting SPDY. Verify mail.google.com:443 and
  // www.google.com:443 are in the list.
  impl_.SetSupportsSpdy(spdy_server_mail, true);
  impl_.GetSpdyServerList(&spdy_server_list, kMaxSupportsSpdyServerHosts);
  ASSERT_EQ(2U, spdy_server_list.GetSize());
  ASSERT_TRUE(spdy_server_list.GetString(0, &string_value_m));
  ASSERT_EQ(spdy_server_m, string_value_m);
  ASSERT_TRUE(spdy_server_list.GetString(1, &string_value_g));
  ASSERT_EQ(spdy_server_g, string_value_g);

  // Get www.google.com:443 should reorder SpdyServerHostPortMap. Verify that it
  // is www.google.com:443 is the MRU server.
  EXPECT_TRUE(impl_.SupportsRequestPriority(spdy_server_google));
  impl_.GetSpdyServerList(&spdy_server_list, kMaxSupportsSpdyServerHosts);
  ASSERT_EQ(2U, spdy_server_list.GetSize());
  ASSERT_TRUE(spdy_server_list.GetString(0, &string_value_g));
  ASSERT_EQ(spdy_server_g, string_value_g);
  ASSERT_TRUE(spdy_server_list.GetString(1, &string_value_m));
  ASSERT_EQ(spdy_server_m, string_value_m);
}

typedef HttpServerPropertiesImplTest AlternateProtocolServerPropertiesTest;

TEST_F(AlternateProtocolServerPropertiesTest, Basic) {
  url::SchemeHostPort test_server("http", "foo", 80);
  EXPECT_FALSE(HasAlternativeService(test_server));

  AlternativeService alternative_service(kProtoHTTP2, "foo", 443);
  SetAlternativeService(test_server, alternative_service);
  const AlternativeServiceInfoVector alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service,
            alternative_service_info_vector[0].alternative_service);

  impl_.Clear();
  EXPECT_FALSE(HasAlternativeService(test_server));
}

TEST_F(AlternateProtocolServerPropertiesTest, ExcludeOrigin) {
  AlternativeServiceInfoVector alternative_service_info_vector;
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  // Same hostname, same port, TCP: should be ignored.
  AlternativeServiceInfo alternative_service_info1(kProtoHTTP2, "foo", 443,
                                                   expiration);
  alternative_service_info_vector.push_back(alternative_service_info1);
  // Different hostname: GetAlternativeServiceInfos should return this one.
  AlternativeServiceInfo alternative_service_info2(kProtoHTTP2, "bar", 443,
                                                   expiration);
  alternative_service_info_vector.push_back(alternative_service_info2);
  // Different port: GetAlternativeServiceInfos should return this one too.
  AlternativeServiceInfo alternative_service_info3(kProtoHTTP2, "foo", 80,
                                                   expiration);
  alternative_service_info_vector.push_back(alternative_service_info3);
  // QUIC: GetAlternativeServices should return this one too.
  AlternativeServiceInfo alternative_service_info4(kProtoQUIC, "foo", 443,
                                                   expiration);
  alternative_service_info_vector.push_back(alternative_service_info4);

  url::SchemeHostPort test_server("https", "foo", 443);
  impl_.SetAlternativeServices(test_server, alternative_service_info_vector);

  const AlternativeServiceInfoVector alternative_service_info_vector2 =
      impl_.GetAlternativeServiceInfos(test_server);
  ASSERT_EQ(3u, alternative_service_info_vector2.size());
  EXPECT_EQ(alternative_service_info2, alternative_service_info_vector2[0]);
  EXPECT_EQ(alternative_service_info3, alternative_service_info_vector2[1]);
  EXPECT_EQ(alternative_service_info4, alternative_service_info_vector2[2]);
}

TEST_F(AlternateProtocolServerPropertiesTest, Set) {
  // |test_server1| has an alternative service, which will not be
  // affected by SetAlternativeServiceServers(), because
  // |alternative_service_map| does not have an entry for
  // |test_server1|.
  url::SchemeHostPort test_server1("http", "foo1", 80);
  const AlternativeService alternative_service1(kProtoHTTP2, "bar1", 443);
  const base::Time now = base::Time::Now();
  base::Time expiration1 = now + base::TimeDelta::FromDays(1);
  // 1st entry in the memory.
  impl_.SetAlternativeService(test_server1, alternative_service1, expiration1);

  // |test_server2| has an alternative service, which will be
  // overwritten by SetAlternativeServiceServers(), because
  // |alternative_service_map| has an entry for
  // |test_server2|.
  AlternativeServiceInfoVector alternative_service_info_vector;
  const AlternativeService alternative_service2(kProtoHTTP2, "bar2", 443);
  base::Time expiration2 = now + base::TimeDelta::FromDays(2);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo(alternative_service2, expiration2));
  url::SchemeHostPort test_server2("http", "foo2", 80);
  // 0th entry in the memory.
  impl_.SetAlternativeServices(test_server2, alternative_service_info_vector);

  // Prepare |alternative_service_map| to be loaded by
  // SetAlternativeServiceServers().
  AlternativeServiceMap alternative_service_map(
      AlternativeServiceMap::NO_AUTO_EVICT);
  const AlternativeService alternative_service3(kProtoHTTP2, "bar3", 123);
  base::Time expiration3 = now + base::TimeDelta::FromDays(3);
  const AlternativeServiceInfo alternative_service_info1(alternative_service3,
                                                         expiration3);
  // Simulate updating data for 0th entry with data from Preferences.
  alternative_service_map.Put(
      test_server2,
      AlternativeServiceInfoVector(/*size=*/1, alternative_service_info1));

  url::SchemeHostPort test_server3("http", "foo3", 80);
  const AlternativeService alternative_service4(kProtoHTTP2, "bar4", 1234);
  base::Time expiration4 = now + base::TimeDelta::FromDays(4);
  const AlternativeServiceInfo alternative_service_info2(alternative_service4,
                                                         expiration4);
  // Add an old entry from Preferences, this will be added to end of recency
  // list.
  alternative_service_map.Put(
      test_server3,
      AlternativeServiceInfoVector(/*size=*/1, alternative_service_info2));

  // MRU list will be test_server2, test_server1, test_server3.
  impl_.SetAlternativeServiceServers(&alternative_service_map);

  // Verify alternative_service_map.
  const AlternativeServiceMap& map = impl_.alternative_service_map();
  ASSERT_EQ(3u, map.size());
  AlternativeServiceMap::const_iterator map_it = map.begin();

  EXPECT_TRUE(map_it->first.Equals(test_server2));
  ASSERT_EQ(1u, map_it->second.size());
  EXPECT_EQ(alternative_service3, map_it->second[0].alternative_service);
  EXPECT_EQ(expiration3, map_it->second[0].expiration);
  ++map_it;
  EXPECT_TRUE(map_it->first.Equals(test_server1));
  ASSERT_EQ(1u, map_it->second.size());
  EXPECT_EQ(alternative_service1, map_it->second[0].alternative_service);
  EXPECT_EQ(expiration1, map_it->second[0].expiration);
  ++map_it;
  EXPECT_TRUE(map_it->first.Equals(test_server3));
  ASSERT_EQ(1u, map_it->second.size());
  EXPECT_EQ(alternative_service4, map_it->second[0].alternative_service);
  EXPECT_EQ(expiration4, map_it->second[0].expiration);
}

// Regression test for https://crbug.com/504032:
// SetAlternativeServiceServers() should not crash if there is an empty
// hostname is the mapping.
TEST_F(AlternateProtocolServerPropertiesTest, SetWithEmptyHostname) {
  url::SchemeHostPort server("https", "foo", 443);
  const AlternativeService alternative_service_with_empty_hostname(kProtoHTTP2,
                                                                   "", 1234);
  const AlternativeService alternative_service_with_foo_hostname(kProtoHTTP2,
                                                                 "foo", 1234);
  SetAlternativeService(server, alternative_service_with_empty_hostname);
  impl_.MarkAlternativeServiceBroken(alternative_service_with_foo_hostname);

  AlternativeServiceMap alternative_service_map(
      AlternativeServiceMap::NO_AUTO_EVICT);
  impl_.SetAlternativeServiceServers(&alternative_service_map);

  EXPECT_TRUE(
      impl_.IsAlternativeServiceBroken(alternative_service_with_foo_hostname));
  const AlternativeServiceInfoVector alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(server);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service_with_foo_hostname,
            alternative_service_info_vector[0].alternative_service);
}

// Regression test for https://crbug.com/516486:
// GetAlternativeServiceInfos() should remove |alternative_service_map_|
// elements with empty value.
TEST_F(AlternateProtocolServerPropertiesTest, EmptyVector) {
  url::SchemeHostPort server("https", "foo", 443);
  const AlternativeService alternative_service(kProtoHTTP2, "bar", 443);
  base::Time expiration = base::Time::Now() - base::TimeDelta::FromDays(1);
  const AlternativeServiceInfo alternative_service_info(alternative_service,
                                                        expiration);
  AlternativeServiceMap alternative_service_map(
      AlternativeServiceMap::NO_AUTO_EVICT);
  alternative_service_map.Put(
      server,
      AlternativeServiceInfoVector(/*size=*/1, alternative_service_info));

  // Prepare |alternative_service_map_| with a single key that has a single
  // AlternativeServiceInfo with identical hostname and port.
  impl_.SetAlternativeServiceServers(&alternative_service_map);

  // GetAlternativeServiceInfos() should remove such AlternativeServiceInfo from
  // |alternative_service_map_|, emptying the AlternativeServiceInfoVector
  // corresponding to |server|.
  ASSERT_TRUE(impl_.GetAlternativeServiceInfos(server).empty());

  // GetAlternativeServiceInfos() should remove this key from
  // |alternative_service_map_|, and SetAlternativeServices() should not crash.
  impl_.SetAlternativeServices(
      server,
      AlternativeServiceInfoVector(/*size=*/1, alternative_service_info));

  // There should still be no alternative service assigned to |server|.
  ASSERT_TRUE(impl_.GetAlternativeServiceInfos(server).empty());
}

// Regression test for https://crbug.com/516486 for the canonical host case.
TEST_F(AlternateProtocolServerPropertiesTest, EmptyVectorForCanonical) {
  url::SchemeHostPort server("https", "foo.c.youtube.com", 443);
  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  const AlternativeService alternative_service(kProtoHTTP2, "", 443);
  base::Time expiration = base::Time::Now() - base::TimeDelta::FromDays(1);
  const AlternativeServiceInfo alternative_service_info(alternative_service,
                                                        expiration);
  AlternativeServiceMap alternative_service_map(
      AlternativeServiceMap::NO_AUTO_EVICT);
  alternative_service_map.Put(
      canonical_server,
      AlternativeServiceInfoVector(/*size=*/1, alternative_service_info));

  // Prepare |alternative_service_map_| with a single key that has a single
  // AlternativeServiceInfo with identical hostname and port.
  impl_.SetAlternativeServiceServers(&alternative_service_map);

  // GetAlternativeServiceInfos() should remove such AlternativeServiceInfo from
  // |alternative_service_map_|, emptying the AlternativeServiceInfoVector
  // corresponding to |canonical_server|, even when looking up
  // alternative services for |server|.
  ASSERT_TRUE(impl_.GetAlternativeServiceInfos(server).empty());

  // GetAlternativeServiceInfos() should remove this key from
  // |alternative_service_map_|, and SetAlternativeServices() should not crash.
  impl_.SetAlternativeServices(
      canonical_server,
      AlternativeServiceInfoVector(/*size=*/1, alternative_service_info));

  // There should still be no alternative service assigned to
  // |canonical_server|.
  ASSERT_TRUE(impl_.GetAlternativeServiceInfos(canonical_server).empty());
}

TEST_F(AlternateProtocolServerPropertiesTest, ClearServerWithCanonical) {
  url::SchemeHostPort server("https", "foo.c.youtube.com", 443);
  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  const AlternativeService alternative_service(kProtoQUIC, "", 443);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  const AlternativeServiceInfo alternative_service_info(alternative_service,
                                                        expiration);

  impl_.SetAlternativeServices(
      canonical_server,
      AlternativeServiceInfoVector(/*size=*/1, alternative_service_info));

  // Make sure the canonical service is returned for the other server.
  const AlternativeServiceInfoVector alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(server);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(kProtoQUIC,
            alternative_service_info_vector[0].alternative_service.protocol);
  EXPECT_EQ(443, alternative_service_info_vector[0].alternative_service.port);

  // Now clear the alternatives for the other server and make sure it stays
  // cleared.
  // GetAlternativeServices() should remove this key from
  // |alternative_service_map_|, and SetAlternativeServices() should not crash.
  impl_.SetAlternativeServices(server, AlternativeServiceInfoVector());

  ASSERT_TRUE(impl_.GetAlternativeServiceInfos(server).empty());
}

TEST_F(AlternateProtocolServerPropertiesTest, MRUOfGetAlternativeServiceInfos) {
  url::SchemeHostPort test_server1("http", "foo1", 80);
  const AlternativeService alternative_service1(kProtoHTTP2, "foo1", 443);
  SetAlternativeService(test_server1, alternative_service1);
  url::SchemeHostPort test_server2("http", "foo2", 80);
  const AlternativeService alternative_service2(kProtoHTTP2, "foo2", 1234);
  SetAlternativeService(test_server2, alternative_service2);

  const AlternativeServiceMap& map = impl_.alternative_service_map();
  AlternativeServiceMap::const_iterator it = map.begin();
  EXPECT_TRUE(it->first.Equals(test_server2));
  ASSERT_EQ(1u, it->second.size());
  EXPECT_EQ(alternative_service2, it->second[0].alternative_service);

  const AlternativeServiceInfoVector alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server1);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector[0].alternative_service);

  // GetAlternativeServices should reorder the AlternateProtocol map.
  it = map.begin();
  EXPECT_TRUE(it->first.Equals(test_server1));
  ASSERT_EQ(1u, it->second.size());
  EXPECT_EQ(alternative_service1, it->second[0].alternative_service);
}

TEST_F(AlternateProtocolServerPropertiesTest, SetBroken) {
  url::SchemeHostPort test_server("http", "foo", 80);
  const AlternativeService alternative_service1(kProtoHTTP2, "foo", 443);
  SetAlternativeService(test_server, alternative_service1);
  AlternativeServiceInfoVector alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector[0].alternative_service);
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service1));

  // GetAlternativeServiceInfos should return the broken alternative service.
  impl_.MarkAlternativeServiceBroken(alternative_service1);
  alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector[0].alternative_service);
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service1));

  // SetAlternativeServices should add a broken alternative service to the map.
  AlternativeServiceInfoVector alternative_service_info_vector2;
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  alternative_service_info_vector2.push_back(
      AlternativeServiceInfo(alternative_service1, expiration));
  const AlternativeService alternative_service2(kProtoHTTP2, "foo", 1234);
  alternative_service_info_vector2.push_back(
      AlternativeServiceInfo(alternative_service2, expiration));
  impl_.SetAlternativeServices(test_server, alternative_service_info_vector2);
  alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server);
  ASSERT_EQ(2u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector[0].alternative_service);
  EXPECT_EQ(alternative_service2,
            alternative_service_info_vector[1].alternative_service);
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service1));
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service2));

  // SetAlternativeService should add a broken alternative service to the map.
  SetAlternativeService(test_server, alternative_service1);
  alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service1,
            alternative_service_info_vector[0].alternative_service);
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service1));
}

TEST_F(AlternateProtocolServerPropertiesTest, MaxAge) {
  AlternativeServiceInfoVector alternative_service_info_vector;
  base::Time now = base::Time::Now();
  base::TimeDelta one_day = base::TimeDelta::FromDays(1);

  // First alternative service expired one day ago, should not be returned by
  // GetAlternativeServiceInfos().
  const AlternativeService alternative_service1(kProtoHTTP2, "foo", 443);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo(alternative_service1, now - one_day));

  // Second alterrnative service will expire one day from now, should be
  // returned by GetAlternativeSerices().
  const AlternativeService alternative_service2(kProtoHTTP2, "bar", 1234);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo(alternative_service2, now + one_day));

  url::SchemeHostPort test_server("http", "foo", 80);
  impl_.SetAlternativeServices(test_server, alternative_service_info_vector);

  AlternativeServiceInfoVector alternative_service_info_vector2 =
      impl_.GetAlternativeServiceInfos(test_server);
  ASSERT_EQ(1u, alternative_service_info_vector2.size());
  EXPECT_EQ(alternative_service2,
            alternative_service_info_vector2[0].alternative_service);
}

TEST_F(AlternateProtocolServerPropertiesTest, MaxAgeCanonical) {
  AlternativeServiceInfoVector alternative_service_info_vector;
  base::Time now = base::Time::Now();
  base::TimeDelta one_day = base::TimeDelta::FromDays(1);

  // First alternative service expired one day ago, should not be returned by
  // GetAlternativeServiceInfos().
  const AlternativeService alternative_service1(kProtoHTTP2, "foo", 443);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo(alternative_service1, now - one_day));

  // Second alterrnative service will expire one day from now, should be
  // returned by GetAlternativeSerices().
  const AlternativeService alternative_service2(kProtoHTTP2, "bar", 1234);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo(alternative_service2, now + one_day));

  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  impl_.SetAlternativeServices(canonical_server,
                               alternative_service_info_vector);

  url::SchemeHostPort test_server("https", "foo.c.youtube.com", 443);
  AlternativeServiceInfoVector alternative_service_info_vector2 =
      impl_.GetAlternativeServiceInfos(test_server);
  ASSERT_EQ(1u, alternative_service_info_vector2.size());
  EXPECT_EQ(alternative_service2,
            alternative_service_info_vector2[0].alternative_service);
}

TEST_F(AlternateProtocolServerPropertiesTest, AlternativeServiceWithScheme) {
  AlternativeServiceInfoVector alternative_service_info_vector;
  const AlternativeService alternative_service1(kProtoHTTP2, "foo", 443);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo(alternative_service1, expiration));
  const AlternativeService alternative_service2(kProtoHTTP2, "bar", 1234);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo(alternative_service2, expiration));
  // Set Alt-Svc list for |http_server|.
  url::SchemeHostPort http_server("http", "foo", 80);
  impl_.SetAlternativeServices(http_server, alternative_service_info_vector);

  const net::AlternativeServiceMap& map = impl_.alternative_service_map();
  net::AlternativeServiceMap::const_iterator it = map.begin();
  EXPECT_TRUE(it->first.Equals(http_server));
  ASSERT_EQ(2u, it->second.size());
  EXPECT_EQ(alternative_service1, it->second[0].alternative_service);
  EXPECT_EQ(alternative_service2, it->second[1].alternative_service);

  // Check Alt-Svc list should not be set for |https_server|.
  url::SchemeHostPort https_server("https", "foo", 80);
  EXPECT_EQ(0u, impl_.GetAlternativeServiceInfos(https_server).size());

  // Set Alt-Svc list for |https_server|.
  impl_.SetAlternativeServices(https_server, alternative_service_info_vector);
  EXPECT_EQ(2u, impl_.GetAlternativeServiceInfos(https_server).size());
  EXPECT_EQ(2u, impl_.GetAlternativeServiceInfos(http_server).size());

  // Clear Alt-Svc list for |http_server|.
  impl_.SetAlternativeServices(http_server, AlternativeServiceInfoVector());

  EXPECT_EQ(0u, impl_.GetAlternativeServiceInfos(http_server).size());
  EXPECT_EQ(2u, impl_.GetAlternativeServiceInfos(https_server).size());
}

TEST_F(AlternateProtocolServerPropertiesTest, ClearAlternativeServices) {
  AlternativeServiceInfoVector alternative_service_info_vector;
  const AlternativeService alternative_service1(kProtoHTTP2, "foo", 443);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo(alternative_service1, expiration));
  const AlternativeService alternative_service2(kProtoHTTP2, "bar", 1234);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo(alternative_service2, expiration));
  url::SchemeHostPort test_server("http", "foo", 80);
  impl_.SetAlternativeServices(test_server, alternative_service_info_vector);

  const net::AlternativeServiceMap& map = impl_.alternative_service_map();
  net::AlternativeServiceMap::const_iterator it = map.begin();
  EXPECT_TRUE(it->first.Equals(test_server));
  ASSERT_EQ(2u, it->second.size());
  EXPECT_EQ(alternative_service1, it->second[0].alternative_service);
  EXPECT_EQ(alternative_service2, it->second[1].alternative_service);

  impl_.SetAlternativeServices(test_server, AlternativeServiceInfoVector());
  EXPECT_TRUE(map.empty());
}

// A broken alternative service in the mapping carries meaningful information,
// therefore it should not be ignored by SetAlternativeService().  In
// particular, an alternative service mapped to an origin shadows alternative
// services of canonical hosts.
TEST_F(AlternateProtocolServerPropertiesTest, BrokenShadowsCanonical) {
  url::SchemeHostPort test_server("https", "foo.c.youtube.com", 443);
  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  AlternativeService canonical_alternative_service(kProtoQUIC,
                                                   "bar.c.youtube.com", 1234);
  SetAlternativeService(canonical_server, canonical_alternative_service);
  AlternativeServiceInfoVector alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(canonical_alternative_service,
            alternative_service_info_vector[0].alternative_service);

  const AlternativeService broken_alternative_service(kProtoHTTP2, "foo", 443);
  impl_.MarkAlternativeServiceBroken(broken_alternative_service);
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(broken_alternative_service));

  SetAlternativeService(test_server, broken_alternative_service);
  alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(test_server);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(broken_alternative_service,
            alternative_service_info_vector[0].alternative_service);
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(broken_alternative_service));
}

TEST_F(AlternateProtocolServerPropertiesTest, ClearBroken) {
  url::SchemeHostPort test_server("http", "foo", 80);
  const AlternativeService alternative_service(kProtoHTTP2, "foo", 443);
  SetAlternativeService(test_server, alternative_service);
  impl_.MarkAlternativeServiceBroken(alternative_service);
  ASSERT_TRUE(HasAlternativeService(test_server));
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service));
  // SetAlternativeServices should leave a broken alternative service marked
  // as such.
  impl_.SetAlternativeServices(test_server, AlternativeServiceInfoVector());
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service));
}

TEST_F(AlternateProtocolServerPropertiesTest, MarkRecentlyBroken) {
  url::SchemeHostPort server("http", "foo", 80);
  const AlternativeService alternative_service(kProtoHTTP2, "foo", 443);
  SetAlternativeService(server, alternative_service);

  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(alternative_service));

  impl_.MarkAlternativeServiceRecentlyBroken(alternative_service);
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(alternative_service));

  impl_.ConfirmAlternativeService(alternative_service);
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(alternative_service));
}

TEST_F(AlternateProtocolServerPropertiesTest, Canonical) {
  url::SchemeHostPort test_server("https", "foo.c.youtube.com", 443);
  EXPECT_FALSE(HasAlternativeService(test_server));

  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  EXPECT_FALSE(HasAlternativeService(canonical_server));

  AlternativeServiceInfoVector alternative_service_info_vector;
  const AlternativeService canonical_alternative_service1(
      kProtoQUIC, "bar.c.youtube.com", 1234);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo(canonical_alternative_service1, expiration));
  const AlternativeService canonical_alternative_service2(kProtoHTTP2, "", 443);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo(canonical_alternative_service2, expiration));
  impl_.SetAlternativeServices(canonical_server,
                               alternative_service_info_vector);

  // Since |test_server| does not have an alternative service itself,
  // GetAlternativeServiceInfos should return those of |canonical_server|.
  AlternativeServiceInfoVector alternative_service_info_vector2 =
      impl_.GetAlternativeServiceInfos(test_server);
  ASSERT_EQ(2u, alternative_service_info_vector2.size());
  EXPECT_EQ(canonical_alternative_service1,
            alternative_service_info_vector2[0].alternative_service);

  // Since |canonical_alternative_service2| has an empty host,
  // GetAlternativeServiceInfos should substitute the hostname of its |origin|
  // argument.
  EXPECT_EQ(test_server.host(),
            alternative_service_info_vector2[1].alternative_service.host);
  EXPECT_EQ(canonical_alternative_service2.protocol,
            alternative_service_info_vector2[1].alternative_service.protocol);
  EXPECT_EQ(canonical_alternative_service2.port,
            alternative_service_info_vector2[1].alternative_service.port);

  // Verify the canonical suffix.
  EXPECT_EQ(".c.youtube.com", *impl_.GetCanonicalSuffix(test_server.host()));
  EXPECT_EQ(".c.youtube.com",
            *impl_.GetCanonicalSuffix(canonical_server.host()));
}

TEST_F(AlternateProtocolServerPropertiesTest, ClearCanonical) {
  url::SchemeHostPort test_server("https", "foo.c.youtube.com", 443);
  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  AlternativeService canonical_alternative_service(kProtoQUIC,
                                                   "bar.c.youtube.com", 1234);

  SetAlternativeService(canonical_server, canonical_alternative_service);
  impl_.SetAlternativeServices(canonical_server,
                               AlternativeServiceInfoVector());
  EXPECT_FALSE(HasAlternativeService(test_server));
}

TEST_F(AlternateProtocolServerPropertiesTest, CanonicalBroken) {
  url::SchemeHostPort test_server("https", "foo.c.youtube.com", 443);
  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  AlternativeService canonical_alternative_service(kProtoQUIC,
                                                   "bar.c.youtube.com", 1234);

  SetAlternativeService(canonical_server, canonical_alternative_service);
  impl_.MarkAlternativeServiceBroken(canonical_alternative_service);
  EXPECT_FALSE(HasAlternativeService(test_server));
}

// Adding an alternative service for a new host overrides canonical host.
TEST_F(AlternateProtocolServerPropertiesTest, CanonicalOverride) {
  url::SchemeHostPort foo_server("https", "foo.c.youtube.com", 443);
  url::SchemeHostPort bar_server("https", "bar.c.youtube.com", 443);
  AlternativeService bar_alternative_service(kProtoQUIC, "bar.c.youtube.com",
                                             1234);
  SetAlternativeService(bar_server, bar_alternative_service);
  AlternativeServiceInfoVector alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(foo_server);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(bar_alternative_service,
            alternative_service_info_vector[0].alternative_service);

  url::SchemeHostPort qux_server("https", "qux.c.youtube.com", 443);
  AlternativeService qux_alternative_service(kProtoQUIC, "qux.c.youtube.com",
                                             443);
  SetAlternativeService(qux_server, qux_alternative_service);
  alternative_service_info_vector =
      impl_.GetAlternativeServiceInfos(foo_server);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(qux_alternative_service,
            alternative_service_info_vector[0].alternative_service);
}

TEST_F(AlternateProtocolServerPropertiesTest, ClearWithCanonical) {
  url::SchemeHostPort test_server("https", "foo.c.youtube.com", 443);
  url::SchemeHostPort canonical_server("https", "bar.c.youtube.com", 443);
  AlternativeService canonical_alternative_service(kProtoQUIC,
                                                   "bar.c.youtube.com", 1234);

  SetAlternativeService(canonical_server, canonical_alternative_service);
  impl_.Clear();
  EXPECT_FALSE(HasAlternativeService(test_server));
}

TEST_F(AlternateProtocolServerPropertiesTest,
       ExpireBrokenAlternateProtocolMappings) {
  url::SchemeHostPort server("https", "foo", 443);
  AlternativeService alternative_service(kProtoQUIC, "foo", 443);
  SetAlternativeService(server, alternative_service);
  EXPECT_TRUE(HasAlternativeService(server));
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service));
  EXPECT_FALSE(impl_.WasAlternativeServiceRecentlyBroken(alternative_service));

  base::TimeTicks past =
      base::TimeTicks::Now() - base::TimeDelta::FromSeconds(42);
  HttpServerPropertiesImplPeer::AddBrokenAlternativeServiceWithExpirationTime(
      impl_, alternative_service, past);
  EXPECT_TRUE(impl_.IsAlternativeServiceBroken(alternative_service));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(alternative_service));

  HttpServerPropertiesImplPeer::ExpireBrokenAlternateProtocolMappings(impl_);
  EXPECT_FALSE(impl_.IsAlternativeServiceBroken(alternative_service));
  EXPECT_TRUE(impl_.WasAlternativeServiceRecentlyBroken(alternative_service));
}

// Regression test for https://crbug.com/505413.
TEST_F(AlternateProtocolServerPropertiesTest, RemoveExpiredBrokenAltSvc) {
  url::SchemeHostPort foo_server("https", "foo", 443);
  AlternativeService bar_alternative_service(kProtoQUIC, "bar", 443);
  SetAlternativeService(foo_server, bar_alternative_service);
  EXPECT_TRUE(HasAlternativeService(foo_server));

  url::SchemeHostPort bar_server1("http", "bar", 80);
  AlternativeService nohost_alternative_service(kProtoQUIC, "", 443);
  SetAlternativeService(bar_server1, nohost_alternative_service);
  EXPECT_TRUE(HasAlternativeService(bar_server1));

  url::SchemeHostPort bar_server2("https", "bar", 443);
  AlternativeService baz_alternative_service(kProtoQUIC, "baz", 1234);
  SetAlternativeService(bar_server2, baz_alternative_service);
  EXPECT_TRUE(HasAlternativeService(bar_server2));

  // Mark "bar:443" as broken.
  base::TimeTicks past =
      base::TimeTicks::Now() - base::TimeDelta::FromSeconds(42);
  HttpServerPropertiesImplPeer::AddBrokenAlternativeServiceWithExpirationTime(
      impl_, bar_alternative_service, past);

  // Expire brokenness of "bar:443".
  HttpServerPropertiesImplPeer::ExpireBrokenAlternateProtocolMappings(impl_);

  // "foo:443" should have no alternative service now.
  EXPECT_FALSE(HasAlternativeService(foo_server));
  // "bar:80" should have no alternative service now.
  EXPECT_FALSE(HasAlternativeService(bar_server1));
  // The alternative service of "bar:443" should be unaffected.
  EXPECT_TRUE(HasAlternativeService(bar_server2));

  EXPECT_TRUE(
      impl_.WasAlternativeServiceRecentlyBroken(bar_alternative_service));
  EXPECT_FALSE(
      impl_.WasAlternativeServiceRecentlyBroken(baz_alternative_service));
}

typedef HttpServerPropertiesImplTest SupportsQuicServerPropertiesTest;

TEST_F(SupportsQuicServerPropertiesTest, Set) {
  HostPortPair quic_server_google("www.google.com", 443);

  // Check by initializing empty address.
  IPAddress initial_address;
  impl_.SetSupportsQuic(&initial_address);

  IPAddress address;
  EXPECT_FALSE(impl_.GetSupportsQuic(&address));
  EXPECT_TRUE(address.empty());

  // Check by initializing with a valid address.
  initial_address = IPAddress::IPv4Localhost();
  impl_.SetSupportsQuic(&initial_address);

  EXPECT_TRUE(impl_.GetSupportsQuic(&address));
  EXPECT_EQ(initial_address, address);
}

TEST_F(SupportsQuicServerPropertiesTest, SetSupportsQuic) {
  IPAddress address;
  EXPECT_FALSE(impl_.GetSupportsQuic(&address));
  EXPECT_TRUE(address.empty());

  IPAddress actual_address(127, 0, 0, 1);
  impl_.SetSupportsQuic(true, actual_address);

  EXPECT_TRUE(impl_.GetSupportsQuic(&address));
  EXPECT_EQ(actual_address, address);

  impl_.Clear();

  EXPECT_FALSE(impl_.GetSupportsQuic(&address));
}

typedef HttpServerPropertiesImplTest ServerNetworkStatsServerPropertiesTest;

TEST_F(ServerNetworkStatsServerPropertiesTest, Set) {
  url::SchemeHostPort google_server("https", "www.google.com", 443);

  // Check by initializing empty ServerNetworkStats.
  ServerNetworkStatsMap init_server_network_stats_map(
      ServerNetworkStatsMap::NO_AUTO_EVICT);
  impl_.SetServerNetworkStats(&init_server_network_stats_map);
  const ServerNetworkStats* stats = impl_.GetServerNetworkStats(google_server);
  EXPECT_EQ(NULL, stats);

  // Check by initializing with www.google.com:443.
  ServerNetworkStats stats_google;
  stats_google.srtt = base::TimeDelta::FromMicroseconds(10);
  stats_google.bandwidth_estimate = QuicBandwidth::FromBitsPerSecond(100);
  init_server_network_stats_map.Put(google_server, stats_google);
  impl_.SetServerNetworkStats(&init_server_network_stats_map);

  // Verify data for www.google.com:443.
  ASSERT_EQ(1u, impl_.server_network_stats_map().size());
  EXPECT_EQ(stats_google, *(impl_.GetServerNetworkStats(google_server)));

  // Test recency order and overwriting of data.
  //
  // |docs_server| has a ServerNetworkStats, which will be overwritten by
  // SetServerNetworkStats(), because |server_network_stats_map| has an
  // entry for |docs_server|.
  url::SchemeHostPort docs_server("https", "docs.google.com", 443);
  ServerNetworkStats stats_docs;
  stats_docs.srtt = base::TimeDelta::FromMicroseconds(20);
  stats_docs.bandwidth_estimate = QuicBandwidth::FromBitsPerSecond(200);
  // Recency order will be |docs_server| and |google_server|.
  impl_.SetServerNetworkStats(docs_server, stats_docs);

  // Prepare |server_network_stats_map| to be loaded by
  // SetServerNetworkStats().
  ServerNetworkStatsMap server_network_stats_map(
      ServerNetworkStatsMap::NO_AUTO_EVICT);

  // Change the values for |docs_server|.
  ServerNetworkStats new_stats_docs;
  new_stats_docs.srtt = base::TimeDelta::FromMicroseconds(25);
  new_stats_docs.bandwidth_estimate = QuicBandwidth::FromBitsPerSecond(250);
  server_network_stats_map.Put(docs_server, new_stats_docs);
  // Add data for mail.google.com:443.
  url::SchemeHostPort mail_server("https", "mail.google.com", 443);
  ServerNetworkStats stats_mail;
  stats_mail.srtt = base::TimeDelta::FromMicroseconds(30);
  stats_mail.bandwidth_estimate = QuicBandwidth::FromBitsPerSecond(300);
  server_network_stats_map.Put(mail_server, stats_mail);

  // Recency order will be |docs_server|, |google_server| and |mail_server|.
  impl_.SetServerNetworkStats(&server_network_stats_map);

  const ServerNetworkStatsMap& map = impl_.server_network_stats_map();
  ASSERT_EQ(3u, map.size());
  ServerNetworkStatsMap::const_iterator map_it = map.begin();

  EXPECT_TRUE(map_it->first.Equals(docs_server));
  EXPECT_EQ(new_stats_docs, map_it->second);
  ++map_it;
  EXPECT_TRUE(map_it->first.Equals(google_server));
  EXPECT_EQ(stats_google, map_it->second);
  ++map_it;
  EXPECT_TRUE(map_it->first.Equals(mail_server));
  EXPECT_EQ(stats_mail, map_it->second);
}

TEST_F(ServerNetworkStatsServerPropertiesTest, SetServerNetworkStats) {
  url::SchemeHostPort foo_http_server("http", "foo", 443);
  url::SchemeHostPort foo_https_server("https", "foo", 443);
  EXPECT_EQ(NULL, impl_.GetServerNetworkStats(foo_http_server));
  EXPECT_EQ(NULL, impl_.GetServerNetworkStats(foo_https_server));

  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromMicroseconds(10);
  stats1.bandwidth_estimate = QuicBandwidth::FromBitsPerSecond(100);
  impl_.SetServerNetworkStats(foo_http_server, stats1);

  const ServerNetworkStats* stats2 =
      impl_.GetServerNetworkStats(foo_http_server);
  EXPECT_EQ(10, stats2->srtt.ToInternalValue());
  EXPECT_EQ(100, stats2->bandwidth_estimate.ToBitsPerSecond());
  // Https server should have nothing set for server network stats.
  EXPECT_EQ(NULL, impl_.GetServerNetworkStats(foo_https_server));

  impl_.Clear();
  EXPECT_EQ(NULL, impl_.GetServerNetworkStats(foo_http_server));
  EXPECT_EQ(NULL, impl_.GetServerNetworkStats(foo_https_server));
}

TEST_F(ServerNetworkStatsServerPropertiesTest, ClearServerNetworkStats) {
  ServerNetworkStats stats;
  stats.srtt = base::TimeDelta::FromMicroseconds(10);
  stats.bandwidth_estimate = QuicBandwidth::FromBitsPerSecond(100);
  url::SchemeHostPort foo_https_server("https", "foo", 443);
  impl_.SetServerNetworkStats(foo_https_server, stats);

  impl_.ClearServerNetworkStats(foo_https_server);
  EXPECT_EQ(nullptr, impl_.GetServerNetworkStats(foo_https_server));
}

typedef HttpServerPropertiesImplTest QuicServerInfoServerPropertiesTest;

TEST_F(QuicServerInfoServerPropertiesTest, Set) {
  HostPortPair google_server("www.google.com", 443);
  QuicServerId google_quic_server_id(google_server, PRIVACY_MODE_ENABLED);

  EXPECT_EQ(QuicServerInfoMap::NO_AUTO_EVICT,
            impl_.quic_server_info_map().max_size());
  impl_.SetMaxServerConfigsStoredInProperties(10);
  EXPECT_EQ(10u, impl_.quic_server_info_map().max_size());

  // Check empty map.
  QuicServerInfoMap init_quic_server_info_map(QuicServerInfoMap::NO_AUTO_EVICT);
  impl_.SetQuicServerInfoMap(&init_quic_server_info_map);
  EXPECT_EQ(0u, impl_.quic_server_info_map().size());

  // Check by initializing with www.google.com:443.
  std::string google_server_info("google_quic_server_info");
  init_quic_server_info_map.Put(google_quic_server_id, google_server_info);
  impl_.SetQuicServerInfoMap(&init_quic_server_info_map);

  // Verify data for www.google.com:443.
  EXPECT_EQ(1u, impl_.quic_server_info_map().size());
  EXPECT_EQ(google_server_info,
            *impl_.GetQuicServerInfo(google_quic_server_id));

  // Test recency order and overwriting of data.
  //
  // |docs_server| has a QuicServerInfo, which will be overwritten by
  // SetQuicServerInfoMap(), because |quic_server_info_map| has an
  // entry for |docs_server|.
  HostPortPair docs_server("docs.google.com", 443);
  QuicServerId docs_quic_server_id(docs_server, PRIVACY_MODE_ENABLED);
  std::string docs_server_info("docs_quic_server_info");
  impl_.SetQuicServerInfo(docs_quic_server_id, docs_server_info);

  // Recency order will be |docs_server| and |google_server|.
  const QuicServerInfoMap& map = impl_.quic_server_info_map();
  ASSERT_EQ(2u, map.size());
  QuicServerInfoMap::const_iterator map_it = map.begin();
  EXPECT_EQ(map_it->first, docs_quic_server_id);
  EXPECT_EQ(docs_server_info, map_it->second);
  ++map_it;
  EXPECT_EQ(map_it->first, google_quic_server_id);
  EXPECT_EQ(google_server_info, map_it->second);

  // Prepare |quic_server_info_map| to be loaded by
  // SetQuicServerInfoMap().
  QuicServerInfoMap quic_server_info_map(QuicServerInfoMap::NO_AUTO_EVICT);
  // Change the values for |docs_server|.
  std::string new_docs_server_info("new_docs_quic_server_info");
  quic_server_info_map.Put(docs_quic_server_id, new_docs_server_info);
  // Add data for mail.google.com:443.
  HostPortPair mail_server("mail.google.com", 443);
  QuicServerId mail_quic_server_id(mail_server, PRIVACY_MODE_ENABLED);
  std::string mail_server_info("mail_quic_server_info");
  quic_server_info_map.Put(mail_quic_server_id, mail_server_info);
  impl_.SetQuicServerInfoMap(&quic_server_info_map);

  // Recency order will be |docs_server|, |google_server| and |mail_server|.
  const QuicServerInfoMap& memory_map = impl_.quic_server_info_map();
  ASSERT_EQ(3u, memory_map.size());
  QuicServerInfoMap::const_iterator memory_map_it = memory_map.begin();
  EXPECT_EQ(memory_map_it->first, docs_quic_server_id);
  EXPECT_EQ(new_docs_server_info, memory_map_it->second);
  ++memory_map_it;
  EXPECT_EQ(memory_map_it->first, google_quic_server_id);
  EXPECT_EQ(google_server_info, memory_map_it->second);
  ++memory_map_it;
  EXPECT_EQ(memory_map_it->first, mail_quic_server_id);
  EXPECT_EQ(mail_server_info, memory_map_it->second);

  // Shrink the size of |quic_server_info_map| and verify the MRU order is
  // maintained.
  impl_.SetMaxServerConfigsStoredInProperties(2);
  EXPECT_EQ(2u, impl_.quic_server_info_map().max_size());

  const QuicServerInfoMap& memory_map1 = impl_.quic_server_info_map();
  ASSERT_EQ(2u, memory_map1.size());
  QuicServerInfoMap::const_iterator memory_map1_it = memory_map1.begin();
  EXPECT_EQ(memory_map1_it->first, docs_quic_server_id);
  EXPECT_EQ(new_docs_server_info, memory_map1_it->second);
  ++memory_map1_it;
  EXPECT_EQ(memory_map1_it->first, google_quic_server_id);
  EXPECT_EQ(google_server_info, memory_map1_it->second);
  // |QuicServerInfo| for |mail_quic_server_id| shouldn't be there.
  EXPECT_EQ(nullptr, impl_.GetQuicServerInfo(mail_quic_server_id));
}

TEST_F(QuicServerInfoServerPropertiesTest, SetQuicServerInfo) {
  HostPortPair foo_server("foo", 80);
  QuicServerId quic_server_id(foo_server, PRIVACY_MODE_ENABLED);
  EXPECT_EQ(0u, impl_.quic_server_info_map().size());

  std::string quic_server_info1("quic_server_info1");
  impl_.SetQuicServerInfo(quic_server_id, quic_server_info1);

  EXPECT_EQ(1u, impl_.quic_server_info_map().size());
  EXPECT_EQ(quic_server_info1, *(impl_.GetQuicServerInfo(quic_server_id)));

  impl_.Clear();
  EXPECT_EQ(0u, impl_.quic_server_info_map().size());
  EXPECT_EQ(nullptr, impl_.GetQuicServerInfo(quic_server_id));
}

}  // namespace

}  // namespace net
