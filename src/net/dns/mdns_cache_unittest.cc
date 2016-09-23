// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/mdns_cache.h"

#include <algorithm>
#include <utility>

#include "base/bind.h"
#include "net/dns/dns_response.h"
#include "net/dns/dns_test_util.h"
#include "net/dns/record_parsed.h"
#include "net/dns/record_rdata.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::Return;
using ::testing::StrictMock;

namespace net {

static const uint8_t kTestResponsesDifferentAnswers[] = {
    // Answer 1
    // ghs.l.google.com in DNS format.
    3, 'g', 'h', 's', 1, 'l', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm',
    0x00, 0x00, 0x01,  // TYPE is A.
    0x00, 0x01,        // CLASS is IN.
    0, 0, 0, 53,       // TTL (4 bytes) is 53 seconds.
    0, 4,              // RDLENGTH is 4 bytes.
    74, 125, 95, 121,  // RDATA is the IP: 74.125.95.121

    // Answer 2
    // Pointer to answer 1
    0xc0, 0x00, 0x00, 0x01,  // TYPE is A.
    0x00, 0x01,              // CLASS is IN.
    0, 0, 0, 53,             // TTL (4 bytes) is 53 seconds.
    0, 4,                    // RDLENGTH is 4 bytes.
    74, 125, 95, 122,        // RDATA is the IP: 74.125.95.122
};

static const uint8_t kTestResponsesSameAnswers[] = {
    // Answer 1
    // ghs.l.google.com in DNS format.
    3, 'g', 'h', 's', 1, 'l', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm',
    0x00, 0x00, 0x01,  // TYPE is A.
    0x00, 0x01,        // CLASS is IN.
    0, 0, 0, 53,       // TTL (4 bytes) is 53 seconds.
    0, 4,              // RDLENGTH is 4 bytes.
    74, 125, 95, 121,  // RDATA is the IP: 74.125.95.121

    // Answer 2
    // Pointer to answer 1
    0xc0, 0x00, 0x00, 0x01,  // TYPE is A.
    0x00, 0x01,              // CLASS is IN.
    0, 0, 0, 112,            // TTL (4 bytes) is 112 seconds.
    0, 4,                    // RDLENGTH is 4 bytes.
    74, 125, 95, 121,        // RDATA is the IP: 74.125.95.121
};

static const uint8_t kTestResponseTwoRecords[] = {
    // Answer 1
    // ghs.l.google.com in DNS format. (A)
    3, 'g', 'h', 's', 1, 'l', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm',
    0x00, 0x00, 0x01,  // TYPE is A.
    0x00, 0x01,        // CLASS is IN.
    0, 0, 0, 53,       // TTL (4 bytes) is 53 seconds.
    0, 4,              // RDLENGTH is 4 bytes.
    74, 125, 95, 121,  // RDATA is the IP: 74.125.95.121

    // Answer 2
    // ghs.l.google.com in DNS format. (AAAA)
    3, 'g', 'h', 's', 1, 'l', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm',
    0x00, 0x00, 0x1c,  // TYPE is AAA.
    0x00, 0x01,        // CLASS is IN.
    0, 0, 0, 53,       // TTL (4 bytes) is 53 seconds.
    0, 16,             // RDLENGTH is 16 bytes.
    0x4a, 0x7d, 0x4a, 0x7d, 0x5f, 0x79, 0x5f, 0x79, 0x5f, 0x79, 0x5f, 0x79,
    0x5f, 0x79, 0x5f, 0x79,
};

static const uint8_t kTestResponsesGoodbyePacket[] = {
    // Answer 1
    // ghs.l.google.com in DNS format. (Goodbye packet)
    3, 'g', 'h', 's', 1, 'l', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm',
    0x00, 0x00, 0x01,  // TYPE is A.
    0x00, 0x01,        // CLASS is IN.
    0, 0, 0, 0,        // TTL (4 bytes) is zero.
    0, 4,              // RDLENGTH is 4 bytes.
    74, 125, 95, 121,  // RDATA is the IP: 74.125.95.121

    // Answer 2
    // ghs.l.google.com in DNS format.
    3, 'g', 'h', 's', 1, 'l', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm',
    0x00, 0x00, 0x01,  // TYPE is A.
    0x00, 0x01,        // CLASS is IN.
    0, 0, 0, 53,       // TTL (4 bytes) is 53 seconds.
    0, 4,              // RDLENGTH is 4 bytes.
    74, 125, 95, 121,  // RDATA is the IP: 74.125.95.121
};

class RecordRemovalMock {
 public:
  MOCK_METHOD1(OnRecordRemoved, void(const RecordParsed*));
};

class MDnsCacheTest : public ::testing::Test {
 public:
  MDnsCacheTest()
      : default_time_(base::Time::FromDoubleT(1234.0)) {}
  virtual ~MDnsCacheTest() {}

 protected:
  base::Time default_time_;
  StrictMock<RecordRemovalMock> record_removal_;
  MDnsCache cache_;
};

// Test a single insert, corresponding lookup, and unsuccessful lookup.
TEST_F(MDnsCacheTest, InsertLookupSingle) {
  DnsRecordParser parser(kT1ResponseDatagram, sizeof(kT1ResponseDatagram),
                         sizeof(dns_protocol::Header));
  parser.SkipQuestion();

  std::unique_ptr<const RecordParsed> record1;
  std::unique_ptr<const RecordParsed> record2;
  std::vector<const RecordParsed*> results;

  record1 = RecordParsed::CreateFrom(&parser, default_time_);
  record2 = RecordParsed::CreateFrom(&parser, default_time_);

  EXPECT_EQ(MDnsCache::RecordAdded, cache_.UpdateDnsRecord(std::move(record1)));

  EXPECT_EQ(MDnsCache::RecordAdded, cache_.UpdateDnsRecord(std::move(record2)));

  cache_.FindDnsRecords(ARecordRdata::kType, "ghs.l.google.com", &results,
                        default_time_);

  EXPECT_EQ(1u, results.size());
  EXPECT_EQ(default_time_, results.front()->time_created());

  EXPECT_EQ("ghs.l.google.com", results.front()->name());

  results.clear();
  cache_.FindDnsRecords(PtrRecordRdata::kType, "ghs.l.google.com", &results,
                        default_time_);

  EXPECT_EQ(0u, results.size());
}

// Test that records expire when their ttl has passed.
TEST_F(MDnsCacheTest, Expiration) {
  DnsRecordParser parser(kT1ResponseDatagram, sizeof(kT1ResponseDatagram),
                         sizeof(dns_protocol::Header));
  parser.SkipQuestion();
  std::unique_ptr<const RecordParsed> record1;
  std::unique_ptr<const RecordParsed> record2;

  std::vector<const RecordParsed*> results;
  const RecordParsed* record_to_be_deleted;

  record1 = RecordParsed::CreateFrom(&parser, default_time_);
  base::TimeDelta ttl1 = base::TimeDelta::FromSeconds(record1->ttl());

  record2 = RecordParsed::CreateFrom(&parser, default_time_);
  base::TimeDelta ttl2 = base::TimeDelta::FromSeconds(record2->ttl());
  record_to_be_deleted = record2.get();

  EXPECT_EQ(MDnsCache::RecordAdded, cache_.UpdateDnsRecord(std::move(record1)));
  EXPECT_EQ(MDnsCache::RecordAdded, cache_.UpdateDnsRecord(std::move(record2)));

  cache_.FindDnsRecords(ARecordRdata::kType, "ghs.l.google.com", &results,
                        default_time_);

  EXPECT_EQ(1u, results.size());

  EXPECT_EQ(default_time_ + ttl2, cache_.next_expiration());


  cache_.FindDnsRecords(ARecordRdata::kType, "ghs.l.google.com", &results,
                        default_time_ + ttl2);

  EXPECT_EQ(0u, results.size());

  EXPECT_CALL(record_removal_, OnRecordRemoved(record_to_be_deleted));

  cache_.CleanupRecords(default_time_ + ttl2, base::Bind(
      &RecordRemovalMock::OnRecordRemoved, base::Unretained(&record_removal_)));

  // To make sure that we've indeed removed them from the map, check no funny
  // business happens once they're deleted for good.

  EXPECT_EQ(default_time_ + ttl1, cache_.next_expiration());
  cache_.FindDnsRecords(ARecordRdata::kType, "ghs.l.google.com", &results,
                        default_time_ + ttl2);

  EXPECT_EQ(0u, results.size());
}

// Test that a new record replacing one with the same identity (name/rrtype for
// unique records) causes the cache to output a "record changed" event.
TEST_F(MDnsCacheTest, RecordChange) {
  DnsRecordParser parser(kTestResponsesDifferentAnswers,
                         sizeof(kTestResponsesDifferentAnswers),
                         0);

  std::unique_ptr<const RecordParsed> record1;
  std::unique_ptr<const RecordParsed> record2;
  std::vector<const RecordParsed*> results;

  record1 = RecordParsed::CreateFrom(&parser, default_time_);
  record2 = RecordParsed::CreateFrom(&parser, default_time_);

  EXPECT_EQ(MDnsCache::RecordAdded, cache_.UpdateDnsRecord(std::move(record1)));
  EXPECT_EQ(MDnsCache::RecordChanged,
            cache_.UpdateDnsRecord(std::move(record2)));
}

// Test that a new record replacing an otherwise identical one already in the
// cache causes the cache to output a "no change" event.
TEST_F(MDnsCacheTest, RecordNoChange) {
  DnsRecordParser parser(kTestResponsesSameAnswers,
                         sizeof(kTestResponsesSameAnswers),
                         0);

  std::unique_ptr<const RecordParsed> record1;
  std::unique_ptr<const RecordParsed> record2;
  std::vector<const RecordParsed*> results;

  record1 = RecordParsed::CreateFrom(&parser, default_time_);
  record2 = RecordParsed::CreateFrom(&parser, default_time_ +
                                     base::TimeDelta::FromSeconds(1));

  EXPECT_EQ(MDnsCache::RecordAdded, cache_.UpdateDnsRecord(std::move(record1)));
  EXPECT_EQ(MDnsCache::NoChange, cache_.UpdateDnsRecord(std::move(record2)));
}

// Test that the next expiration time of the cache is updated properly on record
// insertion.
TEST_F(MDnsCacheTest, RecordPreemptExpirationTime) {
  DnsRecordParser parser(kTestResponsesSameAnswers,
                         sizeof(kTestResponsesSameAnswers),
                         0);

  std::unique_ptr<const RecordParsed> record1;
  std::unique_ptr<const RecordParsed> record2;
  std::vector<const RecordParsed*> results;

  record1 = RecordParsed::CreateFrom(&parser, default_time_);
  record2 = RecordParsed::CreateFrom(&parser, default_time_);
  base::TimeDelta ttl1 = base::TimeDelta::FromSeconds(record1->ttl());
  base::TimeDelta ttl2 = base::TimeDelta::FromSeconds(record2->ttl());

  EXPECT_EQ(base::Time(), cache_.next_expiration());
  EXPECT_EQ(MDnsCache::RecordAdded, cache_.UpdateDnsRecord(std::move(record2)));
  EXPECT_EQ(default_time_ + ttl2, cache_.next_expiration());
  EXPECT_EQ(MDnsCache::NoChange, cache_.UpdateDnsRecord(std::move(record1)));
  EXPECT_EQ(default_time_ + ttl1, cache_.next_expiration());
}

// Test that the cache handles mDNS "goodbye" packets correctly, not adding the
// records to the cache if they are not already there, and eventually removing
// records from the cache if they are.
TEST_F(MDnsCacheTest, GoodbyePacket) {
  DnsRecordParser parser(kTestResponsesGoodbyePacket,
                         sizeof(kTestResponsesGoodbyePacket),
                         0);

  std::unique_ptr<const RecordParsed> record_goodbye;
  std::unique_ptr<const RecordParsed> record_hello;
  std::unique_ptr<const RecordParsed> record_goodbye2;
  std::vector<const RecordParsed*> results;

  record_goodbye = RecordParsed::CreateFrom(&parser, default_time_);
  record_hello = RecordParsed::CreateFrom(&parser, default_time_);
  parser = DnsRecordParser(kTestResponsesGoodbyePacket,
                           sizeof(kTestResponsesGoodbyePacket),
                           0);
  record_goodbye2 = RecordParsed::CreateFrom(&parser, default_time_);

  base::TimeDelta ttl = base::TimeDelta::FromSeconds(record_hello->ttl());

  EXPECT_EQ(base::Time(), cache_.next_expiration());
  EXPECT_EQ(MDnsCache::NoChange,
            cache_.UpdateDnsRecord(std::move(record_goodbye)));
  EXPECT_EQ(base::Time(), cache_.next_expiration());
  EXPECT_EQ(MDnsCache::RecordAdded,
            cache_.UpdateDnsRecord(std::move(record_hello)));
  EXPECT_EQ(default_time_ + ttl, cache_.next_expiration());
  EXPECT_EQ(MDnsCache::NoChange,
            cache_.UpdateDnsRecord(std::move(record_goodbye2)));
  EXPECT_EQ(default_time_ + base::TimeDelta::FromSeconds(1),
            cache_.next_expiration());
}

TEST_F(MDnsCacheTest, AnyRRType) {
  DnsRecordParser parser(kTestResponseTwoRecords,
                         sizeof(kTestResponseTwoRecords),
                         0);

  std::unique_ptr<const RecordParsed> record1;
  std::unique_ptr<const RecordParsed> record2;
  std::vector<const RecordParsed*> results;

  record1 = RecordParsed::CreateFrom(&parser, default_time_);
  record2 = RecordParsed::CreateFrom(&parser, default_time_);
  EXPECT_EQ(MDnsCache::RecordAdded, cache_.UpdateDnsRecord(std::move(record1)));
  EXPECT_EQ(MDnsCache::RecordAdded, cache_.UpdateDnsRecord(std::move(record2)));

  cache_.FindDnsRecords(0, "ghs.l.google.com", &results, default_time_);

  EXPECT_EQ(2u, results.size());
  EXPECT_EQ(default_time_, results.front()->time_created());

  EXPECT_EQ("ghs.l.google.com", results[0]->name());
  EXPECT_EQ("ghs.l.google.com", results[1]->name());
  EXPECT_EQ(dns_protocol::kTypeA,
            std::min(results[0]->type(), results[1]->type()));
  EXPECT_EQ(dns_protocol::kTypeAAAA,
            std::max(results[0]->type(), results[1]->type()));
}

TEST_F(MDnsCacheTest, RemoveRecord) {
  DnsRecordParser parser(kT1ResponseDatagram, sizeof(kT1ResponseDatagram),
                         sizeof(dns_protocol::Header));
  parser.SkipQuestion();

  std::unique_ptr<const RecordParsed> record1;
  std::vector<const RecordParsed*> results;

  record1 = RecordParsed::CreateFrom(&parser, default_time_);
  EXPECT_EQ(MDnsCache::RecordAdded, cache_.UpdateDnsRecord(std::move(record1)));

  cache_.FindDnsRecords(dns_protocol::kTypeCNAME, "codereview.chromium.org",
                        &results, default_time_);

  EXPECT_EQ(1u, results.size());

  std::unique_ptr<const RecordParsed> record_out =
      cache_.RemoveRecord(results.front());

  EXPECT_EQ(record_out.get(), results.front());

  cache_.FindDnsRecords(dns_protocol::kTypeCNAME, "codereview.chromium.org",
                        &results, default_time_);

  EXPECT_EQ(0u, results.size());
}

}  // namespace net
