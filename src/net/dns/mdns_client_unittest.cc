// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <queue>
#include <vector>

#include "base/location.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/clock.h"
#include "base/time/default_clock.h"
#include "base/timer/mock_timer.h"
#include "net/base/ip_address.h"
#include "net/base/rand_callback.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/mdns_client_impl.h"
#include "net/dns/mock_mdns_socket_factory.h"
#include "net/dns/record_rdata.h"
#include "net/udp/udp_client_socket.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::StrictMock;
using ::testing::NiceMock;
using ::testing::Exactly;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::_;

namespace net {

namespace {

const uint8_t kSamplePacket1[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x00,                                 // TTL (4 bytes) is 1 second;
    0x00, 0x01, 0x00, 0x08,                     // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'p', 'r', 'i', 'n', 't', 'e', 'r', 0xc0,
    0x14,        // Pointer to "._tcp.local"
    0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 49 seconds.
    0x24, 0x75, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x32};

const uint8_t kCorruptedPacketBadQuestion[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x01,  // One question
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Question is corrupted and cannot be read.
    0x99, 'h', 'e', 'l', 'l', 'o', 0x00, 0x00, 0x00, 0x00, 0x00,

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x99,  // RDLENGTH is impossible
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'p', 'r',  // Useless trailing data.
};

const uint8_t kCorruptedPacketUnsalvagable[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x99,  // RDLENGTH is impossible
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'p', 'r',  // Useless trailing data.
};

const uint8_t kCorruptedPacketDoubleRecord[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x06, 'p', 'r', 'i', 'v', 'e', 't', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
    0x00, 0x01,  // TYPE is A.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x04,  // RDLENGTH is 4
    0x05, 0x03, 0xc0, 0x0c,

    // Answer 2 -- Same key
    0x06, 'p', 'r', 'i', 'v', 'e', 't', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
    0x00, 0x01,  // TYPE is A.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x04,  // RDLENGTH is 4
    0x02, 0x03, 0x04, 0x05,
};

const uint8_t kCorruptedPacketSalvagable[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x08,         // RDLENGTH is 8 bytes.
    0x99, 'h', 'e', 'l', 'l', 'o',  // Bad RDATA format.
    0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'p', 'r', 'i', 'n', 't', 'e', 'r', 0xc0,
    0x14,        // Pointer to "._tcp.local"
    0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 49 seconds.
    0x24, 0x75, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x32};

const uint8_t kSamplePacket2[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'z', 'z', 'z', 'z', 'z', 0xc0, 0x0c,

    // Answer 2
    0x08, '_', 'p', 'r', 'i', 'n', 't', 'e', 'r', 0xc0,
    0x14,        // Pointer to "._tcp.local"
    0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,  // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'z', 'z', 'z', 'z', 'z', 0xc0, 0x32};

const uint8_t kSamplePacket3[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x02,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't',  //
    0x04, '_', 't', 'c', 'p',                 //
    0x05, 'l', 'o', 'c', 'a', 'l',            //
    0x00, 0x00, 0x0c,                         // TYPE is PTR.
    0x00, 0x01,                               // CLASS is IN.
    0x00, 0x00,                               // TTL (4 bytes) is 1 second;
    0x00, 0x01,                               //
    0x00, 0x08,                               // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o',            //
    0xc0, 0x0c,                               //

    // Answer 2
    0x08, '_', 'p', 'r', 'i', 'n', 't', 'e', 'r',  //
    0xc0, 0x14,                                    // Pointer to "._tcp.local"
    0x00, 0x0c,                                    // TYPE is PTR.
    0x00, 0x01,                                    // CLASS is IN.
    0x00, 0x00,                     // TTL (4 bytes) is 3 seconds.
    0x00, 0x03,                     //
    0x00, 0x08,                     // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o',  //
    0xc0, 0x32};

const uint8_t kQueryPacketPrivet[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x00, 0x00,  // No flags.
    0x00, 0x01,  // One question.
    0x00, 0x00,  // 0 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Question
    // This part is echoed back from the respective query.
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
};

const uint8_t kQueryPacketPrivetA[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x00, 0x00,  // No flags.
    0x00, 0x01,  // One question.
    0x00, 0x00,  // 0 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Question
    // This part is echoed back from the respective query.
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x01,  // TYPE is A.
    0x00, 0x01,                                 // CLASS is IN.
};

const uint8_t kSamplePacketAdditionalOnly[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x00,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x01,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x08,  // RDLENGTH is 8 bytes.
    0x05, 'h', 'e', 'l', 'l', 'o', 0xc0, 0x0c,
};

const uint8_t kSamplePacketNsec[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x2f,  // TYPE is NSEC.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x01,  // TTL (4 bytes) is 20 hours, 47 minutes, 48 seconds.
    0x24, 0x74, 0x00, 0x06,             // RDLENGTH is 6 bytes.
    0xc0, 0x0c, 0x00, 0x02, 0x00, 0x08  // Only A record present
};

const uint8_t kSamplePacketAPrivet[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 1 RR (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x01,  // TYPE is A.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x00,                                 // TTL (4 bytes) is 5 seconds
    0x00, 0x05, 0x00, 0x04,                     // RDLENGTH is 4 bytes.
    0xc0, 0x0c, 0x00, 0x02,
};

const uint8_t kSamplePacketGoodbye[] = {
    // Header
    0x00, 0x00,  // ID is zeroed out
    0x81, 0x80,  // Standard query response, RA, no error
    0x00, 0x00,  // No questions (for simplicity)
    0x00, 0x01,  // 2 RRs (answers)
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs

    // Answer 1
    0x07, '_', 'p', 'r', 'i', 'v', 'e', 't', 0x04, '_', 't', 'c', 'p', 0x05,
    'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x0c,  // TYPE is PTR.
    0x00, 0x01,                                 // CLASS is IN.
    0x00, 0x00,                                 // TTL (4 bytes) is zero;
    0x00, 0x00, 0x00, 0x08,                     // RDLENGTH is 8 bytes.
    0x05, 'z', 'z', 'z', 'z', 'z', 0xc0, 0x0c,
};

std::string MakeString(const uint8_t* data, unsigned size) {
  return std::string(reinterpret_cast<const char*>(data), size);
}

class PtrRecordCopyContainer {
 public:
  PtrRecordCopyContainer() {}
  ~PtrRecordCopyContainer() {}

  bool is_set() const { return set_; }

  void SaveWithDummyArg(int unused, const RecordParsed* value) {
    Save(value);
  }

  void Save(const RecordParsed* value) {
    set_ = true;
    name_ = value->name();
    ptrdomain_ = value->rdata<PtrRecordRdata>()->ptrdomain();
    ttl_ = value->ttl();
  }

  bool IsRecordWith(const std::string& name, const std::string& ptrdomain) {
    return set_ && name_ == name && ptrdomain_ == ptrdomain;
  }

  const std::string& name() { return name_; }
  const std::string& ptrdomain() { return ptrdomain_; }
  int ttl() { return ttl_; }

 private:
  bool set_;
  std::string name_;
  std::string ptrdomain_;
  int ttl_;
};

class MockClock : public base::DefaultClock {
 public:
  MockClock() : base::DefaultClock() {}
  virtual ~MockClock() {}

  MOCK_METHOD0(Now, base::Time());

 private:
  DISALLOW_COPY_AND_ASSIGN(MockClock);
};

class MockTimer : public base::MockTimer {
 public:
  MockTimer() : base::MockTimer(false, false) {}
  ~MockTimer() {}

  void Start(const tracked_objects::Location& posted_from,
             base::TimeDelta delay,
             const base::Closure& user_task) {
    StartObserver(posted_from, delay, user_task);
    base::MockTimer::Start(posted_from, delay, user_task);
  }

  // StartObserver is invoked when MockTimer::Start() is called.
  // Does not replace the behavior of MockTimer::Start().
  MOCK_METHOD3(StartObserver,
               void(const tracked_objects::Location& posted_from,
                    base::TimeDelta delay,
                    const base::Closure& user_task));

 private:
  DISALLOW_COPY_AND_ASSIGN(MockTimer);
};

}  // namespace

class MDnsTest : public ::testing::Test {
 public:
  void SetUp() override;
  void DeleteTransaction();
  void DeleteBothListeners();
  void RunFor(base::TimeDelta time_period);
  void Stop();

  MOCK_METHOD2(MockableRecordCallback, void(MDnsTransaction::Result result,
                                            const RecordParsed* record));

  MOCK_METHOD2(MockableRecordCallback2, void(MDnsTransaction::Result result,
                                             const RecordParsed* record));

 protected:
  void ExpectPacket(const uint8_t* packet, unsigned size);
  void SimulatePacketReceive(const uint8_t* packet, unsigned size);

  std::unique_ptr<MDnsClientImpl> test_client_;
  IPEndPoint mdns_ipv4_endpoint_;
  StrictMock<MockMDnsSocketFactory> socket_factory_;

  // Transactions and listeners that can be deleted by class methods for
  // reentrancy tests.
  std::unique_ptr<MDnsTransaction> transaction_;
  std::unique_ptr<MDnsListener> listener1_;
  std::unique_ptr<MDnsListener> listener2_;
};

class MockListenerDelegate : public MDnsListener::Delegate {
 public:
  MOCK_METHOD2(OnRecordUpdate,
               void(MDnsListener::UpdateType update,
                    const RecordParsed* records));
  MOCK_METHOD2(OnNsecRecord, void(const std::string&, unsigned));
  MOCK_METHOD0(OnCachePurged, void());
};

void MDnsTest::SetUp() {
  test_client_.reset(new MDnsClientImpl());
  test_client_->StartListening(&socket_factory_);
}

void MDnsTest::SimulatePacketReceive(const uint8_t* packet, unsigned size) {
  socket_factory_.SimulateReceive(packet, size);
}

void MDnsTest::ExpectPacket(const uint8_t* packet, unsigned size) {
  EXPECT_CALL(socket_factory_, OnSendTo(MakeString(packet, size)))
      .Times(2);
}

void MDnsTest::DeleteTransaction() {
  transaction_.reset();
}

void MDnsTest::DeleteBothListeners() {
  listener1_.reset();
  listener2_.reset();
}

void MDnsTest::RunFor(base::TimeDelta time_period) {
  base::CancelableCallback<void()> callback(base::Bind(&MDnsTest::Stop,
                                                       base::Unretained(this)));
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, callback.callback(), time_period);

  base::RunLoop().Run();
  callback.Cancel();
}

void MDnsTest::Stop() {
  base::MessageLoop::current()->QuitWhenIdle();
}

TEST_F(MDnsTest, PassiveListeners) {
  StrictMock<MockListenerDelegate> delegate_privet;
  StrictMock<MockListenerDelegate> delegate_printer;

  PtrRecordCopyContainer record_privet;
  PtrRecordCopyContainer record_printer;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);
  std::unique_ptr<MDnsListener> listener_printer = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_printer._tcp.local", &delegate_printer);

  ASSERT_TRUE(listener_privet->Start());
  ASSERT_TRUE(listener_printer->Start());

  // Send the same packet twice to ensure no records are double-counted.

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(Invoke(
          &record_privet,
          &PtrRecordCopyContainer::SaveWithDummyArg));

  EXPECT_CALL(delegate_printer, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(Invoke(
          &record_printer,
          &PtrRecordCopyContainer::SaveWithDummyArg));


  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));
  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));

  EXPECT_TRUE(record_privet.IsRecordWith("_privet._tcp.local",
                                         "hello._privet._tcp.local"));

  EXPECT_TRUE(record_printer.IsRecordWith("_printer._tcp.local",
                                          "hello._printer._tcp.local"));

  listener_privet.reset();
  listener_printer.reset();
}

TEST_F(MDnsTest, PassiveListenersCacheCleanup) {
  StrictMock<MockListenerDelegate> delegate_privet;

  PtrRecordCopyContainer record_privet;
  PtrRecordCopyContainer record_privet2;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);

  ASSERT_TRUE(listener_privet->Start());

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(Invoke(
          &record_privet,
          &PtrRecordCopyContainer::SaveWithDummyArg));

  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));

  EXPECT_TRUE(record_privet.IsRecordWith("_privet._tcp.local",
                                         "hello._privet._tcp.local"));

  // Expect record is removed when its TTL expires.
  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_REMOVED, _))
      .Times(Exactly(1))
      .WillOnce(DoAll(InvokeWithoutArgs(this, &MDnsTest::Stop),
                      Invoke(&record_privet2,
                             &PtrRecordCopyContainer::SaveWithDummyArg)));

  RunFor(base::TimeDelta::FromSeconds(record_privet.ttl() + 1));

  EXPECT_TRUE(record_privet2.IsRecordWith("_privet._tcp.local",
                                          "hello._privet._tcp.local"));
}

// Ensure that the cleanup task scheduler won't schedule cleanup tasks in the
// past if the system clock creeps past the expiration time while in the
// cleanup dispatcher.
TEST_F(MDnsTest, CacheCleanupWithShortTTL) {
  // Use a nonzero starting time as a base.
  base::Time start_time = base::Time() + base::TimeDelta::FromSeconds(1);

  MockClock* clock = new MockClock;
  MockTimer* timer = new MockTimer;

  test_client_.reset(
      new MDnsClientImpl(base::WrapUnique(clock), base::WrapUnique(timer)));
  test_client_->StartListening(&socket_factory_);

  EXPECT_CALL(*timer, StartObserver(_, _, _)).Times(1);
  EXPECT_CALL(*clock, Now())
      .Times(3)
      .WillRepeatedly(Return(start_time))
      .RetiresOnSaturation();

  // Receive two records with different TTL values.
  // TTL(privet)=1.0s
  // TTL(printer)=3.0s
  StrictMock<MockListenerDelegate> delegate_privet;
  StrictMock<MockListenerDelegate> delegate_printer;

  PtrRecordCopyContainer record_privet;
  PtrRecordCopyContainer record_printer;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);
  std::unique_ptr<MDnsListener> listener_printer = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_printer._tcp.local", &delegate_printer);

  ASSERT_TRUE(listener_privet->Start());
  ASSERT_TRUE(listener_printer->Start());

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1));
  EXPECT_CALL(delegate_printer, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1));

  SimulatePacketReceive(kSamplePacket3, sizeof(kSamplePacket3));

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_REMOVED, _))
      .Times(Exactly(1));

  // Set the clock to 2.0s, which should clean up the 'privet' record, but not
  // the printer. The mock clock will change Now() mid-execution from 2s to 4s.
  // Note: expectations are FILO-ordered -- t+2 seconds is returned, then t+4.
  EXPECT_CALL(*clock, Now())
      .WillOnce(Return(start_time + base::TimeDelta::FromSeconds(4)))
      .RetiresOnSaturation();
  EXPECT_CALL(*clock, Now())
      .WillOnce(Return(start_time + base::TimeDelta::FromSeconds(2)))
      .RetiresOnSaturation();

  EXPECT_CALL(*timer, StartObserver(_, base::TimeDelta(), _));

  timer->Fire();
}

TEST_F(MDnsTest, MalformedPacket) {
  StrictMock<MockListenerDelegate> delegate_printer;

  PtrRecordCopyContainer record_printer;

  std::unique_ptr<MDnsListener> listener_printer = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_printer._tcp.local", &delegate_printer);

  ASSERT_TRUE(listener_printer->Start());

  EXPECT_CALL(delegate_printer, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(Invoke(
          &record_printer,
          &PtrRecordCopyContainer::SaveWithDummyArg));

  // First, send unsalvagable packet to ensure we can deal with it.
  SimulatePacketReceive(kCorruptedPacketUnsalvagable,
                        sizeof(kCorruptedPacketUnsalvagable));

  // Regression test: send a packet where the question cannot be read.
  SimulatePacketReceive(kCorruptedPacketBadQuestion,
                        sizeof(kCorruptedPacketBadQuestion));

  // Then send salvagable packet to ensure we can extract useful records.
  SimulatePacketReceive(kCorruptedPacketSalvagable,
                        sizeof(kCorruptedPacketSalvagable));

  EXPECT_TRUE(record_printer.IsRecordWith("_printer._tcp.local",
                                          "hello._printer._tcp.local"));
}

TEST_F(MDnsTest, TransactionWithEmptyCache) {
  ExpectPacket(kQueryPacketPrivet, sizeof(kQueryPacketPrivet));

  std::unique_ptr<MDnsTransaction> transaction_privet =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
              MDnsTransaction::SINGLE_RESULT,
          base::Bind(&MDnsTest::MockableRecordCallback,
                     base::Unretained(this)));

  ASSERT_TRUE(transaction_privet->Start());

  PtrRecordCopyContainer record_privet;

  EXPECT_CALL(*this, MockableRecordCallback(MDnsTransaction::RESULT_RECORD, _))
      .Times(Exactly(1))
      .WillOnce(Invoke(&record_privet,
                       &PtrRecordCopyContainer::SaveWithDummyArg));

  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));

  EXPECT_TRUE(record_privet.IsRecordWith("_privet._tcp.local",
                                         "hello._privet._tcp.local"));
}

TEST_F(MDnsTest, TransactionCacheOnlyNoResult) {
  std::unique_ptr<MDnsTransaction> transaction_privet =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_privet._tcp.local",
          MDnsTransaction::QUERY_CACHE | MDnsTransaction::SINGLE_RESULT,
          base::Bind(&MDnsTest::MockableRecordCallback,
                     base::Unretained(this)));

  EXPECT_CALL(*this,
              MockableRecordCallback(MDnsTransaction::RESULT_NO_RESULTS, _))
      .Times(Exactly(1));

  ASSERT_TRUE(transaction_privet->Start());
}

TEST_F(MDnsTest, TransactionWithCache) {
  // Listener to force the client to listen
  StrictMock<MockListenerDelegate> delegate_irrelevant;
  std::unique_ptr<MDnsListener> listener_irrelevant =
      test_client_->CreateListener(dns_protocol::kTypeA,
                                   "codereview.chromium.local",
                                   &delegate_irrelevant);

  ASSERT_TRUE(listener_irrelevant->Start());

  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));


  PtrRecordCopyContainer record_privet;

  EXPECT_CALL(*this, MockableRecordCallback(MDnsTransaction::RESULT_RECORD, _))
      .WillOnce(Invoke(&record_privet,
                       &PtrRecordCopyContainer::SaveWithDummyArg));

  std::unique_ptr<MDnsTransaction> transaction_privet =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
              MDnsTransaction::SINGLE_RESULT,
          base::Bind(&MDnsTest::MockableRecordCallback,
                     base::Unretained(this)));

  ASSERT_TRUE(transaction_privet->Start());

  EXPECT_TRUE(record_privet.IsRecordWith("_privet._tcp.local",
                                         "hello._privet._tcp.local"));
}

TEST_F(MDnsTest, AdditionalRecords) {
  StrictMock<MockListenerDelegate> delegate_privet;

  PtrRecordCopyContainer record_privet;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);

  ASSERT_TRUE(listener_privet->Start());

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(Invoke(
          &record_privet,
          &PtrRecordCopyContainer::SaveWithDummyArg));

  SimulatePacketReceive(kSamplePacketAdditionalOnly,
                        sizeof(kSamplePacketAdditionalOnly));

  EXPECT_TRUE(record_privet.IsRecordWith("_privet._tcp.local",
                                         "hello._privet._tcp.local"));
}

TEST_F(MDnsTest, TransactionTimeout) {
  ExpectPacket(kQueryPacketPrivet, sizeof(kQueryPacketPrivet));

  std::unique_ptr<MDnsTransaction> transaction_privet =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
              MDnsTransaction::SINGLE_RESULT,
          base::Bind(&MDnsTest::MockableRecordCallback,
                     base::Unretained(this)));

  ASSERT_TRUE(transaction_privet->Start());

  EXPECT_CALL(*this,
              MockableRecordCallback(MDnsTransaction::RESULT_NO_RESULTS, NULL))
      .Times(Exactly(1))
      .WillOnce(InvokeWithoutArgs(this, &MDnsTest::Stop));

  RunFor(base::TimeDelta::FromSeconds(4));
}

TEST_F(MDnsTest, TransactionMultipleRecords) {
  ExpectPacket(kQueryPacketPrivet, sizeof(kQueryPacketPrivet));

  std::unique_ptr<MDnsTransaction> transaction_privet =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE,
          base::Bind(&MDnsTest::MockableRecordCallback,
                     base::Unretained(this)));

  ASSERT_TRUE(transaction_privet->Start());

  PtrRecordCopyContainer record_privet;
  PtrRecordCopyContainer record_privet2;

  EXPECT_CALL(*this, MockableRecordCallback(MDnsTransaction::RESULT_RECORD, _))
      .Times(Exactly(2))
      .WillOnce(Invoke(&record_privet,
                       &PtrRecordCopyContainer::SaveWithDummyArg))
      .WillOnce(Invoke(&record_privet2,
                       &PtrRecordCopyContainer::SaveWithDummyArg));

  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));
  SimulatePacketReceive(kSamplePacket2, sizeof(kSamplePacket2));

  EXPECT_TRUE(record_privet.IsRecordWith("_privet._tcp.local",
                                         "hello._privet._tcp.local"));

  EXPECT_TRUE(record_privet2.IsRecordWith("_privet._tcp.local",
                                          "zzzzz._privet._tcp.local"));

  EXPECT_CALL(*this, MockableRecordCallback(MDnsTransaction::RESULT_DONE, NULL))
      .WillOnce(InvokeWithoutArgs(this, &MDnsTest::Stop));

  RunFor(base::TimeDelta::FromSeconds(4));
}

TEST_F(MDnsTest, TransactionReentrantDelete) {
  ExpectPacket(kQueryPacketPrivet, sizeof(kQueryPacketPrivet));

  transaction_ = test_client_->CreateTransaction(
      dns_protocol::kTypePTR, "_privet._tcp.local",
      MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
          MDnsTransaction::SINGLE_RESULT,
      base::Bind(&MDnsTest::MockableRecordCallback, base::Unretained(this)));

  ASSERT_TRUE(transaction_->Start());

  EXPECT_CALL(*this, MockableRecordCallback(MDnsTransaction::RESULT_NO_RESULTS,
                                            NULL))
      .Times(Exactly(1))
      .WillOnce(DoAll(InvokeWithoutArgs(this, &MDnsTest::DeleteTransaction),
                      InvokeWithoutArgs(this, &MDnsTest::Stop)));

  RunFor(base::TimeDelta::FromSeconds(4));

  EXPECT_EQ(NULL, transaction_.get());
}

TEST_F(MDnsTest, TransactionReentrantDeleteFromCache) {
  StrictMock<MockListenerDelegate> delegate_irrelevant;
  std::unique_ptr<MDnsListener> listener_irrelevant =
      test_client_->CreateListener(dns_protocol::kTypeA,
                                   "codereview.chromium.local",
                                   &delegate_irrelevant);
  ASSERT_TRUE(listener_irrelevant->Start());

  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));

  transaction_ = test_client_->CreateTransaction(
      dns_protocol::kTypePTR, "_privet._tcp.local",
      MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE,
      base::Bind(&MDnsTest::MockableRecordCallback, base::Unretained(this)));

  EXPECT_CALL(*this, MockableRecordCallback(MDnsTransaction::RESULT_RECORD, _))
      .Times(Exactly(1))
      .WillOnce(InvokeWithoutArgs(this, &MDnsTest::DeleteTransaction));

  ASSERT_TRUE(transaction_->Start());

  EXPECT_EQ(NULL, transaction_.get());
}

TEST_F(MDnsTest, TransactionReentrantCacheLookupStart) {
  ExpectPacket(kQueryPacketPrivet, sizeof(kQueryPacketPrivet));

  std::unique_ptr<MDnsTransaction> transaction1 =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
              MDnsTransaction::SINGLE_RESULT,
          base::Bind(&MDnsTest::MockableRecordCallback,
                     base::Unretained(this)));

  std::unique_ptr<MDnsTransaction> transaction2 =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_printer._tcp.local",
          MDnsTransaction::QUERY_CACHE | MDnsTransaction::SINGLE_RESULT,
          base::Bind(&MDnsTest::MockableRecordCallback2,
                     base::Unretained(this)));

  EXPECT_CALL(*this, MockableRecordCallback2(MDnsTransaction::RESULT_RECORD,
                                             _))
      .Times(Exactly(1));

  EXPECT_CALL(*this, MockableRecordCallback(MDnsTransaction::RESULT_RECORD,
                                            _))
      .Times(Exactly(1))
      .WillOnce(IgnoreResult(InvokeWithoutArgs(transaction2.get(),
                                               &MDnsTransaction::Start)));

  ASSERT_TRUE(transaction1->Start());

  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));
}

TEST_F(MDnsTest, GoodbyePacketNotification) {
  StrictMock<MockListenerDelegate> delegate_privet;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);
  ASSERT_TRUE(listener_privet->Start());

  SimulatePacketReceive(kSamplePacketGoodbye, sizeof(kSamplePacketGoodbye));

  RunFor(base::TimeDelta::FromSeconds(2));
}

TEST_F(MDnsTest, GoodbyePacketRemoval) {
  StrictMock<MockListenerDelegate> delegate_privet;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);
  ASSERT_TRUE(listener_privet->Start());

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1));

  SimulatePacketReceive(kSamplePacket2, sizeof(kSamplePacket2));

  SimulatePacketReceive(kSamplePacketGoodbye, sizeof(kSamplePacketGoodbye));

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_REMOVED, _))
      .Times(Exactly(1));

  RunFor(base::TimeDelta::FromSeconds(2));
}

// In order to reliably test reentrant listener deletes, we create two listeners
// and have each of them delete both, so we're guaranteed to try and deliver a
// callback to at least one deleted listener.

TEST_F(MDnsTest, ListenerReentrantDelete) {
  StrictMock<MockListenerDelegate> delegate_privet;

  listener1_ = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);

  listener2_ = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);

  ASSERT_TRUE(listener1_->Start());

  ASSERT_TRUE(listener2_->Start());

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(InvokeWithoutArgs(this, &MDnsTest::DeleteBothListeners));

  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));

  EXPECT_EQ(NULL, listener1_.get());
  EXPECT_EQ(NULL, listener2_.get());
}

ACTION_P(SaveIPAddress, ip_container) {
  ::testing::StaticAssertTypeEq<const RecordParsed*, arg1_type>();
  ::testing::StaticAssertTypeEq<IPAddress*, ip_container_type>();

  *ip_container = arg1->template rdata<ARecordRdata>()->address();
}

TEST_F(MDnsTest, DoubleRecordDisagreeing) {
  IPAddress address;
  StrictMock<MockListenerDelegate> delegate_privet;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypeA, "privet.local", &delegate_privet);

  ASSERT_TRUE(listener_privet->Start());

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(SaveIPAddress(&address));

  SimulatePacketReceive(kCorruptedPacketDoubleRecord,
                        sizeof(kCorruptedPacketDoubleRecord));

  EXPECT_EQ("2.3.4.5", address.ToString());
}

TEST_F(MDnsTest, NsecWithListener) {
  StrictMock<MockListenerDelegate> delegate_privet;
  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypeA, "_privet._tcp.local", &delegate_privet);

  // Test to make sure nsec callback is NOT called for PTR
  // (which is marked as existing).
  StrictMock<MockListenerDelegate> delegate_privet2;
  std::unique_ptr<MDnsListener> listener_privet2 = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet2);

  ASSERT_TRUE(listener_privet->Start());

  EXPECT_CALL(delegate_privet,
              OnNsecRecord("_privet._tcp.local", dns_protocol::kTypeA));

  SimulatePacketReceive(kSamplePacketNsec,
                        sizeof(kSamplePacketNsec));
}

TEST_F(MDnsTest, NsecWithTransactionFromNetwork) {
  std::unique_ptr<MDnsTransaction> transaction_privet =
      test_client_->CreateTransaction(
          dns_protocol::kTypeA, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
              MDnsTransaction::SINGLE_RESULT,
          base::Bind(&MDnsTest::MockableRecordCallback,
                     base::Unretained(this)));

  EXPECT_CALL(socket_factory_, OnSendTo(_)).Times(2);

  ASSERT_TRUE(transaction_privet->Start());

  EXPECT_CALL(*this,
              MockableRecordCallback(MDnsTransaction::RESULT_NSEC, NULL));

  SimulatePacketReceive(kSamplePacketNsec,
                        sizeof(kSamplePacketNsec));
}

TEST_F(MDnsTest, NsecWithTransactionFromCache) {
  // Force mDNS to listen.
  StrictMock<MockListenerDelegate> delegate_irrelevant;
  std::unique_ptr<MDnsListener> listener_irrelevant =
      test_client_->CreateListener(dns_protocol::kTypePTR, "_privet._tcp.local",
                                   &delegate_irrelevant);
  listener_irrelevant->Start();

  SimulatePacketReceive(kSamplePacketNsec,
                        sizeof(kSamplePacketNsec));

  EXPECT_CALL(*this,
              MockableRecordCallback(MDnsTransaction::RESULT_NSEC, NULL));

  std::unique_ptr<MDnsTransaction> transaction_privet_a =
      test_client_->CreateTransaction(
          dns_protocol::kTypeA, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
              MDnsTransaction::SINGLE_RESULT,
          base::Bind(&MDnsTest::MockableRecordCallback,
                     base::Unretained(this)));

  ASSERT_TRUE(transaction_privet_a->Start());

  // Test that a PTR transaction does NOT consider the same NSEC record to be a
  // valid answer to the query

  std::unique_ptr<MDnsTransaction> transaction_privet_ptr =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
              MDnsTransaction::SINGLE_RESULT,
          base::Bind(&MDnsTest::MockableRecordCallback,
                     base::Unretained(this)));

  EXPECT_CALL(socket_factory_, OnSendTo(_)).Times(2);

  ASSERT_TRUE(transaction_privet_ptr->Start());
}

TEST_F(MDnsTest, NsecConflictRemoval) {
  StrictMock<MockListenerDelegate> delegate_privet;
  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypeA, "_privet._tcp.local", &delegate_privet);

  ASSERT_TRUE(listener_privet->Start());

  const RecordParsed* record1;
  const RecordParsed* record2;

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .WillOnce(SaveArg<1>(&record1));

  SimulatePacketReceive(kSamplePacketAPrivet,
                        sizeof(kSamplePacketAPrivet));

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_REMOVED, _))
      .WillOnce(SaveArg<1>(&record2));

  EXPECT_CALL(delegate_privet,
              OnNsecRecord("_privet._tcp.local", dns_protocol::kTypeA));

  SimulatePacketReceive(kSamplePacketNsec,
                        sizeof(kSamplePacketNsec));

  EXPECT_EQ(record1, record2);
}


TEST_F(MDnsTest, RefreshQuery) {
  StrictMock<MockListenerDelegate> delegate_privet;
  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypeA, "_privet._tcp.local", &delegate_privet);

  listener_privet->SetActiveRefresh(true);
  ASSERT_TRUE(listener_privet->Start());

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _));

  SimulatePacketReceive(kSamplePacketAPrivet,
                        sizeof(kSamplePacketAPrivet));

  // Expecting 2 calls (one for ipv4 and one for ipv6) for each of the 2
  // scheduled refresh queries.
  EXPECT_CALL(socket_factory_, OnSendTo(
      MakeString(kQueryPacketPrivetA, sizeof(kQueryPacketPrivetA))))
      .Times(4);

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_REMOVED, _));

  RunFor(base::TimeDelta::FromSeconds(6));
}

// Note: These tests assume that the ipv4 socket will always be created first.
// This is a simplifying assumption based on the way the code works now.
class SimpleMockSocketFactory : public MDnsSocketFactory {
 public:
  void CreateSockets(
      std::vector<std::unique_ptr<DatagramServerSocket>>* sockets) override {
    sockets->clear();
    sockets->swap(sockets_);
  }

  void PushSocket(std::unique_ptr<DatagramServerSocket> socket) {
    sockets_.push_back(std::move(socket));
  }

 private:
  std::vector<std::unique_ptr<DatagramServerSocket>> sockets_;
};

class MockMDnsConnectionDelegate : public MDnsConnection::Delegate {
 public:
  virtual void HandlePacket(DnsResponse* response, int size) {
    HandlePacketInternal(std::string(response->io_buffer()->data(), size));
  }

  MOCK_METHOD1(HandlePacketInternal, void(std::string packet));

  MOCK_METHOD1(OnConnectionError, void(int error));
};

class MDnsConnectionTest : public ::testing::Test {
 public:
  MDnsConnectionTest() : connection_(&delegate_) {
  }

 protected:
  // Follow successful connection initialization.
  void SetUp() override {
    socket_ipv4_ = new MockMDnsDatagramServerSocket(ADDRESS_FAMILY_IPV4);
    socket_ipv6_ = new MockMDnsDatagramServerSocket(ADDRESS_FAMILY_IPV6);
    factory_.PushSocket(base::WrapUnique(socket_ipv6_));
    factory_.PushSocket(base::WrapUnique(socket_ipv4_));
    sample_packet_ = MakeString(kSamplePacket1, sizeof(kSamplePacket1));
    sample_buffer_ = new StringIOBuffer(sample_packet_);
  }

  bool InitConnection() {
    return connection_.Init(&factory_);
  }

  StrictMock<MockMDnsConnectionDelegate> delegate_;

  MockMDnsDatagramServerSocket* socket_ipv4_;
  MockMDnsDatagramServerSocket* socket_ipv6_;
  SimpleMockSocketFactory factory_;
  MDnsConnection connection_;
  TestCompletionCallback callback_;
  std::string sample_packet_;
  scoped_refptr<IOBuffer> sample_buffer_;
};

TEST_F(MDnsConnectionTest, ReceiveSynchronous) {
  socket_ipv6_->SetResponsePacket(sample_packet_);
  EXPECT_CALL(*socket_ipv4_, RecvFrom(_, _, _, _))
      .WillOnce(Return(ERR_IO_PENDING));
  EXPECT_CALL(*socket_ipv6_, RecvFrom(_, _, _, _))
      .WillOnce(
          Invoke(socket_ipv6_, &MockMDnsDatagramServerSocket::HandleRecvNow))
      .WillOnce(Return(ERR_IO_PENDING));

  EXPECT_CALL(delegate_, HandlePacketInternal(sample_packet_));
  ASSERT_TRUE(InitConnection());
}

TEST_F(MDnsConnectionTest, ReceiveAsynchronous) {
  socket_ipv6_->SetResponsePacket(sample_packet_);

  EXPECT_CALL(*socket_ipv4_, RecvFrom(_, _, _, _))
      .WillOnce(Return(ERR_IO_PENDING));
  EXPECT_CALL(*socket_ipv6_, RecvFrom(_, _, _, _))
      .Times(2)
      .WillOnce(
           Invoke(socket_ipv6_, &MockMDnsDatagramServerSocket::HandleRecvLater))
      .WillOnce(Return(ERR_IO_PENDING));

  ASSERT_TRUE(InitConnection());

  EXPECT_CALL(delegate_, HandlePacketInternal(sample_packet_));

  base::RunLoop().RunUntilIdle();
}

TEST_F(MDnsConnectionTest, Error) {
  CompletionCallback callback;

  EXPECT_CALL(*socket_ipv4_, RecvFrom(_, _, _, _))
      .WillOnce(Return(ERR_IO_PENDING));
  EXPECT_CALL(*socket_ipv6_, RecvFrom(_, _, _, _))
      .WillOnce(DoAll(SaveArg<3>(&callback), Return(ERR_IO_PENDING)));

  ASSERT_TRUE(InitConnection());

  EXPECT_CALL(delegate_, OnConnectionError(ERR_SOCKET_NOT_CONNECTED));
  callback.Run(ERR_SOCKET_NOT_CONNECTED);
  base::RunLoop().RunUntilIdle();
}

class MDnsConnectionSendTest : public MDnsConnectionTest {
 protected:
  void SetUp() override {
    MDnsConnectionTest::SetUp();
    EXPECT_CALL(*socket_ipv4_, RecvFrom(_, _, _, _))
        .WillOnce(Return(ERR_IO_PENDING));
    EXPECT_CALL(*socket_ipv6_, RecvFrom(_, _, _, _))
        .WillOnce(Return(ERR_IO_PENDING));
    EXPECT_TRUE(InitConnection());
  }
};

TEST_F(MDnsConnectionSendTest, Send) {
  EXPECT_CALL(*socket_ipv4_,
              SendToInternal(sample_packet_, "224.0.0.251:5353", _));
  EXPECT_CALL(*socket_ipv6_,
              SendToInternal(sample_packet_, "[ff02::fb]:5353", _));

  connection_.Send(sample_buffer_, sample_packet_.size());
}

TEST_F(MDnsConnectionSendTest, SendError) {
  CompletionCallback callback;

  EXPECT_CALL(*socket_ipv4_,
              SendToInternal(sample_packet_, "224.0.0.251:5353", _));
  EXPECT_CALL(*socket_ipv6_,
              SendToInternal(sample_packet_, "[ff02::fb]:5353", _))
      .WillOnce(DoAll(SaveArg<2>(&callback), Return(ERR_SOCKET_NOT_CONNECTED)));

  connection_.Send(sample_buffer_, sample_packet_.size());
  EXPECT_CALL(delegate_, OnConnectionError(ERR_SOCKET_NOT_CONNECTED));
  base::RunLoop().RunUntilIdle();
}

TEST_F(MDnsConnectionSendTest, SendQueued) {
  // Send data immediately.
  EXPECT_CALL(*socket_ipv4_,
              SendToInternal(sample_packet_, "224.0.0.251:5353", _))
      .Times(2)
      .WillRepeatedly(Return(OK));

  CompletionCallback callback;
  // Delay sending data. Only the first call should be made.
  EXPECT_CALL(*socket_ipv6_,
              SendToInternal(sample_packet_, "[ff02::fb]:5353", _))
      .WillOnce(DoAll(SaveArg<2>(&callback), Return(ERR_IO_PENDING)));

  connection_.Send(sample_buffer_, sample_packet_.size());
  connection_.Send(sample_buffer_, sample_packet_.size());

  // The second IPv6 packed is not sent yet.
  EXPECT_CALL(*socket_ipv4_,
              SendToInternal(sample_packet_, "224.0.0.251:5353", _))
      .Times(0);
  // Expect call for the second IPv6 packed.
  EXPECT_CALL(*socket_ipv6_,
              SendToInternal(sample_packet_, "[ff02::fb]:5353", _))
      .WillOnce(Return(OK));
  callback.Run(OK);
}

}  // namespace net
