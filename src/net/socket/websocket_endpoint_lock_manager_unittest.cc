// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/websocket_endpoint_lock_manager.h"

#include "base/logging.h"
#include "base/macros.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/time/time.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/stream_socket.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsOk;

namespace net {

namespace {

// A StreamSocket implementation with no functionality at all.
// TODO(ricea): If you need to use this in another file, please move it to
// socket_test_util.h.
class FakeStreamSocket : public StreamSocket {
 public:
  FakeStreamSocket() {}

  // StreamSocket implementation
  int Connect(const CompletionCallback& callback) override {
    return ERR_FAILED;
  }

  void Disconnect() override { return; }

  bool IsConnected() const override { return false; }

  bool IsConnectedAndIdle() const override { return false; }

  int GetPeerAddress(IPEndPoint* address) const override { return ERR_FAILED; }

  int GetLocalAddress(IPEndPoint* address) const override { return ERR_FAILED; }

  const NetLogWithSource& NetLog() const override { return net_log_; }

  void SetSubresourceSpeculation() override { return; }
  void SetOmniboxSpeculation() override { return; }

  bool WasEverUsed() const override { return false; }

  bool WasAlpnNegotiated() const override { return false; }

  NextProto GetNegotiatedProtocol() const override { return kProtoUnknown; }

  bool GetSSLInfo(SSLInfo* ssl_info) override { return false; }

  void GetConnectionAttempts(ConnectionAttempts* out) const override {
    out->clear();
  }

  void ClearConnectionAttempts() override {}

  void AddConnectionAttempts(const ConnectionAttempts& attempts) override {}

  int64_t GetTotalReceivedBytes() const override {
    NOTIMPLEMENTED();
    return 0;
  }

  // Socket implementation
  int Read(IOBuffer* buf,
           int buf_len,
           const CompletionCallback& callback) override {
    return ERR_FAILED;
  }

  int Write(IOBuffer* buf,
            int buf_len,
            const CompletionCallback& callback) override {
    return ERR_FAILED;
  }

  int SetReceiveBufferSize(int32_t size) override { return ERR_FAILED; }

  int SetSendBufferSize(int32_t size) override { return ERR_FAILED; }

 private:
  NetLogWithSource net_log_;

  DISALLOW_COPY_AND_ASSIGN(FakeStreamSocket);
};

class FakeWaiter : public WebSocketEndpointLockManager::Waiter {
 public:
  FakeWaiter() : called_(false) {}

  void GotEndpointLock() override {
    CHECK(!called_);
    called_ = true;
  }

  bool called() const { return called_; }

 private:
  bool called_;
};

class BlockingWaiter : public FakeWaiter {
 public:
  void WaitForLock() {
    while (!called()) {
      run_loop_.Run();
    }
  }

  void GotEndpointLock() override {
    FakeWaiter::GotEndpointLock();
    run_loop_.Quit();
  }

 private:
  base::RunLoop run_loop_;
};

class WebSocketEndpointLockManagerTest : public ::testing::Test {
 protected:
  WebSocketEndpointLockManagerTest()
      : instance_(WebSocketEndpointLockManager::GetInstance()) {}
  ~WebSocketEndpointLockManagerTest() override {
    // Permit any pending asynchronous unlock operations to complete.
    RunUntilIdle();
    // If this check fails then subsequent tests may fail.
    CHECK(instance_->IsEmpty());
  }

  WebSocketEndpointLockManager* instance() const { return instance_; }

  IPEndPoint DummyEndpoint() {
    return IPEndPoint(IPAddress::IPv4Localhost(), 80);
  }

  void UnlockDummyEndpoint(int times) {
    for (int i = 0; i < times; ++i) {
      instance()->UnlockEndpoint(DummyEndpoint());
      RunUntilIdle();
    }
  }

  static void RunUntilIdle() { base::RunLoop().RunUntilIdle(); }

  WebSocketEndpointLockManager* const instance_;
  ScopedWebSocketEndpointZeroUnlockDelay zero_unlock_delay_;
};

TEST_F(WebSocketEndpointLockManagerTest, GetInstanceWorks) {
  // All the work is done by the test framework.
}

TEST_F(WebSocketEndpointLockManagerTest, LockEndpointReturnsOkOnce) {
  FakeWaiter waiters[2];
  EXPECT_THAT(instance()->LockEndpoint(DummyEndpoint(), &waiters[0]), IsOk());
  EXPECT_EQ(ERR_IO_PENDING,
            instance()->LockEndpoint(DummyEndpoint(), &waiters[1]));

  UnlockDummyEndpoint(2);
}

TEST_F(WebSocketEndpointLockManagerTest, GotEndpointLockNotCalledOnOk) {
  FakeWaiter waiter;
  EXPECT_THAT(instance()->LockEndpoint(DummyEndpoint(), &waiter), IsOk());
  RunUntilIdle();
  EXPECT_FALSE(waiter.called());

  UnlockDummyEndpoint(1);
}

TEST_F(WebSocketEndpointLockManagerTest, GotEndpointLockNotCalledImmediately) {
  FakeWaiter waiters[2];
  EXPECT_THAT(instance()->LockEndpoint(DummyEndpoint(), &waiters[0]), IsOk());
  EXPECT_EQ(ERR_IO_PENDING,
            instance()->LockEndpoint(DummyEndpoint(), &waiters[1]));
  RunUntilIdle();
  EXPECT_FALSE(waiters[1].called());

  UnlockDummyEndpoint(2);
}

TEST_F(WebSocketEndpointLockManagerTest, GotEndpointLockCalledWhenUnlocked) {
  FakeWaiter waiters[2];
  EXPECT_THAT(instance()->LockEndpoint(DummyEndpoint(), &waiters[0]), IsOk());
  EXPECT_EQ(ERR_IO_PENDING,
            instance()->LockEndpoint(DummyEndpoint(), &waiters[1]));
  instance()->UnlockEndpoint(DummyEndpoint());
  RunUntilIdle();
  EXPECT_TRUE(waiters[1].called());

  UnlockDummyEndpoint(1);
}

TEST_F(WebSocketEndpointLockManagerTest,
       EndpointUnlockedIfWaiterAlreadyDeleted) {
  FakeWaiter first_lock_holder;
  EXPECT_THAT(instance()->LockEndpoint(DummyEndpoint(), &first_lock_holder),
              IsOk());

  {
    FakeWaiter short_lived_waiter;
    EXPECT_EQ(ERR_IO_PENDING,
              instance()->LockEndpoint(DummyEndpoint(), &short_lived_waiter));
  }

  instance()->UnlockEndpoint(DummyEndpoint());
  RunUntilIdle();

  FakeWaiter second_lock_holder;
  EXPECT_THAT(instance()->LockEndpoint(DummyEndpoint(), &second_lock_holder),
              IsOk());

  UnlockDummyEndpoint(1);
}

TEST_F(WebSocketEndpointLockManagerTest, RememberSocketWorks) {
  FakeWaiter waiters[2];
  FakeStreamSocket dummy_socket;
  EXPECT_THAT(instance()->LockEndpoint(DummyEndpoint(), &waiters[0]), IsOk());
  EXPECT_EQ(ERR_IO_PENDING,
            instance()->LockEndpoint(DummyEndpoint(), &waiters[1]));

  instance()->RememberSocket(&dummy_socket, DummyEndpoint());
  instance()->UnlockSocket(&dummy_socket);
  RunUntilIdle();
  EXPECT_TRUE(waiters[1].called());

  UnlockDummyEndpoint(1);
}

// UnlockEndpoint() should cause any sockets remembered for this endpoint
// to be forgotten.
TEST_F(WebSocketEndpointLockManagerTest, SocketAssociationForgottenOnUnlock) {
  FakeWaiter waiter;
  FakeStreamSocket dummy_socket;

  EXPECT_THAT(instance()->LockEndpoint(DummyEndpoint(), &waiter), IsOk());
  instance()->RememberSocket(&dummy_socket, DummyEndpoint());
  instance()->UnlockEndpoint(DummyEndpoint());
  RunUntilIdle();
  EXPECT_TRUE(instance()->IsEmpty());
}

// When ownership of the endpoint is passed to a new waiter, the new waiter can
// call RememberSocket() again.
TEST_F(WebSocketEndpointLockManagerTest, NextWaiterCanCallRememberSocketAgain) {
  FakeWaiter waiters[2];
  FakeStreamSocket dummy_sockets[2];
  EXPECT_THAT(instance()->LockEndpoint(DummyEndpoint(), &waiters[0]), IsOk());
  EXPECT_EQ(ERR_IO_PENDING,
            instance()->LockEndpoint(DummyEndpoint(), &waiters[1]));

  instance()->RememberSocket(&dummy_sockets[0], DummyEndpoint());
  instance()->UnlockEndpoint(DummyEndpoint());
  RunUntilIdle();
  EXPECT_TRUE(waiters[1].called());
  instance()->RememberSocket(&dummy_sockets[1], DummyEndpoint());

  UnlockDummyEndpoint(1);
}

// Calling UnlockSocket() after UnlockEndpoint() does nothing.
TEST_F(WebSocketEndpointLockManagerTest,
       UnlockSocketAfterUnlockEndpointDoesNothing) {
  FakeWaiter waiters[3];
  FakeStreamSocket dummy_socket;

  EXPECT_THAT(instance()->LockEndpoint(DummyEndpoint(), &waiters[0]), IsOk());
  EXPECT_EQ(ERR_IO_PENDING,
            instance()->LockEndpoint(DummyEndpoint(), &waiters[1]));
  EXPECT_EQ(ERR_IO_PENDING,
            instance()->LockEndpoint(DummyEndpoint(), &waiters[2]));
  instance()->RememberSocket(&dummy_socket, DummyEndpoint());
  instance()->UnlockEndpoint(DummyEndpoint());
  instance()->UnlockSocket(&dummy_socket);
  RunUntilIdle();
  EXPECT_TRUE(waiters[1].called());
  EXPECT_FALSE(waiters[2].called());

  UnlockDummyEndpoint(2);
}

// UnlockEndpoint() should always be asynchronous.
TEST_F(WebSocketEndpointLockManagerTest, UnlockEndpointIsAsynchronous) {
  FakeWaiter waiters[2];
  EXPECT_THAT(instance()->LockEndpoint(DummyEndpoint(), &waiters[0]), IsOk());
  EXPECT_EQ(ERR_IO_PENDING,
            instance()->LockEndpoint(DummyEndpoint(), &waiters[1]));

  instance()->UnlockEndpoint(DummyEndpoint());
  EXPECT_FALSE(waiters[1].called());
  RunUntilIdle();
  EXPECT_TRUE(waiters[1].called());

  UnlockDummyEndpoint(1);
}

// UnlockEndpoint() should normally have a delay.
TEST_F(WebSocketEndpointLockManagerTest, UnlockEndpointIsDelayed) {
  using base::TimeTicks;

  // This 1ms delay is too short for very slow environments (usually those
  // running memory checkers). In those environments, the code takes >1ms to run
  // and no delay is needed. Rather than increase the delay and slow down the
  // test everywhere, the test doesn't explicitly verify that a delay has been
  // applied. Instead it just verifies that the whole thing took >=1ms. 1ms is
  // easily enough for normal compiles even on Android, so the fact that there
  // is a delay is still checked on every platform.
  const base::TimeDelta unlock_delay = base::TimeDelta::FromMilliseconds(1);
  instance()->SetUnlockDelayForTesting(unlock_delay);
  FakeWaiter fake_waiter;
  BlockingWaiter blocking_waiter;
  EXPECT_THAT(instance()->LockEndpoint(DummyEndpoint(), &fake_waiter), IsOk());
  EXPECT_EQ(ERR_IO_PENDING,
            instance()->LockEndpoint(DummyEndpoint(), &blocking_waiter));

  TimeTicks before_unlock = TimeTicks::Now();
  instance()->UnlockEndpoint(DummyEndpoint());
  blocking_waiter.WaitForLock();
  TimeTicks after_unlock = TimeTicks::Now();
  EXPECT_GE(after_unlock - before_unlock, unlock_delay);
  instance()->SetUnlockDelayForTesting(base::TimeDelta());
  UnlockDummyEndpoint(1);
}

}  // namespace

}  // namespace net
