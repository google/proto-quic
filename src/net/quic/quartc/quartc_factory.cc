// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quartc/quartc_factory.h"

#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/quartc/quartc_alarm_factory.h"
#include "net/quic/quartc/quartc_session.h"

namespace {

// Implements the QuicAlarm with QuartcTaskRunnerInterface for the Quartc
//  users other than Chromium. For example, WebRTC will create QuartcAlarm with
// a QuartcTaskRunner implemented by WebRTC.
class QuartcAlarm : public net::QuicAlarm,
                    public net::QuartcTaskRunnerInterface::Task {
 public:
  QuartcAlarm(const net::QuicClock* clock,
              net::QuartcTaskRunnerInterface* task_runner,
              net::QuicArenaScopedPtr<QuicAlarm::Delegate> delegate)
      : net::QuicAlarm(std::move(delegate)),
        clock_(clock),
        task_runner_(task_runner) {}

  ~QuartcAlarm() override {
    // Cancel the scheduled task before getting deleted.
    CancelImpl();
  }

  // QuicAlarm overrides.
  void SetImpl() override {
    DCHECK(deadline().IsInitialized());
    // Cancel it if already set.
    CancelImpl();

    int64_t delay_ms = (deadline() - (clock_->Now())).ToMilliseconds();
    if (delay_ms < 0) {
      delay_ms = 0;
    }

    DCHECK(task_runner_);
    DCHECK(!scheduled_task_);
    scheduled_task_ = task_runner_->Schedule(this, delay_ms);
  }

  void CancelImpl() override {
    if (scheduled_task_) {
      scheduled_task_->Cancel();
      scheduled_task_.reset();
    }
  }

  // QuartcTaskRunner::Task overrides.
  void Run() override {
    // The alarm may have been cancelled.
    if (!deadline().IsInitialized()) {
      return;
    }

    // The alarm may have been re-set to a later time.
    if (clock_->Now() < deadline()) {
      SetImpl();
      return;
    }

    Fire();
  }

 private:
  // Not owned by QuartcAlarm. Owned by the QuartcFactory.
  const net::QuicClock* clock_;
  // Not owned by QuartcAlarm. Owned by the QuartcFactory.
  net::QuartcTaskRunnerInterface* task_runner_;
  // Owned by QuartcAlarm.
  std::unique_ptr<net::QuartcTaskRunnerInterface::ScheduledTask>
      scheduled_task_;
};

}  // namespace

namespace net {

QuartcFactory::QuartcFactory(const QuartcFactoryConfig& factory_config) {
  task_runner_.reset(factory_config.task_runner);
  if (factory_config.create_at_exit_manager) {
    at_exit_manager_.reset(new base::AtExitManager);
  }
}

QuartcFactory::~QuartcFactory() {}

std::unique_ptr<QuartcSessionInterface> QuartcFactory::CreateQuartcSession(
    const QuartcSessionConfig& quartc_session_config) {
  DCHECK(quartc_session_config.packet_transport);

  Perspective perspective = quartc_session_config.is_server
                                ? Perspective::IS_SERVER
                                : Perspective::IS_CLIENT;
  std::unique_ptr<QuicConnection> quic_connection =
      CreateQuicConnection(quartc_session_config, perspective);
  QuicConfig quic_config;
  return std::unique_ptr<QuartcSessionInterface>(
      new QuartcSession(std::move(quic_connection), quic_config,
                        quartc_session_config.unique_remote_server_id,
                        perspective, this /*QuicConnectionHelperInterface*/));
}

std::unique_ptr<QuicConnection> QuartcFactory::CreateQuicConnection(
    const QuartcSessionConfig& quartc_session_config,
    Perspective perspective) {
  // The QuicConnection will take the ownership.
  std::unique_ptr<QuartcPacketWriter> writer(
      new QuartcPacketWriter(quartc_session_config.packet_transport,
                             quartc_session_config.max_packet_size));
  // dummy_id and dummy_address are used because Quartc network layer will not
  // use these two.
  QuicConnectionId dummy_id = 0;
  IPEndPoint dummy_address(IPAddress(0, 0, 0, 0), 0 /*Port*/);
  return std::unique_ptr<QuicConnection>(new QuicConnection(
      dummy_id, QuicSocketAddress(QuicSocketAddressImpl(dummy_address)),
      this, /*QuicConnectionHelperInterface*/
      this /*QuicAlarmFactory*/, writer.release(), true /*own the writer*/,
      perspective, AllSupportedVersions()));
}

QuicAlarm* QuartcFactory::CreateAlarm(QuicAlarm::Delegate* delegate) {
  return new QuartcAlarm(GetClock(), task_runner_.get(),
                         QuicArenaScopedPtr<QuicAlarm::Delegate>(delegate));
}

QuicArenaScopedPtr<QuicAlarm> QuartcFactory::CreateAlarm(
    QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
    QuicConnectionArena* arena) {
  return QuicArenaScopedPtr<QuicAlarm>(
      new QuartcAlarm(GetClock(), task_runner_.get(), std::move(delegate)));
}

const QuicClock* QuartcFactory::GetClock() const {
  return &clock_;
}

QuicRandom* QuartcFactory::GetRandomGenerator() {
  return QuicRandom::GetInstance();
}

QuicBufferAllocator* QuartcFactory::GetBufferAllocator() {
  return &buffer_allocator_;
}

std::unique_ptr<QuartcFactoryInterface> CreateQuartcFactory(
    const QuartcFactoryConfig& factory_config) {
  return std::unique_ptr<QuartcFactoryInterface>(
      new QuartcFactory(factory_config));
}

}  // namespace net
