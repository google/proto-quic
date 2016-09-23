// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/ptr_util.h"
#include "net/quic/core/congestion_control/simulation/alarm_factory.h"
#include "net/quic/core/congestion_control/simulation/link.h"
#include "net/quic/core/congestion_control/simulation/queue.h"
#include "net/quic/core/congestion_control/simulation/simulator.h"
#include "net/quic/core/congestion_control/simulation/switch.h"
#include "net/quic/test_tools/quic_test_utils.h"

#include "net/test/gtest_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace simulation {

// A simple counter that increments its value by 1 every specified period.
class Counter : public Actor {
 public:
  Counter(Simulator* simulator, std::string name, QuicTime::Delta period)
      : Actor(simulator, name), value_(-1), period_(period) {
    Schedule(clock_->Now());
  }
  ~Counter() override {}

  inline int get_value() const { return value_; }

  void Act() override {
    ++value_;
    DVLOG(1) << name_ << " has value " << value_ << " at time "
             << clock_->Now().ToDebuggingValue();
    Schedule(clock_->Now() + period_);
  }

 private:
  int value_;
  QuicTime::Delta period_;
};

// Test that the basic event handling works.
TEST(SimulatorTest, Counters) {
  Simulator simulator;
  Counter fast_counter(&simulator, "fast_counter",
                       QuicTime::Delta::FromSeconds(3));
  Counter slow_counter(&simulator, "slow_counter",
                       QuicTime::Delta::FromSeconds(10));

  simulator.RunUntil(
      [&slow_counter]() { return slow_counter.get_value() >= 10; });

  EXPECT_EQ(10, slow_counter.get_value());
  EXPECT_EQ(10 * 10 / 3, fast_counter.get_value());
}

// A port which counts the number of packets received on it, both total and
// per-destination.
class CounterPort : public UnconstrainedPortInterface {
 public:
  CounterPort() { Reset(); }
  ~CounterPort() override {}

  inline QuicByteCount bytes() const { return bytes_; }
  inline QuicPacketCount packets() const { return packets_; }

  void AcceptPacket(std::unique_ptr<Packet> packet) override {
    bytes_ += packet->size;
    packets_ += 1;

    per_destination_packet_counter_[packet->destination] += 1;
  }

  void Reset() {
    bytes_ = 0;
    packets_ = 0;
    per_destination_packet_counter_.clear();
  }

  QuicPacketCount CountPacketsForDestination(std::string destination) const {
    auto result_it = per_destination_packet_counter_.find(destination);
    if (result_it == per_destination_packet_counter_.cend()) {
      return 0;
    }
    return result_it->second;
  }

 private:
  QuicByteCount bytes_;
  QuicPacketCount packets_;

  std::unordered_map<std::string, QuicPacketCount>
      per_destination_packet_counter_;
};

// Sends the packet to the specified destination at the uplink rate.  Provides a
// CounterPort as an Rx interface.
class LinkSaturator : public Endpoint {
 public:
  LinkSaturator(Simulator* simulator,
                std::string name,
                QuicByteCount packet_size,
                std::string destination)
      : Endpoint(simulator, name),
        packet_size_(packet_size),
        destination_(std::move(destination)),
        bytes_transmitted_(0),
        packets_transmitted_(0) {
    Schedule(clock_->Now());
  }

  void Act() override {
    if (tx_port_->TimeUntilAvailable().IsZero()) {
      auto packet = base::MakeUnique<Packet>();
      packet->source = name_;
      packet->destination = destination_;
      packet->tx_timestamp = clock_->Now();
      packet->size = packet_size_;

      tx_port_->AcceptPacket(std::move(packet));

      bytes_transmitted_ += packet_size_;
      packets_transmitted_ += 1;
    }

    Schedule(clock_->Now() + tx_port_->TimeUntilAvailable());
  }

  UnconstrainedPortInterface* GetRxPort() override {
    return static_cast<UnconstrainedPortInterface*>(&rx_port_);
  }

  void SetTxPort(ConstrainedPortInterface* port) override { tx_port_ = port; }

  CounterPort* counter() { return &rx_port_; }

  inline QuicByteCount bytes_transmitted() const { return bytes_transmitted_; }
  inline QuicPacketCount packets_transmitted() const {
    return packets_transmitted_;
  }

 private:
  QuicByteCount packet_size_;
  std::string destination_;

  ConstrainedPortInterface* tx_port_;
  CounterPort rx_port_;

  QuicByteCount bytes_transmitted_;
  QuicPacketCount packets_transmitted_;
};

// Saturate a symmetric link and verify that the number of packets sent and
// received is correct.
TEST(SimulatorTest, DirectLinkSaturation) {
  Simulator simulator;
  LinkSaturator saturator_a(&simulator, "Saturator A", 1000, "Saturator B");
  LinkSaturator saturator_b(&simulator, "Saturator B", 100, "Saturator A");
  SymmetricLink link(&saturator_a, &saturator_b,
                     QuicBandwidth::FromKBytesPerSecond(1000),
                     QuicTime::Delta::FromMilliseconds(100) +
                         QuicTime::Delta::FromMicroseconds(1));

  const QuicTime start_time = simulator.GetClock()->Now();
  const QuicTime after_first_50_ms =
      start_time + QuicTime::Delta::FromMilliseconds(50);
  simulator.RunUntil([&simulator, after_first_50_ms]() {
    return simulator.GetClock()->Now() >= after_first_50_ms;
  });
  EXPECT_LE(1000u * 50u, saturator_a.bytes_transmitted());
  EXPECT_GE(1000u * 51u, saturator_a.bytes_transmitted());
  EXPECT_LE(1000u * 50u, saturator_b.bytes_transmitted());
  EXPECT_GE(1000u * 51u, saturator_b.bytes_transmitted());
  EXPECT_LE(50u, saturator_a.packets_transmitted());
  EXPECT_GE(51u, saturator_a.packets_transmitted());
  EXPECT_LE(500u, saturator_b.packets_transmitted());
  EXPECT_GE(501u, saturator_b.packets_transmitted());
  EXPECT_EQ(0u, saturator_a.counter()->bytes());
  EXPECT_EQ(0u, saturator_b.counter()->bytes());

  simulator.RunUntil([&saturator_a, &saturator_b]() {
    if (saturator_a.counter()->packets() > 1000 ||
        saturator_b.counter()->packets() > 100) {
      ADD_FAILURE() << "The simulation did not arrive at the expected "
                       "termination contidition. Saturator A counter: "
                    << saturator_a.counter()->packets()
                    << ", saturator B counter: "
                    << saturator_b.counter()->packets();
      return true;
    }

    return saturator_a.counter()->packets() == 1000 &&
           saturator_b.counter()->packets() == 100;
  });
  EXPECT_EQ(201u, saturator_a.packets_transmitted());
  EXPECT_EQ(2001u, saturator_b.packets_transmitted());
  EXPECT_EQ(201u * 1000, saturator_a.bytes_transmitted());
  EXPECT_EQ(2001u * 100, saturator_b.bytes_transmitted());

  EXPECT_EQ(1000u,
            saturator_a.counter()->CountPacketsForDestination("Saturator A"));
  EXPECT_EQ(100u,
            saturator_b.counter()->CountPacketsForDestination("Saturator B"));
  EXPECT_EQ(0u,
            saturator_a.counter()->CountPacketsForDestination("Saturator B"));
  EXPECT_EQ(0u,
            saturator_b.counter()->CountPacketsForDestination("Saturator A"));

  const QuicTime end_time = simulator.GetClock()->Now();
  const QuicBandwidth observed_bandwidth = QuicBandwidth::FromBytesAndTimeDelta(
      saturator_a.bytes_transmitted(), end_time - start_time);
  test::ExpectApproxEq(link.bandwidth(), observed_bandwidth, 0.01);
}

// Accepts packets and stores them internally.
class PacketAcceptor : public ConstrainedPortInterface {
 public:
  void AcceptPacket(std::unique_ptr<Packet> packet) override {
    packets_.emplace_back(std::move(packet));
  }

  QuicTime::Delta TimeUntilAvailable() override {
    return QuicTime::Delta::Zero();
  }

  std::vector<std::unique_ptr<Packet>>* packets() { return &packets_; }

 private:
  std::vector<std::unique_ptr<Packet>> packets_;
};

// Ensure the queue behaves correctly with accepting packets.
TEST(SimulatorTest, Queue) {
  Simulator simulator;
  Queue queue(&simulator, "Queue", 1000);
  PacketAcceptor acceptor;
  queue.set_tx_port(&acceptor);

  EXPECT_EQ(0u, queue.bytes_queued());
  EXPECT_EQ(0u, queue.packets_queued());
  EXPECT_EQ(0u, acceptor.packets()->size());

  auto first_packet = base::MakeUnique<Packet>();
  first_packet->size = 600;
  queue.AcceptPacket(std::move(first_packet));
  EXPECT_EQ(600u, queue.bytes_queued());
  EXPECT_EQ(1u, queue.packets_queued());
  EXPECT_EQ(0u, acceptor.packets()->size());

  // The second packet does not fit and is dropped.
  auto second_packet = base::MakeUnique<Packet>();
  second_packet->size = 500;
  queue.AcceptPacket(std::move(second_packet));
  EXPECT_EQ(600u, queue.bytes_queued());
  EXPECT_EQ(1u, queue.packets_queued());
  EXPECT_EQ(0u, acceptor.packets()->size());

  auto third_packet = base::MakeUnique<Packet>();
  third_packet->size = 400;
  queue.AcceptPacket(std::move(third_packet));
  EXPECT_EQ(1000u, queue.bytes_queued());
  EXPECT_EQ(2u, queue.packets_queued());
  EXPECT_EQ(0u, acceptor.packets()->size());

  // Run until there is nothing scheduled, so that the queue can deplete.
  simulator.RunUntil([]() { return false; });
  EXPECT_EQ(0u, queue.bytes_queued());
  EXPECT_EQ(0u, queue.packets_queued());
  ASSERT_EQ(2u, acceptor.packets()->size());
  EXPECT_EQ(600u, acceptor.packets()->at(0)->size);
  EXPECT_EQ(400u, acceptor.packets()->at(1)->size);
}

// Simulate a situation where the bottleneck link is 10 times slower than the
// uplink, and they are separated by a queue.
TEST(SimulatorTest, QueueBottleneck) {
  const QuicBandwidth local_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(1000);
  const QuicBandwidth bottleneck_bandwidth = 0.1f * local_bandwidth;
  const QuicTime::Delta local_propagation_delay =
      QuicTime::Delta::FromMilliseconds(1);
  const QuicTime::Delta bottleneck_propagation_delay =
      QuicTime::Delta::FromMilliseconds(20);
  const QuicByteCount bdp =
      bottleneck_bandwidth *
      (local_propagation_delay + bottleneck_propagation_delay);

  Simulator simulator;
  LinkSaturator saturator(&simulator, "Saturator", 1000, "Counter");
  ASSERT_GE(bdp, 1000u);
  Queue queue(&simulator, "Queue", bdp);
  CounterPort counter;

  OneWayLink local_link(&simulator, "Local link", &queue, local_bandwidth,
                        local_propagation_delay);
  OneWayLink bottleneck_link(&simulator, "Bottleneck link", &counter,
                             bottleneck_bandwidth,
                             bottleneck_propagation_delay);
  saturator.SetTxPort(&local_link);
  queue.set_tx_port(&bottleneck_link);

  const QuicPacketCount packets_received = 1000;
  simulator.RunUntil([&counter, packets_received]() {
    return counter.packets() == packets_received;
  });
  const double loss_ratio =
      1 -
      static_cast<double>(packets_received) / saturator.packets_transmitted();
  EXPECT_NEAR(loss_ratio, 0.9, 0.001);
}

// Verify that the queue of exactly one packet allows the transmission to
// actually go through.
TEST(SimulatorTest, OnePacketQueue) {
  const QuicBandwidth local_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(1000);
  const QuicBandwidth bottleneck_bandwidth = 0.1f * local_bandwidth;
  const QuicTime::Delta local_propagation_delay =
      QuicTime::Delta::FromMilliseconds(1);
  const QuicTime::Delta bottleneck_propagation_delay =
      QuicTime::Delta::FromMilliseconds(20);

  Simulator simulator;
  LinkSaturator saturator(&simulator, "Saturator", 1000, "Counter");
  Queue queue(&simulator, "Queue", 1000);
  CounterPort counter;

  OneWayLink local_link(&simulator, "Local link", &queue, local_bandwidth,
                        local_propagation_delay);
  OneWayLink bottleneck_link(&simulator, "Bottleneck link", &counter,
                             bottleneck_bandwidth,
                             bottleneck_propagation_delay);
  saturator.SetTxPort(&local_link);
  queue.set_tx_port(&bottleneck_link);

  const QuicPacketCount packets_received = 10;
  // The deadline here is to prevent this tests from looping infinitely in case
  // the packets never reach the receiver.
  const QuicTime deadline =
      simulator.GetClock()->Now() + QuicTime::Delta::FromSeconds(10);
  simulator.RunUntil([&simulator, &counter, packets_received, deadline]() {
    return counter.packets() == packets_received ||
           simulator.GetClock()->Now() > deadline;
  });
  ASSERT_EQ(packets_received, counter.packets());
}

// Simulate a network where three endpoints are connected to a switch and they
// are sending traffic in circle (1 -> 2, 2 -> 3, 3 -> 1).
TEST(SimulatorTest, SwitchedNetwork) {
  const QuicBandwidth bandwidth = QuicBandwidth::FromBytesPerSecond(10000);
  const QuicTime::Delta base_propagation_delay =
      QuicTime::Delta::FromMilliseconds(50);

  Simulator simulator;
  LinkSaturator saturator1(&simulator, "Saturator 1", 1000, "Saturator 2");
  LinkSaturator saturator2(&simulator, "Saturator 2", 1000, "Saturator 3");
  LinkSaturator saturator3(&simulator, "Saturator 3", 1000, "Saturator 1");
  Switch network_switch(&simulator, "Switch", 8,
                        bandwidth * base_propagation_delay * 10);

  // For determinicity, make it so that the first packet will arrive from
  // Saturator 1, then from Saturator 2, and then from Saturator 3.
  SymmetricLink link1(&saturator1, network_switch.port(1), bandwidth,
                      base_propagation_delay);
  SymmetricLink link2(&saturator2, network_switch.port(2), bandwidth,
                      base_propagation_delay * 2);
  SymmetricLink link3(&saturator3, network_switch.port(3), bandwidth,
                      base_propagation_delay * 3);

  const QuicTime start_time = simulator.GetClock()->Now();
  const QuicPacketCount bytes_received = 64 * 1000;
  simulator.RunUntil([&saturator1, bytes_received]() {
    return saturator1.counter()->bytes() >= bytes_received;
  });
  const QuicTime end_time = simulator.GetClock()->Now();

  const QuicBandwidth observed_bandwidth = QuicBandwidth::FromBytesAndTimeDelta(
      bytes_received, end_time - start_time);
  const double bandwidth_ratio =
      static_cast<double>(observed_bandwidth.ToBitsPerSecond()) /
      bandwidth.ToBitsPerSecond();
  EXPECT_NEAR(1, bandwidth_ratio, 0.1);

  const double normalized_received_packets_for_saturator_2 =
      static_cast<double>(saturator2.counter()->packets()) /
      saturator1.counter()->packets();
  const double normalized_received_packets_for_saturator_3 =
      static_cast<double>(saturator3.counter()->packets()) /
      saturator1.counter()->packets();
  EXPECT_NEAR(1, normalized_received_packets_for_saturator_2, 0.1);
  EXPECT_NEAR(1, normalized_received_packets_for_saturator_3, 0.1);

  // Since Saturator 1 has its packet arrive first into the switch, switch will
  // always know how to route traffic to it.
  EXPECT_EQ(0u,
            saturator2.counter()->CountPacketsForDestination("Saturator 1"));
  EXPECT_EQ(0u,
            saturator3.counter()->CountPacketsForDestination("Saturator 1"));

  // Packets from the other saturators will be broadcast at least once.
  EXPECT_EQ(1u,
            saturator1.counter()->CountPacketsForDestination("Saturator 2"));
  EXPECT_EQ(1u,
            saturator3.counter()->CountPacketsForDestination("Saturator 2"));
  EXPECT_EQ(1u,
            saturator1.counter()->CountPacketsForDestination("Saturator 3"));
  EXPECT_EQ(1u,
            saturator2.counter()->CountPacketsForDestination("Saturator 3"));
}

// Toggle an alarm on and off at the specified interval.  Assumes that alarm is
// initially set and unsets it almost immediately after the object is
// instantiated.
class AlarmToggler : public Actor {
 public:
  AlarmToggler(Simulator* simulator,
               std::string name,
               QuicAlarm* alarm,
               QuicTime::Delta interval)
      : Actor(simulator, name),
        alarm_(alarm),
        interval_(interval),
        deadline_(alarm->deadline()),
        times_set_(0),
        times_cancelled_(0) {
    EXPECT_TRUE(alarm->IsSet());
    EXPECT_GE(alarm->deadline(), clock_->Now());
    Schedule(clock_->Now());
  }

  void Act() override {
    if (deadline_ <= clock_->Now()) {
      return;
    }

    if (alarm_->IsSet()) {
      alarm_->Cancel();
      times_cancelled_++;
    } else {
      alarm_->Set(deadline_);
      times_set_++;
    }

    Schedule(clock_->Now() + interval_);
  }

  inline int times_set() { return times_set_; }
  inline int times_cancelled() { return times_cancelled_; }

 private:
  QuicAlarm* alarm_;
  QuicTime::Delta interval_;
  QuicTime deadline_;

  // Counts the number of times the alarm was set.
  int times_set_;
  // Counts the number of times the alarm was cancelled.
  int times_cancelled_;
};

// Counts the number of times an alarm has fired.
class CounterDelegate : public QuicAlarm::Delegate {
 public:
  explicit CounterDelegate(size_t* counter) : counter_(counter) {}

  void OnAlarm() override { *counter_ += 1; }

 private:
  size_t* counter_;
};

// Verifies that the alarms work correctly, even when they are repeatedly
// toggled.
TEST(SimulatorTest, Alarms) {
  Simulator simulator;
  QuicAlarmFactory* alarm_factory = simulator.GetAlarmFactory();

  size_t fast_alarm_counter = 0;
  size_t slow_alarm_counter = 0;
  std::unique_ptr<QuicAlarm> alarm_fast(
      alarm_factory->CreateAlarm(new CounterDelegate(&fast_alarm_counter)));
  std::unique_ptr<QuicAlarm> alarm_slow(
      alarm_factory->CreateAlarm(new CounterDelegate(&slow_alarm_counter)));

  const QuicTime start_time = simulator.GetClock()->Now();
  alarm_fast->Set(start_time + QuicTime::Delta::FromMilliseconds(100));
  alarm_slow->Set(start_time + QuicTime::Delta::FromMilliseconds(750));
  AlarmToggler toggler(&simulator, "Toggler", alarm_slow.get(),
                       QuicTime::Delta::FromMilliseconds(100));

  const QuicTime end_time =
      start_time + QuicTime::Delta::FromMilliseconds(1000);
  EXPECT_FALSE(simulator.RunUntil([&simulator, end_time]() {
    return simulator.GetClock()->Now() >= end_time;
  }));
  EXPECT_EQ(1u, slow_alarm_counter);
  EXPECT_EQ(1u, fast_alarm_counter);

  EXPECT_EQ(4, toggler.times_set());
  EXPECT_EQ(4, toggler.times_cancelled());
}

// Verifies that a cancelled alarm is never fired.
TEST(SimulatorTest, AlarmCancelling) {
  Simulator simulator;
  QuicAlarmFactory* alarm_factory = simulator.GetAlarmFactory();

  size_t alarm_counter = 0;
  std::unique_ptr<QuicAlarm> alarm(
      alarm_factory->CreateAlarm(new CounterDelegate(&alarm_counter)));

  const QuicTime start_time = simulator.GetClock()->Now();
  const QuicTime alarm_at = start_time + QuicTime::Delta::FromMilliseconds(300);
  const QuicTime end_time = start_time + QuicTime::Delta::FromMilliseconds(400);

  alarm->Set(alarm_at);
  alarm->Cancel();
  EXPECT_FALSE(alarm->IsSet());

  EXPECT_FALSE(simulator.RunUntil([&simulator, end_time]() {
    return simulator.GetClock()->Now() >= end_time;
  }));

  EXPECT_FALSE(alarm->IsSet());
  EXPECT_EQ(0u, alarm_counter);
}

}  // namespace simulation
}  // namespace net
