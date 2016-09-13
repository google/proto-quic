// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/ptr_util.h"
#include "net/quic/core/congestion_control/simulation/quic_endpoint.h"
#include "net/quic/core/congestion_control/simulation/simulator.h"
#include "net/quic/core/congestion_control/simulation/switch.h"

#include "net/test/gtest_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace simulation {

const QuicBandwidth kDefaultBandwidth =
    QuicBandwidth::FromKBitsPerSecond(10 * 1000);
const QuicTime::Delta kDefaultPropagationDelay =
    QuicTime::Delta::FromMilliseconds(20);
const QuicByteCount kDefaultBdp = kDefaultBandwidth * kDefaultPropagationDelay;

// A simple test harness where all hosts are connected to a switch with
// identical links.
class QuicEndpointTest : public ::testing::Test {
 public:
  QuicEndpointTest()
      : simulator_(), switch_(&simulator_, "Switch", 8, kDefaultBdp * 2) {}

 protected:
  Simulator simulator_;
  Switch switch_;

  std::unique_ptr<SymmetricLink> Link(Endpoint* a, Endpoint* b) {
    return base::MakeUnique<SymmetricLink>(a, b, kDefaultBandwidth,
                                           kDefaultPropagationDelay);
  }
};

// Test transmission from one host to another.
TEST_F(QuicEndpointTest, DISABLED_OneWayTransmission) {
  QuicEndpoint endpoint_a(&simulator_, "Endpoint A", "Endpoint B",
                          Perspective::IS_CLIENT, 42);
  QuicEndpoint endpoint_b(&simulator_, "Endpoint B", "Endpoint A",
                          Perspective::IS_SERVER, 42);
  auto link_a = Link(&endpoint_a, switch_.port(1));
  auto link_b = Link(&endpoint_b, switch_.port(2));

  // First transmit a small, packet-size chunk of data.
  endpoint_a.AddBytesToTransfer(600);
  QuicTime end_time =
      simulator_.GetClock()->Now() + QuicTime::Delta::FromMilliseconds(1000);
  simulator_.RunUntil(
      [this, end_time]() { return simulator_.GetClock()->Now() >= end_time; });

  EXPECT_EQ(600u, endpoint_a.bytes_transferred());
  ASSERT_EQ(600u, endpoint_b.bytes_received());
  EXPECT_FALSE(endpoint_a.wrong_data_received());
  EXPECT_FALSE(endpoint_b.wrong_data_received());

  // After a small chunk succeeds, try to transfer 2 MiB.
  endpoint_a.AddBytesToTransfer(2 * 1024 * 1024);
  end_time = simulator_.GetClock()->Now() + QuicTime::Delta::FromSeconds(5);
  simulator_.RunUntil(
      [this, end_time]() { return simulator_.GetClock()->Now() >= end_time; });

  const QuicByteCount total_bytes_transferred = 600 + 2 * 1024 * 1024;
  EXPECT_EQ(total_bytes_transferred, endpoint_a.bytes_transferred());
  EXPECT_EQ(total_bytes_transferred, endpoint_b.bytes_received());
  EXPECT_FALSE(endpoint_a.wrong_data_received());
  EXPECT_FALSE(endpoint_b.wrong_data_received());
}

// Test transmission of 1 MiB of data between two hosts simultaneously in both
// directions.
TEST_F(QuicEndpointTest, DISABLED_TwoWayTransmission) {
  QuicEndpoint endpoint_a(&simulator_, "Endpoint A", "Endpoint B",
                          Perspective::IS_CLIENT, 42);
  QuicEndpoint endpoint_b(&simulator_, "Endpoint B", "Endpoint A",
                          Perspective::IS_SERVER, 42);
  auto link_a = Link(&endpoint_a, switch_.port(1));
  auto link_b = Link(&endpoint_b, switch_.port(2));

  endpoint_a.AddBytesToTransfer(1024 * 1024);
  endpoint_b.AddBytesToTransfer(1024 * 1024);
  QuicTime end_time =
      simulator_.GetClock()->Now() + QuicTime::Delta::FromSeconds(5);
  simulator_.RunUntil(
      [this, end_time]() { return simulator_.GetClock()->Now() >= end_time; });

  EXPECT_EQ(1024u * 1024u, endpoint_a.bytes_transferred());
  EXPECT_EQ(1024u * 1024u, endpoint_b.bytes_transferred());
  EXPECT_EQ(1024u * 1024u, endpoint_a.bytes_received());
  EXPECT_EQ(1024u * 1024u, endpoint_b.bytes_received());
  EXPECT_FALSE(endpoint_a.wrong_data_received());
  EXPECT_FALSE(endpoint_b.wrong_data_received());
}

// Simulate three hosts trying to send data to a fourth one simultaneously.
TEST_F(QuicEndpointTest, DISABLED_Competition) {
  auto endpoint_a = base::MakeUnique<QuicEndpoint>(
      &simulator_, "Endpoint A", "Endpoint D (A)", Perspective::IS_CLIENT, 42);
  auto endpoint_b = base::MakeUnique<QuicEndpoint>(
      &simulator_, "Endpoint B", "Endpoint D (B)", Perspective::IS_CLIENT, 43);
  auto endpoint_c = base::MakeUnique<QuicEndpoint>(
      &simulator_, "Endpoint C", "Endpoint D (C)", Perspective::IS_CLIENT, 44);
  auto endpoint_d_a = base::MakeUnique<QuicEndpoint>(
      &simulator_, "Endpoint D (A)", "Endpoint A", Perspective::IS_SERVER, 42);
  auto endpoint_d_b = base::MakeUnique<QuicEndpoint>(
      &simulator_, "Endpoint D (B)", "Endpoint B", Perspective::IS_SERVER, 43);
  auto endpoint_d_c = base::MakeUnique<QuicEndpoint>(
      &simulator_, "Endpoint D (C)", "Endpoint C", Perspective::IS_SERVER, 44);
  QuicEndpointMultiplexer endpoint_d(
      "Endpoint D",
      {endpoint_d_a.get(), endpoint_d_b.get(), endpoint_d_c.get()});

  auto link_a = Link(endpoint_a.get(), switch_.port(1));
  auto link_b = Link(endpoint_b.get(), switch_.port(2));
  auto link_c = Link(endpoint_c.get(), switch_.port(3));
  auto link_d = Link(&endpoint_d, switch_.port(4));

  endpoint_a->AddBytesToTransfer(2 * 1024 * 1024);
  endpoint_b->AddBytesToTransfer(2 * 1024 * 1024);
  endpoint_c->AddBytesToTransfer(2 * 1024 * 1024);
  QuicTime end_time =
      simulator_.GetClock()->Now() + QuicTime::Delta::FromSeconds(8);
  simulator_.RunUntil(
      [this, end_time]() { return simulator_.GetClock()->Now() >= end_time; });

  for (QuicEndpoint* endpoint :
       {endpoint_a.get(), endpoint_b.get(), endpoint_c.get()}) {
    EXPECT_EQ(2u * 1024u * 1024u, endpoint->bytes_transferred());
    EXPECT_GE(endpoint->connection()->GetStats().packets_lost, 0u);
  }
  for (QuicEndpoint* endpoint :
       {endpoint_d_a.get(), endpoint_d_b.get(), endpoint_d_c.get()}) {
    EXPECT_EQ(2u * 1024u * 1024u, endpoint->bytes_received());
    EXPECT_FALSE(endpoint->wrong_data_received());
  }
}

}  // namespace simulation
}  // namespace net
