// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_stream_factory_peer.h"

#include <string>
#include <vector>

#include "net/quic/crypto/quic_crypto_client_config.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_http_stream.h"
#include "net/quic/quic_stream_factory.h"

using std::string;
using std::vector;

namespace net {
namespace test {

const QuicConfig* QuicStreamFactoryPeer::GetConfig(QuicStreamFactory* factory) {
  return &factory->config_;
}

QuicCryptoClientConfig* QuicStreamFactoryPeer::GetCryptoConfig(
    QuicStreamFactory* factory) {
  return &factory->crypto_config_;
}

bool QuicStreamFactoryPeer::HasActiveSession(QuicStreamFactory* factory,
                                             const QuicServerId& server_id) {
  return factory->HasActiveSession(server_id);
}

QuicChromiumClientSession* QuicStreamFactoryPeer::GetActiveSession(
    QuicStreamFactory* factory,
    const QuicServerId& server_id) {
  DCHECK(factory->HasActiveSession(server_id));
  return factory->active_sessions_[server_id];
}

std::unique_ptr<QuicHttpStream> QuicStreamFactoryPeer::CreateFromSession(
    QuicStreamFactory* factory,
    QuicChromiumClientSession* session) {
  return factory->CreateFromSession(session);
}

bool QuicStreamFactoryPeer::IsLiveSession(QuicStreamFactory* factory,
                                          QuicChromiumClientSession* session) {
  for (QuicStreamFactory::SessionIdMap::iterator it =
           factory->all_sessions_.begin();
       it != factory->all_sessions_.end(); ++it) {
    if (it->first == session)
      return true;
  }
  return false;
}

void QuicStreamFactoryPeer::SetTaskRunner(QuicStreamFactory* factory,
                                          base::TaskRunner* task_runner) {
  factory->task_runner_ = task_runner;
}

int QuicStreamFactoryPeer::GetNumberOfLossyConnections(
    QuicStreamFactory* factory,
    uint16_t port) {
  return factory->number_of_lossy_connections_[port];
}

bool QuicStreamFactoryPeer::IsQuicDisabled(QuicStreamFactory* factory,
                                           uint16_t port) {
  return factory->IsQuicDisabled(port);
}

bool QuicStreamFactoryPeer::GetDelayTcpRace(QuicStreamFactory* factory) {
  return factory->delay_tcp_race_;
}

void QuicStreamFactoryPeer::SetDelayTcpRace(QuicStreamFactory* factory,
                                            bool delay_tcp_race) {
  factory->delay_tcp_race_ = delay_tcp_race;
}

void QuicStreamFactoryPeer::SetYieldAfterPackets(QuicStreamFactory* factory,
                                                 int yield_after_packets) {
  factory->yield_after_packets_ = yield_after_packets;
}

void QuicStreamFactoryPeer::SetYieldAfterDuration(
    QuicStreamFactory* factory,
    QuicTime::Delta yield_after_duration) {
  factory->yield_after_duration_ = yield_after_duration;
}

size_t QuicStreamFactoryPeer::GetNumberOfActiveJobs(
    QuicStreamFactory* factory,
    const QuicServerId& server_id) {
  return (factory->active_jobs_[server_id]).size();
}

int QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(
    QuicStreamFactory* factory) {
  return factory->num_timeouts_with_open_streams_;
}

int QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
    QuicStreamFactory* factory) {
  return factory->num_public_resets_post_handshake_;
}

void QuicStreamFactoryPeer::MaybeInitialize(QuicStreamFactory* factory) {
  factory->MaybeInitialize();
}

bool QuicStreamFactoryPeer::HasInitializedData(QuicStreamFactory* factory) {
  return factory->has_initialized_data_;
}

bool QuicStreamFactoryPeer::SupportsQuicAtStartUp(QuicStreamFactory* factory,
                                                  HostPortPair host_port_pair) {
  return ContainsKey(factory->quic_supported_servers_at_startup_,
                     host_port_pair);
}

bool QuicStreamFactoryPeer::CryptoConfigCacheIsEmpty(
    QuicStreamFactory* factory,
    const QuicServerId& quic_server_id) {
  return factory->CryptoConfigCacheIsEmpty(quic_server_id);
}

void QuicStreamFactoryPeer::CacheDummyServerConfig(
    QuicStreamFactory* factory,
    const QuicServerId& quic_server_id) {
  // Minimum SCFG that passes config validation checks.
  const char scfg[] = {// SCFG
                       0x53, 0x43, 0x46, 0x47,
                       // num entries
                       0x01, 0x00,
                       // padding
                       0x00, 0x00,
                       // EXPY
                       0x45, 0x58, 0x50, 0x59,
                       // EXPY end offset
                       0x08, 0x00, 0x00, 0x00,
                       // Value
                       '1', '2', '3', '4', '5', '6', '7', '8'};

  string server_config(reinterpret_cast<const char*>(&scfg), sizeof(scfg));
  string source_address_token("test_source_address_token");
  string signature("test_signature");
  string test_cert("test_cert");
  vector<string> certs;
  certs.push_back(test_cert);

  QuicCryptoClientConfig* crypto_config = &factory->crypto_config_;
  QuicCryptoClientConfig::CachedState* cached =
      crypto_config->LookupOrCreate(quic_server_id);
  QuicClock clock;
  cached->Initialize(server_config, source_address_token, certs, "", "",
                     signature, clock.WallNow());
}

QuicClientPushPromiseIndex* QuicStreamFactoryPeer::GetPushPromiseIndex(
    QuicStreamFactory* factory) {
  return &factory->push_promise_index_;
}

int QuicStreamFactoryPeer::GetNumPushStreamsCreated(
    QuicStreamFactory* factory) {
  return factory->num_push_streams_created_;
}

}  // namespace test
}  // namespace net
