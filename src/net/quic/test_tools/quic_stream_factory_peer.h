// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_QUIC_STREAM_FACTORY_PEER_H_
#define NET_QUIC_TEST_TOOLS_QUIC_STREAM_FACTORY_PEER_H_

#include <stddef.h>
#include <stdint.h>

#include "base/macros.h"
#include "base/task_runner.h"
#include "net/base/host_port_pair.h"
#include "net/base/privacy_mode.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_server_id.h"
#include "net/quic/quic_time.h"

namespace net {

class QuicConfig;
class QuicCryptoClientConfig;
class QuicHttpStream;
class QuicStreamFactory;
class QuicChromiumClientSession;
class QuicClientPushPromiseIndex;

namespace test {

class QuicStreamFactoryPeer {
 public:
  static const QuicConfig* GetConfig(QuicStreamFactory* factory);

  static QuicCryptoClientConfig* GetCryptoConfig(QuicStreamFactory* factory);

  static bool HasActiveSession(QuicStreamFactory* factory,
                               const QuicServerId& server_id);

  static QuicChromiumClientSession* GetActiveSession(
      QuicStreamFactory* factory,
      const QuicServerId& server_id);

  static std::unique_ptr<QuicHttpStream> CreateFromSession(
      QuicStreamFactory* factory,
      QuicChromiumClientSession* session);

  static bool IsLiveSession(QuicStreamFactory* factory,
                            QuicChromiumClientSession* session);

  static void SetTaskRunner(QuicStreamFactory* factory,
                            base::TaskRunner* task_runner);

  static int GetNumberOfLossyConnections(QuicStreamFactory* factory,
                                         uint16_t port);

  static bool IsQuicDisabled(QuicStreamFactory* factory, uint16_t port);

  static bool GetDelayTcpRace(QuicStreamFactory* factory);

  static void SetDelayTcpRace(QuicStreamFactory* factory, bool delay_tcp_race);

  static void SetYieldAfterPackets(QuicStreamFactory* factory,
                                   int yield_after_packets);

  static void SetYieldAfterDuration(QuicStreamFactory* factory,
                                    QuicTime::Delta yield_after_duration);

  static size_t GetNumberOfActiveJobs(QuicStreamFactory* factory,
                                      const QuicServerId& server_id);

  static int GetNumTimeoutsWithOpenStreams(QuicStreamFactory* factory);

  static int GetNumPublicResetsPostHandshake(QuicStreamFactory* factory);

  static void MaybeInitialize(QuicStreamFactory* factory);

  static bool HasInitializedData(QuicStreamFactory* factory);

  static bool SupportsQuicAtStartUp(QuicStreamFactory* factory,
                                    HostPortPair host_port_pair);

  static bool CryptoConfigCacheIsEmpty(QuicStreamFactory* factory,
                                       const QuicServerId& quic_server_id);

  // Creates a dummy QUIC server config and caches it.
  static void CacheDummyServerConfig(QuicStreamFactory* factory,
                                     const QuicServerId& quic_server_id);

  static QuicClientPushPromiseIndex* GetPushPromiseIndex(
      QuicStreamFactory* factory);

  static int GetNumPushStreamsCreated(QuicStreamFactory* factory);

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicStreamFactoryPeer);
};

}  // namespace test
}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_QUIC_STREAM_FACTORY_PEER_H_
