// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/mock_quic_dispatcher.h"

#include "net/quic/test_tools/quic_test_utils.h"

namespace net {
namespace test {

MockQuicDispatcher::MockQuicDispatcher(
    const QuicConfig& config,
    const QuicCryptoServerConfig* crypto_config,
    std::unique_ptr<QuicConnectionHelperInterface> helper,
    std::unique_ptr<QuicAlarmFactory> alarm_factory)
    : QuicDispatcher(config,
                     crypto_config,
                     QuicSupportedVersions(),
                     std::move(helper),
                     std::move(alarm_factory)) {}

MockQuicDispatcher::~MockQuicDispatcher() {}

}  // namespace test
}  // namespace net
