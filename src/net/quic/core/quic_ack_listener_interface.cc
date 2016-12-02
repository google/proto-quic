// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_ack_listener_interface.h"

namespace net {

AckListenerWrapper::AckListenerWrapper(QuicAckListenerInterface* listener,
                                       QuicPacketLength data_length)
    : ack_listener(listener), length(data_length) {
  DCHECK(listener != nullptr);
}

AckListenerWrapper::AckListenerWrapper(const AckListenerWrapper& other) =
    default;

AckListenerWrapper::~AckListenerWrapper() {}

}  // namespace net
