// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUARTC_QUARTC_STREAM_H_
#define NET_QUIC_QUARTC_QUARTC_STREAM_H_

#include "net/quic/core/quic_session.h"
#include "net/quic/core/reliable_quic_stream.h"
#include "net/quic/quartc/quartc_stream_interface.h"

namespace net {

// Implements a QuartcStreamInterface using a ReliableQuicStream.
class NET_EXPORT_PRIVATE QuartcStream : public ReliableQuicStream,
                                        public QuartcStreamInterface {
 public:
  QuartcStream(QuicStreamId id, QuicSession* session);

  ~QuartcStream() override;

  // ReliableQuicStream overrides.
  void OnDataAvailable() override;

  void OnClose() override;

  void OnCanWrite() override;

  // QuartcStreamInterface overrides.
  uint32_t stream_id() override;

  uint64_t buffered_amount() override;

  bool fin_sent() override;

  void Write(const char* data,
             size_t size,
             const WriteParameters& param) override;

  void Close() override;

  void SetDelegate(QuartcStreamInterface::Delegate* delegate) override;

 private:
  QuartcStreamInterface::Delegate* delegate_ = nullptr;
};

}  // namespace net

#endif  // NET_QUIC_QUARTC_STREAM_H_
