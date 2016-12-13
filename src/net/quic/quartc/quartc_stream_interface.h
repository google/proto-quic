// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUARTC_QUARTC_STREAM_INTERFACE_H_
#define NET_QUIC_QUARTC_QUARTC_STREAM_INTERFACE_H_

#include <stddef.h>
#include <stdint.h>

#include "net/quic/platform/api/quic_export.h"

namespace net {

// Sends and receives data with a particular QUIC stream ID, reliably and
// in-order. To send/receive data out of order, use separate streams. To
// send/receive unreliably, close a stream after reliability is no longer
// needed.
class QUIC_EXPORT_PRIVATE QuartcStreamInterface {
 public:
  virtual ~QuartcStreamInterface() {}

  // The QUIC stream ID.
  virtual uint32_t stream_id() = 0;

  // The amount of data buffered by the QuicConnection.
  virtual uint64_t buffered_amount() = 0;

  // Return true if the FIN has been sent. Used by the outgoing streams to
  // determine if all the data has been sent
  virtual bool fin_sent() = 0;

  struct WriteParameters {
    WriteParameters() : fin(false) {}
    // |fin| is set to be true when there is no more data need to be send
    // through a particular stream. The receiving side will used it to determine
    // if the sender finish sending data.
    bool fin;
  };

  // Sends data reliably and in-order, buffering if necessary until Close() is
  // called.
  virtual void Write(const char* data,
                     size_t size,
                     const WriteParameters& param) = 0;

  // Once Close is called, no more data can be sent, all buffered data will be
  // dropped and no data will be retransmitted.
  virtual void Close() = 0;

  // Implemented by the user of the QuartcStreamInterface to receive incoming
  // data and be notified of state changes.
  class Delegate {
   public:
    virtual ~Delegate() {}

    // Called when the stream receives the date.
    virtual void OnReceived(QuartcStreamInterface* stream,
                            const char* data,
                            size_t size) = 0;

    // Called when the stream is closed, either locally or by the remote
    // endpoint.
    // TODO(zhihuang) Creates a map from the integer error_code to WebRTC native
    // error code.
    virtual void OnClose(QuartcStreamInterface* stream, int error_code) = 0;

    // Called when buffered_amount() decreases.
    virtual void OnBufferedAmountDecrease(QuartcStreamInterface* stream) = 0;
  };

  // The |delegate| is not owned by QuartcStream.
  virtual void SetDelegate(Delegate* delegate) = 0;
};

}  // namespace net

#endif  // NET_QUIC_QUARTC_QUARTC_STREAM_INTERFACE_H_
