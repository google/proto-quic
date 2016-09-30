// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_DELAYED_PACKET_WRITER_H_
#define NET_QUIC_TEST_TOOLS_DELAYED_PACKET_WRITER_H_

#include "net/quic/quic_packet_writer_wrapper.h"

namespace net {

namespace test {

// This writer can be configed to defer writing packet for certain amount of
// time.
class DelayedPacketWriter : public QuicPacketWriterWrapper {
 public:
  class WriteAlarm : public gfe2::EpollAlarm {
   public:
    WriteAlarm(const char* buffer, size_t buf_len,
               const IPAddress& self_address, const SocketAddress& peer_address,
               std::unique_ptr<PerPacketOptions> options,
               DelayedPacketWriter* wrapper)
        : data_(buffer, buf_len),
          self_address_(self_address),
          peer_address_(peer_address),
          options_(std::move(options)),
          wrapper_(wrapper) {}

    void OnShutdown(gfe2::EpollServer* eps) override {
      EpollAlarm::OnShutdown(eps);
      delete this;
    }

    int64 OnAlarm() override {
      EpollAlarm::OnAlarm();
      wrapper_->WriteInternal(data_.data(), data_.length(), self_address_,
                              peer_address_, options_.get());
      delete this;
      return 0;
    }

    string data_;
    IPAddress self_address_;
    SocketAddress peer_address_;
    std::unique_ptr<PerPacketOptions> options_;
    DelayedPacketWriter* wrapper_;
  };

  explicit DelayedPacketWriter(gfe2::EpollServer* eps)
      : eps_(eps), delay_in_usec_(-1) {}

  WriteResult WritePacket(const char* buffer, size_t buf_len,
                          const IPAddress& self_address,
                          const SocketAddress& peer_address,
                          PerPacketOptions* options) override {
    if (delay_in_usec_ > 0) {
      std::unique_ptr<PerPacketOptions> delayed_options;
      if (options != nullptr) {
        delayed_options.reset(options->Clone());
      }
      WriteAlarm* alarm =
          new WriteAlarm(buffer, buf_len, self_address, peer_address,
                         std::move(delayed_options), this);
      eps_->RegisterAlarm(eps_->NowInUsec() + delay_in_usec_, alarm);
      return WriteResult(WRITE_STATUS_OK, buf_len);
    }
    return WriteInternal(buffer, buf_len, self_address, peer_address, options);
  }

  WriteResult WriteInternal(const char* buffer, size_t buf_len,
                            const IPAddress& self_address,
                            const SocketAddress& peer_address,
                            PerPacketOptions* options) {
    return QuicPacketWriterWrapper::WritePacket(buffer, buf_len, self_address,
                                                peer_address, options);
  }
  void set_delay_in_usec(int32 delay) { delay_in_usec_ = delay; }

 private:
  gfe2::EpollServer* eps_;
  int32 delay_in_usec_;
};

}  // namespace test
}  // namespace net

#endif  // GFE_QUIC_TEST_TOOLS_DELAYED_PACKET_WRITER_H_
