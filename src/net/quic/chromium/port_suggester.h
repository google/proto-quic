// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_PORT_SUGGESTER_H_
#define NET_QUIC_PORT_SUGGESTER_H_

#include <stdint.h>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/sha1.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_export.h"

namespace net {

// We provide a pseudo-random number generator that is always seeded the same
// way for a given destination host-port pair.  The generator is used to
// consistently suggest (for that host-port pair) an ephemeral source port,
// and hence increase the likelihood that a server's load balancer will direct
// a repeated connection to the same server (with QUIC, further increasing the
// chance of connection establishment with 0-RTT).
class NET_EXPORT_PRIVATE PortSuggester
    : public base::RefCounted<PortSuggester> {
 public:
  PortSuggester(const HostPortPair& server, uint64_t seed);

  // Generate a pseudo-random int in the inclusive range from |min| to |max|.
  // Will (probably) return different numbers when called repeatedly.
  int SuggestPort(int min, int max);

  uint32_t call_count() const { return call_count_; }
  int previous_suggestion() const;

 private:
  friend class base::RefCounted<PortSuggester>;

  virtual ~PortSuggester() {}

  // We maintain the first 8 bytes of a hash as our seed_ state.
  uint64_t seed_;
  uint32_t call_count_;  // Number of suggestions made.
  int previous_suggestion_;

  DISALLOW_COPY_AND_ASSIGN(PortSuggester);
};

}  // namespace net

#endif  // NET_QUIC_PORT_SUGGESTER_H_
