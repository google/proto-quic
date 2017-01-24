// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/event_creator.h"

#include <memory>
#include <utility>

#include "base/bind.h"
#include "base/strings/string_number_conversions.h"
#include "base/values.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_with_source.h"

namespace net {

namespace nqe {

namespace internal {

namespace {

std::unique_ptr<base::Value> EffectiveConnectionTypeChangedNetLogCallback(
    base::TimeDelta http_rtt,
    base::TimeDelta transport_rtt,
    int32_t downstream_throughput_kbps,
    EffectiveConnectionType effective_connection_type,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("http_rtt_ms", http_rtt.InMilliseconds());
  dict->SetInteger("transport_rtt_ms", transport_rtt.InMilliseconds());
  dict->SetInteger("downstream_throughput_kbps", downstream_throughput_kbps);
  dict->SetString("effective_connection_type",
                  GetNameForEffectiveConnectionType(effective_connection_type));
  return std::move(dict);
}

}  // namespace

void AddEffectiveConnectionTypeChangedEventToNetLog(
    const NetLogWithSource& net_log,
    base::TimeDelta http_rtt,
    base::TimeDelta transport_rtt,
    int32_t downstream_throughput_kbps,
    EffectiveConnectionType effective_connection_type) {
  net_log.AddEvent(
      NetLogEventType::NETWORK_QUALITY_CHANGED,
      base::Bind(&EffectiveConnectionTypeChangedNetLogCallback, http_rtt,
                 transport_rtt, downstream_throughput_kbps,
                 effective_connection_type));
}

}  // namespace internal

}  // namespace nqe

}  // namespace net
