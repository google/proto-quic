// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_NETWORK_QUALITY_OBSERVATION_SOURCE_H_
#define NET_NQE_NETWORK_QUALITY_OBSERVATION_SOURCE_H_

namespace net {

// On Android, a Java counterpart will be generated for this enum.
// GENERATED_JAVA_ENUM_PACKAGE: org.chromium.net
// GENERATED_JAVA_CLASS_NAME_OVERRIDE: NetworkQualityObservationSource
// GENERATED_JAVA_PREFIX_TO_STRIP: NETWORK_QUALITY_OBSERVATION_SOURCE_
enum NetworkQualityObservationSource {
  // The observation was taken at the request layer, e.g., a round trip time
  // is recorded as the time between the request being sent and the first byte
  // being received.
  NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST = 0,

  // The observation is taken from TCP statistics maintained by the kernel.
  NETWORK_QUALITY_OBSERVATION_SOURCE_TCP,

  // The observation is taken at the QUIC layer.
  NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC,

  // The observation is a previously cached estimate of the metric.
  NETWORK_QUALITY_OBSERVATION_SOURCE_CACHED_ESTIMATE,

  // The observation is derived from network connection information provided
  // by the platform. For example, typical RTT and throughput values are used
  // for a given type of network connection.
  NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_FROM_PLATFORM,

  // The observation came from a Chromium-external source.
  NETWORK_QUALITY_OBSERVATION_SOURCE_EXTERNAL_ESTIMATE
};

}  // namespace net

#endif  // NET_NQE_NETWORK_QUALITY_OBSERVATION_SOURCE_H_