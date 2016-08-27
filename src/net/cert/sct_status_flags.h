// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_SCT_STATUS_FLAGS_H_
#define NET_CERT_SCT_STATUS_FLAGS_H_

namespace net {

namespace ct {

// The possible verification statuses for a SignedCertificateTimestamp.
// Note: The numeric values are used within histograms and should not change
// or be re-assigned.
enum SCTVerifyStatus {
  // Not a real status, this just prevents a default int value from being
  // mis-interpreseted as a valid status.
  // Also used to count SCTs that cannot be decoded in the histogram.
  SCT_STATUS_NONE = 0,

  // The SCT is from an unknown log, so we cannot verify its signature.
  SCT_STATUS_LOG_UNKNOWN = 1,

  // This value is deprecated and should not be used. It has been split
  // into INVALID_SIGNATURE and INVALID_TIMESTAMP to represent the
  // different reasons an SCT could be invalid. Though it is no longer
  // in use, it is preserved here because it may be present in
  // serialized messages.
  SCT_STATUS_INVALID = 2,

  // The SCT is from a known log, and the signature is valid.
  SCT_STATUS_OK = 3,

  // The SCT is from a known log, but the signature is invalid.
  SCT_STATUS_INVALID_SIGNATURE = 4,

  // The SCT is from a known log, but the timestamp is in the future.
  SCT_STATUS_INVALID_TIMESTAMP = 5,

  // Used to bound the enum values. Since this enum is passed over IPC,
  // the last value must be a valid one (rather than one past a valid one).
  SCT_STATUS_MAX = SCT_STATUS_INVALID_TIMESTAMP,
};

}  // namespace ct

}  // namespace net

#endif  // NET_CERT_SCT_STATUS_FLAGS_H_
