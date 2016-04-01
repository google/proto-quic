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

  // The SCT is from a known log, but the signature is invalid.
  SCT_STATUS_INVALID = 2,

  // The SCT is from a known log, and the signature is valid.
  SCT_STATUS_OK = 3,

  // Used to bound the enum values.
  SCT_STATUS_MAX,
};

}  // namespace ct

}  // namespace net

#endif  // NET_CERT_SCT_STATUS_FLAGS_H_
