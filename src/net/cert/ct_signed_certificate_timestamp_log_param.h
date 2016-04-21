// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_CT_SIGNED_CERTIFICATE_TIMESTAMP_LOG_PARAM_H_
#define NET_CERT_CT_SIGNED_CERTIFICATE_TIMESTAMP_LOG_PARAM_H_

#include <memory>

#include "net/log/net_log.h"

namespace net {

namespace ct {
struct CTVerifyResult;
}

// Creates a dictionary of processed Signed Certificate Timestamps to be
// logged in the NetLog.
// See the documentation for SIGNED_CERTIFICATE_TIMESTAMPS_CHECKED
// in net/log/net_log_event_type_list.h
std::unique_ptr<base::Value> NetLogSignedCertificateTimestampCallback(
    const ct::CTVerifyResult* ct_result,
    NetLogCaptureMode capture_mode);

// Creates a dictionary of raw Signed Certificate Timestamps to be logged
// in the NetLog.
// See the documentation for SIGNED_CERTIFICATE_TIMESTAMPS_RECEIVED
// in net/log/net_log_event_type_list.h
std::unique_ptr<base::Value> NetLogRawSignedCertificateTimestampCallback(
    const std::string* embedded_scts,
    const std::string* sct_list_from_ocsp,
    const std::string* sct_list_from_tls_extension,
    NetLogCaptureMode capture_mode);

}  // namespace net

#endif  // NET_CERT_CT_SIGNED_CERTIFICATE_TIMESTAMP_LOG_PARAM_H_
