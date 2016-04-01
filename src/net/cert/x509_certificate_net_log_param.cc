// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_certificate_net_log_param.h"

#include <string>
#include <utility>
#include <vector>

#include "base/values.h"
#include "net/cert/x509_certificate.h"

namespace net {

scoped_ptr<base::Value> NetLogX509CertificateCallback(
    const X509Certificate* certificate,
    NetLogCaptureMode capture_mode) {
  scoped_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  scoped_ptr<base::ListValue> certs(new base::ListValue());
  std::vector<std::string> encoded_chain;
  certificate->GetPEMEncodedChain(&encoded_chain);
  for (size_t i = 0; i < encoded_chain.size(); ++i)
    certs->Append(new base::StringValue(encoded_chain[i]));
  dict->Set("certificates", std::move(certs));
  return std::move(dict);
}

}  // namespace net
