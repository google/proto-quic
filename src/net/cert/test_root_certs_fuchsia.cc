// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/test_root_certs.h"

#include "base/location.h"
#include "base/logging.h"
#include "net/cert/x509_certificate.h"

namespace net {

bool TestRootCerts::Add(X509Certificate* certificate) {
  // TODO(fuchsia): Implement this.
  NOTIMPLEMENTED();
  return false;
}

void TestRootCerts::Clear() {
  // TODO(fuchsia): Implement this.
  NOTIMPLEMENTED();
  empty_ = true;
}

bool TestRootCerts::IsEmpty() const {
  return empty_;
}

TestRootCerts::~TestRootCerts() {}

void TestRootCerts::Init() {
  empty_ = true;
}

}  // namespace net
