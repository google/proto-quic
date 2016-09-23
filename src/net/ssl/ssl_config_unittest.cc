// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_config.h"

#include "net/cert/cert_verifier.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

void CheckCertVerifyFlags(SSLConfig& ssl_config,
                          bool rev_checking_enabled,
                          bool verify_ev_cert,
                          bool cert_io_enabled,
                          bool rev_checking_required_local_anchors) {
  ssl_config.rev_checking_enabled = rev_checking_enabled;
  ssl_config.verify_ev_cert = verify_ev_cert;
  ssl_config.cert_io_enabled = cert_io_enabled;
  ssl_config.rev_checking_required_local_anchors =
      rev_checking_required_local_anchors;
  int flags = ssl_config.GetCertVerifyFlags();
  if (rev_checking_enabled)
    EXPECT_TRUE(flags & CertVerifier::VERIFY_REV_CHECKING_ENABLED);
  else
    EXPECT_FALSE(flags & CertVerifier::VERIFY_REV_CHECKING_ENABLED);
  if (verify_ev_cert)
    EXPECT_TRUE(flags & CertVerifier::VERIFY_EV_CERT);
  else
    EXPECT_FALSE(flags & CertVerifier::VERIFY_EV_CERT);
  if (cert_io_enabled)
    EXPECT_TRUE(flags & CertVerifier::VERIFY_CERT_IO_ENABLED);
  else
    EXPECT_FALSE(flags & CertVerifier::VERIFY_CERT_IO_ENABLED);
  if (rev_checking_required_local_anchors) {
    EXPECT_TRUE(flags &
                CertVerifier::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS);
  } else {
    EXPECT_FALSE(flags &
                 CertVerifier::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS);
  }
}

}  // namespace

TEST(SSLConfigTest, GetCertVerifyFlags) {
  SSLConfig ssl_config;
  CheckCertVerifyFlags(ssl_config,
                       /*rev_checking_enabled=*/true,
                       /*verify_ev_cert=*/true,
                       /*cert_io_enabled=*/true,
                       /*rev_checking_required_local_anchors=*/true);

  CheckCertVerifyFlags(ssl_config,
                       /*rev_checking_enabled=*/false,
                       /*verify_ev_cert=*/false,
                       /*cert_io_enabled=*/false,
                       /*rev_checking_required_local_anchors=*/false);

  CheckCertVerifyFlags(ssl_config,
                       /*rev_checking_enabled=*/true,
                       /*verify_ev_cert=*/false,
                       /*cert_io_enabled=*/false,
                       /*rev_checking_required_local_anchors=*/false);

  CheckCertVerifyFlags(ssl_config,
                       /*rev_checking_enabled=*/false,
                       /*verify_ev_cert=*/true,
                       /*cert_io_enabled=*/false,
                       /*rev_checking_required_local_anchors=*/false);

  CheckCertVerifyFlags(ssl_config,
                       /*rev_checking_enabled=*/false,
                       /*verify_ev_cert=*/false,
                       /*cert_io_enabled=*/true,
                       /*rev_checking_required_local_anchors=*/false);

  CheckCertVerifyFlags(ssl_config,
                       /*rev_checking_enabled=*/false,
                       /*verify_ev_cert=*/false,
                       /*cert_io_enabled=*/false,
                       /*rev_checking_required_local_anchors=*/true);
}

}  // namespace net
