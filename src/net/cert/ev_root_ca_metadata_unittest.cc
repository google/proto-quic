// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/ev_root_ca_metadata.h"

#include "net/cert/x509_cert_types.h"
#include "net/test/cert_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

#if defined(USE_NSS_CERTS)
#include "crypto/nss_util.h"
#include "crypto/scoped_nss_types.h"
#endif

namespace net {

namespace {

#if defined(USE_NSS_CERTS) || defined(OS_WIN)
const char kVerisignPolicy[] = "2.16.840.1.113733.1.7.23.6";
const char kThawtePolicy[] = "2.16.840.1.113733.1.7.48.1";
const char kFakePolicy[] = "2.16.840.1.42";
const SHA1HashValue kVerisignFingerprint =
    { { 0x74, 0x2c, 0x31, 0x92, 0xe6, 0x07, 0xe4, 0x24, 0xeb, 0x45,
        0x49, 0x54, 0x2b, 0xe1, 0xbb, 0xc5, 0x3e, 0x61, 0x74, 0xe2 } };
const SHA1HashValue kFakeFingerprint =
    { { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 } };

class EVOidData {
 public:
  EVOidData();
  bool Init();

  EVRootCAMetadata::PolicyOID verisign_policy;
  EVRootCAMetadata::PolicyOID thawte_policy;
  EVRootCAMetadata::PolicyOID fake_policy;
};

#endif  // defined(USE_NSS_CERTS) || defined(OS_WIN)

#if defined(USE_NSS_CERTS)

SECOidTag RegisterOID(PLArenaPool* arena, const char* oid_string) {
  SECOidData oid_data;
  memset(&oid_data, 0, sizeof(oid_data));
  oid_data.offset = SEC_OID_UNKNOWN;
  oid_data.desc = oid_string;
  oid_data.mechanism = CKM_INVALID_MECHANISM;
  oid_data.supportedExtension = INVALID_CERT_EXTENSION;

  SECStatus rv = SEC_StringToOID(arena, &oid_data.oid, oid_string, 0);
  if (rv != SECSuccess)
    return SEC_OID_UNKNOWN;

  return SECOID_AddEntry(&oid_data);
}

EVOidData::EVOidData()
    : verisign_policy(SEC_OID_UNKNOWN),
      thawte_policy(SEC_OID_UNKNOWN),
      fake_policy(SEC_OID_UNKNOWN) {
}

bool EVOidData::Init() {
  crypto::EnsureNSSInit();
  crypto::ScopedPLArenaPool pool(PORT_NewArena(DER_DEFAULT_CHUNKSIZE));
  if (!pool.get())
    return false;

  verisign_policy = RegisterOID(pool.get(), kVerisignPolicy);
  thawte_policy = RegisterOID(pool.get(), kThawtePolicy);
  fake_policy = RegisterOID(pool.get(), kFakePolicy);

  return verisign_policy != SEC_OID_UNKNOWN &&
         thawte_policy != SEC_OID_UNKNOWN &&
         fake_policy != SEC_OID_UNKNOWN;
}

#elif defined(OS_WIN)

EVOidData::EVOidData()
    : verisign_policy(kVerisignPolicy),
      thawte_policy(kThawtePolicy),
      fake_policy(kFakePolicy) {
}

bool EVOidData::Init() {
  return true;
}

#endif

#if defined(USE_NSS_CERTS) || defined(OS_WIN)

class EVRootCAMetadataTest : public testing::Test {
 protected:
  void SetUp() override { ASSERT_TRUE(ev_oid_data.Init()); }

  EVOidData ev_oid_data;
};

TEST_F(EVRootCAMetadataTest, Basic) {
  EVRootCAMetadata* ev_metadata(EVRootCAMetadata::GetInstance());

  EXPECT_TRUE(ev_metadata->IsEVPolicyOID(ev_oid_data.verisign_policy));
  EXPECT_FALSE(ev_metadata->IsEVPolicyOID(ev_oid_data.fake_policy));
  EXPECT_TRUE(ev_metadata->HasEVPolicyOID(kVerisignFingerprint,
                                          ev_oid_data.verisign_policy));
  EXPECT_FALSE(ev_metadata->HasEVPolicyOID(kFakeFingerprint,
                                           ev_oid_data.verisign_policy));
  EXPECT_FALSE(ev_metadata->HasEVPolicyOID(kVerisignFingerprint,
                                           ev_oid_data.fake_policy));
  EXPECT_FALSE(ev_metadata->HasEVPolicyOID(kVerisignFingerprint,
                                           ev_oid_data.thawte_policy));
}

TEST_F(EVRootCAMetadataTest, AddRemove) {
  EVRootCAMetadata* ev_metadata(EVRootCAMetadata::GetInstance());

  EXPECT_FALSE(ev_metadata->IsEVPolicyOID(ev_oid_data.fake_policy));
  EXPECT_FALSE(ev_metadata->HasEVPolicyOID(kFakeFingerprint,
                                           ev_oid_data.fake_policy));

  {
    ScopedTestEVPolicy test_ev_policy(ev_metadata, kFakeFingerprint,
                                      kFakePolicy);

    EXPECT_TRUE(ev_metadata->IsEVPolicyOID(ev_oid_data.fake_policy));
    EXPECT_TRUE(ev_metadata->HasEVPolicyOID(kFakeFingerprint,
                                            ev_oid_data.fake_policy));
  }

  EXPECT_FALSE(ev_metadata->IsEVPolicyOID(ev_oid_data.fake_policy));
  EXPECT_FALSE(ev_metadata->HasEVPolicyOID(kFakeFingerprint,
                                           ev_oid_data.fake_policy));
}

#endif  // defined(USE_NSS_CERTS) || defined(OS_WIN)

}  // namespace

}  // namespace net
