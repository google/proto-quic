// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/openssl_client_key_store.h"

#include "base/logging.h"
#include "base/memory/ref_counted.h"
#include "net/ssl/ssl_private_key.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// A common test class to ensure that the store is flushed after
// each test.
class OpenSSLClientKeyStoreTest : public ::testing::Test {
 public:
  OpenSSLClientKeyStoreTest()
    : store_(OpenSSLClientKeyStore::GetInstance()) {
  }

  ~OpenSSLClientKeyStoreTest() override {
    if (store_)
      store_->Flush();
  }

 protected:
  OpenSSLClientKeyStore* store_;
};

class MockSSLPrivateKey : public SSLPrivateKey {
 public:
  MockSSLPrivateKey() : on_destroyed_(nullptr) {}

  void set_on_destroyed(bool* on_destroyed) { on_destroyed_ = on_destroyed; }

  std::vector<Hash> GetDigestPreferences() override {
    NOTREACHED();
    return {};
  }

  void SignDigest(Hash hash,
                  const base::StringPiece& input,
                  const SignCallback& callback) override {
    NOTREACHED();
  }

 private:
  ~MockSSLPrivateKey() override {
    if (on_destroyed_)
      *on_destroyed_ = true;
  }

  bool* on_destroyed_;
};

// Check that GetInstance() returns non-null
TEST_F(OpenSSLClientKeyStoreTest, GetInstance) {
  ASSERT_TRUE(store_);
}

// Check that Flush() works correctly.
TEST_F(OpenSSLClientKeyStoreTest, Flush) {
  ASSERT_TRUE(store_);

  scoped_refptr<X509Certificate> cert_1(
      ImportCertFromFile(GetTestCertsDirectory(), "client_1.pem"));
  ASSERT_TRUE(cert_1);

  EXPECT_TRUE(store_->RecordClientCertPrivateKey(
      cert_1.get(), make_scoped_refptr(new MockSSLPrivateKey)));

  store_->Flush();

  // Retrieve the private key. This should fail because the store
  // was flushed.
  EXPECT_FALSE(store_->FetchClientCertPrivateKey(cert_1.get()));
}

// Check that trying to retrieve the private key of an unknown certificate
// simply fails by returning null.
TEST_F(OpenSSLClientKeyStoreTest, FetchEmptyPrivateKey) {
  ASSERT_TRUE(store_);

  scoped_refptr<X509Certificate> cert_1(
      ImportCertFromFile(GetTestCertsDirectory(), "client_1.pem"));
  ASSERT_TRUE(cert_1);

  // Retrieve the private key now. This should fail because it was
  // never recorded in the store.
  EXPECT_FALSE(store_->FetchClientCertPrivateKey(cert_1.get()));
}

// Check that any private key recorded through RecordClientCertPrivateKey
// can be retrieved with FetchClientCertPrivateKey.
TEST_F(OpenSSLClientKeyStoreTest, RecordAndFetchPrivateKey) {
  ASSERT_TRUE(store_);

  // Any certificate / key pair will do, the store is not supposed to
  // check that the private and certificate public keys match. This is
  // by design since the private EVP_PKEY could be a wrapper around a
  // JNI reference, with no way to access the real private key bits.
  scoped_refptr<X509Certificate> cert_1(
      ImportCertFromFile(GetTestCertsDirectory(), "client_1.pem"));
  ASSERT_TRUE(cert_1);

  bool on_destroyed = false;
  scoped_refptr<MockSSLPrivateKey> priv_key(new MockSSLPrivateKey);
  priv_key->set_on_destroyed(&on_destroyed);

  // Add a key twice.
  EXPECT_TRUE(store_->RecordClientCertPrivateKey(cert_1.get(), priv_key));
  EXPECT_TRUE(store_->RecordClientCertPrivateKey(cert_1.get(), priv_key));

  // Retrieve the private key.
  scoped_refptr<SSLPrivateKey> pkey2 =
      store_->FetchClientCertPrivateKey(cert_1.get());
  EXPECT_EQ(pkey2.get(), priv_key.get());

  // Flush the key store and release all references. At this point, the private
  // key should be cleanly destroyed.
  store_->Flush();
  priv_key = nullptr;
  pkey2 = nullptr;
  EXPECT_TRUE(on_destroyed);
}

// Same test, but with two certificates / private keys.
TEST_F(OpenSSLClientKeyStoreTest, RecordAndFetchTwoPrivateKeys) {
  scoped_refptr<X509Certificate> cert_1(
      ImportCertFromFile(GetTestCertsDirectory(), "client_1.pem"));
  ASSERT_TRUE(cert_1);

  scoped_refptr<X509Certificate> cert_2(
      ImportCertFromFile(GetTestCertsDirectory(), "client_2.pem"));
  ASSERT_TRUE(cert_2);

  scoped_refptr<SSLPrivateKey> priv_key1(new MockSSLPrivateKey);
  scoped_refptr<SSLPrivateKey> priv_key2(new MockSSLPrivateKey);

  EXPECT_TRUE(store_->RecordClientCertPrivateKey(cert_1.get(), priv_key1));
  EXPECT_TRUE(store_->RecordClientCertPrivateKey(cert_2.get(), priv_key2));

  scoped_refptr<SSLPrivateKey> fetch_key1 =
      store_->FetchClientCertPrivateKey(cert_1.get());
  scoped_refptr<SSLPrivateKey> fetch_key2 =
      store_->FetchClientCertPrivateKey(cert_2.get());

  EXPECT_TRUE(fetch_key1);
  EXPECT_TRUE(fetch_key2);

  EXPECT_EQ(fetch_key1.get(), priv_key1.get());
  EXPECT_EQ(fetch_key2.get(), priv_key2.get());
}

}  // namespace
}  // namespace net
