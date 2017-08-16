// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_util_openssl.h"

#include <limits.h>

#include <algorithm>
#include <memory>

#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "crypto/openssl_util.h"
#include "net/cert/x509_cert_types.h"
#include "net/cert/x509_util.h"
#include "third_party/boringssl/src/include/openssl/asn1.h"
#include "third_party/boringssl/src/include/openssl/mem.h"

namespace net {

namespace x509_util {

namespace {

// DER-encodes |x509|. On success, returns true and writes the
// encoding to |*out_der|.
bool DerEncodeCert(X509* x509, std::string* out_der) {
  int len = i2d_X509(x509, NULL);
  if (len < 0)
    return false;

  uint8_t* ptr = reinterpret_cast<uint8_t*>(base::WriteInto(out_der, len + 1));
  if (i2d_X509(x509, &ptr) < 0) {
    NOTREACHED();
    out_der->clear();
    return false;
  }
  return true;
}

struct DERCache {
  std::string data;
};

void DERCache_free(void* parent, void* ptr, CRYPTO_EX_DATA* ad, int idx,
                   long argl, void* argp) {
  DERCache* der_cache = static_cast<DERCache*>(ptr);
  delete der_cache;
}

class DERCacheInitSingleton {
 public:
  DERCacheInitSingleton() {
    crypto::EnsureOpenSSLInit();
    der_cache_ex_index_ = X509_get_ex_new_index(0, 0, 0, 0, DERCache_free);
    DCHECK_NE(-1, der_cache_ex_index_);
  }

  int der_cache_ex_index() const { return der_cache_ex_index_; }

 private:
  int der_cache_ex_index_;

  DISALLOW_COPY_AND_ASSIGN(DERCacheInitSingleton);
};

base::LazyInstance<DERCacheInitSingleton>::Leaky g_der_cache_singleton =
    LAZY_INSTANCE_INITIALIZER;

}  // namespace

bool ParsePrincipalKeyAndValue(X509_NAME_ENTRY* entry,
                               std::string* key,
                               std::string* value) {
  if (key) {
    ASN1_OBJECT* object = X509_NAME_ENTRY_get_object(entry);
    key->assign(OBJ_nid2sn(OBJ_obj2nid(object)));
  }

  ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
  if (!data)
    return false;

  unsigned char* buf = NULL;
  int len = ASN1_STRING_to_UTF8(&buf, data);
  if (len <= 0)
    return false;

  value->assign(reinterpret_cast<const char*>(buf), len);
  OPENSSL_free(buf);
  return true;
}

bool ParsePrincipalKeyAndValueByIndex(X509_NAME* name,
                                      int index,
                                      std::string* key,
                                      std::string* value) {
  X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, index);
  if (!entry)
    return false;

  return ParsePrincipalKeyAndValue(entry, key, value);
}

bool ParsePrincipalValueByIndex(X509_NAME* name,
                                int index,
                                std::string* value) {
  return ParsePrincipalKeyAndValueByIndex(name, index, NULL, value);
}

bool ParsePrincipalValueByNID(X509_NAME* name, int nid, std::string* value) {
  int index = X509_NAME_get_index_by_NID(name, nid, -1);
  if (index < 0)
    return false;

  return ParsePrincipalValueByIndex(name, index, value);
}

bool ParseDate(ASN1_TIME* x509_time, base::Time* time) {
  if (!x509_time ||
      (x509_time->type != V_ASN1_UTCTIME &&
       x509_time->type != V_ASN1_GENERALIZEDTIME))
    return false;

  base::StringPiece str_date(reinterpret_cast<const char*>(x509_time->data),
                             x509_time->length);

  CertDateFormat format = x509_time->type == V_ASN1_UTCTIME ?
      CERT_DATE_FORMAT_UTC_TIME : CERT_DATE_FORMAT_GENERALIZED_TIME;
  return ParseCertificateDate(str_date, format, time);
}

// Returns true if |der_cache| points to valid data, false otherwise.
// (note: the DER-encoded data in |der_cache| is owned by |x509|, callers should
// not free it).
bool GetDER(X509* x509, base::StringPiece* der_cache) {
  if (x509->buf) {
    *der_cache = base::StringPiece(
        reinterpret_cast<const char*>(CRYPTO_BUFFER_data(x509->buf)),
        CRYPTO_BUFFER_len(x509->buf));
    return true;
  }

  int x509_der_cache_index =
      g_der_cache_singleton.Get().der_cache_ex_index();

  // Re-encoding the DER data via i2d_X509 is an expensive operation,
  // but it's necessary for comparing two certificates. Re-encode at
  // most once per certificate and cache the data within the X509 cert
  // using X509_set_ex_data.
  DERCache* internal_cache = static_cast<DERCache*>(
      X509_get_ex_data(x509, x509_der_cache_index));
  if (!internal_cache) {
    std::unique_ptr<DERCache> new_cache(new DERCache);
    if (!DerEncodeCert(x509, &new_cache->data))
      return false;
    internal_cache = new_cache.get();
    X509_set_ex_data(x509, x509_der_cache_index, new_cache.release());
  }
  *der_cache = base::StringPiece(internal_cache->data);
  return true;
}

}  // namespace x509_util

}  // namespace net
