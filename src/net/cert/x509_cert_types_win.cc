// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_cert_types.h"

#include <windows.h>

#include <memory>

#include "base/logging.h"
#include "base/memory/free_deleter.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "crypto/capi_util.h"
#include "crypto/wincrypt_shim.h"

namespace net {

namespace {

// A list of OIDs to decode. Any OID not on this list will be ignored for
// purposes of parsing.
const char* const kOIDs[] = {
  szOID_COMMON_NAME,
  szOID_LOCALITY_NAME,
  szOID_STATE_OR_PROVINCE_NAME,
  szOID_COUNTRY_NAME,
  szOID_STREET_ADDRESS,
  szOID_ORGANIZATION_NAME,
  szOID_ORGANIZATIONAL_UNIT_NAME,
  szOID_DOMAIN_COMPONENT
};

// Converts the value for |attribute| to an UTF-8 string, storing the result
// in |value|. Returns false if the string cannot be converted.
bool GetAttributeValue(PCERT_RDN_ATTR attribute,
                       std::string* value) {
  DWORD chars_needed = CertRDNValueToStrW(attribute->dwValueType,
                                          &attribute->Value, NULL, 0);
  if (chars_needed == 0)
    return false;
  if (chars_needed == 1) {
    // The value is actually an empty string (chars_needed includes a single
    // char for a NULL value). Don't bother converting - just clear the
    // string.
    value->clear();
    return true;
  }
  std::wstring wide_name;
  DWORD chars_written = CertRDNValueToStrW(
      attribute->dwValueType, &attribute->Value,
      base::WriteInto(&wide_name, chars_needed), chars_needed);
  if (chars_written <= 1)
    return false;
  wide_name.resize(chars_written - 1);
  *value = base::WideToUTF8(wide_name);
  return true;
}

// Adds a type+value pair to the appropriate vector from a C array.
// The array is keyed by the matching OIDs from kOIDS[].
bool AddTypeValuePair(PCERT_RDN_ATTR attribute,
                      std::vector<std::string>* values[]) {
  for (size_t oid = 0; oid < arraysize(kOIDs); ++oid) {
    if (strcmp(attribute->pszObjId, kOIDs[oid]) == 0) {
      std::string value;
      if (!GetAttributeValue(attribute, &value))
        return false;
      values[oid]->push_back(value);
      break;
    }
  }
  return true;
}

// Stores the first string of the vector, if any, to *single_value.
void SetSingle(const std::vector<std::string>& values,
               std::string* single_value) {
  // We don't expect to have more than one CN, L, S, and C.
  LOG_IF(WARNING, values.size() > 1) << "Didn't expect multiple values";
  if (!values.empty())
    *single_value = values[0];
}

}  // namespace

bool CertPrincipal::ParseDistinguishedName(const void* ber_name_data,
                                           size_t length) {
  DCHECK(ber_name_data);

  CRYPT_DECODE_PARA decode_para;
  decode_para.cbSize = sizeof(decode_para);
  decode_para.pfnAlloc = crypto::CryptAlloc;
  decode_para.pfnFree = crypto::CryptFree;
  CERT_NAME_INFO* name_info = NULL;
  DWORD name_info_size = 0;
  BOOL rv;
  rv = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                           WINCRYPT_X509_NAME,
                           reinterpret_cast<const BYTE*>(ber_name_data),
                           length,
                           CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
                           &decode_para,
                           &name_info, &name_info_size);
  if (!rv)
    return false;
  std::unique_ptr<CERT_NAME_INFO, base::FreeDeleter> scoped_name_info(
      name_info);

  std::vector<std::string> common_names, locality_names, state_names,
      country_names;

  std::vector<std::string>* values[] = {
      &common_names, &locality_names,
      &state_names, &country_names,
      &this->street_addresses,
      &this->organization_names,
      &this->organization_unit_names,
      &this->domain_components
  };
  DCHECK(arraysize(kOIDs) == arraysize(values));

  for (DWORD cur_rdn = 0; cur_rdn < name_info->cRDN; ++cur_rdn) {
    PCERT_RDN rdn = &name_info->rgRDN[cur_rdn];
    for (DWORD cur_ava = 0; cur_ava < rdn->cRDNAttr; ++cur_ava) {
      PCERT_RDN_ATTR ava = &rdn->rgRDNAttr[cur_ava];
      if (!AddTypeValuePair(ava, values))
        return false;
    }
  }

  SetSingle(common_names, &this->common_name);
  SetSingle(locality_names, &this->locality_name);
  SetSingle(state_names, &this->state_or_province_name);
  SetSingle(country_names, &this->country_name);
  return true;
}

}  // namespace net
