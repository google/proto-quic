// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cert.h>  // Must be included before certdb.h
#include <certdb.h>
#include <cryptohi.h>
#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <secder.h>
#include <secmod.h>
#include <secport.h>

#include <memory>

#include "base/debug/leak_annotations.h"
#include "base/logging.h"
#include "base/memory/singleton.h"
#include "base/numerics/safe_conversions.h"
#include "base/pickle.h"
#include "base/strings/stringprintf.h"
#include "crypto/ec_private_key.h"
#include "crypto/nss_util.h"
#include "crypto/nss_util_internal.h"
#include "crypto/rsa_private_key.h"
#include "crypto/scoped_nss_types.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/cert/x509_util_nss.h"

namespace net {

namespace {

// Microsoft User Principal Name: 1.3.6.1.4.1.311.20.2.3
const uint8_t kUpnOid[] = {0x2b, 0x6,  0x1,  0x4, 0x1,
                           0x82, 0x37, 0x14, 0x2, 0x3};

// Callback for CERT_DecodeCertPackage(), used in
// CreateOSCertHandlesFromBytes().
SECStatus PR_CALLBACK CollectCertsCallback(void* arg,
                                           SECItem** certs,
                                           int num_certs) {
  X509Certificate::OSCertHandles* results =
      reinterpret_cast<X509Certificate::OSCertHandles*>(arg);

  for (int i = 0; i < num_certs; ++i) {
    X509Certificate::OSCertHandle handle =
        X509Certificate::CreateOSCertHandleFromBytes(
            reinterpret_cast<char*>(certs[i]->data), certs[i]->len);
    if (handle)
      results->push_back(handle);
  }

  return SECSuccess;
}

typedef std::unique_ptr<CERTName,
                        crypto::NSSDestroyer<CERTName, CERT_DestroyName>>
    ScopedCERTName;

// Create a new CERTName object from its encoded representation.
// |arena| is the allocation pool to use.
// |data| points to a DER-encoded X.509 DistinguishedName.
// Return a new CERTName pointer on success, or NULL.
CERTName* CreateCertNameFromEncoded(PLArenaPool* arena,
                                    const base::StringPiece& data) {
  if (!arena)
    return NULL;

  ScopedCERTName name(PORT_ArenaZNew(arena, CERTName));
  if (!name.get())
    return NULL;

  SECItem item;
  item.len = static_cast<unsigned int>(data.length());
  item.data = reinterpret_cast<unsigned char*>(const_cast<char*>(data.data()));

  SECStatus rv = SEC_ASN1DecodeItem(arena, name.get(),
                                    SEC_ASN1_GET(CERT_NameTemplate), &item);
  if (rv != SECSuccess)
    return NULL;

  return name.release();
}

}  // namespace

namespace x509_util {

void ParsePrincipal(CERTName* name, CertPrincipal* principal) {
// Starting in NSS 3.15, CERTGetNameFunc takes a const CERTName* argument.
#if NSS_VMINOR >= 15
  typedef char* (*CERTGetNameFunc)(const CERTName* name);
#else
  typedef char* (*CERTGetNameFunc)(CERTName * name);
#endif

  // TODO(jcampan): add business_category and serial_number.
  // TODO(wtc): NSS has the CERT_GetOrgName, CERT_GetOrgUnitName, and
  // CERT_GetDomainComponentName functions, but they return only the most
  // general (the first) RDN.  NSS doesn't have a function for the street
  // address.
  static const SECOidTag kOIDs[] = {
      SEC_OID_AVA_STREET_ADDRESS, SEC_OID_AVA_ORGANIZATION_NAME,
      SEC_OID_AVA_ORGANIZATIONAL_UNIT_NAME, SEC_OID_AVA_DC};

  std::vector<std::string>* values[] = {
      &principal->street_addresses, &principal->organization_names,
      &principal->organization_unit_names, &principal->domain_components};
  DCHECK_EQ(arraysize(kOIDs), arraysize(values));

  CERTRDN** rdns = name->rdns;
  for (size_t rdn = 0; rdns[rdn]; ++rdn) {
    CERTAVA** avas = rdns[rdn]->avas;
    for (size_t pair = 0; avas[pair] != 0; ++pair) {
      SECOidTag tag = CERT_GetAVATag(avas[pair]);
      for (size_t oid = 0; oid < arraysize(kOIDs); ++oid) {
        if (kOIDs[oid] == tag) {
          SECItem* decode_item = CERT_DecodeAVAValue(&avas[pair]->value);
          if (!decode_item)
            break;
          // TODO(wtc): Pass decode_item to CERT_RFC1485_EscapeAndQuote.
          std::string value(reinterpret_cast<char*>(decode_item->data),
                            decode_item->len);
          values[oid]->push_back(value);
          SECITEM_FreeItem(decode_item, PR_TRUE);
          break;
        }
      }
    }
  }

  // Get CN, L, S, and C.
  CERTGetNameFunc get_name_funcs[4] = {CERT_GetCommonName, CERT_GetLocalityName,
                                       CERT_GetStateName, CERT_GetCountryName};
  std::string* single_values[4] = {
      &principal->common_name, &principal->locality_name,
      &principal->state_or_province_name, &principal->country_name};
  for (size_t i = 0; i < arraysize(get_name_funcs); ++i) {
    char* value = get_name_funcs[i](name);
    if (value) {
      single_values[i]->assign(value);
      PORT_Free(value);
    }
  }
}

void ParseDate(const SECItem* der_date, base::Time* result) {
  PRTime prtime;
  SECStatus rv = DER_DecodeTimeChoice(&prtime, der_date);
  DCHECK_EQ(SECSuccess, rv);
  *result = crypto::PRTimeToBaseTime(prtime);
}

std::string ParseSerialNumber(const CERTCertificate* certificate) {
  return std::string(reinterpret_cast<char*>(certificate->serialNumber.data),
                     certificate->serialNumber.len);
}

void GetSubjectAltName(CERTCertificate* cert_handle,
                       std::vector<std::string>* dns_names,
                       std::vector<std::string>* ip_addrs) {
  if (dns_names)
    dns_names->clear();
  if (ip_addrs)
    ip_addrs->clear();

  SECItem alt_name;
  SECStatus rv = CERT_FindCertExtension(
      cert_handle, SEC_OID_X509_SUBJECT_ALT_NAME, &alt_name);
  if (rv != SECSuccess)
    return;

  PLArenaPool* arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
  DCHECK(arena != NULL);

  CERTGeneralName* alt_name_list;
  alt_name_list = CERT_DecodeAltNameExtension(arena, &alt_name);
  SECITEM_FreeItem(&alt_name, PR_FALSE);

  CERTGeneralName* name = alt_name_list;
  while (name) {
    // DNSName and IPAddress are encoded as IA5String and OCTET STRINGs
    // respectively, both of which can be byte copied from
    // SECItemType::data into the appropriate output vector.
    if (dns_names && name->type == certDNSName) {
      dns_names->push_back(
          std::string(reinterpret_cast<char*>(name->name.other.data),
                      name->name.other.len));
    } else if (ip_addrs && name->type == certIPAddress) {
      ip_addrs->push_back(
          std::string(reinterpret_cast<char*>(name->name.other.data),
                      name->name.other.len));
    }
    name = CERT_GetNextGeneralName(name);
    if (name == alt_name_list)
      break;
  }
  PORT_FreeArena(arena, PR_FALSE);
}

void GetRFC822SubjectAltNames(CERTCertificate* cert_handle,
                              std::vector<std::string>* names) {
  crypto::ScopedSECItem alt_name(SECITEM_AllocItem(NULL, NULL, 0));
  DCHECK(alt_name.get());

  names->clear();
  SECStatus rv = CERT_FindCertExtension(
      cert_handle, SEC_OID_X509_SUBJECT_ALT_NAME, alt_name.get());
  if (rv != SECSuccess)
    return;

  crypto::ScopedPLArenaPool arena(PORT_NewArena(DER_DEFAULT_CHUNKSIZE));
  DCHECK(arena.get());

  CERTGeneralName* alt_name_list;
  alt_name_list = CERT_DecodeAltNameExtension(arena.get(), alt_name.get());

  CERTGeneralName* name = alt_name_list;
  while (name) {
    if (name->type == certRFC822Name) {
      names->push_back(
          std::string(reinterpret_cast<char*>(name->name.other.data),
                      name->name.other.len));
    }
    name = CERT_GetNextGeneralName(name);
    if (name == alt_name_list)
      break;
  }
}

void GetUPNSubjectAltNames(CERTCertificate* cert_handle,
                           std::vector<std::string>* names) {
  crypto::ScopedSECItem alt_name(SECITEM_AllocItem(NULL, NULL, 0));
  DCHECK(alt_name.get());

  names->clear();
  SECStatus rv = CERT_FindCertExtension(
      cert_handle, SEC_OID_X509_SUBJECT_ALT_NAME, alt_name.get());
  if (rv != SECSuccess)
    return;

  crypto::ScopedPLArenaPool arena(PORT_NewArena(DER_DEFAULT_CHUNKSIZE));
  DCHECK(arena.get());

  CERTGeneralName* alt_name_list;
  alt_name_list = CERT_DecodeAltNameExtension(arena.get(), alt_name.get());

  CERTGeneralName* name = alt_name_list;
  while (name) {
    if (name->type == certOtherName) {
      OtherName* on = &name->name.OthName;
      if (on->oid.len == sizeof(kUpnOid) &&
          memcmp(on->oid.data, kUpnOid, sizeof(kUpnOid)) == 0) {
        SECItem decoded;
        if (SEC_QuickDERDecodeItem(arena.get(), &decoded,
                                   SEC_ASN1_GET(SEC_UTF8StringTemplate),
                                   &name->name.OthName.name) == SECSuccess) {
          names->push_back(
              std::string(reinterpret_cast<char*>(decoded.data), decoded.len));
        }
      }
    }
    name = CERT_GetNextGeneralName(name);
    if (name == alt_name_list)
      break;
  }
}

X509Certificate::OSCertHandles CreateOSCertHandlesFromBytes(
    const char* data,
    size_t length,
    X509Certificate::Format format) {
  X509Certificate::OSCertHandles results;

  crypto::EnsureNSSInit();

  if (!NSS_IsInitialized())
    return results;

  switch (format) {
    case X509Certificate::FORMAT_SINGLE_CERTIFICATE: {
      X509Certificate::OSCertHandle handle =
          X509Certificate::CreateOSCertHandleFromBytes(data, length);
      if (handle)
        results.push_back(handle);
      break;
    }
    case X509Certificate::FORMAT_PKCS7: {
      // Make a copy since CERT_DecodeCertPackage may modify it
      std::vector<char> data_copy(data, data + length);

      SECStatus result = CERT_DecodeCertPackage(
          data_copy.data(), base::checked_cast<int>(data_copy.size()),
          CollectCertsCallback, &results);
      if (result != SECSuccess)
        results.clear();
      break;
    }
    default:
      NOTREACHED() << "Certificate format " << format << " unimplemented";
      break;
  }

  return results;
}

X509Certificate::OSCertHandle ReadOSCertHandleFromPickle(
    base::PickleIterator* pickle_iter) {
  const char* data;
  int length;
  if (!pickle_iter->ReadData(&data, &length))
    return NULL;

  return X509Certificate::CreateOSCertHandleFromBytes(data, length);
}

void GetPublicKeyInfo(CERTCertificate* handle,
                      size_t* size_bits,
                      X509Certificate::PublicKeyType* type) {
  // Since we might fail, set the output parameters to default values first.
  *type = X509Certificate::kPublicKeyTypeUnknown;
  *size_bits = 0;

  crypto::ScopedSECKEYPublicKey key(CERT_ExtractPublicKey(handle));
  if (!key.get())
    return;

  *size_bits = SECKEY_PublicKeyStrengthInBits(key.get());

  switch (key->keyType) {
    case rsaKey:
      *type = X509Certificate::kPublicKeyTypeRSA;
      break;
    case dsaKey:
      *type = X509Certificate::kPublicKeyTypeDSA;
      break;
    case dhKey:
      *type = X509Certificate::kPublicKeyTypeDH;
      break;
    case ecKey:
      *type = X509Certificate::kPublicKeyTypeECDSA;
      break;
    default:
      *type = X509Certificate::kPublicKeyTypeUnknown;
      *size_bits = 0;
      break;
  }
}

bool GetIssuersFromEncodedList(const std::vector<std::string>& encoded_issuers,
                               PLArenaPool* arena,
                               std::vector<CERTName*>* out) {
  std::vector<CERTName*> result;
  for (size_t n = 0; n < encoded_issuers.size(); ++n) {
    CERTName* name = CreateCertNameFromEncoded(arena, encoded_issuers[n]);
    if (name != NULL)
      result.push_back(name);
  }

  if (result.size() == encoded_issuers.size()) {
    out->swap(result);
    return true;
  }

  for (size_t n = 0; n < result.size(); ++n)
    CERT_DestroyName(result[n]);
  return false;
}

bool IsCertificateIssuedBy(const std::vector<CERTCertificate*>& cert_chain,
                           const std::vector<CERTName*>& valid_issuers) {
  for (size_t n = 0; n < cert_chain.size(); ++n) {
    CERTName* cert_issuer = &cert_chain[n]->issuer;
    for (size_t i = 0; i < valid_issuers.size(); ++i) {
      if (CERT_CompareName(valid_issuers[i], cert_issuer) == SECEqual)
        return true;
    }
  }
  return false;
}

std::string GetUniqueNicknameForSlot(const std::string& nickname,
                                     const SECItem* subject,
                                     PK11SlotInfo* slot) {
  int index = 2;
  std::string new_name = nickname;
  std::string temp_nickname = new_name;
  std::string token_name;

  if (!slot)
    return new_name;

  if (!PK11_IsInternalKeySlot(slot)) {
    token_name.assign(PK11_GetTokenName(slot));
    token_name.append(":");

    temp_nickname = token_name + new_name;
  }

  while (SEC_CertNicknameConflict(temp_nickname.c_str(),
                                  const_cast<SECItem*>(subject),
                                  CERT_GetDefaultCertDB())) {
    base::SStringPrintf(&new_name, "%s #%d", nickname.c_str(), index++);
    temp_nickname = token_name + new_name;
  }

  return new_name;
}

}  // namespace x509_util

}  // namespace net
