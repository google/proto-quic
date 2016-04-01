// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/rsa_private_key.h"

#include <cryptohi.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <stdint.h>

#include <list>

#include "base/debug/leak_annotations.h"
#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_util.h"
#include "crypto/nss_key_util.h"
#include "crypto/nss_util.h"
#include "crypto/scoped_nss_types.h"

// Helper for error handling during key import.
#define READ_ASSERT(truth) \
  if (!(truth)) { \
    NOTREACHED(); \
    return false; \
  }

// TODO(rafaelw): Consider using NSS's ASN.1 encoder.
namespace {

static bool ReadAttribute(SECKEYPrivateKey* key,
                          CK_ATTRIBUTE_TYPE type,
                          std::vector<uint8_t>* output) {
  SECItem item;
  SECStatus rv;
  rv = PK11_ReadRawAttribute(PK11_TypePrivKey, key, type, &item);
  if (rv != SECSuccess) {
    NOTREACHED();
    return false;
  }

  output->assign(item.data, item.data + item.len);
  SECITEM_FreeItem(&item, PR_FALSE);
  return true;
}

// Used internally by RSAPrivateKey for serializing and deserializing
// PKCS #8 PrivateKeyInfo and PublicKeyInfo.
class PrivateKeyInfoCodec {
 public:
  // ASN.1 encoding of the AlgorithmIdentifier from PKCS #8.
  static const uint8_t kRsaAlgorithmIdentifier[];

  // ASN.1 tags for some types we use.
  static const uint8_t kBitStringTag = 0x03;
  static const uint8_t kIntegerTag = 0x02;
  static const uint8_t kOctetStringTag = 0x04;
  static const uint8_t kSequenceTag = 0x30;

  // |big_endian| here specifies the byte-significance of the integer components
  // that will be parsed & serialized (modulus(), etc...) during Import(),
  // Export() and ExportPublicKeyInfo() -- not the ASN.1 DER encoding of the
  // PrivateKeyInfo/PublicKeyInfo (which is always big-endian).
  explicit PrivateKeyInfoCodec(bool big_endian);

  ~PrivateKeyInfoCodec();

  // Exports the contents of the integer components to the ASN.1 DER encoding
  // of the PrivateKeyInfo structure to |output|.
  bool Export(std::vector<uint8_t>* output);

  // Exports the contents of the integer components to the ASN.1 DER encoding
  // of the PublicKeyInfo structure to |output|.
  bool ExportPublicKeyInfo(std::vector<uint8_t>* output);

  // Exports the contents of the integer components to the ASN.1 DER encoding
  // of the RSAPublicKey structure to |output|.
  bool ExportPublicKey(std::vector<uint8_t>* output);

  // Parses the ASN.1 DER encoding of the PrivateKeyInfo structure in |input|
  // and populates the integer components with |big_endian_| byte-significance.
  // IMPORTANT NOTE: This is currently *not* security-approved for importing
  // keys from unstrusted sources.
  bool Import(const std::vector<uint8_t>& input);

  // Accessors to the contents of the integer components of the PrivateKeyInfo
  // structure.
  std::vector<uint8_t>* modulus() { return &modulus_; }
  std::vector<uint8_t>* public_exponent() { return &public_exponent_; }
  std::vector<uint8_t>* private_exponent() { return &private_exponent_; }
  std::vector<uint8_t>* prime1() { return &prime1_; }
  std::vector<uint8_t>* prime2() { return &prime2_; }
  std::vector<uint8_t>* exponent1() { return &exponent1_; }
  std::vector<uint8_t>* exponent2() { return &exponent2_; }
  std::vector<uint8_t>* coefficient() { return &coefficient_; }

 private:
  // Utility wrappers for PrependIntegerImpl that use the class's |big_endian_|
  // value.
  void PrependInteger(const std::vector<uint8_t>& in, std::list<uint8_t>* out);
  void PrependInteger(uint8_t* val, int num_bytes, std::list<uint8_t>* data);

  // Prepends the integer stored in |val| - |val + num_bytes| with |big_endian|
  // byte-significance into |data| as an ASN.1 integer.
  void PrependIntegerImpl(uint8_t* val,
                          int num_bytes,
                          std::list<uint8_t>* data,
                          bool big_endian);

  // Utility wrappers for ReadIntegerImpl that use the class's |big_endian_|
  // value.
  bool ReadInteger(uint8_t** pos, uint8_t* end, std::vector<uint8_t>* out);
  bool ReadIntegerWithExpectedSize(uint8_t** pos,
                                   uint8_t* end,
                                   size_t expected_size,
                                   std::vector<uint8_t>* out);

  // Reads an ASN.1 integer from |pos|, and stores the result into |out| with
  // |big_endian| byte-significance.
  bool ReadIntegerImpl(uint8_t** pos,
                       uint8_t* end,
                       std::vector<uint8_t>* out,
                       bool big_endian);

  // Prepends the integer stored in |val|, starting a index |start|, for
  // |num_bytes| bytes onto |data|.
  void PrependBytes(uint8_t* val,
                    int start,
                    int num_bytes,
                    std::list<uint8_t>* data);

  // Helper to prepend an ASN.1 length field.
  void PrependLength(size_t size, std::list<uint8_t>* data);

  // Helper to prepend an ASN.1 type header.
  void PrependTypeHeaderAndLength(uint8_t type,
                                  uint32_t length,
                                  std::list<uint8_t>* output);

  // Helper to prepend an ASN.1 bit string
  void PrependBitString(uint8_t* val,
                        int num_bytes,
                        std::list<uint8_t>* output);

  // Read an ASN.1 length field. This also checks that the length does not
  // extend beyond |end|.
  bool ReadLength(uint8_t** pos, uint8_t* end, uint32_t* result);

  // Read an ASN.1 type header and its length.
  bool ReadTypeHeaderAndLength(uint8_t** pos,
                               uint8_t* end,
                               uint8_t expected_tag,
                               uint32_t* length);

  // Read an ASN.1 sequence declaration. This consumes the type header and
  // length field, but not the contents of the sequence.
  bool ReadSequence(uint8_t** pos, uint8_t* end);

  // Read the RSA AlgorithmIdentifier.
  bool ReadAlgorithmIdentifier(uint8_t** pos, uint8_t* end);

  // Read one of the two version fields in PrivateKeyInfo.
  bool ReadVersion(uint8_t** pos, uint8_t* end);

  // The byte-significance of the stored components (modulus, etc..).
  bool big_endian_;

  // Component integers of the PrivateKeyInfo
  std::vector<uint8_t> modulus_;
  std::vector<uint8_t> public_exponent_;
  std::vector<uint8_t> private_exponent_;
  std::vector<uint8_t> prime1_;
  std::vector<uint8_t> prime2_;
  std::vector<uint8_t> exponent1_;
  std::vector<uint8_t> exponent2_;
  std::vector<uint8_t> coefficient_;

  DISALLOW_COPY_AND_ASSIGN(PrivateKeyInfoCodec);
};

const uint8_t PrivateKeyInfoCodec::kRsaAlgorithmIdentifier[] = {
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00};

PrivateKeyInfoCodec::PrivateKeyInfoCodec(bool big_endian)
    : big_endian_(big_endian) {}

PrivateKeyInfoCodec::~PrivateKeyInfoCodec() {}

bool PrivateKeyInfoCodec::Export(std::vector<uint8_t>* output) {
  std::list<uint8_t> content;

  // Version (always zero)
  uint8_t version = 0;

  PrependInteger(coefficient_, &content);
  PrependInteger(exponent2_, &content);
  PrependInteger(exponent1_, &content);
  PrependInteger(prime2_, &content);
  PrependInteger(prime1_, &content);
  PrependInteger(private_exponent_, &content);
  PrependInteger(public_exponent_, &content);
  PrependInteger(modulus_, &content);
  PrependInteger(&version, 1, &content);
  PrependTypeHeaderAndLength(kSequenceTag, content.size(), &content);
  PrependTypeHeaderAndLength(kOctetStringTag, content.size(), &content);

  // RSA algorithm OID
  for (size_t i = sizeof(kRsaAlgorithmIdentifier); i > 0; --i)
    content.push_front(kRsaAlgorithmIdentifier[i - 1]);

  PrependInteger(&version, 1, &content);
  PrependTypeHeaderAndLength(kSequenceTag, content.size(), &content);

  // Copy everying into the output.
  output->reserve(content.size());
  output->assign(content.begin(), content.end());

  return true;
}

bool PrivateKeyInfoCodec::ExportPublicKeyInfo(std::vector<uint8_t>* output) {
  // Create a sequence with the modulus (n) and public exponent (e).
  std::vector<uint8_t> bit_string;
  if (!ExportPublicKey(&bit_string))
    return false;

  // Add the sequence as the contents of a bit string.
  std::list<uint8_t> content;
  PrependBitString(&bit_string[0], static_cast<int>(bit_string.size()),
                   &content);

  // Add the RSA algorithm OID.
  for (size_t i = sizeof(kRsaAlgorithmIdentifier); i > 0; --i)
    content.push_front(kRsaAlgorithmIdentifier[i - 1]);

  // Finally, wrap everything in a sequence.
  PrependTypeHeaderAndLength(kSequenceTag, content.size(), &content);

  // Copy everything into the output.
  output->reserve(content.size());
  output->assign(content.begin(), content.end());

  return true;
}

bool PrivateKeyInfoCodec::ExportPublicKey(std::vector<uint8_t>* output) {
  // Create a sequence with the modulus (n) and public exponent (e).
  std::list<uint8_t> content;
  PrependInteger(&public_exponent_[0],
                 static_cast<int>(public_exponent_.size()),
                 &content);
  PrependInteger(&modulus_[0],  static_cast<int>(modulus_.size()), &content);
  PrependTypeHeaderAndLength(kSequenceTag, content.size(), &content);

  // Copy everything into the output.
  output->reserve(content.size());
  output->assign(content.begin(), content.end());

  return true;
}

bool PrivateKeyInfoCodec::Import(const std::vector<uint8_t>& input) {
  if (input.empty()) {
    return false;
  }

  // Parse the private key info up to the public key values, ignoring
  // the subsequent private key values.
  uint8_t* src = const_cast<uint8_t*>(&input.front());
  uint8_t* end = src + input.size();
  if (!ReadSequence(&src, end) ||
      !ReadVersion(&src, end) ||
      !ReadAlgorithmIdentifier(&src, end) ||
      !ReadTypeHeaderAndLength(&src, end, kOctetStringTag, NULL) ||
      !ReadSequence(&src, end) ||
      !ReadVersion(&src, end) ||
      !ReadInteger(&src, end, &modulus_))
    return false;

  int mod_size = modulus_.size();
  READ_ASSERT(mod_size % 2 == 0);
  int primes_size = mod_size / 2;

  if (!ReadIntegerWithExpectedSize(&src, end, 4, &public_exponent_) ||
      !ReadIntegerWithExpectedSize(&src, end, mod_size, &private_exponent_) ||
      !ReadIntegerWithExpectedSize(&src, end, primes_size, &prime1_) ||
      !ReadIntegerWithExpectedSize(&src, end, primes_size, &prime2_) ||
      !ReadIntegerWithExpectedSize(&src, end, primes_size, &exponent1_) ||
      !ReadIntegerWithExpectedSize(&src, end, primes_size, &exponent2_) ||
      !ReadIntegerWithExpectedSize(&src, end, primes_size, &coefficient_))
    return false;

  READ_ASSERT(src == end);


  return true;
}

void PrivateKeyInfoCodec::PrependInteger(const std::vector<uint8_t>& in,
                                         std::list<uint8_t>* out) {
  uint8_t* ptr = const_cast<uint8_t*>(&in.front());
  PrependIntegerImpl(ptr, in.size(), out, big_endian_);
}

// Helper to prepend an ASN.1 integer.
void PrivateKeyInfoCodec::PrependInteger(uint8_t* val,
                                         int num_bytes,
                                         std::list<uint8_t>* data) {
  PrependIntegerImpl(val, num_bytes, data, big_endian_);
}

void PrivateKeyInfoCodec::PrependIntegerImpl(uint8_t* val,
                                             int num_bytes,
                                             std::list<uint8_t>* data,
                                             bool big_endian) {
 // Reverse input if little-endian.
 std::vector<uint8_t> tmp;
 if (!big_endian) {
   tmp.assign(val, val + num_bytes);
   std::reverse(tmp.begin(), tmp.end());
   val = &tmp.front();
 }

  // ASN.1 integers are unpadded byte arrays, so skip any null padding bytes
  // from the most-significant end of the integer.
  int start = 0;
  while (start < (num_bytes - 1) && val[start] == 0x00) {
    start++;
    num_bytes--;
  }
  PrependBytes(val, start, num_bytes, data);

  // ASN.1 integers are signed. To encode a positive integer whose sign bit
  // (the most significant bit) would otherwise be set and make the number
  // negative, ASN.1 requires a leading null byte to force the integer to be
  // positive.
  uint8_t front = data->front();
  if ((front & 0x80) != 0) {
    data->push_front(0x00);
    num_bytes++;
  }

  PrependTypeHeaderAndLength(kIntegerTag, num_bytes, data);
}

bool PrivateKeyInfoCodec::ReadInteger(uint8_t** pos,
                                      uint8_t* end,
                                      std::vector<uint8_t>* out) {
  return ReadIntegerImpl(pos, end, out, big_endian_);
}

bool PrivateKeyInfoCodec::ReadIntegerWithExpectedSize(
    uint8_t** pos,
    uint8_t* end,
    size_t expected_size,
    std::vector<uint8_t>* out) {
  std::vector<uint8_t> temp;
  if (!ReadIntegerImpl(pos, end, &temp, true))  // Big-Endian
    return false;

  int pad = expected_size - temp.size();
  int index = 0;
  if (out->size() == expected_size + 1) {
    READ_ASSERT(out->front() == 0x00);
    pad++;
    index++;
  } else {
    READ_ASSERT(out->size() <= expected_size);
  }

  out->insert(out->end(), pad, 0x00);
  out->insert(out->end(), temp.begin(), temp.end());

  // Reverse output if little-endian.
  if (!big_endian_)
    std::reverse(out->begin(), out->end());
  return true;
}

bool PrivateKeyInfoCodec::ReadIntegerImpl(uint8_t** pos,
                                          uint8_t* end,
                                          std::vector<uint8_t>* out,
                                          bool big_endian) {
  uint32_t length = 0;
  if (!ReadTypeHeaderAndLength(pos, end, kIntegerTag, &length) || !length)
    return false;

  // The first byte can be zero to force positiveness. We can ignore this.
  if (**pos == 0x00) {
    ++(*pos);
    --length;
  }

  if (length)
    out->insert(out->end(), *pos, (*pos) + length);

  (*pos) += length;

  // Reverse output if little-endian.
  if (!big_endian)
    std::reverse(out->begin(), out->end());
  return true;
}

void PrivateKeyInfoCodec::PrependBytes(uint8_t* val,
                                       int start,
                                       int num_bytes,
                                       std::list<uint8_t>* data) {
  while (num_bytes > 0) {
    --num_bytes;
    data->push_front(val[start + num_bytes]);
  }
}

void PrivateKeyInfoCodec::PrependLength(size_t size, std::list<uint8_t>* data) {
  // The high bit is used to indicate whether additional octets are needed to
  // represent the length.
  if (size < 0x80) {
    data->push_front(static_cast<uint8_t>(size));
  } else {
    uint8_t num_bytes = 0;
    while (size > 0) {
      data->push_front(static_cast<uint8_t>(size & 0xFF));
      size >>= 8;
      num_bytes++;
    }
    CHECK_LE(num_bytes, 4);
    data->push_front(0x80 | num_bytes);
  }
}

void PrivateKeyInfoCodec::PrependTypeHeaderAndLength(
    uint8_t type,
    uint32_t length,
    std::list<uint8_t>* output) {
  PrependLength(length, output);
  output->push_front(type);
}

void PrivateKeyInfoCodec::PrependBitString(uint8_t* val,
                                           int num_bytes,
                                           std::list<uint8_t>* output) {
  // Start with the data.
  PrependBytes(val, 0, num_bytes, output);
  // Zero unused bits.
  output->push_front(0);
  // Add the length.
  PrependLength(num_bytes + 1, output);
  // Finally, add the bit string tag.
  output->push_front((uint8_t)kBitStringTag);
}

bool PrivateKeyInfoCodec::ReadLength(uint8_t** pos,
                                     uint8_t* end,
                                     uint32_t* result) {
  READ_ASSERT(*pos < end);
  int length = 0;

  // If the MSB is not set, the length is just the byte itself.
  if (!(**pos & 0x80)) {
    length = **pos;
    (*pos)++;
  } else {
    // Otherwise, the lower 7 indicate the length of the length.
    int length_of_length = **pos & 0x7F;
    READ_ASSERT(length_of_length <= 4);
    (*pos)++;
    READ_ASSERT(*pos + length_of_length < end);

    length = 0;
    for (int i = 0; i < length_of_length; ++i) {
      length <<= 8;
      length |= **pos;
      (*pos)++;
    }
  }

  READ_ASSERT(*pos + length <= end);
  if (result) *result = length;
  return true;
}

bool PrivateKeyInfoCodec::ReadTypeHeaderAndLength(uint8_t** pos,
                                                  uint8_t* end,
                                                  uint8_t expected_tag,
                                                  uint32_t* length) {
  READ_ASSERT(*pos < end);
  READ_ASSERT(**pos == expected_tag);
  (*pos)++;

  return ReadLength(pos, end, length);
}

bool PrivateKeyInfoCodec::ReadSequence(uint8_t** pos, uint8_t* end) {
  return ReadTypeHeaderAndLength(pos, end, kSequenceTag, NULL);
}

bool PrivateKeyInfoCodec::ReadAlgorithmIdentifier(uint8_t** pos, uint8_t* end) {
  READ_ASSERT(*pos + sizeof(kRsaAlgorithmIdentifier) < end);
  READ_ASSERT(memcmp(*pos, kRsaAlgorithmIdentifier,
                     sizeof(kRsaAlgorithmIdentifier)) == 0);
  (*pos) += sizeof(kRsaAlgorithmIdentifier);
  return true;
}

bool PrivateKeyInfoCodec::ReadVersion(uint8_t** pos, uint8_t* end) {
  uint32_t length = 0;
  if (!ReadTypeHeaderAndLength(pos, end, kIntegerTag, &length))
    return false;

  // The version should be zero.
  for (uint32_t i = 0; i < length; ++i) {
    READ_ASSERT(**pos == 0x00);
    (*pos)++;
  }

  return true;
}

}  // namespace

namespace crypto {

RSAPrivateKey::~RSAPrivateKey() {
  if (key_)
    SECKEY_DestroyPrivateKey(key_);
  if (public_key_)
    SECKEY_DestroyPublicKey(public_key_);
}

// static
RSAPrivateKey* RSAPrivateKey::Create(uint16_t num_bits) {
  EnsureNSSInit();

  ScopedPK11Slot slot(PK11_GetInternalSlot());
  if (!slot) {
    NOTREACHED();
    return nullptr;
  }

  ScopedSECKEYPublicKey public_key;
  ScopedSECKEYPrivateKey private_key;
  if (!GenerateRSAKeyPairNSS(slot.get(), num_bits, false /* not permanent */,
                             &public_key, &private_key)) {
    return nullptr;
  }

  RSAPrivateKey* rsa_key = new RSAPrivateKey;
  rsa_key->public_key_ = public_key.release();
  rsa_key->key_ = private_key.release();
  return rsa_key;
}

// static
RSAPrivateKey* RSAPrivateKey::CreateFromPrivateKeyInfo(
    const std::vector<uint8_t>& input) {
  EnsureNSSInit();

  ScopedPK11Slot slot(PK11_GetInternalSlot());
  if (!slot) {
    NOTREACHED();
    return nullptr;
  }
  ScopedSECKEYPrivateKey key(ImportNSSKeyFromPrivateKeyInfo(
      slot.get(), input, false /* not permanent */));
  if (!key || SECKEY_GetPrivateKeyType(key.get()) != rsaKey)
    return nullptr;
  return RSAPrivateKey::CreateFromKey(key.get());
}

// static
RSAPrivateKey* RSAPrivateKey::CreateFromKey(SECKEYPrivateKey* key) {
  DCHECK(key);
  if (SECKEY_GetPrivateKeyType(key) != rsaKey)
    return NULL;
  RSAPrivateKey* copy = new RSAPrivateKey();
  copy->key_ = SECKEY_CopyPrivateKey(key);
  copy->public_key_ = SECKEY_ConvertToPublicKey(key);
  if (!copy->key_ || !copy->public_key_) {
    NOTREACHED();
    delete copy;
    return NULL;
  }
  return copy;
}

RSAPrivateKey* RSAPrivateKey::Copy() const {
  RSAPrivateKey* copy = new RSAPrivateKey();
  copy->key_ = SECKEY_CopyPrivateKey(key_);
  copy->public_key_ = SECKEY_CopyPublicKey(public_key_);
  return copy;
}

bool RSAPrivateKey::ExportPrivateKey(std::vector<uint8_t>* output) const {
  PrivateKeyInfoCodec private_key_info(true);

  // Manually read the component attributes of the private key and build up
  // the PrivateKeyInfo.
  if (!ReadAttribute(key_, CKA_MODULUS, private_key_info.modulus()) ||
      !ReadAttribute(key_, CKA_PUBLIC_EXPONENT,
          private_key_info.public_exponent()) ||
      !ReadAttribute(key_, CKA_PRIVATE_EXPONENT,
          private_key_info.private_exponent()) ||
      !ReadAttribute(key_, CKA_PRIME_1, private_key_info.prime1()) ||
      !ReadAttribute(key_, CKA_PRIME_2, private_key_info.prime2()) ||
      !ReadAttribute(key_, CKA_EXPONENT_1, private_key_info.exponent1()) ||
      !ReadAttribute(key_, CKA_EXPONENT_2, private_key_info.exponent2()) ||
      !ReadAttribute(key_, CKA_COEFFICIENT, private_key_info.coefficient())) {
    NOTREACHED();
    return false;
  }

  return private_key_info.Export(output);
}

bool RSAPrivateKey::ExportPublicKey(std::vector<uint8_t>* output) const {
  ScopedSECItem der_pubkey(SECKEY_EncodeDERSubjectPublicKeyInfo(public_key_));
  if (!der_pubkey.get()) {
    NOTREACHED();
    return false;
  }

  output->assign(der_pubkey->data, der_pubkey->data + der_pubkey->len);
  return true;
}

RSAPrivateKey::RSAPrivateKey() : key_(NULL), public_key_(NULL) {
  EnsureNSSInit();
}

}  // namespace crypto
