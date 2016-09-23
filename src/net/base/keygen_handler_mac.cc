// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/keygen_handler.h"

#include <Security/SecAsn1Coder.h>
#include <Security/SecAsn1Templates.h>
#include <Security/Security.h>

#include "base/base64.h"
#include "base/logging.h"
#include "base/mac/mac_logging.h"
#include "base/mac/scoped_cftyperef.h"
#include "base/strings/string_util.h"
#include "base/strings/sys_string_conversions.h"
#include "base/synchronization/lock.h"
#include "crypto/cssm_init.h"
#include "crypto/mac_security_services_lock.h"

// CSSM functions are deprecated as of OSX 10.7, but have no replacement.
// https://bugs.chromium.org/p/chromium/issues/detail?id=590914#c1
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// These are in Security.framework but not declared in a public header.
extern const SecAsn1Template kSecAsn1AlgorithmIDTemplate[];
extern const SecAsn1Template kSecAsn1SubjectPublicKeyInfoTemplate[];

namespace net {

// Declarations of Netscape keygen cert structures for ASN.1 encoding:

struct PublicKeyAndChallenge {
  CSSM_X509_SUBJECT_PUBLIC_KEY_INFO spki;
  CSSM_DATA challenge_string;
};

// This is a copy of the built-in kSecAsn1IA5StringTemplate, but without the
// 'streamable' flag, which was causing bogus data to be written.
const SecAsn1Template kIA5StringTemplate[] = {
    { SEC_ASN1_IA5_STRING, 0, NULL, sizeof(CSSM_DATA) }
};

static const SecAsn1Template kPublicKeyAndChallengeTemplate[] = {
  {
    SEC_ASN1_SEQUENCE,
    0,
    NULL,
    sizeof(PublicKeyAndChallenge)
  },
  {
    SEC_ASN1_INLINE,
    offsetof(PublicKeyAndChallenge, spki),
    kSecAsn1SubjectPublicKeyInfoTemplate
  },
  {
    SEC_ASN1_INLINE,
    offsetof(PublicKeyAndChallenge, challenge_string),
    kIA5StringTemplate
  },
  {
    0
  }
};

struct SignedPublicKeyAndChallenge {
  PublicKeyAndChallenge pkac;
  CSSM_X509_ALGORITHM_IDENTIFIER signature_algorithm;
  CSSM_DATA signature;
};

static const SecAsn1Template kSignedPublicKeyAndChallengeTemplate[] = {
  {
    SEC_ASN1_SEQUENCE,
    0,
    NULL,
    sizeof(SignedPublicKeyAndChallenge)
  },
  {
    SEC_ASN1_INLINE,
    offsetof(SignedPublicKeyAndChallenge, pkac),
    kPublicKeyAndChallengeTemplate
  },
  {
    SEC_ASN1_INLINE,
    offsetof(SignedPublicKeyAndChallenge, signature_algorithm),
    kSecAsn1AlgorithmIDTemplate
  },
  {
    SEC_ASN1_BIT_STRING,
    offsetof(SignedPublicKeyAndChallenge, signature)
  },
  {
    0
  }
};


static OSStatus CreateRSAKeyPair(int size_in_bits,
                                 SecAccessRef initial_access,
                                 SecKeyRef* out_pub_key,
                                 SecKeyRef* out_priv_key);
static OSStatus SignData(CSSM_DATA data,
                         SecKeyRef private_key,
                         CSSM_DATA* signature);

std::string KeygenHandler::GenKeyAndSignChallenge() {
  std::string result;
  OSStatus err;
  SecAccessRef initial_access = NULL;
  SecKeyRef public_key = NULL;
  SecKeyRef private_key = NULL;
  SecAsn1CoderRef coder = NULL;
  CSSM_DATA signature = {0, NULL};

  {
    if (url_.has_host()) {
      // TODO(davidben): Use something like "Key generated for
      // example.com", but localize it.
      base::ScopedCFTypeRef<CFStringRef> label(
          base::SysUTF8ToCFStringRef(url_.host()));
      // Create an initial access object to set the SecAccessRef. This
      // sets a label on the Keychain dialogs. Pass NULL as the second
      // argument to use the default trusted list; only allow the
      // current application to access without user confirmation.
      err = SecAccessCreate(label, NULL, &initial_access);
      // If we fail, just continue without a label.
      if (err)
        crypto::LogCSSMError("SecAccessCreate", err);
    }

    // Create the key-pair.
    err = CreateRSAKeyPair(key_size_in_bits_, initial_access,
                           &public_key, &private_key);
    if (err)
      goto failure;

    // Get the public key data (DER sequence of modulus, exponent).
    CFDataRef key_data = NULL;
    err = SecKeychainItemExport(public_key, kSecFormatBSAFE, 0, NULL,
                                &key_data);
    if (err) {
      crypto::LogCSSMError("SecKeychainItemExpor", err);
      goto failure;
    }
    base::ScopedCFTypeRef<CFDataRef> scoped_key_data(key_data);

    // Create an ASN.1 encoder.
    err = SecAsn1CoderCreate(&coder);
    if (err) {
      crypto::LogCSSMError("SecAsn1CoderCreate", err);
      goto failure;
    }

    // The DER encoding of a NULL.
    static const uint8_t kNullDer[] = {0x05, 0x00};

    // Fill in and DER-encode the PublicKeyAndChallenge:
    SignedPublicKeyAndChallenge spkac;
    memset(&spkac, 0, sizeof(spkac));
    spkac.pkac.spki.algorithm.algorithm = CSSMOID_RSA;
    spkac.pkac.spki.algorithm.parameters.Data = const_cast<uint8_t*>(kNullDer);
    spkac.pkac.spki.algorithm.parameters.Length = sizeof(kNullDer);
    spkac.pkac.spki.subjectPublicKey.Length =
        CFDataGetLength(key_data) * 8;  // interpreted as a _bit_ count
    spkac.pkac.spki.subjectPublicKey.Data =
        const_cast<uint8_t*>(CFDataGetBytePtr(key_data));
    spkac.pkac.challenge_string.Length = challenge_.length();
    spkac.pkac.challenge_string.Data =
        reinterpret_cast<uint8_t*>(const_cast<char*>(challenge_.data()));

    CSSM_DATA encoded;
    err = SecAsn1EncodeItem(coder, &spkac.pkac,
                            kPublicKeyAndChallengeTemplate, &encoded);
    if (err) {
      crypto::LogCSSMError("SecAsn1EncodeItem", err);
      goto failure;
    }

    // Compute a signature of the result:
    err = SignData(encoded, private_key, &signature);
    if (err)
      goto failure;
    spkac.signature.Data = signature.Data;
    spkac.signature.Length = signature.Length * 8;  // a _bit_ count
    spkac.signature_algorithm.algorithm = CSSMOID_MD5WithRSA;
    spkac.signature_algorithm.parameters.Data = const_cast<uint8_t*>(kNullDer);
    spkac.signature_algorithm.parameters.Length = sizeof(kNullDer);
    // TODO(snej): MD5 is weak. Can we use SHA1 instead?
    // See <https://bugzilla.mozilla.org/show_bug.cgi?id=549460>

    // DER-encode the entire SignedPublicKeyAndChallenge:
    err = SecAsn1EncodeItem(coder, &spkac,
                            kSignedPublicKeyAndChallengeTemplate, &encoded);
    if (err) {
      crypto::LogCSSMError("SecAsn1EncodeItem", err);
      goto failure;
    }

    // Base64 encode the result.
    std::string input(reinterpret_cast<char*>(encoded.Data), encoded.Length);
    base::Base64Encode(input, &result);
  }

 failure:
  if (err)
    OSSTATUS_LOG(ERROR, err) << "SSL Keygen failed!";
  else
    VLOG(1) << "SSL Keygen succeeded! Output is: " << result;

  // Remove keys from keychain if asked to during unit testing:
  if (!stores_key_) {
    if (public_key)
      SecKeychainItemDelete(reinterpret_cast<SecKeychainItemRef>(public_key));
    if (private_key)
      SecKeychainItemDelete(reinterpret_cast<SecKeychainItemRef>(private_key));
  }

  // Clean up:
  free(signature.Data);
  if (coder)
    SecAsn1CoderRelease(coder);
  if (initial_access)
    CFRelease(initial_access);
  if (public_key)
    CFRelease(public_key);
  if (private_key)
    CFRelease(private_key);
  return result;
}


// Create an RSA key pair with size |size_in_bits|. |initial_access|
// is passed as the initial access control list in Keychain. The
// public and private keys are placed in |out_pub_key| and
// |out_priv_key|, respectively.
static OSStatus CreateRSAKeyPair(int size_in_bits,
                                 SecAccessRef initial_access,
                                 SecKeyRef* out_pub_key,
                                 SecKeyRef* out_priv_key) {
  OSStatus err;
  SecKeychainRef keychain;
  err = SecKeychainCopyDefault(&keychain);
  if (err) {
    crypto::LogCSSMError("SecKeychainCopyDefault", err);
    return err;
  }
  base::ScopedCFTypeRef<SecKeychainRef> scoped_keychain(keychain);
  {
    base::AutoLock locked(crypto::GetMacSecurityServicesLock());
    err = SecKeyCreatePair(
        keychain,
        CSSM_ALGID_RSA,
        size_in_bits,
        0LL,
        // public key usage and attributes:
        CSSM_KEYUSE_ENCRYPT | CSSM_KEYUSE_VERIFY | CSSM_KEYUSE_WRAP,
        CSSM_KEYATTR_EXTRACTABLE | CSSM_KEYATTR_PERMANENT,
        // private key usage and attributes:
        CSSM_KEYUSE_DECRYPT | CSSM_KEYUSE_SIGN | CSSM_KEYUSE_UNWRAP,
        CSSM_KEYATTR_EXTRACTABLE | CSSM_KEYATTR_PERMANENT |
            CSSM_KEYATTR_SENSITIVE,
        initial_access,
        out_pub_key, out_priv_key);
  }
  if (err)
    crypto::LogCSSMError("SecKeyCreatePair", err);
  return err;
}

static OSStatus CreateSignatureContext(SecKeyRef key,
                                       CSSM_ALGORITHMS algorithm,
                                       CSSM_CC_HANDLE* out_cc_handle) {
  OSStatus err;
  const CSSM_ACCESS_CREDENTIALS* credentials = NULL;
  {
    base::AutoLock locked(crypto::GetMacSecurityServicesLock());
    err = SecKeyGetCredentials(key,
                               CSSM_ACL_AUTHORIZATION_SIGN,
                               kSecCredentialTypeDefault,
                               &credentials);
  }
  if (err) {
    crypto::LogCSSMError("SecKeyGetCredentials", err);
    return err;
  }

  CSSM_CSP_HANDLE csp_handle = 0;
  {
    base::AutoLock locked(crypto::GetMacSecurityServicesLock());
    err = SecKeyGetCSPHandle(key, &csp_handle);
  }
  if (err) {
    crypto::LogCSSMError("SecKeyGetCSPHandle", err);
    return err;
  }

  const CSSM_KEY* cssm_key = NULL;
  {
    base::AutoLock locked(crypto::GetMacSecurityServicesLock());
    err = SecKeyGetCSSMKey(key, &cssm_key);
  }
  if (err) {
    crypto::LogCSSMError("SecKeyGetCSSMKey", err);
    return err;
  }

  err = CSSM_CSP_CreateSignatureContext(csp_handle,
                                        algorithm,
                                        credentials,
                                        cssm_key,
                                        out_cc_handle);
  if (err)
    crypto::LogCSSMError("CSSM_CSP_CreateSignatureContext", err);
  return err;
}

static OSStatus SignData(CSSM_DATA data,
                         SecKeyRef private_key,
                         CSSM_DATA* signature) {
  CSSM_CC_HANDLE cc_handle;
  OSStatus err = CreateSignatureContext(private_key,
                                        CSSM_ALGID_MD5WithRSA,
                                        &cc_handle);
  if (err) {
    crypto::LogCSSMError("CreateSignatureContext", err);
    return err;
  }
  err = CSSM_SignData(cc_handle, &data, 1, CSSM_ALGID_NONE, signature);
  if (err)
    crypto::LogCSSMError("CSSM_SignData", err);
  CSSM_DeleteContext(cc_handle);
  return err;
}

}  // namespace net

#pragma clang diagnostic pop  // "-Wdeprecated-declarations"
