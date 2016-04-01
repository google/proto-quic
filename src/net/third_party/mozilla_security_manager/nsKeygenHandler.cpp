/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 *
 * ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is mozilla.org code.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1998
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Vipul Gupta <vipul.gupta@sun.com>
 *   Douglas Stebila <douglas@stebila.ca>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#include "net/third_party/mozilla_security_manager/nsKeygenHandler.h"

#include <pk11pub.h>
#include <prerror.h>   // PR_GetError()
#include <secmod.h>
#include <secder.h>    // DER_Encode()
#include <cryptohi.h>  // SEC_DerSignData()
#include <keyhi.h>     // SECKEY_CreateSubjectPublicKeyInfo()

#include "base/base64.h"
#include "base/logging.h"
#include "crypto/nss_util.h"
#include "url/gurl.h"

namespace {

// Template for creating the signed public key structure to be sent to the CA.
DERTemplate SECAlgorithmIDTemplate[] = {
  { DER_SEQUENCE,
    0, NULL, sizeof(SECAlgorithmID) },
  { DER_OBJECT_ID,
    offsetof(SECAlgorithmID, algorithm), },
  { DER_OPTIONAL | DER_ANY,
    offsetof(SECAlgorithmID, parameters), },
  { 0, }
};

DERTemplate CERTSubjectPublicKeyInfoTemplate[] = {
  { DER_SEQUENCE,
    0, NULL, sizeof(CERTSubjectPublicKeyInfo) },
  { DER_INLINE,
    offsetof(CERTSubjectPublicKeyInfo, algorithm),
    SECAlgorithmIDTemplate, },
  { DER_BIT_STRING,
    offsetof(CERTSubjectPublicKeyInfo, subjectPublicKey), },
  { 0, }
};

DERTemplate CERTPublicKeyAndChallengeTemplate[] = {
  { DER_SEQUENCE,
    0, NULL, sizeof(CERTPublicKeyAndChallenge) },
  { DER_ANY,
    offsetof(CERTPublicKeyAndChallenge, spki), },
  { DER_IA5_STRING,
    offsetof(CERTPublicKeyAndChallenge, challenge), },
  { 0, }
};

}  // namespace

namespace mozilla_security_manager {

// This function is based on the nsKeygenFormProcessor::GetPublicKey function
// in mozilla/security/manager/ssl/src/nsKeygenHandler.cpp.
std::string GenKeyAndSignChallenge(int key_size_in_bits,
                                   const std::string& challenge,
                                   const GURL& url,
                                   PK11SlotInfo* slot,
                                   bool stores_key) {
  // Key pair generation mechanism - only RSA is supported at present.
  PRUint32 keyGenMechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;  // from nss/pkcs11t.h

  // Temporary structures used for generating the result
  // in the right format.
  PK11RSAGenParams rsaKeyGenParams;  // Keygen parameters.
  SECOidTag algTag;  // used by SEC_DerSignData().
  SECKEYPrivateKey *privateKey = NULL;
  SECKEYPublicKey *publicKey = NULL;
  CERTSubjectPublicKeyInfo *spkInfo = NULL;
  PLArenaPool *arena = NULL;
  SECStatus sec_rv =SECFailure;
  SECItem spkiItem;
  SECItem pkacItem;
  SECItem signedItem;
  CERTPublicKeyAndChallenge pkac;
  void *keyGenParams;
  bool isSuccess = true;  // Set to false as soon as a step fails.

  std::string result_blob;  // the result.

  switch (keyGenMechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
      rsaKeyGenParams.keySizeInBits = key_size_in_bits;
      rsaKeyGenParams.pe = DEFAULT_RSA_KEYGEN_PE;
      keyGenParams = &rsaKeyGenParams;

      algTag = DEFAULT_RSA_KEYGEN_ALG;
      break;
    default:
      // TODO(gauravsh): If we ever support other mechanisms,
      // this can be changed.
      LOG(ERROR) << "Only RSA keygen mechanism is supported";
      isSuccess = false;
      goto failure;
  }

  VLOG(1) << "Creating key pair...";
  {
    crypto::AutoNSSWriteLock lock;
    privateKey = PK11_GenerateKeyPair(slot,
                                      keyGenMechanism,
                                      keyGenParams,
                                      &publicKey,
                                      PR_TRUE,  // isPermanent?
                                      PR_TRUE,  // isSensitive?
                                      NULL);
  }
  VLOG(1) << "done.";

  if (!privateKey) {
    LOG(ERROR) << "Generation of Keypair failed!";
    isSuccess = false;
    goto failure;
  }

  // Set friendly names for the keys.
  if (url.has_host()) {
    // TODO(davidben): Use something like "Key generated for
    // example.com", but localize it.
    const std::string& label = url.host();
    {
      crypto::AutoNSSWriteLock lock;
      PK11_SetPublicKeyNickname(publicKey, label.c_str());
      PK11_SetPrivateKeyNickname(privateKey, label.c_str());
    }
  }

  // The CA expects the signed public key in a specific format
  // Let's create that now.

  // Create a subject public key info from the public key.
  spkInfo = SECKEY_CreateSubjectPublicKeyInfo(publicKey);
  if (!spkInfo) {
    LOG(ERROR) << "Couldn't create SubjectPublicKeyInfo from public key";
    isSuccess = false;
    goto failure;
  }

  arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
  if (!arena) {
    LOG(ERROR) << "PORT_NewArena: Couldn't allocate memory";
    isSuccess = false;
    goto failure;
  }

  // DER encode the whole subjectPublicKeyInfo.
  sec_rv = DER_Encode(arena, &spkiItem, CERTSubjectPublicKeyInfoTemplate,
                      spkInfo);
  if (SECSuccess != sec_rv) {
    LOG(ERROR) << "Couldn't DER Encode subjectPublicKeyInfo";
    isSuccess = false;
    goto failure;
  }

  // Set up the PublicKeyAndChallenge data structure, then DER encode it.
  pkac.spki = spkiItem;
  pkac.challenge.type = siBuffer;
  pkac.challenge.len = challenge.length();
  pkac.challenge.data = (unsigned char *)challenge.data();
  sec_rv = DER_Encode(arena, &pkacItem, CERTPublicKeyAndChallengeTemplate,
                      &pkac);
  if (SECSuccess != sec_rv) {
    LOG(ERROR) << "Couldn't DER Encode PublicKeyAndChallenge";
    isSuccess = false;
    goto failure;
  }

  // Sign the DER encoded PublicKeyAndChallenge.
  sec_rv = SEC_DerSignData(arena, &signedItem, pkacItem.data, pkacItem.len,
                           privateKey, algTag);
  if (SECSuccess != sec_rv) {
    LOG(ERROR) << "Couldn't sign the DER encoded PublicKeyandChallenge";
    isSuccess = false;
    goto failure;
  }

  // Convert the signed public key and challenge into base64/ascii.
  base::Base64Encode(
      std::string(reinterpret_cast<char*>(signedItem.data), signedItem.len),
      &result_blob);

 failure:
  if (!isSuccess) {
    LOG(ERROR) << "SSL Keygen failed! (NSS error code " << PR_GetError() << ")";
  } else {
    VLOG(1) << "SSL Keygen succeeded!";
  }

  // Do cleanups
  if (privateKey) {
    // On successful keygen we need to keep the private key, of course,
    // or we won't be able to use the client certificate.
    if (!isSuccess || !stores_key) {
      crypto::AutoNSSWriteLock lock;
      PK11_DestroyTokenObject(privateKey->pkcs11Slot, privateKey->pkcs11ID);
    }
    SECKEY_DestroyPrivateKey(privateKey);
  }

  if (publicKey) {
    if (!isSuccess || !stores_key) {
      crypto::AutoNSSWriteLock lock;
      PK11_DestroyTokenObject(publicKey->pkcs11Slot, publicKey->pkcs11ID);
    }
    SECKEY_DestroyPublicKey(publicKey);
  }
  if (spkInfo) {
    SECKEY_DestroySubjectPublicKeyInfo(spkInfo);
  }
  if (arena) {
    PORT_FreeArena(arena, PR_TRUE);
  }

  return (isSuccess ? result_blob : std::string());
}

}  // namespace mozilla_security_manager
