// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/des.h"

#include <openssl/des.h>

#include "base/logging.h"
#include "crypto/openssl_util.h"

// The iOS version of DESEncrypt is our own code.
// DESSetKeyParity and DESMakeKey are based on
// mozilla/security/manager/ssl/src/nsNTLMAuthModule.cpp, CVS rev. 1.14.

/* ***** BEGIN LICENSE BLOCK *****
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
 * The Original Code is Mozilla.
 *
 * The Initial Developer of the Original Code is IBM Corporation.
 * Portions created by IBM Corporation are Copyright (C) 2003
 * IBM Corporation. All Rights Reserved.
 *
 * Contributor(s):
 *   Darin Fisher <darin@meer.net>
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

// Set odd parity bit (in least significant bit position).
static uint8_t DESSetKeyParity(uint8_t x) {
  if ((((x >> 7) ^ (x >> 6) ^ (x >> 5) ^
        (x >> 4) ^ (x >> 3) ^ (x >> 2) ^
        (x >> 1)) & 0x01) == 0) {
    x |= 0x01;
  } else {
    x &= 0xfe;
  }
  return x;
}

namespace net {

void DESMakeKey(const uint8_t* raw, uint8_t* key) {
  key[0] = DESSetKeyParity(raw[0]);
  key[1] = DESSetKeyParity((raw[0] << 7) | (raw[1] >> 1));
  key[2] = DESSetKeyParity((raw[1] << 6) | (raw[2] >> 2));
  key[3] = DESSetKeyParity((raw[2] << 5) | (raw[3] >> 3));
  key[4] = DESSetKeyParity((raw[3] << 4) | (raw[4] >> 4));
  key[5] = DESSetKeyParity((raw[4] << 3) | (raw[5] >> 5));
  key[6] = DESSetKeyParity((raw[5] << 2) | (raw[6] >> 6));
  key[7] = DESSetKeyParity((raw[6] << 1));
}

void DESEncrypt(const uint8_t* key, const uint8_t* src, uint8_t* hash) {
  crypto::EnsureOpenSSLInit();

  DES_key_schedule ks;
  DES_set_key(
      reinterpret_cast<const DES_cblock*>(key), &ks);

  DES_ecb_encrypt(reinterpret_cast<const DES_cblock*>(src),
                  reinterpret_cast<DES_cblock*>(hash), &ks, DES_ENCRYPT);
}

}  // namespace net
