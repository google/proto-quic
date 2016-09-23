// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/android/keystore.h"

#include <vector>

#include "base/android/jni_android.h"
#include "base/android/jni_array.h"
#include "base/logging.h"
#include "jni/AndroidKeyStore_jni.h"

using base::android::AttachCurrentThread;
using base::android::HasException;
using base::android::JavaArrayOfByteArrayToStringVector;
using base::android::JavaByteArrayToByteVector;
using base::android::JavaRef;
using base::android::ScopedJavaLocalRef;
using base::android::ToJavaByteArray;

namespace net {
namespace android {

bool GetRSAKeyModulus(const JavaRef<jobject>& private_key_ref,
                      std::vector<uint8_t>* result) {
  JNIEnv* env = AttachCurrentThread();

  ScopedJavaLocalRef<jbyteArray> modulus_ref =
      Java_AndroidKeyStore_getRSAKeyModulus(env, private_key_ref);
  if (modulus_ref.is_null())
    return false;

  JavaByteArrayToByteVector(env, modulus_ref.obj(), result);
  return true;
}

bool GetECKeyOrder(const JavaRef<jobject>& private_key_ref,
                   std::vector<uint8_t>* result) {
  JNIEnv* env = AttachCurrentThread();

  ScopedJavaLocalRef<jbyteArray> order_ref =
      Java_AndroidKeyStore_getECKeyOrder(env, private_key_ref);

  if (order_ref.is_null())
    return false;

  JavaByteArrayToByteVector(env, order_ref.obj(), result);
  return true;
}

bool RawSignDigestWithPrivateKey(const JavaRef<jobject>& private_key_ref,
                                 const base::StringPiece& digest,
                                 std::vector<uint8_t>* signature) {
  JNIEnv* env = AttachCurrentThread();

  // Convert message to byte[] array.
  ScopedJavaLocalRef<jbyteArray> digest_ref = ToJavaByteArray(
      env, reinterpret_cast<const uint8_t*>(digest.data()), digest.length());
  DCHECK(!digest_ref.is_null());

  // Invoke platform API
  ScopedJavaLocalRef<jbyteArray> signature_ref =
      Java_AndroidKeyStore_rawSignDigestWithPrivateKey(env, private_key_ref,
                                                       digest_ref);
  if (HasException(env) || signature_ref.is_null())
    return false;

  // Write signature to string.
  JavaByteArrayToByteVector(env, signature_ref.obj(), signature);
  return true;
}

PrivateKeyType GetPrivateKeyType(const JavaRef<jobject>& private_key_ref) {
  JNIEnv* env = AttachCurrentThread();
  int type = Java_AndroidKeyStore_getPrivateKeyType(env, private_key_ref);
  return static_cast<PrivateKeyType>(type);
}

AndroidEVP_PKEY* GetOpenSSLSystemHandleForPrivateKey(
    const JavaRef<jobject>& private_key_ref) {
  JNIEnv* env = AttachCurrentThread();
  // Note: the pointer is passed as a jint here because that's how it
  // is stored in the Java object. Java doesn't have a primitive type
  // like intptr_t that matches the size of pointers on the host
  // machine, and Android only runs on 32-bit CPUs.
  //
  // Given that this routine shall only be called on Android < 4.2,
  // this won't be a problem in the far future (e.g. when Android gets
  // ported to 64-bit environments, if ever).
  long pkey =
      Java_AndroidKeyStore_getOpenSSLHandleForPrivateKey(env, private_key_ref);
  return reinterpret_cast<AndroidEVP_PKEY*>(pkey);
}

ScopedJavaLocalRef<jobject> GetOpenSSLEngineForPrivateKey(
    const JavaRef<jobject>& private_key_ref) {
  JNIEnv* env = AttachCurrentThread();
  ScopedJavaLocalRef<jobject> engine =
      Java_AndroidKeyStore_getOpenSSLEngineForPrivateKey(env, private_key_ref);
  return engine;
}

}  // namespace android
}  // namespace net
