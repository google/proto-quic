// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/android/jni_array.h"

#include <stddef.h>
#include <stdint.h>

#include <limits>

#include "base/android/jni_android.h"
#include "base/android/scoped_java_ref.h"
#include "base/macros.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace android {

TEST(JniArray, BasicConversions) {
  const uint8_t kBytes[] = {0, 1, 2, 3};
  const size_t kLen = arraysize(kBytes);
  JNIEnv* env = AttachCurrentThread();
  ScopedJavaLocalRef<jbyteArray> bytes = ToJavaByteArray(env, kBytes, kLen);
  ASSERT_TRUE(bytes.obj());

  std::vector<uint8_t> inputVector(kBytes, kBytes + kLen);
  ScopedJavaLocalRef<jbyteArray> bytesFromVector =
      ToJavaByteArray(env, inputVector);
  ASSERT_TRUE(bytesFromVector.obj());

  std::vector<uint8_t> vectorFromBytes(5);
  std::vector<uint8_t> vectorFromVector(5);
  JavaByteArrayToByteVector(env, bytes.obj(), &vectorFromBytes);
  JavaByteArrayToByteVector(env, bytesFromVector.obj(), &vectorFromVector);
  EXPECT_EQ(4U, vectorFromBytes.size());
  EXPECT_EQ(4U, vectorFromVector.size());
  std::vector<uint8_t> expected_vec(kBytes, kBytes + kLen);
  EXPECT_EQ(expected_vec, vectorFromBytes);
  EXPECT_EQ(expected_vec, vectorFromVector);

  AppendJavaByteArrayToByteVector(env, bytes.obj(), &vectorFromBytes);
  EXPECT_EQ(8U, vectorFromBytes.size());
  expected_vec.insert(expected_vec.end(), kBytes, kBytes + kLen);
  EXPECT_EQ(expected_vec, vectorFromBytes);
}

void CheckIntConversion(
    JNIEnv* env,
    const int* int_array,
    const size_t len,
    const ScopedJavaLocalRef<jintArray>& ints) {
  ASSERT_TRUE(ints.obj());

  jsize java_array_len = env->GetArrayLength(ints.obj());
  ASSERT_EQ(static_cast<jsize>(len), java_array_len);

  jint value;
  for (size_t i = 0; i < len; ++i) {
    env->GetIntArrayRegion(ints.obj(), i, 1, &value);
    ASSERT_EQ(int_array[i], value);
  }
}

TEST(JniArray, IntConversions) {
  const int kInts[] = {0, 1, -1, std::numeric_limits<int32_t>::min(),
                       std::numeric_limits<int32_t>::max()};
  const size_t kLen = arraysize(kInts);

  JNIEnv* env = AttachCurrentThread();
  CheckIntConversion(env, kInts, kLen, ToJavaIntArray(env, kInts, kLen));

  const std::vector<int> vec(kInts, kInts + kLen);
  CheckIntConversion(env, kInts, kLen, ToJavaIntArray(env, vec));
}

void CheckLongConversion(JNIEnv* env,
                         const int64_t* long_array,
                         const size_t len,
                         const ScopedJavaLocalRef<jlongArray>& longs) {
  ASSERT_TRUE(longs.obj());

  jsize java_array_len = env->GetArrayLength(longs.obj());
  ASSERT_EQ(static_cast<jsize>(len), java_array_len);

  jlong value;
  for (size_t i = 0; i < len; ++i) {
    env->GetLongArrayRegion(longs.obj(), i, 1, &value);
    ASSERT_EQ(long_array[i], value);
  }
}

TEST(JniArray, LongConversions) {
  const int64_t kLongs[] = {0, 1, -1, std::numeric_limits<int64_t>::min(),
                            std::numeric_limits<int64_t>::max()};
  const size_t kLen = arraysize(kLongs);

  JNIEnv* env = AttachCurrentThread();
  CheckLongConversion(env, kLongs, kLen, ToJavaLongArray(env, kLongs, kLen));

  const std::vector<int64_t> vec(kLongs, kLongs + kLen);
  CheckLongConversion(env, kLongs, kLen, ToJavaLongArray(env, vec));
}

void CheckIntArrayConversion(JNIEnv* env,
                             ScopedJavaLocalRef<jintArray> jints,
                             std::vector<int> int_vector,
                             const size_t len) {
  jint value;
  for (size_t i = 0; i < len; ++i) {
    env->GetIntArrayRegion(jints.obj(), i, 1, &value);
    ASSERT_EQ(int_vector[i], value);
  }
}

void CheckFloatConversion(
    JNIEnv* env,
    const float* float_array,
    const size_t len,
    const ScopedJavaLocalRef<jfloatArray>& floats) {
  ASSERT_TRUE(floats.obj());

  jsize java_array_len = env->GetArrayLength(floats.obj());
  ASSERT_EQ(static_cast<jsize>(len), java_array_len);

  jfloat value;
  for (size_t i = 0; i < len; ++i) {
    env->GetFloatArrayRegion(floats.obj(), i, 1, &value);
    ASSERT_EQ(float_array[i], value);
  }
}

TEST(JniArray, FloatConversions) {
  const float kFloats[] = { 0.0f, 1.0f, -10.0f};
  const size_t kLen = arraysize(kFloats);

  JNIEnv* env = AttachCurrentThread();
  CheckFloatConversion(env, kFloats, kLen,
                       ToJavaFloatArray(env, kFloats, kLen));

  const std::vector<float> vec(kFloats, kFloats + kLen);
  CheckFloatConversion(env, kFloats, kLen, ToJavaFloatArray(env, vec));
}

TEST(JniArray, JavaIntArrayToIntVector) {
  const int kInts[] = {0, 1, -1};
  const size_t kLen = arraysize(kInts);

  JNIEnv* env = AttachCurrentThread();
  ScopedJavaLocalRef<jintArray> jints(env, env->NewIntArray(kLen));
  ASSERT_TRUE(jints.obj());

  for (size_t i = 0; i < kLen; ++i) {
    jint j = static_cast<jint>(kInts[i]);
    env->SetIntArrayRegion(jints.obj(), i, 1, &j);
    ASSERT_FALSE(HasException(env));
  }

  std::vector<int> ints;
  JavaIntArrayToIntVector(env, jints.obj(), &ints);

  ASSERT_EQ(static_cast<jsize>(ints.size()), env->GetArrayLength(jints.obj()));

  CheckIntArrayConversion(env, jints, ints, kLen);
}

TEST(JniArray, JavaLongArrayToInt64Vector) {
  const int64_t kInt64s[] = {0LL, 1LL, -1LL};
  const size_t kLen = arraysize(kInt64s);

  JNIEnv* env = AttachCurrentThread();
  ScopedJavaLocalRef<jlongArray> jlongs(env, env->NewLongArray(kLen));
  ASSERT_TRUE(jlongs.obj());

  for (size_t i = 0; i < kLen; ++i) {
    jlong j = static_cast<jlong>(kInt64s[i]);
    env->SetLongArrayRegion(jlongs.obj(), i, 1, &j);
    ASSERT_FALSE(HasException(env));
  }

  std::vector<int64_t> int64s;
  JavaLongArrayToInt64Vector(env, jlongs.obj(), &int64s);

  ASSERT_EQ(static_cast<jsize>(int64s.size()),
            env->GetArrayLength(jlongs.obj()));

  jlong value;
  for (size_t i = 0; i < kLen; ++i) {
    env->GetLongArrayRegion(jlongs.obj(), i, 1, &value);
    ASSERT_EQ(int64s[i], value);
    ASSERT_EQ(kInt64s[i], int64s[i]);
  }
}

TEST(JniArray, JavaLongArrayToLongVector) {
  const int64_t kInt64s[] = {0LL, 1LL, -1LL};
  const size_t kLen = arraysize(kInt64s);

  JNIEnv* env = AttachCurrentThread();
  ScopedJavaLocalRef<jlongArray> jlongs(env, env->NewLongArray(kLen));
  ASSERT_TRUE(jlongs.obj());

  for (size_t i = 0; i < kLen; ++i) {
    jlong j = static_cast<jlong>(kInt64s[i]);
    env->SetLongArrayRegion(jlongs.obj(), i, 1, &j);
    ASSERT_FALSE(HasException(env));
  }

  std::vector<jlong> jlongs_vector;
  JavaLongArrayToLongVector(env, jlongs.obj(), &jlongs_vector);

  ASSERT_EQ(static_cast<jsize>(jlongs_vector.size()),
            env->GetArrayLength(jlongs.obj()));

  jlong value;
  for (size_t i = 0; i < kLen; ++i) {
    env->GetLongArrayRegion(jlongs.obj(), i, 1, &value);
    ASSERT_EQ(jlongs_vector[i], value);
  }
}

TEST(JniArray, JavaFloatArrayToFloatVector) {
  const float kFloats[] = {0.0, 0.5, -0.5};
  const size_t kLen = arraysize(kFloats);

  JNIEnv* env = AttachCurrentThread();
  ScopedJavaLocalRef<jfloatArray> jfloats(env, env->NewFloatArray(kLen));
  ASSERT_TRUE(jfloats.obj());

  for (size_t i = 0; i < kLen; ++i) {
    jfloat j = static_cast<jfloat>(kFloats[i]);
    env->SetFloatArrayRegion(jfloats.obj(), i, 1, &j);
    ASSERT_FALSE(HasException(env));
  }

  std::vector<float> floats;
  JavaFloatArrayToFloatVector(env, jfloats.obj(), &floats);

  ASSERT_EQ(static_cast<jsize>(floats.size()),
      env->GetArrayLength(jfloats.obj()));

  jfloat value;
  for (size_t i = 0; i < kLen; ++i) {
    env->GetFloatArrayRegion(jfloats.obj(), i, 1, &value);
    ASSERT_EQ(floats[i], value);
  }
}

TEST(JniArray, JavaArrayOfByteArrayToStringVector) {
  const int kMaxItems = 50;
  JNIEnv* env = AttachCurrentThread();

  // Create a byte[][] object.
  ScopedJavaLocalRef<jclass> byte_array_clazz(env, env->FindClass("[B"));
  ASSERT_TRUE(byte_array_clazz.obj());

  ScopedJavaLocalRef<jobjectArray> array(
      env, env->NewObjectArray(kMaxItems, byte_array_clazz.obj(), NULL));
  ASSERT_TRUE(array.obj());

  // Create kMaxItems byte buffers.
  char text[16];
  for (int i = 0; i < kMaxItems; ++i) {
    snprintf(text, sizeof text, "%d", i);
    ScopedJavaLocalRef<jbyteArray> byte_array =
        ToJavaByteArray(env, reinterpret_cast<uint8_t*>(text),
                        static_cast<size_t>(strlen(text)));
    ASSERT_TRUE(byte_array.obj());

    env->SetObjectArrayElement(array.obj(), i, byte_array.obj());
    ASSERT_FALSE(HasException(env));
  }

  // Convert to std::vector<std::string>, check the content.
  std::vector<std::string> vec;
  JavaArrayOfByteArrayToStringVector(env, array.obj(), &vec);

  EXPECT_EQ(static_cast<size_t>(kMaxItems), vec.size());
  for (int i = 0; i < kMaxItems; ++i) {
    snprintf(text, sizeof text, "%d", i);
    EXPECT_STREQ(text, vec[i].c_str());
  }
}

TEST(JniArray, JavaArrayOfIntArrayToIntVector) {
  const size_t kNumItems = 4;
  JNIEnv* env = AttachCurrentThread();

  // Create an int[][] object.
  ScopedJavaLocalRef<jclass> int_array_clazz(env, env->FindClass("[I"));
  ASSERT_TRUE(int_array_clazz.obj());

  ScopedJavaLocalRef<jobjectArray> array(
      env, env->NewObjectArray(kNumItems, int_array_clazz.obj(), nullptr));
  ASSERT_TRUE(array.obj());

  // Populate int[][] object.
  const int kInts0[] = {0, 1, -1, std::numeric_limits<int32_t>::min(),
                        std::numeric_limits<int32_t>::max()};
  const size_t kLen0 = arraysize(kInts0);
  ScopedJavaLocalRef<jintArray> int_array0 = ToJavaIntArray(env, kInts0, kLen0);
  env->SetObjectArrayElement(array.obj(), 0, int_array0.obj());

  const int kInts1[] = {3, 4, 5};
  const size_t kLen1 = arraysize(kInts1);
  ScopedJavaLocalRef<jintArray> int_array1 = ToJavaIntArray(env, kInts1, kLen1);
  env->SetObjectArrayElement(array.obj(), 1, int_array1.obj());

  const int kInts2[] = {};
  const size_t kLen2 = 0;
  ScopedJavaLocalRef<jintArray> int_array2 = ToJavaIntArray(env, kInts2, kLen2);
  env->SetObjectArrayElement(array.obj(), 2, int_array2.obj());

  const int kInts3[] = {16};
  const size_t kLen3 = arraysize(kInts3);
  ScopedJavaLocalRef<jintArray> int_array3 = ToJavaIntArray(env, kInts3, kLen3);
  env->SetObjectArrayElement(array.obj(), 3, int_array3.obj());

  // Convert to std::vector<std::vector<int>>, check the content.
  std::vector<std::vector<int>> out;
  JavaArrayOfIntArrayToIntVector(env, array.obj(), &out);

  EXPECT_EQ(kNumItems, out.size());
  CheckIntArrayConversion(env, int_array0, out[0], kLen0);
  CheckIntArrayConversion(env, int_array1, out[1], kLen1);
  CheckIntArrayConversion(env, int_array2, out[2], kLen2);
  CheckIntArrayConversion(env, int_array3, out[3], kLen3);
}

}  // namespace android
}  // namespace base
