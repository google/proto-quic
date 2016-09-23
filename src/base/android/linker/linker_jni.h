// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is the Android-specific Chromium linker, a tiny shared library
// implementing a custom dynamic linker that can be used to load the
// real Chromium libraries.

// The main point of this linker is to be able to share the RELRO
// section of libcontentshell.so (or equivalent) between the browser and
// renderer process.

// This source code *cannot* depend on anything from base/ or the C++
// STL, to keep the final library small, and avoid ugly dependency issues.

#ifndef BASE_ANDROID_LINKER_LINKER_JNI_H_
#define BASE_ANDROID_LINKER_LINKER_JNI_H_

#include <android/log.h>
#include <jni.h>
#include <stddef.h>
#include <stdlib.h>

// Set this to 1 to enable debug traces to the Android log.
// Note that LOG() from "base/logging.h" cannot be used, since it is
// in base/ which hasn't been loaded yet.
#define DEBUG 0

#define TAG "cr_ChromiumAndroidLinker"

#if DEBUG
#define LOG_INFO(FORMAT, ...) \
    __android_log_print(ANDROID_LOG_INFO, TAG, \
                        "%s: " FORMAT, __FUNCTION__, ##__VA_ARGS__)
#else
#define LOG_INFO(FORMAT, ...) ((void)0)
#endif
#define LOG_ERROR(FORMAT, ...) \
    __android_log_print(ANDROID_LOG_ERROR, TAG, \
                        "%s: " FORMAT, __FUNCTION__, ##__VA_ARGS__)

#define UNUSED __attribute__((unused))

// See commentary in crazy_linker_elf_loader.cpp for the effect of setting
// this. If changing there, change here also.
//
// For more, see:
//   https://crbug.com/504410
#define RESERVE_BREAKPAD_GUARD_REGION 1

namespace chromium_android_linker {

// Larger than the largest library we might attempt to load.
static const size_t kAddressSpaceReservationSize = 192 * 1024 * 1024;

// Size of any Breakpad guard region. 16MB is comfortably larger than the
// ~6MB relocation packing of the current 64-bit libchrome.so, the largest we
// expect to encounter.
#if RESERVE_BREAKPAD_GUARD_REGION
static const size_t kBreakpadGuardRegionBytes = 16 * 1024 * 1024;
#endif

// A simple scoped UTF String class that can be initialized from
// a Java jstring handle. Modeled like std::string, which cannot
// be used here.
class String {
 public:
  String(JNIEnv* env, jstring str);

  inline ~String() { ::free(ptr_); }

  inline const char* c_str() const { return ptr_ ? ptr_ : ""; }
  inline size_t size() const { return size_; }

 private:
  char* ptr_;
  size_t size_;
};

// Return true iff |address| is a valid address for the target CPU.
inline bool IsValidAddress(jlong address) {
  return static_cast<jlong>(static_cast<size_t>(address)) == address;
}

// Find the jclass JNI reference corresponding to a given |class_name|.
// |env| is the current JNI environment handle.
// On success, return true and set |*clazz|.
extern bool InitClassReference(JNIEnv* env,
                               const char* class_name,
                               jclass* clazz);

// Initialize a jfieldID corresponding to the field of a given |clazz|,
// with name |field_name| and signature |field_sig|.
// |env| is the current JNI environment handle.
// On success, return true and set |*field_id|.
extern bool InitFieldId(JNIEnv* env,
                        jclass clazz,
                        const char* field_name,
                        const char* field_sig,
                        jfieldID* field_id);

// Initialize a jmethodID corresponding to the static method of a given
// |clazz|, with name |method_name| and signature |method_sig|.
// |env| is the current JNI environment handle.
// On success, return true and set |*method_id|.
extern bool InitStaticMethodId(JNIEnv* env,
                               jclass clazz,
                               const char* method_name,
                               const char* method_sig,
                               jmethodID* method_id);

// Initialize a jfieldID corresponding to the static field of a given |clazz|,
// with name |field_name| and signature |field_sig|.
// |env| is the current JNI environment handle.
// On success, return true and set |*field_id|.
extern bool InitStaticFieldId(JNIEnv* env,
                              jclass clazz,
                              const char* field_name,
                              const char* field_sig,
                              jfieldID* field_id);

// Initialize a jint corresponding to the static integer field of a class
// with class name |class_name| and field name |field_name|.
// |env| is the current JNI environment handle.
// On success, return true and set |*value|.
extern bool InitStaticInt(JNIEnv* env,
                          const char* class_name,
                          const char* field_name,
                          jint* value);

// Use Android ASLR to create a random library load address.
// |env| is the current JNI environment handle, and |clazz| a class.
// Returns the address selected by ASLR.
extern jlong GetRandomBaseLoadAddress(JNIEnv* env, jclass clazz);

// A class used to model the field IDs of the org.chromium.base.Linker
// LibInfo inner class, used to communicate data with the Java side
// of the linker.
struct LibInfo_class {
  jfieldID load_address_id;
  jfieldID load_size_id;
  jfieldID relro_start_id;
  jfieldID relro_size_id;
  jfieldID relro_fd_id;

  // Initialize an instance.
  bool Init(JNIEnv* env) {
    jclass clazz;
    if (!InitClassReference(
             env, "org/chromium/base/library_loader/Linker$LibInfo", &clazz)) {
      return false;
    }

    return InitFieldId(env, clazz, "mLoadAddress", "J", &load_address_id) &&
           InitFieldId(env, clazz, "mLoadSize", "J", &load_size_id) &&
           InitFieldId(env, clazz, "mRelroStart", "J", &relro_start_id) &&
           InitFieldId(env, clazz, "mRelroSize", "J", &relro_size_id) &&
           InitFieldId(env, clazz, "mRelroFd", "I", &relro_fd_id);
  }

  void SetLoadInfo(JNIEnv* env,
                   jobject library_info_obj,
                   size_t load_address,
                   size_t load_size) {
    env->SetLongField(library_info_obj, load_address_id, load_address);
    env->SetLongField(library_info_obj, load_size_id, load_size);
  }

  void SetRelroInfo(JNIEnv* env,
                    jobject library_info_obj,
                    size_t relro_start,
                    size_t relro_size,
                    int relro_fd) {
    env->SetLongField(library_info_obj, relro_start_id, relro_start);
    env->SetLongField(library_info_obj, relro_size_id, relro_size);
    env->SetIntField(library_info_obj, relro_fd_id, relro_fd);
  }

  // Use this instance to convert a RelroInfo reference into
  // a crazy_library_info_t.
  void GetRelroInfo(JNIEnv* env,
                    jobject library_info_obj,
                    size_t* relro_start,
                    size_t* relro_size,
                    int* relro_fd) {
    if (relro_start) {
      *relro_start = static_cast<size_t>(
          env->GetLongField(library_info_obj, relro_start_id));
    }

    if (relro_size) {
      *relro_size = static_cast<size_t>(
          env->GetLongField(library_info_obj, relro_size_id));
    }

    if (relro_fd) {
      *relro_fd = env->GetIntField(library_info_obj, relro_fd_id);
    }
  }
};

// Variable containing LibInfo for the loaded library.
extern LibInfo_class s_lib_info_fields;

}  // namespace chromium_android_linker

#endif  // BASE_ANDROID_LINKER_LINKER_JNI_H_
