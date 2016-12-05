// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/android/early_trace_event_binding.h"

#include <stdint.h>

#include "base/android/jni_string.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "jni/EarlyTraceEvent_jni.h"

namespace base {
namespace android {

const char kEarlyJavaCategory[] = "EarlyJava";

static void RecordEarlyEvent(JNIEnv* env,
                             const JavaParamRef<jclass>& clazz,
                             const JavaParamRef<jstring>& jname,
                             jlong begin_time_ms,
                             jlong end_time_ms,
                             jint thread_id) {
  std::string name = ConvertJavaStringToUTF8(env, jname);
  int64_t begin_us = begin_time_ms * 1000;
  int64_t end_us = end_time_ms * 1000;

  INTERNAL_TRACE_EVENT_ADD_WITH_ID_TID_AND_TIMESTAMP(
      TRACE_EVENT_PHASE_BEGIN, kEarlyJavaCategory, name.c_str(),
      trace_event_internal::kNoId, thread_id,
      TimeTicks::FromInternalValue(begin_us), TRACE_EVENT_FLAG_COPY);
  INTERNAL_TRACE_EVENT_ADD_WITH_ID_TID_AND_TIMESTAMP(
      TRACE_EVENT_PHASE_END, kEarlyJavaCategory, name.c_str(),
      trace_event_internal::kNoId, thread_id,
      TimeTicks::FromInternalValue(end_us), TRACE_EVENT_FLAG_COPY);
}

bool RegisterEarlyTraceEvent(JNIEnv* env) {
  return RegisterNativesImpl(env);
}

}  // namespace android
}  // namespace base
