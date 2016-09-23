// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/android/trace_event_binding.h"

#include <jni.h>

#include <set>

#include "base/android/jni_string.h"
#include "base/lazy_instance.h"
#include "base/macros.h"
#include "base/trace_event/trace_event.h"
#include "base/trace_event/trace_event_impl.h"
#include "jni/TraceEvent_jni.h"

namespace base {
namespace android {

namespace {

const char kJavaCategory[] = "Java";
const char kToplevelCategory[] = "toplevel";
const char kLooperDispatchMessage[] = "Looper.dispatchMessage";

// Boilerplate for safely converting Java data to TRACE_EVENT data.
class TraceEventDataConverter {
 public:
  TraceEventDataConverter(JNIEnv* env, jstring jname, jstring jarg)
      : name_(ConvertJavaStringToUTF8(env, jname)),
        has_arg_(jarg != nullptr),
        arg_(jarg ? ConvertJavaStringToUTF8(env, jarg) : "") {}
  ~TraceEventDataConverter() {
  }

  // Return saves values to pass to TRACE_EVENT macros.
  const char* name() { return name_.c_str(); }
  const char* arg_name() { return has_arg_ ? "arg" : nullptr; }
  const char* arg() { return has_arg_ ? arg_.c_str() : nullptr; }

 private:
  std::string name_;
  bool has_arg_;
  std::string arg_;

  DISALLOW_COPY_AND_ASSIGN(TraceEventDataConverter);
};

class TraceEnabledObserver
    : public trace_event::TraceLog::EnabledStateObserver {
  public:
   void OnTraceLogEnabled() override {
      JNIEnv* env = base::android::AttachCurrentThread();
      base::android::Java_TraceEvent_setEnabled(env, true);
    }
    void OnTraceLogDisabled() override {
      JNIEnv* env = base::android::AttachCurrentThread();
      base::android::Java_TraceEvent_setEnabled(env, false);
    }
};

base::LazyInstance<TraceEnabledObserver>::Leaky g_trace_enabled_state_observer_;

}  // namespace

static void RegisterEnabledObserver(JNIEnv* env,
                                    const JavaParamRef<jclass>& clazz) {
  bool enabled = trace_event::TraceLog::GetInstance()->IsEnabled();
  base::android::Java_TraceEvent_setEnabled(env, enabled);
  trace_event::TraceLog::GetInstance()->AddEnabledStateObserver(
      g_trace_enabled_state_observer_.Pointer());
}

static void StartATrace(JNIEnv* env, const JavaParamRef<jclass>& clazz) {
  base::trace_event::TraceLog::GetInstance()->StartATrace();
}

static void StopATrace(JNIEnv* env, const JavaParamRef<jclass>& clazz) {
  base::trace_event::TraceLog::GetInstance()->StopATrace();
}

static void Instant(JNIEnv* env,
                    const JavaParamRef<jclass>& clazz,
                    const JavaParamRef<jstring>& jname,
                    const JavaParamRef<jstring>& jarg) {
  TraceEventDataConverter converter(env, jname, jarg);
  if (converter.arg()) {
    TRACE_EVENT_COPY_INSTANT1(kJavaCategory, converter.name(),
                              TRACE_EVENT_SCOPE_THREAD,
                              converter.arg_name(), converter.arg());
  } else {
    TRACE_EVENT_COPY_INSTANT0(kJavaCategory, converter.name(),
                              TRACE_EVENT_SCOPE_THREAD);
  }
}

static void Begin(JNIEnv* env,
                  const JavaParamRef<jclass>& clazz,
                  const JavaParamRef<jstring>& jname,
                  const JavaParamRef<jstring>& jarg) {
  TraceEventDataConverter converter(env, jname, jarg);
  if (converter.arg()) {
    TRACE_EVENT_COPY_BEGIN1(kJavaCategory, converter.name(),
                       converter.arg_name(), converter.arg());
  } else {
    TRACE_EVENT_COPY_BEGIN0(kJavaCategory, converter.name());
  }
}

static void End(JNIEnv* env,
                const JavaParamRef<jclass>& clazz,
                const JavaParamRef<jstring>& jname,
                const JavaParamRef<jstring>& jarg) {
  TraceEventDataConverter converter(env, jname, jarg);
  if (converter.arg()) {
    TRACE_EVENT_COPY_END1(kJavaCategory, converter.name(),
                     converter.arg_name(), converter.arg());
  } else {
    TRACE_EVENT_COPY_END0(kJavaCategory, converter.name());
  }
}

static void BeginToplevel(JNIEnv* env, const JavaParamRef<jclass>& clazz) {
  TRACE_EVENT_BEGIN0(kToplevelCategory, kLooperDispatchMessage);
}

static void EndToplevel(JNIEnv* env, const JavaParamRef<jclass>& clazz) {
  TRACE_EVENT_END0(kToplevelCategory, kLooperDispatchMessage);
}

static void StartAsync(JNIEnv* env,
                       const JavaParamRef<jclass>& clazz,
                       const JavaParamRef<jstring>& jname,
                       jlong jid) {
  TraceEventDataConverter converter(env, jname, nullptr);
  TRACE_EVENT_COPY_ASYNC_BEGIN0(kJavaCategory, converter.name(), jid);
}

static void FinishAsync(JNIEnv* env,
                        const JavaParamRef<jclass>& clazz,
                        const JavaParamRef<jstring>& jname,
                        jlong jid) {
  TraceEventDataConverter converter(env, jname, nullptr);
  TRACE_EVENT_COPY_ASYNC_END0(kJavaCategory, converter.name(), jid);
}

bool RegisterTraceEvent(JNIEnv* env) {
  return RegisterNativesImpl(env);
}

}  // namespace android
}  // namespace base
