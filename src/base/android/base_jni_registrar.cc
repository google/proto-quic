// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/android/base_jni_registrar.h"

#include "base/android/animation_frame_time_histogram.h"
#include "base/android/application_status_listener.h"
#include "base/android/command_line_android.h"
#include "base/android/context_utils.h"
#include "base/android/cpu_features.h"
#include "base/android/early_trace_event_binding.h"
#include "base/android/field_trial_list.h"
#include "base/android/important_file_writer_android.h"
#include "base/android/java_handler_thread.h"
#include "base/android/jni_android.h"
#include "base/android/jni_registrar.h"
#include "base/android/memory_pressure_listener_android.h"
#include "base/android/path_service_android.h"
#include "base/android/record_histogram.h"
#include "base/android/record_user_action.h"
#include "base/android/trace_event_binding.h"
#include "base/macros.h"
#include "base/message_loop/message_pump_android.h"
#include "base/power_monitor/power_monitor_device_source_android.h"
#include "base/trace_event/trace_event.h"

namespace base {
namespace android {

static RegistrationMethod kBaseRegisteredMethods[] = {
    {"AnimationFrameTimeHistogram",
     base::android::RegisterAnimationFrameTimeHistogram},
    {"ApplicationStatusListener",
     base::android::ApplicationStatusListener::RegisterBindings},
    {"CommandLine", base::android::RegisterCommandLine},
    {"ContextUtils", base::android::RegisterContextUtils},
    {"CpuFeatures", base::android::RegisterCpuFeatures},
    {"EarlyTraceEvent", base::android::RegisterEarlyTraceEvent},
    {"FieldTrialList", base::android::RegisterFieldTrialList},
    {"ImportantFileWriterAndroid",
     base::android::RegisterImportantFileWriterAndroid},
    {"MemoryPressureListenerAndroid",
     base::android::MemoryPressureListenerAndroid::Register},
    {"JavaHandlerThread", base::android::JavaHandlerThread::RegisterBindings},
    {"PathService", base::android::RegisterPathService},
    {"PowerMonitor", base::RegisterPowerMonitor},
    {"RecordHistogram", base::android::RegisterRecordHistogram},
    {"RecordUserAction", base::android::RegisterRecordUserAction},
    {"SystemMessageHandler", base::MessagePumpForUI::RegisterBindings},
    {"TraceEvent", base::android::RegisterTraceEvent},
};

bool RegisterJni(JNIEnv* env) {
  TRACE_EVENT0("startup", "base_android::RegisterJni");
  return RegisterNativeMethods(env, kBaseRegisteredMethods,
                               arraysize(kBaseRegisteredMethods));
}

}  // namespace android
}  // namespace base
