// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/memory_pressure_monitor_mac.h"

#include <dlfcn.h>
#include <stddef.h>
#include <sys/sysctl.h>

#include <cmath>

#include "base/bind.h"
#include "base/logging.h"
#include "base/mac/mac_util.h"

// Redeclare for partial 10.9 availability.
DISPATCH_EXPORT const struct dispatch_source_type_s
    _dispatch_source_type_memorypressure;

namespace base {
namespace mac {

MemoryPressureListener::MemoryPressureLevel
MemoryPressureMonitor::MemoryPressureLevelForMacMemoryPressure(
    int mac_memory_pressure) {
  switch (mac_memory_pressure) {
    case DISPATCH_MEMORYPRESSURE_NORMAL:
      return MemoryPressureListener::MEMORY_PRESSURE_LEVEL_NONE;
    case DISPATCH_MEMORYPRESSURE_WARN:
      return MemoryPressureListener::MEMORY_PRESSURE_LEVEL_MODERATE;
    case DISPATCH_MEMORYPRESSURE_CRITICAL:
      return MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL;
  }
  return MemoryPressureListener::MEMORY_PRESSURE_LEVEL_NONE;
}

MemoryPressureMonitor::MemoryPressureMonitor()
    : memory_level_event_source_(dispatch_source_create(
          DISPATCH_SOURCE_TYPE_MEMORYPRESSURE,
          0,
          DISPATCH_MEMORYPRESSURE_WARN | DISPATCH_MEMORYPRESSURE_CRITICAL |
              DISPATCH_MEMORYPRESSURE_NORMAL,
          dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0))),
      dispatch_callback_(
          base::Bind(&MemoryPressureListener::NotifyMemoryPressure)),
      last_pressure_change_(CFAbsoluteTimeGetCurrent()),
      reporting_error_(0) {
  last_pressure_level_ = GetCurrentPressureLevel();
  dispatch_source_set_event_handler(memory_level_event_source_, ^{
    OnMemoryPressureChanged(memory_level_event_source_.get(),
                            dispatch_callback_);
  });
  dispatch_resume(memory_level_event_source_);
}

MemoryPressureMonitor::~MemoryPressureMonitor() {
  dispatch_source_cancel(memory_level_event_source_);
}

MemoryPressureListener::MemoryPressureLevel
MemoryPressureMonitor::GetCurrentPressureLevel() const {
  int mac_memory_pressure;
  size_t length = sizeof(int);
  sysctlbyname("kern.memorystatus_vm_pressure_level", &mac_memory_pressure,
               &length, nullptr, 0);
  return MemoryPressureLevelForMacMemoryPressure(mac_memory_pressure);
}
void MemoryPressureMonitor::OnMemoryPressureChanged(
    dispatch_source_s* event_source,
    const MemoryPressureMonitor::DispatchCallback& dispatch_callback) {
  int mac_memory_pressure = dispatch_source_get_data(event_source);
  MemoryPressureListener::MemoryPressureLevel memory_pressure_level =
      MemoryPressureLevelForMacMemoryPressure(mac_memory_pressure);
  CFTimeInterval now = CFAbsoluteTimeGetCurrent();
  CFTimeInterval since_last_change = now - last_pressure_change_;
  last_pressure_change_ = now;

  double ticks_to_report;
  reporting_error_ =
      modf(since_last_change + reporting_error_, &ticks_to_report);

  // Sierra fails to call the handler when pressure returns to normal,
  // which would skew our data. For example, if pressure went to 'warn'
  // at T0, back to 'normal' at T1, then to 'critical' at T10, we would
  // report 10 ticks of 'warn' instead of 1 tick of 'warn' and 9 ticks
  // of 'normal'.
  // This is rdar://29114314
  if (mac::IsAtMostOS10_11())
    RecordMemoryPressure(last_pressure_level_,
                         static_cast<int>(ticks_to_report));

  last_pressure_level_ = memory_pressure_level;
  if (memory_pressure_level !=
      MemoryPressureListener::MEMORY_PRESSURE_LEVEL_NONE)
    dispatch_callback.Run(memory_pressure_level);
}

void MemoryPressureMonitor::SetDispatchCallback(
    const DispatchCallback& callback) {
  dispatch_callback_ = callback;
}

}  // namespace mac
}  // namespace base
