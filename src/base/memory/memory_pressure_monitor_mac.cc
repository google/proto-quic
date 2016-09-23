// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/memory_pressure_monitor_mac.h"

#include <dlfcn.h>
#include <stddef.h>
#include <sys/sysctl.h>

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

void MemoryPressureMonitor::NotifyMemoryPressureChanged(
    dispatch_source_s* event_source,
    const MemoryPressureMonitor::DispatchCallback& dispatch_callback) {
  int mac_memory_pressure = dispatch_source_get_data(event_source);
  MemoryPressureListener::MemoryPressureLevel memory_pressure_level =
      MemoryPressureLevelForMacMemoryPressure(mac_memory_pressure);
  dispatch_callback.Run(memory_pressure_level);
}

MemoryPressureMonitor::MemoryPressureMonitor()
    // The MemoryPressureListener doesn't want to know about transitions to
    // MEMORY_PRESSURE_LEVEL_NONE so don't watch for
    // DISPATCH_MEMORYPRESSURE_NORMAL notifications.
    : memory_level_event_source_(dispatch_source_create(
          DISPATCH_SOURCE_TYPE_MEMORYPRESSURE,
          0,
          DISPATCH_MEMORYPRESSURE_WARN | DISPATCH_MEMORYPRESSURE_CRITICAL,
          dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0))),
      dispatch_callback_(
          base::Bind(&MemoryPressureListener::NotifyMemoryPressure)) {
  dispatch_source_set_event_handler(memory_level_event_source_, ^{
    NotifyMemoryPressureChanged(memory_level_event_source_.get(),
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

void MemoryPressureMonitor::SetDispatchCallback(
    const DispatchCallback& callback) {
  dispatch_callback_ = callback;
}

}  // namespace mac
}  // namespace base
