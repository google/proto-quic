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

namespace {
static const int kUMATickSize = 5;
}  // namespace

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
      last_statistic_report_(CFAbsoluteTimeGetCurrent()),
      last_pressure_level_(MemoryPressureListener::MEMORY_PRESSURE_LEVEL_NONE),
      reporting_error_(0) {
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
MemoryPressureMonitor::GetCurrentPressureLevel() {
  int mac_memory_pressure;
  size_t length = sizeof(int);
  sysctlbyname("kern.memorystatus_vm_pressure_level", &mac_memory_pressure,
               &length, nullptr, 0);
  MemoryPressureListener::MemoryPressureLevel memory_pressure_level =
      MemoryPressureLevelForMacMemoryPressure(mac_memory_pressure);
  bool pressure_level_changed = false;
  if (last_pressure_level_ != memory_pressure_level) {
    pressure_level_changed = true;
  }
  SendStatisticsIfNecessary(pressure_level_changed);
  last_pressure_level_ = memory_pressure_level;
  return memory_pressure_level;
}

void MemoryPressureMonitor::OnMemoryPressureChanged(
    dispatch_source_s* event_source,
    const MemoryPressureMonitor::DispatchCallback& dispatch_callback) {
  int mac_memory_pressure = dispatch_source_get_data(event_source);
  MemoryPressureListener::MemoryPressureLevel memory_pressure_level =
      MemoryPressureLevelForMacMemoryPressure(mac_memory_pressure);
  bool pressure_level_changed = false;
  if (last_pressure_level_ != memory_pressure_level) {
    pressure_level_changed = true;
  }
  SendStatisticsIfNecessary(pressure_level_changed);
  last_pressure_level_ = memory_pressure_level;
  if (memory_pressure_level !=
      MemoryPressureListener::MEMORY_PRESSURE_LEVEL_NONE)
    dispatch_callback.Run(memory_pressure_level);
}

void MemoryPressureMonitor::SendStatisticsIfNecessary(
    bool pressure_level_changed) {
  CFTimeInterval now = CFAbsoluteTimeGetCurrent();
  CFTimeInterval since_last_report = now - last_statistic_report_;
  last_statistic_report_ = now;

  double accumulated_time = since_last_report + reporting_error_;
  int ticks_to_report = static_cast<int>(accumulated_time / kUMATickSize);
  reporting_error_ = std::fmod(accumulated_time, kUMATickSize);

  // Round up on change to ensure we capture it
  if (pressure_level_changed && ticks_to_report < 1) {
    ticks_to_report = 1;
    reporting_error_ = 0;
  }

  if (ticks_to_report >= 1)
    RecordMemoryPressure(last_pressure_level_, ticks_to_report);
}

void MemoryPressureMonitor::SetDispatchCallback(
    const DispatchCallback& callback) {
  dispatch_callback_ = callback;
}

}  // namespace mac
}  // namespace base
