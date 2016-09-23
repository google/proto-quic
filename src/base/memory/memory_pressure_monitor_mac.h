// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_MEMORY_MEMORY_PRESSURE_MONITOR_MAC_H_
#define BASE_MEMORY_MEMORY_PRESSURE_MONITOR_MAC_H_

#include <dispatch/dispatch.h>

#include "base/base_export.h"
#include "base/mac/scoped_dispatch_object.h"
#include "base/macros.h"
#include "base/memory/memory_pressure_listener.h"
#include "base/memory/memory_pressure_monitor.h"

namespace base {
namespace mac {

class TestMemoryPressureMonitor;

// Declares the interface for the Mac MemoryPressureMonitor, which reports
// memory pressure events and status.
class BASE_EXPORT MemoryPressureMonitor : public base::MemoryPressureMonitor {
 public:
  MemoryPressureMonitor();
  ~MemoryPressureMonitor() override;

  // Returns the currently-observed memory pressure.
  MemoryPressureLevel GetCurrentPressureLevel() const override;

  void SetDispatchCallback(const DispatchCallback& callback) override;

 private:
  friend TestMemoryPressureMonitor;

  static MemoryPressureLevel
      MemoryPressureLevelForMacMemoryPressure(int mac_memory_pressure);
  static void NotifyMemoryPressureChanged(
      dispatch_source_s* event_source,
      const DispatchCallback& dispatch_callback);

  ScopedDispatchObject<dispatch_source_t> memory_level_event_source_;

  DispatchCallback dispatch_callback_;

  DISALLOW_COPY_AND_ASSIGN(MemoryPressureMonitor);
};

}  // namespace mac
}  // namespace base

#endif  // BASE_MEMORY_MEMORY_PRESSURE_MONITOR_MAC_H_
