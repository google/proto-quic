// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_PROCESS_MEMORY_TOTALS_H_
#define BASE_TRACE_EVENT_PROCESS_MEMORY_TOTALS_H_

#include <stdint.h>

#include <map>

#include "base/base_export.h"
#include "base/macros.h"

namespace base {
namespace trace_event {

class TracedValue;

// Data model for process-wide memory stats.
class BASE_EXPORT ProcessMemoryTotals {
 public:
  ProcessMemoryTotals();
  ~ProcessMemoryTotals();

  // Called at trace generation time to populate the TracedValue.
  void AsValueInto(TracedValue* value) const;

  // Clears up all the data collected.
  void Clear();

  uint64_t resident_set_bytes() const { return resident_set_bytes_; }
  void set_resident_set_bytes(uint64_t value) { resident_set_bytes_ = value; }

  // Platform-specific data that will be used to compute the
  // PrivateMemoryFootprint.
  struct PlatformPrivateFootprint {
    // macOS 10.12+
    uint64_t phys_footprint_bytes = 0;

    // macOS [all versions]
    uint64_t internal_bytes = 0;
    uint64_t compressed_bytes = 0;

    // Linux, Android, ChromeOS
    uint64_t rss_anon_bytes = 0;
    uint64_t vm_swap_bytes = 0;

    // On Windows,
    //   TBD: https://crbug.com/707022
    // On iOS,
    //   TBD: https://crbug.com/714961
  };
  const PlatformPrivateFootprint& GetPlatformPrivateFootprint() const {
    return platform_private_footprint_;
  }
  PlatformPrivateFootprint& GetPlatformPrivateFootprint() {
    return platform_private_footprint_;
  }

  uint64_t peak_resident_set_bytes() const { return peak_resident_set_bytes_; }
  void set_peak_resident_set_bytes(uint64_t value) {
    peak_resident_set_bytes_ = value;
  }

  // On some platforms (recent linux kernels, see goo.gl/sMvAVz) the peak rss
  // can be reset. When is_peak_rss_resettable == true, the peak refers to
  // peak from the previous measurement. When false, it is the absolute peak
  // since the start of the process.
  bool is_peak_rss_resetable() const { return is_peak_rss_resetable_; }
  void set_is_peak_rss_resetable(bool value) { is_peak_rss_resetable_ = value; }

  void SetExtraFieldInBytes(const char* name, uint64_t value);

 private:
  uint64_t resident_set_bytes_;
  uint64_t peak_resident_set_bytes_;
  bool is_peak_rss_resetable_;

  // Not emitted in the trace as this is intended to be an intermediary in
  // computation of private memory footprint.
  PlatformPrivateFootprint platform_private_footprint_;

  // Extra metrics for OS-specific statistics.
  std::map<const char*, uint64_t> extra_fields_;

  DISALLOW_COPY_AND_ASSIGN(ProcessMemoryTotals);
};

}  // namespace trace_event
}  // namespace base

#endif  // BASE_TRACE_EVENT_PROCESS_MEMORY_TOTALS_H_
