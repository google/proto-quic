// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/sys_info.h"

#include <magenta/syscalls.h>

namespace base {

// static
int64_t SysInfo::AmountOfPhysicalMemory() {
  return mx_system_get_physmem();
}

// static
int SysInfo::NumberOfProcessors() {
  return mx_system_get_num_cpus();
}

}  // namespace base
