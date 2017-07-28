// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/sys_info.h"

#include <mach/mach.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#import <UIKit/UIKit.h>

#include "base/logging.h"
#include "base/mac/scoped_mach_port.h"
#include "base/mac/scoped_nsautorelease_pool.h"
#include "base/macros.h"
#include "base/process/process_metrics.h"
#include "base/strings/sys_string_conversions.h"

namespace base {

namespace {

// Queries sysctlbyname() for the given key and returns the value from the
// system or the empty string on failure.
std::string GetSysctlValue(const char* key_name) {
  char value[256];
  size_t len = arraysize(value);
  if (sysctlbyname(key_name, &value, &len, nullptr, 0) == 0) {
    DCHECK_GE(len, 1u);
    DCHECK_EQ('\0', value[len - 1]);
    return std::string(value, len - 1);
  }
  return std::string();
}

}  // namespace

// static
std::string SysInfo::OperatingSystemName() {
  static dispatch_once_t get_system_name_once;
  static std::string* system_name;
  dispatch_once(&get_system_name_once, ^{
      base::mac::ScopedNSAutoreleasePool pool;
      system_name = new std::string(
          SysNSStringToUTF8([[UIDevice currentDevice] systemName]));
  });
  // Examples of returned value: 'iPhone OS' on iPad 5.1.1
  // and iPhone 5.1.1.
  return *system_name;
}

// static
std::string SysInfo::OperatingSystemVersion() {
  static dispatch_once_t get_system_version_once;
  static std::string* system_version;
  dispatch_once(&get_system_version_once, ^{
      base::mac::ScopedNSAutoreleasePool pool;
      system_version = new std::string(
          SysNSStringToUTF8([[UIDevice currentDevice] systemVersion]));
  });
  return *system_version;
}

// static
void SysInfo::OperatingSystemVersionNumbers(int32_t* major_version,
                                            int32_t* minor_version,
                                            int32_t* bugfix_version) {
  base::mac::ScopedNSAutoreleasePool pool;
  std::string system_version = OperatingSystemVersion();
  if (!system_version.empty()) {
    // Try to parse out the version numbers from the string.
    int num_read = sscanf(system_version.c_str(), "%d.%d.%d", major_version,
                          minor_version, bugfix_version);
    if (num_read < 1)
      *major_version = 0;
    if (num_read < 2)
      *minor_version = 0;
    if (num_read < 3)
      *bugfix_version = 0;
  }
}

// static
int64_t SysInfo::AmountOfPhysicalMemoryImpl() {
  struct host_basic_info hostinfo;
  mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
  base::mac::ScopedMachSendRight host(mach_host_self());
  int result = host_info(host.get(),
                         HOST_BASIC_INFO,
                         reinterpret_cast<host_info_t>(&hostinfo),
                         &count);
  if (result != KERN_SUCCESS) {
    NOTREACHED();
    return 0;
  }
  DCHECK_EQ(HOST_BASIC_INFO_COUNT, count);
  return static_cast<int64_t>(hostinfo.max_mem);
}

// static
int64_t SysInfo::AmountOfAvailablePhysicalMemoryImpl() {
  SystemMemoryInfoKB info;
  if (!GetSystemMemoryInfo(&info))
    return 0;
  // We should add inactive file-backed memory also but there is no such
  // information from iOS unfortunately.
  return static_cast<int64_t>(info.free + info.speculative) * 1024;
}

// static
std::string SysInfo::CPUModelName() {
  return GetSysctlValue("machdep.cpu.brand_string");
}

// static
std::string SysInfo::HardwareModelName() {
#if TARGET_OS_SIMULATOR
  // On the simulator, "hw.machine" returns "i386" or "x86_64" which doesn't
  // match the expected format, so supply a fake string here.
  return "Simulator1,1";
#else
  // Note: This uses "hw.machine" instead of "hw.model" like the Mac code,
  // because "hw.model" doesn't always return the right string on some devices.
  return GetSysctlValue("hw.machine");
#endif
}

}  // namespace base
