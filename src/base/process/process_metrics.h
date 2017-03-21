// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file contains routines for gathering resource statistics for processes
// running on the system.

#ifndef BASE_PROCESS_PROCESS_METRICS_H_
#define BASE_PROCESS_PROCESS_METRICS_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>

#include "base/base_export.h"
#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/process/process_handle.h"
#include "base/time/time.h"
#include "base/values.h"
#include "build/build_config.h"

#if defined(OS_MACOSX)
#include <mach/mach.h>
#include "base/process/port_provider_mac.h"
#endif

namespace base {

#if defined(OS_WIN)
struct IoCounters : public IO_COUNTERS {
};
#elif defined(OS_POSIX)
struct IoCounters {
  uint64_t ReadOperationCount;
  uint64_t WriteOperationCount;
  uint64_t OtherOperationCount;
  uint64_t ReadTransferCount;
  uint64_t WriteTransferCount;
  uint64_t OtherTransferCount;
};
#endif

// Working Set (resident) memory usage broken down by
//
// On Windows:
// priv (private): These pages (kbytes) cannot be shared with any other process.
// shareable:      These pages (kbytes) can be shared with other processes under
//                 the right circumstances.
// shared :        These pages (kbytes) are currently shared with at least one
//                 other process.
//
// On Linux:
// priv:           Pages mapped only by this process.
// shared:         PSS or 0 if the kernel doesn't support this.
// shareable:      0

// On ChromeOS:
// priv:           Pages mapped only by this process.
// shared:         PSS or 0 if the kernel doesn't support this.
// shareable:      0
// swapped         Pages swapped out to zram.
//
// On OS X: TODO(thakis): Revise.
// priv:           Memory.
// shared:         0
// shareable:      0
//
struct WorkingSetKBytes {
  WorkingSetKBytes() : priv(0), shareable(0), shared(0) {}
  size_t priv;
  size_t shareable;
  size_t shared;
#if defined(OS_CHROMEOS)
  size_t swapped;
#endif
};

// Committed (resident + paged) memory usage broken down by
// private: These pages cannot be shared with any other process.
// mapped:  These pages are mapped into the view of a section (backed by
//          pagefile.sys)
// image:   These pages are mapped into the view of an image section (backed by
//          file system)
struct CommittedKBytes {
  CommittedKBytes() : priv(0), mapped(0), image(0) {}
  size_t priv;
  size_t mapped;
  size_t image;
};

// Convert a POSIX timeval to microseconds.
BASE_EXPORT int64_t TimeValToMicroseconds(const struct timeval& tv);

// Provides performance metrics for a specified process (CPU usage, memory and
// IO counters). Use CreateCurrentProcessMetrics() to get an instance for the
// current process, or CreateProcessMetrics() to get an instance for an
// arbitrary process. Then, access the information with the different get
// methods.
class BASE_EXPORT ProcessMetrics {
 public:
  ~ProcessMetrics();

  // Creates a ProcessMetrics for the specified process.
#if !defined(OS_MACOSX) || defined(OS_IOS)
  static std::unique_ptr<ProcessMetrics> CreateProcessMetrics(
      ProcessHandle process);
#else

  // The port provider needs to outlive the ProcessMetrics object returned by
  // this function. If NULL is passed as provider, the returned object
  // only returns valid metrics if |process| is the current process.
  static std::unique_ptr<ProcessMetrics> CreateProcessMetrics(
      ProcessHandle process,
      PortProvider* port_provider);
#endif  // !defined(OS_MACOSX) || defined(OS_IOS)

  // Creates a ProcessMetrics for the current process. This a cross-platform
  // convenience wrapper for CreateProcessMetrics().
  static std::unique_ptr<ProcessMetrics> CreateCurrentProcessMetrics();

  // Returns the current space allocated for the pagefile, in bytes (these pages
  // may or may not be in memory).  On Linux, this returns the total virtual
  // memory size.
  size_t GetPagefileUsage() const;
  // Returns the peak space allocated for the pagefile, in bytes.
  size_t GetPeakPagefileUsage() const;
  // Returns the current working set size, in bytes.  On Linux, this returns
  // the resident set size.
  size_t GetWorkingSetSize() const;
  // Returns the peak working set size, in bytes.
  size_t GetPeakWorkingSetSize() const;
  // Returns private and sharedusage, in bytes. Private bytes is the amount of
  // memory currently allocated to a process that cannot be shared. Returns
  // false on platform specific error conditions.  Note: |private_bytes|
  // returns 0 on unsupported OSes: prior to XP SP2.
  bool GetMemoryBytes(size_t* private_bytes, size_t* shared_bytes) const;
  // Fills a CommittedKBytes with both resident and paged
  // memory usage as per definition of CommittedBytes.
  void GetCommittedKBytes(CommittedKBytes* usage) const;
  // Fills a WorkingSetKBytes containing resident private and shared memory
  // usage in bytes, as per definition of WorkingSetBytes. Note that this
  // function is somewhat expensive on Windows (a few ms per process).
  bool GetWorkingSetKBytes(WorkingSetKBytes* ws_usage) const;
  // Computes pss (proportional set size) of a process. Note that this
  // function is somewhat expensive on Windows (a few ms per process).
  bool GetProportionalSetSizeBytes(uint64_t* pss_bytes) const;

#if defined(OS_MACOSX)
  // Fills both CommitedKBytes and WorkingSetKBytes in a single operation. This
  // is more efficient on Mac OS X, as the two can be retrieved with a single
  // system call.
  bool GetCommittedAndWorkingSetKBytes(CommittedKBytes* usage,
                                       WorkingSetKBytes* ws_usage) const;
  // Returns private, shared, and total resident bytes.
  bool GetMemoryBytes(size_t* private_bytes,
                      size_t* shared_bytes,
                      size_t* resident_bytes) const;
#endif

  // Returns the CPU usage in percent since the last time this method or
  // GetPlatformIndependentCPUUsage() was called. The first time this method
  // is called it returns 0 and will return the actual CPU info on subsequent
  // calls. On Windows, the CPU usage value is for all CPUs. So if you have
  // 2 CPUs and your process is using all the cycles of 1 CPU and not the other
  // CPU, this method returns 50.
  double GetCPUUsage();

  // Returns the number of average idle cpu wakeups per second since the last
  // call.
  int GetIdleWakeupsPerSecond();

  // Same as GetCPUUsage(), but will return consistent values on all platforms
  // (cancelling the Windows exception mentioned above) by returning a value in
  // the range of 0 to (100 * numCPUCores) everywhere.
  double GetPlatformIndependentCPUUsage();

  // Retrieves accounting information for all I/O operations performed by the
  // process.
  // If IO information is retrieved successfully, the function returns true
  // and fills in the IO_COUNTERS passed in. The function returns false
  // otherwise.
  bool GetIOCounters(IoCounters* io_counters) const;

#if defined(OS_LINUX)
  // Returns the number of file descriptors currently open by the process, or
  // -1 on error.
  int GetOpenFdCount() const;

  // Returns the soft limit of file descriptors that can be opened by the
  // process, or -1 on error.
  int GetOpenFdSoftLimit() const;
#endif  // defined(OS_LINUX)

 private:
#if !defined(OS_MACOSX) || defined(OS_IOS)
  explicit ProcessMetrics(ProcessHandle process);
#else
  ProcessMetrics(ProcessHandle process, PortProvider* port_provider);
#endif  // !defined(OS_MACOSX) || defined(OS_IOS)

#if defined(OS_LINUX) || defined(OS_ANDROID)
  bool GetWorkingSetKBytesStatm(WorkingSetKBytes* ws_usage) const;
#endif

#if defined(OS_CHROMEOS)
  bool GetWorkingSetKBytesTotmaps(WorkingSetKBytes *ws_usage) const;
#endif

#if defined(OS_MACOSX) || defined(OS_LINUX)
  int CalculateIdleWakeupsPerSecond(uint64_t absolute_idle_wakeups);
#endif

  ProcessHandle process_;

  int processor_count_;

  // Used to store the previous times and CPU usage counts so we can
  // compute the CPU usage between calls.
  TimeTicks last_cpu_time_;
  int64_t last_system_time_;

#if defined(OS_MACOSX) || defined(OS_LINUX)
  // Same thing for idle wakeups.
  TimeTicks last_idle_wakeups_time_;
  uint64_t last_absolute_idle_wakeups_;
#endif

#if !defined(OS_IOS)
#if defined(OS_MACOSX)
  // Queries the port provider if it's set.
  mach_port_t TaskForPid(ProcessHandle process) const;

  PortProvider* port_provider_;
#elif defined(OS_POSIX)
  // Jiffie count at the last_cpu_time_ we updated.
  int last_cpu_;
#endif  // defined(OS_POSIX)
#endif  // !defined(OS_IOS)

  DISALLOW_COPY_AND_ASSIGN(ProcessMetrics);
};

// Returns the memory committed by the system in KBytes.
// Returns 0 if it can't compute the commit charge.
BASE_EXPORT size_t GetSystemCommitCharge();

// Returns the number of bytes in a memory page. Do not use this to compute
// the number of pages in a block of memory for calling mincore(). On some
// platforms, e.g. iOS, mincore() uses a different page size from what is
// returned by GetPageSize().
BASE_EXPORT size_t GetPageSize();

#if defined(OS_POSIX)
// Returns the maximum number of file descriptors that can be open by a process
// at once. If the number is unavailable, a conservative best guess is returned.
BASE_EXPORT size_t GetMaxFds();

// Sets the file descriptor soft limit to |max_descriptors| or the OS hard
// limit, whichever is lower.
BASE_EXPORT void SetFdLimit(unsigned int max_descriptors);
#endif  // defined(OS_POSIX)

#if defined(OS_WIN) || defined(OS_MACOSX) || defined(OS_LINUX) || \
    defined(OS_ANDROID)
// Data about system-wide memory consumption. Values are in KB. Available on
// Windows, Mac, Linux, Android and Chrome OS.
//
// Total/free memory are available on all platforms that implement
// GetSystemMemoryInfo(). Total/free swap memory are available on all platforms
// except on Mac. Buffers/cached/active_anon/inactive_anon/active_file/
// inactive_file/dirty/pswpin/pswpout/pgmajfault are available on
// Linux/Android/Chrome OS. Shmem/slab/gem_objects/gem_size are Chrome OS only.
struct BASE_EXPORT SystemMemoryInfoKB {
  SystemMemoryInfoKB();
  SystemMemoryInfoKB(const SystemMemoryInfoKB& other);

  // Serializes the platform specific fields to value.
  std::unique_ptr<Value> ToValue() const;

  int total;
  int free;

#if defined(OS_LINUX)
  // This provides an estimate of available memory as described here:
  // https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=34e431b0ae398fc54ea69ff85ec700722c9da773
  // NOTE: this is ONLY valid in kernels 3.14 and up.  Its value will always
  // be 0 in earlier kernel versions.
  int available;
#endif

#if !defined(OS_MACOSX)
  int swap_total;
  int swap_free;
#endif

#if defined(OS_ANDROID) || defined(OS_LINUX)
  int buffers;
  int cached;
  int active_anon;
  int inactive_anon;
  int active_file;
  int inactive_file;
  int dirty;

  // vmstats data.
  unsigned long pswpin;
  unsigned long pswpout;
  unsigned long pgmajfault;
#endif  // defined(OS_ANDROID) || defined(OS_LINUX)

#if defined(OS_CHROMEOS)
  int shmem;
  int slab;
  // Gem data will be -1 if not supported.
  int gem_objects;
  long long gem_size;
#endif  // defined(OS_CHROMEOS)
};

// On Linux/Android/Chrome OS, system-wide memory consumption data is parsed
// from /proc/meminfo and /proc/vmstat. On Windows/Mac, it is obtained using
// system API calls.
//
// Fills in the provided |meminfo| structure. Returns true on success.
// Exposed for memory debugging widget.
BASE_EXPORT bool GetSystemMemoryInfo(SystemMemoryInfoKB* meminfo);

#endif  // defined(OS_WIN) || defined(OS_MACOSX) || defined(OS_LINUX) ||
        // defined(OS_ANDROID)

#if defined(OS_LINUX) || defined(OS_ANDROID)
// Parse the data found in /proc/<pid>/stat and return the sum of the
// CPU-related ticks.  Returns -1 on parse error.
// Exposed for testing.
BASE_EXPORT int ParseProcStatCPU(const std::string& input);

// Get the number of threads of |process| as available in /proc/<pid>/stat.
// This should be used with care as no synchronization with running threads is
// done. This is mostly useful to guarantee being single-threaded.
// Returns 0 on failure.
BASE_EXPORT int GetNumberOfThreads(ProcessHandle process);

// /proc/self/exe refers to the current executable.
BASE_EXPORT extern const char kProcSelfExe[];

// Parses a string containing the contents of /proc/meminfo
// returns true on success or false for a parsing error
BASE_EXPORT bool ParseProcMeminfo(const std::string& input,
                                  SystemMemoryInfoKB* meminfo);

// Parses a string containing the contents of /proc/vmstat
// returns true on success or false for a parsing error
BASE_EXPORT bool ParseProcVmstat(const std::string& input,
                                 SystemMemoryInfoKB* meminfo);

// Data from /proc/diskstats about system-wide disk I/O.
struct BASE_EXPORT SystemDiskInfo {
  SystemDiskInfo();
  SystemDiskInfo(const SystemDiskInfo& other);

  // Serializes the platform specific fields to value.
  std::unique_ptr<Value> ToValue() const;

  uint64_t reads;
  uint64_t reads_merged;
  uint64_t sectors_read;
  uint64_t read_time;
  uint64_t writes;
  uint64_t writes_merged;
  uint64_t sectors_written;
  uint64_t write_time;
  uint64_t io;
  uint64_t io_time;
  uint64_t weighted_io_time;
};

// Checks whether the candidate string is a valid disk name, [hsv]d[a-z]+
// for a generic disk or mmcblk[0-9]+ for the MMC case.
// Names of disk partitions (e.g. sda1) are not valid.
BASE_EXPORT bool IsValidDiskName(const std::string& candidate);

// Retrieves data from /proc/diskstats about system-wide disk I/O.
// Fills in the provided |diskinfo| structure. Returns true on success.
BASE_EXPORT bool GetSystemDiskInfo(SystemDiskInfo* diskinfo);

// Returns the amount of time spent in user space since boot across all CPUs.
BASE_EXPORT TimeDelta GetUserCpuTimeSinceBoot();
#endif  // defined(OS_LINUX) || defined(OS_ANDROID)

#if defined(OS_CHROMEOS)
// Data from files in directory /sys/block/zram0 about ZRAM usage.
struct BASE_EXPORT SwapInfo {
  SwapInfo()
      : num_reads(0),
        num_writes(0),
        compr_data_size(0),
        orig_data_size(0),
        mem_used_total(0) {
  }

  // Serializes the platform specific fields to value.
  std::unique_ptr<Value> ToValue() const;

  uint64_t num_reads;
  uint64_t num_writes;
  uint64_t compr_data_size;
  uint64_t orig_data_size;
  uint64_t mem_used_total;
};

// In ChromeOS, reads files from /sys/block/zram0 that contain ZRAM usage data.
// Fills in the provided |swap_data| structure.
BASE_EXPORT void GetSwapInfo(SwapInfo* swap_info);
#endif  // defined(OS_CHROMEOS)

// Collects and holds performance metrics for system memory and disk.
// Provides functionality to retrieve the data on various platforms and
// to serialize the stored data.
class SystemMetrics {
 public:
  SystemMetrics();

  static SystemMetrics Sample();

  // Serializes the system metrics to value.
  std::unique_ptr<Value> ToValue() const;

 private:
  FRIEND_TEST_ALL_PREFIXES(SystemMetricsTest, SystemMetrics);

  size_t committed_memory_;
#if defined(OS_LINUX) || defined(OS_ANDROID)
  SystemMemoryInfoKB memory_info_;
  SystemDiskInfo disk_info_;
#endif
#if defined(OS_CHROMEOS)
  SwapInfo swap_info_;
#endif
};

}  // namespace base

#endif  // BASE_PROCESS_PROCESS_METRICS_H_
