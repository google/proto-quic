// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/cygprofile/cygprofile.h"

#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "base/bind.h"
#include "base/containers/hash_tables.h"
#include "base/files/scoped_file.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/lock.h"

namespace cygprofile {
namespace {

// Allow 8 MBytes of data for each thread log.
const size_t kMaxBufferSize = 8 * 1024 * 1024 / sizeof(LogEntry);

// Have the background internal thread do its flush every 15 sec.
const int kFlushThreadIdleTimeSec = 15;

const char kLogFileNamePrefix[] = "/data/local/tmp/chrome/cyglog/";

// "cyglog.PID.LWP.PPID"
const char kLogFilenameFormat[] = "%scyglog.%d.%d-%d";

// Magic value of above to prevent instrumentation. Used when ThreadLog is being
// constructed (to prevent reentering by malloc, for example) and by the flush
// log thread (to prevent it from being logged0.
ThreadLog* const kMagicBeingConstructed = reinterpret_cast<ThreadLog*>(1);

// Per-thread pointer to the current log object.
pthread_key_t g_tls_slot;

// Used to initialize the tls slot, once per the entire process.
pthread_once_t g_tls_slot_initializer_once = PTHREAD_ONCE_INIT;

// This variable is to prevent re-entrancy in the __cyg_profile_func_enter()
// while the TLS slot itself is being initialized. Volatile here is required
// to avoid compiler optimizations as this need to be read in a re-entrant way.
// This variable is written by one thread only, which is the first thread that
// happens to run the TLSSlotInitializer(). In practice this will happen very
// early in the startup process, as soon as the first instrumented function is
// called.
volatile bool g_tls_slot_being_initialized = false;

// Initializes the global TLS slot. This is invoked only once per process.
static void TLSSlotInitializer()
{
    g_tls_slot_being_initialized = true;
    PCHECK(0 == pthread_key_create(&g_tls_slot, NULL));
    g_tls_slot_being_initialized = false;
}

// Returns light-weight process ID. On Linux, this is a system-wide unique
// thread id.
pid_t GetTID() {
  return syscall(__NR_gettid);
}

timespec GetCurrentTime() {
  timespec timestamp;
  clock_gettime(CLOCK_MONOTONIC, &timestamp);
  return timestamp;
}

// Sleeps for |sec| seconds.
void SleepSec(int sec) {
  for (int secs_to_sleep = sec; secs_to_sleep != 0;)
    secs_to_sleep = sleep(secs_to_sleep);
}

// Exposes the string header that will appear at the top of every trace file.
// This string contains memory mapping information for the mapped
// library/executable which is used offline during symbolization. Note that
// this class is meant to be instantiated once per process and lazily (during
// the first flush).
struct ImmutableFileHeaderLine {
  ImmutableFileHeaderLine() : value(MakeFileHeaderLine()) {}

  const std::string value;

 private:
  // Returns whether the integer representation of the hexadecimal address
  // stored in |line| at position |start_offset| was successfully stored in
  // |result|.
  static bool ParseAddress(const std::string& line,
                           size_t start_offset,
                           size_t length,
                           uint64_t* result) {
    if (start_offset >= line.length())
      return false;

    uint64_t address;
    const bool ret = HexStringToUInt64(
        base::StringPiece(line.c_str() + start_offset, length), &address);
    if (!ret)
      return false;

    *result = address;
    return true;
  }

  // Parses /proc/self/maps and returns a two line string such as:
  // 758c6000-79f4b000 r-xp 00000000 b3:17 309475 libchrome.2009.0.so
  // secs    usecs   pid:threadid    func
  static std::string MakeFileHeaderLine() {
    std::ifstream mapsfile("/proc/self/maps");
    CHECK(mapsfile.good());
    std::string result;

    for (std::string line; std::getline(mapsfile, line); ) {
      if (line.find("r-xp") == std::string::npos)
        continue;

      const size_t address_length = line.find('-');
      uint64_t start_address = 0;
      CHECK(ParseAddress(line, 0, address_length, &start_address));

      uint64_t end_address = 0;
      CHECK(ParseAddress(line, address_length + 1, address_length,
                         &end_address));

      const uintptr_t current_func_addr = reinterpret_cast<uintptr_t>(
          &MakeFileHeaderLine);
      if (current_func_addr >= start_address &&
          current_func_addr < end_address) {
        result.swap(line);
        break;
      }
    }
    CHECK(!result.empty());
    result.append("\nsecs\tusecs\tpid:threadid\tfunc\n");
    return result;
  }
};

base::LazyInstance<ThreadLogsManager>::Leaky g_logs_manager =
    LAZY_INSTANCE_INITIALIZER;

base::LazyInstance<ImmutableFileHeaderLine>::Leaky g_file_header_line =
    LAZY_INSTANCE_INITIALIZER;

}  // namespace

// Custom thread implementation that joins on destruction. Note that
// base::Thread has non-trivial dependencies on e.g. AtExitManager which makes
// it hard to use it early.
class Thread {
 public:
  Thread(const base::Closure& thread_callback)
      : thread_callback_(thread_callback) {
    PCHECK(0 == pthread_create(&handle_, NULL, &Thread::EntryPoint, this));
  }

  ~Thread() {
    PCHECK(0 == pthread_join(handle_, NULL));
  }

 private:
  static void* EntryPoint(void* data) {
    // Disable logging on this thread. Although this routine is not instrumented
    // (cygprofile.gyp provides that), the called routines are and thus will
    // call instrumentation.
    pthread_once(&g_tls_slot_initializer_once, TLSSlotInitializer);
    ThreadLog* thread_log = reinterpret_cast<ThreadLog*>(
        pthread_getspecific(g_tls_slot));
    CHECK(thread_log == NULL);  // Must be 0 as this is a new thread.
    PCHECK(0 == pthread_setspecific(g_tls_slot, kMagicBeingConstructed));

    Thread* const instance = reinterpret_cast<Thread*>(data);
    instance->thread_callback_.Run();
    return NULL;
  }

  const base::Closure thread_callback_;
  pthread_t handle_;

  DISALLOW_COPY_AND_ASSIGN(Thread);
};

// Single log entry recorded for each function call.
LogEntry::LogEntry(const void* address)
    : time(GetCurrentTime()),
      pid(getpid()),
      tid(GetTID()),
      address(address) {
}

ThreadLog::ThreadLog()
  : tid_(GetTID()),
    in_use_(false),
    flush_callback_(
        base::Bind(&ThreadLog::FlushInternal, base::Unretained(this))) {
}

ThreadLog::ThreadLog(const FlushCallback& flush_callback)
  : tid_(GetTID()),
    in_use_(false),
    flush_callback_(flush_callback) {
}

ThreadLog::~ThreadLog() {
  PCHECK(0 == pthread_setspecific(g_tls_slot, NULL));
}

void ThreadLog::AddEntry(void* address) {
  if (in_use_)
    return;
  in_use_ = true;

  CHECK_EQ(tid_, GetTID());
  const std::pair<base::hash_set<void*>::iterator, bool> pair =
      called_functions_.insert(address);
  const bool did_insert = pair.second;

  if (did_insert) {
    base::AutoLock auto_lock(lock_);
    entries_.push_back(LogEntry(address));
    // Crash in a quickly understandable way instead of crashing (or maybe not
    // though) due to OOM.
    CHECK_LE(entries_.size(), kMaxBufferSize);
  }

  in_use_ = false;
}

void ThreadLog::TakeEntries(std::vector<LogEntry>* destination) {
  base::AutoLock auto_lock(lock_);
  destination->swap(entries_);
  base::STLClearObject(&entries_);
}

void ThreadLog::Flush(std::vector<LogEntry>* entries) const {
  flush_callback_.Run(entries);
}

void ThreadLog::FlushInternal(std::vector<LogEntry>* entries) const {
  const std::string log_filename(
      base::StringPrintf(
          kLogFilenameFormat, kLogFileNamePrefix, getpid(), tid_, getppid()));
  const base::ScopedFILE file(fopen(log_filename.c_str(), "a"));
  CHECK(file.get());

  const long offset = ftell(file.get());
  if (offset == 0)
    fprintf(file.get(), "%s", g_file_header_line.Get().value.c_str());

  for (std::vector<LogEntry>::const_iterator it = entries->begin();
       it != entries->end(); ++it) {
    fprintf(file.get(), "%ld %ld\t%d:%d\t%p\n", it->time.tv_sec,
            it->time.tv_nsec / 1000, it->pid, it->tid, it->address);
  }

  base::STLClearObject(entries);
}

ThreadLogsManager::ThreadLogsManager()
    : wait_callback_(base::Bind(&SleepSec, kFlushThreadIdleTimeSec)) {
}

ThreadLogsManager::ThreadLogsManager(const base::Closure& wait_callback,
                                     const base::Closure& notify_callback)

    : wait_callback_(wait_callback),
      notify_callback_(notify_callback) {
}

ThreadLogsManager::~ThreadLogsManager() {
  // Note that the internal thread does some work until it sees |flush_thread_|
  // = NULL.
  std::unique_ptr<Thread> flush_thread;
  {
    base::AutoLock auto_lock(lock_);
    flush_thread_.swap(flush_thread);
  }
  flush_thread.reset();  // Joins the flush thread.
}

void ThreadLogsManager::AddLog(std::unique_ptr<ThreadLog> new_log) {
  base::AutoLock auto_lock(lock_);

  if (logs_.empty())
    StartInternalFlushThread_Locked();

  logs_.push_back(std::move(new_log));
}

void ThreadLogsManager::StartInternalFlushThread_Locked() {
  lock_.AssertAcquired();
  CHECK(!flush_thread_);
  // Note that the |flush_thread_| joins at destruction which guarantees that it
  // will never outlive |this|, i.e. it's safe not to use ref-counting.
  flush_thread_.reset(
      new Thread(base::Bind(&ThreadLogsManager::FlushAllLogsOnFlushThread,
                            base::Unretained(this))));
}

// Type used below for flushing.
struct LogData {
  LogData(ThreadLog* thread_log) : thread_log(thread_log) {}

  ThreadLog* const thread_log;
  std::vector<LogEntry> entries;
};

void ThreadLogsManager::FlushAllLogsOnFlushThread() {
  while (true) {
    {
      base::AutoLock auto_lock(lock_);
      // The |flush_thread_| field is reset during destruction.
      if (!flush_thread_)
        return;
    }
    // Sleep for a few secs and then flush all thread's buffers. There is a
    // danger that, when quitting Chrome, this thread may see unallocated data
    // and segfault. We do not care because we need logs when Chrome is working.
    wait_callback_.Run();

    // Copy the ThreadLog pointers to avoid acquiring both the logs manager's
    // lock and the one for individual thread logs.
    std::vector<ThreadLog*> thread_logs_copy;
    {
      base::AutoLock auto_lock(lock_);
      for (const auto& log : logs_)
        thread_logs_copy.push_back(log.get());
    }

    // Move the logs' data before flushing them so that the mutexes are not
    // acquired for too long.
    std::vector<LogData> logs;
    for (std::vector<ThreadLog*>::const_iterator it =
             thread_logs_copy.begin();
         it != thread_logs_copy.end(); ++it) {
      ThreadLog* const thread_log = *it;
      LogData log_data(thread_log);
      logs.push_back(log_data);
      thread_log->TakeEntries(&logs.back().entries);
    }

    for (std::vector<LogData>::iterator it = logs.begin();
         it != logs.end(); ++it) {
      if (!it->entries.empty())
        it->thread_log->Flush(&it->entries);
    }

    if (!notify_callback_.is_null())
      notify_callback_.Run();
  }
}

extern "C" {

// The GCC compiler callbacks, called on every function invocation providing
// addresses of caller and callee codes.
void __cyg_profile_func_enter(void* this_fn, void* call_site)
    __attribute__((no_instrument_function));
void __cyg_profile_func_exit(void* this_fn, void* call_site)
    __attribute__((no_instrument_function));

void __cyg_profile_func_enter(void* this_fn, void* callee_unused) {
  // Avoid re-entrancy while initializing the TLS slot (once per process).
  if (g_tls_slot_being_initialized)
    return;

  pthread_once(&g_tls_slot_initializer_once, TLSSlotInitializer);
  ThreadLog* thread_log = reinterpret_cast<ThreadLog*>(
      pthread_getspecific(g_tls_slot));

  if (thread_log == NULL) {
    PCHECK(0 == pthread_setspecific(g_tls_slot, kMagicBeingConstructed));
    thread_log = new ThreadLog();
    CHECK(thread_log);
    g_logs_manager.Pointer()->AddLog(base::WrapUnique(thread_log));
    PCHECK(0 == pthread_setspecific(g_tls_slot, thread_log));
  }

  if (thread_log != kMagicBeingConstructed)
    thread_log->AddEntry(this_fn);
}

void __cyg_profile_func_exit(void* this_fn, void* call_site) {}

}  // extern "C"
}  // namespace cygprofile
