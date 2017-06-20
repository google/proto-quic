// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_MEMORY_DUMP_MANAGER_H_
#define BASE_TRACE_EVENT_MEMORY_DUMP_MANAGER_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <unordered_set>
#include <vector>

#include "base/atomicops.h"
#include "base/containers/hash_tables.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/singleton.h"
#include "base/synchronization/lock.h"
#include "base/trace_event/memory_allocator_dump.h"
#include "base/trace_event/memory_dump_provider_info.h"
#include "base/trace_event/memory_dump_request_args.h"
#include "base/trace_event/process_memory_dump.h"
#include "base/trace_event/trace_event.h"

namespace base {

class SequencedTaskRunner;
class SingleThreadTaskRunner;
class Thread;

namespace trace_event {

class MemoryTracingObserver;
class MemoryDumpProvider;
class HeapProfilerSerializationState;

enum HeapProfilingMode {
  kHeapProfilingModeNone,
  kHeapProfilingModePseudo,
  kHeapProfilingModeNative,
  kHeapProfilingModeTaskProfiler,
  kHeapProfilingModeInvalid
};

// This is the interface exposed to the rest of the codebase to deal with
// memory tracing. The main entry point for clients is represented by
// RequestDumpPoint(). The extension by Un(RegisterDumpProvider).
class BASE_EXPORT MemoryDumpManager {
 public:
  using RequestGlobalDumpFunction =
      RepeatingCallback<void(const MemoryDumpRequestArgs& args,
                             const GlobalMemoryDumpCallback& callback)>;

  static const char* const kTraceCategory;

  // This value is returned as the tracing id of the child processes by
  // GetTracingProcessId() when tracing is not enabled.
  static const uint64_t kInvalidTracingProcessId;

  static MemoryDumpManager* GetInstance();
  static std::unique_ptr<MemoryDumpManager> CreateInstanceForTesting();

  // Invoked once per process to listen to trace begin / end events.
  // Initialization can happen after (Un)RegisterMemoryDumpProvider() calls
  // and the MemoryDumpManager guarantees to support this.
  // On the other side, the MemoryDumpManager will not be fully operational
  // (i.e. will NACK any RequestGlobalMemoryDump()) until initialized.
  // Arguments:
  //  request_dump_function: Function to invoke a global dump. Global dump
  //      involves embedder-specific behaviors like multiprocess handshaking.
  //  is_coordinator: True when current process coordinates the periodic dump
  //      triggering.
  void Initialize(RequestGlobalDumpFunction request_dump_function,
                  bool is_coordinator);

  // (Un)Registers a MemoryDumpProvider instance.
  // Args:
  //  - mdp: the MemoryDumpProvider instance to be registered. MemoryDumpManager
  //      does NOT take memory ownership of |mdp|, which is expected to either
  //      be a singleton or unregister itself.
  //  - name: a friendly name (duplicates allowed). Used for debugging and
  //      run-time profiling of memory-infra internals. Must be a long-lived
  //      C string.
  //  - task_runner: either a SingleThreadTaskRunner or SequencedTaskRunner. All
  //      the calls to |mdp| will be run on the given |task_runner|. If passed
  //      null |mdp| should be able to handle calls on arbitrary threads.
  //  - options: extra optional arguments. See memory_dump_provider.h.
  void RegisterDumpProvider(MemoryDumpProvider* mdp,
                            const char* name,
                            scoped_refptr<SingleThreadTaskRunner> task_runner);
  void RegisterDumpProvider(MemoryDumpProvider* mdp,
                            const char* name,
                            scoped_refptr<SingleThreadTaskRunner> task_runner,
                            MemoryDumpProvider::Options options);
  void RegisterDumpProviderWithSequencedTaskRunner(
      MemoryDumpProvider* mdp,
      const char* name,
      scoped_refptr<SequencedTaskRunner> task_runner,
      MemoryDumpProvider::Options options);
  void UnregisterDumpProvider(MemoryDumpProvider* mdp);

  // Unregisters an unbound dump provider and takes care about its deletion
  // asynchronously. Can be used only for for dump providers with no
  // task-runner affinity.
  // This method takes ownership of the dump provider and guarantees that:
  //  - The |mdp| will be deleted at some point in the near future.
  //  - Its deletion will not happen concurrently with the OnMemoryDump() call.
  // Note that OnMemoryDump() and PollFastMemoryTotal() calls can still happen
  // after this method returns.
  void UnregisterAndDeleteDumpProviderSoon(
      std::unique_ptr<MemoryDumpProvider> mdp);

  // Requests a memory dump. The dump might happen or not depending on the
  // filters and categories specified when enabling tracing.
  // A SUMMARY_ONLY dump can be requested at any time after initialization and
  // other type of dumps can be requested only when MDM is enabled.
  // The optional |callback| is executed asynchronously, on an arbitrary thread,
  // to notify about the completion of the global dump (i.e. after all the
  // processes have dumped) and its success (true iff all the dumps were
  // successful).
  void RequestGlobalDump(MemoryDumpType,
                         MemoryDumpLevelOfDetail,
                         const GlobalMemoryDumpCallback&);

  // Same as above (still asynchronous), but without callback.
  void RequestGlobalDump(MemoryDumpType, MemoryDumpLevelOfDetail);

  // Prepare MemoryDumpManager for RequestGlobalMemoryDump calls for tracing
  // related modes (non-SUMMARY_ONLY).
  // Initializes the peak detector, scheduler and heap profiler with the given
  // config.
  void SetupForTracing(const TraceConfig::MemoryDumpConfig&);

  // Tear-down tracing related state.
  // Non-tracing modes (e.g. SUMMARY_ONLY) will continue to work.
  void TeardownForTracing();

  // NOTE: Use RequestGlobalDump() to create memory dumps. Creates a memory dump
  // for the current process and appends it to the trace. |callback| will be
  // invoked asynchronously upon completion on the same thread on which
  // CreateProcessDump() was called. This method should only be used by the
  // embedder while creating a global memory dump.
  void CreateProcessDump(const MemoryDumpRequestArgs& args,
                         const ProcessMemoryDumpCallback& callback);

  // Returns the heap profiling mode configured on the command-line, if any.
  // If heap profiling is configured but not supported by this binary, or if an
  // invalid mode is specified, then kHeapProfilingInvalid is returned.
  static HeapProfilingMode GetHeapProfilingModeFromCommandLine();

  // Enable heap profiling if supported, and kEnableHeapProfiling is specified.
  void EnableHeapProfilingIfNeeded();

  // Lets tests see if a dump provider is registered.
  bool IsDumpProviderRegisteredForTesting(MemoryDumpProvider*);

  const scoped_refptr<HeapProfilerSerializationState>&
  heap_profiler_serialization_state_for_testing() const {
    return heap_profiler_serialization_state_;
  }

  // Returns a unique id for identifying the processes. The id can be
  // retrieved by child processes only when tracing is enabled. This is
  // intended to express cross-process sharing of memory dumps on the
  // child-process side, without having to know its own child process id.
  uint64_t GetTracingProcessId() const { return tracing_process_id_; }
  void set_tracing_process_id(uint64_t tracing_process_id) {
    tracing_process_id_ = tracing_process_id;
  }

  // Returns the name for a the allocated_objects dump. Use this to declare
  // suballocator dumps from other dump providers.
  // It will return nullptr if there is no dump provider for the system
  // allocator registered (which is currently the case for Mac OS).
  const char* system_allocator_pool_name() const {
    return kSystemAllocatorPoolName;
  };

  // When set to true, calling |RegisterMemoryDumpProvider| is a no-op.
  void set_dumper_registrations_ignored_for_testing(bool ignored) {
    dumper_registrations_ignored_for_testing_ = ignored;
  }

 private:
  friend std::default_delete<MemoryDumpManager>;  // For the testing instance.
  friend struct DefaultSingletonTraits<MemoryDumpManager>;
  friend class MemoryDumpManagerTest;

  // Holds the state of a process memory dump that needs to be carried over
  // across task runners in order to fulfill an asynchronous CreateProcessDump()
  // request. At any time exactly one task runner owns a
  // ProcessMemoryDumpAsyncState.
  struct ProcessMemoryDumpAsyncState {
    ProcessMemoryDumpAsyncState(
        MemoryDumpRequestArgs req_args,
        const MemoryDumpProviderInfo::OrderedSet& dump_providers,
        scoped_refptr<HeapProfilerSerializationState>
            heap_profiler_serialization_state,
        ProcessMemoryDumpCallback callback,
        scoped_refptr<SequencedTaskRunner> dump_thread_task_runner);
    ~ProcessMemoryDumpAsyncState();

    // Gets or creates the memory dump container for the given target process.
    ProcessMemoryDump* GetOrCreateMemoryDumpContainerForProcess(
        ProcessId pid,
        const MemoryDumpArgs& dump_args);

    // A map of ProcessId -> ProcessMemoryDump, one for each target process
    // being dumped from the current process. Typically each process dumps only
    // for itself, unless dump providers specify a different |target_process| in
    // MemoryDumpProvider::Options.
    std::map<ProcessId, std::unique_ptr<ProcessMemoryDump>> process_dumps;

    // The arguments passed to the initial CreateProcessDump() request.
    const MemoryDumpRequestArgs req_args;

    // An ordered sequence of dump providers that have to be invoked to complete
    // the dump. This is a copy of |dump_providers_| at the beginning of a dump
    // and becomes empty at the end, when all dump providers have been invoked.
    std::vector<scoped_refptr<MemoryDumpProviderInfo>> pending_dump_providers;

    // The HeapProfilerSerializationState object, which is shared by all
    // the ProcessMemoryDump and MemoryAllocatorDump instances through all the
    // tracing session lifetime.
    scoped_refptr<HeapProfilerSerializationState>
        heap_profiler_serialization_state;

    // Callback passed to the initial call to CreateProcessDump().
    ProcessMemoryDumpCallback callback;

    // The |success| field that will be passed as argument to the |callback|.
    bool dump_successful;

    // The thread on which FinalizeDumpAndAddToTrace() (and hence |callback|)
    // should be invoked. This is the thread on which the initial
    // CreateProcessDump() request was called.
    const scoped_refptr<SingleThreadTaskRunner> callback_task_runner;

    // The thread on which unbound dump providers should be invoked.
    // This is essentially |dump_thread_|.task_runner() but needs to be kept
    // as a separate variable as it needs to be accessed by arbitrary dumpers'
    // threads outside of the lock_ to avoid races when disabling tracing.
    // It is immutable for all the duration of a tracing session.
    const scoped_refptr<SequencedTaskRunner> dump_thread_task_runner;

   private:
    DISALLOW_COPY_AND_ASSIGN(ProcessMemoryDumpAsyncState);
  };

  static const int kMaxConsecutiveFailuresCount;
  static const char* const kSystemAllocatorPoolName;

  MemoryDumpManager();
  virtual ~MemoryDumpManager();

  static void SetInstanceForTesting(MemoryDumpManager* instance);
  static uint32_t GetDumpsSumKb(const std::string&, const ProcessMemoryDump*);

  void FinalizeDumpAndAddToTrace(
      std::unique_ptr<ProcessMemoryDumpAsyncState> pmd_async_state);

  // Lazily initializes dump_thread_ and returns its TaskRunner.
  scoped_refptr<base::SequencedTaskRunner> GetOrCreateBgTaskRunnerLocked();

  // Calls InvokeOnMemoryDump() for the next MDP on the task runner specified by
  // the MDP while registration. On failure to do so, skips and continues to
  // next MDP.
  void SetupNextMemoryDump(
      std::unique_ptr<ProcessMemoryDumpAsyncState> pmd_async_state);

  // Invokes OnMemoryDump() of the next MDP and calls SetupNextMemoryDump() at
  // the end to continue the ProcessMemoryDump. Should be called on the MDP task
  // runner.
  void InvokeOnMemoryDump(ProcessMemoryDumpAsyncState* owned_pmd_async_state);

  // Helper for RegierDumpProvider* functions.
  void RegisterDumpProviderInternal(
      MemoryDumpProvider* mdp,
      const char* name,
      scoped_refptr<SequencedTaskRunner> task_runner,
      const MemoryDumpProvider::Options& options);

  // Helper for the public UnregisterDumpProvider* functions.
  void UnregisterDumpProviderInternal(MemoryDumpProvider* mdp,
                                      bool take_mdp_ownership_and_delete_async);

  // Fills the passed vector with the subset of dump providers which were
  // registered with is_fast_polling_supported == true.
  void GetDumpProvidersForPolling(
      std::vector<scoped_refptr<MemoryDumpProviderInfo>>*);

  // Returns true if Initialize() has been called, false otherwise.
  bool is_initialized() const { return !request_dump_function_.is_null(); }

  // An ordered set of registered MemoryDumpProviderInfo(s), sorted by task
  // runner affinity (MDPs belonging to the same task runners are adjacent).
  MemoryDumpProviderInfo::OrderedSet dump_providers_;

  // Shared among all the PMDs to keep state scoped to the tracing session.
  scoped_refptr<HeapProfilerSerializationState>
      heap_profiler_serialization_state_;

  std::unique_ptr<MemoryTracingObserver> tracing_observer_;

  // Function provided by the embedder to handle global dump requests.
  RequestGlobalDumpFunction request_dump_function_;

  // True when current process coordinates the periodic dump triggering.
  bool is_coordinator_;

  // Protects from concurrent accesses to the local state, eg: to guard against
  // disabling logging while dumping on another thread.
  Lock lock_;

  // Thread used for MemoryDumpProviders which don't specify a task runner
  // affinity.
  std::unique_ptr<Thread> dump_thread_;

  // The unique id of the child process. This is created only for tracing and is
  // expected to be valid only when tracing is enabled.
  uint64_t tracing_process_id_;

  // When true, calling |RegisterMemoryDumpProvider| is a no-op.
  bool dumper_registrations_ignored_for_testing_;

  // Whether new memory dump providers should be told to enable heap profiling.
  bool heap_profiling_enabled_;

  DISALLOW_COPY_AND_ASSIGN(MemoryDumpManager);
};

}  // namespace trace_event
}  // namespace base

#endif  // BASE_TRACE_EVENT_MEMORY_DUMP_MANAGER_H_
