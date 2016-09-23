// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_TRACE_LOG_H_
#define BASE_TRACE_EVENT_TRACE_LOG_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "base/atomicops.h"
#include "base/containers/hash_tables.h"
#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/scoped_vector.h"
#include "base/trace_event/memory_dump_provider.h"
#include "base/trace_event/trace_config.h"
#include "base/trace_event/trace_event_impl.h"
#include "build/build_config.h"

namespace base {

template <typename Type>
struct DefaultSingletonTraits;
class RefCountedString;

namespace trace_event {

class TraceBuffer;
class TraceBufferChunk;
class TraceEvent;
class TraceEventMemoryOverhead;
class TraceSamplingThread;

struct BASE_EXPORT TraceLogStatus {
  TraceLogStatus();
  ~TraceLogStatus();
  uint32_t event_capacity;
  uint32_t event_count;
};

class BASE_EXPORT TraceLog : public MemoryDumpProvider {
 public:
  enum Mode {
    DISABLED = 0,
    RECORDING_MODE
  };

  // The pointer returned from GetCategoryGroupEnabledInternal() points to a
  // value with zero or more of the following bits. Used in this class only.
  // The TRACE_EVENT macros should only use the value as a bool.
  // These values must be in sync with macro values in TraceEvent.h in Blink.
  enum CategoryGroupEnabledFlags {
    // Category group enabled for the recording mode.
    ENABLED_FOR_RECORDING = 1 << 0,
    // Category group enabled by SetEventCallbackEnabled().
    ENABLED_FOR_EVENT_CALLBACK = 1 << 2,
    // Category group enabled to export events to ETW.
    ENABLED_FOR_ETW_EXPORT = 1 << 3,
    // Category group being filtered before logged.
    ENABLED_FOR_FILTERING = 1 << 4
  };

  static TraceLog* GetInstance();

  // Get set of known category groups. This can change as new code paths are
  // reached. The known category groups are inserted into |category_groups|.
  void GetKnownCategoryGroups(std::vector<std::string>* category_groups);

  // Retrieves a copy (for thread-safety) of the current TraceConfig.
  TraceConfig GetCurrentTraceConfig() const;

  // Initializes the thread-local event buffer, if not already initialized and
  // if the current thread supports that (has a message loop).
  void InitializeThreadLocalEventBufferIfSupported();

  // Enables normal tracing (recording trace events in the trace buffer).
  // See TraceConfig comments for details on how to control what categories
  // will be traced. If tracing has already been enabled, |category_filter| will
  // be merged into the current category filter.
  void SetEnabled(const TraceConfig& trace_config, Mode mode);

  // Disables normal tracing for all categories.
  void SetDisabled();

  bool IsEnabled() { return mode_ != DISABLED; }

  // The number of times we have begun recording traces. If tracing is off,
  // returns -1. If tracing is on, then it returns the number of times we have
  // recorded a trace. By watching for this number to increment, you can
  // passively discover when a new trace has begun. This is then used to
  // implement the TRACE_EVENT_IS_NEW_TRACE() primitive.
  int GetNumTracesRecorded();

#if defined(OS_ANDROID)
  void StartATrace();
  void StopATrace();
  void AddClockSyncMetadataEvent();
#endif

  // Enabled state listeners give a callback when tracing is enabled or
  // disabled. This can be used to tie into other library's tracing systems
  // on-demand.
  class BASE_EXPORT EnabledStateObserver {
   public:
    virtual ~EnabledStateObserver() = default;

    // Called just after the tracing system becomes enabled, outside of the
    // |lock_|. TraceLog::IsEnabled() is true at this point.
    virtual void OnTraceLogEnabled() = 0;

    // Called just after the tracing system disables, outside of the |lock_|.
    // TraceLog::IsEnabled() is false at this point.
    virtual void OnTraceLogDisabled() = 0;
  };
  void AddEnabledStateObserver(EnabledStateObserver* listener);
  void RemoveEnabledStateObserver(EnabledStateObserver* listener);
  bool HasEnabledStateObserver(EnabledStateObserver* listener) const;

  // Asynchronous enabled state listeners. When tracing is enabled or disabled,
  // for each observer, a task for invoking its appropriate callback is posted
  // to the thread from which AddAsyncEnabledStateObserver() was called. This
  // allows the observer to be safely destroyed, provided that it happens on the
  // same thread that invoked AddAsyncEnabledStateObserver().
  class BASE_EXPORT AsyncEnabledStateObserver {
   public:
    virtual ~AsyncEnabledStateObserver() = default;

    // Posted just after the tracing system becomes enabled, outside |lock_|.
    // TraceLog::IsEnabled() is true at this point.
    virtual void OnTraceLogEnabled() = 0;

    // Posted just after the tracing system becomes disabled, outside |lock_|.
    // TraceLog::IsEnabled() is false at this point.
    virtual void OnTraceLogDisabled() = 0;
  };
  void AddAsyncEnabledStateObserver(
      WeakPtr<AsyncEnabledStateObserver> listener);
  void RemoveAsyncEnabledStateObserver(AsyncEnabledStateObserver* listener);
  bool HasAsyncEnabledStateObserver(AsyncEnabledStateObserver* listener) const;

  TraceLogStatus GetStatus() const;
  bool BufferIsFull() const;

  // Computes an estimate of the size of the TraceLog including all the retained
  // objects.
  void EstimateTraceMemoryOverhead(TraceEventMemoryOverhead* overhead);

  // Not using base::Callback because of its limited by 7 parameters.
  // Also, using primitive type allows directly passing callback from WebCore.
  // WARNING: It is possible for the previously set callback to be called
  // after a call to SetEventCallbackEnabled() that replaces or a call to
  // SetEventCallbackDisabled() that disables the callback.
  // This callback may be invoked on any thread.
  // For TRACE_EVENT_PHASE_COMPLETE events, the client will still receive pairs
  // of TRACE_EVENT_PHASE_BEGIN and TRACE_EVENT_PHASE_END events to keep the
  // interface simple.
  typedef void (*EventCallback)(TimeTicks timestamp,
                                char phase,
                                const unsigned char* category_group_enabled,
                                const char* name,
                                const char* scope,
                                unsigned long long id,
                                int num_args,
                                const char* const arg_names[],
                                const unsigned char arg_types[],
                                const unsigned long long arg_values[],
                                unsigned int flags);

  // Enable tracing for EventCallback.
  void SetEventCallbackEnabled(const TraceConfig& trace_config,
                               EventCallback cb);
  void SetEventCallbackDisabled();
  void SetArgumentFilterPredicate(
      const ArgumentFilterPredicate& argument_filter_predicate);

  // Flush all collected events to the given output callback. The callback will
  // be called one or more times either synchronously or asynchronously from
  // the current thread with IPC-bite-size chunks. The string format is
  // undefined. Use TraceResultBuffer to convert one or more trace strings to
  // JSON. The callback can be null if the caller doesn't want any data.
  // Due to the implementation of thread-local buffers, flush can't be
  // done when tracing is enabled. If called when tracing is enabled, the
  // callback will be called directly with (empty_string, false) to indicate
  // the end of this unsuccessful flush. Flush does the serialization
  // on the same thread if the caller doesn't set use_worker_thread explicitly.
  typedef base::Callback<void(const scoped_refptr<base::RefCountedString>&,
                              bool has_more_events)> OutputCallback;
  void Flush(const OutputCallback& cb, bool use_worker_thread = false);

  // Cancels tracing and discards collected data.
  void CancelTracing(const OutputCallback& cb);

  // Called by TRACE_EVENT* macros, don't call this directly.
  // The name parameter is a category group for example:
  // TRACE_EVENT0("renderer,webkit", "WebViewImpl::HandleInputEvent")
  static const unsigned char* GetCategoryGroupEnabled(const char* name);
  static const char* GetCategoryGroupName(
      const unsigned char* category_group_enabled);

  // Called by TRACE_EVENT* macros, don't call this directly.
  // If |copy| is set, |name|, |arg_name1| and |arg_name2| will be deep copied
  // into the event; see "Memory scoping note" and TRACE_EVENT_COPY_XXX above.
  TraceEventHandle AddTraceEvent(
      char phase,
      const unsigned char* category_group_enabled,
      const char* name,
      const char* scope,
      unsigned long long id,
      int num_args,
      const char** arg_names,
      const unsigned char* arg_types,
      const unsigned long long* arg_values,
      std::unique_ptr<ConvertableToTraceFormat>* convertable_values,
      unsigned int flags);
  TraceEventHandle AddTraceEventWithBindId(
      char phase,
      const unsigned char* category_group_enabled,
      const char* name,
      const char* scope,
      unsigned long long id,
      unsigned long long bind_id,
      int num_args,
      const char** arg_names,
      const unsigned char* arg_types,
      const unsigned long long* arg_values,
      std::unique_ptr<ConvertableToTraceFormat>* convertable_values,
      unsigned int flags);
  TraceEventHandle AddTraceEventWithProcessId(
      char phase,
      const unsigned char* category_group_enabled,
      const char* name,
      const char* scope,
      unsigned long long id,
      int process_id,
      int num_args,
      const char** arg_names,
      const unsigned char* arg_types,
      const unsigned long long* arg_values,
      std::unique_ptr<ConvertableToTraceFormat>* convertable_values,
      unsigned int flags);
  TraceEventHandle AddTraceEventWithThreadIdAndTimestamp(
      char phase,
      const unsigned char* category_group_enabled,
      const char* name,
      const char* scope,
      unsigned long long id,
      int thread_id,
      const TimeTicks& timestamp,
      int num_args,
      const char** arg_names,
      const unsigned char* arg_types,
      const unsigned long long* arg_values,
      std::unique_ptr<ConvertableToTraceFormat>* convertable_values,
      unsigned int flags);
  TraceEventHandle AddTraceEventWithThreadIdAndTimestamp(
      char phase,
      const unsigned char* category_group_enabled,
      const char* name,
      const char* scope,
      unsigned long long id,
      unsigned long long bind_id,
      int thread_id,
      const TimeTicks& timestamp,
      int num_args,
      const char** arg_names,
      const unsigned char* arg_types,
      const unsigned long long* arg_values,
      std::unique_ptr<ConvertableToTraceFormat>* convertable_values,
      unsigned int flags);

  // Adds a metadata event that will be written when the trace log is flushed.
  void AddMetadataEvent(
      const unsigned char* category_group_enabled,
      const char* name,
      int num_args,
      const char** arg_names,
      const unsigned char* arg_types,
      const unsigned long long* arg_values,
      std::unique_ptr<ConvertableToTraceFormat>* convertable_values,
      unsigned int flags);

  void UpdateTraceEventDuration(const unsigned char* category_group_enabled,
                                const char* name,
                                TraceEventHandle handle);

  void EndFilteredEvent(const unsigned char* category_group_enabled,
                        const char* name,
                        TraceEventHandle handle);

  // For every matching event, the callback will be called.
  typedef base::Callback<void()> WatchEventCallback;
  void SetWatchEvent(const std::string& category_name,
                     const std::string& event_name,
                     const WatchEventCallback& callback);
  // Cancel the watch event. If tracing is enabled, this may race with the
  // watch event notification firing.
  void CancelWatchEvent();

  int process_id() const { return process_id_; }

  uint64_t MangleEventId(uint64_t id);

  // Exposed for unittesting:

  void WaitSamplingEventForTesting();

  // Allows deleting our singleton instance.
  static void DeleteForTesting();

  class BASE_EXPORT TraceEventFilter {
   public:
    static const char* const kEventWhitelistPredicate;
    static const char* const kHeapProfilerPredicate;

    TraceEventFilter() {}
    virtual ~TraceEventFilter() {}
    virtual bool FilterTraceEvent(const TraceEvent& trace_event) const = 0;
    virtual void EndEvent(const char* category_group, const char* name) {}

   private:
    DISALLOW_COPY_AND_ASSIGN(TraceEventFilter);
  };
  typedef std::unique_ptr<TraceEventFilter> (
      *TraceEventFilterConstructorForTesting)(void);
  static void SetTraceEventFilterConstructorForTesting(
      TraceEventFilterConstructorForTesting predicate);

  // Allow tests to inspect TraceEvents.
  TraceEvent* GetEventByHandle(TraceEventHandle handle);

  void SetProcessID(int process_id);

  // Process sort indices, if set, override the order of a process will appear
  // relative to other processes in the trace viewer. Processes are sorted first
  // on their sort index, ascending, then by their name, and then tid.
  void SetProcessSortIndex(int sort_index);

  // Sets the name of the process. |process_name| should be a string literal
  // since it is a whitelisted argument for background field trials.
  void SetProcessName(const char* process_name);

  // Processes can have labels in addition to their names. Use labels, for
  // instance, to list out the web page titles that a process is handling.
  void UpdateProcessLabel(int label_id, const std::string& current_label);
  void RemoveProcessLabel(int label_id);

  // Thread sort indices, if set, override the order of a thread will appear
  // within its process in the trace viewer. Threads are sorted first on their
  // sort index, ascending, then by their name, and then tid.
  void SetThreadSortIndex(PlatformThreadId thread_id, int sort_index);

  // Allow setting an offset between the current TimeTicks time and the time
  // that should be reported.
  void SetTimeOffset(TimeDelta offset);

  size_t GetObserverCountForTest() const;

  // Call this method if the current thread may block the message loop to
  // prevent the thread from using the thread-local buffer because the thread
  // may not handle the flush request in time causing lost of unflushed events.
  void SetCurrentThreadBlocksMessageLoop();

#if defined(OS_WIN)
  // This function is called by the ETW exporting module whenever the ETW
  // keyword (flags) changes. This keyword indicates which categories should be
  // exported, so whenever it changes, we adjust accordingly.
  void UpdateETWCategoryGroupEnabledFlags();
#endif

 private:
  typedef unsigned int InternalTraceOptions;

  FRIEND_TEST_ALL_PREFIXES(TraceEventTestFixture,
                           TraceBufferRingBufferGetReturnChunk);
  FRIEND_TEST_ALL_PREFIXES(TraceEventTestFixture,
                           TraceBufferRingBufferHalfIteration);
  FRIEND_TEST_ALL_PREFIXES(TraceEventTestFixture,
                           TraceBufferRingBufferFullIteration);
  FRIEND_TEST_ALL_PREFIXES(TraceEventTestFixture, TraceBufferVectorReportFull);
  FRIEND_TEST_ALL_PREFIXES(TraceEventTestFixture,
                           ConvertTraceConfigToInternalOptions);
  FRIEND_TEST_ALL_PREFIXES(TraceEventTestFixture,
                           TraceRecordAsMuchAsPossibleMode);

  // This allows constructor and destructor to be private and usable only
  // by the Singleton class.
  friend struct DefaultSingletonTraits<TraceLog>;

  // MemoryDumpProvider implementation.
  bool OnMemoryDump(const MemoryDumpArgs& args,
                    ProcessMemoryDump* pmd) override;

  // Enable/disable each category group based on the current mode_,
  // category_filter_, event_callback_ and event_callback_category_filter_.
  // Enable the category group in the enabled mode if category_filter_ matches
  // the category group, or event_callback_ is not null and
  // event_callback_category_filter_ matches the category group.
  void UpdateCategoryGroupEnabledFlags();
  void UpdateCategoryGroupEnabledFlag(size_t category_index);

  void CreateFiltersForTraceConfig();

  // Configure synthetic delays based on the values set in the current
  // trace config.
  void UpdateSyntheticDelaysFromTraceConfig();

  InternalTraceOptions GetInternalOptionsFromTraceConfig(
      const TraceConfig& config);

  class ThreadLocalEventBuffer;
  class OptionalAutoLock;
  struct RegisteredAsyncObserver;

  TraceLog();
  ~TraceLog() override;
  const unsigned char* GetCategoryGroupEnabledInternal(const char* name);
  void AddMetadataEventsWhileLocked();

  InternalTraceOptions trace_options() const {
    return static_cast<InternalTraceOptions>(
        subtle::NoBarrier_Load(&trace_options_));
  }

  TraceBuffer* trace_buffer() const { return logged_events_.get(); }
  TraceBuffer* CreateTraceBuffer();

  std::string EventToConsoleMessage(unsigned char phase,
                                    const TimeTicks& timestamp,
                                    TraceEvent* trace_event);

  TraceEvent* AddEventToThreadSharedChunkWhileLocked(TraceEventHandle* handle,
                                                     bool check_buffer_is_full);
  void CheckIfBufferIsFullWhileLocked();
  void SetDisabledWhileLocked();

  TraceEvent* GetEventByHandleInternal(TraceEventHandle handle,
                                       OptionalAutoLock* lock);

  void FlushInternal(const OutputCallback& cb,
                     bool use_worker_thread,
                     bool discard_events);

  // |generation| is used in the following callbacks to check if the callback
  // is called for the flush of the current |logged_events_|.
  void FlushCurrentThread(int generation, bool discard_events);
  // Usually it runs on a different thread.
  static void ConvertTraceEventsToTraceFormat(
      std::unique_ptr<TraceBuffer> logged_events,
      const TraceLog::OutputCallback& flush_output_callback,
      const ArgumentFilterPredicate& argument_filter_predicate);
  void FinishFlush(int generation, bool discard_events);
  void OnFlushTimeout(int generation, bool discard_events);

  int generation() const {
    return static_cast<int>(subtle::NoBarrier_Load(&generation_));
  }
  bool CheckGeneration(int generation) const {
    return generation == this->generation();
  }
  void UseNextTraceBuffer();

  TimeTicks OffsetNow() const { return OffsetTimestamp(TimeTicks::Now()); }
  TimeTicks OffsetTimestamp(const TimeTicks& timestamp) const {
    return timestamp - time_offset_;
  }

  // Internal representation of trace options since we store the currently used
  // trace option as an AtomicWord.
  static const InternalTraceOptions kInternalNone;
  static const InternalTraceOptions kInternalRecordUntilFull;
  static const InternalTraceOptions kInternalRecordContinuously;
  static const InternalTraceOptions kInternalEchoToConsole;
  static const InternalTraceOptions kInternalEnableSampling;
  static const InternalTraceOptions kInternalRecordAsMuchAsPossible;
  static const InternalTraceOptions kInternalEnableArgumentFilter;

  // This lock protects TraceLog member accesses (except for members protected
  // by thread_info_lock_) from arbitrary threads.
  mutable Lock lock_;
  // This lock protects accesses to thread_names_, thread_event_start_times_
  // and thread_colors_.
  Lock thread_info_lock_;
  Mode mode_;
  int num_traces_recorded_;
  std::unique_ptr<TraceBuffer> logged_events_;
  std::vector<std::unique_ptr<TraceEvent>> metadata_events_;
  subtle::AtomicWord /* EventCallback */ event_callback_;
  bool dispatching_to_observer_list_;
  std::vector<EnabledStateObserver*> enabled_state_observer_list_;
  std::map<AsyncEnabledStateObserver*, RegisteredAsyncObserver>
      async_observers_;

  std::string process_name_;
  base::hash_map<int, std::string> process_labels_;
  int process_sort_index_;
  base::hash_map<int, int> thread_sort_indices_;
  base::hash_map<int, std::string> thread_names_;

  // The following two maps are used only when ECHO_TO_CONSOLE.
  base::hash_map<int, std::stack<TimeTicks>> thread_event_start_times_;
  base::hash_map<std::string, int> thread_colors_;

  TimeTicks buffer_limit_reached_timestamp_;

  // XORed with TraceID to make it unlikely to collide with other processes.
  unsigned long long process_id_hash_;

  int process_id_;

  TimeDelta time_offset_;

  // Allow tests to wake up when certain events occur.
  WatchEventCallback watch_event_callback_;
  subtle::AtomicWord /* const unsigned char* */ watch_category_;
  std::string watch_event_name_;

  subtle::AtomicWord /* Options */ trace_options_;

  // Sampling thread handles.
  std::unique_ptr<TraceSamplingThread> sampling_thread_;
  PlatformThreadHandle sampling_thread_handle_;

  TraceConfig trace_config_;
  TraceConfig event_callback_trace_config_;

  ThreadLocalPointer<ThreadLocalEventBuffer> thread_local_event_buffer_;
  ThreadLocalBoolean thread_blocks_message_loop_;
  ThreadLocalBoolean thread_is_in_trace_event_;

  // Contains the message loops of threads that have had at least one event
  // added into the local event buffer. Not using SingleThreadTaskRunner
  // because we need to know the life time of the message loops.
  hash_set<MessageLoop*> thread_message_loops_;

  // For events which can't be added into the thread local buffer, e.g. events
  // from threads without a message loop.
  std::unique_ptr<TraceBufferChunk> thread_shared_chunk_;
  size_t thread_shared_chunk_index_;

  // Set when asynchronous Flush is in progress.
  OutputCallback flush_output_callback_;
  scoped_refptr<SingleThreadTaskRunner> flush_task_runner_;
  ArgumentFilterPredicate argument_filter_predicate_;
  subtle::AtomicWord generation_;
  bool use_worker_thread_;

  DISALLOW_COPY_AND_ASSIGN(TraceLog);
};

}  // namespace trace_event
}  // namespace base

#endif  // BASE_TRACE_EVENT_TRACE_LOG_H_
