// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BOUNDED_FILE_NET_LOG_OBSERVER_H_
#define BOUNDED_FILE_NET_LOG_OBSERVER_H_

#include <queue>

#include "base/files/file_path.h"
#include "base/files/scoped_file.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/net_export.h"
#include "net/log/net_log.h"
#include "net/log/net_log_capture_mode.h"

namespace base {
class Value;
}  // namespace base

namespace net {

class URLRequestContext;

// BoundedFileNetLogObserver watches the NetLog event stream and sends all
// entries to a group of files in the directory specified when observation
// starts.
//
// The events are written to a single JSON object that is split across the
// files, and the files must be stitched together once the observation period
// is over. The first file is constants.json, followed by a consumer-specified
// number of event files named event_file_<index>.json, and the last file is
// end_netlog.json.
//
// The user is able to specify an approximate maximum cumulative size for the
// netlog files and the observer overwrites old events when the maximum file
// size is reached.
//
// The consumer must call StartObserving before calling StopObserving, and must
// call each method exactly once in the lifetime of the observer. StartObserving
// and StopObserving must be called on the same thread, but there is no
// restriction on which thread is used.
class NET_EXPORT BoundedFileNetLogObserver : public NetLog::ThreadSafeObserver {
 public:
  // |task_runner| indicates the task runner that should be used to post tasks
  // from the main thread to the file thread.
  //
  // |num_event_files| sets the number of event files that should be used to
  // write events to file.
  BoundedFileNetLogObserver(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  ~BoundedFileNetLogObserver() override;

  // Sets the capture mode to log at. Must be called before StartObserving.
  void set_capture_mode(NetLogCaptureMode capture_mode);

  // Starts observing |net_log| and writes output to files in |filepath|.
  // May only be called once in the lifetime of the object.
  //
  // |max_total_size| is the approximate limit on the cumulative size of all
  // netlog files.
  //
  // |total_num_files| sets the total number of event files that are used to
  // write the events. It must be greater than 0.
  //
  // |constants| is an optional legend for decoding constant values used in
  // the log. It should generally be a modified version of GetNetConstants().
  // If not present, the output of GetNetConstants() will be used.
  //
  // |url_request_context| is an optional URLRequestContext that will be used
  // to pre-populate the log with information about in-progress events. If the
  // context is non-NULL, StartObserving() must be called on the context's
  // thread.
  void StartObserving(NetLog* net_log,
                      const base::FilePath& filepath,
                      base::Value* constants,
                      URLRequestContext* url_request_context,
                      size_t max_total_size,
                      size_t total_num_files);

  // Stops observing net_log(). Must be called after StartObserving(). Should
  // be called before destruction of the BoundedFileNetLogObserver and the
  // NetLog, or the NetLog files will be deleted when the observer is
  // destroyed.
  //
  // |callback| will be run on whichever thread StopObserving() was called on
  // once all file writing is complete and the netlog files can be accessed
  // safely.
  //
  // |url_request_context| is an optional argument used to add additional
  // network stack state to the log. If the context is non-NULL,
  // StopObserving() must be called on the context's thread.
  void StopObserving(URLRequestContext* url_request_context,
                     const base::Closure& callback);

  // NetLog::ThreadSafeObserver
  void OnAddEntry(const NetLogEntry& entry) override;

 private:
  class WriteQueue;
  class FileWriter;

  // The capture mode to log at.
  NetLogCaptureMode capture_mode_;

  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  // The |write_queue_| object is shared between the file thread and the main
  // thread, and should be alive for the entirety of the observer's lifetime.
  // It should be destroyed once both the observer has been destroyed and all
  // tasks posted to the file thread have completed.
  scoped_refptr<WriteQueue> write_queue_;

  // This is the owning reference to a file thread object. The observer is
  // responsible for destroying the file thread object by posting a task from
  // the main thread to the file thread to destroy the FileWriter when the
  // observer is destroyed.
  //
  // The use of base::Unretained with |file_writer_| to post tasks to the file
  // thread is safe because the FileWriter object will be alive until the
  // observer's destruction.
  FileWriter* file_writer_;

  DISALLOW_COPY_AND_ASSIGN(BoundedFileNetLogObserver);
};

}  // namespace net

#endif  // BOUNDED_FILE_NET_LOG_OBSERVER_H_
