// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_LOG_FILE_NET_LOG_OBSERVER_H_
#define NET_LOG_FILE_NET_LOG_OBSERVER_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"
#include "net/log/net_log.h"

namespace base {
class Value;
class FilePath;
class SingleThreadTaskRunner;
}  // namespace base

namespace net {

class NetLogCaptureMode;
class URLRequestContext;

// FileNetLogObserver watches the NetLog event stream and sends all entries to
// either a group of files in a directory (bounded mode) or to a single file
// (unbounded mode).
//
// Bounded mode:
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
// Unbounded mode:
// The entire JSON object is put into one file. There is no size limit to how
// large this file can grow; all events added will be written to the file.
//
// The consumer must call StartObservingBounded/StartObservingUnbounded before
// calling StopObserving, and must call each method exactly once in the lifetime
// of the observer. StartObservingBounded/StartObservingUnbounded and
// StopObserving must be called on the same thread, but there is no restriction
// on which thread is used.
class NET_EXPORT FileNetLogObserver : public NetLog::ThreadSafeObserver {
 public:
  // |file_task_runner| indicates the task runner that should be used to post
  // tasks from the main thread to the file thread.
  explicit FileNetLogObserver(
      scoped_refptr<base::SingleThreadTaskRunner> file_task_runner);

  ~FileNetLogObserver() override;

  // Starts observing |net_log| in bounded mode and writes output files to
  // |directory|.
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
  // context is non-NULL, StartObservingBounded() must be called on the
  // context's thread.
  void StartObservingBounded(NetLog* net_log,
                             NetLogCaptureMode capture_mode,
                             const base::FilePath& directory,
                             std::unique_ptr<base::Value> constants,
                             URLRequestContext* url_request_context,
                             size_t max_total_size,
                             size_t total_num_files);

  // Starts observing |net_log| in unbounded mode and writes to the file at
  // |filepath|.
  // May only be called once in the lifetime of the object.
  //
  // |constants| is an optional legend for decoding constant values used in
  // the log. It should generally be a modified version of GetNetConstants().
  // If not present, the output of GetNetConstants() will be used.
  //
  // |url_request_context| is an optional URLRequestContext that will be used
  // to pre-populate the log with information about in-progress events. If the
  // context is non-NULL, StartObservingUnbounded() must be called on
  // the context's thread.
  void StartObservingUnbounded(NetLog* net_log,
                               NetLogCaptureMode capture_mode,
                               const base::FilePath& filepath,
                               std::unique_ptr<base::Value> constants,
                               URLRequestContext* url_request_context);

  // Stops observing net_log(). Must be called after StartObservingBounded/
  // StartObservingUnbounded. Should be called before destruction of the
  // FileNetLogObserver and the NetLog, or the NetLog files will be deleted when
  // the observer is destroyed.
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
  class BoundedFileWriter;
  class UnboundedFileWriter;

  // Performs tasks common to both StartObservingBounded() and
  // StartObservingUnbounded().
  void StartObservingHelper(NetLog* net_log,
                            NetLogCaptureMode capture_mode,
                            std::unique_ptr<base::Value> constants,
                            URLRequestContext* url_request_context);

  scoped_refptr<base::SingleThreadTaskRunner> file_task_runner_;

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

  DISALLOW_COPY_AND_ASSIGN(FileNetLogObserver);
};

}  // namespace net

#endif  // NET_LOG_FILE_NET_LOG_OBSERVER_H_
