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
// The consumer must call StartObserving before calling StopObserving, and must
// call each method exactly once in the lifetime of the observer. StartObserving
// and StopObserving must be called on the same thread, but there is no
// restriction on which thread is used.
class NET_EXPORT FileNetLogObserver : public NetLog::ThreadSafeObserver {
 public:
  // Creates a FileNetLogObserver in bounded mode.
  //
  // |file_task_runner| indicates the task runner that should be used to post
  // tasks from the main thread to the file thread.
  //
  // |directory| is the directory where the log files will be.
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
  static std::unique_ptr<FileNetLogObserver> CreateBounded(
      scoped_refptr<base::SingleThreadTaskRunner> file_task_runner,
      const base::FilePath& directory,
      size_t max_total_size,
      size_t total_num_files,
      std::unique_ptr<base::Value> constants);

  // Creates a FileNetLogObserver in unbounded mode.
  //
  // |file_task_runner| indicates the task runner that should be used to post
  // tasks from the main thread to the file thread.
  //
  // |log_path| is where the log file will be.
  //
  // |constants| is an optional legend for decoding constant values used in
  // the log. It should generally be a modified version of GetNetConstants().
  // If not present, the output of GetNetConstants() will be used.
  static std::unique_ptr<FileNetLogObserver> CreateUnbounded(
      scoped_refptr<base::SingleThreadTaskRunner> file_task_runner,
      const base::FilePath& log_path,
      std::unique_ptr<base::Value> constants);

  ~FileNetLogObserver() override;

  // Attaches this observer to |net_log| and begins observing events.
  void StartObserving(NetLog* net_log, NetLogCaptureMode capture_mode);

  // Stops observing net_log() and closes the output file(s). Must be called
  // after StartObserving. Should be called before destruction of the
  // FileNetLogObserver and the NetLog, or the NetLog files will be deleted when
  // the observer is destroyed.
  //
  // |polled_data| is an optional argument used to add additional network stack
  // state to the log.
  //
  // |callback| will be run on whichever thread StopObserving() was called on
  // once all file writing is complete and the netlog files can be accessed
  // safely.
  void StopObserving(std::unique_ptr<base::Value> polled_data,
                     const base::Closure& callback);

  // NetLog::ThreadSafeObserver
  void OnAddEntry(const NetLogEntry& entry) override;

 private:
  class WriteQueue;
  class FileWriter;
  class BoundedFileWriter;
  class UnboundedFileWriter;

  FileNetLogObserver(
      scoped_refptr<base::SingleThreadTaskRunner> file_task_runner,
      std::unique_ptr<FileWriter> file_writer,
      scoped_refptr<WriteQueue> write_queue,
      std::unique_ptr<base::Value> constants);

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
