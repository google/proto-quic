// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/log/file_net_log_observer.h"

#include <limits>
#include <memory>
#include <queue>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/files/file_util.h"
#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread.h"
#include "base/values.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_entry.h"
#include "net/log/net_log_util.h"
#include "net/url_request/url_request_context.h"

namespace {

// Number of events that can build up in |write_queue_| before file thread
// is triggered to drain the queue.
const int kNumWriteQueueEvents = 15;

}  // namespace

namespace net {

// Used to store events to be written to file.
using EventQueue = std::queue<std::unique_ptr<std::string>>;

// WriteQueue receives events from FileNetLogObserver on the main thread and
// holds them in a queue until they are drained from the queue and written to
// file on the file thread.
//
// WriteQueue contains the resources shared between the main thread and the
// file thread. |lock_| must be acquired to read or write to |queue_| and
// |memory_|.
//
// WriteQueue is refcounted and should be destroyed once all events on the
// file thread have finished executing.
class FileNetLogObserver::WriteQueue
    : public base::RefCountedThreadSafe<WriteQueue> {
 public:
  // |memory_max| indicates the maximum amount of memory that the virtual write
  // queue can use. If |memory_| exceeds |memory_max_|, the |queue_| of events
  // is overwritten.
  explicit WriteQueue(size_t memory_max);

  // Adds |event| to |queue_|. Also manages the size of |memory_|; if it
  // exceeds |memory_max_|, then old events are dropped from |queue_| without
  // being written to file.
  //
  // Returns the number of events in the |queue_|.
  size_t AddEntryToQueue(std::unique_ptr<std::string> event);

  // Swaps |queue_| with |local_queue|. |local_queue| should be empty, so that
  // |queue_| is emptied. Resets |memory_| to 0.
  void SwapQueue(EventQueue* local_queue);

 private:
  friend class base::RefCountedThreadSafe<WriteQueue>;

  ~WriteQueue();

  // Queue of events to be written shared between main thread and file thread.
  // Main thread adds events to the queue and the file thread drains them and
  // writes the events to file.
  //
  // |lock_| must be acquired to read or write to this.
  EventQueue queue_;

  // Tracks how much memory is being used by the virtual write queue.
  // Incremented in AddEntryToQueue() when events are added to the
  // buffer, and decremented when SwapQueue() is called and the file thread's
  // local queue is swapped with the shared write queue.
  //
  // |lock_| must be acquired to read or write to this.
  size_t memory_;

  // Indicates the maximum amount of memory that the |queue_| is allowed to
  // use.
  const size_t memory_max_;

  // Protects access to |queue_| and |memory_|.
  //
  // A lock is necessary because |queue_| and |memory_| are shared between the
  // file thread and the main thread. NetLog's lock protects OnAddEntry(),
  // which calls AddEntryToQueue(), but it does not protect access to the
  // observer's member variables. Thus, a race condition exists if a thread is
  // calling OnAddEntry() at the same time that the file thread is accessing
  // |memory_| and |queue_| to write events to file. The |queue_| and |memory_|
  // counter are necessary to bound the amount of memory that is used for the
  // queue in the event that the file thread lags significantly behind the main
  // thread in writing events to file.
  base::Lock lock_;

  DISALLOW_COPY_AND_ASSIGN(WriteQueue);
};

// FileWriter is an interface describing an object that drains events from a
// WriteQueue and writes them to disk.
class FileNetLogObserver::FileWriter {
 public:
  virtual ~FileWriter();

  // Writes |constants_value| to disk and opens the events array (closed in
  // Stop()).
  virtual void Initialize(std::unique_ptr<base::Value> constants_value) = 0;

  // Closes the events array opened in Initialize() and writes |polled_data| to
  // disk. If |polled_data| cannot be converted to proper JSON, then it
  // is ignored.
  virtual void Stop(std::unique_ptr<base::Value> polled_data) = 0;

  // Drains |queue_| from WriteQueue into a local file queue and writes the
  // events in the queue to disk.
  virtual void Flush(scoped_refptr<WriteQueue> write_queue) = 0;

  // Deletes all netlog files. It is not valid to call any method of
  // FileNetLogObserver after DeleteAllFiles().
  virtual void DeleteAllFiles() = 0;

  void FlushThenStop(scoped_refptr<WriteQueue> write_queue,
                     std::unique_ptr<base::Value> polled_data);
};

// This implementation of FileWriter is used when the observer is in bounded
// mode.
// BoundedFileWriter can be constructed on any thread, and afterwards is only
// accessed on the file thread.
class FileNetLogObserver::BoundedFileWriter
    : public FileNetLogObserver::FileWriter {
 public:
  BoundedFileWriter(const base::FilePath& directory,
                    size_t max_file_size,
                    size_t total_num_files,
                    scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  ~BoundedFileWriter() override;

  // FileNetLogObserver::FileWriter implementation
  void Initialize(std::unique_ptr<base::Value> constants_value) override;
  void Stop(std::unique_ptr<base::Value> polled_data) override;
  void Flush(scoped_refptr<WriteQueue> write_queue) override;
  void DeleteAllFiles() override;

 private:
  // Increments |current_file_idx_|, and handles the clearing and openining of
  // the new current file. Also sets |event_files_[current_file_idx_]| to point
  // to the new current file.
  void IncrementCurrentFile();

  // Each ScopedFILE points to a netlog event file with the file name
  // "event_file_<index>.json".
  std::vector<base::ScopedFILE> event_files_;

  // The directory where the netlog files are created.
  const base::FilePath directory_;

  // Indicates the total number of netlog event files, which does not include
  // the constants file (constants.json), or closing file (end_netlog.json).
  const size_t total_num_files_;

  // Indicates the index of the file in |event_files_| currently being written
  // into.
  size_t current_file_idx_;

  // Indicates the maximum size of each individual netlogging file, excluding
  // the constant file.
  const size_t max_file_size_;

  // Task runner from the file thread.
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  DISALLOW_COPY_AND_ASSIGN(BoundedFileWriter);
};

// This implementation of FileWriter is used when the observer is in unbounded
// mode.
// UnboundedFileWriter can be constructed on any thread, and afterwards is only
// accessed on the file thread.
class FileNetLogObserver::UnboundedFileWriter
    : public FileNetLogObserver::FileWriter {
 public:
  UnboundedFileWriter(const base::FilePath& path,
                      scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  ~UnboundedFileWriter() override;

  // FileNetLogObserver::FileWriter implementation
  void Initialize(std::unique_ptr<base::Value> constants_value) override;
  void Stop(std::unique_ptr<base::Value> polled_data) override;
  void Flush(scoped_refptr<WriteQueue> write_queue) override;
  void DeleteAllFiles() override;

 private:
  base::FilePath file_path_;
  base::ScopedFILE file_;

  // Is set to true after the first event is written to the log file.
  bool first_event_written_;

  // Task runner from the file thread.
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  DISALLOW_COPY_AND_ASSIGN(UnboundedFileWriter);
};

std::unique_ptr<FileNetLogObserver> FileNetLogObserver::CreateBounded(
    scoped_refptr<base::SingleThreadTaskRunner> file_task_runner,
    const base::FilePath& directory,
    size_t max_total_size,
    size_t total_num_files,
    std::unique_ptr<base::Value> constants) {
  DCHECK_GT(total_num_files, 0u);
  // The BoundedFileWriter uses a soft limit to write events to file that allows
  // the size of the file to exceed the limit, but the WriteQueue uses a hard
  // limit which the size of |WriteQueue::queue_| cannot exceed. Thus, the
  // BoundedFileWriter may write more events to file than can be contained by
  // the WriteQueue if they have the same size limit. The maximum size of the
  // WriteQueue is doubled to allow |WriteQueue::queue_| to hold enough events
  // for the BoundedFileWriter to fill all files. As long as all events have
  // sizes <= the size of an individual event file, the discrepancy between the
  // hard limit and the soft limit will not cause an issue.
  // TODO(dconnol): Handle the case when the WriteQueue  still doesn't
  // contain enough events to fill all files, because of very large events
  // relative to file size.
  std::unique_ptr<FileWriter> file_writer(
      new BoundedFileWriter(directory, max_total_size / total_num_files,
                            total_num_files, file_task_runner));

  scoped_refptr<WriteQueue> write_queue(new WriteQueue(max_total_size * 2));

  return std::unique_ptr<FileNetLogObserver>(
      new FileNetLogObserver(file_task_runner, std::move(file_writer),
                             std::move(write_queue), std::move(constants)));
}

std::unique_ptr<FileNetLogObserver> FileNetLogObserver::CreateUnbounded(
    scoped_refptr<base::SingleThreadTaskRunner> file_task_runner,
    const base::FilePath& log_path,
    std::unique_ptr<base::Value> constants) {
  std::unique_ptr<FileWriter> file_writer(
      new UnboundedFileWriter(log_path, file_task_runner));

  scoped_refptr<WriteQueue> write_queue(
      new WriteQueue(std::numeric_limits<size_t>::max()));

  return std::unique_ptr<FileNetLogObserver>(
      new FileNetLogObserver(file_task_runner, std::move(file_writer),
                             std::move(write_queue), std::move(constants)));
}

FileNetLogObserver::~FileNetLogObserver() {
  if (net_log()) {
    // StopObserving was not called.
    file_task_runner_->PostTask(
        FROM_HERE, base::Bind(&FileNetLogObserver::FileWriter::DeleteAllFiles,
                              base::Unretained(file_writer_)));
    net_log()->DeprecatedRemoveObserver(this);
  }
  file_task_runner_->DeleteSoon(FROM_HERE, file_writer_);
}

void FileNetLogObserver::StartObserving(NetLog* net_log,
                                        NetLogCaptureMode capture_mode) {
  net_log->DeprecatedAddObserver(this, capture_mode);
}

void FileNetLogObserver::StopObserving(std::unique_ptr<base::Value> polled_data,
                                       const base::Closure& callback) {
  file_task_runner_->PostTaskAndReply(
      FROM_HERE, base::Bind(&FileNetLogObserver::FileWriter::FlushThenStop,
                            base::Unretained(file_writer_), write_queue_,
                            base::Passed(&polled_data)),
      callback);

  net_log()->DeprecatedRemoveObserver(this);
}

void FileNetLogObserver::OnAddEntry(const NetLogEntry& entry) {
  std::unique_ptr<std::string> json(new std::string);

  // If |entry| cannot be converted to proper JSON, ignore it.
  if (!base::JSONWriter::Write(*entry.ToValue(), json.get()))
    return;

  size_t queue_size = write_queue_->AddEntryToQueue(std::move(json));

  // If events build up in |write_queue_|, trigger the file thread to drain
  // the queue. Because only 1 item is added to the queue at a time, if
  // queue_size > kNumWriteQueueEvents a task has already been posted, or will
  // be posted.
  if (queue_size == kNumWriteQueueEvents) {
    file_task_runner_->PostTask(
        FROM_HERE, base::Bind(&FileNetLogObserver::FileWriter::Flush,
                              base::Unretained(file_writer_), write_queue_));
  }
}

FileNetLogObserver::FileNetLogObserver(
    scoped_refptr<base::SingleThreadTaskRunner> file_task_runner,
    std::unique_ptr<FileWriter> file_writer,
    scoped_refptr<WriteQueue> write_queue,
    std::unique_ptr<base::Value> constants)
    : file_task_runner_(std::move(file_task_runner)),
      write_queue_(std::move(write_queue)),
      file_writer_(file_writer.release()) {
  if (!constants)
    constants = GetNetConstants();
  file_task_runner_->PostTask(
      FROM_HERE,
      base::Bind(&FileNetLogObserver::FileWriter::Initialize,
                 base::Unretained(file_writer_), base::Passed(&constants)));
}

FileNetLogObserver::WriteQueue::WriteQueue(size_t memory_max)
    : memory_(0), memory_max_(memory_max) {}

size_t FileNetLogObserver::WriteQueue::AddEntryToQueue(
    std::unique_ptr<std::string> event) {
  base::AutoLock lock(lock_);

  memory_ += event->size();
  queue_.push(std::move(event));

  while (memory_ > memory_max_ && !queue_.empty()) {
    // Delete oldest events in the queue.
    DCHECK(queue_.front());
    memory_ -= queue_.front()->size();
    queue_.pop();
  }

  return queue_.size();
}

void FileNetLogObserver::WriteQueue::SwapQueue(EventQueue* local_queue) {
  DCHECK(local_queue->empty());
  base::AutoLock lock(lock_);
  queue_.swap(*local_queue);
  memory_ = 0;
}

FileNetLogObserver::WriteQueue::~WriteQueue() {}

FileNetLogObserver::FileWriter::~FileWriter() {}

void FileNetLogObserver::FileWriter::FlushThenStop(
    scoped_refptr<FileNetLogObserver::WriteQueue> write_queue,
    std::unique_ptr<base::Value> polled_data) {
  Flush(write_queue);
  Stop(std::move(polled_data));
}

FileNetLogObserver::BoundedFileWriter::BoundedFileWriter(
    const base::FilePath& directory,
    size_t max_file_size,
    size_t total_num_files,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : directory_(directory),
      total_num_files_(total_num_files),
      current_file_idx_(0),
      max_file_size_(max_file_size),
      task_runner_(task_runner) {
  event_files_.resize(total_num_files_);
}

FileNetLogObserver::BoundedFileWriter::~BoundedFileWriter() {}

void FileNetLogObserver::BoundedFileWriter::Initialize(
    std::unique_ptr<base::Value> constants_value) {
  DCHECK(task_runner_->RunsTasksOnCurrentThread());

  event_files_[current_file_idx_] = base::ScopedFILE(
      base::OpenFile(directory_.AppendASCII("event_file_0.json"), "w"));

  base::ScopedFILE constants_file(
      base::OpenFile(directory_.AppendASCII("constants.json"), "w"));

  // Print constants to file and open events array.
  std::string json;

  // It should always be possible to convert constants to JSON.
  if (!base::JSONWriter::Write(*constants_value, &json))
    DCHECK(false);
  fprintf(constants_file.get(), "{\"constants\":%s,\n\"events\": [\n",
          json.c_str());
}

void FileNetLogObserver::BoundedFileWriter::Stop(
    std::unique_ptr<base::Value> polled_data) {
  DCHECK(task_runner_->RunsTasksOnCurrentThread());

  base::ScopedFILE closing_file(
      base::OpenFile(directory_.AppendASCII("end_netlog.json"), "w"));

  std::string json;
  if (polled_data)
    base::JSONWriter::Write(*polled_data, &json);

  fprintf(closing_file.get(), "]%s}\n",
          json.empty() ? "" : (",\n\"polledData\": " + json + "\n").c_str());

  // Flush all fprintfs to disk so that files can be safely accessed on
  // callback.
  event_files_.clear();
}

void FileNetLogObserver::BoundedFileWriter::IncrementCurrentFile() {
  DCHECK(task_runner_->RunsTasksOnCurrentThread());

  current_file_idx_++;
  current_file_idx_ %= total_num_files_;
  event_files_[current_file_idx_].reset();
  event_files_[current_file_idx_] = base::ScopedFILE(base::OpenFile(
      directory_.AppendASCII("event_file_" +
                             base::SizeTToString(current_file_idx_) + ".json"),
      "w"));
}

void FileNetLogObserver::BoundedFileWriter::Flush(
    scoped_refptr<FileNetLogObserver::WriteQueue> write_queue) {
  DCHECK(task_runner_->RunsTasksOnCurrentThread());

  EventQueue local_file_queue;
  write_queue->SwapQueue(&local_file_queue);

  std::string to_print;
  size_t file_size = ftell(event_files_[current_file_idx_].get());
  size_t memory_freed = 0;

  while (!local_file_queue.empty()) {
    if (file_size >= max_file_size_) {
      // The current file is full. Start a new current file.
      IncrementCurrentFile();
      file_size = 0;
    }
    fprintf(event_files_[current_file_idx_].get(), "%s,\n",
            local_file_queue.front().get()->c_str());
    file_size += local_file_queue.front()->size();
    memory_freed += local_file_queue.front()->size();
    local_file_queue.pop();
  }
}

void FileNetLogObserver::BoundedFileWriter::DeleteAllFiles() {
  DCHECK(task_runner_->RunsTasksOnCurrentThread());

  // Reset |event_files_| to release all file handles so base::DeleteFile can
  // safely access files.
  event_files_.clear();

  base::DeleteFile(directory_.AppendASCII("constants.json"), false);
  base::DeleteFile(directory_.AppendASCII("end_netlog.json"), false);
  for (size_t i = 0; i < total_num_files_; i++) {
    base::DeleteFile(directory_.AppendASCII("event_file_" +
                                            base::SizeTToString(i) + ".json"),
                     false);
  }
}

FileNetLogObserver::UnboundedFileWriter::UnboundedFileWriter(
    const base::FilePath& path,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : file_path_(path), task_runner_(task_runner) {}

FileNetLogObserver::UnboundedFileWriter::~UnboundedFileWriter() {}

void FileNetLogObserver::UnboundedFileWriter::Initialize(
    std::unique_ptr<base::Value> constants_value) {
  DCHECK(task_runner_->RunsTasksOnCurrentThread());

  file_.reset(base::OpenFile(file_path_, "w"));
  first_event_written_ = false;

  // Print constants to file and open events array.
  std::string json;

  // It should always be possible to convert constants to JSON.
  if (!base::JSONWriter::Write(*constants_value, &json))
    DCHECK(false);
  fprintf(file_.get(), "{\"constants\":%s,\n\"events\": [\n", json.c_str());
}

void FileNetLogObserver::UnboundedFileWriter::Stop(
    std::unique_ptr<base::Value> polled_data) {
  DCHECK(task_runner_->RunsTasksOnCurrentThread());

  std::string json;
  if (polled_data)
    base::JSONWriter::Write(*polled_data, &json);

  fprintf(file_.get(), "]%s}\n",
          json.empty() ? "" : (",\n\"polledData\": " + json + "\n").c_str());

  // Flush all fprintfs to disk so that the file can be safely accessed on
  // callback.
  file_.reset();
}

void FileNetLogObserver::UnboundedFileWriter::Flush(
    scoped_refptr<FileNetLogObserver::WriteQueue> write_queue) {
  DCHECK(task_runner_->RunsTasksOnCurrentThread());

  EventQueue local_file_queue;
  write_queue->SwapQueue(&local_file_queue);

  while (!local_file_queue.empty()) {
    if (first_event_written_) {
      fputs(",\n", file_.get());
    } else {
      first_event_written_ = true;
    }
    fputs(local_file_queue.front()->c_str(), file_.get());
    local_file_queue.pop();
  }
}

void FileNetLogObserver::UnboundedFileWriter::DeleteAllFiles() {
  DCHECK(task_runner_->RunsTasksOnCurrentThread());

  // Reset |file_| to release the file handle so base::DeleteFile can
  // safely access it.
  file_.reset();
  base::DeleteFile(file_path_, false);
}

}  // namespace net
