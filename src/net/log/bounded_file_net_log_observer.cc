// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/log/bounded_file_net_log_observer.h"

#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/files/file_util.h"
#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread.h"
#include "base/values.h"
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

// WriteQueue receives events from BoundedFileNetLogObserver on the main
// thread and holds them in a queue until they are drained from the queue
// and written to file on the file thread.
//
// WriteQueue contains the resources shared between the main thread and the
// file thread. |lock_| must be acquired to read or write to |queue_| and
// |memory_|.
//
// WriteQueue is refcounted and should be destroyed once all events on the
// file thread have finished executing.
class BoundedFileNetLogObserver::WriteQueue
    : public base::RefCountedThreadSafe<WriteQueue> {
 public:
  // |memory_max| indicates the maximum amount of memory that the virtual write
  // queue can use. If |memory_| exceeds |memory_max_|, the |queue_| of events
  // is overwritten.
  WriteQueue(size_t memory_max);

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

// FileWriter drains events from WriteQueue and writes them to file.
//
// Owned by BoundedFileNetLogObserver. FileWriter can be constructed on any
// thread, and afterwards is only accessed on the file thread.
class BoundedFileNetLogObserver::FileWriter {
 public:
  FileWriter(const base::FilePath& path,
             size_t max_file_size,
             size_t total_num_files,
             scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  ~FileWriter();

  // Writes |constants_value| to constants.json, and opens the
  // events array (closed in Stop()).
  void Initialize(std::unique_ptr<base::Value> constants_value);

  // Closes the events array opened in Initialize() and writes |tab_info| to
  // end_netlog.json. If |tab_info| cannot be converted to proper JSON, then it
  // is ignored.
  void Stop(std::unique_ptr<base::Value> tab_info);

  // Drains |queue_| from WriteQueue into a local file queue and writes the
  // events in the queue to file.
  void Flush(scoped_refptr<WriteQueue> write_queue);

  // Deletes all netlog files, including constants.json and end_netlog.json.
  // It is not valid to call any method of BoundedFileNetLogObserver after
  // DeleteAllFiles().
  void DeleteAllFiles();

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

  DISALLOW_COPY_AND_ASSIGN(FileWriter);
};

BoundedFileNetLogObserver::BoundedFileNetLogObserver(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : capture_mode_(NetLogCaptureMode::Default()), task_runner_(task_runner) {}

BoundedFileNetLogObserver::~BoundedFileNetLogObserver() {
  if (net_log()) {
    // StopObserving was not called.
    task_runner_->PostTask(
        FROM_HERE,
        base::Bind(&BoundedFileNetLogObserver::FileWriter::DeleteAllFiles,
                   base::Unretained(file_writer_)));
    net_log()->DeprecatedRemoveObserver(this);
  }

  task_runner_->DeleteSoon(FROM_HERE, file_writer_);
}

void BoundedFileNetLogObserver::set_capture_mode(
    NetLogCaptureMode capture_mode) {
  DCHECK(!net_log());
  capture_mode_ = capture_mode;
}

void BoundedFileNetLogObserver::StartObserving(
    NetLog* net_log,
    const base::FilePath& filepath,
    base::Value* constants,
    URLRequestContext* url_request_context,
    size_t max_total_size,
    size_t total_num_files) {
  DCHECK_GT(total_num_files, 0u);

  file_writer_ = new FileWriter(filepath, max_total_size / total_num_files,
                                total_num_files, task_runner_);

  // The |file_writer_| uses a soft limit to write events to file that allows
  // the size of the file to exceed the limit, but the |write_queue_| uses a
  // hard limit which the size of the |queue_| cannot exceed. Thus, the
  // |file_writer_| may write more events to file than can be contained by the
  // |write_queue_| if they have the same size limit. The maximum size of the
  // |write_queue_| is doubled to allow the |queue_| to hold enough events for
  // the |file_writer_| to fill all files. As long as all events have sizes <=
  // the size of an individual event file, the discrepancy between the hard
  // limit and the soft limit will not cause an issue.
  // TODO(dconnol): Handle the case when the |write_queue_| still doesn't
  // contain enough events to fill all files, because of very large events
  // relative to file size.
  write_queue_ = make_scoped_refptr(new WriteQueue(max_total_size * 2));

  task_runner_->PostTask(
      FROM_HERE, base::Bind(&BoundedFileNetLogObserver::FileWriter::Initialize,
                            base::Unretained(file_writer_),
                            base::Passed(constants ? constants->CreateDeepCopy()
                                                   : GetNetConstants())));

  if (url_request_context) {
    DCHECK(url_request_context->CalledOnValidThread());
    std::set<URLRequestContext*> contexts;
    contexts.insert(url_request_context);
    CreateNetLogEntriesForActiveObjects(contexts, this);
  }

  net_log->DeprecatedAddObserver(this, capture_mode_);
}

void BoundedFileNetLogObserver::StopObserving(
    URLRequestContext* url_request_context,
    const base::Closure& callback) {
  task_runner_->PostTask(
      FROM_HERE, base::Bind(&BoundedFileNetLogObserver::FileWriter::Flush,
                            base::Unretained(file_writer_), write_queue_));

  task_runner_->PostTaskAndReply(
      FROM_HERE, base::Bind(&BoundedFileNetLogObserver::FileWriter::Stop,
                            base::Unretained(file_writer_),
                            base::Passed(url_request_context
                                             ? GetNetInfo(url_request_context,
                                                          NET_INFO_ALL_SOURCES)
                                             : nullptr)),
      callback);

  net_log()->DeprecatedRemoveObserver(this);
}

void BoundedFileNetLogObserver::OnAddEntry(const NetLogEntry& entry) {
  std::unique_ptr<std::string> json(new std::string);

  // If |entry| cannot be converted to proper JSON, ignore it.
  if (!base::JSONWriter::Write(*entry.ToValue(), json.get()))
    return;

  size_t queue_size = write_queue_->AddEntryToQueue(std::move(json));

  // If events build up in |write_queue_|, trigger the file thread to drain
  // the queue.
  if (queue_size >= kNumWriteQueueEvents) {
    task_runner_->PostTask(
        FROM_HERE, base::Bind(&BoundedFileNetLogObserver::FileWriter::Flush,
                              base::Unretained(file_writer_), write_queue_));
  }
}

BoundedFileNetLogObserver::WriteQueue::WriteQueue(size_t memory_max)
    : memory_(0), memory_max_(memory_max) {}

size_t BoundedFileNetLogObserver::WriteQueue::AddEntryToQueue(
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
void BoundedFileNetLogObserver::WriteQueue::SwapQueue(EventQueue* local_queue) {
  DCHECK(local_queue->empty());
  base::AutoLock lock(lock_);
  queue_.swap(*local_queue);
  memory_ = 0;
}

BoundedFileNetLogObserver::WriteQueue::~WriteQueue() {}

BoundedFileNetLogObserver::FileWriter::FileWriter(
    const base::FilePath& path,
    size_t max_file_size,
    size_t total_num_files,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : directory_(path),
      total_num_files_(total_num_files),
      current_file_idx_(0),
      max_file_size_(max_file_size),
      task_runner_(task_runner) {
  event_files_.resize(total_num_files_);
}

BoundedFileNetLogObserver::FileWriter::~FileWriter() {}

void BoundedFileNetLogObserver::FileWriter::Initialize(
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

void BoundedFileNetLogObserver::FileWriter::Stop(
    std::unique_ptr<base::Value> tab_info) {
  DCHECK(task_runner_->RunsTasksOnCurrentThread());

  base::ScopedFILE closing_file(
      base::OpenFile(directory_.AppendASCII("end_netlog.json"), "w"));

  std::string json;
  if (tab_info)
    base::JSONWriter::Write(*tab_info, &json);

  fprintf(closing_file.get(), "]%s}",
          json.empty() ? "" : (",\"tabInfo\": " + json + "\n").c_str());

  // Flush all fprintfs to disk so that files can be safely accessed on
  // callback.
  event_files_.clear();
}

void BoundedFileNetLogObserver::FileWriter::IncrementCurrentFile() {
  DCHECK(task_runner_->RunsTasksOnCurrentThread());

  current_file_idx_++;
  current_file_idx_ %= total_num_files_;
  event_files_[current_file_idx_].reset();
  event_files_[current_file_idx_] = base::ScopedFILE(base::OpenFile(
      directory_.AppendASCII("event_file_" +
                             base::SizeTToString(current_file_idx_) + ".json"),
      "w"));
}

void BoundedFileNetLogObserver::FileWriter::Flush(
    scoped_refptr<BoundedFileNetLogObserver::WriteQueue> write_queue) {
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

void BoundedFileNetLogObserver::FileWriter::DeleteAllFiles() {
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

}  // namespace net
