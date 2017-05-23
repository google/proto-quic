// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/important_file_writer.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <utility>

#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/critical_closure.h"
#include "base/debug/alias.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/task_runner.h"
#include "base/task_runner_util.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "build/build_config.h"

namespace base {

namespace {

const int kDefaultCommitIntervalMs = 10000;

// This enum is used to define the buckets for an enumerated UMA histogram.
// Hence,
//   (a) existing enumerated constants should never be deleted or reordered, and
//   (b) new constants should only be appended at the end of the enumeration.
enum TempFileFailure {
  FAILED_CREATING,
  FAILED_OPENING,
  FAILED_CLOSING,  // Unused.
  FAILED_WRITING,
  FAILED_RENAMING,
  FAILED_FLUSHING,
  TEMP_FILE_FAILURE_MAX
};

void LogFailure(const FilePath& path, TempFileFailure failure_code,
                StringPiece message) {
  UMA_HISTOGRAM_ENUMERATION("ImportantFile.TempFileFailures", failure_code,
                            TEMP_FILE_FAILURE_MAX);
  DPLOG(WARNING) << "temp file failure: " << path.value() << " : " << message;
}

// Helper function to call WriteFileAtomically() with a
// std::unique_ptr<std::string>.
void WriteScopedStringToFileAtomically(
    const FilePath& path,
    std::unique_ptr<std::string> data,
    Closure before_write_callback,
    Callback<void(bool success)> after_write_callback) {
  if (!before_write_callback.is_null())
    before_write_callback.Run();

  bool result = ImportantFileWriter::WriteFileAtomically(path, *data);

  if (!after_write_callback.is_null())
    after_write_callback.Run(result);
}

}  // namespace

// static
bool ImportantFileWriter::WriteFileAtomically(const FilePath& path,
                                              StringPiece data) {
#if defined(OS_CHROMEOS)
  // On Chrome OS, chrome gets killed when it cannot finish shutdown quickly,
  // and this function seems to be one of the slowest shutdown steps.
  // Include some info to the report for investigation. crbug.com/418627
  // TODO(hashimoto): Remove this.
  struct {
    size_t data_size;
    char path[128];
  } file_info;
  file_info.data_size = data.size();
  strlcpy(file_info.path, path.value().c_str(), arraysize(file_info.path));
  debug::Alias(&file_info);
#endif

  // Write the data to a temp file then rename to avoid data loss if we crash
  // while writing the file. Ensure that the temp file is on the same volume
  // as target file, so it can be moved in one step, and that the temp file
  // is securely created.
  FilePath tmp_file_path;
  if (!CreateTemporaryFileInDir(path.DirName(), &tmp_file_path)) {
    LogFailure(path, FAILED_CREATING, "could not create temporary file");
    return false;
  }

  File tmp_file(tmp_file_path, File::FLAG_OPEN | File::FLAG_WRITE);
  if (!tmp_file.IsValid()) {
    LogFailure(path, FAILED_OPENING, "could not open temporary file");
    DeleteFile(tmp_file_path, false);
    return false;
  }

  // If this fails in the wild, something really bad is going on.
  const int data_length = checked_cast<int32_t>(data.length());
  int bytes_written = tmp_file.Write(0, data.data(), data_length);
  bool flush_success = tmp_file.Flush();
  tmp_file.Close();

  if (bytes_written < data_length) {
    LogFailure(path, FAILED_WRITING, "error writing, bytes_written=" +
               IntToString(bytes_written));
    DeleteFile(tmp_file_path, false);
    return false;
  }

  if (!flush_success) {
    LogFailure(path, FAILED_FLUSHING, "error flushing");
    DeleteFile(tmp_file_path, false);
    return false;
  }

  if (!ReplaceFile(tmp_file_path, path, nullptr)) {
    LogFailure(path, FAILED_RENAMING, "could not rename temporary file");
    DeleteFile(tmp_file_path, false);
    return false;
  }

  return true;
}

ImportantFileWriter::ImportantFileWriter(
    const FilePath& path,
    scoped_refptr<SequencedTaskRunner> task_runner)
    : ImportantFileWriter(
          path,
          std::move(task_runner),
          TimeDelta::FromMilliseconds(kDefaultCommitIntervalMs)) {}

ImportantFileWriter::ImportantFileWriter(
    const FilePath& path,
    scoped_refptr<SequencedTaskRunner> task_runner,
    TimeDelta interval)
    : path_(path),
      task_runner_(std::move(task_runner)),
      serializer_(nullptr),
      commit_interval_(interval),
      weak_factory_(this) {
  DCHECK(CalledOnValidThread());
  DCHECK(task_runner_);
}

ImportantFileWriter::~ImportantFileWriter() {
  // We're usually a member variable of some other object, which also tends
  // to be our serializer. It may not be safe to call back to the parent object
  // being destructed.
  DCHECK(!HasPendingWrite());
}

bool ImportantFileWriter::HasPendingWrite() const {
  DCHECK(CalledOnValidThread());
  return timer_.IsRunning();
}

void ImportantFileWriter::WriteNow(std::unique_ptr<std::string> data) {
  DCHECK(CalledOnValidThread());
  if (!IsValueInRangeForNumericType<int32_t>(data->length())) {
    NOTREACHED();
    return;
  }

  Closure task = AdaptCallbackForRepeating(
      BindOnce(&WriteScopedStringToFileAtomically, path_, std::move(data),
               std::move(before_next_write_callback_),
               std::move(after_next_write_callback_)));

  if (!task_runner_->PostTask(FROM_HERE, MakeCriticalClosure(task))) {
    // Posting the task to background message loop is not expected
    // to fail, but if it does, avoid losing data and just hit the disk
    // on the current thread.
    NOTREACHED();

    task.Run();
  }
  ClearPendingWrite();
}

void ImportantFileWriter::ScheduleWrite(DataSerializer* serializer) {
  DCHECK(CalledOnValidThread());

  DCHECK(serializer);
  serializer_ = serializer;

  if (!timer_.IsRunning()) {
    timer_.Start(FROM_HERE, commit_interval_, this,
                 &ImportantFileWriter::DoScheduledWrite);
  }
}

void ImportantFileWriter::DoScheduledWrite() {
  DCHECK(serializer_);
  std::unique_ptr<std::string> data(new std::string);
  if (serializer_->SerializeData(data.get())) {
    WriteNow(std::move(data));
  } else {
    DLOG(WARNING) << "failed to serialize data to be saved in "
                  << path_.value();
  }
  ClearPendingWrite();
}

void ImportantFileWriter::RegisterOnNextWriteCallbacks(
    const Closure& before_next_write_callback,
    const Callback<void(bool success)>& after_next_write_callback) {
  before_next_write_callback_ = before_next_write_callback;
  after_next_write_callback_ = after_next_write_callback;
}

void ImportantFileWriter::ClearPendingWrite() {
  timer_.Stop();
  serializer_ = nullptr;
}

}  // namespace base
