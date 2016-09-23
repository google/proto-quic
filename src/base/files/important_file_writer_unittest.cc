// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/important_file_writer.h"

#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

namespace {

std::string GetFileContent(const FilePath& path) {
  std::string content;
  if (!ReadFileToString(path, &content)) {
    NOTREACHED();
  }
  return content;
}

class DataSerializer : public ImportantFileWriter::DataSerializer {
 public:
  explicit DataSerializer(const std::string& data) : data_(data) {
  }

  bool SerializeData(std::string* output) override {
    output->assign(data_);
    return true;
  }

 private:
  const std::string data_;
};

enum WriteCallbackObservationState {
  NOT_CALLED,
  CALLED_WITH_ERROR,
  CALLED_WITH_SUCCESS,
};

class WriteCallbackObserver {
 public:
  WriteCallbackObserver() : observation_state_(NOT_CALLED) {}

  // Register OnWrite() to be called on the next write of |writer|.
  void ObserveNextWriteCallback(ImportantFileWriter* writer);

  // Returns true if a write was observed via OnWrite()
  // and resets the observation state to false regardless.
  WriteCallbackObservationState GetAndResetObservationState();

 private:
  void OnWrite(bool success) {
    EXPECT_EQ(NOT_CALLED, observation_state_);
    observation_state_ = success ? CALLED_WITH_SUCCESS : CALLED_WITH_ERROR;
  }

  WriteCallbackObservationState observation_state_;

  DISALLOW_COPY_AND_ASSIGN(WriteCallbackObserver);
};

void WriteCallbackObserver::ObserveNextWriteCallback(
    ImportantFileWriter* writer) {
  writer->RegisterOnNextWriteCallback(
      base::Bind(&WriteCallbackObserver::OnWrite, base::Unretained(this)));
}

WriteCallbackObservationState
WriteCallbackObserver::GetAndResetObservationState() {
  WriteCallbackObservationState state = observation_state_;
  observation_state_ = NOT_CALLED;
  return state;
}

}  // namespace

class ImportantFileWriterTest : public testing::Test {
 public:
  ImportantFileWriterTest() { }
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    file_ = temp_dir_.GetPath().AppendASCII("test-file");
  }

 protected:
  WriteCallbackObserver write_callback_observer_;
  FilePath file_;
  MessageLoop loop_;

 private:
  ScopedTempDir temp_dir_;
};

TEST_F(ImportantFileWriterTest, Basic) {
  ImportantFileWriter writer(file_, ThreadTaskRunnerHandle::Get());
  EXPECT_FALSE(PathExists(writer.path()));
  EXPECT_EQ(NOT_CALLED, write_callback_observer_.GetAndResetObservationState());
  writer.WriteNow(MakeUnique<std::string>("foo"));
  RunLoop().RunUntilIdle();

  EXPECT_EQ(NOT_CALLED, write_callback_observer_.GetAndResetObservationState());
  ASSERT_TRUE(PathExists(writer.path()));
  EXPECT_EQ("foo", GetFileContent(writer.path()));
}

TEST_F(ImportantFileWriterTest, WriteWithObserver) {
  ImportantFileWriter writer(file_, ThreadTaskRunnerHandle::Get());
  EXPECT_FALSE(PathExists(writer.path()));
  EXPECT_EQ(NOT_CALLED, write_callback_observer_.GetAndResetObservationState());

  // Confirm that the observer is invoked.
  write_callback_observer_.ObserveNextWriteCallback(&writer);
  writer.WriteNow(MakeUnique<std::string>("foo"));
  RunLoop().RunUntilIdle();

  EXPECT_EQ(CALLED_WITH_SUCCESS,
            write_callback_observer_.GetAndResetObservationState());
  ASSERT_TRUE(PathExists(writer.path()));
  EXPECT_EQ("foo", GetFileContent(writer.path()));

  // Confirm that re-installing the observer works for another write.
  EXPECT_EQ(NOT_CALLED, write_callback_observer_.GetAndResetObservationState());
  write_callback_observer_.ObserveNextWriteCallback(&writer);
  writer.WriteNow(MakeUnique<std::string>("bar"));
  RunLoop().RunUntilIdle();

  EXPECT_EQ(CALLED_WITH_SUCCESS,
            write_callback_observer_.GetAndResetObservationState());
  ASSERT_TRUE(PathExists(writer.path()));
  EXPECT_EQ("bar", GetFileContent(writer.path()));

  // Confirm that writing again without re-installing the observer doesn't
  // result in a notification.
  EXPECT_EQ(NOT_CALLED, write_callback_observer_.GetAndResetObservationState());
  writer.WriteNow(MakeUnique<std::string>("baz"));
  RunLoop().RunUntilIdle();

  EXPECT_EQ(NOT_CALLED, write_callback_observer_.GetAndResetObservationState());
  ASSERT_TRUE(PathExists(writer.path()));
  EXPECT_EQ("baz", GetFileContent(writer.path()));
}

TEST_F(ImportantFileWriterTest, FailedWriteWithObserver) {
  // Use an invalid file path (relative paths are invalid) to get a
  // FILE_ERROR_ACCESS_DENIED error when trying to write the file.
  ImportantFileWriter writer(FilePath().AppendASCII("bad/../path"),
                             ThreadTaskRunnerHandle::Get());
  EXPECT_FALSE(PathExists(writer.path()));
  EXPECT_EQ(NOT_CALLED, write_callback_observer_.GetAndResetObservationState());
  write_callback_observer_.ObserveNextWriteCallback(&writer);
  writer.WriteNow(MakeUnique<std::string>("foo"));
  RunLoop().RunUntilIdle();

  // Confirm that the write observer was invoked with its boolean parameter set
  // to false.
  EXPECT_EQ(CALLED_WITH_ERROR,
            write_callback_observer_.GetAndResetObservationState());
  EXPECT_FALSE(PathExists(writer.path()));
}

TEST_F(ImportantFileWriterTest, CallbackRunsOnWriterThread) {
  base::Thread file_writer_thread("ImportantFileWriter test thread");
  file_writer_thread.Start();
  ImportantFileWriter writer(file_, file_writer_thread.task_runner());
  EXPECT_EQ(NOT_CALLED, write_callback_observer_.GetAndResetObservationState());

  write_callback_observer_.ObserveNextWriteCallback(&writer);
  writer.WriteNow(MakeUnique<std::string>("foo"));
  RunLoop().RunUntilIdle();

  // Expect the callback to not have been executed before the write.
  EXPECT_EQ(NOT_CALLED, write_callback_observer_.GetAndResetObservationState());

  // Make sure tasks posted by WriteNow() have ran before continuing.
  file_writer_thread.FlushForTesting();
  EXPECT_EQ(CALLED_WITH_SUCCESS,
            write_callback_observer_.GetAndResetObservationState());
  ASSERT_TRUE(PathExists(writer.path()));
  EXPECT_EQ("foo", GetFileContent(writer.path()));
}

TEST_F(ImportantFileWriterTest, ScheduleWrite) {
  ImportantFileWriter writer(file_,
                             ThreadTaskRunnerHandle::Get(),
                             TimeDelta::FromMilliseconds(25));
  EXPECT_FALSE(writer.HasPendingWrite());
  DataSerializer serializer("foo");
  writer.ScheduleWrite(&serializer);
  EXPECT_TRUE(writer.HasPendingWrite());
  ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, MessageLoop::QuitWhenIdleClosure(),
      TimeDelta::FromMilliseconds(100));
  RunLoop().Run();
  EXPECT_FALSE(writer.HasPendingWrite());
  ASSERT_TRUE(PathExists(writer.path()));
  EXPECT_EQ("foo", GetFileContent(writer.path()));
}

TEST_F(ImportantFileWriterTest, DoScheduledWrite) {
  ImportantFileWriter writer(file_, ThreadTaskRunnerHandle::Get());
  EXPECT_FALSE(writer.HasPendingWrite());
  DataSerializer serializer("foo");
  writer.ScheduleWrite(&serializer);
  EXPECT_TRUE(writer.HasPendingWrite());
  writer.DoScheduledWrite();
  ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, MessageLoop::QuitWhenIdleClosure(),
      TimeDelta::FromMilliseconds(100));
  RunLoop().Run();
  EXPECT_FALSE(writer.HasPendingWrite());
  ASSERT_TRUE(PathExists(writer.path()));
  EXPECT_EQ("foo", GetFileContent(writer.path()));
}

TEST_F(ImportantFileWriterTest, BatchingWrites) {
  ImportantFileWriter writer(file_,
                             ThreadTaskRunnerHandle::Get(),
                             TimeDelta::FromMilliseconds(25));
  DataSerializer foo("foo"), bar("bar"), baz("baz");
  writer.ScheduleWrite(&foo);
  writer.ScheduleWrite(&bar);
  writer.ScheduleWrite(&baz);
  ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, MessageLoop::QuitWhenIdleClosure(),
      TimeDelta::FromMilliseconds(100));
  RunLoop().Run();
  ASSERT_TRUE(PathExists(writer.path()));
  EXPECT_EQ("baz", GetFileContent(writer.path()));
}

}  // namespace base
