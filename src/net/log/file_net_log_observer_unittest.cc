// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/log/file_net_log_observer.h"

#include <math.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/files/scoped_temp_dir.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread.h"
#include "base/values.h"
#include "net/base/test_completion_callback.h"
#include "net/log/net_log_entry.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_parameters_callback.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_util.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// Indicates the number of event files used in test cases.
const int kTotalNumFiles = 10;

// Used to set the total file size maximum in test cases where the file size
// doesn't matter.
const int kLargeFileSize = 100000000;

// Used to set the size of events to be sent to the observer in test cases
// where event size doesn't matter.
const size_t kDummyEventSize = 150;

const char kWinLineEnd[] = "\r\n";
const char kLinuxLineEnd[] = "\n";

void AddEntries(FileNetLogObserver* logger,
                int num_entries,
                size_t entry_size) {
  // Get base size of event.
  const int kDummyId = 0;
  std::string message = "";
  NetLogParametersCallback callback =
      NetLog::StringCallback("message", &message);
  NetLogSource source(NetLogSourceType::HTTP2_SESSION, kDummyId);
  NetLogEntryData base_entry_data(NetLogEventType::PAC_JAVASCRIPT_ERROR, source,
                                  NetLogEventPhase::BEGIN,
                                  base::TimeTicks::Now(), &callback);
  NetLogEntry base_entry(&base_entry_data,
                         NetLogCaptureMode::IncludeSocketBytes());
  std::unique_ptr<base::Value> value(base_entry.ToValue());
  std::string json;
  base::JSONWriter::Write(*value, &json);
  size_t base_entry_size = json.size();

  // The maximum value of base::TimeTicks::Now() will be the maximum value of
  // int64_t, and if the maximum number of digits are included, the
  // |base_entry_size| could be up to 101 characters. Check that the event
  // format does not include additional padding.
  DCHECK_LE(base_entry_size, 101u);

  // |entry_size| should be at least as big as the largest possible base
  // entry.
  EXPECT_GE(entry_size, 101u);

  // |entry_size| cannot be smaller than the minimum event size.
  EXPECT_GE(entry_size, base_entry_size);

  for (int i = 0; i < num_entries; i++) {
    source = NetLogSource(NetLogSourceType::HTTP2_SESSION, i);
    std::string id = std::to_string(i);

    // String size accounts for the number of digits in id so that all events
    // are the same size.
    message = std::string(entry_size - base_entry_size - id.size() + 1, 'x');
    callback = NetLog::StringCallback("message", &message);
    NetLogEntryData entry_data(NetLogEventType::PAC_JAVASCRIPT_ERROR, source,
                               NetLogEventPhase::BEGIN, base::TimeTicks::Now(),
                               &callback);
    NetLogEntry entry(&entry_data, NetLogCaptureMode::IncludeSocketBytes());
    logger->OnAddEntry(entry);
  }
}

// Loads and concatenates the contents of bounded log files into a string
void ReadBoundedLogFiles(const base::FilePath& log_dir, std::string* input) {
  base::ReadFileToString(log_dir.AppendASCII("constants.json"), input);
  size_t input_no_events = input->length();
  std::string to_add;
  for (int i = 0; base::ReadFileToString(
           log_dir.AppendASCII("event_file_" + std::to_string(i) + ".json"),
           &to_add);
       ++i) {
    *input += to_add;
  }

  // Delete the hanging comma and newline from the events array.
  if (input->length() > input_no_events) {
    // Remove carriage returns in case of Windows machine.
    base::ReplaceSubstringsAfterOffset(input, 0, kWinLineEnd, kLinuxLineEnd);
    ASSERT_GE(input->length() - input_no_events, 2u);
    ASSERT_EQ(std::string(",\n"), std::string(*input, input->length() - 2));
    input->erase(input->end() - 2, input->end() - 1);
  }

  base::ReadFileToString(log_dir.AppendASCII("end_netlog.json"), &to_add);
  *input += to_add;
}

::testing::AssertionResult ParseNetLogString(const std::string& input,
                                             std::unique_ptr<base::Value>* root,
                                             base::ListValue** events) {
  if (input.empty()) {
    return ::testing::AssertionFailure() << "input is empty";
  }

  base::JSONReader reader;
  *root = reader.ReadToValue(input);
  if (!*root) {
    return ::testing::AssertionFailure() << reader.GetErrorMessage();
  }

  base::DictionaryValue* dict;
  if (!(*root)->GetAsDictionary(&dict)) {
    return ::testing::AssertionFailure() << "Not a dictionary";
  }

  if (!dict->GetList("events", events)) {
    return ::testing::AssertionFailure() << "No events list";
  }

  return ::testing::AssertionSuccess();
}

// Used for tests that are common to both bounded and unbounded modes of the
// the FileNetLogObserver. The param is true if bounded mode is used.
class FileNetLogObserverTest : public ::testing::TestWithParam<bool> {
 public:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    bounded_log_dir_ = temp_dir_.GetPath();
    unbounded_log_path_ = bounded_log_dir_.AppendASCII("net-log.json");
    file_thread_.reset(new base::Thread("NetLog File Thread"));
    file_thread_->StartWithOptions(
        base::Thread::Options(base::MessageLoop::TYPE_DEFAULT, 0));
    ASSERT_TRUE(file_thread_->WaitUntilThreadStarted());
  }

  void CreateAndStartObserving(std::unique_ptr<base::Value> constants) {
    bool bounded = GetParam();
    if (bounded) {
      logger_ = FileNetLogObserver::CreateBounded(
          file_thread_->task_runner(), bounded_log_dir_, kLargeFileSize,
          kTotalNumFiles, std::move(constants));
    } else {
      logger_ = FileNetLogObserver::CreateUnbounded(file_thread_->task_runner(),
                                                    unbounded_log_path_,
                                                    std::move(constants));
    }

    logger_->StartObserving(&net_log_, NetLogCaptureMode::Default());
  }

  ::testing::AssertionResult ReadNetLogFromDisk(
      std::unique_ptr<base::Value>* root,
      base::ListValue** events) {
    bool bounded = GetParam();
    std::string input;
    if (bounded) {
      ReadBoundedLogFiles(bounded_log_dir_, &input);
    } else {
      base::ReadFileToString(unbounded_log_path_, &input);
    }
    return ParseNetLogString(input, root, events);
  }

  bool LogFilesExist() {
    bool bounded = GetParam();
    if (bounded) {
      if (base::PathExists(bounded_log_dir_.AppendASCII("constants.json")) ||
          base::PathExists(bounded_log_dir_.AppendASCII("end_netlog.json")))
        return true;
      for (int i = 0; i < kTotalNumFiles; i++) {
        if (base::PathExists(bounded_log_dir_.AppendASCII(
                "event_file_" + std::to_string(i) + ".json")))
          return true;
      }
      return false;
    } else {
      return base::PathExists(unbounded_log_path_);
    }
  }

 protected:
  NetLog net_log_;
  std::unique_ptr<base::Thread> file_thread_;
  std::unique_ptr<FileNetLogObserver> logger_;

 private:
  base::ScopedTempDir temp_dir_;
  base::FilePath bounded_log_dir_;
  base::FilePath unbounded_log_path_;
};

// Used for tests that are exclusive to the bounded mode of FileNetLogObserver.
class FileNetLogObserverBoundedTest : public ::testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    bounded_log_dir_ = temp_dir_.GetPath();
    file_thread_.reset(new base::Thread("NetLog File Thread"));
    file_thread_->StartWithOptions(
        base::Thread::Options(base::MessageLoop::TYPE_DEFAULT, 0));
    ASSERT_TRUE(file_thread_->WaitUntilThreadStarted());
  }

  void CreateAndStartObserving(std::unique_ptr<base::Value> constants,
                               int total_file_size,
                               int num_files) {
    logger_ = FileNetLogObserver::CreateBounded(
        file_thread_->task_runner(), bounded_log_dir_, total_file_size,
        num_files, std::move(constants));
    logger_->StartObserving(&net_log_, NetLogCaptureMode::Default());
  }

  ::testing::AssertionResult ReadNetLogFromDisk(
      std::unique_ptr<base::Value>* root,
      base::ListValue** events) {
    std::string input;
    ReadBoundedLogFiles(bounded_log_dir_, &input);
    return ParseNetLogString(input, root, events);
  }

  base::FilePath GetEventFilePath(int index) const {
    return bounded_log_dir_.AppendASCII("event_file_" + std::to_string(index) +
                                        ".json");
  }

  static int64_t GetFileSize(const base::FilePath& path) {
    int64_t file_size;
    EXPECT_TRUE(base::GetFileSize(path, &file_size));
    return file_size;
  }

 protected:
  NetLog net_log_;
  std::unique_ptr<base::Thread> file_thread_;
  std::unique_ptr<FileNetLogObserver> logger_;

 private:
  base::ScopedTempDir temp_dir_;
  base::FilePath bounded_log_dir_;
};

// Instantiates each FileNetLogObserverTest to use bounded and unbounded modes.
INSTANTIATE_TEST_CASE_P(,
                        FileNetLogObserverTest,
                        ::testing::Values(true, false));

TEST_P(FileNetLogObserverTest, ObserverDestroyedWithoutStopObserving) {
  CreateAndStartObserving(nullptr);

  // Send dummy event
  AddEntries(logger_.get(), 1, kDummyEventSize);

  logger_.reset();
  file_thread_.reset();

  ASSERT_FALSE(LogFilesExist());
}

TEST_P(FileNetLogObserverTest, GeneratesValidJSONWithNoEvents) {
  TestClosure closure;

  CreateAndStartObserving(nullptr);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::unique_ptr<base::Value> root;
  base::ListValue* events;
  ASSERT_TRUE(ReadNetLogFromDisk(&root, &events));

  // Check that there are no events
  ASSERT_EQ(0u, events->GetSize());

  // Check that constants are printed
  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::DictionaryValue* constants;
  ASSERT_TRUE(dict->GetDictionary("constants", &constants));
}

TEST_P(FileNetLogObserverTest, GeneratesValidJSONWithOneEvent) {
  TestClosure closure;

  CreateAndStartObserving(nullptr);

  // Send dummy event.
  AddEntries(logger_.get(), 1, kDummyEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::unique_ptr<base::Value> root;
  base::ListValue* events;
  ASSERT_TRUE(ReadNetLogFromDisk(&root, &events));

  // Check that there is 1 event written.
  ASSERT_EQ(1u, events->GetSize());
}

TEST_P(FileNetLogObserverTest, CustomConstants) {
  TestClosure closure;

  const char kConstantString[] = "awesome constant";
  std::unique_ptr<base::Value> constants(
      new base::StringValue(kConstantString));

  CreateAndStartObserving(std::move(constants));

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::unique_ptr<base::Value> root;
  base::ListValue* events;
  ASSERT_TRUE(ReadNetLogFromDisk(&root, &events));

  // Check that custom constant was correctly printed.
  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  std::string constants_string;
  ASSERT_TRUE(dict->GetString("constants", &constants_string));
  ASSERT_EQ(kConstantString, constants_string);
}

TEST_P(FileNetLogObserverTest, GeneratesValidJSONWithPolledData) {
  TestClosure closure;

  CreateAndStartObserving(nullptr);

  // Create dummy polled data
  const char kDummyPolledDataPath[] = "dummy_path";
  const char kDummyPolledDataString[] = "dummy_info";
  std::unique_ptr<base::DictionaryValue> dummy_polled_data =
      base::MakeUnique<base::DictionaryValue>();
  dummy_polled_data->SetString(kDummyPolledDataPath, kDummyPolledDataString);

  logger_->StopObserving(std::move(dummy_polled_data), closure.closure());

  closure.WaitForResult();

  std::unique_ptr<base::Value> root;
  base::ListValue* events;
  ASSERT_TRUE(ReadNetLogFromDisk(&root, &events));

  // Check that no events were written.
  ASSERT_EQ(0u, events->GetSize());

  // Make sure additional information is present and validate it.
  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::DictionaryValue* polled_data;
  std::string dummy_string;
  ASSERT_TRUE(dict->GetDictionary("polledData", &polled_data));
  ASSERT_TRUE(polled_data->GetString(kDummyPolledDataPath, &dummy_string));
  ASSERT_EQ(dummy_string, kDummyPolledDataString);
}

// Adds events concurrently from several different threads. The exact order of
// events seen by this test is non-deterministic.
TEST_P(FileNetLogObserverTest, AddEventsFromMultipleThreads) {
  const size_t kNumThreads = 10;
  std::vector<std::unique_ptr<base::Thread>> threads(kNumThreads);
  // Start all the threads. Waiting for them to start is to hopefuly improve
  // the odds of hitting interesting races once events start being added.
  for (size_t i = 0; i < threads.size(); ++i) {
    threads[i] = base::MakeUnique<base::Thread>(
        base::StringPrintf("WorkerThread%i", static_cast<int>(i)));
    threads[i]->Start();
    threads[i]->WaitUntilThreadStarted();
  }

  CreateAndStartObserving(nullptr);

  const size_t kNumEventsAddedPerThread = 200;

  // Add events in parallel from all the threads.
  for (size_t i = 0; i < kNumThreads; ++i) {
    threads[i]->task_runner()->PostTask(
        FROM_HERE, base::Bind(&AddEntries, base::Unretained(logger_.get()),
                              kNumEventsAddedPerThread, kDummyEventSize));
  }

  // Join all the threads.
  threads.clear();

  // Stop observing.
  TestClosure closure;
  logger_->StopObserving(nullptr, closure.closure());
  closure.WaitForResult();

  // Check that the expected number of events were written to disk.
  std::unique_ptr<base::Value> root;
  base::ListValue* events;
  ASSERT_TRUE(ReadNetLogFromDisk(&root, &events));
  ASSERT_EQ(kNumEventsAddedPerThread * kNumThreads, events->GetSize());
}

// Sends enough events to the observer to completely fill one file, but not
// write any events to an additional file. Checks the file bounds.
TEST_F(FileNetLogObserverBoundedTest, EqualToOneFile) {
  // The total size of the events is equal to the size of one file.
  // |kNumEvents| * |kEventSize| = |kTotalFileSize| / |kTotalNumEvents|
  const int kTotalFileSize = 5000;
  const int kNumEvents = 2;
  const int kEventSize = 250;
  TestClosure closure;

  CreateAndStartObserving(nullptr, kTotalFileSize, kTotalNumFiles);

  AddEntries(logger_.get(), kNumEvents, kEventSize);
  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::unique_ptr<base::Value> root;
  base::ListValue* events;
  ASSERT_TRUE(ReadNetLogFromDisk(&root, &events));

  // Check that the correct number of events were written.
  ASSERT_EQ(static_cast<size_t>(kNumEvents), events->GetSize());

  // Check that the last event in array is the last event written.
  base::Value* last_event = nullptr;
  ASSERT_TRUE(events->Get(events->GetSize() - 1, &last_event));
  base::DictionaryValue* dict;
  last_event->GetAsDictionary(&dict);
  base::Value* id_value = nullptr;
  ASSERT_TRUE(dict->Get("source.id", &id_value));
  int id;
  ASSERT_TRUE(id_value->GetAsInteger(&id));
  ASSERT_EQ(kNumEvents - 1, id);

  // Check that events have been written to the first file.
  ASSERT_GT(GetFileSize(GetEventFilePath(0)), 0);

  // Check that all event files except the first do not exist.
  for (int i = 1; i < kTotalNumFiles; i++) {
    ASSERT_FALSE(base::PathExists(GetEventFilePath(i)));
  }
}

// Sends enough events to fill one file, and partially fill a second file.
// Checks the file bounds and writing to a new file.
TEST_F(FileNetLogObserverBoundedTest, OneEventOverOneFile) {
  // The total size of the events is greater than the size of one file, and
  // less than the size of two files. The total size of all events except one
  // is equal to the size of one file, so the last event will be the only event
  // in the second file.
  // (|kNumEvents| - 1) * kEventSize = |kTotalFileSize| / |kTotalNumEvents|
  const int kTotalFileSize = 6000;
  const int kNumEvents = 4;
  const int kEventSize = 200;
  TestClosure closure;

  CreateAndStartObserving(nullptr, kTotalFileSize, kTotalNumFiles);

  AddEntries(logger_.get(), kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::unique_ptr<base::Value> root;
  base::ListValue* events;
  ASSERT_TRUE(ReadNetLogFromDisk(&root, &events));

  // Check that the correct number of events were written.
  ASSERT_EQ(static_cast<size_t>(kNumEvents), events->GetSize());

  // Check that the last event in array is the last event written.
  base::Value* last_event = nullptr;
  ASSERT_TRUE(events->Get(events->GetSize() - 1, &last_event));
  base::DictionaryValue* dict;
  last_event->GetAsDictionary(&dict);
  base::Value* id_value = nullptr;
  ASSERT_TRUE(dict->Get("source.id", &id_value));
  int id;
  ASSERT_TRUE(id_value->GetAsInteger(&id));
  ASSERT_EQ(kNumEvents - 1, id);

  // Check that all event files except the first two do not exist.
  for (int i = 2; i < kTotalNumFiles; i++) {
    ASSERT_FALSE(base::PathExists(GetEventFilePath(i)));
  }
}

// Sends enough events to the observer to completely fill two files.
TEST_F(FileNetLogObserverBoundedTest, EqualToTwoFiles) {
  // The total size of the events is equal to the total size of two files.
  // |kNumEvents| * |kEventSize| = 2 * |kTotalFileSize| / |kTotalNumEvents|
  const int kTotalFileSize = 6000;
  const int kNumEvents = 6;
  const int kEventSize = 200;
  TestClosure closure;

  CreateAndStartObserving(nullptr, kTotalFileSize, kTotalNumFiles);

  AddEntries(logger_.get(), kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::unique_ptr<base::Value> root;
  base::ListValue* events;
  ASSERT_TRUE(ReadNetLogFromDisk(&root, &events));

  // Check that the correct number of events were written.
  ASSERT_EQ(static_cast<size_t>(kNumEvents), events->GetSize());

  // Check that the last event in array is the last event written.
  base::Value* last_event = nullptr;
  ASSERT_TRUE(events->Get(events->GetSize() - 1, &last_event));
  base::DictionaryValue* dict;
  last_event->GetAsDictionary(&dict);
  base::Value* id_value = nullptr;
  ASSERT_TRUE(dict->Get("source.id", &id_value));
  int id;
  ASSERT_TRUE(id_value->GetAsInteger(&id));
  ASSERT_EQ(kNumEvents - 1, id);

  // Check that the first two event files are full.
  for (int i = 0; i < (kNumEvents * kEventSize) /
                          ((kTotalFileSize - 1) / kTotalNumFiles + 1);
       i++) {
    ASSERT_GE(GetFileSize(GetEventFilePath(i)),
              static_cast<int64_t>(kTotalFileSize / kTotalNumFiles));
  }

  // Check that all event files except the first two do not exist.
  for (int i = 2; i < kTotalNumFiles; i++) {
    ASSERT_FALSE(base::PathExists(GetEventFilePath(i)));
  }
}

// Sends exactly enough events to the observer to completely fill all files,
// so that all events fit into the event files and no files need to be
// overwritten.
TEST_F(FileNetLogObserverBoundedTest, FillAllFilesNoOverwriting) {
  // The total size of events is equal to the total size of all files.
  // |kEventSize| * |kNumEvents| = |kTotalFileSize|
  const int kTotalFileSize = 10000;
  const int kEventSize = 200;
  const int kFileSize = kTotalFileSize / kTotalNumFiles;
  const int kNumEvents = kTotalNumFiles * ((kFileSize - 1) / kEventSize + 1);
  TestClosure closure;

  CreateAndStartObserving(nullptr, kTotalFileSize, kTotalNumFiles);

  AddEntries(logger_.get(), kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::unique_ptr<base::Value> root;
  base::ListValue* events;
  ASSERT_TRUE(ReadNetLogFromDisk(&root, &events));

  // Check that the correct number of events were written.
  ASSERT_EQ(static_cast<size_t>(kNumEvents), events->GetSize());

  // Check that the last event in array is the last event written.
  base::Value* last_event = nullptr;
  ASSERT_TRUE(events->Get(events->GetSize() - 1, &last_event));
  base::DictionaryValue* dict;
  last_event->GetAsDictionary(&dict);
  base::Value* id_value = nullptr;
  ASSERT_TRUE(dict->Get("source.id", &id_value));
  int id;
  ASSERT_TRUE(id_value->GetAsInteger(&id));
  ASSERT_EQ(kNumEvents - 1, id);

  // Check that all the event files are full.
  for (int i = 0; i < kTotalNumFiles; i++) {
    ASSERT_GE(GetFileSize(GetEventFilePath(i)),
              static_cast<int64_t>(kTotalFileSize / kTotalNumFiles));
  }
}

// Sends more events to the observer than will fill the WriteQueue, forcing the
// queue to drop an event. Checks that the queue drops the oldest event.
TEST_F(FileNetLogObserverBoundedTest, DropOldEventsFromWriteQueue) {
  // The total size of events is greater than the WriteQueue's memory limit, so
  // the oldest event must be dropped from the queue and not written to any
  // file.
  // |kNumEvents| * |kEventSize| > |kTotalFileSize| * 2
  const int kTotalFileSize = 1000;
  const int kNumEvents = 11;
  const int kEventSize = 200;
  const int kFileSize = kTotalFileSize / kTotalNumFiles;
  TestClosure closure;

  CreateAndStartObserving(nullptr, kTotalFileSize, kTotalNumFiles);

  AddEntries(logger_.get(), kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::unique_ptr<base::Value> root;
  base::ListValue* events;
  ASSERT_TRUE(ReadNetLogFromDisk(&root, &events));

  // Check that the correct number of events were written.
  ASSERT_EQ(
      static_cast<size_t>(kTotalNumFiles * ((kFileSize - 1) / kEventSize + 1)),
      events->GetSize());

  // Check that the oldest event was dropped from the queue.
  base::Value* event_to_check = nullptr;
  ASSERT_TRUE(events->Get(0, &event_to_check));
  base::DictionaryValue* dict;
  event_to_check->GetAsDictionary(&dict);
  base::Value* id_value = nullptr;
  ASSERT_TRUE(dict->Get("source.id", &id_value));
  int id;
  ASSERT_TRUE(id_value->GetAsInteger(&id));
  ASSERT_EQ(1, id);

  // Check that the last event was written last.
  event_to_check = nullptr;
  ASSERT_TRUE(events->Get(events->GetSize() - 1, &event_to_check));
  event_to_check->GetAsDictionary(&dict);
  ASSERT_TRUE(dict->Get("source.id", &id_value));
  ASSERT_TRUE(id_value->GetAsInteger(&id));
  ASSERT_EQ(kNumEvents - 1, id);
}

// Sends twice as many events as will fill all files to the observer, so that
// all of the event files will be filled twice, and every file will be
// overwritten.
TEST_F(FileNetLogObserverBoundedTest, OverwriteAllFiles) {
  // The total size of the events is much greater than twice the number of
  // events that can fit in the event files, to make sure that the extra events
  // are written to a file, not just dropped from the queue.
  // |kNumEvents| * |kEventSize| >= 2 * |kTotalFileSize|
  const int kTotalFileSize = 6000;
  const int kNumEvents = 60;
  const int kEventSize = 200;
  const int kFileSize = kTotalFileSize / kTotalNumFiles;
  TestClosure closure;

  CreateAndStartObserving(nullptr, kTotalFileSize, kTotalNumFiles);

  AddEntries(logger_.get(), kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::unique_ptr<base::Value> root;
  base::ListValue* events;
  ASSERT_TRUE(ReadNetLogFromDisk(&root, &events));

  // Check that the minimum number of events that should fit in event files
  // have been written to all files.
  int events_per_file = (kFileSize - 1) / kEventSize + 1;
  int events_in_last_file = (kNumEvents - 1) % events_per_file + 1;

  // Indicates the total number of events that should be written to all files.
  int num_events_in_files =
      (kTotalNumFiles - 1) * events_per_file + events_in_last_file;

  // Tracks whether each of the events that should be written to all files
  // actually appears in the |events| array. The bool at each index corresponds
  // to the event with id = index + |kNumEvents| - |num_events_in_files|.
  std::vector<bool> events_written(num_events_in_files, false);

  base::Value* event = nullptr;
  base::Value* id_value = nullptr;
  int id;

  // Iterate through each event in |events| and if it is supposed to appear in
  // file, mark the corresponding bool in |events_written| as true.
  for (size_t i = 0; i < events->GetSize(); i++) {
    ASSERT_TRUE(events->Get(i, &event));
    base::DictionaryValue* dict;
    event->GetAsDictionary(&dict);
    ASSERT_TRUE(dict->Get("source.id", &id_value));
    ASSERT_TRUE(id_value->GetAsInteger(&id));
    ASSERT_LT(id, kNumEvents);
    if (id >= kNumEvents - num_events_in_files) {
      events_written[id - (kNumEvents - num_events_in_files)] = true;
    }
  }

  // Check that all events that are supposed to be written to all files
  // appeared in the |events| array.
  ASSERT_TRUE(std::all_of(std::begin(events_written), std::end(events_written),
                          [](bool j) { return j; }));

  // Check that there are events written to all files.
  for (int i = 0; i < kTotalNumFiles; i++) {
    ASSERT_GE(GetFileSize(GetEventFilePath(i)),
              static_cast<int64_t>(kEventSize));
  }
}

// Sends enough events to the observer to fill all event files, plus overwrite
// some files, without overwriting all of them. Checks that the FileWriter
// overwrites the file with the oldest events.
TEST_F(FileNetLogObserverBoundedTest, PartiallyOverwriteFiles) {
  // The number of events sent to the observer is greater than the number of
  // events that can fit into the event files, but the events can fit in less
  // than twice the number of event files, so not every file will need to be
  // overwritten.
  // |kTotalFileSize| < |kNumEvents| * |kEventSize|
  // |kNumEvents| * |kEventSize| <= (2 * |kTotalNumFiles| - 1) * |kFileSize|
  const int kTotalFileSize = 6000;
  const int kNumEvents = 50;
  const int kEventSize = 200;
  const int kFileSize = kTotalFileSize / kTotalNumFiles;
  TestClosure closure;

  CreateAndStartObserving(nullptr, kTotalFileSize, kTotalNumFiles);

  AddEntries(logger_.get(), kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::unique_ptr<base::Value> root;
  base::ListValue* events;
  ASSERT_TRUE(ReadNetLogFromDisk(&root, &events));

  // Check that the minimum number of events that should fit in event files
  // have been written to a file.
  int events_per_file = (kFileSize - 1) / kEventSize + 1;
  int events_in_last_file = kNumEvents % events_per_file;
  if (!events_in_last_file)
    events_in_last_file = events_per_file;
  int num_events_in_files =
      (kTotalNumFiles - 1) * events_per_file + events_in_last_file;
  std::vector<bool> events_written(num_events_in_files, false);
  base::Value* event = nullptr;
  base::Value* id_value = nullptr;
  int id;
  for (size_t i = 0; i < events->GetSize(); i++) {
    ASSERT_TRUE(events->Get(i, &event));
    base::DictionaryValue* dict;
    event->GetAsDictionary(&dict);
    ASSERT_TRUE(dict->Get("source.id", &id_value));
    ASSERT_TRUE(id_value->GetAsInteger(&id));
    ASSERT_LT(id, kNumEvents);
    if (id >= kNumEvents - num_events_in_files) {
      events_written[id - (kNumEvents - num_events_in_files)] = true;
    }
  }
  ASSERT_TRUE(std::all_of(std::begin(events_written), std::end(events_written),
                          [](bool j) { return j; }));

  // Check that there are events written to all files.
  for (int i = 0; i < kTotalNumFiles; i++) {
    ASSERT_GE(GetFileSize(GetEventFilePath(i)),
              static_cast<int64_t>(kEventSize));
  }
}

}  // namespace

}  // namespace net
