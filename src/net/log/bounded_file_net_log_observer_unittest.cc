// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/log/bounded_file_net_log_observer.h"

#include <math.h>

#include <memory>
#include <string>
#include <utility>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/files/scoped_temp_dir.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/strings/string_util.h"
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

const std::string kWinLineEnd = "\r\n";
const std::string kLinuxLineEnd = "\n";

class BoundedFileNetLogObserverTest : public testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    log_path_ = temp_dir_.GetPath();
    file_thread_.reset(new base::Thread("NetLog File Thread"));
    file_thread_->StartWithOptions(
        base::Thread::Options(base::MessageLoop::TYPE_DEFAULT, 0));
    if (file_thread_->WaitUntilThreadStarted()) {
      logger_ = std::unique_ptr<BoundedFileNetLogObserver>(
          new BoundedFileNetLogObserver(file_thread_->task_runner()));
    }
  }

  // Concatenates all files together, including constants file and end file.
  void AddAllFiles(std::string* input) {
    base::ReadFileToString(log_path_.AppendASCII("constants.json"), input);
    std::string to_add;
    size_t input_no_events = input->length();
    for (int i = 0; i < kTotalNumFiles; i++) {
      base::ReadFileToString(
          log_path_.AppendASCII("event_file_" + std::to_string(i) + ".json"),
          &to_add);
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

    base::ReadFileToString(log_path_.AppendASCII("end_netlog.json"), &to_add);
    *input += to_add;
  }

  // Sends |num_entries_to_add| number of events of size |entry_size| to
  // |logger_|.
  //
  // |entry_size| must be >= 101, since the size of entries without a message,
  // |base_entry_size|, is dependent on TimeTicks formatting, and
  // |base_entry_size| can be up to 101 and cannot be shortened.
  void AddEntries(int num_entries_to_add, size_t entry_size) {
    // Get base size of event.
    const int kDummyId = 0;
    std::string message = "";
    NetLogParametersCallback callback =
        NetLog::StringCallback("message", &message);
    NetLogSource source(NetLogSourceType::HTTP2_SESSION, kDummyId);
    NetLogEntryData base_entry_data(NetLogEventType::PAC_JAVASCRIPT_ERROR,
                                    source, NetLogEventPhase::BEGIN,
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

    for (int i = 0; i < num_entries_to_add; i++) {
      source = NetLogSource(NetLogSourceType::HTTP2_SESSION, i);
      std::string id = std::to_string(i);

      // String size accounts for the number of digits in id so that all events
      // are the same size.
      message = std::string(entry_size - base_entry_size - id.size() + 1, 'x');
      callback = NetLog::StringCallback("message", &message);
      NetLogEntryData entry_data(NetLogEventType::PAC_JAVASCRIPT_ERROR, source,
                                 NetLogEventPhase::BEGIN,
                                 base::TimeTicks::Now(), &callback);
      NetLogEntry entry(&entry_data, NetLogCaptureMode::IncludeSocketBytes());
      logger_->OnAddEntry(entry);
    }
  }

 protected:
  base::FilePath log_path_;
  NetLog net_log_;
  std::unique_ptr<base::Thread> file_thread_;
  std::unique_ptr<BoundedFileNetLogObserver> logger_;

 private:
  base::ScopedTempDir temp_dir_;
};

TEST_F(BoundedFileNetLogObserverTest, ObserverDestroyedWithoutStopObserving) {
  logger_->StartObserving(&net_log_, log_path_, nullptr, nullptr,
                          kLargeFileSize, kTotalNumFiles);

  // Send dummy event
  AddEntries(1, kDummyEventSize);

  logger_.reset();
  file_thread_.reset();

  ASSERT_FALSE(base::PathExists(log_path_.AppendASCII("constants.json")));
  ASSERT_FALSE(base::PathExists(log_path_.AppendASCII("end_netlog.json")));
  for (int i = 0; i < kTotalNumFiles; i++) {
    ASSERT_FALSE(base::PathExists(
        log_path_.AppendASCII("event_file_" + std::to_string(i) + ".json")));
  }
}

TEST_F(BoundedFileNetLogObserverTest, GeneratesValidJSONForNoEvents) {
  TestClosure closure;

  logger_->StartObserving(&net_log_, log_path_, nullptr, nullptr,
                          kLargeFileSize, kTotalNumFiles);
  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::string input;
  AddAllFiles(&input);
  ASSERT_FALSE(input.empty());

  // Parse JSON
  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.Read(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  // Check that there are no events
  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));
  ASSERT_EQ(0u, events->GetSize());

  // Check that constants are printed
  base::DictionaryValue* constants;
  ASSERT_TRUE(dict->GetDictionary("constants", &constants));
}

// Checks that capture_mode_ defaults correctly when set_capture_mode is not
// called, and that |capture_mode_| is changed when set_capture_mode is called.
TEST_F(BoundedFileNetLogObserverTest, SetsCaptureMode) {
  TestClosure default_closure;

  logger_->StartObserving(&net_log_, log_path_, nullptr, nullptr,
                          kLargeFileSize, kTotalNumFiles);
  EXPECT_EQ(NetLogCaptureMode::Default(), logger_->capture_mode());
  logger_->StopObserving(nullptr, default_closure.closure());

  default_closure.WaitForResult();

  TestClosure new_capture_mode_closure;
  logger_ = std::unique_ptr<BoundedFileNetLogObserver>(
      new BoundedFileNetLogObserver(file_thread_->task_runner()));

  logger_->set_capture_mode(NetLogCaptureMode::IncludeCookiesAndCredentials());
  logger_->StartObserving(&net_log_, log_path_, nullptr, nullptr,
                          kLargeFileSize, kTotalNumFiles);
  EXPECT_EQ(NetLogCaptureMode::IncludeCookiesAndCredentials(),
            logger_->capture_mode());
  logger_->StopObserving(nullptr, new_capture_mode_closure.closure());

  new_capture_mode_closure.WaitForResult();

  std::string input;
  AddAllFiles(&input);
  ASSERT_FALSE(input.empty());
}

TEST_F(BoundedFileNetLogObserverTest, GeneratesValidJSONWithOneEvent) {
  TestClosure closure;

  logger_->StartObserving(&net_log_, log_path_, nullptr, nullptr,
                          kLargeFileSize, kTotalNumFiles);

  // Send dummy event.
  AddEntries(1, kDummyEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::string input;
  AddAllFiles(&input);
  ASSERT_FALSE(input.empty());

  // Parse input.
  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));

  ASSERT_TRUE(root) << reader.GetErrorMessage();

  // Check that there is 1 event written.
  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));
  ASSERT_EQ(1u, events->GetSize());
}

TEST_F(BoundedFileNetLogObserverTest, GeneratesValidJSONWithMultipleEvents) {
  const int kTotalFileSize = 250000;
  TestClosure closure;

  logger_->StartObserving(&net_log_, log_path_, nullptr, nullptr,
                          kTotalFileSize, kTotalNumFiles);

  AddEntries(2, kDummyEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::string input;
  AddAllFiles(&input);
  ASSERT_FALSE(input.empty());

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  // Check that 2 events are written.
  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));
  ASSERT_EQ(2u, events->GetSize());
}

// Sends enough events to the observer to completely fill one file, but not
// write any events to an additional file. Checks the file bounds.
TEST_F(BoundedFileNetLogObserverTest, EqualToOneFile) {
  // The total size of the events is equal to the size of one file.
  // |kNumEvents| * |kEventSize| = |kTotalFileSize| / |kTotalNumEvents|
  const int kTotalFileSize = 5000;
  const int kNumEvents = 2;
  const int kEventSize = 250;
  TestClosure closure;

  logger_->StartObserving(&net_log_, log_path_, nullptr, nullptr,
                          kTotalFileSize, kTotalNumFiles);

  AddEntries(kNumEvents, kEventSize);
  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::string input;
  AddAllFiles(&input);
  ASSERT_FALSE(input.empty());

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  // Check that the correct number of events were written.
  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));
  ASSERT_EQ(static_cast<size_t>(kNumEvents), events->GetSize());

  // Check that the last event in array is the last event written.
  base::Value* last_event = nullptr;
  ASSERT_TRUE(events->Get(events->GetSize() - 1, &last_event));
  last_event->GetAsDictionary(&dict);
  base::Value* id_value = nullptr;
  ASSERT_TRUE(dict->Get("source.id", &id_value));
  int id;
  ASSERT_TRUE(id_value->GetAsInteger(&id));
  ASSERT_EQ(kNumEvents - 1, id);

  // Check that events have been written to the first file.
  base::ScopedFILE first_file(base::OpenFile(
      log_path_.AppendASCII("event_file_" + std::to_string(0) + ".json"),
      "rb"));
  ASSERT_TRUE(first_file.get());
  fseek(first_file.get(), 0, SEEK_END);
  ASSERT_TRUE(ftell(first_file.get()));

  // Check that all event files except the first do not exist.
  for (int i = 1; i < kTotalNumFiles; i++) {
    ASSERT_FALSE(base::PathExists(
        log_path_.AppendASCII("event_file_" + std::to_string(i) + ".json")));
  }
}

// Sends enough events to fill one file, and partially fill a second file.
// Checks the file bounds and writing to a new file.
TEST_F(BoundedFileNetLogObserverTest, OneEventOverOneFile) {
  // The total size of the events is greater than the size of one file, and
  // less than the size of two files. The total size of all events except one
  // is equal to the size of one file, so the last event will be the only event
  // in the second file.
  // (|kNumEvents| - 1) * kEventSize = |kTotalFileSize| / |kTotalNumEvents|
  const int kTotalFileSize = 6000;
  const int kNumEvents = 4;
  const int kEventSize = 200;
  TestClosure closure;

  logger_->StartObserving(&net_log_, log_path_, nullptr, nullptr,
                          kTotalFileSize, kTotalNumFiles);

  AddEntries(kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::string input;
  AddAllFiles(&input);
  ASSERT_FALSE(input.empty());

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  // Check that the correct number of events were written.
  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));
  ASSERT_EQ(static_cast<size_t>(kNumEvents), events->GetSize());

  // Check that the last event in array is the last event written.
  base::Value* last_event = nullptr;
  ASSERT_TRUE(events->Get(events->GetSize() - 1, &last_event));
  last_event->GetAsDictionary(&dict);
  base::Value* id_value = nullptr;
  ASSERT_TRUE(dict->Get("source.id", &id_value));
  int id;
  ASSERT_TRUE(id_value->GetAsInteger(&id));
  ASSERT_EQ(kNumEvents - 1, id);

  // Check that all event files except the first two do not exist.
  for (int i = 2; i < kTotalNumFiles; i++) {
    ASSERT_FALSE(base::PathExists(
        log_path_.AppendASCII("event_file_" + std::to_string(i) + ".json")));
  }
}

// Sends enough events to the observer to completely fill two files.
TEST_F(BoundedFileNetLogObserverTest, EqualToTwoFiles) {
  // The total size of the events is equal to the total size of two files.
  // |kNumEvents| * |kEventSize| = 2 * |kTotalFileSize| / |kTotalNumEvents|
  const int kTotalFileSize = 6000;
  const int kNumEvents = 6;
  const int kEventSize = 200;
  TestClosure closure;

  logger_->StartObserving(&net_log_, log_path_, nullptr, nullptr,
                          kTotalFileSize, kTotalNumFiles);

  AddEntries(kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::string input;
  AddAllFiles(&input);
  ASSERT_FALSE(input.empty());

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  // Check that the correct number of events were written.
  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));
  ASSERT_EQ(static_cast<size_t>(kNumEvents), events->GetSize());

  // Check that the last event in array is the last event written.
  base::Value* last_event = nullptr;
  ASSERT_TRUE(events->Get(events->GetSize() - 1, &last_event));
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
    base::ScopedFILE file_to_test(base::OpenFile(
        log_path_.AppendASCII("event_file_" + std::to_string(i) + ".json"),
        "rb"));
    ASSERT_TRUE(file_to_test.get());
    fseek(file_to_test.get(), 0, SEEK_END);
    ASSERT_GE(ftell(file_to_test.get()), kTotalFileSize / kTotalNumFiles);
  }

  // Check that all event files except the first two do not exist.
  for (int i = 2; i < kTotalNumFiles; i++) {
    ASSERT_FALSE(base::PathExists(
        log_path_.AppendASCII("event_file_" + std::to_string(i) + ".json")));
  }
}

// Sends exactly enough events to the observer to completely fill all files,
// so that all events fit into the event files and no files need to be
// overwritten.
TEST_F(BoundedFileNetLogObserverTest, FillAllFilesNoOverwriting) {
  // The total size of events is equal to the total size of all files.
  // |kEventSize| * |kNumEvents| = |kTotalFileSize|
  const int kTotalFileSize = 10000;
  const int kEventSize = 200;
  const int kFileSize = kTotalFileSize / kTotalNumFiles;
  const int kNumEvents = kTotalNumFiles * ((kFileSize - 1) / kEventSize + 1);
  TestClosure closure;

  logger_->StartObserving(&net_log_, log_path_, nullptr, nullptr,
                          kTotalFileSize, kTotalNumFiles);

  AddEntries(kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::string input;
  AddAllFiles(&input);
  ASSERT_FALSE(input.empty());

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  // Check that the correct number of events were written.
  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));
  ASSERT_EQ(static_cast<size_t>(kNumEvents), events->GetSize());

  // Check that the last event in array is the last event written.
  base::Value* last_event = nullptr;
  ASSERT_TRUE(events->Get(events->GetSize() - 1, &last_event));
  last_event->GetAsDictionary(&dict);
  base::Value* id_value = nullptr;
  ASSERT_TRUE(dict->Get("source.id", &id_value));
  int id;
  ASSERT_TRUE(id_value->GetAsInteger(&id));
  ASSERT_EQ(kNumEvents - 1, id);

  // Check that all the event files are full.
  for (int i = 0; i < kTotalNumFiles; i++) {
    base::ScopedFILE file_to_test(base::OpenFile(
        log_path_.AppendASCII("event_file_" + std::to_string(i) + ".json"),
        "rb"));
    ASSERT_TRUE(file_to_test.get());
    fseek(file_to_test.get(), 0, SEEK_END);
    ASSERT_GE(ftell(file_to_test.get()), kTotalFileSize / kTotalNumFiles);
  }
}

// Sends more events to the observer than will fill the WriteQueue, forcing the
// queue to drop an event. Checks that the queue drops the oldest event.
TEST_F(BoundedFileNetLogObserverTest, DropOldEventsFromWriteQueue) {
  // The total size of events is greater than the WriteQueue's memory limit, so
  // the oldest event must be dropped from the queue and not written to any
  // file.
  // |kNumEvents| * |kEventSize| > |kTotalFileSize| * 2
  const int kTotalFileSize = 1000;
  const int kNumEvents = 11;
  const int kEventSize = 200;
  const int kFileSize = kTotalFileSize / kTotalNumFiles;
  TestClosure closure;

  logger_->StartObserving(&net_log_, log_path_, nullptr, nullptr,
                          kTotalFileSize, kTotalNumFiles);

  AddEntries(kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::string input;
  AddAllFiles(&input);
  ASSERT_FALSE(input.empty());

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  // Check that the correct number of events were written.
  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));
  ASSERT_EQ(
      static_cast<size_t>(kTotalNumFiles * ((kFileSize - 1) / kEventSize + 1)),
      events->GetSize());

  // Check that the oldest event was dropped from the queue.
  base::Value* event_to_check = nullptr;
  ASSERT_TRUE(events->Get(0, &event_to_check));
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
TEST_F(BoundedFileNetLogObserverTest, OverwriteAllFiles) {
  // The total size of the events is much greater than twice the number of
  // events that can fit in the event files, to make sure that the extra events
  // are written to a file, not just dropped from the queue.
  // |kNumEvents| * |kEventSize| >= 2 * |kTotalFileSize|
  const int kTotalFileSize = 6000;
  const int kNumEvents = 60;
  const int kEventSize = 200;
  const int kFileSize = kTotalFileSize / kTotalNumFiles;
  TestClosure closure;

  logger_->StartObserving(&net_log_, log_path_, nullptr, nullptr,
                          kTotalFileSize, kTotalNumFiles);

  AddEntries(kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::string input;
  AddAllFiles(&input);
  ASSERT_FALSE(input.empty());

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  // Check that the correct number of events were written.
  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));

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
    base::ScopedFILE file_to_test(base::OpenFile(
        log_path_.AppendASCII("event_file_" + std::to_string(i) + ".json"),
        "rb"));
    ASSERT_TRUE(file_to_test.get());
    fseek(file_to_test.get(), 0, SEEK_END);
    ASSERT_GE(ftell(file_to_test.get()), kEventSize);
  }
}

// Sends enough events to the observer to fill all event files, plus overwrite
// some files, without overwriting all of them. Checks that the FileWriter
// overwrites the file with the oldest events.
TEST_F(BoundedFileNetLogObserverTest, PartiallyOverwriteFiles) {
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

  logger_->StartObserving(&net_log_, log_path_, nullptr, nullptr,
                          kTotalFileSize, kTotalNumFiles);

  AddEntries(kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::string input;
  AddAllFiles(&input);
  ASSERT_FALSE(input.empty());

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));

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
    base::ScopedFILE file_to_test(base::OpenFile(
        log_path_.AppendASCII("event_file_" + std::to_string(i) + ".json"),
        "rb"));
    ASSERT_TRUE(file_to_test.get());
    fseek(file_to_test.get(), 0, SEEK_END);
    ASSERT_GE(ftell(file_to_test.get()), kEventSize);
  }
}

TEST_F(BoundedFileNetLogObserverTest, CustomConstants) {
  TestClosure closure;

  const char kConstantString[] = "awesome constant";
  std::unique_ptr<base::Value> constants(
      new base::StringValue(kConstantString));

  logger_->StartObserving(&net_log_, log_path_, constants.get(), nullptr,
                          kLargeFileSize, kTotalNumFiles);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  std::string input;
  AddAllFiles(&input);
  ASSERT_FALSE(input.empty());

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  // Check that custom constant was correctly printed.
  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  std::string constants_string;
  ASSERT_TRUE(dict->GetString("constants", &constants_string));
  ASSERT_EQ(kConstantString, constants_string);
}

TEST_F(BoundedFileNetLogObserverTest, GeneratesValidJSONWithContext) {
  TestClosure closure;

  logger_->StartObserving(&net_log_, log_path_, nullptr, nullptr,
                          kLargeFileSize, kTotalNumFiles);

  // Create unique context.
  TestURLRequestContext context(true);
  context.set_net_log(&net_log_);
  const int kDummyParam = 75;
  std::unique_ptr<HttpNetworkSession::Params> params(
      new HttpNetworkSession::Params);
  params->quic_idle_connection_timeout_seconds = kDummyParam;
  context.set_http_network_session_params(std::move(params));
  context.Init();

  logger_->StopObserving(&context, closure.closure());

  closure.WaitForResult();

  std::string input;
  AddAllFiles(&input);
  ASSERT_FALSE(input.empty());

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  // Check that no events were written.
  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));
  ASSERT_EQ(0u, events->GetSize());

  // Make sure additional information is present and validate it.
  base::DictionaryValue* tab_info;
  base::DictionaryValue* quic_info;
  ASSERT_TRUE(dict->GetDictionary("tabInfo", &tab_info));
  ASSERT_TRUE(tab_info->GetDictionary("quicInfo", &quic_info));
  base::Value* timeout_value = nullptr;
  int timeout;
  ASSERT_TRUE(
      quic_info->Get("idle_connection_timeout_seconds", &timeout_value));
  ASSERT_TRUE(timeout_value->GetAsInteger(&timeout));
  ASSERT_EQ(timeout, kDummyParam);
}

TEST_F(BoundedFileNetLogObserverTest,
       GeneratesValidJSONWithContextWithActiveRequest) {
  TestClosure closure;

  // Create context, start a request.
  TestURLRequestContext context(true);
  context.set_net_log(&net_log_);
  context.Init();
  TestDelegate delegate;
  delegate.set_quit_on_complete(false);

  // URL doesn't matter.  Requests can't fail synchronously.
  std::unique_ptr<URLRequest> request(
      context.CreateRequest(GURL("blah:blah"), IDLE, &delegate));
  request->Start();

  logger_->StartObserving(&net_log_, log_path_, nullptr, &context,
                          kLargeFileSize, kTotalNumFiles);

  logger_->StopObserving(&context, closure.closure());

  closure.WaitForResult();

  std::string input;
  AddAllFiles(&input);
  ASSERT_FALSE(input.empty());

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  // Check that 1 event was written
  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));
  ASSERT_EQ(1u, events->GetSize());

  // Make sure additional information is present, but don't validate it.
  base::DictionaryValue* tab_info;
  ASSERT_TRUE(dict->GetDictionary("tabInfo", &tab_info));
}

}  // namespace

}  // namespace net
