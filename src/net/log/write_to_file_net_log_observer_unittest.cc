// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/log/write_to_file_net_log_observer.h"

#include <memory>
#include <utility>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/files/scoped_temp_dir.h"
#include "base/json/json_reader.h"
#include "base/values.h"
#include "net/log/net_log.h"
#include "net/log/net_log_entry.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_util.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

class WriteToFileNetLogObserverTest : public testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    log_path_ = temp_dir_.GetPath().AppendASCII("NetLogFile");
  }

 protected:
  base::ScopedTempDir temp_dir_;
  base::FilePath log_path_;
  NetLog net_log_;
};

TEST_F(WriteToFileNetLogObserverTest, GeneratesValidJSONForNoEvents) {
  // Create and destroy a logger.
  base::ScopedFILE file(base::OpenFile(log_path_, "w"));
  ASSERT_TRUE(file);
  std::unique_ptr<WriteToFileNetLogObserver> logger(
      new WriteToFileNetLogObserver());
  logger->StartObserving(&net_log_, std::move(file), nullptr, nullptr);
  logger->StopObserving(nullptr);
  logger.reset();

  std::string input;
  ASSERT_TRUE(base::ReadFileToString(log_path_, &input));

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));
  ASSERT_EQ(0u, events->GetSize());

  base::DictionaryValue* constants;
  ASSERT_TRUE(dict->GetDictionary("constants", &constants));
}

TEST_F(WriteToFileNetLogObserverTest, CaptureMode) {
  base::ScopedFILE file(base::OpenFile(log_path_, "w"));
  ASSERT_TRUE(file);
  WriteToFileNetLogObserver logger;
  logger.StartObserving(&net_log_, std::move(file), nullptr, nullptr);
  EXPECT_EQ(NetLogCaptureMode::Default(), logger.capture_mode());
  logger.StopObserving(nullptr);

  file.reset(base::OpenFile(log_path_, "w"));
  ASSERT_TRUE(file);
  logger.set_capture_mode(NetLogCaptureMode::IncludeCookiesAndCredentials());
  logger.StartObserving(&net_log_, std::move(file), nullptr, nullptr);
  EXPECT_EQ(NetLogCaptureMode::IncludeCookiesAndCredentials(),
            logger.capture_mode());
  logger.StopObserving(nullptr);
}

TEST_F(WriteToFileNetLogObserverTest, GeneratesValidJSONWithOneEvent) {
  base::ScopedFILE file(base::OpenFile(log_path_, "w"));
  ASSERT_TRUE(file);
  std::unique_ptr<WriteToFileNetLogObserver> logger(
      new WriteToFileNetLogObserver());
  logger->StartObserving(&net_log_, std::move(file), nullptr, nullptr);

  const int kDummyId = 1;
  NetLogSource source(NetLogSourceType::HTTP2_SESSION, kDummyId);
  NetLogEntryData entry_data(NetLogEventType::PROXY_SERVICE, source,
                             NetLogEventPhase::BEGIN, base::TimeTicks::Now(),
                             NULL);
  NetLogEntry entry(&entry_data, NetLogCaptureMode::IncludeSocketBytes());
  logger->OnAddEntry(entry);
  logger->StopObserving(nullptr);
  logger.reset();

  std::string input;
  ASSERT_TRUE(base::ReadFileToString(log_path_, &input));

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));
  ASSERT_EQ(1u, events->GetSize());
}

TEST_F(WriteToFileNetLogObserverTest, GeneratesValidJSONWithMultipleEvents) {
  base::ScopedFILE file(base::OpenFile(log_path_, "w"));
  ASSERT_TRUE(file);
  std::unique_ptr<WriteToFileNetLogObserver> logger(
      new WriteToFileNetLogObserver());
  logger->StartObserving(&net_log_, std::move(file), nullptr, nullptr);

  const int kDummyId = 1;
  NetLogSource source(NetLogSourceType::HTTP2_SESSION, kDummyId);
  NetLogEntryData entry_data(NetLogEventType::PROXY_SERVICE, source,
                             NetLogEventPhase::BEGIN, base::TimeTicks::Now(),
                             NULL);
  NetLogEntry entry(&entry_data, NetLogCaptureMode::IncludeSocketBytes());

  // Add the entry multiple times.
  logger->OnAddEntry(entry);
  logger->OnAddEntry(entry);
  logger->StopObserving(nullptr);
  logger.reset();

  std::string input;
  ASSERT_TRUE(base::ReadFileToString(log_path_, &input));

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));
  ASSERT_EQ(2u, events->GetSize());
}

TEST_F(WriteToFileNetLogObserverTest, CustomConstants) {
  const char kConstantString[] = "awesome constant";
  std::unique_ptr<base::Value> constants(new base::Value(kConstantString));
  base::ScopedFILE file(base::OpenFile(log_path_, "w"));
  ASSERT_TRUE(file);
  std::unique_ptr<WriteToFileNetLogObserver> logger(
      new WriteToFileNetLogObserver());
  logger->StartObserving(&net_log_, std::move(file), constants.get(), nullptr);
  logger->StopObserving(nullptr);
  logger.reset();

  std::string input;
  ASSERT_TRUE(base::ReadFileToString(log_path_, &input));

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  std::string constants_string;
  ASSERT_TRUE(dict->GetString("constants", &constants_string));
  ASSERT_EQ(kConstantString, constants_string);
}

TEST_F(WriteToFileNetLogObserverTest, GeneratesValidJSONWithContext) {
  // Create context, start a request.
  TestURLRequestContext context(true);
  context.set_net_log(&net_log_);
  context.Init();

  // Create and destroy a logger.
  base::ScopedFILE file(base::OpenFile(log_path_, "w"));
  ASSERT_TRUE(file);
  std::unique_ptr<WriteToFileNetLogObserver> logger(
      new WriteToFileNetLogObserver());
  logger->StartObserving(&net_log_, std::move(file), nullptr, &context);
  logger->StopObserving(&context);
  logger.reset();

  std::string input;
  ASSERT_TRUE(base::ReadFileToString(log_path_, &input));

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

  base::DictionaryValue* dict;
  ASSERT_TRUE(root->GetAsDictionary(&dict));
  base::ListValue* events;
  ASSERT_TRUE(dict->GetList("events", &events));
  ASSERT_EQ(0u, events->GetSize());

  // Make sure additional information is present, but don't validate it.
  base::DictionaryValue* tab_info;
  ASSERT_TRUE(dict->GetDictionary("tabInfo", &tab_info));
}

TEST_F(WriteToFileNetLogObserverTest,
       GeneratesValidJSONWithContextWithActiveRequest) {
  // Create context, start a request.
  TestURLRequestContext context(true);
  context.set_net_log(&net_log_);
  context.Init();
  TestDelegate delegate;

  // URL doesn't matter.  Requests can't fail synchronously.
  std::unique_ptr<URLRequest> request(context.CreateRequest(
      GURL("blah:blah"), IDLE, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();

  // Create and destroy a logger.
  base::ScopedFILE file(base::OpenFile(log_path_, "w"));
  ASSERT_TRUE(file);
  std::unique_ptr<WriteToFileNetLogObserver> logger(
      new WriteToFileNetLogObserver());
  logger->StartObserving(&net_log_, std::move(file), nullptr, &context);
  logger->StopObserving(&context);
  logger.reset();

  std::string input;
  ASSERT_TRUE(base::ReadFileToString(log_path_, &input));

  base::JSONReader reader;
  std::unique_ptr<base::Value> root(reader.ReadToValue(input));
  ASSERT_TRUE(root) << reader.GetErrorMessage();

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
