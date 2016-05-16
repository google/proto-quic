// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/blame_context.h"

#include "base/json/json_writer.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted_memory.h"
#include "base/run_loop.h"
#include "base/test/trace_event_analyzer.h"
#include "base/trace_event/trace_buffer.h"
#include "base/trace_event/trace_event_argument.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace trace_event {
namespace {

const char kTestBlameContextCategory[] = "test";
const char kDisabledTestBlameContextCategory[] = "disabled-by-default-test";
const char kTestBlameContextName[] = "TestBlameContext";
const char kTestBlameContextType[] = "TestBlameContextType";
const char kTestBlameContextScope[] = "TestBlameContextScope";

class TestBlameContext : public BlameContext {
 public:
  explicit TestBlameContext(int id)
      : BlameContext(kTestBlameContextCategory,
                     kTestBlameContextName,
                     kTestBlameContextType,
                     kTestBlameContextScope,
                     id,
                     nullptr) {}

  TestBlameContext(int id, const TestBlameContext& parent)
      : BlameContext(kTestBlameContextCategory,
                     kTestBlameContextName,
                     kTestBlameContextType,
                     kTestBlameContextScope,
                     id,
                     &parent) {}

 protected:
  void AsValueInto(trace_event::TracedValue* state) override {
    BlameContext::AsValueInto(state);
    state->SetBoolean("crossStreams", false);
  }
};

class DisabledTestBlameContext : public BlameContext {
 public:
  explicit DisabledTestBlameContext(int id)
      : BlameContext(kDisabledTestBlameContextCategory,
                     kTestBlameContextName,
                     kTestBlameContextType,
                     kTestBlameContextScope,
                     id,
                     nullptr) {}
};

void OnTraceDataCollected(Closure quit_closure,
                          trace_event::TraceResultBuffer* buffer,
                          const scoped_refptr<RefCountedString>& json,
                          bool has_more_events) {
  buffer->AddFragment(json->data());
  if (!has_more_events)
    quit_closure.Run();
}

class BlameContextTest : public testing::Test {
 public:
  void StartTracing();
  void StopTracing();
  std::unique_ptr<trace_analyzer::TraceAnalyzer> CreateTraceAnalyzer();
 protected:
  MessageLoop loop_;
};

void BlameContextTest::StartTracing() {
  trace_event::TraceLog::GetInstance()->SetEnabled(
      trace_event::TraceConfig("*"), trace_event::TraceLog::RECORDING_MODE);
}

void BlameContextTest::StopTracing() {
  trace_event::TraceLog::GetInstance()->SetDisabled();
}

std::unique_ptr<trace_analyzer::TraceAnalyzer>
BlameContextTest::CreateTraceAnalyzer() {
  trace_event::TraceResultBuffer buffer;
  trace_event::TraceResultBuffer::SimpleOutput trace_output;
  buffer.SetOutputCallback(trace_output.GetCallback());
  RunLoop run_loop;
  buffer.Start();
  trace_event::TraceLog::GetInstance()->Flush(
      Bind(&OnTraceDataCollected, run_loop.QuitClosure(), Unretained(&buffer)));
  run_loop.Run();
  buffer.Finish();

  return WrapUnique(
      trace_analyzer::TraceAnalyzer::Create(trace_output.json_output));
}

TEST_F(BlameContextTest, EnterAndLeave) {
  using trace_analyzer::Query;
  StartTracing();
  {
    TestBlameContext blame_context(0x1234);
    blame_context.Initialize();
    blame_context.Enter();
    blame_context.Leave();
  }
  StopTracing();
  std::unique_ptr<trace_analyzer::TraceAnalyzer> analyzer =
      CreateTraceAnalyzer();

  trace_analyzer::TraceEventVector events;
  Query q = Query::EventPhaseIs(TRACE_EVENT_PHASE_ENTER_CONTEXT) ||
            Query::EventPhaseIs(TRACE_EVENT_PHASE_LEAVE_CONTEXT);
  analyzer->FindEvents(q, &events);

  EXPECT_EQ(2u, events.size());
  EXPECT_EQ(TRACE_EVENT_PHASE_ENTER_CONTEXT, events[0]->phase);
  EXPECT_EQ(kTestBlameContextCategory, events[0]->category);
  EXPECT_EQ(kTestBlameContextName, events[0]->name);
  EXPECT_EQ("0x1234", events[0]->id);
  EXPECT_EQ(TRACE_EVENT_PHASE_LEAVE_CONTEXT, events[1]->phase);
  EXPECT_EQ(kTestBlameContextCategory, events[1]->category);
  EXPECT_EQ(kTestBlameContextName, events[1]->name);
  EXPECT_EQ("0x1234", events[1]->id);
}

TEST_F(BlameContextTest, DifferentCategories) {
  // Ensure there is no cross talk between blame contexts from different
  // categories.
  using trace_analyzer::Query;
  StartTracing();
  {
    TestBlameContext blame_context(0x1234);
    DisabledTestBlameContext disabled_blame_context(0x5678);
    blame_context.Initialize();
    blame_context.Enter();
    blame_context.Leave();
    disabled_blame_context.Initialize();
    disabled_blame_context.Enter();
    disabled_blame_context.Leave();
  }
  StopTracing();
  std::unique_ptr<trace_analyzer::TraceAnalyzer> analyzer =
      CreateTraceAnalyzer();

  trace_analyzer::TraceEventVector events;
  Query q = Query::EventPhaseIs(TRACE_EVENT_PHASE_ENTER_CONTEXT) ||
            Query::EventPhaseIs(TRACE_EVENT_PHASE_LEAVE_CONTEXT);
  analyzer->FindEvents(q, &events);

  // None of the events from the disabled-by-default category should show up.
  EXPECT_EQ(2u, events.size());
  EXPECT_EQ(TRACE_EVENT_PHASE_ENTER_CONTEXT, events[0]->phase);
  EXPECT_EQ(kTestBlameContextCategory, events[0]->category);
  EXPECT_EQ(kTestBlameContextName, events[0]->name);
  EXPECT_EQ("0x1234", events[0]->id);
  EXPECT_EQ(TRACE_EVENT_PHASE_LEAVE_CONTEXT, events[1]->phase);
  EXPECT_EQ(kTestBlameContextCategory, events[1]->category);
  EXPECT_EQ(kTestBlameContextName, events[1]->name);
  EXPECT_EQ("0x1234", events[1]->id);
}

TEST_F(BlameContextTest, TakeSnapshot) {
  using trace_analyzer::Query;
  StartTracing();
  {
    TestBlameContext parent_blame_context(0x5678);
    TestBlameContext blame_context(0x1234, parent_blame_context);
    parent_blame_context.Initialize();
    blame_context.Initialize();
    blame_context.TakeSnapshot();
  }
  StopTracing();
  std::unique_ptr<trace_analyzer::TraceAnalyzer> analyzer =
      CreateTraceAnalyzer();

  trace_analyzer::TraceEventVector events;
  Query q = Query::EventPhaseIs(TRACE_EVENT_PHASE_SNAPSHOT_OBJECT);
  analyzer->FindEvents(q, &events);

  // We should have 3 snapshots: one for both calls to Initialize() and one from
  // the explicit call to TakeSnapshot().
  EXPECT_EQ(3u, events.size());
  EXPECT_EQ(kTestBlameContextCategory, events[0]->category);
  EXPECT_EQ(kTestBlameContextType, events[0]->name);
  EXPECT_EQ("0x5678", events[0]->id);
  EXPECT_TRUE(events[0]->HasArg("snapshot"));

  EXPECT_EQ(kTestBlameContextCategory, events[1]->category);
  EXPECT_EQ(kTestBlameContextType, events[1]->name);
  EXPECT_EQ("0x1234", events[1]->id);
  EXPECT_TRUE(events[0]->HasArg("snapshot"));

  EXPECT_EQ(kTestBlameContextCategory, events[2]->category);
  EXPECT_EQ(kTestBlameContextType, events[2]->name);
  EXPECT_EQ("0x1234", events[2]->id);
  EXPECT_TRUE(events[0]->HasArg("snapshot"));

  const char kExpectedSnapshotJson[] =
      "{"
          "\"crossStreams\":false,"
          "\"parent\":{"
              "\"id_ref\":\"0x5678\","
              "\"scope\":\"TestBlameContextScope\""
          "}"
      "}";

  std::string snapshot_json;
  JSONWriter::Write(*events[2]->GetKnownArgAsValue("snapshot"), &snapshot_json);
  EXPECT_EQ(kExpectedSnapshotJson, snapshot_json);
}

}  // namepace
}  // namespace trace_event
}  // namespace base
