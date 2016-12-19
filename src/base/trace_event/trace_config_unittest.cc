// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>

#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/macros.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/trace_event/trace_config.h"
#include "base/trace_event/trace_config_memory_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace trace_event {

namespace {

const char kDefaultTraceConfigString[] =
  "{"
    "\"enable_argument_filter\":false,"
    "\"enable_systrace\":false,"
    "\"record_mode\":\"record-until-full\""
  "}";

const char kCustomTraceConfigString[] =
    "{"
    "\"enable_argument_filter\":true,"
    "\"enable_systrace\":true,"
    "\"event_filters\":["
    "{"
    "\"excluded_categories\":[\"unfiltered_cat\"],"
    "\"filter_args\":{\"event_name_whitelist\":[\"a snake\",\"a dog\"]},"
    "\"filter_predicate\":\"event_whitelist_predicate\","
    "\"included_categories\":[\"*\"]"
    "}"
    "],"
    "\"excluded_categories\":[\"excluded\",\"exc_pattern*\"],"
    "\"included_categories\":["
    "\"included\","
    "\"inc_pattern*\","
    "\"disabled-by-default-cc\","
    "\"disabled-by-default-memory-infra\"],"
    "\"memory_dump_config\":{"
    "\"allowed_dump_modes\":[\"background\",\"light\",\"detailed\"],"
    "\"heap_profiler_options\":{"
    "\"breakdown_threshold_bytes\":10240"
    "},"
    "\"triggers\":["
    "{"
    "\"min_time_between_dumps_ms\":50,"
    "\"mode\":\"light\","
    "\"type\":\"periodic_interval\""
    "},"
    "{"
    "\"min_time_between_dumps_ms\":1000,"
    "\"mode\":\"detailed\","
    "\"type\":\"peak_memory_usage\""
    "}"
    "]"
    "},"
    "\"record_mode\":\"record-continuously\","
    "\"synthetic_delays\":[\"test.Delay1;16\",\"test.Delay2;32\"]"
    "}";

void CheckDefaultTraceConfigBehavior(const TraceConfig& tc) {
  EXPECT_EQ(RECORD_UNTIL_FULL, tc.GetTraceRecordMode());
  EXPECT_FALSE(tc.IsSystraceEnabled());
  EXPECT_FALSE(tc.IsArgumentFilterEnabled());

  // Default trace config enables every category filter except the
  // disabled-by-default-* ones.
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("Category1"));
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("not-excluded-category"));
  EXPECT_FALSE(tc.IsCategoryGroupEnabled("disabled-by-default-cc"));

  EXPECT_TRUE(tc.IsCategoryGroupEnabled("Category1,not-excluded-category"));
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("Category1,disabled-by-default-cc"));
  EXPECT_FALSE(tc.IsCategoryGroupEnabled(
      "disabled-by-default-cc,disabled-by-default-cc2"));
}

}  // namespace

TEST(TraceConfigTest, TraceConfigFromValidLegacyFormat) {
  // From trace options strings
  TraceConfig config("", "record-until-full");
  EXPECT_EQ(RECORD_UNTIL_FULL, config.GetTraceRecordMode());
  EXPECT_FALSE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("record-until-full", config.ToTraceOptionsString().c_str());

  config = TraceConfig("", "record-continuously");
  EXPECT_EQ(RECORD_CONTINUOUSLY, config.GetTraceRecordMode());
  EXPECT_FALSE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("record-continuously", config.ToTraceOptionsString().c_str());

  config = TraceConfig("", "trace-to-console");
  EXPECT_EQ(ECHO_TO_CONSOLE, config.GetTraceRecordMode());
  EXPECT_FALSE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("trace-to-console", config.ToTraceOptionsString().c_str());

  config = TraceConfig("", "record-as-much-as-possible");
  EXPECT_EQ(RECORD_AS_MUCH_AS_POSSIBLE, config.GetTraceRecordMode());
  EXPECT_FALSE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("record-as-much-as-possible",
               config.ToTraceOptionsString().c_str());

  config = TraceConfig("", "enable-systrace, record-continuously");
  EXPECT_EQ(RECORD_CONTINUOUSLY, config.GetTraceRecordMode());
  EXPECT_TRUE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("record-continuously,enable-systrace",
               config.ToTraceOptionsString().c_str());

  config = TraceConfig("", "enable-argument-filter,record-as-much-as-possible");
  EXPECT_EQ(RECORD_AS_MUCH_AS_POSSIBLE, config.GetTraceRecordMode());
  EXPECT_FALSE(config.IsSystraceEnabled());
  EXPECT_TRUE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("record-as-much-as-possible,enable-argument-filter",
               config.ToTraceOptionsString().c_str());

  config = TraceConfig(
    "",
    "enable-systrace,trace-to-console,enable-argument-filter");
  EXPECT_EQ(ECHO_TO_CONSOLE, config.GetTraceRecordMode());
  EXPECT_TRUE(config.IsSystraceEnabled());
  EXPECT_TRUE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ(
    "trace-to-console,enable-systrace,enable-argument-filter",
    config.ToTraceOptionsString().c_str());

  config = TraceConfig(
    "", "record-continuously, record-until-full, trace-to-console");
  EXPECT_EQ(ECHO_TO_CONSOLE, config.GetTraceRecordMode());
  EXPECT_FALSE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("trace-to-console", config.ToTraceOptionsString().c_str());

  // From TraceRecordMode
  config = TraceConfig("", RECORD_UNTIL_FULL);
  EXPECT_EQ(RECORD_UNTIL_FULL, config.GetTraceRecordMode());
  EXPECT_FALSE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("record-until-full", config.ToTraceOptionsString().c_str());

  config = TraceConfig("", RECORD_CONTINUOUSLY);
  EXPECT_EQ(RECORD_CONTINUOUSLY, config.GetTraceRecordMode());
  EXPECT_FALSE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("record-continuously", config.ToTraceOptionsString().c_str());

  config = TraceConfig("", ECHO_TO_CONSOLE);
  EXPECT_EQ(ECHO_TO_CONSOLE, config.GetTraceRecordMode());
  EXPECT_FALSE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("trace-to-console", config.ToTraceOptionsString().c_str());

  config = TraceConfig("", RECORD_AS_MUCH_AS_POSSIBLE);
  EXPECT_EQ(RECORD_AS_MUCH_AS_POSSIBLE, config.GetTraceRecordMode());
  EXPECT_FALSE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("record-as-much-as-possible",
               config.ToTraceOptionsString().c_str());

  // From category filter strings
  config = TraceConfig("included,-excluded,inc_pattern*,-exc_pattern*", "");
  EXPECT_STREQ("included,inc_pattern*,-excluded,-exc_pattern*",
               config.ToCategoryFilterString().c_str());

  config = TraceConfig("only_inc_cat", "");
  EXPECT_STREQ("only_inc_cat", config.ToCategoryFilterString().c_str());

  config = TraceConfig("-only_exc_cat", "");
  EXPECT_STREQ("-only_exc_cat", config.ToCategoryFilterString().c_str());

  config = TraceConfig("disabled-by-default-cc,-excluded", "");
  EXPECT_STREQ("disabled-by-default-cc,-excluded",
               config.ToCategoryFilterString().c_str());

  config = TraceConfig("disabled-by-default-cc,included", "");
  EXPECT_STREQ("included,disabled-by-default-cc",
               config.ToCategoryFilterString().c_str());

  config = TraceConfig("DELAY(test.Delay1;16),included", "");
  EXPECT_STREQ("included,DELAY(test.Delay1;16)",
               config.ToCategoryFilterString().c_str());

  // From both trace options and category filter strings
  config = TraceConfig("", "");
  EXPECT_EQ(RECORD_UNTIL_FULL, config.GetTraceRecordMode());
  EXPECT_FALSE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("", config.ToCategoryFilterString().c_str());
  EXPECT_STREQ("record-until-full", config.ToTraceOptionsString().c_str());

  config = TraceConfig("included,-excluded,inc_pattern*,-exc_pattern*",
                       "enable-systrace, trace-to-console");
  EXPECT_EQ(ECHO_TO_CONSOLE, config.GetTraceRecordMode());
  EXPECT_TRUE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("included,inc_pattern*,-excluded,-exc_pattern*",
               config.ToCategoryFilterString().c_str());
  EXPECT_STREQ("trace-to-console,enable-systrace",
               config.ToTraceOptionsString().c_str());

  // From both trace options and category filter strings with spaces.
  config = TraceConfig(" included , -excluded, inc_pattern*, ,-exc_pattern*   ",
                       "enable-systrace, ,trace-to-console  ");
  EXPECT_EQ(ECHO_TO_CONSOLE, config.GetTraceRecordMode());
  EXPECT_TRUE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("included,inc_pattern*,-excluded,-exc_pattern*",
               config.ToCategoryFilterString().c_str());
  EXPECT_STREQ("trace-to-console,enable-systrace",
               config.ToTraceOptionsString().c_str());

  // From category filter string and TraceRecordMode
  config = TraceConfig("included,-excluded,inc_pattern*,-exc_pattern*",
                       RECORD_CONTINUOUSLY);
  EXPECT_EQ(RECORD_CONTINUOUSLY, config.GetTraceRecordMode());
  EXPECT_FALSE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("included,inc_pattern*,-excluded,-exc_pattern*",
               config.ToCategoryFilterString().c_str());
  EXPECT_STREQ("record-continuously", config.ToTraceOptionsString().c_str());
}

TEST(TraceConfigTest, TraceConfigFromInvalidLegacyStrings) {
  TraceConfig config("", "foo-bar-baz");
  EXPECT_EQ(RECORD_UNTIL_FULL, config.GetTraceRecordMode());
  EXPECT_FALSE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("", config.ToCategoryFilterString().c_str());
  EXPECT_STREQ("record-until-full", config.ToTraceOptionsString().c_str());

  config = TraceConfig("arbitrary-category", "foo-bar-baz, enable-systrace");
  EXPECT_EQ(RECORD_UNTIL_FULL, config.GetTraceRecordMode());
  EXPECT_TRUE(config.IsSystraceEnabled());
  EXPECT_FALSE(config.IsArgumentFilterEnabled());
  EXPECT_STREQ("arbitrary-category", config.ToCategoryFilterString().c_str());
  EXPECT_STREQ("record-until-full,enable-systrace",
               config.ToTraceOptionsString().c_str());

  const char* const configs[] = {
    "",
    "DELAY(",
    "DELAY(;",
    "DELAY(;)",
    "DELAY(test.Delay)",
    "DELAY(test.Delay;)"
  };
  for (size_t i = 0; i < arraysize(configs); i++) {
    TraceConfig tc(configs[i], "");
    EXPECT_EQ(0u, tc.GetSyntheticDelayValues().size());
  }
}

TEST(TraceConfigTest, ConstructDefaultTraceConfig) {
  TraceConfig tc;
  EXPECT_STREQ("", tc.ToCategoryFilterString().c_str());
  EXPECT_STREQ(kDefaultTraceConfigString, tc.ToString().c_str());
  CheckDefaultTraceConfigBehavior(tc);

  // Constructors from category filter string and trace option string.
  TraceConfig tc_asterisk("*", "");
  EXPECT_STREQ("*", tc_asterisk.ToCategoryFilterString().c_str());
  CheckDefaultTraceConfigBehavior(tc_asterisk);

  TraceConfig tc_empty_category_filter("", "");
  EXPECT_STREQ("", tc_empty_category_filter.ToCategoryFilterString().c_str());
  EXPECT_STREQ(kDefaultTraceConfigString,
               tc_empty_category_filter.ToString().c_str());
  CheckDefaultTraceConfigBehavior(tc_empty_category_filter);

  // Constructor from JSON formated config string.
  TraceConfig tc_empty_json_string("");
  EXPECT_STREQ("", tc_empty_json_string.ToCategoryFilterString().c_str());
  EXPECT_STREQ(kDefaultTraceConfigString,
               tc_empty_json_string.ToString().c_str());
  CheckDefaultTraceConfigBehavior(tc_empty_json_string);

  // Constructor from dictionary value.
  DictionaryValue dict;
  TraceConfig tc_dict(dict);
  EXPECT_STREQ("", tc_dict.ToCategoryFilterString().c_str());
  EXPECT_STREQ(kDefaultTraceConfigString, tc_dict.ToString().c_str());
  CheckDefaultTraceConfigBehavior(tc_dict);
}

TEST(TraceConfigTest, EmptyAndAsteriskCategoryFilterString) {
  TraceConfig tc_empty("", "");
  TraceConfig tc_asterisk("*", "");

  EXPECT_STREQ("", tc_empty.ToCategoryFilterString().c_str());
  EXPECT_STREQ("*", tc_asterisk.ToCategoryFilterString().c_str());

  // Both fall back to default config.
  CheckDefaultTraceConfigBehavior(tc_empty);
  CheckDefaultTraceConfigBehavior(tc_asterisk);

  // They differ only for internal checking.
  EXPECT_FALSE(tc_empty.IsCategoryEnabled("Category1"));
  EXPECT_FALSE(tc_empty.IsCategoryEnabled("not-excluded-category"));
  EXPECT_TRUE(tc_asterisk.IsCategoryEnabled("Category1"));
  EXPECT_TRUE(tc_asterisk.IsCategoryEnabled("not-excluded-category"));
}

TEST(TraceConfigTest, DisabledByDefaultCategoryFilterString) {
  TraceConfig tc("foo,disabled-by-default-foo", "");
  EXPECT_STREQ("foo,disabled-by-default-foo",
               tc.ToCategoryFilterString().c_str());
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("foo"));
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("disabled-by-default-foo"));
  EXPECT_FALSE(tc.IsCategoryGroupEnabled("bar"));
  EXPECT_FALSE(tc.IsCategoryGroupEnabled("disabled-by-default-bar"));

  EXPECT_TRUE(tc.event_filters().empty());
  // Enabling only the disabled-by-default-* category means the default ones
  // are also enabled.
  tc = TraceConfig("disabled-by-default-foo", "");
  EXPECT_STREQ("disabled-by-default-foo", tc.ToCategoryFilterString().c_str());
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("disabled-by-default-foo"));
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("foo"));
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("bar"));
  EXPECT_FALSE(tc.IsCategoryGroupEnabled("disabled-by-default-bar"));
}

TEST(TraceConfigTest, TraceConfigFromDict) {
  // Passing in empty dictionary will result in default trace config.
  DictionaryValue dict;
  TraceConfig tc(dict);
  EXPECT_STREQ(kDefaultTraceConfigString, tc.ToString().c_str());
  EXPECT_EQ(RECORD_UNTIL_FULL, tc.GetTraceRecordMode());
  EXPECT_FALSE(tc.IsSystraceEnabled());
  EXPECT_FALSE(tc.IsArgumentFilterEnabled());
  EXPECT_STREQ("", tc.ToCategoryFilterString().c_str());

  std::unique_ptr<Value> default_value(
      JSONReader::Read(kDefaultTraceConfigString));
  DCHECK(default_value);
  const DictionaryValue* default_dict = nullptr;
  bool is_dict = default_value->GetAsDictionary(&default_dict);
  DCHECK(is_dict);
  TraceConfig default_tc(*default_dict);
  EXPECT_STREQ(kDefaultTraceConfigString, default_tc.ToString().c_str());
  EXPECT_EQ(RECORD_UNTIL_FULL, default_tc.GetTraceRecordMode());
  EXPECT_FALSE(default_tc.IsSystraceEnabled());
  EXPECT_FALSE(default_tc.IsArgumentFilterEnabled());
  EXPECT_STREQ("", default_tc.ToCategoryFilterString().c_str());

  std::unique_ptr<Value> custom_value(
      JSONReader::Read(kCustomTraceConfigString));
  DCHECK(custom_value);
  const DictionaryValue* custom_dict = nullptr;
  is_dict = custom_value->GetAsDictionary(&custom_dict);
  DCHECK(is_dict);
  TraceConfig custom_tc(*custom_dict);
  EXPECT_STREQ(kCustomTraceConfigString, custom_tc.ToString().c_str());
  EXPECT_EQ(RECORD_CONTINUOUSLY, custom_tc.GetTraceRecordMode());
  EXPECT_TRUE(custom_tc.IsSystraceEnabled());
  EXPECT_TRUE(custom_tc.IsArgumentFilterEnabled());
  EXPECT_STREQ("included,inc_pattern*,"
               "disabled-by-default-cc,disabled-by-default-memory-infra,"
               "-excluded,-exc_pattern*,"
               "DELAY(test.Delay1;16),DELAY(test.Delay2;32)",
               custom_tc.ToCategoryFilterString().c_str());
}

TEST(TraceConfigTest, TraceConfigFromValidString) {
  // Using some non-empty config string.
  const char config_string[] =
      "{"
      "\"enable_argument_filter\":true,"
      "\"enable_systrace\":true,"
      "\"event_filters\":["
      "{"
      "\"excluded_categories\":[\"unfiltered_cat\"],"
      "\"filter_args\":{\"event_name_whitelist\":[\"a snake\",\"a dog\"]},"
      "\"filter_predicate\":\"event_whitelist_predicate\","
      "\"included_categories\":[\"*\"]"
      "}"
      "],"
      "\"excluded_categories\":[\"excluded\",\"exc_pattern*\"],"
      "\"included_categories\":[\"included\","
      "\"inc_pattern*\","
      "\"disabled-by-default-cc\"],"
      "\"record_mode\":\"record-continuously\","
      "\"synthetic_delays\":[\"test.Delay1;16\",\"test.Delay2;32\"]"
      "}";
  TraceConfig tc(config_string);

  EXPECT_STREQ(config_string, tc.ToString().c_str());
  EXPECT_EQ(RECORD_CONTINUOUSLY, tc.GetTraceRecordMode());
  EXPECT_TRUE(tc.IsSystraceEnabled());
  EXPECT_TRUE(tc.IsArgumentFilterEnabled());
  EXPECT_STREQ("included,inc_pattern*,disabled-by-default-cc,-excluded,"
               "-exc_pattern*,DELAY(test.Delay1;16),DELAY(test.Delay2;32)",
               tc.ToCategoryFilterString().c_str());

  EXPECT_TRUE(tc.IsCategoryEnabled("included"));
  EXPECT_TRUE(tc.IsCategoryEnabled("inc_pattern_category"));
  EXPECT_TRUE(tc.IsCategoryEnabled("disabled-by-default-cc"));
  EXPECT_FALSE(tc.IsCategoryEnabled("excluded"));
  EXPECT_FALSE(tc.IsCategoryEnabled("exc_pattern_category"));
  EXPECT_FALSE(tc.IsCategoryEnabled("disabled-by-default-others"));
  EXPECT_FALSE(tc.IsCategoryEnabled("not-excluded-nor-included"));

  EXPECT_TRUE(tc.IsCategoryGroupEnabled("included"));
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("inc_pattern_category"));
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("disabled-by-default-cc"));
  EXPECT_FALSE(tc.IsCategoryGroupEnabled("excluded"));
  EXPECT_FALSE(tc.IsCategoryGroupEnabled("exc_pattern_category"));
  EXPECT_FALSE(tc.IsCategoryGroupEnabled("disabled-by-default-others"));
  EXPECT_FALSE(tc.IsCategoryGroupEnabled("not-excluded-nor-included"));

  EXPECT_TRUE(tc.IsCategoryGroupEnabled("included,excluded"));
  EXPECT_FALSE(tc.IsCategoryGroupEnabled("excluded,exc_pattern_category"));
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("included,DELAY(test.Delay1;16)"));
  EXPECT_FALSE(tc.IsCategoryGroupEnabled("DELAY(test.Delay1;16)"));

  EXPECT_EQ(2u, tc.GetSyntheticDelayValues().size());
  EXPECT_STREQ("test.Delay1;16", tc.GetSyntheticDelayValues()[0].c_str());
  EXPECT_STREQ("test.Delay2;32", tc.GetSyntheticDelayValues()[1].c_str());

  EXPECT_EQ(tc.event_filters().size(), 1u);
  const TraceConfig::EventFilterConfig& event_filter = tc.event_filters()[0];
  EXPECT_STREQ("event_whitelist_predicate",
               event_filter.predicate_name().c_str());
  EXPECT_EQ(1u, event_filter.included_categories().size());
  EXPECT_STREQ("*", event_filter.included_categories()[0].c_str());
  EXPECT_EQ(1u, event_filter.excluded_categories().size());
  EXPECT_STREQ("unfiltered_cat", event_filter.excluded_categories()[0].c_str());
  EXPECT_TRUE(event_filter.filter_args());

  std::string json_out;
  base::JSONWriter::Write(*event_filter.filter_args(), &json_out);
  EXPECT_STREQ(json_out.c_str(),
               "{\"event_name_whitelist\":[\"a snake\",\"a dog\"]}");
  std::unordered_set<std::string> filter_values;
  EXPECT_TRUE(event_filter.GetArgAsSet("event_name_whitelist", &filter_values));
  EXPECT_EQ(2u, filter_values.size());
  EXPECT_EQ(1u, filter_values.count("a snake"));
  EXPECT_EQ(1u, filter_values.count("a dog"));

  const char config_string_2[] = "{\"included_categories\":[\"*\"]}";
  TraceConfig tc2(config_string_2);
  EXPECT_TRUE(tc2.IsCategoryEnabled("non-disabled-by-default-pattern"));
  EXPECT_FALSE(tc2.IsCategoryEnabled("disabled-by-default-pattern"));
  EXPECT_TRUE(tc2.IsCategoryGroupEnabled("non-disabled-by-default-pattern"));
  EXPECT_FALSE(tc2.IsCategoryGroupEnabled("disabled-by-default-pattern"));

  // Clear
  tc.Clear();
  EXPECT_STREQ(tc.ToString().c_str(),
               "{"
                 "\"enable_argument_filter\":false,"
                 "\"enable_systrace\":false,"
                 "\"record_mode\":\"record-until-full\""
               "}");
}

TEST(TraceConfigTest, TraceConfigFromInvalidString) {
  // The config string needs to be a dictionary correctly formatted as a JSON
  // string. Otherwise, it will fall back to the default initialization.
  TraceConfig tc("");
  EXPECT_STREQ(kDefaultTraceConfigString, tc.ToString().c_str());
  EXPECT_EQ(RECORD_UNTIL_FULL, tc.GetTraceRecordMode());
  EXPECT_FALSE(tc.IsSystraceEnabled());
  EXPECT_FALSE(tc.IsArgumentFilterEnabled());
  EXPECT_STREQ("", tc.ToCategoryFilterString().c_str());
  CheckDefaultTraceConfigBehavior(tc);

  tc = TraceConfig("This is an invalid config string.");
  EXPECT_STREQ(kDefaultTraceConfigString, tc.ToString().c_str());
  EXPECT_EQ(RECORD_UNTIL_FULL, tc.GetTraceRecordMode());
  EXPECT_FALSE(tc.IsSystraceEnabled());
  EXPECT_FALSE(tc.IsArgumentFilterEnabled());
  EXPECT_STREQ("", tc.ToCategoryFilterString().c_str());
  CheckDefaultTraceConfigBehavior(tc);

  tc = TraceConfig("[\"This\", \"is\", \"not\", \"a\", \"dictionary\"]");
  EXPECT_STREQ(kDefaultTraceConfigString, tc.ToString().c_str());
  EXPECT_EQ(RECORD_UNTIL_FULL, tc.GetTraceRecordMode());
  EXPECT_FALSE(tc.IsSystraceEnabled());
  EXPECT_FALSE(tc.IsArgumentFilterEnabled());
  EXPECT_STREQ("", tc.ToCategoryFilterString().c_str());
  CheckDefaultTraceConfigBehavior(tc);

  tc = TraceConfig("{\"record_mode\": invalid-value-needs-double-quote}");
  EXPECT_STREQ(kDefaultTraceConfigString, tc.ToString().c_str());
  EXPECT_EQ(RECORD_UNTIL_FULL, tc.GetTraceRecordMode());
  EXPECT_FALSE(tc.IsSystraceEnabled());
  EXPECT_FALSE(tc.IsArgumentFilterEnabled());
  EXPECT_STREQ("", tc.ToCategoryFilterString().c_str());
  CheckDefaultTraceConfigBehavior(tc);

  // If the config string a dictionary formatted as a JSON string, it will
  // initialize TraceConfig with best effort.
  tc = TraceConfig("{}");
  EXPECT_EQ(RECORD_UNTIL_FULL, tc.GetTraceRecordMode());
  EXPECT_FALSE(tc.IsSystraceEnabled());
  EXPECT_FALSE(tc.IsArgumentFilterEnabled());
  EXPECT_STREQ("", tc.ToCategoryFilterString().c_str());
  CheckDefaultTraceConfigBehavior(tc);

  tc = TraceConfig("{\"arbitrary-key\":\"arbitrary-value\"}");
  EXPECT_EQ(RECORD_UNTIL_FULL, tc.GetTraceRecordMode());
  EXPECT_FALSE(tc.IsSystraceEnabled());
  EXPECT_FALSE(tc.IsArgumentFilterEnabled());
  EXPECT_STREQ("", tc.ToCategoryFilterString().c_str());
  CheckDefaultTraceConfigBehavior(tc);

  const char invalid_config_string[] =
    "{"
      "\"enable_systrace\":1,"
      "\"excluded_categories\":[\"excluded\"],"
      "\"included_categories\":\"not a list\","
      "\"record_mode\":\"arbitrary-mode\","
      "\"synthetic_delays\":[\"test.Delay1;16\","
                            "\"invalid-delay\","
                            "\"test.Delay2;32\"]"
    "}";
  tc = TraceConfig(invalid_config_string);
  EXPECT_EQ(RECORD_UNTIL_FULL, tc.GetTraceRecordMode());
  EXPECT_FALSE(tc.IsSystraceEnabled());
  EXPECT_FALSE(tc.IsArgumentFilterEnabled());
  EXPECT_STREQ("-excluded,DELAY(test.Delay1;16),DELAY(test.Delay2;32)",
               tc.ToCategoryFilterString().c_str());

  const char invalid_config_string_2[] =
    "{"
      "\"included_categories\":[\"category\",\"disabled-by-default-pattern\"],"
      "\"excluded_categories\":[\"category\",\"disabled-by-default-pattern\"]"
    "}";
  tc = TraceConfig(invalid_config_string_2);
  EXPECT_TRUE(tc.IsCategoryEnabled("category"));
  EXPECT_TRUE(tc.IsCategoryEnabled("disabled-by-default-pattern"));
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("category"));
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("disabled-by-default-pattern"));
}

TEST(TraceConfigTest, MergingTraceConfigs) {
  // Merge
  TraceConfig tc;
  TraceConfig tc2("included,-excluded,inc_pattern*,-exc_pattern*", "");
  tc.Merge(tc2);
  EXPECT_STREQ("{"
                 "\"enable_argument_filter\":false,"
                 "\"enable_systrace\":false,"
                 "\"excluded_categories\":[\"excluded\",\"exc_pattern*\"],"
                 "\"record_mode\":\"record-until-full\""
               "}",
               tc.ToString().c_str());

  tc = TraceConfig("DELAY(test.Delay1;16)", "");
  tc2 = TraceConfig("DELAY(test.Delay2;32)", "");
  tc.Merge(tc2);
  EXPECT_EQ(2u, tc.GetSyntheticDelayValues().size());
  EXPECT_STREQ("test.Delay1;16", tc.GetSyntheticDelayValues()[0].c_str());
  EXPECT_STREQ("test.Delay2;32", tc.GetSyntheticDelayValues()[1].c_str());
}

TEST(TraceConfigTest, IsCategoryGroupEnabled) {
  // Enabling a disabled- category does not require all categories to be traced
  // to be included.
  TraceConfig tc("disabled-by-default-cc,-excluded", "");
  EXPECT_STREQ("disabled-by-default-cc,-excluded",
               tc.ToCategoryFilterString().c_str());
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("disabled-by-default-cc"));
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("some_other_group"));
  EXPECT_FALSE(tc.IsCategoryGroupEnabled("excluded"));

  // Enabled a disabled- category and also including makes all categories to
  // be traced require including.
  tc = TraceConfig("disabled-by-default-cc,included", "");
  EXPECT_STREQ("included,disabled-by-default-cc",
               tc.ToCategoryFilterString().c_str());
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("disabled-by-default-cc"));
  EXPECT_TRUE(tc.IsCategoryGroupEnabled("included"));
  EXPECT_FALSE(tc.IsCategoryGroupEnabled("other_included"));

  // Excluding categories won't enable disabled-by-default ones with the
  // excluded category is also present in the group.
  tc = TraceConfig("-excluded", "");
  EXPECT_STREQ("-excluded", tc.ToCategoryFilterString().c_str());
  EXPECT_FALSE(tc.IsCategoryGroupEnabled("excluded,disabled-by-default-cc"));
}

TEST(TraceConfigTest, IsEmptyOrContainsLeadingOrTrailingWhitespace) {
  // Test that IsEmptyOrContainsLeadingOrTrailingWhitespace actually catches
  // categories that are explicitly forbidden.
  // This method is called in a DCHECK to assert that we don't have these types
  // of strings as categories.
  EXPECT_TRUE(TraceConfig::IsEmptyOrContainsLeadingOrTrailingWhitespace(
      " bad_category "));
  EXPECT_TRUE(TraceConfig::IsEmptyOrContainsLeadingOrTrailingWhitespace(
      " bad_category"));
  EXPECT_TRUE(TraceConfig::IsEmptyOrContainsLeadingOrTrailingWhitespace(
      "bad_category "));
  EXPECT_TRUE(TraceConfig::IsEmptyOrContainsLeadingOrTrailingWhitespace(
      "   bad_category"));
  EXPECT_TRUE(TraceConfig::IsEmptyOrContainsLeadingOrTrailingWhitespace(
      "bad_category   "));
  EXPECT_TRUE(TraceConfig::IsEmptyOrContainsLeadingOrTrailingWhitespace(
      "   bad_category   "));
  EXPECT_TRUE(TraceConfig::IsEmptyOrContainsLeadingOrTrailingWhitespace(
      ""));
  EXPECT_FALSE(TraceConfig::IsEmptyOrContainsLeadingOrTrailingWhitespace(
      "good_category"));
}

TEST(TraceConfigTest, SetTraceOptionValues) {
  TraceConfig tc;
  EXPECT_EQ(RECORD_UNTIL_FULL, tc.GetTraceRecordMode());
  EXPECT_FALSE(tc.IsSystraceEnabled());

  tc.SetTraceRecordMode(RECORD_AS_MUCH_AS_POSSIBLE);
  EXPECT_EQ(RECORD_AS_MUCH_AS_POSSIBLE, tc.GetTraceRecordMode());

  tc.EnableSystrace();
  EXPECT_TRUE(tc.IsSystraceEnabled());
}

TEST(TraceConfigTest, TraceConfigFromMemoryConfigString) {
  std::string tc_str1 =
      TraceConfigMemoryTestUtil::GetTraceConfig_PeriodicTriggers(200, 2000);
  TraceConfig tc1(tc_str1);
  EXPECT_EQ(tc_str1, tc1.ToString());
  TraceConfig tc2(
      TraceConfigMemoryTestUtil::GetTraceConfig_LegacyPeriodicTriggers(200,
                                                                       2000));
  EXPECT_EQ(tc_str1, tc2.ToString());

  EXPECT_TRUE(tc1.IsCategoryGroupEnabled(MemoryDumpManager::kTraceCategory));
  ASSERT_EQ(2u, tc1.memory_dump_config_.triggers.size());

  EXPECT_EQ(200u,
            tc1.memory_dump_config_.triggers[0].min_time_between_dumps_ms);
  EXPECT_EQ(MemoryDumpLevelOfDetail::LIGHT,
            tc1.memory_dump_config_.triggers[0].level_of_detail);

  EXPECT_EQ(2000u,
            tc1.memory_dump_config_.triggers[1].min_time_between_dumps_ms);
  EXPECT_EQ(MemoryDumpLevelOfDetail::DETAILED,
            tc1.memory_dump_config_.triggers[1].level_of_detail);
  EXPECT_EQ(
      2048u,
      tc1.memory_dump_config_.heap_profiler_options.breakdown_threshold_bytes);

  std::string tc_str3 =
      TraceConfigMemoryTestUtil::GetTraceConfig_BackgroundTrigger(
          1 /* period_ms */);
  TraceConfig tc3(tc_str3);
  EXPECT_EQ(tc_str3, tc3.ToString());
  EXPECT_TRUE(tc3.IsCategoryGroupEnabled(MemoryDumpManager::kTraceCategory));
  ASSERT_EQ(1u, tc3.memory_dump_config_.triggers.size());
  EXPECT_EQ(1u, tc3.memory_dump_config_.triggers[0].min_time_between_dumps_ms);
  EXPECT_EQ(MemoryDumpLevelOfDetail::BACKGROUND,
            tc3.memory_dump_config_.triggers[0].level_of_detail);

  std::string tc_str4 =
      TraceConfigMemoryTestUtil::GetTraceConfig_PeakDetectionTrigger(
          1 /*heavy_period */);
  TraceConfig tc4(tc_str4);
  EXPECT_EQ(tc_str4, tc4.ToString());
  ASSERT_EQ(1u, tc4.memory_dump_config_.triggers.size());
  EXPECT_EQ(1u, tc4.memory_dump_config_.triggers[0].min_time_between_dumps_ms);
  EXPECT_EQ(MemoryDumpLevelOfDetail::DETAILED,
            tc4.memory_dump_config_.triggers[0].level_of_detail);
}

TEST(TraceConfigTest, EmptyMemoryDumpConfigTest) {
  // Empty trigger list should also be specified when converting back to string.
  TraceConfig tc(TraceConfigMemoryTestUtil::GetTraceConfig_EmptyTriggers());
  EXPECT_EQ(TraceConfigMemoryTestUtil::GetTraceConfig_EmptyTriggers(),
            tc.ToString());
  EXPECT_EQ(0u, tc.memory_dump_config_.triggers.size());
  EXPECT_EQ(TraceConfig::MemoryDumpConfig::HeapProfiler
            ::kDefaultBreakdownThresholdBytes,
            tc.memory_dump_config_.heap_profiler_options
            .breakdown_threshold_bytes);
}

TEST(TraceConfigTest, LegacyStringToMemoryDumpConfig) {
  TraceConfig tc(MemoryDumpManager::kTraceCategory, "");
  EXPECT_TRUE(tc.IsCategoryGroupEnabled(MemoryDumpManager::kTraceCategory));
  EXPECT_NE(std::string::npos, tc.ToString().find("memory_dump_config"));
  EXPECT_EQ(2u, tc.memory_dump_config_.triggers.size());
  EXPECT_EQ(TraceConfig::MemoryDumpConfig::HeapProfiler
            ::kDefaultBreakdownThresholdBytes,
            tc.memory_dump_config_.heap_profiler_options
            .breakdown_threshold_bytes);
}

}  // namespace trace_event
}  // namespace base
