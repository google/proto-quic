// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/traffic_annotation/auditor/traffic_annotation_auditor.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/memory/ptr_util.h"
#include "base/path_service.h"
#include "base/stl_util.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "tools/traffic_annotation/auditor/traffic_annotation_file_filter.h"

namespace {

#define TEST_HASH_CODE(X)                                  \
  EXPECT_EQ(TrafficAnnotationAuditor::ComputeHashValue(X), \
            net::DefineNetworkTrafficAnnotation(X, "").unique_id_hash_code)

const char* kIrrelevantFiles[] = {
    "tools/traffic_annotation/auditor/tests/git_list.txt",
    "tools/traffic_annotation/auditor/tests/irrelevant_file_content.cc",
    "tools/traffic_annotation/auditor/tests/irrelevant_file_content.mm",
    "tools/traffic_annotation/auditor/tests/irrelevant_file_name.txt"};

const char* kRelevantFiles[] = {
    "tools/traffic_annotation/auditor/tests/relevant_file_name_and_content.cc",
    "tools/traffic_annotation/auditor/tests/relevant_file_name_and_content.mm"};
}

using namespace testing;

class TrafficAnnotationAuditorTest : public ::testing::Test {
 public:
  void SetUp() override {
    if (!PathService::Get(base::DIR_SOURCE_ROOT, &source_path_)) {
      LOG(ERROR) << "Could not get current directory to find source path.";
      return;
    }

    tests_folder_ = source_path_.Append(FILE_PATH_LITERAL("tools"))
                        .Append(FILE_PATH_LITERAL("traffic_annotation"))
                        .Append(FILE_PATH_LITERAL("auditor"))
                        .Append(FILE_PATH_LITERAL("tests"));
  }

  const base::FilePath source_path() const { return source_path_; }
  const base::FilePath build_path() const { return build_path_; }
  const base::FilePath tests_folder() const { return tests_folder_; };

 protected:
  // Deserializes an annotation or a call instance from a sample file similar to
  // clang tool outputs.
  AuditorResult::ResultType Deserialize(const std::string& file_name,
                                        InstanceBase* instance);

  // Creates a complete annotation instance using sample files.
  std::unique_ptr<AnnotationInstance> CreateAnnotationInstanceSample();

 private:
  base::FilePath source_path_;
  base::FilePath build_path_;  // Currently stays empty. Will be set if access
                               // to a compiled build directory would be
                               // granted.
  base::FilePath tests_folder_;
};

AuditorResult::ResultType TrafficAnnotationAuditorTest::Deserialize(
    const std::string& file_name,
    InstanceBase* instance) {
  std::string file_content;
  EXPECT_TRUE(base::ReadFileToString(
      tests_folder_.Append(FILE_PATH_LITERAL("extractor_outputs"))
          .AppendASCII(file_name),
      &file_content));
  base::RemoveChars(file_content, "\r", &file_content);
  std::vector<std::string> lines = base::SplitString(
      file_content, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

  return instance->Deserialize(lines, 0, static_cast<int>(lines.size())).type();
}

std::unique_ptr<AnnotationInstance>
TrafficAnnotationAuditorTest::CreateAnnotationInstanceSample() {
  std::unique_ptr<AnnotationInstance> instance =
      base::MakeUnique<AnnotationInstance>();
  if (Deserialize("good_complete_annotation.txt", instance.get()) !=
      AuditorResult::ResultType::RESULT_OK) {
    instance.reset();
  }
  return instance;
}

// Tests if the two hash computation functions have the same result.
TEST_F(TrafficAnnotationAuditorTest, HashFunctionCheck) {
  TEST_HASH_CODE("test");
  TEST_HASH_CODE("unique_id");
  TEST_HASH_CODE("123_id");
  TEST_HASH_CODE("ID123");
  TEST_HASH_CODE(
      "a_unique_looooooooooooooooooooooooooooooooooooooooooooooooooooooong_id");
}

// Tests if TrafficAnnotationFileFilter::GetFilesFromGit function returns
// correct files given a mock git list file. It also inherently checks
// TrafficAnnotationFileFilter::IsFileRelevant.
TEST_F(TrafficAnnotationAuditorTest, GetFilesFromGit) {
  TrafficAnnotationFileFilter filter;
  filter.SetGitFileForTest(
      tests_folder().Append(FILE_PATH_LITERAL("git_list.txt")));
  filter.GetFilesFromGit(source_path());

  const std::vector<std::string> git_files = filter.git_files();

  EXPECT_EQ(git_files.size(), arraysize(kRelevantFiles));
  for (const char* filepath : kRelevantFiles) {
    EXPECT_TRUE(base::ContainsValue(git_files, filepath));
  }

  for (const char* filepath : kIrrelevantFiles) {
    EXPECT_FALSE(base::ContainsValue(git_files, filepath));
  }
}

// Tests if TrafficAnnotationFileFilter::GetRelevantFiles gives the correct list
// of files, given a mock git list file.
TEST_F(TrafficAnnotationAuditorTest, RelevantFilesReceived) {
  TrafficAnnotationFileFilter filter;
  filter.SetGitFileForTest(
      tests_folder().Append(FILE_PATH_LITERAL("git_list.txt")));
  filter.GetFilesFromGit(source_path());

  unsigned int git_files_count = filter.git_files().size();

  std::vector<std::string> ignore_list;
  std::vector<std::string> file_paths;

  // Check if all files are returned with no ignore list and directory.
  filter.GetRelevantFiles(base::FilePath(), ignore_list, "", &file_paths);
  EXPECT_EQ(file_paths.size(), git_files_count);

  // Check if a file is ignored if it is added to ignore list.
  ignore_list.push_back(file_paths[0]);
  file_paths.clear();
  filter.GetRelevantFiles(base::FilePath(), ignore_list, "", &file_paths);
  EXPECT_EQ(file_paths.size(), git_files_count - 1);
  EXPECT_FALSE(base::ContainsValue(file_paths, ignore_list[0]));

  // Check if files are filtered based on given directory.
  ignore_list.clear();
  file_paths.clear();
  filter.GetRelevantFiles(base::FilePath(), ignore_list,
                          "tools/traffic_annotation", &file_paths);
  EXPECT_EQ(file_paths.size(), git_files_count);
  file_paths.clear();
  filter.GetRelevantFiles(base::FilePath(), ignore_list, "content",
                          &file_paths);
  EXPECT_EQ(file_paths.size(), 0u);
}

// Tests if TrafficAnnotationFileFilter::IsWhitelisted works as expected.
// Inherently checks if TrafficAnnotationFileFilter::LoadWhiteList works and
// AuditorException rules are correctly deserialized.
TEST_F(TrafficAnnotationAuditorTest, IsWhitelisted) {
  TrafficAnnotationAuditor auditor(source_path(), build_path());

  for (unsigned int i = 0;
       i < static_cast<unsigned int>(
               AuditorException::ExceptionType::EXCEPTION_TYPE_LAST);
       i++) {
    AuditorException::ExceptionType type =
        static_cast<AuditorException::ExceptionType>(i);
    // Anything in /tools directory is whitelisted for all types.
    EXPECT_TRUE(auditor.IsWhitelisted("tools/something.cc", type));
    EXPECT_TRUE(auditor.IsWhitelisted("tools/somewhere/something.mm", type));

    // Anything in a general folder is not whitelisted for any type
    EXPECT_FALSE(auditor.IsWhitelisted("something.cc", type));
    EXPECT_FALSE(auditor.IsWhitelisted("content/something.mm", type));
  }

  // Files defining missing annotation functions in net/ are exceptions of
  // 'missing' type.
  EXPECT_TRUE(auditor.IsWhitelisted("net/url_request/url_fetcher.cc",
                                    AuditorException::ExceptionType::MISSING));
  EXPECT_TRUE(auditor.IsWhitelisted("net/url_request/url_request_context.cc",
                                    AuditorException::ExceptionType::MISSING));
}

// Tests if annotation instances are corrrectly deserialized.
TEST_F(TrafficAnnotationAuditorTest, AnnotationDeserialization) {
  struct AnnotationSample {
    std::string file_name;
    AuditorResult::ResultType result_type;
    AnnotationInstance::AnnotationType annotation_type;
  };

  AnnotationSample test_cases[] = {
      {"good_complete_annotation.txt", AuditorResult::ResultType::RESULT_OK,
       AnnotationInstance::AnnotationType::ANNOTATION_COMPLETE},
      {"good_branched_completing_annotation.txt",
       AuditorResult::ResultType::RESULT_OK,
       AnnotationInstance::AnnotationType::ANNOTATION_BRANCHED_COMPLETING},
      {"good_completing_annotation.txt", AuditorResult::ResultType::RESULT_OK,
       AnnotationInstance::AnnotationType::ANNOTATION_COMPLETENG},
      {"good_partial_annotation.txt", AuditorResult::ResultType::RESULT_OK,
       AnnotationInstance::AnnotationType::ANNOTATION_PARTIAL},
      {"good_test_annotation.txt", AuditorResult::ResultType::RESULT_IGNORE},
      {"missing_annotation.txt", AuditorResult::ResultType::ERROR_MISSING},
      {"no_annotation.txt", AuditorResult::ResultType::ERROR_NO_ANNOTATION},
      {"fatal_annotation1.txt", AuditorResult::ResultType::ERROR_FATAL},
      {"fatal_annotation2.txt", AuditorResult::ResultType::ERROR_FATAL},
      {"fatal_annotation3.txt", AuditorResult::ResultType::ERROR_FATAL},
      {"bad_syntax_annotation1.txt", AuditorResult::ResultType::ERROR_SYNTAX},
      {"bad_syntax_annotation2.txt", AuditorResult::ResultType::ERROR_SYNTAX},
      {"bad_syntax_annotation3.txt", AuditorResult::ResultType::ERROR_SYNTAX},
      {"bad_syntax_annotation4.txt", AuditorResult::ResultType::ERROR_SYNTAX},
  };

  for (const auto& test_case : test_cases) {
    // Check if deserialization result is as expected.
    AnnotationInstance annotation;
    AuditorResult::ResultType result_type =
        Deserialize(test_case.file_name, &annotation);
    EXPECT_EQ(result_type, test_case.result_type);

    if (result_type == AuditorResult::ResultType::RESULT_OK)
      EXPECT_EQ(annotation.annotation_type, test_case.annotation_type);

    // Content checks for one complete sample.
    if (test_case.file_name != "good_complete_annotation.txt")
      continue;

    EXPECT_EQ(annotation.proto.unique_id(),
              "supervised_user_refresh_token_fetcher");
    EXPECT_EQ(annotation.proto.source().file(),
              "chrome/browser/supervised_user/legacy/"
              "supervised_user_refresh_token_fetcher.cc");
    EXPECT_EQ(annotation.proto.source().function(), "OnGetTokenSuccess");
    EXPECT_EQ(annotation.proto.source().line(), 166);
    EXPECT_EQ(annotation.proto.semantics().sender(), "Supervised Users");
    EXPECT_EQ(annotation.proto.policy().cookies_allowed(), false);
  }
}

// Tests if call instances are corrrectly deserialized.
TEST_F(TrafficAnnotationAuditorTest, CallDeserialization) {
  struct CallSample {
    std::string file_name;
    AuditorResult::ResultType result_type;
  };

  CallSample test_cases[] = {
      {"good_call.txt", AuditorResult::ResultType::RESULT_OK},
      {"bad_call.txt", AuditorResult::ResultType::ERROR_FATAL},
  };

  for (const auto& test_case : test_cases) {
    // Check if deserialization result is as expected.
    CallInstance call;
    AuditorResult::ResultType result_type =
        Deserialize(test_case.file_name, &call);
    EXPECT_EQ(result_type, test_case.result_type);

    // Content checks for one complete sample.
    if (test_case.file_name != "good_call.txt")
      continue;

    EXPECT_EQ(call.file_path, "headless/public/util/http_url_fetcher.cc");
    EXPECT_EQ(call.line_number, 100u);
    EXPECT_EQ(call.function_context,
              "headless::HttpURLFetcher::Delegate::Delegate");
    EXPECT_EQ(call.function_name, "net::URLRequestContext::CreateRequest");
    EXPECT_EQ(call.is_annotated, true);
  }
}

// Tests if TrafficAnnotationAuditor::GetReservedUniqueIDs has all known ids and
// they have correct text.
TEST_F(TrafficAnnotationAuditorTest, GetReservedUniqueIDs) {
  int expected_ids[] = {
      TRAFFIC_ANNOTATION_FOR_TESTS.unique_id_hash_code,
      PARTIAL_TRAFFIC_ANNOTATION_FOR_TESTS.unique_id_hash_code,
      NO_TRAFFIC_ANNOTATION_YET.unique_id_hash_code,
      NO_PARTIAL_TRAFFIC_ANNOTATION_YET.unique_id_hash_code,
      MISSING_TRAFFIC_ANNOTATION.unique_id_hash_code};

  std::map<int, std::string> reserved_words =
      TrafficAnnotationAuditor::GetReservedUniqueIDs();

  for (int id : expected_ids) {
    EXPECT_TRUE(base::ContainsKey(reserved_words, id));
    EXPECT_EQ(id, TrafficAnnotationAuditor::ComputeHashValue(
                      reserved_words.find(id)->second));
  }
}

// Tests if TrafficAnnotationAuditor::CheckDuplicateHashes works as expected.
TEST_F(TrafficAnnotationAuditorTest, CheckDuplicateHashes) {
  // Load a valid annotation.
  std::unique_ptr<AnnotationInstance> instance =
      CreateAnnotationInstanceSample();
  EXPECT_TRUE(instance != nullptr);

  const std::map<int, std::string>& reserved_words =
      TrafficAnnotationAuditor::GetReservedUniqueIDs();

  TrafficAnnotationAuditor auditor(source_path(), build_path());
  std::vector<AnnotationInstance> annotations;

  // Check for reserved words hash code duplication errors.
  for (const auto& reserved_word : reserved_words) {
    instance->unique_id_hash_code = reserved_word.first;
    annotations.push_back(*instance);
  }

  auditor.SetExtractedAnnotationsForTest(annotations);
  auditor.CheckDuplicateHashes();
  EXPECT_EQ(auditor.errors().size(), reserved_words.size());
  for (const auto& error : auditor.errors()) {
    EXPECT_EQ(error.type(),
              AuditorResult::ResultType::ERROR_RESERVED_UNIQUE_ID_HASH_CODE);
  }

  // Check if several different hash codes result in no error.
  annotations.clear();
  for (int i = 0; i < 10; i++) {
    // Ensure that the test id is not a reserved hash code.
    EXPECT_FALSE(base::ContainsKey(reserved_words, i));
    instance->unique_id_hash_code = i;
    annotations.push_back(*instance);
  }
  auditor.SetExtractedAnnotationsForTest(annotations);
  auditor.ClearErrorsForTest();
  auditor.CheckDuplicateHashes();
  EXPECT_EQ(auditor.errors().size(), 0u);

  // Check if repeating the same hash codes results in errors.
  annotations.clear();
  for (int i = 0; i < 10; i++) {
    instance->unique_id_hash_code = i;
    annotations.push_back(*instance);
    annotations.push_back(*instance);
  }
  auditor.SetExtractedAnnotationsForTest(annotations);
  auditor.ClearErrorsForTest();
  auditor.CheckDuplicateHashes();
  EXPECT_EQ(auditor.errors().size(), 10u);
  for (const auto& error : auditor.errors()) {
    EXPECT_EQ(error.type(),
              AuditorResult::ResultType::ERROR_DUPLICATE_UNIQUE_ID_HASH_CODE);
  }
}

// Tests if TrafficAnnotationAuditor::CheckUniqueIDsFormat results are as
// expected.
TEST_F(TrafficAnnotationAuditorTest, CheckUniqueIDsFormat) {
  std::map<std::string, bool> test_cases = {
      {"ID1", true},   {"id2", true},   {"Id_3", true},
      {"ID?4", false}, {"ID:5", false}, {"ID>>6", false},
  };

  TrafficAnnotationAuditor auditor(source_path(), build_path());
  std::vector<AnnotationInstance> annotations;
  std::vector<AnnotationInstance> all_annotations;
  std::unique_ptr<AnnotationInstance> instance =
      CreateAnnotationInstanceSample();
  EXPECT_TRUE(instance != nullptr);
  unsigned int false_samples_count = 0;

  // Test cases one by one.
  for (const auto& test_case : test_cases) {
    instance->proto.set_unique_id(test_case.first);
    annotations.clear();
    annotations.push_back(*instance);
    all_annotations.push_back(*instance);
    auditor.SetExtractedAnnotationsForTest(annotations);
    auditor.ClearErrorsForTest();
    auditor.CheckUniqueIDsFormat();
    EXPECT_EQ(auditor.errors().size(), test_case.second ? 0u : 1u);
    if (!test_case.second)
      false_samples_count++;
  }

  // Test all cases together.
  auditor.SetExtractedAnnotationsForTest(all_annotations);
  auditor.ClearErrorsForTest();
  auditor.CheckUniqueIDsFormat();
  EXPECT_EQ(auditor.errors().size(), false_samples_count);
}

// Tests if TrafficAnnotationAuditor::CheckAllRequiredFunctionsAreAnnotated
// results are as expected. It also inherently checks
// TrafficAnnotationAuditor::CheckIfCallCanBeUnannotated.
TEST_F(TrafficAnnotationAuditorTest, CheckAllRequiredFunctionsAreAnnotated) {
  std::string file_paths[] = {"net/url_request/url_fetcher.cc",
                              "net/url_request/url_request_context.cc",
                              "net/url_request/other_file.cc",
                              "somewhere_else.cc"};
  std::string function_names[] = {"net::URLFetcher::Create",
                                  "net::URLRequestContext::CreateRequest",
                                  "SSLClientSocket", "Something else", ""};

  TrafficAnnotationAuditor auditor(source_path(), build_path());
  std::vector<CallInstance> calls(1);
  CallInstance& call = calls[0];

  for (const std::string& file_path : file_paths) {
    for (const std::string& function_name : function_names) {
      for (int annotated = 0; annotated < 2; annotated++) {
        for (int dependent = 0; dependent < 2; dependent++) {
          call.file_path = file_path;
          call.function_name = function_name;
          call.is_annotated = annotated;
          auditor.SetGnFileForTest(tests_folder().Append(
              dependent ? FILE_PATH_LITERAL("gn_list_positive.txt")
                        : FILE_PATH_LITERAL("gn_list_negative.txt")));

          auditor.ClearErrorsForTest();
          auditor.SetExtractedCallsForTest(calls);
          auditor.ClearCheckedDependenciesForTest();
          auditor.CheckAllRequiredFunctionsAreAnnotated();
          // Error should be issued if a function is not annotated,
          // chrome::chrome depends on it, the filepath is not whitelisted, and
          // function name is either of the two specified ones.
          EXPECT_EQ(
              auditor.errors().size() == 1,
              !annotated && dependent &&
                  file_path != "net/url_request/url_fetcher.cc" &&
                  file_path != "net/url_request/url_request_context.cc" &&
                  (function_name == "net::URLFetcher::Create" ||
                   function_name == "net::URLRequestContext::CreateRequest"))
              << "The conditions for generating an error for missing "
                 "annotation do not match the returned number of errors by "
                 "auditor.";
        }
      }
    }
  }
}