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
#include "base/strings/stringprintf.h"
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
    auditor_ =
        base::MakeUnique<TrafficAnnotationAuditor>(source_path(), build_path());
  }

  const base::FilePath source_path() const { return source_path_; }
  const base::FilePath build_path() const { return build_path_; }
  const base::FilePath tests_folder() const { return tests_folder_; };
  TrafficAnnotationAuditor& auditor() { return *auditor_; }

 protected:
  // Deserializes an annotation or a call instance from a sample file similar to
  // clang tool outputs.
  AuditorResult::Type Deserialize(const std::string& file_name,
                                  InstanceBase* instance);

  // Creates a complete annotation instance using sample files.
  AnnotationInstance CreateAnnotationInstanceSample();

  void SetAnnotationForTesting(const AnnotationInstance& instance) {
    std::vector<AnnotationInstance> annotations;
    annotations.push_back(instance);
    auditor_->SetExtractedAnnotationsForTesting(annotations);
    auditor_->ClearErrorsForTesting();
  }

 private:
  base::FilePath source_path_;
  base::FilePath build_path_;  // Currently stays empty. Will be set if access
                               // to a compiled build directory would be
                               // granted.
  base::FilePath tests_folder_;
  std::unique_ptr<TrafficAnnotationAuditor> auditor_;
};

AuditorResult::Type TrafficAnnotationAuditorTest::Deserialize(
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

AnnotationInstance
TrafficAnnotationAuditorTest::CreateAnnotationInstanceSample() {
  AnnotationInstance instance;
  EXPECT_EQ(Deserialize("good_complete_annotation.txt", &instance),
            AuditorResult::Type::RESULT_OK);
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
  filter.SetGitFileForTesting(
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
  filter.SetGitFileForTesting(
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

// Tests if TrafficAnnotationFileFilter::IsSafeListed works as expected.
// Inherently checks if TrafficAnnotationFileFilter::LoadSafeList works and
// AuditorException rules are correctly deserialized.
TEST_F(TrafficAnnotationAuditorTest, IsSafeListed) {
  for (unsigned int i = 0;
       i < static_cast<unsigned int>(
               AuditorException::ExceptionType::EXCEPTION_TYPE_LAST);
       i++) {
    AuditorException::ExceptionType type =
        static_cast<AuditorException::ExceptionType>(i);
    // Anything in /tools directory is safelisted for all types.
    EXPECT_TRUE(auditor().IsSafeListed("tools/something.cc", type));
    EXPECT_TRUE(auditor().IsSafeListed("tools/somewhere/something.mm", type));

    // Anything in a general folder is not safelisted for any type
    EXPECT_FALSE(auditor().IsSafeListed("something.cc", type));
    EXPECT_FALSE(auditor().IsSafeListed("content/something.mm", type));
  }

  // Files defining missing annotation functions in net/ are exceptions of
  // 'missing' type.
  EXPECT_TRUE(auditor().IsSafeListed("net/url_request/url_fetcher.cc",
                                     AuditorException::ExceptionType::MISSING));
  EXPECT_TRUE(auditor().IsSafeListed("net/url_request/url_request_context.cc",
                                     AuditorException::ExceptionType::MISSING));
}

// Tests if annotation instances are corrrectly deserialized.
TEST_F(TrafficAnnotationAuditorTest, AnnotationDeserialization) {
  struct AnnotationSample {
    std::string file_name;
    AuditorResult::Type result_type;
    AnnotationInstance::Type type;
  };

  AnnotationSample test_cases[] = {
      {"good_complete_annotation.txt", AuditorResult::Type::RESULT_OK,
       AnnotationInstance::Type::ANNOTATION_COMPLETE},
      {"good_branched_completing_annotation.txt",
       AuditorResult::Type::RESULT_OK,
       AnnotationInstance::Type::ANNOTATION_BRANCHED_COMPLETING},
      {"good_completing_annotation.txt", AuditorResult::Type::RESULT_OK,
       AnnotationInstance::Type::ANNOTATION_COMPLETING},
      {"good_partial_annotation.txt", AuditorResult::Type::RESULT_OK,
       AnnotationInstance::Type::ANNOTATION_PARTIAL},
      {"good_test_annotation.txt", AuditorResult::Type::RESULT_IGNORE},
      {"missing_annotation.txt", AuditorResult::Type::ERROR_MISSING},
      {"no_annotation.txt", AuditorResult::Type::ERROR_NO_ANNOTATION},
      {"fatal_annotation1.txt", AuditorResult::Type::ERROR_FATAL},
      {"fatal_annotation2.txt", AuditorResult::Type::ERROR_FATAL},
      {"fatal_annotation3.txt", AuditorResult::Type::ERROR_FATAL},
      {"bad_syntax_annotation1.txt", AuditorResult::Type::ERROR_SYNTAX},
      {"bad_syntax_annotation2.txt", AuditorResult::Type::ERROR_SYNTAX},
      {"bad_syntax_annotation3.txt", AuditorResult::Type::ERROR_SYNTAX},
      {"bad_syntax_annotation4.txt", AuditorResult::Type::ERROR_SYNTAX},
  };

  for (const auto& test_case : test_cases) {
    // Check if deserialization result is as expected.
    AnnotationInstance annotation;
    AuditorResult::Type result_type =
        Deserialize(test_case.file_name, &annotation);
    EXPECT_EQ(result_type, test_case.result_type);

    if (result_type == AuditorResult::Type::RESULT_OK)
      EXPECT_EQ(annotation.type, test_case.type);

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
    EXPECT_EQ(annotation.proto.policy().cookies_allowed(), 1);
  }
}

// Tests if call instances are corrrectly deserialized.
TEST_F(TrafficAnnotationAuditorTest, CallDeserialization) {
  struct CallSample {
    std::string file_name;
    AuditorResult::Type result_type;
  };

  CallSample test_cases[] = {
      {"good_call.txt", AuditorResult::Type::RESULT_OK},
      {"bad_call.txt", AuditorResult::Type::ERROR_FATAL},
  };

  for (const auto& test_case : test_cases) {
    // Check if deserialization result is as expected.
    CallInstance call;
    AuditorResult::Type result_type = Deserialize(test_case.file_name, &call);
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
  AnnotationInstance instance = CreateAnnotationInstanceSample();

  const std::map<int, std::string>& reserved_words =
      TrafficAnnotationAuditor::GetReservedUniqueIDs();

  std::vector<AnnotationInstance> annotations;

  // Check for reserved words hash code duplication errors.
  int next_id = 0;
  for (const auto& reserved_word : reserved_words) {
    EXPECT_FALSE(base::ContainsKey(reserved_words, next_id));
    instance.unique_id_hash_code = next_id;
    instance.extra_id_hash_code = reserved_word.first;
    instance.extra_id = "SomeID";
    annotations.push_back(instance);
    next_id++;

    EXPECT_FALSE(base::ContainsKey(reserved_words, next_id));
    instance.unique_id_hash_code = reserved_word.first;
    instance.extra_id_hash_code = next_id;
    instance.extra_id.clear();
    annotations.push_back(instance);
    next_id++;
  }

  auditor().SetExtractedAnnotationsForTesting(annotations);
  auditor().ClearErrorsForTesting();
  auditor().CheckDuplicateHashes();
  EXPECT_EQ(auditor().errors().size(), annotations.size());
  for (const auto& error : auditor().errors()) {
    EXPECT_EQ(error.type(),
              AuditorResult::Type::ERROR_RESERVED_UNIQUE_ID_HASH_CODE);
  }

  // Check if several different hash codes result in no error.
  annotations.clear();
  instance.extra_id_hash_code = 0;
  instance.extra_id.clear();
  for (int i = 0; i < 10; i++) {
    // Ensure that the test id is not a reserved hash code.
    EXPECT_FALSE(base::ContainsKey(reserved_words, i));
    instance.unique_id_hash_code = i;
    annotations.push_back(instance);
  }
  auditor().SetExtractedAnnotationsForTesting(annotations);
  auditor().ClearErrorsForTesting();
  auditor().CheckDuplicateHashes();
  EXPECT_EQ(auditor().errors().size(), 0u);

  // Check if repeating the same hash codes results in errors.
  annotations.clear();
  for (int i = 0; i < 10; i++) {
    instance.unique_id_hash_code = i;
    annotations.push_back(instance);
    annotations.push_back(instance);
  }
  auditor().SetExtractedAnnotationsForTesting(annotations);
  auditor().ClearErrorsForTesting();
  auditor().CheckDuplicateHashes();
  EXPECT_EQ(auditor().errors().size(), 10u);
  for (const auto& error : auditor().errors()) {
    EXPECT_EQ(error.type(),
              AuditorResult::Type::ERROR_DUPLICATE_UNIQUE_ID_HASH_CODE);
  }

  // Check if the same value for unique id and extra id only results in error in
  // types with valid extra id.
  instance.unique_id_hash_code = 1;
  instance.extra_id_hash_code = 1;
  const int last_type =
      static_cast<int>(AnnotationInstance::Type::ANNOTATION_INSTANCE_TYPE_LAST);
  for (int type = 0; type <= last_type; type++) {
    instance.type = static_cast<AnnotationInstance::Type>(type);
    SetAnnotationForTesting(instance);
    auditor().CheckDuplicateHashes();
    SCOPED_TRACE(type);
    if (instance.type == AnnotationInstance::Type::ANNOTATION_COMPLETE ||
        instance.type == AnnotationInstance::Type::ANNOTATION_COMPLETING) {
      // Extra id of these two types is not used.
      EXPECT_EQ(auditor().errors().size(), 0u);
    } else {
      EXPECT_EQ(auditor().errors().size(), 1u);
    }
  }

  // Check for unique id / extra id collision cases.
  AnnotationInstance other = instance;
  for (int type1 = 0; type1 < last_type; type1++) {
    for (int type2 = type1; type2 <= last_type; type2++) {
      // Iterate different possiblities of common id.
      for (int common1 = 0; common1 < 2; common1++) {
        for (int common2 = 0; common2 < 2; common2++) {
          instance.type = static_cast<AnnotationInstance::Type>(type1);
          other.type = static_cast<AnnotationInstance::Type>(type2);
          instance.unique_id_hash_code = common1 ? 1 : 2;
          instance.extra_id_hash_code = common1 ? 2 : 1;
          other.unique_id_hash_code = common2 ? 2 : 3;
          other.extra_id_hash_code = common2 ? 3 : 2;

          annotations.clear();
          annotations.push_back(instance);
          annotations.push_back(other);
          auditor().SetExtractedAnnotationsForTesting(annotations);
          auditor().ClearErrorsForTesting();
          auditor().CheckDuplicateHashes();

          bool acceptable = false;
          switch (instance.type) {
            case AnnotationInstance::Type::ANNOTATION_COMPLETE:
              // The unique id of a complete annotation must not be reused.
              acceptable =
                  (instance.unique_id_hash_code != other.unique_id_hash_code &&
                   instance.unique_id_hash_code != other.extra_id_hash_code);
              break;

            case AnnotationInstance::Type::ANNOTATION_PARTIAL:
              // The unique id of a partial annotation should be unique.
              // It's extra id can be used as unique id of a completing
              // annotation or extra id of a branched completing one.
              if (instance.unique_id_hash_code != other.unique_id_hash_code &&
                  instance.unique_id_hash_code != other.extra_id_hash_code) {
                if (instance.extra_id_hash_code == other.unique_id_hash_code) {
                  acceptable =
                      (other.type ==
                       AnnotationInstance::Type::ANNOTATION_COMPLETING);
                } else if (instance.extra_id_hash_code ==
                           other.extra_id_hash_code) {
                  acceptable =
                      (other.type == AnnotationInstance::Type::
                                         ANNOTATION_BRANCHED_COMPLETING);
                } else {
                  acceptable = true;
                }
              }
              break;

            case AnnotationInstance::Type::ANNOTATION_COMPLETING:
            case AnnotationInstance::Type::ANNOTATION_INSTANCE_TYPE_LAST:
              // Considering the other annotation has a higher type number,
              // unique id of a completing or branched completing annotation
              // should not be used as unique or extra id of another one.
              acceptable =
                  (instance.unique_id_hash_code != other.unique_id_hash_code &&
                   instance.unique_id_hash_code != other.extra_id_hash_code);
              break;

            default:
              NOTREACHED();
          }
        }
      }
    }
  }
}

// Tests if TrafficAnnotationAuditor::CheckUniqueIDsFormat results are as
// expected.
TEST_F(TrafficAnnotationAuditorTest, CheckUniqueIDsFormat) {
  std::map<std::string, bool> test_cases = {
      {"ID1", true},   {"id2", true},   {"Id_3", true},
      {"ID?4", false}, {"ID:5", false}, {"ID>>6", false},
  };

  std::vector<AnnotationInstance> annotations;
  AnnotationInstance instance = CreateAnnotationInstanceSample();
  unsigned int false_samples_count = 0;

  // Test cases one by one.
  for (const auto& test_case : test_cases) {
    instance.type = AnnotationInstance::Type::ANNOTATION_COMPLETE;
    instance.proto.set_unique_id(test_case.first);
    instance.extra_id.clear();
    SetAnnotationForTesting(instance);
    annotations.push_back(instance);
    auditor().CheckUniqueIDsFormat();
    EXPECT_EQ(auditor().errors().size(), test_case.second ? 0u : 1u);
    if (!test_case.second)
      false_samples_count++;

    instance.type = AnnotationInstance::Type::ANNOTATION_COMPLETING;
    instance.proto.set_unique_id("Something_Good");
    instance.extra_id = test_case.first;
    SetAnnotationForTesting(instance);
    annotations.push_back(instance);
    auditor().CheckUniqueIDsFormat();
    EXPECT_EQ(auditor().errors().size(), test_case.second ? 0u : 1u);
    if (!test_case.second)
      false_samples_count++;
  }

  // Test all cases together.
  auditor().SetExtractedAnnotationsForTesting(annotations);
  auditor().ClearErrorsForTesting();
  auditor().CheckUniqueIDsFormat();
  EXPECT_EQ(auditor().errors().size(), false_samples_count);
}

// Tests if TrafficAnnotationAuditor::CheckAllRequiredFunctionsAreAnnotated
// results are as expected. It also inherently checks
// TrafficAnnotationAuditor::CheckIfCallCanBeUnannotated.
TEST_F(TrafficAnnotationAuditorTest, CheckAllRequiredFunctionsAreAnnotated) {
  std::string file_paths[] = {"net/url_request/url_fetcher.cc",
                              "net/url_request/url_request_context.cc",
                              "net/url_request/other_file.cc",
                              "somewhere_else.cc", "something_unittest.cc"};
  std::string function_names[] = {"net::URLFetcher::Create",
                                  "net::URLRequestContext::CreateRequest",
                                  "SSLClientSocket", "Something else", ""};

  std::vector<CallInstance> calls(1);
  CallInstance& call = calls[0];

  for (const std::string& file_path : file_paths) {
    for (const std::string& function_name : function_names) {
      for (int annotated = 0; annotated < 2; annotated++) {
        for (int dependent = 0; dependent < 2; dependent++) {
          SCOPED_TRACE(
              base::StringPrintf("Testing (%s, %s, %i, %i).", file_path.c_str(),
                                 function_name.c_str(), annotated, dependent));
          call.file_path = file_path;
          call.function_name = function_name;
          call.is_annotated = annotated;
          auditor().SetGnFileForTesting(tests_folder().Append(
              dependent ? FILE_PATH_LITERAL("gn_list_positive.txt")
                        : FILE_PATH_LITERAL("gn_list_negative.txt")));

          auditor().ClearErrorsForTesting();
          auditor().SetExtractedCallsForTesting(calls);
          auditor().ClearCheckedDependenciesForTesting();
          auditor().CheckAllRequiredFunctionsAreAnnotated();
          // Error should be issued if all the following is met:
          //   1- Function is not annotated.
          //   2- It's a unittest or chrome::chrome depends on it.
          //   3- The filepath is not safelisted.
          //   4- Function name is either of the two specified ones.
          bool is_unittest = file_path.find("unittest") != std::string::npos;
          bool is_safelist =
              file_path == "net/url_request/url_fetcher.cc" ||
              file_path == "net/url_request/url_request_context.cc";
          bool monitored_function =
              function_name == "net::URLFetcher::Create" ||
              function_name == "net::URLRequestContext::CreateRequest";
          EXPECT_EQ(auditor().errors().size() == 1,
                    !annotated && (dependent || is_unittest) && !is_safelist &&
                        monitored_function)
              << base::StringPrintf(
                     "Annotated:%i, Depending:%i, IsUnitTest:%i, "
                     "IsSafeListed:%i, MonitoredFunction:%i",
                     annotated, dependent, is_unittest, is_safelist,
                     monitored_function);
        }
      }
    }
  }
}

// Tests if TrafficAnnotationAuditor::CheckAnnotationsContents works as
// expected for COMPLETE annotations. It also inherently checks
// TrafficAnnotationAuditor::IsAnnotationComplete and
// TrafficAnnotationAuditor::IsAnnotationConsistent.
TEST_F(TrafficAnnotationAuditorTest, CheckCompleteAnnotations) {
  AnnotationInstance instance = CreateAnnotationInstanceSample();
  std::vector<AnnotationInstance> annotations;
  unsigned int expected_errors_count = 0;

  for (int test_no = 0;; test_no++) {
    AnnotationInstance test_case = instance;
    bool expect_error = true;
    std::string test_description;
    test_case.unique_id_hash_code = test_no;
    switch (test_no) {
      case 0:
        test_description = "All fields OK.";
        expect_error = false;
        break;
      case 1:
        test_description = "Missing semantics::sender.";
        test_case.proto.mutable_semantics()->clear_sender();
        break;
      case 2:
        test_description = "Missing semantics::description.";
        test_case.proto.mutable_semantics()->clear_description();
        break;
      case 3:
        test_description = "Missing semantics::trigger.";
        test_case.proto.mutable_semantics()->clear_trigger();
        break;
      case 4:
        test_description = "Missing semantics::data.";
        test_case.proto.mutable_semantics()->clear_data();
        break;
      case 5:
        test_description = "Missing semantics::destination.";
        test_case.proto.mutable_semantics()->clear_destination();
        break;
      case 6:
        test_description = "Missing policy::cookies_allowed.";
        test_case.proto.mutable_policy()->set_cookies_allowed(
            traffic_annotation::
                NetworkTrafficAnnotation_TrafficPolicy_CookiesAllowed_UNSPECIFIED);
        break;
      case 7:
        test_description =
            "policy::cookies_allowed = NO with existing policy::cookies_store.";
        test_case.proto.mutable_policy()->set_cookies_allowed(
            traffic_annotation::
                NetworkTrafficAnnotation_TrafficPolicy_CookiesAllowed_NO);
        test_case.proto.mutable_policy()->set_cookies_store("somewhere");
        break;
      case 8:
        test_description =
            "policy::cookies_allowed = NO and no policy::cookies_store.";
        test_case.proto.mutable_policy()->set_cookies_allowed(
            traffic_annotation::
                NetworkTrafficAnnotation_TrafficPolicy_CookiesAllowed_NO);
        test_case.proto.mutable_policy()->clear_cookies_store();
        expect_error = false;
        break;
      case 9:
        test_description =
            "policy::cookies_allowed = YES and policy::cookies_store exists.";
        test_case.proto.mutable_policy()->set_cookies_allowed(
            traffic_annotation::
                NetworkTrafficAnnotation_TrafficPolicy_CookiesAllowed_YES);
        test_case.proto.mutable_policy()->set_cookies_store("somewhere");
        expect_error = false;
        break;
      case 10:
        test_description =
            "policy::cookies_allowed = YES and no policy::cookies_store.";
        test_case.proto.mutable_policy()->set_cookies_allowed(
            traffic_annotation::
                NetworkTrafficAnnotation_TrafficPolicy_CookiesAllowed_YES);
        test_case.proto.mutable_policy()->clear_cookies_store();
        break;
      case 11:
        test_description = "Missing policy::settings.";
        test_case.proto.mutable_policy()->clear_setting();
        break;
      case 12:
        test_description =
            "Missing policy::chrome_policy and "
            "policy::policy_exception_justification.";
        test_case.proto.mutable_policy()->clear_chrome_policy();
        test_case.proto.mutable_policy()
            ->clear_policy_exception_justification();
        break;
      case 13:
        test_description =
            "Missing policy::chrome_policy and existing "
            "policy::policy_exception_justification.";
        test_case.proto.mutable_policy()->clear_chrome_policy();
        test_case.proto.mutable_policy()->set_policy_exception_justification(
            "Because!");
        expect_error = false;
        break;
      case 14:
        test_description =
            "Existing policy::chrome_policy and no "
            "policy::policy_exception_justification.";
        test_case.proto.mutable_policy()->add_chrome_policy();
        test_case.proto.mutable_policy()
            ->clear_policy_exception_justification();
        expect_error = false;
        break;
      case 15:
        test_description =
            "Existing policy::chrome_policy and existing"
            "policy::policy_exception_justification.";
        test_case.proto.mutable_policy()->add_chrome_policy();
        test_case.proto.mutable_policy()->set_policy_exception_justification(
            "Because!");
        break;

      default:
        // Trigger stop.
        test_no = -1;
        break;
    }
    if (test_no < 0)
      break;
    SCOPED_TRACE(base::StringPrintf("Testing: %s", test_description.c_str()));
    SetAnnotationForTesting(test_case);
    auditor().CheckAnnotationsContents();

    EXPECT_EQ(auditor().errors().size(), expect_error ? 1u : 0u);
    annotations.push_back(test_case);
    if (expect_error)
      expected_errors_count++;
  }

  // Check All.
  unsigned int tests_count = annotations.size();
  auditor().SetExtractedAnnotationsForTesting(annotations);
  auditor().ClearErrorsForTesting();
  auditor().CheckAnnotationsContents();
  EXPECT_EQ(auditor().errors().size(), expected_errors_count);
  // All annotations with errors should be purged.
  EXPECT_EQ(auditor().extracted_annotations().size(),
            tests_count - expected_errors_count);
}

// Tests if AnnotationInstance::IsCompletableWith works as expected.
TEST_F(TrafficAnnotationAuditorTest, IsCompletableWith) {
  AnnotationInstance instance = CreateAnnotationInstanceSample();
  AnnotationInstance other = instance;

  const int last_type =
      static_cast<int>(AnnotationInstance::Type::ANNOTATION_INSTANCE_TYPE_LAST);
  for (int type1 = 0; type1 < last_type; type1++) {
    for (int type2 = 0; type2 <= last_type; type2++) {
      // Iterate all combination of common/specified ids.
      for (int ids = 0; ids < 256; ids++) {
        instance.type = static_cast<AnnotationInstance::Type>(type1);
        other.type = static_cast<AnnotationInstance::Type>(type2);
        instance.unique_id_hash_code = ids % 4;
        instance.extra_id_hash_code = (ids >> 2) % 4;
        other.unique_id_hash_code = (ids >> 4) % 4;
        other.extra_id_hash_code = (ids >> 6);
        instance.extra_id =
            instance.extra_id_hash_code ? "SomeID" : std::string();
        other.extra_id = other.extra_id_hash_code ? "SomeID" : std::string();

        bool expectation = false;
        // It's compatible only if the first one is partial and has extra_id,
        // and the second one is either completing with matching unique id, or
        // branched completing with matching extra id.
        if (instance.type == AnnotationInstance::Type::ANNOTATION_PARTIAL &&
            !instance.extra_id.empty()) {
          expectation |=
              (other.type == AnnotationInstance::Type::ANNOTATION_COMPLETING &&
               instance.extra_id_hash_code == other.unique_id_hash_code);
          expectation |=
              (other.type ==
                   AnnotationInstance::Type::ANNOTATION_BRANCHED_COMPLETING &&
               instance.extra_id_hash_code == other.extra_id_hash_code);
        }
        EXPECT_EQ(instance.IsCompletableWith(other), expectation);
      }
    }
  }
}

// Tests if AnnotationInstance::CreateCompleteAnnotation works as
// expected.
TEST_F(TrafficAnnotationAuditorTest, CreateCompleteAnnotation) {
  AnnotationInstance instance = CreateAnnotationInstanceSample();
  AnnotationInstance other = instance;

  instance.proto.clear_semantics();
  other.proto.clear_policy();

  AnnotationInstance combination;

  // Partial and Completing.
  instance.type = AnnotationInstance::Type::ANNOTATION_PARTIAL;
  other.type = AnnotationInstance::Type::ANNOTATION_COMPLETING;
  instance.extra_id_hash_code = 1;
  instance.extra_id = "SomeID";
  other.unique_id_hash_code = 1;
  EXPECT_EQ(instance.CreateCompleteAnnotation(other, &combination).type(),
            AuditorResult::Type::RESULT_OK);
  EXPECT_EQ(combination.unique_id_hash_code, instance.unique_id_hash_code);

  // Partial and Branched Completing.
  other.type = AnnotationInstance::Type::ANNOTATION_BRANCHED_COMPLETING;
  instance.extra_id_hash_code = 1;
  other.extra_id_hash_code = 1;
  other.extra_id = "SomeID";
  EXPECT_EQ(instance.CreateCompleteAnnotation(other, &combination).type(),
            AuditorResult::Type::RESULT_OK);
  EXPECT_EQ(combination.unique_id_hash_code, other.unique_id_hash_code);

  // Inconsistent field.
  other = instance;
  other.type = AnnotationInstance::Type::ANNOTATION_BRANCHED_COMPLETING;
  instance.extra_id_hash_code = 1;
  other.extra_id_hash_code = 1;
  other.extra_id = "SomeID";
  instance.proto.mutable_semantics()->set_destination(
      traffic_annotation::
          NetworkTrafficAnnotation_TrafficSemantics_Destination_WEBSITE);
  other.proto.mutable_semantics()->set_destination(
      traffic_annotation::
          NetworkTrafficAnnotation_TrafficSemantics_Destination_LOCAL);
  EXPECT_NE(instance.CreateCompleteAnnotation(other, &combination).type(),
            AuditorResult::Type::RESULT_OK);
}