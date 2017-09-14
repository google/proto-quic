// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_TRAFFIC_ANNOTATION_AUDITOR_TRAFFIC_ANNOTATION_AUDITOR_H_
#define TOOLS_TRAFFIC_ANNOTATION_AUDITOR_TRAFFIC_ANNOTATION_AUDITOR_H_

#include <vector>

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "tools/traffic_annotation/auditor/auditor_result.h"
#include "tools/traffic_annotation/auditor/instance.h"
#include "tools/traffic_annotation/traffic_annotation.pb.h"

// Holds an item of safe list rules for auditor.
struct AuditorException {
  enum class ExceptionType {
    ALL,                // Ignore all errors (doesn't check the files at all).
    MISSING,            // Ignore missing annotations.
    DIRECT_ASSIGNMENT,  // Ignore direct assignment of annotation value.
    EXCEPTION_TYPE_LAST = DIRECT_ASSIGNMENT
  } type;

  static bool TypeFromString(const std::string& type_string,
                             ExceptionType* type_value) {
    if (type_string == "all") {
      *type_value = ExceptionType::ALL;
    } else if (type_string == "missing") {
      *type_value = ExceptionType::MISSING;
    } else if (type_string == "direct_assignment") {
      *type_value = ExceptionType::DIRECT_ASSIGNMENT;
    } else {
      return false;
    }
    return true;
  }
};


class TrafficAnnotationAuditor {
 public:
  // Creates an auditor object, storing the following paths:
  //   |source_path|: Path to the src directory.
  //   |build_path|: Path to a compiled build directory.
  //   |clang_tool_path|: Path to the 'traffic_annotation_extractor' clang tool.
  TrafficAnnotationAuditor(const base::FilePath& source_path,
                           const base::FilePath& build_path,
                           const base::FilePath& clang_tool_path);
  ~TrafficAnnotationAuditor();

  // Runs traffic_annotation_extractor clang tool and puts its output in
  // |clang_tool_raw_output_|.
  bool RunClangTool(const std::vector<std::string>& path_filters,
                    bool full_run);

  // Parses the output of clang tool (|clang_tool_raw_output_|) and populates
  // |extracted_annotations_|, |extracted_calls_|, and |errors_|.
  // Errors include not finding the file, incorrect content, or missing or not
  // provided annotations.
  bool ParseClangToolRawOutput();

  // Computes the hash value of a traffic annotation unique id.
  static int ComputeHashValue(const std::string& unique_id);

  // Loads the safe list file and populates |safe_list_|.
  bool LoadSafeList();

  // Checks to see if a |file_path| matches a safe list with given type.
  bool IsSafeListed(const std::string& file_path,
                    AuditorException::ExceptionType exception_type);

  // Checks to see if any unique id or extra id or their hash code are
  // duplicated, either in currently existing annotations, or in deprecated
  // ones. Adds errors to |errors_| and purges annotations with duplicate ids.
  // Returns false if any errors happen while checking.
  bool CheckDuplicateHashes();

  // Checks to see if unique ids only include alphanumeric characters and
  // underline. Adds errors to |errors_| and purges annotations with
  // incorrect ids.
  void CheckUniqueIDsFormat();

  // Checks to see if annotation contents are valid. Complete annotations should
  // have all required fields and be consistent, and incomplete annotations
  // should be completed with each other. Merges all matching incomplete
  // annotations and adds them to |extracted_annotations_|, adds errors
  // to |errors| and purges all incomplete annotations.
  void CheckAnnotationsContents();

  // Checks to see if all functions that need annotations have one.
  void CheckAllRequiredFunctionsAreAnnotated();

  // Checks if a call instance can stay not annotated.
  bool CheckIfCallCanBeUnannotated(const CallInstance& call);

  // Performs all checks on extracted annotations and calls.
  bool RunAllChecks();

  // Returns a mapping of reserved unique ids' hash codes to the unique ids'
  // texts. This list includes all unique ids that are defined in
  // net/traffic_annotation/network_traffic_annotation.h and
  // net/traffic_annotation/network_traffic_annotation_test_helper.h
  static const std::map<int, std::string>& GetReservedUniqueIDs();

  // Removes annotations whose unique id hash code are given.
  void PurgeAnnotations(const std::set<int>& hash_codes);

  std::string clang_tool_raw_output() const { return clang_tool_raw_output_; };

  void set_clang_tool_raw_output(const std::string& raw_output) {
    clang_tool_raw_output_ = raw_output;
  };

  const std::vector<AnnotationInstance>& extracted_annotations() const {
    return extracted_annotations_;
  }

  void SetExtractedAnnotationsForTesting(
      const std::vector<AnnotationInstance>& annotations) {
    extracted_annotations_ = annotations;
  }

  void SetExtractedCallsForTesting(const std::vector<CallInstance>& calls) {
    extracted_calls_ = calls;
  }

  const std::vector<CallInstance>& extracted_calls() const {
    return extracted_calls_;
  }

  const std::vector<AuditorResult>& errors() const { return errors_; }

  void ClearErrorsForTesting() { errors_.clear(); }

  void ClearCheckedDependenciesForTesting() { checked_dependencies_.clear(); }

  // Sets the path to a file that would be used to mock the output of
  // 'gn refs --all [build directory] [file path]' in tests.
  void SetGnFileForTesting(const base::FilePath& file_path) {
    gn_file_for_test_ = file_path;
  }

  // Returns the path to clang internal libraries.
  base::FilePath GetClangLibraryPath();

 private:
  const base::FilePath source_path_;
  const base::FilePath build_path_;
  const base::FilePath clang_tool_path_;

  std::string clang_tool_raw_output_;
  std::vector<AnnotationInstance> extracted_annotations_;
  std::vector<CallInstance> extracted_calls_;
  std::vector<AuditorResult> errors_;

  bool safe_list_loaded_;
  std::vector<std::string>
      safe_list_[static_cast<int>(
                     AuditorException::ExceptionType::EXCEPTION_TYPE_LAST) +
                 1];

  base::FilePath gn_file_for_test_;
  std::map<std::string, bool> checked_dependencies_;
};

#endif  // TOOLS_TRAFFIC_ANNOTATION_AUDITOR_TRAFFIC_ANNOTATION_AUDITOR_H_