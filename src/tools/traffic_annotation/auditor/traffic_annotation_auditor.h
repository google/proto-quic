// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_TRAFFIC_ANNOTATION_AUDITOR_TRAFFIC_ANNOTATION_AUDITOR_H_
#define TOOLS_TRAFFIC_ANNOTATION_AUDITOR_TRAFFIC_ANNOTATION_AUDITOR_H_

#include <vector>

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "tools/traffic_annotation/traffic_annotation.pb.h"

// Holds an item of whitelist exception rule for auditor.
struct AuditorException {
  enum class ExceptionType {
    ALL,            // Ignore all errors (doesn't check the files at all).
    MISSING,        // Ignore missing annotations.
    EMPTY_MUTABLE,  // Ignore empty mutable annotation constructor.
    EXCEPTION_TYPE_LAST = EMPTY_MUTABLE
  } type;
  std::string partial_path;

  static bool TypeFromString(const std::string& type_string,
                             ExceptionType* type_value) {
    if (type_string == "all") {
      *type_value = ExceptionType::ALL;
    } else if (type_string == "missing") {
      *type_value = ExceptionType::MISSING;
    } else if (type_string == "empty_mutable") {
      *type_value = ExceptionType::EMPTY_MUTABLE;
    } else {
      return false;
    }
    return true;
  }
};

// Holds the auditor processing results on one unit of annotation or function.
class AuditorResult {
 public:
  enum class ResultType {
    RESULT_OK,            // No error
    RESULT_IGNORE,        // The item does not require furthure processing.
    ERROR_FATAL,          // A fatal error that should stop process.
    ERROR_MISSING,        // A function is called without annotation.
    ERROR_NO_ANNOTATION,  // A function is called with NO_ANNOTATION tag.
    ERROR_SYNTAX,         // Annotation syntax is not right.
    ERROR_RESERVED_UNIQUE_ID_HASH_CODE,   // A unique id has a hash code similar
                                          // to a reserved word.
    ERROR_DUPLICATE_UNIQUE_ID_HASH_CODE,  // Two unique ids have similar hash
                                          // codes.
    ERROR_UNIQUE_ID_INVALID_CHARACTER,    // A unique id contanins a characer
                                          // which is not alphanumeric or
                                          // underline.
    ERROR_MISSING_ANNOTATION  // A function that requires annotation is not
                              // annotated.
  };

  static const int kNoCodeLineSpecified;

  AuditorResult(ResultType type,
                const std::string& message,
                const std::string& file_path,
                int line);

  AuditorResult(ResultType type, const std::string& message);

  AuditorResult(ResultType type);

  ~AuditorResult();

  AuditorResult(const AuditorResult& other);

  void AddDetail(const std::string& message);

  ResultType type() const { return type_; };

  std::string file_path() const { return file_path_; }

  // Formats the error message into one line of text.
  std::string ToText() const;

 private:
  ResultType type_;
  std::vector<std::string> details_;
  std::string file_path_;
  int line_;
};

// Base class for Annotation and Call instances.
class InstanceBase {
 public:
  InstanceBase(){};
  virtual ~InstanceBase(){};
  virtual AuditorResult Deserialize(
      const std::vector<std::string>& serialized_lines,
      int start_line,
      int end_line) = 0;
};

// Holds an instance of network traffic annotation.
// TODO(rhalavati): Check if this class can also be reused in clang tool.
class AnnotationInstance : public InstanceBase {
 public:
  // Annotation Type.
  enum class AnnotationType {
    ANNOTATION_COMPLETE,
    ANNOTATION_PARTIAL,
    ANNOTATION_COMPLETENG,
    ANNOTATION_BRANCHED_COMPLETING
  };

  AnnotationInstance();
  AnnotationInstance(const AnnotationInstance& other);

  // Deserializes an instance from serialized lines of the text provided by the
  // clang tool.
  // |serialized_lines| are read from |start_line| to |end_line| and should
  // contain the following lines:
  //   1- File path.
  //   2- Name of the function including this annotation.
  //   3- Line number.
  //   4- Annotation function Type.
  //   5- Unique id of annotation.
  //   6- Completing id or group id, when applicable, empty otherwise.
  //   7- Serialization of annotation text (several lines).
  // If the annotation is correctly read and should be stored (is not test,
  // not available, or missing), returns true, otherwise false.
  // If any error happens, |error_text| will be set. If it would be set to
  // FATAL, furthur processing of the text should be stopped.
  AuditorResult Deserialize(const std::vector<std::string>& serialized_lines,
                            int start_line,
                            int end_line) override;

  // Protobuf of the annotation.
  traffic_annotation::NetworkTrafficAnnotation proto;

  // Type of the annotation.
  AnnotationType annotation_type;

  // Extra id of the annotation (if available).
  std::string extra_id;

  // Hash codes of unique id and extra id (if available).
  int unique_id_hash_code;
  int extra_id_hash_code;
};

// Holds an instance of calling a function that might have a network traffic
// annotation argument.
// TODO(rhalavati): Check if this class can also be reused in clang tool.
class CallInstance : public InstanceBase {
 public:
  CallInstance();
  CallInstance(const CallInstance& other);

  // Deserializes an instance from serialized lines of text provided by the
  // clang tool.
  // |serialized_lines| are read from |start_line| to |end_line| and should
  // contain the following lines:
  //   1- File path.
  //   2- Name of the function in which the call is made.
  //   3- Name of the called function.
  //   4- Does the call have an annotation?
  // If the call instance is correctly read returns true, otherwise false.
  // If any error happens, |error_text| will be set. If it would be set to
  // FATAL, further processing of the text should be stopped.
  AuditorResult Deserialize(const std::vector<std::string>& serialized_lines,
                            int start_line,
                            int end_line) override;

  std::string file_path;
  uint32_t line_number;

  // Name of the function in which annotation is defined.
  std::string function_context;

  // Name of the function that may need annotation.
  std::string function_name;

  // Is function |function_name| annotated?
  bool is_annotated;
};

class TrafficAnnotationAuditor {
 public:
  TrafficAnnotationAuditor(const base::FilePath& source_path,
                           const base::FilePath& build_path);
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

  // Loads the whitelist file and populates |ignore_list_|.
  bool LoadWhiteList();

  // Checks to see if a |file_path| matches a whitelist with given type.
  bool IsWhitelisted(const std::string& file_path,
                     AuditorException::ExceptionType whitelist_type);

  // Checks to see if any unique id or its hash code is duplicated.
  void CheckDuplicateHashes();

  // Checks to see if unique ids only include alphanumeric characters and
  // underline.
  void CheckUniqueIDsFormat();

  // Checks to see if all functions that need annotations have one.
  void CheckAllRequiredFunctionsAreAnnotated();

  // Checks if a call instance can stay not annotated.
  bool CheckIfCallCanBeUnannotated(const CallInstance& call);

  // Preforms all checks on extracted annotations and calls, and adds the
  // results to |errors_|.
  void RunAllChecks();

  // Returns a mapping of reserved unique ids' hash codes to the unique ids'
  // texts. This list includes all unique ids that are defined in
  // net/traffic_annotation/network_traffic_annotation.h and
  // net/traffic_annotation/network_traffic_annotation_test_helper.h
  static const std::map<int, std::string>& GetReservedUniqueIDs();

  std::string clang_tool_raw_output() const { return clang_tool_raw_output_; };

  void set_clang_tool_raw_output(const std::string& raw_output) {
    clang_tool_raw_output_ = raw_output;
  };

  const std::vector<AnnotationInstance>& extracted_annotations() const {
    return extracted_annotations_;
  }

  void SetExtractedAnnotationsForTest(
      const std::vector<AnnotationInstance>& annotations) {
    extracted_annotations_ = annotations;
  }

  void SetExtractedCallsForTest(const std::vector<CallInstance>& calls) {
    extracted_calls_ = calls;
  }

  const std::vector<CallInstance>& extracted_calls() const {
    return extracted_calls_;
  }

  const std::vector<AuditorResult>& errors() const { return errors_; }

  void ClearErrorsForTest() { errors_.clear(); }

  void ClearCheckedDependenciesForTest() { checked_dependencies_.clear(); }

  // Sets the path to a file that would be used to mock the output of
  // 'gn refs --all [build directory] [file path]' in tests.
  void SetGnFileForTest(const base::FilePath& file_path) {
    gn_file_for_test_ = file_path;
  }

 private:
  const base::FilePath source_path_;
  const base::FilePath build_path_;

  std::string clang_tool_raw_output_;
  std::vector<AnnotationInstance> extracted_annotations_;
  std::vector<CallInstance> extracted_calls_;
  std::vector<AuditorResult> errors_;

  std::vector<std::string> ignore_list_[static_cast<int>(
      AuditorException::ExceptionType::EXCEPTION_TYPE_LAST)];

  base::FilePath gn_file_for_test_;
  std::map<std::string, bool> checked_dependencies_;
};

#endif  // TOOLS_TRAFFIC_ANNOTATION_AUDITOR_TRAFFIC_ANNOTATION_AUDITOR_H_