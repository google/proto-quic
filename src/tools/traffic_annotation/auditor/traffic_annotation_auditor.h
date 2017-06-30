// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_TRAFFIC_ANNOTATION_AUDITOR_TRAFFIC_ANNOTATION_AUDITOR_H_
#define TOOLS_TRAFFIC_ANNOTATION_AUDITOR_TRAFFIC_ANNOTATION_AUDITOR_H_

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "tools/traffic_annotation/traffic_annotation.pb.h"

namespace traffic_annotation_auditor {

// Holds an instance of network traffic annotation.
// TODO(rhalavati): Check if this class can also be reused in clang tool.
class AnnotationInstance {
 public:
  // Annotation Type
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
  bool Deserialize(const std::vector<std::string>& serialized_lines,
                   int start_line,
                   int end_line,
                   std::string* error_text);

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
class CallInstance {
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
  bool Deserialize(const std::vector<std::string>& serialized_lines,
                   int start_line,
                   int end_line,
                   std::string* error_text);

  std::string file_path;
  uint32_t line_number;

  // Name of the function in which annotation is defined.
  std::string function_context;

  // Name of the function that may need annotation.
  std::string function_name;

  // Is function |function_name| annotated?
  bool is_annotated;
};

// Runs traffic_annotation_extractor clang tool and returns its output.
std::string RunClangTool(const base::FilePath& source_path,
                         const base::FilePath& build_path,
                         const base::CommandLine::StringVector& path_filters,
                         bool full_run);

// Parses the output of clang tool and populates instances, calls, and errors.
// Errors include not finding the file, incorrect content, or missing or not
// provided annotations.
bool ParseClangToolRawOutput(const std::string& clang_output,
                             std::vector<AnnotationInstance>* annotations,
                             std::vector<CallInstance>* calls,
                             std::vector<std::string>* errors);

// Computes the hash value of a traffic annotation unique id.
int ComputeHashValue(const std::string& unique_id);

}  // namespace traffic_annotation_auditor

#endif  // TOOLS_TRAFFIC_ANNOTATION_AUDITOR_TRAFFIC_ANNOTATION_AUDITOR_H_