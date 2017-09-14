// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_TRAFFIC_ANNOTATION_AUDITOR_INSTANCE_H_
#define TOOLS_TRAFFIC_ANNOTATION_AUDITOR_INSTANCE_H_

#include <vector>

#include "tools/traffic_annotation/auditor/auditor_result.h"
#include "tools/traffic_annotation/traffic_annotation.pb.h"

// Base class for Annotation and Call instances.
class InstanceBase {
 public:
  InstanceBase() {}
  virtual ~InstanceBase() {}
  virtual AuditorResult Deserialize(
      const std::vector<std::string>& serialized_lines,
      int start_line,
      int end_line) = 0;
};

// Holds an instance of network traffic annotation.
class AnnotationInstance : public InstanceBase {
 public:
  // Annotation Type.
  enum class Type {
    ANNOTATION_COMPLETE,
    ANNOTATION_PARTIAL,
    ANNOTATION_COMPLETING,
    ANNOTATION_BRANCHED_COMPLETING,
    ANNOTATION_INSTANCE_TYPE_LAST = ANNOTATION_BRANCHED_COMPLETING
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
  AuditorResult Deserialize(const std::vector<std::string>& serialized_lines,
                            int start_line,
                            int end_line) override;

  // Checks if an annotation has all required fields.
  AuditorResult IsComplete() const;

  // Checks if annotation fields are consistent.
  AuditorResult IsConsistent() const;

  // Checks to see if this annotation can be completed with the |other|
  // annotation, based on their unique ids, types, and extra ids. |*this| should
  // be of partial type and the |other| either COMPLETING or BRANCHED_COMPLETING
  // type.
  bool IsCompletableWith(const AnnotationInstance& other) const;

  // Combines |*this| partial annotation with a completing/branched_completing
  // annotation and returns the combined complete annotation.
  AuditorResult CreateCompleteAnnotation(
      AnnotationInstance& completing_annotation,
      AnnotationInstance* combination) const;

  // Protobuf of the annotation.
  traffic_annotation::NetworkTrafficAnnotation proto;

  // Type of the annotation.
  Type type;

  // Extra id of the annotation (if available).
  std::string extra_id;

  // Hash codes of unique id and extra id (if available).
  int unique_id_hash_code;
  int extra_id_hash_code;

  std::string comments;
};

// Holds an instance of calling a function that might have a network traffic
// annotation argument.
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
  AuditorResult Deserialize(const std::vector<std::string>& serialized_lines,
                            int start_line,
                            int end_line) override;

  std::string file_path;
  uint32_t line_number;

  // Name of the function in which the call happens.
  std::string function_context;

  // Name of the function that may need annotation.
  std::string function_name;

  // Is function |function_name| annotated?
  bool is_annotated;
};

// Holds an instance of initializing a traffic annotation tag with list
// expressions or assignment of a value to |unique_id_hash_code| of the mutable
// ones, outside traffic annotation API functions.
class AssignmentInstance : public InstanceBase {
 public:
  AssignmentInstance();
  AssignmentInstance(const AssignmentInstance& other);

  // Deserializes an instance from serialized lines of text provided by the
  // clang tool.
  // |serialized_lines| are read from |start_line| to |end_line| and should
  // contain the following lines:
  //   1- File path.
  //   2- Name of the function in which the assignment is made.
  //   3- Line number.
  AuditorResult Deserialize(const std::vector<std::string>& serialized_lines,
                            int start_line,
                            int end_line) override;

  std::string file_path;
  uint32_t line_number;

  // Name of the function in which assignment happens.
  std::string function_context;
};

#endif  // TOOLS_TRAFFIC_ANNOTATION_AUDITOR_INSTANCE_H_