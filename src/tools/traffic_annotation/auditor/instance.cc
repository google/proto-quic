// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/traffic_annotation/auditor/instance.h"

#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "third_party/protobuf/src/google/protobuf/io/tokenizer.h"
#include "third_party/protobuf/src/google/protobuf/text_format.h"
#include "tools/traffic_annotation/auditor/traffic_annotation_auditor.h"

namespace {

// This class receives parsing errors from google::protobuf::TextFormat::Parser
// which is used during protobuf deserialization.
class SimpleErrorCollector : public google::protobuf::io::ErrorCollector {
 public:
  SimpleErrorCollector(int proto_starting_line)
      : google::protobuf::io::ErrorCollector(),
        line_offset_(proto_starting_line) {}

  ~SimpleErrorCollector() override {}

  void AddError(int line,
                google::protobuf::io::ColumnNumber column,
                const std::string& message) override {
    AddMessage(line, column, message);
  }

  void AddWarning(int line,
                  google::protobuf::io::ColumnNumber column,
                  const std::string& message) override {
    AddMessage(line, column, message);
  }

  std::string GetMessage() { return message_; }

 private:
  void AddMessage(int line,
                  google::protobuf::io::ColumnNumber column,
                  const std::string& message) {
    message_ += base::StringPrintf(
        "%sLine %i, column %i, %s", message_.length() ? " " : "",
        line_offset_ + line, static_cast<int>(column), message.c_str());
  }

  std::string message_;
  int line_offset_;
};

// This macro merges the content of one string field from two annotations.
// DST->FLD is the destination field, and SRD->FLD is the source field.
#define MERGE_STRING_FIELDS(SRC, DST, FLD)                           \
  if (!SRC.FLD().empty()) {                                          \
    if (!DST->FLD().empty()) {                                       \
      DST->set_##FLD(base::StringPrintf("%s\n%s", SRC.FLD().c_str(), \
                                        DST->FLD().c_str()));        \
    } else {                                                         \
      DST->set_##FLD(SRC.FLD());                                     \
    }                                                                \
  }

}  // namespace

AnnotationInstance::AnnotationInstance() : type(Type::ANNOTATION_COMPLETE) {}

AnnotationInstance::AnnotationInstance(const AnnotationInstance& other)
    : proto(other.proto),
      type(other.type),
      extra_id(other.extra_id),
      unique_id_hash_code(other.unique_id_hash_code),
      extra_id_hash_code(other.extra_id_hash_code){};

AuditorResult AnnotationInstance::Deserialize(
    const std::vector<std::string>& serialized_lines,
    int start_line,
    int end_line) {
  if (end_line - start_line < 7) {
    return AuditorResult(AuditorResult::Type::ERROR_FATAL,
                         "Not enough lines to deserialize annotation.");
  }

  // Extract header lines.
  const std::string& file_path = serialized_lines[start_line++];
  const std::string& function_context = serialized_lines[start_line++];
  int line_number;
  base::StringToInt(serialized_lines[start_line++], &line_number);
  std::string function_type = serialized_lines[start_line++];
  const std::string& unique_id = serialized_lines[start_line++];
  extra_id = serialized_lines[start_line++];

  // Decode function type.
  if (function_type == "Definition") {
    type = Type::ANNOTATION_COMPLETE;
  } else if (function_type == "Partial") {
    type = Type::ANNOTATION_PARTIAL;
  } else if (function_type == "Completing") {
    type = Type::ANNOTATION_COMPLETING;
  } else if (function_type == "BranchedCompleting") {
    type = Type::ANNOTATION_BRANCHED_COMPLETING;
  } else {
    return AuditorResult(AuditorResult::Type::ERROR_FATAL,
                         base::StringPrintf("Unexpected function type: %s",
                                            function_type.c_str()));
  }

  // Process test tags.
  unique_id_hash_code = TrafficAnnotationAuditor::ComputeHashValue(unique_id);
  if (unique_id_hash_code == TRAFFIC_ANNOTATION_FOR_TESTS.unique_id_hash_code ||
      unique_id_hash_code ==
          PARTIAL_TRAFFIC_ANNOTATION_FOR_TESTS.unique_id_hash_code) {
    return AuditorResult(AuditorResult::Type::RESULT_IGNORE);
  }

  // Process undefined tags.
  if (unique_id_hash_code == NO_TRAFFIC_ANNOTATION_YET.unique_id_hash_code ||
      unique_id_hash_code ==
          NO_PARTIAL_TRAFFIC_ANNOTATION_YET.unique_id_hash_code) {
    return AuditorResult(AuditorResult::Type::ERROR_NO_ANNOTATION, "",
                         file_path, line_number);
  }

  // Process missing tag.
  if (unique_id_hash_code == MISSING_TRAFFIC_ANNOTATION.unique_id_hash_code)
    return AuditorResult(AuditorResult::Type::ERROR_MISSING, "", file_path,
                         line_number);

  // Decode serialized proto.
  std::string annotation_text = "";
  while (start_line < end_line) {
    annotation_text += serialized_lines[start_line++] + "\n";
  }

  SimpleErrorCollector error_collector(line_number);
  google::protobuf::TextFormat::Parser parser;
  parser.RecordErrorsTo(&error_collector);
  if (!parser.ParseFromString(annotation_text,
                              (google::protobuf::Message*)&proto)) {
    return AuditorResult(AuditorResult::Type::ERROR_SYNTAX,
                         error_collector.GetMessage().c_str(), file_path,
                         line_number);
  }

  // Add other fields.
  traffic_annotation::NetworkTrafficAnnotation_TrafficSource* src =
      proto.mutable_source();
  src->set_file(file_path);
  src->set_function(function_context);
  src->set_line(line_number);
  proto.set_unique_id(unique_id);
  extra_id_hash_code = TrafficAnnotationAuditor::ComputeHashValue(extra_id);

  return AuditorResult(AuditorResult::Type::RESULT_OK);
}

// Checks if an annotation has all required fields.
AuditorResult AnnotationInstance::IsComplete() const {
  std::vector<std::string> unspecifieds;
  std::string extra_texts;

  const traffic_annotation::NetworkTrafficAnnotation_TrafficSemantics
      semantics = proto.semantics();
  if (semantics.sender().empty())
    unspecifieds.push_back("semantics::sender");
  if (semantics.description().empty())
    unspecifieds.push_back("semantics::description");
  if (semantics.trigger().empty())
    unspecifieds.push_back("semantics::trigger");
  if (semantics.data().empty())
    unspecifieds.push_back("semantics::data");
  if (semantics.destination() ==
      traffic_annotation::
          NetworkTrafficAnnotation_TrafficSemantics_Destination_UNSPECIFIED)
    unspecifieds.push_back("semantics::destination");

  const traffic_annotation::NetworkTrafficAnnotation_TrafficPolicy policy =
      proto.policy();
  if (policy.cookies_allowed() ==
      traffic_annotation::
          NetworkTrafficAnnotation_TrafficPolicy_CookiesAllowed_UNSPECIFIED) {
    unspecifieds.push_back("policy::cookies_allowed");
  } else if (
      policy.cookies_allowed() ==
          traffic_annotation::
              NetworkTrafficAnnotation_TrafficPolicy_CookiesAllowed_YES &&
      policy.cookies_store().empty()) {
    unspecifieds.push_back("policy::cookies_store");
  }

  if (policy.setting().empty())
    unspecifieds.push_back("policy::setting");

  if (!policy.chrome_policy_size() &&
      policy.policy_exception_justification().empty()) {
    unspecifieds.push_back(
        "neither policy::chrome_policy nor "
        "policy::policy_exception_justification");
  }

  if (!unspecifieds.size())
    return AuditorResult(AuditorResult::Type::RESULT_OK);

  std::string error_text;
  for (const std::string& item : unspecifieds)
    error_text += item + ", ";
  error_text = error_text.substr(0, error_text.length() - 2);
  return AuditorResult(AuditorResult::Type::ERROR_INCOMPLETE_ANNOTATION,
                       error_text, proto.source().file(),
                       proto.source().line());
}

// Checks if annotation fields are consistent.
AuditorResult AnnotationInstance::IsConsistent() const {
  const traffic_annotation::NetworkTrafficAnnotation_TrafficPolicy policy =
      proto.policy();

  if (policy.cookies_allowed() ==
          traffic_annotation::
              NetworkTrafficAnnotation_TrafficPolicy_CookiesAllowed_NO &&
      policy.cookies_store().size()) {
    return AuditorResult(
        AuditorResult::Type::ERROR_INCONSISTENT_ANNOTATION,
        "Cookies store is specified while cookies are not allowed.",
        proto.source().file(), proto.source().line());
  }

  if (policy.chrome_policy_size() &&
      policy.policy_exception_justification().size()) {
    return AuditorResult(
        AuditorResult::Type::ERROR_INCONSISTENT_ANNOTATION,
        "Both chrome policies and policy exception justification are present.",
        proto.source().file(), proto.source().line());
  }

  return AuditorResult(AuditorResult::Type::RESULT_OK);
}

bool AnnotationInstance::IsCompletableWith(
    const AnnotationInstance& other) const {
  if (type != AnnotationInstance::Type::ANNOTATION_PARTIAL || extra_id.empty())
    return false;
  if (other.type == AnnotationInstance::Type::ANNOTATION_COMPLETING) {
    return extra_id_hash_code == other.unique_id_hash_code;
  } else if (other.type ==
             AnnotationInstance::Type::ANNOTATION_BRANCHED_COMPLETING) {
    return extra_id_hash_code == other.extra_id_hash_code;
  } else {
    return false;
  }
}

AuditorResult AnnotationInstance::CreateCompleteAnnotation(
    AnnotationInstance& completing_annotation,
    AnnotationInstance* combination) const {
  DCHECK(IsCompletableWith(completing_annotation));

  // To keep the source information meta data, if completing annotation is of
  // type COMPLETING, keep |this| as the main and the other as completing.
  // But if compliting annotation is of type BRANCHED_COMPLETING, reverse
  // the order.
  const AnnotationInstance* other;
  if (completing_annotation.type ==
      AnnotationInstance::Type::ANNOTATION_COMPLETING) {
    *combination = *this;
    other = &completing_annotation;
  } else {
    *combination = completing_annotation;
    other = this;
  }

  combination->type = AnnotationInstance::Type::ANNOTATION_COMPLETE;
  combination->extra_id.clear();
  combination->extra_id_hash_code = 0;
  combination->comments = base::StringPrintf(
      "This annotation is a merge of the following two annotations:\n"
      "'%s' in '%s:%i' and '%s' in '%s:%i'.",
      proto.unique_id().c_str(), proto.source().file().c_str(),
      proto.source().line(), completing_annotation.proto.unique_id().c_str(),
      completing_annotation.proto.source().file().c_str(),
      completing_annotation.proto.source().line());

  // Copy TrafficSemantics.
  const traffic_annotation::NetworkTrafficAnnotation_TrafficSemantics
      src_semantics = other->proto.semantics();
  traffic_annotation::NetworkTrafficAnnotation_TrafficSemantics* dst_semantics =
      combination->proto.mutable_semantics();

  MERGE_STRING_FIELDS(src_semantics, dst_semantics, empty_policy_justification);
  MERGE_STRING_FIELDS(src_semantics, dst_semantics, sender);
  MERGE_STRING_FIELDS(src_semantics, dst_semantics, description);
  MERGE_STRING_FIELDS(src_semantics, dst_semantics, trigger);
  MERGE_STRING_FIELDS(src_semantics, dst_semantics, data);
  MERGE_STRING_FIELDS(src_semantics, dst_semantics, destination_other);

  // If destination is not specified in dst_semantics, get it from
  // src_semantics. If both are specified and they differ, issue error.
  if (dst_semantics->destination() ==
      traffic_annotation::
          NetworkTrafficAnnotation_TrafficSemantics_Destination_UNSPECIFIED) {
    dst_semantics->set_destination(src_semantics.destination());
  } else if (
      src_semantics.destination() !=
          traffic_annotation::
              NetworkTrafficAnnotation_TrafficSemantics_Destination_UNSPECIFIED &&
      src_semantics.destination() != dst_semantics->destination()) {
    AuditorResult error(
        AuditorResult::Type::ERROR_MERGE_FAILED,
        "Annotations contain different semantics::destination values.");
    error.AddDetail(proto.unique_id());
    error.AddDetail(completing_annotation.proto.unique_id());
    return error;
  }

  // Copy TrafficPolicy.
  const traffic_annotation::NetworkTrafficAnnotation_TrafficPolicy src_policy =
      other->proto.policy();
  traffic_annotation::NetworkTrafficAnnotation_TrafficPolicy* dst_policy =
      combination->proto.mutable_policy();

  MERGE_STRING_FIELDS(src_policy, dst_policy, cookies_store);
  MERGE_STRING_FIELDS(src_policy, dst_policy, setting);

  // Set cookies_allowed to the superseding value of both.
  dst_policy->set_cookies_allowed(
      std::max(dst_policy->cookies_allowed(), src_policy.cookies_allowed()));
  DCHECK_GT(traffic_annotation::
                NetworkTrafficAnnotation_TrafficPolicy_CookiesAllowed_YES,
            traffic_annotation::
                NetworkTrafficAnnotation_TrafficPolicy_CookiesAllowed_NO);
  DCHECK_GT(
      traffic_annotation::
          NetworkTrafficAnnotation_TrafficPolicy_CookiesAllowed_NO,
      traffic_annotation::
          NetworkTrafficAnnotation_TrafficPolicy_CookiesAllowed_UNSPECIFIED);

  for (int i = 0; i < src_policy.chrome_policy_size(); i++)
    *dst_policy->add_chrome_policy() = src_policy.chrome_policy(i);

  if (!src_policy.policy_exception_justification().empty()) {
    if (!dst_policy->policy_exception_justification().empty()) {
      dst_policy->set_policy_exception_justification(
          dst_policy->policy_exception_justification() + "\n");
    }
    dst_policy->set_policy_exception_justification(
        dst_policy->policy_exception_justification() +
        src_policy.policy_exception_justification());
  }

  return AuditorResult::Type::RESULT_OK;
}

CallInstance::CallInstance() : line_number(0), is_annotated(false) {}

CallInstance::CallInstance(const CallInstance& other)
    : file_path(other.file_path),
      line_number(other.line_number),
      function_context(other.function_context),
      function_name(other.function_name),
      is_annotated(other.is_annotated){};

AuditorResult CallInstance::Deserialize(
    const std::vector<std::string>& serialized_lines,
    int start_line,
    int end_line) {
  if (end_line - start_line != 5) {
    return AuditorResult(AuditorResult::Type::ERROR_FATAL,
                         "Not enough lines to deserialize call.");
  }

  file_path = serialized_lines[start_line++];
  function_context = serialized_lines[start_line++];
  int line_number_int;
  base::StringToInt(serialized_lines[start_line++], &line_number_int);
  line_number = static_cast<uint32_t>(line_number_int);
  function_name = serialized_lines[start_line++];
  int is_annotated_int;
  base::StringToInt(serialized_lines[start_line++], &is_annotated_int);
  is_annotated = is_annotated_int != 0;
  return AuditorResult(AuditorResult::Type::RESULT_OK);
}