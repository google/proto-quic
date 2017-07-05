// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/traffic_annotation/auditor/traffic_annotation_auditor.h"

#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/process/launch.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "third_party/protobuf/src/google/protobuf/io/tokenizer.h"
#include "third_party/protobuf/src/google/protobuf/text_format.h"
#include "tools/traffic_annotation/auditor/traffic_annotation_file_filter.h"

namespace {

// Recursively compute the hash code of the given string as in:
// "net/traffic_annotation/network_traffic_annotation.h"
uint32_t recursive_hash(const char* str, int N) {
  if (N == 1)
    return static_cast<uint32_t>(str[0]);
  else
    return (recursive_hash(str, N - 1) * 31 + str[N - 1]) % 138003713;
}

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

}  // namespace

namespace traffic_annotation_auditor {

const int AuditorResult::kNoCodeLineSpecified = -1;

AuditorResult::AuditorResult(ResultType type,
                             const std::string& message,
                             const std::string& file_path,
                             int line)
    : type_(type), message_(message), file_path_(file_path), line_(line) {
  DCHECK(type == AuditorResult::ResultType::RESULT_OK ||
         type == AuditorResult::ResultType::RESULT_IGNORE ||
         type == AuditorResult::ResultType::ERROR_FATAL ||
         line != kNoCodeLineSpecified);
};

AuditorResult::AuditorResult(ResultType type, const std::string& message)
    : AuditorResult::AuditorResult(type,
                                   message,
                                   std::string(),
                                   kNoCodeLineSpecified) {}

AuditorResult::AuditorResult(ResultType type)
    : AuditorResult::AuditorResult(type,
                                   std::string(),
                                   std::string(),
                                   kNoCodeLineSpecified) {}

std::string AuditorResult::ToText() const {
  switch (type_) {
    case AuditorResult::ResultType::ERROR_FATAL:
      return message_;

    case AuditorResult::ResultType::ERROR_MISSING:
      return base::StringPrintf("Missing annotation in '%s', line %i.",
                                file_path_.c_str(), line_);

    case AuditorResult::ResultType::ERROR_NO_ANNOTATION:
      return base::StringPrintf("Empty annotation in '%s', line %i.",
                                file_path_.c_str(), line_);

    case AuditorResult::ResultType::ERROR_SYNTAX: {
      std::string flat_message(message_);
      std::replace(flat_message.begin(), flat_message.end(), '\n', ' ');
      return base::StringPrintf("Syntax error in '%s': %s", file_path_.c_str(),
                                flat_message.c_str());
    }

    default:
      return std::string();
  }
}

AnnotationInstance::AnnotationInstance()
    : annotation_type(AnnotationType::ANNOTATION_COMPLETE) {}

AnnotationInstance::AnnotationInstance(const AnnotationInstance& other)
    : proto(other.proto),
      annotation_type(other.annotation_type),
      extra_id(other.extra_id),
      unique_id_hash_code(other.unique_id_hash_code),
      extra_id_hash_code(other.extra_id_hash_code){};

AuditorResult AnnotationInstance::Deserialize(
    const std::vector<std::string>& serialized_lines,
    int start_line,
    int end_line) {
  if (end_line - start_line < 7) {
    return AuditorResult(AuditorResult::ResultType::ERROR_FATAL,
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
    annotation_type = AnnotationType::ANNOTATION_COMPLETE;
  } else if (function_type == "Partial") {
    annotation_type = AnnotationType::ANNOTATION_PARTIAL;
  } else if (function_type == "Completing") {
    annotation_type = AnnotationType::ANNOTATION_COMPLETENG;
  } else if (function_type == "BranchedCompleting") {
    annotation_type = AnnotationType::ANNOTATION_BRANCHED_COMPLETING;
  } else {
    return AuditorResult(AuditorResult::ResultType::ERROR_FATAL,
                         base::StringPrintf("Unexpected function type: %s",
                                            function_type.c_str()));
  }

  // Process test tags.
  unique_id_hash_code = ComputeHashValue(unique_id);
  if (unique_id_hash_code == TRAFFIC_ANNOTATION_FOR_TESTS.unique_id_hash_code ||
      unique_id_hash_code ==
          PARTIAL_TRAFFIC_ANNOTATION_FOR_TESTS.unique_id_hash_code) {
    return AuditorResult(AuditorResult::ResultType::RESULT_IGNORE);
  }

  // Process undefined tags.
  if (unique_id_hash_code == NO_TRAFFIC_ANNOTATION_YET.unique_id_hash_code ||
      unique_id_hash_code ==
          NO_PARTIAL_TRAFFIC_ANNOTATION_YET.unique_id_hash_code) {
    return AuditorResult(AuditorResult::ResultType::ERROR_NO_ANNOTATION, "",
                         file_path, line_number);
  }

  // Process missing tag.
  if (unique_id_hash_code == MISSING_TRAFFIC_ANNOTATION.unique_id_hash_code)
    return AuditorResult(AuditorResult::ResultType::ERROR_MISSING, "",
                         file_path, line_number);

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
    return AuditorResult(AuditorResult::ResultType::ERROR_SYNTAX,
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
  extra_id_hash_code = ComputeHashValue(extra_id);

  return AuditorResult(AuditorResult::ResultType::RESULT_OK);
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
    return AuditorResult(AuditorResult::ResultType::ERROR_FATAL,
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
  return AuditorResult(AuditorResult::ResultType::RESULT_OK);
}

int ComputeHashValue(const std::string& unique_id) {
  return unique_id.length() ? static_cast<int>(recursive_hash(
                                  unique_id.c_str(), unique_id.length()))
                            : -1;
}

std::string RunClangTool(const base::FilePath& source_path,
                         const base::FilePath& build_path,
                         const base::CommandLine::StringVector& path_filters,
                         const bool full_run) {
  base::FilePath options_filepath;
  if (!base::CreateTemporaryFile(&options_filepath)) {
    LOG(ERROR) << "Could not create temporary options file.";
    return std::string();
  }
  FILE* options_file = base::OpenFile(options_filepath, "wt");
  if (!options_file) {
    LOG(ERROR) << "Could not create temporary options file.";
    return std::string();
  }
  fprintf(options_file,
          "--generate-compdb --tool=traffic_annotation_extractor -p=%s ",
          build_path.MaybeAsASCII().c_str());

  if (full_run) {
    for (const auto& file_path : path_filters)
      fprintf(options_file, "%s ",
#if defined(OS_WIN)
              base::WideToUTF8(file_path).c_str()
#else
              file_path.c_str()
#endif
                  );
  } else {
    TrafficAnnotationFileFilter filter;
    std::vector<std::string> file_paths;

    if (path_filters.size()) {
      for (const auto& path_filter : path_filters) {
        filter.GetRelevantFiles(source_path,
#if defined(OS_WIN)
                                base::UTF16ToASCII(path_filter),
#else
                                path_filter,
#endif
                                &file_paths);
      }
    } else {
      filter.GetRelevantFiles(source_path, "", &file_paths);
    }

    if (!file_paths.size()) {
      base::CloseFile(options_file);
      base::DeleteFile(options_filepath, false);
      return std::string();
    }
    for (const auto& file_path : file_paths)
      fprintf(options_file, "%s ", file_path.c_str());
  }
  base::CloseFile(options_file);

  base::CommandLine cmdline(source_path.Append(FILE_PATH_LITERAL("tools"))
                                .Append(FILE_PATH_LITERAL("clang"))
                                .Append(FILE_PATH_LITERAL("scripts"))
                                .Append(FILE_PATH_LITERAL("run_tool.py")));

#if defined(OS_WIN)
  cmdline.PrependWrapper(L"python");
#endif

  cmdline.AppendArg(base::StringPrintf(
      "--options-file=%s", options_filepath.MaybeAsASCII().c_str()));

  std::string results;
  if (!base::GetAppOutput(cmdline, &results))
    results = std::string();

  base::DeleteFile(options_filepath, false);

  return results;
}

bool ParseClangToolRawOutput(const std::string& clang_output,
                             std::vector<AnnotationInstance>* annotations,
                             std::vector<CallInstance>* calls,
                             std::vector<AuditorResult>* errors) {
  // Remove possible carriage return characters before splitting lines.
  std::string trimmed_input;
  base::RemoveChars(clang_output, "\r", &trimmed_input);
  std::vector<std::string> lines = base::SplitString(
      trimmed_input, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

  for (unsigned int current = 0; current < lines.size(); current++) {
    bool annotation_block;
    if (lines[current] == "==== NEW ANNOTATION ====")
      annotation_block = true;
    else if (lines[current] == "==== NEW CALL ====") {
      annotation_block = false;
    } else if (lines[current].empty()) {
      continue;
    } else {
      LOG(ERROR) << "Unexpected token at line: " << current;
      return false;
    }

    // Get the block.
    current++;
    unsigned int end_line = current;
    std::string end_marker =
        annotation_block ? "==== ANNOTATION ENDS ====" : "==== CALL ENDS ====";
    while (end_line < lines.size() && lines[end_line] != end_marker)
      end_line++;
    if (end_line == lines.size()) {
      LOG(ERROR) << "Block starting at line " << current
                 << " is not ended by the appropriate tag.";
      return false;
    }

    // Deserialize and handle errors.
    AnnotationInstance new_annotation;
    CallInstance new_call;
    AuditorResult result(AuditorResult::ResultType::RESULT_OK);

    result = annotation_block
                 ? new_annotation.Deserialize(lines, current, end_line)
                 : new_call.Deserialize(lines, current, end_line);

    switch (result.type()) {
      case AuditorResult::ResultType::RESULT_OK: {
        if (annotation_block)
          annotations->push_back(new_annotation);
        else
          calls->push_back(new_call);
        break;
      }
      case AuditorResult::ResultType::RESULT_IGNORE:
        break;
      case AuditorResult::ResultType::ERROR_FATAL: {
        LOG(ERROR) << "Aborting after line " << current
                   << " because: " << result.ToText().c_str();
        return false;
      }
      default:
        errors->push_back(result);
    }

    current = end_line;
  }  // for

  return true;
}

}  // namespace traffic_annotation_auditor