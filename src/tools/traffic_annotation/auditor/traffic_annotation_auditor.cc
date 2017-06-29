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

}  // namespace

namespace traffic_annotation_auditor {

AnnotationInstance::AnnotationInstance()
    : annotation_type(AnnotationType::ANNOTATION_COMPLETE) {}

AnnotationInstance::AnnotationInstance(const AnnotationInstance& other)
    : proto(other.proto),
      annotation_type(other.annotation_type),
      extra_id(other.extra_id),
      unique_id_hash_code(other.unique_id_hash_code),
      extra_id_hash_code(other.extra_id_hash_code){};

bool AnnotationInstance::Deserialize(
    const std::vector<std::string>& serialized_lines,
    int start_line,
    int end_line,
    std::string* error_text) {
  if (end_line - start_line < 7) {
    LOG(ERROR) << "Not enough lines to deserialize annotation.";
    *error_text = "FATAL";
    return false;
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
    LOG(ERROR) << "Unexpected function type: " << function_type;
    *error_text = "FATAL";
    return false;
  }

  // Process test tags.
  unique_id_hash_code = ComputeHashValue(unique_id);
  if (unique_id_hash_code == TRAFFIC_ANNOTATION_FOR_TESTS.unique_id_hash_code ||
      unique_id_hash_code ==
          PARTIAL_TRAFFIC_ANNOTATION_FOR_TESTS.unique_id_hash_code) {
    return false;
  }

  // Process undefined tags.
  if (unique_id_hash_code == NO_TRAFFIC_ANNOTATION_YET.unique_id_hash_code ||
      unique_id_hash_code ==
          NO_PARTIAL_TRAFFIC_ANNOTATION_YET.unique_id_hash_code) {
    *error_text = base::StringPrintf(
        "Annotation is defined with temporary tag for file '%s', line %i.",
        file_path.c_str(), line_number);
    return false;
  }

  // Process missing tag.
  if (unique_id_hash_code == MISSING_TRAFFIC_ANNOTATION.unique_id_hash_code) {
    *error_text =
        base::StringPrintf("Missing annotation in file '%s', line %i.",
                           file_path.c_str(), line_number);
    return false;
  }

  // Decode serialized proto.
  std::string annotation_text = "";
  while (start_line < end_line) {
    annotation_text += serialized_lines[start_line++] + "\n";
  }
  if (!google::protobuf::TextFormat::ParseFromString(
          annotation_text, (google::protobuf::Message*)&proto)) {
    // TODO(rhalavati@): Find exact error message using:
    // google::protobuf::io::ErrorCollector error_collector;
    // google::protobuf::TextFormat::Parser::RecordErrorsTo(&error_collector);
    *error_text =
        base::StringPrintf("Could not parse protobuf for file '%s', line %i.",
                           file_path.c_str(), line_number);
    return false;
  }

  // Add other fields.
  traffic_annotation::NetworkTrafficAnnotation_TrafficSource* src =
      proto.mutable_source();
  src->set_file(file_path);
  src->set_function(function_context);
  src->set_line(line_number);
  proto.set_unique_id(unique_id);
  extra_id_hash_code = ComputeHashValue(extra_id);

  return true;
}

CallInstance::CallInstance() : line_number(0), is_annotated(false) {}

CallInstance::CallInstance(const CallInstance& other)
    : file_path(other.file_path),
      line_number(other.line_number),
      function_context(other.function_context),
      function_name(other.function_name),
      is_annotated(other.is_annotated){};

bool CallInstance::Deserialize(const std::vector<std::string>& serialized_lines,
                               int start_line,
                               int end_line,
                               std::string* error_text) {
  if (end_line - start_line != 5) {
    LOG(ERROR) << "Incorrect number of lines to deserialize call.";
    *error_text = "FATAL";
    return false;
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
  return true;
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
                             std::vector<std::string>* errors) {
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
    std::string error_text;
    if (annotation_block) {
      AnnotationInstance new_annotation;
      if (new_annotation.Deserialize(lines, current, end_line, &error_text))
        annotations->push_back(new_annotation);
    } else {
      CallInstance new_call;
      if (new_call.Deserialize(lines, current, end_line, &error_text))
        calls->push_back(new_call);
    }
    if (!error_text.empty()) {
      if (error_text == "FATAL") {
        LOG(ERROR) << "Aborting after line " << current << ".";
        return false;
      }
      errors->push_back(error_text);
    }

    current = end_line;
  }  // for

  return true;
}

}  // namespace traffic_annotation_auditor