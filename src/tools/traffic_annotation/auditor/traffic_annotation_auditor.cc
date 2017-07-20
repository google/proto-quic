// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/traffic_annotation/auditor/traffic_annotation_auditor.h"

#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/process/launch.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
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

std::map<int, std::string> kReservedAnnotations = {
    {TRAFFIC_ANNOTATION_FOR_TESTS.unique_id_hash_code, "test"},
    {PARTIAL_TRAFFIC_ANNOTATION_FOR_TESTS.unique_id_hash_code, "test_partial"},
    {NO_TRAFFIC_ANNOTATION_YET.unique_id_hash_code, "undefined"},
    {MISSING_TRAFFIC_ANNOTATION.unique_id_hash_code, "missing"},
};

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

const int AuditorResult::kNoCodeLineSpecified = -1;

AuditorResult::AuditorResult(ResultType type,
                             const std::string& message,
                             const std::string& file_path,
                             int line)
    : type_(type), file_path_(file_path), line_(line) {
  DCHECK(line != kNoCodeLineSpecified ||
         type == AuditorResult::ResultType::RESULT_OK ||
         type == AuditorResult::ResultType::RESULT_IGNORE ||
         type == AuditorResult::ResultType::ERROR_FATAL ||
         type ==
             AuditorResult::ResultType::ERROR_DUPLICATE_UNIQUE_ID_HASH_CODE);
  DCHECK(!message.empty() || type == AuditorResult::ResultType::RESULT_OK ||
         type == AuditorResult::ResultType::RESULT_IGNORE ||
         type == AuditorResult::ResultType::ERROR_MISSING ||
         type == AuditorResult::ResultType::ERROR_NO_ANNOTATION ||
         type ==
             AuditorResult::ResultType::ERROR_DUPLICATE_UNIQUE_ID_HASH_CODE);
  if (!message.empty())
    details_.push_back(message);
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

AuditorResult::AuditorResult(const AuditorResult& other)
    : type_(other.type_),
      details_(other.details_),
      file_path_(other.file_path_),
      line_(other.line_){};

AuditorResult::~AuditorResult() {}

void AuditorResult::AddDetail(const std::string& message) {
  details_.push_back(message);
}

std::string AuditorResult::ToText() const {
  switch (type_) {
    case AuditorResult::ResultType::ERROR_FATAL:
      DCHECK(details_.size());
      return details_[0];

    case AuditorResult::ResultType::ERROR_MISSING:
      return base::StringPrintf("Missing annotation in '%s', line %i.",
                                file_path_.c_str(), line_);

    case AuditorResult::ResultType::ERROR_NO_ANNOTATION:
      return base::StringPrintf("Empty annotation in '%s', line %i.",
                                file_path_.c_str(), line_);

    case AuditorResult::ResultType::ERROR_SYNTAX: {
      DCHECK(details_.size());
      std::string flat_message(details_[0]);
      std::replace(flat_message.begin(), flat_message.end(), '\n', ' ');
      return base::StringPrintf("Syntax error in '%s': %s", file_path_.c_str(),
                                flat_message.c_str());
    }

    case AuditorResult::ResultType::ERROR_RESERVED_UNIQUE_ID_HASH_CODE:
      DCHECK(details_.size());
      return base::StringPrintf(
          "Unique id '%s' in '%s:%i' has a hash code similar to a reserved "
          "word and should be changed.",
          details_[0].c_str(), file_path_.c_str(), line_);

    case AuditorResult::ResultType::ERROR_DUPLICATE_UNIQUE_ID_HASH_CODE: {
      DCHECK(details_.size());
      std::string error_text(
          "The following annotations have similar unique id "
          "hash codes and should be updated: ");
      for (const std::string& duplicate : details_)
        error_text += duplicate + ", ";
      error_text.pop_back();
      error_text.pop_back();
      error_text += ".";
      return error_text;
    }

    case AuditorResult::ResultType::ERROR_UNIQUE_ID_INVALID_CHARACTER:
      DCHECK(details_.size());
      return base::StringPrintf(
          "Unique id '%s' in '%s:%i' contains an invalid character.",
          details_[0].c_str(), file_path_.c_str(), line_);

    case AuditorResult::ResultType::ERROR_MISSING_ANNOTATION:
      DCHECK(details_.size());
      return base::StringPrintf("Function '%s' in '%s:%i' requires annotation.",
                                details_[0].c_str(), file_path_.c_str(), line_);

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
  unique_id_hash_code = TrafficAnnotationAuditor::ComputeHashValue(unique_id);
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
  extra_id_hash_code = TrafficAnnotationAuditor::ComputeHashValue(extra_id);

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

int TrafficAnnotationAuditor::ComputeHashValue(const std::string& unique_id) {
  return unique_id.length() ? static_cast<int>(recursive_hash(
                                  unique_id.c_str(), unique_id.length()))
                            : -1;
}

TrafficAnnotationAuditor::TrafficAnnotationAuditor(
    const base::FilePath& source_path,
    const base::FilePath& build_path)
    : source_path_(source_path), build_path_(build_path) {
  LoadWhiteList();
};

TrafficAnnotationAuditor::~TrafficAnnotationAuditor(){};

bool TrafficAnnotationAuditor::RunClangTool(
    const std::vector<std::string>& path_filters,
    const bool full_run) {
  base::FilePath options_filepath;
  if (!base::CreateTemporaryFile(&options_filepath)) {
    LOG(ERROR) << "Could not create temporary options file.";
    return false;
  }
  FILE* options_file = base::OpenFile(options_filepath, "wt");
  if (!options_file) {
    LOG(ERROR) << "Could not create temporary options file.";
    return false;
  }
  fprintf(options_file,
          "--generate-compdb --tool=traffic_annotation_extractor -p=%s ",
          build_path_.MaybeAsASCII().c_str());

  // |ignore_list_[ALL]| is not passed when |full_run| is happening as there is
  // no way to pass it to run_tools.py except enumerating all alternatives.
  // The paths in |ignore_list_[ALL]| are removed later from the results.
  if (full_run) {
    for (const std::string& file_path : path_filters)
      fprintf(options_file, "%s ", file_path.c_str());
  } else {
    TrafficAnnotationFileFilter filter;
    std::vector<std::string> file_paths;

    if (path_filters.size()) {
      for (const auto& path_filter : path_filters) {
        filter.GetRelevantFiles(source_path_,
                                ignore_list_[static_cast<int>(
                                    AuditorException::ExceptionType::ALL)],
                                path_filter, &file_paths);
      }
    } else {
      filter.GetRelevantFiles(
          source_path_,
          ignore_list_[static_cast<int>(AuditorException::ExceptionType::ALL)],
          "", &file_paths);
    }

    if (!file_paths.size()) {
      base::CloseFile(options_file);
      base::DeleteFile(options_filepath, false);
      return false;
    }
    for (const auto& file_path : file_paths)
      fprintf(options_file, "%s ", file_path.c_str());
  }
  base::CloseFile(options_file);

  base::CommandLine cmdline(source_path_.Append(FILE_PATH_LITERAL("tools"))
                                .Append(FILE_PATH_LITERAL("clang"))
                                .Append(FILE_PATH_LITERAL("scripts"))
                                .Append(FILE_PATH_LITERAL("run_tool.py")));

#if defined(OS_WIN)
  cmdline.PrependWrapper(L"python");
#endif

  cmdline.AppendArg(base::StringPrintf(
      "--options-file=%s", options_filepath.MaybeAsASCII().c_str()));

  bool result = base::GetAppOutput(cmdline, &clang_tool_raw_output_);

  base::DeleteFile(options_filepath, false);

  return result;
}

bool TrafficAnnotationAuditor::IsWhitelisted(
    const std::string& file_path,
    AuditorException::ExceptionType whitelist_type) {
  const std::vector<std::string>& whitelist =
      ignore_list_[static_cast<int>(whitelist_type)];

  for (const std::string& ignore_path : whitelist) {
    if (!strncmp(file_path.c_str(), ignore_path.c_str(), ignore_path.length()))
      return true;
  }

  // If the given filepath did not match the rules with the specified type,
  // check it with rules of type 'ALL' as well.
  if (whitelist_type != AuditorException::ExceptionType::ALL)
    return IsWhitelisted(file_path, AuditorException::ExceptionType::ALL);
  return false;
}

bool TrafficAnnotationAuditor::ParseClangToolRawOutput() {
  // Remove possible carriage return characters before splitting lines.
  base::RemoveChars(clang_tool_raw_output_, "\r", &clang_tool_raw_output_);
  std::vector<std::string> lines =
      base::SplitString(clang_tool_raw_output_, "\n", base::KEEP_WHITESPACE,
                        base::SPLIT_WANT_ALL);

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

    if (!IsWhitelisted(result.file_path(),
                       AuditorException::ExceptionType::ALL) &&
        (result.type() != AuditorResult::ResultType::ERROR_MISSING ||
         !IsWhitelisted(result.file_path(),
                        AuditorException::ExceptionType::MISSING))) {
      switch (result.type()) {
        case AuditorResult::ResultType::RESULT_OK: {
          if (annotation_block)
            extracted_annotations_.push_back(new_annotation);
          else
            extracted_calls_.push_back(new_call);
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
          errors_.push_back(result);
      }
    }

    current = end_line;
  }  // for

  return true;
}

bool TrafficAnnotationAuditor::LoadWhiteList() {
  base::FilePath white_list_file = base::MakeAbsoluteFilePath(
      source_path_.Append(FILE_PATH_LITERAL("tools"))
          .Append(FILE_PATH_LITERAL("traffic_annotation"))
          .Append(FILE_PATH_LITERAL("auditor"))
          .Append(FILE_PATH_LITERAL("white_list.txt")));
  std::string file_content;
  if (base::ReadFileToString(white_list_file, &file_content)) {
    base::RemoveChars(file_content, "\r", &file_content);
    std::vector<std::string> lines = base::SplitString(
        file_content, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
    for (const std::string& line : lines) {
      // Ignore comments.
      if (line.length() && line[0] == '#')
        continue;
      size_t comma = line.find(',');
      if (comma == std::string::npos) {
        LOG(ERROR) << "Unexpected syntax in white_list.txt, line: " << line;
        return false;
      }

      AuditorException::ExceptionType exception_type;
      if (AuditorException::TypeFromString(line.substr(0, comma),
                                           &exception_type)) {
        ignore_list_[static_cast<int>(exception_type)].push_back(
            line.substr(comma + 1, line.length() - comma - 1));
      } else {
        LOG(ERROR) << "Unexpected type in white_list.txt line: " << line;
        return false;
      }
    }
    return true;
  }

  LOG(ERROR)
      << "Could not read tools/traffic_annotation/auditor/white_list.txt";
  return false;
}

// static
const std::map<int, std::string>&
TrafficAnnotationAuditor::GetReservedUniqueIDs() {
  return kReservedAnnotations;
}

void TrafficAnnotationAuditor::CheckDuplicateHashes() {
  const std::map<int, std::string> reserved_ids = GetReservedUniqueIDs();

  std::map<int, std::vector<unsigned int>> unique_ids;
  for (unsigned int index = 0; index < extracted_annotations_.size(); index++) {
    AnnotationInstance& instance = extracted_annotations_[index];

    // If unique id's hash code is similar to a reserved id, add an error.
    if (base::ContainsKey(reserved_ids, instance.unique_id_hash_code)) {
      errors_.push_back(AuditorResult(
          AuditorResult::ResultType::ERROR_RESERVED_UNIQUE_ID_HASH_CODE,
          instance.proto.unique_id(), instance.proto.source().file(),
          instance.proto.source().line()));
      continue;
    }

    // Find unique ids with similar hash codes.
    if (!base::ContainsKey(unique_ids, instance.unique_id_hash_code)) {
      std::vector<unsigned> empty_list;
      unique_ids.insert(
          std::make_pair(instance.unique_id_hash_code, empty_list));
    }
    unique_ids[instance.unique_id_hash_code].push_back(index);
  }

  // Add error for unique ids with similar hash codes.
  for (const auto& item : unique_ids) {
    if (item.second.size() > 1) {
      AuditorResult error(
          AuditorResult::ResultType::ERROR_DUPLICATE_UNIQUE_ID_HASH_CODE);
      for (unsigned int index : item.second) {
        error.AddDetail(base::StringPrintf(
            "%s in '%s:%i'",
            extracted_annotations_[index].proto.unique_id().c_str(),
            extracted_annotations_[index].proto.source().file().c_str(),
            extracted_annotations_[index].proto.source().line()));
      }
      errors_.push_back(error);
    }
  }
}

void TrafficAnnotationAuditor::CheckUniqueIDsFormat() {
  for (const AnnotationInstance& instance : extracted_annotations_) {
    if (!base::ContainsOnlyChars(base::ToLowerASCII(instance.proto.unique_id()),
                                 "0123456789_abcdefghijklmnopqrstuvwxyz")) {
      errors_.push_back(AuditorResult(
          AuditorResult::ResultType::ERROR_UNIQUE_ID_INVALID_CHARACTER,
          instance.proto.unique_id(), instance.proto.source().file(),
          instance.proto.source().line()));
    }
  }
}

void TrafficAnnotationAuditor::CheckAllRequiredFunctionsAreAnnotated() {
  for (const CallInstance& call : extracted_calls_) {
    if (!call.is_annotated && !CheckIfCallCanBeUnannotated(call)) {
      errors_.push_back(
          AuditorResult(AuditorResult::ResultType::ERROR_MISSING_ANNOTATION,
                        call.function_name, call.file_path, call.line_number));
    }
  }
}

bool TrafficAnnotationAuditor::CheckIfCallCanBeUnannotated(
    const CallInstance& call) {
  // At this stage we do not enforce annotation on native network requests,
  // hence all calls except those to 'net::URLRequestContext::CreateRequest' and
  // 'net::URLFetcher::Create' are ignored.
  if (call.function_name != "net::URLFetcher::Create" &&
      call.function_name != "net::URLRequestContext::CreateRequest") {
    return true;
  }

  // Is in whitelist?
  if (IsWhitelisted(call.file_path, AuditorException::ExceptionType::MISSING))
    return true;

  // Already checked?
  if (base::ContainsKey(checked_dependencies_, call.file_path))
    return checked_dependencies_[call.file_path];

  std::string gn_output;
  if (gn_file_for_test_.empty()) {
    // Check if the file including this function is part of Chrome build.
    const base::CommandLine::CharType* args[] = {FILE_PATH_LITERAL("gn"),
                                                 FILE_PATH_LITERAL("refs"),
                                                 FILE_PATH_LITERAL("--all")};

    base::CommandLine cmdline(3, args);
    cmdline.AppendArgPath(build_path_);
    cmdline.AppendArg(call.file_path);

    base::FilePath original_path;
    base::GetCurrentDirectory(&original_path);
    base::SetCurrentDirectory(source_path_);

    if (!base::GetAppOutput(cmdline, &gn_output)) {
      LOG(ERROR) << "Could not run gn to get dependencies.";
      gn_output.clear();
    }

    base::SetCurrentDirectory(original_path);
  } else {
    if (!base::ReadFileToString(gn_file_for_test_, &gn_output)) {
      LOG(ERROR) << "Could not load mock gn output file from "
                 << gn_file_for_test_.MaybeAsASCII().c_str();
      gn_output.clear();
    }
  }

  checked_dependencies_[call.file_path] =
      gn_output.length() &&
      gn_output.find("//chrome:chrome") == std::string::npos;

  return checked_dependencies_[call.file_path];
}

void TrafficAnnotationAuditor::RunAllChecks() {
  CheckDuplicateHashes();
  CheckUniqueIDsFormat();
  CheckAllRequiredFunctionsAreAnnotated();
}