// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/traffic_annotation/auditor/traffic_annotation_auditor.h"

#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/process/launch.h"
#include "base/stl_util.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
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

struct AnnotationID {
  // Two ids can be the same in the following cases:
  // 1- One is extra id of a partial annotation, and the other is either the
  //    unique id of a completing annotation, or extra id of a partial or
  //    branched completing annotation
  // 2- Both are extra ids of branched completing annotations.
  // The following Type value facilitate these checks.
  enum class Type { kPatrialExtra, kCompletingMain, kBranchedExtra, kOther };
  Type type;
  std::string text;
  int hash;
  AnnotationInstance* instance;
};

const base::FilePath kSafeListPath(
    FILE_PATH_LITERAL("tools/traffic_annotation/auditor/safe_list.txt"));
}  // namespace

TrafficAnnotationAuditor::TrafficAnnotationAuditor(
    const base::FilePath& source_path,
    const base::FilePath& build_path)
    : source_path_(source_path),
      build_path_(build_path),
      safe_list_loaded_(false){};

TrafficAnnotationAuditor::~TrafficAnnotationAuditor(){};

// static
int TrafficAnnotationAuditor::ComputeHashValue(const std::string& unique_id) {
  return unique_id.length() ? static_cast<int>(recursive_hash(
                                  unique_id.c_str(), unique_id.length()))
                            : -1;
}

bool TrafficAnnotationAuditor::RunClangTool(
    const std::vector<std::string>& path_filters,
    const bool full_run) {
  if (!safe_list_loaded_ && !LoadSafeList())
    return false;
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

  // |safe_list_[ALL]| is not passed when |full_run| is happening as there is
  // no way to pass it to run_tools.py except enumerating all alternatives.
  // The paths in |safe_list_[ALL]| are removed later from the results.
  if (full_run) {
    for (const std::string& file_path : path_filters)
      fprintf(options_file, "%s ", file_path.c_str());
  } else {
    TrafficAnnotationFileFilter filter;
    std::vector<std::string> file_paths;

    if (path_filters.size()) {
      for (const auto& path_filter : path_filters) {
        filter.GetRelevantFiles(
            source_path_,
            safe_list_[static_cast<int>(AuditorException::ExceptionType::ALL)],
            path_filter, &file_paths);
      }
    } else {
      filter.GetRelevantFiles(
          source_path_,
          safe_list_[static_cast<int>(AuditorException::ExceptionType::ALL)],
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

bool TrafficAnnotationAuditor::IsSafeListed(
    const std::string& file_path,
    AuditorException::ExceptionType exception_type) {
  if (!safe_list_loaded_ && !LoadSafeList())
    return false;
  const std::vector<std::string>& safe_list =
      safe_list_[static_cast<int>(exception_type)];

  for (const std::string& ignore_path : safe_list) {
    if (!strncmp(file_path.c_str(), ignore_path.c_str(), ignore_path.length()))
      return true;
  }

  // If the given filepath did not match the rules with the specified type,
  // check it with rules of type 'ALL' as well.
  if (exception_type != AuditorException::ExceptionType::ALL)
    return IsSafeListed(file_path, AuditorException::ExceptionType::ALL);
  return false;
}

bool TrafficAnnotationAuditor::ParseClangToolRawOutput() {
  if (!safe_list_loaded_ && !LoadSafeList())
    return false;
  // Remove possible carriage return characters before splitting lines.
  base::RemoveChars(clang_tool_raw_output_, "\r", &clang_tool_raw_output_);
  std::vector<std::string> lines =
      base::SplitString(clang_tool_raw_output_, "\n", base::KEEP_WHITESPACE,
                        base::SPLIT_WANT_ALL);

  for (unsigned int current = 0; current < lines.size(); current++) {
    // TODO(rhalavati): Remove this after updating auditor to process
    // assignments.
    if (lines[current] == "==== NEW ASSIGNMENT ====") {
      while (current < lines.size()) {
        if (lines[current] == "==== ASSIGNMENT ENDS ====")
          break;
        else
          current++;
      }
      if (current == lines.size()) {
        LOG(ERROR) << "'ASSIGNMENT END' not found.";
        return false;
      }
      continue;
    }

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
    AuditorResult result(AuditorResult::Type::RESULT_OK);

    result = annotation_block
                 ? new_annotation.Deserialize(lines, current, end_line)
                 : new_call.Deserialize(lines, current, end_line);

    if (!IsSafeListed(result.file_path(),
                      AuditorException::ExceptionType::ALL) &&
        (result.type() != AuditorResult::Type::ERROR_MISSING ||
         !IsSafeListed(result.file_path(),
                       AuditorException::ExceptionType::MISSING))) {
      switch (result.type()) {
        case AuditorResult::Type::RESULT_OK: {
          if (annotation_block)
            extracted_annotations_.push_back(new_annotation);
          else
            extracted_calls_.push_back(new_call);
          break;
        }
        case AuditorResult::Type::RESULT_IGNORE:
          break;
        case AuditorResult::Type::ERROR_FATAL: {
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

bool TrafficAnnotationAuditor::LoadSafeList() {
  base::FilePath safe_list_file =
      base::MakeAbsoluteFilePath(source_path_.Append(kSafeListPath));
  std::string file_content;
  if (base::ReadFileToString(safe_list_file, &file_content)) {
    base::RemoveChars(file_content, "\r", &file_content);
    std::vector<std::string> lines = base::SplitString(
        file_content, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
    for (const std::string& line : lines) {
      // Ignore comments and empty lines.
      if (!line.length() || line[0] == '#')
        continue;
      size_t comma = line.find(',');
      if (comma == std::string::npos) {
        LOG(ERROR) << "Unexpected syntax in safe_list.txt, line: " << line;
        return false;
      }

      AuditorException::ExceptionType exception_type;
      if (AuditorException::TypeFromString(line.substr(0, comma),
                                           &exception_type)) {
        safe_list_[static_cast<int>(exception_type)].push_back(
            line.substr(comma + 1, line.length() - comma - 1));
      } else {
        LOG(ERROR) << "Unexpected type in safe_list.txt line: " << line;
        return false;
      }
    }
    safe_list_loaded_ = true;
    return true;
  }

  LOG(ERROR) << "Could not read " << kSafeListPath.MaybeAsASCII();
  return false;
}

// static
const std::map<int, std::string>&
TrafficAnnotationAuditor::GetReservedUniqueIDs() {
  return kReservedAnnotations;
}

void TrafficAnnotationAuditor::PurgeAnnotations(
    const std::set<int>& hash_codes) {
  extracted_annotations_.erase(
      std::remove_if(extracted_annotations_.begin(),
                     extracted_annotations_.end(),
                     [&hash_codes](AnnotationInstance& annotation) {
                       return base::ContainsKey(hash_codes,
                                                annotation.unique_id_hash_code);
                     }),
      extracted_annotations_.end());
}

void TrafficAnnotationAuditor::CheckDuplicateHashes() {
  const std::map<int, std::string> reserved_ids = GetReservedUniqueIDs();

  std::map<int, std::vector<AnnotationID>> collisions;
  std::set<int> to_be_purged;

  for (AnnotationInstance& instance : extracted_annotations_) {
    // Check if partial and branched completing annotation have an extra id
    // which is different from their unique id.
    if ((instance.type == AnnotationInstance::Type::ANNOTATION_PARTIAL ||
         instance.type ==
             AnnotationInstance::Type::ANNOTATION_BRANCHED_COMPLETING) &&
        (instance.unique_id_hash_code == instance.extra_id_hash_code)) {
      errors_.push_back(AuditorResult(
          AuditorResult::Type::ERROR_MISSING_EXTRA_ID, std::string(),
          instance.proto.source().file(), instance.proto.source().line()));
      continue;
    }

    AnnotationID current;
    current.instance = &instance;
    // Iterate over unique id and extra id.
    for (int id = 0; id < 2; id++) {
      if (id) {
        // If it's an empty extra id, no further check is required.
        if (instance.extra_id.empty()) {
          continue;
        } else {
          current.text = instance.extra_id;
          current.hash = instance.extra_id_hash_code;
          if (instance.type == AnnotationInstance::Type::ANNOTATION_PARTIAL) {
            current.type = AnnotationID::Type::kPatrialExtra;
          } else if (instance.type ==
                     AnnotationInstance::Type::ANNOTATION_BRANCHED_COMPLETING) {
            current.type = AnnotationID::Type::kBranchedExtra;
          } else {
            current.type = AnnotationID::Type::kOther;
          }
        }
      } else {
        current.text = instance.proto.unique_id();
        current.hash = instance.unique_id_hash_code;
        current.type =
            instance.type == AnnotationInstance::Type::ANNOTATION_COMPLETING
                ? AnnotationID::Type::kCompletingMain
                : AnnotationID::Type::kOther;
      }

      // If the id's hash code is the same as a reserved id, add an error.
      if (base::ContainsKey(reserved_ids, current.hash)) {
        errors_.push_back(AuditorResult(
            AuditorResult::Type::ERROR_RESERVED_UNIQUE_ID_HASH_CODE,
            current.text, instance.proto.source().file(),
            instance.proto.source().line()));
        continue;
      }

      // Check for collisions.
      if (!base::ContainsKey(collisions, current.hash)) {
        collisions[current.hash] = std::vector<AnnotationID>();
      } else {
        // Add error for ids with the same hash codes. If the texts are really
        // different, there is a hash collision and should be corrected in any
        // case. Otherwise, it's an error if it doesn't match the criteria that
        // are previously spcified in definition of AnnotationID struct.
        for (const auto& other : collisions[current.hash]) {
          if (current.text == other.text &&
              ((current.type == AnnotationID::Type::kPatrialExtra &&
                (other.type == AnnotationID::Type::kPatrialExtra ||
                 other.type == AnnotationID::Type::kCompletingMain ||
                 other.type == AnnotationID::Type::kBranchedExtra)) ||
               (other.type == AnnotationID::Type::kPatrialExtra &&
                (current.type == AnnotationID::Type::kCompletingMain ||
                 current.type == AnnotationID::Type::kBranchedExtra)) ||
               (current.type == AnnotationID::Type::kBranchedExtra &&
                other.type == AnnotationID::Type::kBranchedExtra))) {
            continue;
          }

          AuditorResult error(
              AuditorResult::Type::ERROR_DUPLICATE_UNIQUE_ID_HASH_CODE,
              base::StringPrintf(
                  "%s in '%s:%i'", current.text.c_str(),
                  current.instance->proto.source().file().c_str(),
                  current.instance->proto.source().line()));
          error.AddDetail(
              base::StringPrintf("%s in '%s:%i'", other.text.c_str(),
                                 other.instance->proto.source().file().c_str(),
                                 other.instance->proto.source().line()));

          errors_.push_back(error);
          to_be_purged.insert(current.hash);
          to_be_purged.insert(other.hash);
        }
      }
      collisions[current.hash].push_back(current);
    }
  }

  PurgeAnnotations(to_be_purged);
}

void TrafficAnnotationAuditor::CheckUniqueIDsFormat() {
  std::set<int> to_be_purged;
  for (const AnnotationInstance& instance : extracted_annotations_) {
    if (!base::ContainsOnlyChars(base::ToLowerASCII(instance.proto.unique_id()),
                                 "0123456789_abcdefghijklmnopqrstuvwxyz")) {
      errors_.push_back(AuditorResult(
          AuditorResult::Type::ERROR_UNIQUE_ID_INVALID_CHARACTER,
          instance.proto.unique_id(), instance.proto.source().file(),
          instance.proto.source().line()));
      to_be_purged.insert(instance.unique_id_hash_code);
    }
    if (!instance.extra_id.empty() &&
        !base::ContainsOnlyChars(base::ToLowerASCII(instance.extra_id),
                                 "0123456789_abcdefghijklmnopqrstuvwxyz")) {
      errors_.push_back(
          AuditorResult(AuditorResult::Type::ERROR_UNIQUE_ID_INVALID_CHARACTER,
                        instance.extra_id, instance.proto.source().file(),
                        instance.proto.source().line()));
      to_be_purged.insert(instance.unique_id_hash_code);
    }
  }
  PurgeAnnotations(to_be_purged);
}

void TrafficAnnotationAuditor::CheckAllRequiredFunctionsAreAnnotated() {
  for (const CallInstance& call : extracted_calls_) {
    if (!call.is_annotated && !CheckIfCallCanBeUnannotated(call)) {
      errors_.push_back(
          AuditorResult(AuditorResult::Type::ERROR_MISSING_ANNOTATION,
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

  if (IsSafeListed(call.file_path, AuditorException::ExceptionType::MISSING))
    return true;

  // Unittests should be all annotated. Although this can be detected using gn,
  // doing that would be very slow. The alternative solution would be to bypass
  // every file including test or unittest, but in this case there might be some
  // ambiguety in what should be annotated and what not.
  if (call.file_path.find("unittest") != std::string::npos)
    return false;

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

void TrafficAnnotationAuditor::CheckAnnotationsContents() {
  std::vector<AnnotationInstance*> partial_annotations;
  std::vector<AnnotationInstance*> completing_annotations;
  std::vector<AnnotationInstance> new_annotations;
  std::set<int> to_be_purged;

  // Process complete annotations and separate the others.
  for (AnnotationInstance& instance : extracted_annotations_) {
    bool keep_annotation = false;
    switch (instance.type) {
      case AnnotationInstance::Type::ANNOTATION_COMPLETE: {
        AuditorResult result = instance.IsComplete();
        if (result.IsOK())
          result = instance.IsConsistent();
        if (result.IsOK())
          keep_annotation = true;
        else
          errors_.push_back(result);
        break;
      }
      case AnnotationInstance::Type::ANNOTATION_PARTIAL:
        partial_annotations.push_back(&instance);
        break;
      default:
        completing_annotations.push_back(&instance);
    }
    if (!keep_annotation)
      to_be_purged.insert(instance.unique_id_hash_code);
  }

  std::set<AnnotationInstance*> used_completing_annotations;

  for (AnnotationInstance* partial : partial_annotations) {
    bool found_a_pair = false;
    for (AnnotationInstance* completing : completing_annotations) {
      if (partial->IsCompletableWith(*completing)) {
        found_a_pair = true;
        used_completing_annotations.insert(completing);

        AnnotationInstance completed;
        AuditorResult result =
            partial->CreateCompleteAnnotation(*completing, &completed);

        if (result.IsOK())
          result = completed.IsComplete();

        if (result.IsOK())
          result = completed.IsConsistent();

        if (result.IsOK()) {
          new_annotations.push_back(completed);
        } else {
          result = AuditorResult(AuditorResult::Type::ERROR_MERGE_FAILED,
                                 result.ToShortText());
          result.AddDetail(partial->proto.unique_id());
          result.AddDetail(completing->proto.unique_id());
          errors_.push_back(result);
        }
      }
    }

    if (!found_a_pair) {
      errors_.push_back(AuditorResult(
          AuditorResult::Type::ERROR_INCOMPLETED_ANNOTATION, std::string(),
          partial->proto.source().file(), partial->proto.source().line()));
    }
  }

  for (AnnotationInstance* instance : completing_annotations) {
    if (!base::ContainsKey(used_completing_annotations, instance)) {
      errors_.push_back(AuditorResult(
          AuditorResult::Type::ERROR_INCOMPLETED_ANNOTATION, std::string(),
          instance->proto.source().file(), instance->proto.source().line()));
    }
  }

  PurgeAnnotations(to_be_purged);
  if (new_annotations.size())
    extracted_annotations_.insert(extracted_annotations_.end(),
                                  new_annotations.begin(),
                                  new_annotations.end());
}

void TrafficAnnotationAuditor::RunAllChecks() {
  CheckDuplicateHashes();
  CheckUniqueIDsFormat();
  CheckAnnotationsContents();

  CheckAllRequiredFunctionsAreAnnotated();
}