// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/file_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "third_party/protobuf/src/google/protobuf/text_format.h"
#include "tools/traffic_annotation/auditor/traffic_annotation_auditor.h"

const char* HELP_TEXT = R"(
Traffic Annotation Auditor
Extracts network traffic annotaions from the repository, audits them for errors
and coverage, and produces reports.

Usage: traffic_annotation_auditor [OPTION]... [path_filters]

Extracts network traffic annotations from source files. If path filter(s) are
specified, only those directories of the source  will be analyzed.

Options:
  -h, --help          Shows help.
  --build-path        Path to the build directory.
  --source-path       Optional path to the src directory. If not provided and
                      build-path is available, assumed to be 'build-path/../..',
                      otherwise current directory.
  --extractor-output  Optional path to the temporary file that extracted
                      annotations will be stored into.
  --extracted-input   Optional path to the file that temporary extracted
                      annotations are already stored in. If this is provided,
                      clang tool is not run and this is used as input.
  --full-run          Optional flag asking the tool to run on the whole
                      repository without text filtering files. Using this flag
                      may increase processing time x40.
  --summary-file      Optional path to the output file with all annotations.
  --ids-file          Optional path to the output file with the list of unique
                      ids and their hash codes.
  path_filters        Optional paths to filter what files the tool is run on.

Example:
  traffic_annotation_auditor --build-dir=out/Debug summary-file=report.txt
)";

#if defined(OS_WIN)
int wmain(int argc, wchar_t* argv[]) {
#else
int main(int argc, char* argv[]) {
#endif
  // Parse switches.
  base::CommandLine command_line = base::CommandLine(argc, argv);
  if (command_line.HasSwitch("help") || command_line.HasSwitch("h")) {
    printf("%s", HELP_TEXT);
    return 1;
  }

  base::FilePath build_path = command_line.GetSwitchValuePath("build-path");
  base::FilePath source_path = command_line.GetSwitchValuePath("source-path");
  base::FilePath extractor_output =
      command_line.GetSwitchValuePath("extractor-output");
  base::FilePath extractor_input =
      command_line.GetSwitchValuePath("extractor-input");
  bool full_run = command_line.HasSwitch("full-run");
  base::FilePath summary_file = command_line.GetSwitchValuePath("summary-file");
  base::FilePath ids_file = command_line.GetSwitchValuePath("ids-file");
  std::vector<std::string> path_filters;

#if defined(OS_WIN)
  for (const auto& path : command_line.GetArgs())
    path_filters.push_back(base::UTF16ToASCII(path));
#else
  path_filters = command_line.GetArgs();
#endif

  // If source path is not provided, guess it using build path or current
  // directory.
  if (source_path.empty()) {
    if (build_path.empty())
      base::GetCurrentDirectory(&source_path);
    else
      source_path = build_path.Append(base::FilePath::kParentDirectory)
                        .Append(base::FilePath::kParentDirectory);
  }

  TrafficAnnotationAuditor auditor(source_path, build_path);

  // Extract annotations.
  if (extractor_input.empty()) {
    // Get build directory, if it is empty issue an error.
    if (build_path.empty()) {
      LOG(ERROR)
          << "You must either specify the build directory to run the clang "
             "tool and extract annotations, or specify the input file where "
             "extracted annotations already exist.\n";
      return 1;
    }
    if (!auditor.RunClangTool(path_filters, full_run))
      return 1;

    // Write extractor output if requested.
    if (!extractor_output.empty()) {
      std::string raw_output = auditor.clang_tool_raw_output();
      base::WriteFile(extractor_output, raw_output.c_str(),
                      raw_output.length());
    }
  } else {
    std::string raw_output;
    if (!base::ReadFileToString(extractor_input, &raw_output)) {
      LOG(ERROR) << "Could not read input file: "
                 << extractor_input.value().c_str();
      return 1;
    } else {
      auditor.set_clang_tool_raw_output(raw_output);
    }
  }

  // Process extractor output.
  if (!auditor.ParseClangToolRawOutput())
    return 1;

  // Perform checks.
  auditor.RunAllChecks();

  // Write the summary file.
  if (!summary_file.empty()) {
    const std::vector<AnnotationInstance>& annotation_instances =
        auditor.extracted_annotations();
    const std::vector<CallInstance>& call_instances = auditor.extracted_calls();
    const std::vector<AuditorResult>& errors = auditor.errors();

    std::string report;
    std::vector<std::string> items;

    report = "[Errors]\n";
    for (const auto& error : errors)
      items.push_back(error.ToText());
    std::sort(items.begin(), items.end());
    for (const std::string& item : items)
      report += item + "\n";

    report += "\n[Annotations]\n";
    items.clear();
    for (const auto& instance : annotation_instances) {
      std::string serialized;
      google::protobuf::TextFormat::PrintToString(instance.proto, &serialized);
      items.push_back(serialized +
                      "\n----------------------------------------\n");
    }
    std::sort(items.begin(), items.end());
    for (const std::string& item : items)
      report += item;

    report += "\n[Calls]\n";
    items.clear();
    for (const auto& instance : call_instances) {
      items.push_back(base::StringPrintf(
          "File:%s:%i\nFunction:%s\nAnnotated: %i\n",
          instance.file_path.c_str(), instance.line_number,
          instance.function_name.c_str(), instance.is_annotated));
    }
    std::sort(items.begin(), items.end());
    for (const std::string& item : items)
      report += item;

    if (base::WriteFile(summary_file, report.c_str(), report.length()) == -1) {
      LOG(ERROR) << "Could not write summary file.";
      return 1;
    }
  }

  // Write ids file.
  if (!ids_file.empty()) {
    std::string report;
    std::vector<std::pair<int, std::string>> items;
    const std::vector<AnnotationInstance>& annotation_instances =
        auditor.extracted_annotations();
    for (auto& instance : annotation_instances) {
      items.push_back(make_pair(TrafficAnnotationAuditor::ComputeHashValue(
                                    instance.proto.unique_id()),
                                instance.proto.unique_id()));
    }

    const std::map<int, std::string> reserved_ids =
        TrafficAnnotationAuditor::GetReservedUniqueIDs();
    for (const auto& item : reserved_ids)
      items.push_back(item);

    std::sort(items.begin(), items.end());
    for (const auto& item : items)
      report += base::StringPrintf("<int value=\"%i\" label=\"%s\" />\n",
                                   item.first, item.second.c_str());

    if (base::WriteFile(ids_file, report.c_str(), report.length()) == -1) {
      LOG(ERROR) << "Could not write ids file.";
      return 1;
    }
  }

  // Dump Errors and Warnings to stdout.
  const std::vector<AuditorResult>& errors = auditor.errors();
  for (const auto& error : errors) {
    printf("%s: %s\n",
           error.type() == AuditorResult::ResultType::ERROR_SYNTAX ? "Error"
                                                                   : "Warning",
           error.ToText().c_str());
  }

  return 0;
}
