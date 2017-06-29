// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/file_util.h"
#include "base/strings/stringprintf.h"
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
  base::CommandLine::StringVector path_filters = command_line.GetArgs();

  // If source path is not provided, guess it using build path or current
  // directory.
  if (source_path.empty()) {
    if (build_path.empty())
      base::GetCurrentDirectory(&source_path);
    else
      source_path = build_path.Append(base::FilePath::kParentDirectory)
                        .Append(base::FilePath::kParentDirectory);
  }

  // Extract annotations.
  std::string raw_output;
  if (extractor_input.empty()) {
    // Get build directory, if it is empty issue an error.
    if (build_path.empty()) {
      LOG(ERROR)
          << "You must either specify the build directory to run the clang "
             "tool and extract annotations, or specify the input file where "
             "extracted annotations already exist.\n";
      return 1;
    }

    raw_output = traffic_annotation_auditor::RunClangTool(
        source_path, build_path, path_filters, full_run);
  } else {
    if (!base::ReadFileToString(extractor_input, &raw_output)) {
      LOG(ERROR) << "Could not read input file: "
                 << extractor_input.value().c_str();
      return 1;
    }
  }

  // Write extractor output if requested.
  if (!extractor_output.empty() && extractor_input.empty()) {
    base::WriteFile(extractor_output, raw_output.c_str(), raw_output.length());
  }

  // Process extractor output.
  std::vector<traffic_annotation_auditor::AnnotationInstance>
      annotation_instances;
  std::vector<traffic_annotation_auditor::CallInstance> call_instances;
  std::vector<std::string> errors;

  if (!traffic_annotation_auditor::ParseClangToolRawOutput(
          raw_output, &annotation_instances, &call_instances, &errors)) {
    return 1;
  }

  // Write the summary file.
  if (!summary_file.empty()) {
    std::string report;
    std::vector<std::string> items;

    report = "[Errors]\n";
    std::sort(errors.begin(), errors.end());
    for (const std::string& error : errors)
      report += error + "\n";

    report += "\n[Annotations]\n";
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
    for (auto& instance : annotation_instances) {
      items.push_back(make_pair(traffic_annotation_auditor::ComputeHashValue(
                                    instance.proto.unique_id()),
                                instance.proto.unique_id()));
    }
    items.push_back(std::make_pair(
        TRAFFIC_ANNOTATION_FOR_TESTS.unique_id_hash_code, "test"));
    items.push_back(
        std::make_pair(PARTIAL_TRAFFIC_ANNOTATION_FOR_TESTS.unique_id_hash_code,
                       "test_partial"));
    items.push_back(std::make_pair(
        NO_TRAFFIC_ANNOTATION_YET.unique_id_hash_code, "undefined"));
    DCHECK_EQ(NO_PARTIAL_TRAFFIC_ANNOTATION_YET.unique_id_hash_code,
              NO_TRAFFIC_ANNOTATION_YET.unique_id_hash_code);
    items.push_back(std::make_pair(
        MISSING_TRAFFIC_ANNOTATION.unique_id_hash_code, "missing"));

    std::sort(items.begin(), items.end());
    for (const auto& item : items)
      report += base::StringPrintf("<int value=\"%i\" label=\"%s\" />\n",
                                   item.first, item.second.c_str());

    if (base::WriteFile(ids_file, report.c_str(), report.length()) == -1) {
      LOG(ERROR) << "Could not write ids file.";
      return 1;
    }
  }

  LOG(INFO) << "Extracted " << annotation_instances.size() << " annotations & "
            << call_instances.size() << " calls, with " << errors.size()
            << " errors.";

  return 0;
}
