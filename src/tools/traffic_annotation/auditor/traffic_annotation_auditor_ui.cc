// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/file_util.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "third_party/protobuf/src/google/protobuf/text_format.h"
#include "tools/traffic_annotation/auditor/traffic_annotation_auditor.h"
#include "tools/traffic_annotation/auditor/traffic_annotation_exporter.h"

namespace {

const char* HELP_TEXT = R"(
Traffic Annotation Auditor
Extracts network traffic annotaions from the repository, audits them for errors
and coverage, produces reports, and updates related files.

Usage: traffic_annotation_auditor [OPTION]... [path_filters]

Extracts network traffic annotations from source files. If path filter(s) are
specified, only those directories of the source  will be analyzed.

Options:
  -h, --help          Shows help.
  --build-path        Path to the build directory.
  --source-path       Optional path to the src directory. If not provided and
                      build-path is available, assumed to be 'build-path/../..',
                      otherwise current directory.
  --tool-path         Optional path to traffic_annotation_extractor clang tool.
                      If not specified, it's assumed to be in the same path as
                      auditor's executable.
  --extractor-output  Optional path to the temporary file that extracted
                      annotations will be stored into.
  --extracted-input   Optional path to the file that temporary extracted
                      annotations are already stored in. If this is provided,
                      clang tool is not run and this is used as input.
  --full-run          Optional flag asking the tool to run on the whole
                      repository without text filtering files. Using this flag
                      may increase processing time x40.
  --test-only         Optional flag to request just running tests and not
                      updating any file. If not specified,
                      'tools/traffic_annotation/summary/annotations.xml' might
                      get updated and if it does, 'tools/traffic_annotation/
                      scripts/annotations_xml_downstream_updater.py will
                      be called to update downstream files.
  --summary-file      Optional path to the output file with all annotations.
  --annotations-file  Optional path to a TSV output file with all annotations.
  path_filters        Optional paths to filter what files the tool is run on.

Example:
  traffic_annotation_auditor --build-dir=out/Debug summary-file=report.txt
)";

const base::FilePath kDownstreamUpdater(FILE_PATH_LITERAL(
    "tools/traffic_annotation/scripts/annotations_xml_downstream_caller.py"));
}  // namespace

// Calls |kDownstreamUpdater| script to update files that depend on
// annotations.xml.
bool RunAnnotationDownstreamUpdater(const base::FilePath& source_path) {
  base::CommandLine cmdline(source_path.Append(kDownstreamUpdater));
  int exit_code;

#if defined(OS_WIN)
  cmdline.PrependWrapper(L"python");
  exit_code =
      system(base::UTF16ToASCII(cmdline.GetCommandLineString()).c_str());
#else
  exit_code = system(cmdline.GetCommandLineString().c_str());
#endif

  if (exit_code) {
    LOG(ERROR) << "Running " << kDownstreamUpdater.MaybeAsASCII()
               << " failed with exit code: " << exit_code;
    return false;
  }
  return true;
}

// Writes a summary of annotations, calls, and errors.
bool WriteSummaryFile(const base::FilePath& filepath,
                      const std::vector<AnnotationInstance>& annotations,
                      const std::vector<CallInstance>& calls,
                      const std::vector<AuditorResult>& errors) {
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
  for (const auto& instance : annotations) {
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
  for (const auto& instance : calls) {
    items.push_back(base::StringPrintf(
        "File:%s:%i\nFunction:%s\nAnnotated: %i\n", instance.file_path.c_str(),
        instance.line_number, instance.function_name.c_str(),
        instance.is_annotated));
  }
  std::sort(items.begin(), items.end());
  for (const std::string& item : items)
    report += item;

  return base::WriteFile(filepath, report.c_str(), report.length()) != -1;
}

// Changes double quotations to single quotations, and adds quotations if the
// text includes end of lines or tabs.
std::string UpdateTextForTSV(std::string text) {
  base::ReplaceChars(text, "\"", "'", &text);
  if (text.find('\n') != std::string::npos ||
      text.find('\t') != std::string::npos)
    return base::StringPrintf("\"%s\"", text.c_str());
  return text;
}

// TODO(rhalavati): Update this function to extract the policy name and value
// directly from the ChromeSettingsProto object (gen/components/policy/proto/
// chrome_settings.proto). Since ChromeSettingsProto has over 300+
// implementations, the required output is now extracted from debug output as
// the debug output has the following format:
//   POLICY_NAME {
//    ...
//   POLICY_NAME: POLICY_VALUE (policy value may extend to several lines.)
//   }
std::string PolicyToText(std::string debug_string) {
  std::vector<std::string> lines = base::SplitString(
      debug_string, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  DCHECK(lines.size() && lines[0].length() > 3);
  DCHECK_EQ(lines[0].substr(lines[0].length() - 2, 2), " {");
  // Get the title, remove the open curly bracket.
  std::string title = lines[0].substr(0, lines[0].length() - 2);
  std::string output;
  // Find the first line that has the title in it, keep adding all next lines
  // to have the full value description.
  for (unsigned int i = 1; i < lines.size(); i++) {
    if (!output.empty()) {
      output += lines[i] + " ";
    } else if (lines[i].find(title) != std::string::npos) {
      output += lines[i] + " ";
    }
  }

  // Trim trailing spaces and curly bracket.
  base::TrimString(output, " ", &output);
  DCHECK(!output.empty());
  if (output[output.length() - 1] == '}')
    output.pop_back();

  return output;
}

// Writes a TSV file of all annotations and their content.
bool WriteAnnotationsFile(const base::FilePath& filepath,
                          const std::vector<AnnotationInstance>& annotations) {
  std::vector<std::string> lines;
  std::string title =
      "Unique ID\tReview by pconunsel\tEmpty Policy Justification\t"
      "Sender\tDescription\tTrigger\tData\tDestination\tCookies Allowed\t"
      "Cookies Store\tSetting\tChrome Policy\tComments\tSource File\tHash Code";

  for (auto& instance : annotations) {
    // Unique ID
    std::string line = instance.proto.unique_id();

    // Place holder for Review by pcounsel.
    line += "\t";

    // Semantics.
    const auto semantics = instance.proto.semantics();
    line += base::StringPrintf("\t%s",
                               semantics.empty_policy_justification().c_str());
    line += base::StringPrintf("\t%s", semantics.sender().c_str());
    line += base::StringPrintf(
        "\t%s", UpdateTextForTSV(semantics.description()).c_str());
    line += base::StringPrintf("\t%s",
                               UpdateTextForTSV(semantics.trigger()).c_str());
    line +=
        base::StringPrintf("\t%s", UpdateTextForTSV(semantics.data()).c_str());
    switch (semantics.destination()) {
      case traffic_annotation::
          NetworkTrafficAnnotation_TrafficSemantics_Destination_WEBSITE:
        line += "\tWebsite";
        break;
      case traffic_annotation::
          NetworkTrafficAnnotation_TrafficSemantics_Destination_GOOGLE_OWNED_SERVICE:
        line += "\tGoogle";
        break;
      case traffic_annotation::
          NetworkTrafficAnnotation_TrafficSemantics_Destination_LOCAL:
        line += "\tLocal";
        break;
      case traffic_annotation::
          NetworkTrafficAnnotation_TrafficSemantics_Destination_OTHER:
        if (!semantics.destination_other().empty())
          line += UpdateTextForTSV(base::StringPrintf(
              "\tOther: %s", semantics.destination_other().c_str()));
        else
          line += "\tOther";
        break;

      default:
        NOTREACHED();
        line += "\tInvalid value";
    }

    // Policy.
    const auto policy = instance.proto.policy();
    line +=
        policy.cookies_allowed() ==
                traffic_annotation::
                    NetworkTrafficAnnotation_TrafficPolicy_CookiesAllowed_YES
            ? "\tYes"
            : "\tNo";
    line += base::StringPrintf(
        "\t%s", UpdateTextForTSV(policy.cookies_store()).c_str());
    line +=
        base::StringPrintf("\t%s", UpdateTextForTSV(policy.setting()).c_str());

    // Chrome Policies.
    std::string policies_text;
    if (policy.chrome_policy_size()) {
      for (int i = 0; i < policy.chrome_policy_size(); i++) {
        if (i)
          policies_text += "\n";
        policies_text += PolicyToText(policy.chrome_policy(i).DebugString());
      }
    } else {
      policies_text = policy.policy_exception_justification();
    }
    line += base::StringPrintf("\t%s", UpdateTextForTSV(policies_text).c_str());

    // Comments.
    line += "\t" + instance.proto.comments();

    // Source.
    const auto source = instance.proto.source();
    line += base::StringPrintf("\t%s:%i", source.file().c_str(), source.line());

    // Hash code.
    line += base::StringPrintf("\t%i", instance.unique_id_hash_code);

    lines.push_back(line);
  }

  std::sort(lines.begin(), lines.end());
  lines.insert(lines.begin(), title);
  std::string report;
  for (const std::string& line : lines)
    report += line + "\n";

  return base::WriteFile(filepath, report.c_str(), report.length()) != -1;
}

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
  base::FilePath tool_path = command_line.GetSwitchValuePath("tool-path");
  base::FilePath extractor_output =
      command_line.GetSwitchValuePath("extractor-output");
  base::FilePath extractor_input =
      command_line.GetSwitchValuePath("extractor-input");
  bool full_run = command_line.HasSwitch("full-run");
  bool test_only = command_line.HasSwitch("test-only");
  base::FilePath summary_file = command_line.GetSwitchValuePath("summary-file");
  base::FilePath annotations_file =
      command_line.GetSwitchValuePath("annotations-file");
  std::vector<std::string> path_filters;

#if defined(OS_WIN)
  for (const auto& path : command_line.GetArgs())
    path_filters.push_back(base::UTF16ToASCII(path));
#else
  path_filters = command_line.GetArgs();
#endif

  // If tool path is not specified, assume it is in the same path as this
  // executable.
  if (tool_path.empty())
    tool_path = command_line.GetProgram().DirName();

  // If source path is not provided, guess it using build path or current
  // directory.
  if (source_path.empty()) {
    if (build_path.empty())
      base::GetCurrentDirectory(&source_path);
    else
      source_path = build_path.Append(base::FilePath::kParentDirectory)
                        .Append(base::FilePath::kParentDirectory);
  }

  TrafficAnnotationAuditor auditor(source_path, build_path, tool_path);

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
    if (!auditor.RunClangTool(path_filters, full_run)) {
      LOG(ERROR) << "Failed to run clang tool.";
      return 1;
    }

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
  if (!auditor.RunAllChecks()) {
    LOG(ERROR) << "Running checks failed.";
    return 1;
  }

  // Write the summary file.
  if (!summary_file.empty() &&
      !WriteSummaryFile(summary_file, auditor.extracted_annotations(),
                        auditor.extracted_calls(), auditor.errors())) {
    LOG(ERROR) << "Could not write summary file.";
    return 1;
  }

  // Write annotations TSV file.
  if (!annotations_file.empty() &&
      !WriteAnnotationsFile(annotations_file,
                            auditor.extracted_annotations())) {
    LOG(ERROR) << "Could not write TSV file.";
    return 1;
  }

  // Test/Update annotations.xml.
  TrafficAnnotationExporter exporter(source_path);
  if (!exporter.UpdateAnnotations(
          auditor.extracted_annotations(),
          TrafficAnnotationAuditor::GetReservedUniqueIDs())) {
    return 1;
  }
  if (exporter.modified()) {
    if (test_only) {
      printf("Error: annotation.xml needs update.\n");
    } else if (!exporter.SaveAnnotationsXML() ||
               !RunAnnotationDownstreamUpdater(source_path)) {
      LOG(ERROR) << "Could not update annotations XML or downstream files.";
      return 1;
    }
  }

  // Dump Errors and Warnings to stdout.
  const std::vector<AuditorResult>& errors = auditor.errors();
  for (const auto& error : errors) {
    printf(
        "%s: %s\n",
        error.type() == AuditorResult::Type::ERROR_SYNTAX ? "Error" : "Warning",
        error.ToText().c_str());
  }

  return 0;
}