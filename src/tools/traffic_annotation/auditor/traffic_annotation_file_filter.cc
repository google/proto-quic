// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/traffic_annotation/auditor/traffic_annotation_file_filter.h"

#include <fstream>

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/process/launch.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"

namespace {

// List of keywords that indicate a file may be related to network traffic
// annotations. This list includes all keywords related to defining annotations
// and all functions that need one.
const char* kRelevantKeywords[] = {
    "network_traffic_annotation",
    "network_traffic_annotation_test_helper",
    "NetworkTrafficAnnotationTag",
    "PartialNetworkTrafficAnnotationTag",
    "DefineNetworkTrafficAnnotation",
    "DefinePartialNetworkTrafficAnnotation",
    "CompleteNetworkTrafficAnnotation",
    "BranchedCompleteNetworkTrafficAnnotation",
    "NO_TRAFFIC_ANNOTATION_YET",
    "NO_PARTIAL_TRAFFIC_ANNOTATION_YET",
    "MISSING_TRAFFIC_ANNOTATION",
    "TRAFFIC_ANNOTATION_FOR_TESTS",
    "PARTIAL_TRAFFIC_ANNOTATION_FOR_TESTS",
    "SSLClientSocket",     // SSLClientSocket::
    "TCPClientSocket",     // TCPClientSocket::
    "UDPClientSocket",     // UDPClientSocket::
    "URLFetcher::Create",  // This one is used with class as it's too generic.
    "CreateDatagramClientSocket",   // ClientSocketFactory::
    "CreateSSLClientSocket",        // ClientSocketFactory::
    "CreateTransportClientSocket",  // ClientSocketFactory::
    "CreateRequest",                // URLRequestContext::
    nullptr                         // End Marker
};

}  // namespace

TrafficAnnotationFileFilter::TrafficAnnotationFileFilter() {}

TrafficAnnotationFileFilter::~TrafficAnnotationFileFilter() {}

void TrafficAnnotationFileFilter::GetFilesFromGit(
    const base::FilePath& source_path) {
  const base::CommandLine::CharType* args[] =
#if defined(OS_WIN)
      {FILE_PATH_LITERAL("git.bat"), FILE_PATH_LITERAL("ls-files")};
#else
      {"git", "ls-files"};
#endif
  base::CommandLine cmdline(2, args);

  // Change directory to source path to access git.
  base::FilePath original_path;
  base::GetCurrentDirectory(&original_path);
  base::SetCurrentDirectory(source_path);

  // Get list of files from git.
  std::string results;
  if (!base::GetAppOutput(cmdline, &results)) {
    LOG(ERROR) << "Could not get files from git.";
  } else {
    for (const std::string file_path : base::SplitString(
             results, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL)) {
      if (IsFileRelevant(file_path))
        git_files_.push_back(file_path);
    }
  }

  base::SetCurrentDirectory(original_path);
}

bool TrafficAnnotationFileFilter::IsFileRelevant(const std::string& file_path) {
  // Check file extension.
  int pos = file_path.length() - 3;

  if (pos < 0 || (strcmp(".mm", file_path.c_str() + pos) &&
                  strcmp(".cc", file_path.c_str() + pos))) {
    return false;
  }

  base::FilePath converted_file_path =
#if defined(OS_WIN)
      base::FilePath(
          base::FilePath::StringPieceType(base::UTF8ToWide(file_path)));
#else
      base::FilePath(base::FilePath::StringPieceType(file_path));
#endif

  // Check file content.
  std::string file_content;
  if (!base::ReadFileToString(converted_file_path, &file_content)) {
    LOG(ERROR) << "Could not open file: " << file_path;
    return false;
  }

  for (int i = 0; kRelevantKeywords[i]; i++) {
    if (file_content.find(kRelevantKeywords[i]) != std::string::npos)
      return true;
  }

  return false;
}

void TrafficAnnotationFileFilter::GetRelevantFiles(
    const base::FilePath& source_path,
    std::string directory_name,
    std::vector<std::string>* file_paths) {
  if (!git_files_.size())
    GetFilesFromGit(source_path);

#if defined(FILE_PATH_USES_WIN_SEPARATORS)
  std::replace(directory_name.begin(), directory_name.end(), L'\\', L'/');
#endif

  size_t name_length = directory_name.length();
  for (const std::string& file_path : git_files_) {
    if (!strncmp(file_path.c_str(), directory_name.c_str(), name_length))
      file_paths->push_back(file_path);
  }
}
