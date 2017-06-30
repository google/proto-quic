// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRAFFIC_ANNOTATION_FILE_FILTER_H_
#define TRAFFIC_ANNOTATION_FILE_FILTER_H_

#include <string>
#include <vector>

namespace base {
class FilePath;
}

// Provides the list of files that might be relevent to network traffic
// annotation by matching filename and searching for keywords in the file
// content.
// The file should end with either .cc or .mm and the content should include a
// keyword specifying definition of network traffic annotations or the name of
// a function that needs annotation.
class TrafficAnnotationFileFilter {
 public:
  TrafficAnnotationFileFilter();
  ~TrafficAnnotationFileFilter();

  // Returns the list of relevant files in the given |directory_name| into the
  // |file_paths|. If |directory_name| is empty, all files are returned.
  // |source_path| should be the repository source directory, e.g. C:/src.
  void GetRelevantFiles(const base::FilePath& source_path,
                        std::string directory_name,
                        std::vector<std::string>* file_paths);

  // Checks the name and content of a file and returns true if it is relevant.
  bool IsFileRelevant(const std::string& file_path);

 private:
  // Gets the list of all files in the repository.
  void GetFilesFromGit(const base::FilePath& source_path);

  std::vector<std::string> git_files_;
};

#endif  // TRAFFIC_ANNOTATION_FILE_FILTER_H_