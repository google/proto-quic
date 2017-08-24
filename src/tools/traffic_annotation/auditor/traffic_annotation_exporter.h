// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_TRAFFIC_ANNOTATION_AUDITOR_TRAFFIC_ANNOTATION_EXPORTER_H_
#define TOOLS_TRAFFIC_ANNOTATION_AUDITOR_TRAFFIC_ANNOTATION_EXPORTER_H_

#include <map>
#include <vector>

#include "base/files/file_path.h"
#include "base/strings/string_util.h"
#include "tools/traffic_annotation/auditor/instance.h"

class TrafficAnnotationExporter {
 public:
  TrafficAnnotationExporter() = default;
  ~TrafficAnnotationExporter() = default;
  TrafficAnnotationExporter(const TrafficAnnotationExporter&) = delete;
  TrafficAnnotationExporter(TrafficAnnotationExporter&&) = delete;

  // Updates the xml file including annotations unique id, hash code, content
  // hash code, and a flag specifying that annotation is depricated.
  bool UpdateAnnotationsXML(const base::FilePath& filepath,
                            const std::vector<AnnotationInstance>& annotations,
                            const std::map<int, std::string>& reserved_ids);

 private:
  struct ReportItem {
    ReportItem(std::string id, int hash_code, int content_hash)
        : unique_id(id),
          unique_id_hash_code(hash_code),
          deprecation_date(std::string()),
          content_hash_code(content_hash) {}
    ReportItem(std::string id, int hash_code) : ReportItem(id, hash_code, -1) {}
    ReportItem() : ReportItem(std::string(), -1, -1) {}

    static bool Compare(const ReportItem& a, const ReportItem& b) {
      return base::CompareCaseInsensitiveASCII(a.unique_id, b.unique_id) < 0;
    }

    std::string unique_id;
    int unique_id_hash_code;
    std::string deprecation_date;
    int content_hash_code;
  };

  // Loads annotations from the given XML file.
  bool LoadAnnotationsFromXML(const base::FilePath& filepath,
                              std::vector<ReportItem>* items);
};

#endif  // TOOLS_TRAFFIC_ANNOTATION_AUDITOR_TRAFFIC_ANNOTATION_EXPORTER_H_