// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_TRAFFIC_ANNOTATION_AUDITOR_TRAFFIC_ANNOTATION_EXPORTER_H_
#define TOOLS_TRAFFIC_ANNOTATION_AUDITOR_TRAFFIC_ANNOTATION_EXPORTER_H_

#include <map>
#include <set>
#include <vector>

#include "base/files/file_path.h"
#include "tools/traffic_annotation/auditor/instance.h"

class TrafficAnnotationExporter {
 public:
  TrafficAnnotationExporter(const base::FilePath& source_path);
  ~TrafficAnnotationExporter();
  TrafficAnnotationExporter(const TrafficAnnotationExporter&) = delete;
  TrafficAnnotationExporter(TrafficAnnotationExporter&&) = delete;

  // Loads annotations from annotations.xml file into |report_items_|.
  bool LoadAnnotationsXML();

  // Updates |report_items_| with current set of extracted annotations and
  // reserved ids. Sets the |modified_| flag if any item is updated.
  bool UpdateAnnotations(const std::vector<AnnotationInstance>& annotations,
                         const std::map<int, std::string>& reserved_ids);

  // Saves |report_items_| into annotations.xml.
  bool SaveAnnotationsXML();

  // Produces the list of deprecated hash codes. Returns false if
  // annotations.xml is not and cannot be loaded.
  bool GetDeprecatedHashCodes(std::set<int>* hash_codes);

  bool modified() { return modified_; }

  // Runs tests on content of |report_items_|.
  bool CheckReportItems();

 private:
  struct ReportItem {
    ReportItem();
    ReportItem(const ReportItem& other);
    ~ReportItem();

    int unique_id_hash_code;
    std::string deprecation_date;
    int content_hash_code;
    std::vector<std::string> os_list;
  };

  std::map<std::string, ReportItem> report_items_;
  const base::FilePath source_path_;
  bool modified_;
};

#endif  // TOOLS_TRAFFIC_ANNOTATION_AUDITOR_TRAFFIC_ANNOTATION_EXPORTER_H_