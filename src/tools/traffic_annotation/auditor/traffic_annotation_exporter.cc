// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/traffic_annotation/auditor/traffic_annotation_exporter.h"

#include <ctime>

#include "base/files/file_util.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "third_party/libxml/chromium/libxml_utils.h"
#include "third_party/protobuf/src/google/protobuf/text_format.h"
#include "tools/traffic_annotation/auditor/traffic_annotation_auditor.h"

namespace {

const char* kXmlComment =
    "<!--\n"
    "Copyright 2017 The Chromium Authors. All rights reserved.\n"
    "Use of this source code is governed by a BSD-style license that can be\n"
    "found in the LICENSE file.\n"
    "\nRefer to README.md for content description and update process.\n"
    "-->\n\n";

const base::FilePath kAnnotationsXmlPath(
    FILE_PATH_LITERAL("tools/traffic_annotation/summary/annotations.xml"));

}  // namespace

TrafficAnnotationExporter::ReportItem::ReportItem()
    : unique_id_hash_code(-1), content_hash_code(-1) {}

TrafficAnnotationExporter::ReportItem::ReportItem(
    const TrafficAnnotationExporter::ReportItem& other)
    : unique_id_hash_code(other.unique_id_hash_code),
      deprecation_date(other.deprecation_date),
      content_hash_code(other.content_hash_code),
      os_list(other.os_list) {}

TrafficAnnotationExporter::ReportItem::~ReportItem() {}

TrafficAnnotationExporter::TrafficAnnotationExporter(
    const base::FilePath& source_path)
    : source_path_(source_path), modified_(false) {}

TrafficAnnotationExporter::~TrafficAnnotationExporter() {}

bool TrafficAnnotationExporter::LoadAnnotationsXML() {
  report_items_.clear();
  XmlReader reader;
  if (!reader.LoadFile(
          source_path_.Append(kAnnotationsXmlPath).MaybeAsASCII())) {
    LOG(ERROR) << "Could not load '"
               << source_path_.Append(kAnnotationsXmlPath).MaybeAsASCII()
               << "'.";
    return false;
  }

  bool all_ok = false;
  while (reader.Read()) {
    all_ok = true;
    if (reader.NodeName() != "item")
      continue;

    ReportItem item;
    std::string temp;
    std::string unique_id;

    all_ok &= reader.NodeAttribute("id", &unique_id);
    all_ok &= reader.NodeAttribute("hash_code", &temp) &&
              base::StringToInt(temp, &item.unique_id_hash_code);
    if (all_ok && reader.NodeAttribute("content_hash_code", &temp))
      all_ok &= base::StringToInt(temp, &item.content_hash_code);
    else
      item.content_hash_code = -1;

    reader.NodeAttribute("deprecated", &item.deprecation_date);

    if (reader.NodeAttribute("os_list", &temp)) {
      item.os_list = base::SplitString(temp, ",", base::TRIM_WHITESPACE,
                                       base::SPLIT_WANT_NONEMPTY);
    }

    if (!all_ok) {
      LOG(ERROR) << "Unexpected format in annotations.xml.";
      break;
    }

    report_items_.insert(std::make_pair(unique_id, item));
  }

  modified_ = false;
  return all_ok;
}

bool TrafficAnnotationExporter::UpdateAnnotations(
    const std::vector<AnnotationInstance>& annotations,
    const std::map<int, std::string>& reserved_ids) {
  std::string platform;
#if defined(OS_LINUX)
  platform = "linux";
#elif defined(OS_WIN)
  platform = "windows";
#else
  NOTREACHED() << "Other platforms are not supported yet.";
#endif

  if (report_items_.empty() && !LoadAnnotationsXML())
    return false;

  // Iterate current annotations and add/update.
  for (AnnotationInstance annotation : annotations) {
    // Source tag is not used in computing the hashcode, as we don't need
    // sensitivity to changes in source location (filepath, line number,
    // and function).
    std::string content;
    annotation.proto.clear_source();
    google::protobuf::TextFormat::PrintToString(annotation.proto, &content);
    int content_hash_code = TrafficAnnotationAuditor::ComputeHashValue(content);

    if (base::ContainsKey(report_items_, annotation.proto.unique_id())) {
      ReportItem* current = &report_items_[annotation.proto.unique_id()];
      if (!base::ContainsValue(current->os_list, platform)) {
        current->os_list.push_back(platform);
        modified_ = true;
      }
    } else {
      ReportItem new_item;
      new_item.unique_id_hash_code = annotation.unique_id_hash_code;
      new_item.content_hash_code = content_hash_code;
      new_item.os_list.push_back(platform);
      report_items_[annotation.proto.unique_id()] = new_item;
      modified_ = true;
    }
  }

  // If there is a new reserved id, add it.
  for (const auto& item : reserved_ids) {
    if (!base::ContainsKey(report_items_, item.second)) {
      ReportItem new_item;
      new_item.unique_id_hash_code = item.first;
      new_item.os_list.push_back("all");
      report_items_[item.second] = new_item;
      modified_ = true;
    }
  }

  // If there are annotations that are not used in any OS, set the deprecation
  // flag.
  for (auto& item : report_items_) {
    if (item.second.os_list.empty() && item.second.deprecation_date.empty()) {
      base::Time::Exploded now;
      base::Time::Now().UTCExplode(&now);
      item.second.deprecation_date = base::StringPrintf(
          "%i-%02i-%02i", now.year, now.month, now.day_of_month);
      modified_ = true;
    }
  }

  return CheckReportItems();
}

bool TrafficAnnotationExporter::SaveAnnotationsXML() {
  XmlWriter writer;
  writer.StartWriting();
  writer.StartElement("annotations");

  for (const auto& item : report_items_) {
    writer.StartElement("item");
    writer.AddAttribute("id", item.first);
    writer.AddAttribute(
        "hash_code", base::StringPrintf("%i", item.second.unique_id_hash_code));
    if (!item.second.deprecation_date.empty())
      writer.AddAttribute("deprecated", item.second.deprecation_date);
    if (item.second.content_hash_code == -1)
      writer.AddAttribute("reserved", "1");
    else
      writer.AddAttribute(
          "content_hash_code",
          base::StringPrintf("%i", item.second.content_hash_code));
    std::string os_list;
    for (const std::string& platform : item.second.os_list)
      os_list += platform + ",";
    if (!os_list.empty()) {
      os_list.pop_back();
      writer.AddAttribute("os_list", os_list);
    }
    writer.EndElement();
  }
  writer.EndElement();

  writer.StopWriting();
  std::string xml_content = writer.GetWrittenString();
  // Add comment before annotation tag (and after xml version).
  xml_content.insert(xml_content.find("<annotations>"), kXmlComment);

  return base::WriteFile(source_path_.Append(kAnnotationsXmlPath),
                         xml_content.c_str(), xml_content.length()) != -1;
}

bool TrafficAnnotationExporter::GetDeprecatedHashCodes(
    std::set<int>* hash_codes) {
  if (report_items_.empty() && !LoadAnnotationsXML())
    return false;

  hash_codes->clear();
  for (const auto& item : report_items_) {
    if (!item.second.deprecation_date.empty())
      hash_codes->insert(item.second.unique_id_hash_code);
  }
  return true;
}

bool TrafficAnnotationExporter::CheckReportItems() {
  // Check for annotation hash code duplications.
  std::set<int> used_codes;
  for (auto& item : report_items_) {
    if (base::ContainsKey(used_codes, item.second.unique_id_hash_code)) {
      LOG(ERROR) << "Unique id hash code " << item.second.unique_id_hash_code
                 << " is used more than once.";
      return false;
    } else {
      used_codes.insert(item.second.unique_id_hash_code);
    }
  }

  // Check for coexistence of OS(es) and deprecation date.
  for (auto& item : report_items_) {
    if (!item.second.deprecation_date.empty() && !item.second.os_list.empty()) {
      LOG(ERROR) << "Annotation " << item.first
                 << " has a deprecation date and at least one active OS.";
      return false;
    }
  }
  return true;
}