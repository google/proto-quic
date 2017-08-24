// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>

#include "tools/traffic_annotation/auditor/auditor_result.h"

#include "base/strings/stringprintf.h"

const int AuditorResult::kNoCodeLineSpecified = -1;

AuditorResult::AuditorResult(Type type,
                             const std::string& message,
                             const std::string& file_path,
                             int line)
    : type_(type), file_path_(file_path), line_(line) {
  DCHECK(line != kNoCodeLineSpecified ||
         type == AuditorResult::Type::RESULT_OK ||
         type == AuditorResult::Type::RESULT_IGNORE ||
         type == AuditorResult::Type::ERROR_FATAL ||
         type == AuditorResult::Type::ERROR_DUPLICATE_UNIQUE_ID_HASH_CODE ||
         type == AuditorResult::Type::ERROR_MERGE_FAILED);
  DCHECK(!message.empty() || type == AuditorResult::Type::RESULT_OK ||
         type == AuditorResult::Type::RESULT_IGNORE ||
         type == AuditorResult::Type::ERROR_MISSING ||
         type == AuditorResult::Type::ERROR_NO_ANNOTATION ||
         type == AuditorResult::Type::ERROR_MISSING_EXTRA_ID ||
         type == AuditorResult::Type::ERROR_INCOMPLETED_ANNOTATION);
  if (!message.empty())
    details_.push_back(message);
};

AuditorResult::AuditorResult(Type type, const std::string& message)
    : AuditorResult::AuditorResult(type,
                                   message,
                                   std::string(),
                                   kNoCodeLineSpecified) {}

AuditorResult::AuditorResult(Type type)
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
    case AuditorResult::Type::ERROR_FATAL:
      DCHECK(details_.size());
      return details_[0];

    case AuditorResult::Type::ERROR_MISSING:
      return base::StringPrintf("Missing annotation in '%s', line %i.",
                                file_path_.c_str(), line_);

    case AuditorResult::Type::ERROR_NO_ANNOTATION:
      return base::StringPrintf("Empty annotation in '%s', line %i.",
                                file_path_.c_str(), line_);

    case AuditorResult::Type::ERROR_SYNTAX: {
      DCHECK(details_.size());
      std::string flat_message(details_[0]);
      std::replace(flat_message.begin(), flat_message.end(), '\n', ' ');
      return base::StringPrintf("Syntax error in '%s': %s", file_path_.c_str(),
                                flat_message.c_str());
    }

    case AuditorResult::Type::ERROR_RESERVED_UNIQUE_ID_HASH_CODE:
      DCHECK(details_.size());
      return base::StringPrintf(
          "Unique id '%s' in '%s:%i' has a hash code similar to a reserved "
          "word and should be changed.",
          details_[0].c_str(), file_path_.c_str(), line_);

    case AuditorResult::Type::ERROR_DUPLICATE_UNIQUE_ID_HASH_CODE:
      DCHECK_EQ(details_.size(), 2u);
      return base::StringPrintf(
          "The following annotations have similar unique id "
          "hash codes and should be updated: %s, %s.",
          details_[0].c_str(), details_[1].c_str());

    case AuditorResult::Type::ERROR_UNIQUE_ID_INVALID_CHARACTER:
      DCHECK(details_.size());
      return base::StringPrintf(
          "Unique id '%s' in '%s:%i' contains an invalid character.",
          details_[0].c_str(), file_path_.c_str(), line_);

    case AuditorResult::Type::ERROR_MISSING_ANNOTATION:
      DCHECK(details_.size());
      return base::StringPrintf("Function '%s' in '%s:%i' requires annotation.",
                                details_[0].c_str(), file_path_.c_str(), line_);

    case AuditorResult::Type::ERROR_INCOMPLETE_ANNOTATION:
      DCHECK(details_.size());
      return base::StringPrintf(
          "Annotation at '%s:%i' has the following missing fields: %s",
          file_path_.c_str(), line_, details_[0].c_str());

    case AuditorResult::Type::ERROR_MISSING_EXTRA_ID:
      return base::StringPrintf(
          "Second id of annotation at '%s:%i' should be updated as it has the "
          "same hash code as the first one.",
          file_path_.c_str(), line_);

    case AuditorResult::Type::ERROR_INCONSISTENT_ANNOTATION:
      DCHECK(details_.size());
      return base::StringPrintf(
          "Annotation at '%s:%i' has the following inconsistencies: %s",
          file_path_.c_str(), line_, details_[0].c_str());

    case AuditorResult::Type::ERROR_MERGE_FAILED:
      DCHECK(details_.size() == 3);
      return base::StringPrintf(
          "Annotations '%s' and '%s' cannot be merged due to the following "
          "error(s): %s",
          details_[1].c_str(), details_[2].c_str(), details_[0].c_str());

    case AuditorResult::Type::ERROR_INCOMPLETED_ANNOTATION:
      return base::StringPrintf("Annotation at '%s:%i' is never completed.",
                                file_path_.c_str(), line_);

    default:
      return std::string();
  }
}

std::string AuditorResult::ToShortText() const {
  switch (type_) {
    case AuditorResult::Type::ERROR_INCOMPLETE_ANNOTATION:
      DCHECK(details_.size());
      return base::StringPrintf("the following fields are missing: %s",
                                details_[0].c_str());

    case AuditorResult::Type::ERROR_INCONSISTENT_ANNOTATION:
      DCHECK(details_.size());
      return base::StringPrintf("the following inconsistencies: %s",
                                details_[0].c_str());

    default:
      NOTREACHED();
      return std::string();
  }
}
