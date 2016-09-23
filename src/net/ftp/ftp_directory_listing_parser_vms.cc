// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ftp/ftp_directory_listing_parser_vms.h"

#include <vector>

#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/time/time.h"
#include "net/ftp/ftp_directory_listing_parser.h"
#include "net/ftp/ftp_util.h"

namespace net {

namespace {

// Converts the filename component in listing to the filename we can display.
// Returns true on success.
bool ParseVmsFilename(const base::string16& raw_filename,
                      base::string16* parsed_filename,
                      FtpDirectoryListingEntry::Type* type) {
  // On VMS, the files and directories are versioned. The version number is
  // separated from the file name by a semicolon. Example: ANNOUNCE.TXT;2.
  std::vector<base::string16> listing_parts =
      base::SplitString(raw_filename, base::ASCIIToUTF16(";"),
                        base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (listing_parts.size() != 2)
    return false;
  int version_number;
  if (!base::StringToInt(listing_parts[1], &version_number))
    return false;
  if (version_number < 0)
    return false;

  // Even directories have extensions in the listings. Don't display extensions
  // for directories; it's awkward for non-VMS users. Also, VMS is
  // case-insensitive, but generally uses uppercase characters. This may look
  // awkward, so we convert them to lower case.
  std::vector<base::string16> filename_parts =
      base::SplitString(listing_parts[0], base::ASCIIToUTF16("."),
                        base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (filename_parts.size() != 2)
    return false;
  if (base::EqualsASCII(filename_parts[1], "DIR")) {
    *parsed_filename = base::ToLowerASCII(filename_parts[0]);
    *type = FtpDirectoryListingEntry::DIRECTORY;
  } else {
    *parsed_filename = base::ToLowerASCII(listing_parts[0]);
    *type = FtpDirectoryListingEntry::FILE;
  }
  return true;
}

bool ParseVmsFilesize(const base::string16& input, int64_t* size) {
  if (base::ContainsOnlyChars(input, base::ASCIIToUTF16("*"))) {
    // Response consisting of asterisks means unknown size.
    *size = -1;
    return true;
  }

  // VMS's directory listing gives us file size in blocks. We assume that
  // the block size is 512 bytes. It doesn't give accurate file size, but is the
  // best information we have.
  const int kBlockSize = 512;

  if (base::StringToInt64(input, size)) {
    if (*size < 0)
      return false;
    *size *= kBlockSize;
    return true;
  }

  std::vector<base::StringPiece16> parts =
      base::SplitStringPiece(input, base::ASCIIToUTF16("/"),
                             base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (parts.size() != 2)
    return false;

  int64_t blocks_used, blocks_allocated;
  if (!base::StringToInt64(parts[0], &blocks_used))
    return false;
  if (!base::StringToInt64(parts[1], &blocks_allocated))
    return false;
  if (blocks_used > blocks_allocated)
    return false;
  if (blocks_used < 0 || blocks_allocated < 0)
    return false;

  *size = blocks_used * kBlockSize;
  return true;
}

bool LooksLikeVmsFileProtectionListingPart(const base::string16& input) {
  if (input.length() > 4)
    return false;

  // On VMS there are four different permission bits: Read, Write, Execute,
  // and Delete. They appear in that order in the permission listing.
  std::string pattern("RWED");
  base::string16 match(input);
  while (!match.empty() && !pattern.empty()) {
    if (match[0] == pattern[0])
      match = match.substr(1);
    pattern = pattern.substr(1);
  }
  return match.empty();
}

bool LooksLikeVmsFileProtectionListing(const base::string16& input) {
  if (input.length() < 2)
    return false;
  if (input.front() != '(' || input.back() != ')')
    return false;

  // We expect four parts of the file protection listing: for System, Owner,
  // Group, and World.
  std::vector<base::string16> parts = base::SplitString(
      base::StringPiece16(input).substr(1, input.length() - 2),
      base::ASCIIToUTF16(","), base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (parts.size() != 4)
    return false;

  return LooksLikeVmsFileProtectionListingPart(parts[0]) &&
      LooksLikeVmsFileProtectionListingPart(parts[1]) &&
      LooksLikeVmsFileProtectionListingPart(parts[2]) &&
      LooksLikeVmsFileProtectionListingPart(parts[3]);
}

bool LooksLikeVmsUserIdentificationCode(const base::string16& input) {
  if (input.length() < 2)
    return false;
  return input.front() == '[' && input.back() == ']';
}

bool LooksLikeVMSError(const base::string16& text) {
  static const char* const kPermissionDeniedMessages[] = {
    "%RMS-E-FNF",  // File not found.
    "%RMS-E-PRV",  // Access denied.
    "%SYSTEM-F-NOPRIV",
    "privilege",
  };

  for (size_t i = 0; i < arraysize(kPermissionDeniedMessages); i++) {
    if (text.find(base::ASCIIToUTF16(kPermissionDeniedMessages[i])) !=
        base::string16::npos)
      return true;
  }

  return false;
}

bool VmsDateListingToTime(const std::vector<base::string16>& columns,
                          base::Time* time) {
  DCHECK_EQ(4U, columns.size());

  base::Time::Exploded time_exploded = { 0 };

  // Date should be in format DD-MMM-YYYY.
  std::vector<base::StringPiece16> date_parts =
      base::SplitStringPiece(columns[2], base::ASCIIToUTF16("-"),
                             base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (date_parts.size() != 3)
    return false;
  if (!base::StringToInt(date_parts[0], &time_exploded.day_of_month))
    return false;
  if (!FtpUtil::AbbreviatedMonthToNumber(date_parts[1].as_string(),
                                         &time_exploded.month))
    return false;
  if (!base::StringToInt(date_parts[2], &time_exploded.year))
    return false;

  // Time can be in format HH:MM, HH:MM:SS, or HH:MM:SS.mm. Try to recognize the
  // last type first. Do not parse the seconds, they will be ignored anyway.
  base::string16 time_column(columns[3]);
  if (time_column.length() == 11 && time_column[8] == '.')
    time_column = time_column.substr(0, 8);
  if (time_column.length() == 8 && time_column[5] == ':')
    time_column = time_column.substr(0, 5);
  if (time_column.length() != 5)
    return false;
  std::vector<base::StringPiece16> time_parts =
      base::SplitStringPiece(time_column, base::ASCIIToUTF16(":"),
                             base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (time_parts.size() != 2)
    return false;
  if (!base::StringToInt(time_parts[0], &time_exploded.hour))
    return false;
  if (!base::StringToInt(time_parts[1], &time_exploded.minute))
    return false;

  // We don't know the time zone of the server, so just use local time.
  *time = base::Time::FromLocalExploded(time_exploded);
  return true;
}

}  // namespace

bool ParseFtpDirectoryListingVms(
    const std::vector<base::string16>& lines,
    std::vector<FtpDirectoryListingEntry>* entries) {
  // The first non-empty line is the listing header. It often
  // starts with "Directory ", but not always. We set a flag after
  // seing the header.
  bool seen_header = false;

  // Sometimes the listing doesn't end with a "Total" line, but
  // it's only okay when it contains some errors (it's needed
  // to distinguish it from "ls -l" format).
  bool seen_error = false;

  base::string16 total_of = base::ASCIIToUTF16("Total of ");
  base::char16 space[2] = { ' ', 0 };
  for (size_t i = 0; i < lines.size(); i++) {
    if (lines[i].empty())
      continue;

    if (base::StartsWith(lines[i], total_of, base::CompareCase::SENSITIVE)) {
      // After the "total" line, all following lines must be empty.
      for (size_t j = i + 1; j < lines.size(); j++)
        if (!lines[j].empty())
          return false;

      return true;
    }

    if (!seen_header) {
      seen_header = true;
      continue;
    }

    if (LooksLikeVMSError(lines[i])) {
      seen_error = true;
      continue;
    }

    std::vector<base::string16> columns = base::SplitString(
        base::CollapseWhitespace(lines[i], false), space,
        base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);

    if (columns.size() == 1) {
      // There can be no continuation if the current line is the last one.
      if (i == lines.size() - 1)
        return false;

      // Skip the next line.
      i++;

      // This refers to the continuation line.
      if (LooksLikeVMSError(lines[i])) {
        seen_error = true;
        continue;
      }

      // Join the current and next line and split them into columns.
      columns = base::SplitString(
          base::CollapseWhitespace(
              lines[i - 1] + space + lines[i], false),
          space, base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
    }

    if (columns.empty())
      return false;

    FtpDirectoryListingEntry entry;
    if (!ParseVmsFilename(columns[0], &entry.name, &entry.type))
      return false;

    // There are different variants of a VMS listing. Some display
    // the protection listing and user identification code, some do not.
    if (columns.size() == 6) {
      if (!LooksLikeVmsFileProtectionListing(columns[5]))
        return false;
      if (!LooksLikeVmsUserIdentificationCode(columns[4]))
        return false;

      // Drop the unneeded data, so that the following code can always expect
      // just four columns.
      columns.resize(4);
    }

    if (columns.size() != 4)
      return false;

    if (!ParseVmsFilesize(columns[1], &entry.size))
      return false;
    if (entry.type != FtpDirectoryListingEntry::FILE)
      entry.size = -1;
    if (!VmsDateListingToTime(columns, &entry.last_modified))
      return false;

    entries->push_back(entry);
  }

  // The only place where we return true is after receiving the "Total" line,
  // that should be present in every VMS listing. Alternatively, if the listing
  // contains error messages, it's OK not to have the "Total" line.
  return seen_error;
}

}  // namespace net
