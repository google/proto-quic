// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/test_file_util.h"

#include <aclapi.h>
#include <shlwapi.h>
#include <stddef.h>
#include <wchar.h>
#include <windows.h>

#include <memory>
#include <vector>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string_split.h"
#include "base/threading/platform_thread.h"
#include "base/win/scoped_handle.h"

namespace base {

namespace {

struct PermissionInfo {
  PSECURITY_DESCRIPTOR security_descriptor;
  ACL dacl;
};

// Gets a blob indicating the permission information for |path|.
// |length| is the length of the blob.  Zero on failure.
// Returns the blob pointer, or NULL on failure.
void* GetPermissionInfo(const FilePath& path, size_t* length) {
  DCHECK(length != NULL);
  *length = 0;
  PACL dacl = NULL;
  PSECURITY_DESCRIPTOR security_descriptor;
  if (GetNamedSecurityInfo(const_cast<wchar_t*>(path.value().c_str()),
                           SE_FILE_OBJECT,
                           DACL_SECURITY_INFORMATION, NULL, NULL, &dacl,
                           NULL, &security_descriptor) != ERROR_SUCCESS) {
    return NULL;
  }
  DCHECK(dacl != NULL);

  *length = sizeof(PSECURITY_DESCRIPTOR) + dacl->AclSize;
  PermissionInfo* info = reinterpret_cast<PermissionInfo*>(new char[*length]);
  info->security_descriptor = security_descriptor;
  memcpy(&info->dacl, dacl, dacl->AclSize);

  return info;
}

// Restores the permission information for |path|, given the blob retrieved
// using |GetPermissionInfo()|.
// |info| is the pointer to the blob.
// |length| is the length of the blob.
// Either |info| or |length| may be NULL/0, in which case nothing happens.
bool RestorePermissionInfo(const FilePath& path, void* info, size_t length) {
  if (!info || !length)
    return false;

  PermissionInfo* perm = reinterpret_cast<PermissionInfo*>(info);

  DWORD rc = SetNamedSecurityInfo(const_cast<wchar_t*>(path.value().c_str()),
                                  SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                  NULL, NULL, &perm->dacl, NULL);
  LocalFree(perm->security_descriptor);

  char* char_array = reinterpret_cast<char*>(info);
  delete [] char_array;

  return rc == ERROR_SUCCESS;
}

std::unique_ptr<wchar_t[]> ToCStr(const std::basic_string<wchar_t>& str) {
  size_t size = str.size() + 1;
  std::unique_ptr<wchar_t[]> ptr = base::MakeUnique<wchar_t[]>(size);
  wcsncpy(ptr.get(), str.c_str(), size);
  return ptr;
}

}  // namespace

bool DieFileDie(const FilePath& file, bool recurse) {
  // It turns out that to not induce flakiness a long timeout is needed.
  const int kIterations = 25;
  const TimeDelta kTimeout = TimeDelta::FromSeconds(10) / kIterations;

  if (!PathExists(file))
    return true;

  // Sometimes Delete fails, so try a few more times. Divide the timeout
  // into short chunks, so that if a try succeeds, we won't delay the test
  // for too long.
  for (int i = 0; i < kIterations; ++i) {
    if (DeleteFile(file, recurse))
      return true;
    PlatformThread::Sleep(kTimeout);
  }
  return false;
}

bool EvictFileFromSystemCache(const FilePath& file) {
  base::win::ScopedHandle file_handle(
      CreateFile(file.value().c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL,
                 OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL));
  if (!file_handle.IsValid())
    return false;

  // Re-write the file time information to trigger cache eviction for the file.
  // This function previously overwrote the entire file without buffering, but
  // local experimentation validates this simplified and *much* faster approach:
  // [1] Sysinternals RamMap no longer lists these files as cached afterwards.
  // [2] Telemetry performance test startup.cold.blank_page reports sane values.
  BY_HANDLE_FILE_INFORMATION bhi = {0};
  CHECK(::GetFileInformationByHandle(file_handle.Get(), &bhi));
  CHECK(::SetFileTime(file_handle.Get(), &bhi.ftCreationTime,
                      &bhi.ftLastAccessTime, &bhi.ftLastWriteTime));
  return true;
}

// Deny |permission| on the file |path|, for the current user.
bool DenyFilePermission(const FilePath& path, DWORD permission) {
  PACL old_dacl;
  PSECURITY_DESCRIPTOR security_descriptor;

  std::unique_ptr<TCHAR[]> path_ptr = ToCStr(path.value());
  if (GetNamedSecurityInfo(path_ptr.get(), SE_FILE_OBJECT,
                           DACL_SECURITY_INFORMATION, nullptr, nullptr,
                           &old_dacl, nullptr,
                           &security_descriptor) != ERROR_SUCCESS) {
    return false;
  }

  std::unique_ptr<TCHAR[]> current_user = ToCStr(std::wstring(L"CURRENT_USER"));
  EXPLICIT_ACCESS new_access = {
      permission,
      DENY_ACCESS,
      0,
      {nullptr, NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_NAME, TRUSTEE_IS_USER,
       current_user.get()}};

  PACL new_dacl;
  if (SetEntriesInAcl(1, &new_access, old_dacl, &new_dacl) != ERROR_SUCCESS) {
    LocalFree(security_descriptor);
    return false;
  }

  DWORD rc = SetNamedSecurityInfo(path_ptr.get(), SE_FILE_OBJECT,
                                  DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                  new_dacl, nullptr);
  LocalFree(security_descriptor);
  LocalFree(new_dacl);

  return rc == ERROR_SUCCESS;
}

// Checks if the volume supports Alternate Data Streams. This is required for
// the Zone Identifier implementation.
bool VolumeSupportsADS(const FilePath& path) {
  wchar_t drive[MAX_PATH] = {0};
  wcscpy_s(drive, MAX_PATH, path.value().c_str());

  if (!PathStripToRootW(drive))
    return false;

  DWORD fs_flags = 0;
  if (!GetVolumeInformationW(drive, NULL, 0, 0, NULL, &fs_flags, NULL, 0))
    return false;

  if (fs_flags & FILE_NAMED_STREAMS)
    return true;

  return false;
}

// Return whether the ZoneIdentifier is correctly set to "Internet" (3)
// Only returns a valid result when called from same process as the
// one that (was supposed to have) set the zone identifier.
bool HasInternetZoneIdentifier(const FilePath& full_path) {
  FilePath zone_path(full_path.value() + L":Zone.Identifier");
  std::string zone_path_contents;
  if (!ReadFileToString(zone_path, &zone_path_contents))
    return false;

  std::vector<std::string> lines = SplitString(
      zone_path_contents, "\n", TRIM_WHITESPACE, SPLIT_WANT_ALL);
  switch (lines.size()) {
    case 3:
      // optional empty line at end of file:
      if (!lines[2].empty())
        return false;
      // fall through:
    case 2:
      return lines[0] == "[ZoneTransfer]" && lines[1] == "ZoneId=3";
    default:
      return false;
  }
}

bool MakeFileUnreadable(const FilePath& path) {
  return DenyFilePermission(path, GENERIC_READ);
}

bool MakeFileUnwritable(const FilePath& path) {
  return DenyFilePermission(path, GENERIC_WRITE);
}

FilePermissionRestorer::FilePermissionRestorer(const FilePath& path)
    : path_(path), info_(NULL), length_(0) {
  info_ = GetPermissionInfo(path_, &length_);
  DCHECK(info_ != NULL);
  DCHECK_NE(0u, length_);
}

FilePermissionRestorer::~FilePermissionRestorer() {
  if (!RestorePermissionInfo(path_, info_, length_))
    NOTREACHED();
}

}  // namespace base
