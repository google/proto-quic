// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/process/process_info.h"

#include <windows.h>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/time/time.h"
#include "base/win/scoped_handle.h"

namespace base {

namespace {

HANDLE GetCurrentProcessToken() {
  HANDLE process_token;
  OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &process_token);
  DCHECK(process_token != NULL && process_token != INVALID_HANDLE_VALUE);
  return process_token;
}

}  // namespace

// static
const Time CurrentProcessInfo::CreationTime() {
  FILETIME creation_time = {};
  FILETIME ignore1 = {};
  FILETIME ignore2 = {};
  FILETIME ignore3 = {};
  if (!::GetProcessTimes(::GetCurrentProcess(), &creation_time, &ignore1,
                         &ignore2, &ignore3)) {
    return Time();
  }
  return Time::FromFileTime(creation_time);
}

IntegrityLevel GetCurrentProcessIntegrityLevel() {
  base::win::ScopedHandle scoped_process_token(GetCurrentProcessToken());

  DWORD token_info_length = 0;
  if (::GetTokenInformation(scoped_process_token.Get(), TokenIntegrityLevel,
                            nullptr, 0, &token_info_length) ||
      ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    return INTEGRITY_UNKNOWN;
  }

  auto token_label_bytes = MakeUnique<char[]>(token_info_length);
  TOKEN_MANDATORY_LABEL* token_label =
      reinterpret_cast<TOKEN_MANDATORY_LABEL*>(token_label_bytes.get());
  if (!::GetTokenInformation(scoped_process_token.Get(), TokenIntegrityLevel,
                             token_label, token_info_length,
                             &token_info_length)) {
    return INTEGRITY_UNKNOWN;
  }

  DWORD integrity_level = *::GetSidSubAuthority(
      token_label->Label.Sid,
      static_cast<DWORD>(*::GetSidSubAuthorityCount(token_label->Label.Sid) -
                         1));

  if (integrity_level < SECURITY_MANDATORY_MEDIUM_RID)
    return LOW_INTEGRITY;

  if (integrity_level >= SECURITY_MANDATORY_MEDIUM_RID &&
      integrity_level < SECURITY_MANDATORY_HIGH_RID) {
    return MEDIUM_INTEGRITY;
  }

  if (integrity_level >= SECURITY_MANDATORY_HIGH_RID)
    return HIGH_INTEGRITY;

  NOTREACHED();
  return INTEGRITY_UNKNOWN;
}

bool IsCurrentProcessElevated() {
  base::win::ScopedHandle scoped_process_token(GetCurrentProcessToken());

  // Unlike TOKEN_ELEVATION_TYPE which returns TokenElevationTypeDefault when
  // UAC is turned off, TOKEN_ELEVATION returns whether the process is elevated.
  DWORD size;
  TOKEN_ELEVATION elevation;
  if (!GetTokenInformation(scoped_process_token.Get(), TokenElevation,
                           &elevation, sizeof(elevation), &size)) {
    PLOG(ERROR) << "GetTokenInformation() failed";
    return false;
  }
  return !!elevation.TokenIsElevated;
}

}  // namespace base
