// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/simple/simple_util.h"

#include <limits>

#include "base/files/file_util.h"
#include "base/format_macros.h"
#include "base/logging.h"
#include "base/numerics/safe_conversions.h"
#include "base/sha1.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_restrictions.h"
#include "base/time/time.h"
#include "net/disk_cache/simple/simple_entry_format.h"

namespace {

// Size of the uint64_t hash_key number in Hex format in a string.
const size_t kEntryHashKeyAsHexStringSize = 2 * sizeof(uint64_t);

#if defined(OS_POSIX)
// TODO(clamy, gavinp): this should go in base
bool GetNanoSecsFromStat(const struct stat& st,
                         time_t* out_sec,
                         long* out_nsec) {
#if defined(OS_ANDROID)
  *out_sec = st.st_mtime;
  *out_nsec = st.st_mtime_nsec;
  return true;
#elif defined(OS_LINUX)
  *out_sec = st.st_mtim.tv_sec;
  *out_nsec = st.st_mtim.tv_nsec;
  return true;
#elif defined(OS_MACOSX) || defined(OS_IOS) || defined(OS_BSD)
  *out_sec = st.st_mtimespec.tv_sec;
  *out_nsec = st.st_mtimespec.tv_nsec;
  return true;
#else
  return false;
#endif
}
#endif  // defined(OS_POSIX)

}  // namespace

namespace disk_cache {

namespace simple_util {

std::string ConvertEntryHashKeyToHexString(uint64_t hash_key) {
  const std::string hash_key_str = base::StringPrintf("%016" PRIx64, hash_key);
  DCHECK_EQ(kEntryHashKeyAsHexStringSize, hash_key_str.size());
  return hash_key_str;
}

std::string GetEntryHashKeyAsHexString(const std::string& key) {
  std::string hash_key_str =
      ConvertEntryHashKeyToHexString(GetEntryHashKey(key));
  DCHECK_EQ(kEntryHashKeyAsHexStringSize, hash_key_str.size());
  return hash_key_str;
}

bool GetEntryHashKeyFromHexString(const base::StringPiece& hash_key,
                                  uint64_t* hash_key_out) {
  if (hash_key.size() != kEntryHashKeyAsHexStringSize) {
    return false;
  }
  return base::HexStringToUInt64(hash_key, hash_key_out);
}

uint64_t GetEntryHashKey(const std::string& key) {
  union {
    unsigned char sha_hash[base::kSHA1Length];
    uint64_t key_hash;
  } u;
  base::SHA1HashBytes(reinterpret_cast<const unsigned char*>(key.data()),
                      key.size(), u.sha_hash);
  return u.key_hash;
}

std::string GetFilenameFromEntryHashAndFileIndex(uint64_t entry_hash,
                                                 int file_index) {
  return base::StringPrintf("%016" PRIx64 "_%1d", entry_hash, file_index);
}

std::string GetSparseFilenameFromEntryHash(uint64_t entry_hash) {
  return base::StringPrintf("%016" PRIx64 "_s", entry_hash);
}

std::string GetFilenameFromKeyAndFileIndex(const std::string& key,
                                           int file_index) {
  return GetEntryHashKeyAsHexString(key) +
         base::StringPrintf("_%1d", file_index);
}

size_t GetHeaderSize(size_t key_length) {
  return sizeof(SimpleFileHeader) + key_length;
}

int32_t GetDataSizeFromFileSize(size_t key_length, int64_t file_size) {
  int64_t data_size =
      file_size - key_length - sizeof(SimpleFileHeader) - sizeof(SimpleFileEOF);
  return base::checked_cast<int32_t>(data_size);
}

int64_t GetFileSizeFromDataSize(size_t key_length, int32_t data_size) {
  return data_size + key_length + sizeof(SimpleFileHeader) +
         sizeof(SimpleFileEOF);
}

int GetFileIndexFromStreamIndex(int stream_index) {
  return (stream_index == 2) ? 1 : 0;
}

// TODO(clamy, gavinp): this should go in base
bool GetMTime(const base::FilePath& path, base::Time* out_mtime) {
  DCHECK(out_mtime);
#if defined(OS_POSIX)
  base::ThreadRestrictions::AssertIOAllowed();
  struct stat file_stat;
  if (stat(path.value().c_str(), &file_stat) != 0)
    return false;
  time_t sec;
  long nsec;
  if (GetNanoSecsFromStat(file_stat, &sec, &nsec)) {
    int64_t usec = (nsec / base::Time::kNanosecondsPerMicrosecond);
    *out_mtime = base::Time::FromTimeT(sec)
        + base::TimeDelta::FromMicroseconds(usec);
    return true;
  }
#endif
  base::File::Info file_info;
  if (!base::GetFileInfo(path, &file_info))
    return false;
  *out_mtime = file_info.last_modified;
  return true;
}

}  // namespace simple_backend

}  // namespace disk_cache
