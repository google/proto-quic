// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DISK_CACHE_SIMPLE_SIMPLE_UTIL_H_
#define NET_DISK_CACHE_SIMPLE_SIMPLE_UTIL_H_

#include <stdint.h>

#include <string>

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"

namespace base {
class FilePath;
class Time;
}

namespace disk_cache {

namespace simple_util {

NET_EXPORT_PRIVATE std::string ConvertEntryHashKeyToHexString(
    uint64_t hash_key);

// |key| is the regular cache key, such as an URL.
// Returns the Hex ascii representation of the uint64_t hash_key.
NET_EXPORT_PRIVATE std::string GetEntryHashKeyAsHexString(
    const std::string& key);

// |key| is the regular HTTP Cache key, which is a URL.
// Returns the hash of the key as uint64_t.
NET_EXPORT_PRIVATE uint64_t GetEntryHashKey(const std::string& key);

// Parses the |hash_key| string into a uint64_t buffer.
// |hash_key| string must be of the form: FFFFFFFFFFFFFFFF .
NET_EXPORT_PRIVATE bool GetEntryHashKeyFromHexString(
    const base::StringPiece& hash_key,
    uint64_t* hash_key_out);

// Given a |key| for a (potential) entry in the simple backend and the |index|
// of a stream on that entry, returns the filename in which that stream would be
// stored.
NET_EXPORT_PRIVATE std::string GetFilenameFromKeyAndFileIndex(
    const std::string& key,
    int file_index);

// Same as |GetFilenameFromKeyAndIndex| above, but using a hex string.
std::string GetFilenameFromEntryHashAndFileIndex(uint64_t entry_hash,
                                                 int file_index);

// Given a |key| for an entry, returns the name of the sparse data file.
std::string GetSparseFilenameFromEntryHash(uint64_t entry_hash);

// Given the size of a key, the size in bytes of the header at the beginning
// of a simple cache file.
size_t GetHeaderSize(size_t key_length);

// Given the size of a file holding a stream in the simple backend and the key
// to an entry, returns the number of bytes in the stream.
NET_EXPORT_PRIVATE int32_t GetDataSizeFromFileSize(size_t key_length,
                                                   int64_t file_size);

// Given the size of a stream in the simple backend and the key to an entry,
// returns the number of bytes in the file.
NET_EXPORT_PRIVATE int64_t GetFileSizeFromDataSize(size_t key_length,
                                                   int32_t data_size);

// Given the stream index, returns the number of the file the stream is stored
// in.
NET_EXPORT_PRIVATE int GetFileIndexFromStreamIndex(int stream_index);

// Fills |out_time| with the time the file last modified time. Unlike the
// functions in file.h, the time resolution is milliseconds.
NET_EXPORT_PRIVATE bool GetMTime(const base::FilePath& path,
                                 base::Time* out_mtime);

// Deletes a file, insuring POSIX semantics. Provided that all open handles to
// this file were opened with File::FLAG_SHARE_DELETE, it is possible to delete
// an open file and continue to use that file. After deleting an open file, it
// is possible to immediately create a new file with the same name.
NET_EXPORT_PRIVATE bool SimpleCacheDeleteFile(const base::FilePath& path);

}  // namespace simple_util

}  // namespace disk_cache

#endif  // NET_DISK_CACHE_SIMPLE_SIMPLE_UTIL_H_
