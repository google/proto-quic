// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DISK_CACHE_SIMPLE_SIMPLE_ENTRY_FORMAT_H_
#define NET_DISK_CACHE_SIMPLE_SIMPLE_ENTRY_FORMAT_H_

#include <stdint.h>

#include "net/base/net_export.h"

namespace base {
class Time;
}

namespace disk_cache {

const uint64_t kSimpleInitialMagicNumber = UINT64_C(0xfcfb6d1ba7725c30);
const uint64_t kSimpleFinalMagicNumber = UINT64_C(0xf4fa6f45970d41d8);
const uint64_t kSimpleSparseRangeMagicNumber = UINT64_C(0xeb97bf016553676b);

// A file containing stream 0 and stream 1 in the Simple cache consists of:
//   - a SimpleFileHeader.
//   - the key.
//   - the data from stream 1.
//   - a SimpleFileEOF record for stream 1.
//   - the data from stream 0.
//   - (optionally) the SHA256 of the key.
//   - a SimpleFileEOF record for stream 0.
//
// Because stream 0 data (typically HTTP headers) is on the critical path of
// requests, on open, the cache reads the end of the record and does not
// read the SimpleFileHeader. If the key can be validated with a SHA256, then
// the stream 0 data can be returned to the caller without reading the
// SimpleFileHeader. If the key SHA256 is not present, then the cache must
// read the SimpleFileHeader to confirm key equality.

// A file containing stream 2 in the Simple cache consists of:
//   - a SimpleFileHeader.
//   - the key.
//   - the data.
//   - at the end, a SimpleFileEOF record.
static const int kSimpleEntryFileCount = 2;
static const int kSimpleEntryStreamCount = 3;

struct NET_EXPORT_PRIVATE SimpleFileHeader {
  SimpleFileHeader();

  uint64_t initial_magic_number;
  uint32_t version;
  uint32_t key_length;
  uint32_t key_hash;
};

struct NET_EXPORT_PRIVATE SimpleFileEOF {
  enum Flags {
    FLAG_HAS_CRC32 = (1U << 0),
    FLAG_HAS_KEY_SHA256 = (1U << 1),  // Preceding the record if present.
  };

  SimpleFileEOF();

  uint64_t final_magic_number;
  uint32_t flags;
  uint32_t data_crc32;
  // |stream_size| is only used in the EOF record for stream 0.
  uint32_t stream_size;
};

struct SimpleFileSparseRangeHeader {
  SimpleFileSparseRangeHeader();

  uint64_t sparse_range_magic_number;
  int64_t offset;
  int64_t length;
  uint32_t data_crc32;
};

}  // namespace disk_cache

#endif  // NET_DISK_CACHE_SIMPLE_SIMPLE_ENTRY_FORMAT_H_
