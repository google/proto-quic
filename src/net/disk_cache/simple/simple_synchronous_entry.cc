// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/simple/simple_synchronous_entry.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <limits>

#include "base/compiler_specific.h"
#include "base/files/file_util.h"
#include "base/hash.h"
#include "base/location.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_conversions.h"
#include "base/sha1.h"
#include "base/timer/elapsed_timer.h"
#include "crypto/secure_hash.h"
#include "net/base/hash_value.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/disk_cache/simple/simple_backend_version.h"
#include "net/disk_cache/simple/simple_histogram_macros.h"
#include "net/disk_cache/simple/simple_util.h"
#include "third_party/zlib/zlib.h"

using base::File;
using base::FilePath;
using base::Time;

namespace {

// Used in histograms, please only add entries at the end.
enum OpenEntryResult {
  OPEN_ENTRY_SUCCESS = 0,
  OPEN_ENTRY_PLATFORM_FILE_ERROR = 1,
  OPEN_ENTRY_CANT_READ_HEADER = 2,
  OPEN_ENTRY_BAD_MAGIC_NUMBER = 3,
  OPEN_ENTRY_BAD_VERSION = 4,
  OPEN_ENTRY_CANT_READ_KEY = 5,
  OPEN_ENTRY_KEY_MISMATCH = 6,
  OPEN_ENTRY_KEY_HASH_MISMATCH = 7,
  OPEN_ENTRY_SPARSE_OPEN_FAILED = 8,
  OPEN_ENTRY_INVALID_FILE_LENGTH = 9,
  OPEN_ENTRY_MAX = 10,
};

// Used in histograms, please only add entries at the end.
enum WriteResult {
  WRITE_RESULT_SUCCESS = 0,
  WRITE_RESULT_PRETRUNCATE_FAILURE,
  WRITE_RESULT_WRITE_FAILURE,
  WRITE_RESULT_TRUNCATE_FAILURE,
  WRITE_RESULT_LAZY_STREAM_ENTRY_DOOMED,
  WRITE_RESULT_LAZY_CREATE_FAILURE,
  WRITE_RESULT_LAZY_INITIALIZE_FAILURE,
  WRITE_RESULT_MAX,
};

// Used in histograms, please only add entries at the end.
enum CheckEOFResult {
  CHECK_EOF_RESULT_SUCCESS,
  CHECK_EOF_RESULT_READ_FAILURE,
  CHECK_EOF_RESULT_MAGIC_NUMBER_MISMATCH,
  CHECK_EOF_RESULT_CRC_MISMATCH,
  CHECK_EOF_RESULT_KEY_SHA256_MISMATCH,
  CHECK_EOF_RESULT_MAX,
};

// Used in histograms, please only add entries at the end.
enum CloseResult {
  CLOSE_RESULT_SUCCESS,
  CLOSE_RESULT_WRITE_FAILURE,
  CLOSE_RESULT_MAX,
};

// Used in histograms, please only add entries at the end.
enum class KeySHA256Result { NOT_PRESENT, MATCHED, NO_MATCH, MAX };

void RecordSyncOpenResult(net::CacheType cache_type,
                          OpenEntryResult result,
                          bool had_index) {
  DCHECK_LT(result, OPEN_ENTRY_MAX);
  SIMPLE_CACHE_UMA(ENUMERATION,
                   "SyncOpenResult", cache_type, result, OPEN_ENTRY_MAX);
  if (had_index) {
    SIMPLE_CACHE_UMA(ENUMERATION,
                     "SyncOpenResult_WithIndex", cache_type,
                     result, OPEN_ENTRY_MAX);
  } else {
    SIMPLE_CACHE_UMA(ENUMERATION,
                     "SyncOpenResult_WithoutIndex", cache_type,
                     result, OPEN_ENTRY_MAX);
  }
}

void RecordWriteResult(net::CacheType cache_type, WriteResult result) {
  SIMPLE_CACHE_UMA(ENUMERATION,
                   "SyncWriteResult", cache_type, result, WRITE_RESULT_MAX);
}

void RecordCheckEOFResult(net::CacheType cache_type, CheckEOFResult result) {
  SIMPLE_CACHE_UMA(ENUMERATION,
                   "SyncCheckEOFResult", cache_type,
                   result, CHECK_EOF_RESULT_MAX);
}

void RecordCloseResult(net::CacheType cache_type, CloseResult result) {
  SIMPLE_CACHE_UMA(ENUMERATION,
                   "SyncCloseResult", cache_type, result, CLOSE_RESULT_MAX);
}

void RecordKeySHA256Result(net::CacheType cache_type, KeySHA256Result result) {
  SIMPLE_CACHE_UMA(ENUMERATION, "SyncKeySHA256Result", cache_type,
                   static_cast<int>(result),
                   static_cast<int>(KeySHA256Result::MAX));
}

bool CanOmitEmptyFile(int file_index) {
  DCHECK_GE(file_index, 0);
  DCHECK_LT(file_index, disk_cache::kSimpleEntryFileCount);
  return file_index == disk_cache::simple_util::GetFileIndexFromStreamIndex(2);
}

bool TruncatePath(const FilePath& filename_to_truncate) {
  File file_to_truncate;
  int flags = File::FLAG_OPEN | File::FLAG_READ | File::FLAG_WRITE |
              File::FLAG_SHARE_DELETE;
  file_to_truncate.Initialize(filename_to_truncate, flags);
  if (!file_to_truncate.IsValid())
    return false;
  if (!file_to_truncate.SetLength(0))
    return false;
  return true;
}

void CalculateSHA256OfKey(const std::string& key,
                          net::SHA256HashValue* out_hash_value) {
  std::unique_ptr<crypto::SecureHash> hash(
      crypto::SecureHash::Create(crypto::SecureHash::SHA256));
  hash->Update(key.data(), key.size());
  hash->Finish(out_hash_value, sizeof(*out_hash_value));
}

}  // namespace

namespace disk_cache {

using simple_util::GetEntryHashKey;
using simple_util::GetFilenameFromEntryHashAndFileIndex;
using simple_util::GetSparseFilenameFromEntryHash;
using simple_util::GetHeaderSize;
using simple_util::GetDataSizeFromFileSize;
using simple_util::GetFileSizeFromDataSize;
using simple_util::GetFileIndexFromStreamIndex;

SimpleEntryStat::SimpleEntryStat(base::Time last_used,
                                 base::Time last_modified,
                                 const int32_t data_size[],
                                 const int32_t sparse_data_size)
    : last_used_(last_used),
      last_modified_(last_modified),
      sparse_data_size_(sparse_data_size) {
  memcpy(data_size_, data_size, sizeof(data_size_));
}

// These size methods all assume the presence of the SHA256 on stream zero,
// since this version of the cache always writes it. In the read case, it may
// not be present and these methods can't be relied upon.

int SimpleEntryStat::GetOffsetInFile(size_t key_length,
                                     int offset,
                                     int stream_index) const {
  const size_t headers_size = sizeof(SimpleFileHeader) + key_length;
  const size_t additional_offset =
      stream_index == 0 ? data_size_[1] + sizeof(SimpleFileEOF) : 0;
  return headers_size + offset + additional_offset;
}

int SimpleEntryStat::GetEOFOffsetInFile(size_t key_length,
                                        int stream_index) const {
  size_t additional_offset;
  if (stream_index != 0)
    additional_offset = 0;
  else
    additional_offset = sizeof(net::SHA256HashValue);
  return additional_offset +
         GetOffsetInFile(key_length, data_size_[stream_index], stream_index);
}

int SimpleEntryStat::GetLastEOFOffsetInFile(size_t key_length,
                                            int stream_index) const {
  if (stream_index == 1)
    return GetEOFOffsetInFile(key_length, 0);
  return GetEOFOffsetInFile(key_length, stream_index);
}

int64_t SimpleEntryStat::GetFileSize(size_t key_length, int file_index) const {
  int32_t total_data_size;
  if (file_index == 0) {
    total_data_size = data_size_[0] + data_size_[1] +
                      sizeof(net::SHA256HashValue) + sizeof(SimpleFileEOF);
  } else {
    total_data_size = data_size_[2];
  }
  return GetFileSizeFromDataSize(key_length, total_data_size);
}

SimpleEntryCreationResults::SimpleEntryCreationResults(
    SimpleEntryStat entry_stat)
    : sync_entry(NULL),
      entry_stat(entry_stat),
      stream_0_crc32(crc32(0, Z_NULL, 0)),
      result(net::OK) {
}

SimpleEntryCreationResults::~SimpleEntryCreationResults() {
}

SimpleSynchronousEntry::CRCRecord::CRCRecord() : index(-1),
                                                 has_crc32(false),
                                                 data_crc32(0) {
}

SimpleSynchronousEntry::CRCRecord::CRCRecord(int index_p,
                                             bool has_crc32_p,
                                             uint32_t data_crc32_p)
    : index(index_p), has_crc32(has_crc32_p), data_crc32(data_crc32_p) {}

SimpleSynchronousEntry::EntryOperationData::EntryOperationData(int index_p,
                                                               int offset_p,
                                                               int buf_len_p)
    : index(index_p),
      offset(offset_p),
      buf_len(buf_len_p) {}

SimpleSynchronousEntry::EntryOperationData::EntryOperationData(int index_p,
                                                               int offset_p,
                                                               int buf_len_p,
                                                               bool truncate_p,
                                                               bool doomed_p)
    : index(index_p),
      offset(offset_p),
      buf_len(buf_len_p),
      truncate(truncate_p),
      doomed(doomed_p) {}

SimpleSynchronousEntry::EntryOperationData::EntryOperationData(
    int64_t sparse_offset_p,
    int buf_len_p)
    : sparse_offset(sparse_offset_p), buf_len(buf_len_p) {}

// static
void SimpleSynchronousEntry::OpenEntry(
    net::CacheType cache_type,
    const FilePath& path,
    const std::string& key,
    const uint64_t entry_hash,
    const bool had_index,
    const base::TimeTicks& time_enqueued,
    SimpleEntryCreationResults* out_results) {
  base::TimeTicks start_sync_open_entry = base::TimeTicks::Now();
  SIMPLE_CACHE_UMA(TIMES, "QueueLatency.OpenEntry", cache_type,
                   (start_sync_open_entry - time_enqueued));

  SimpleSynchronousEntry* sync_entry =
      new SimpleSynchronousEntry(cache_type, path, key, entry_hash, had_index);
  out_results->result = sync_entry->InitializeForOpen(
      &out_results->entry_stat, &out_results->stream_0_data,
      &out_results->stream_0_crc32);
  if (out_results->result != net::OK) {
    sync_entry->Doom();
    delete sync_entry;
    out_results->sync_entry = NULL;
    out_results->stream_0_data = NULL;
    return;
  }
  SIMPLE_CACHE_UMA(TIMES, "DiskOpenLatency", cache_type,
                   base::TimeTicks::Now() - start_sync_open_entry);
  out_results->sync_entry = sync_entry;
}

// static
void SimpleSynchronousEntry::CreateEntry(
    net::CacheType cache_type,
    const FilePath& path,
    const std::string& key,
    const uint64_t entry_hash,
    const bool had_index,
    const base::TimeTicks& time_enqueued,
    SimpleEntryCreationResults* out_results) {
  DCHECK_EQ(entry_hash, GetEntryHashKey(key));
  base::TimeTicks start_sync_create_entry = base::TimeTicks::Now();
  SIMPLE_CACHE_UMA(TIMES, "QueueLatency.CreateEntry", cache_type,
                   (start_sync_create_entry - time_enqueued));

  SimpleSynchronousEntry* sync_entry =
      new SimpleSynchronousEntry(cache_type, path, key, entry_hash, had_index);
  out_results->result =
      sync_entry->InitializeForCreate(&out_results->entry_stat);
  if (out_results->result != net::OK) {
    if (out_results->result != net::ERR_FILE_EXISTS)
      sync_entry->Doom();
    delete sync_entry;
    out_results->sync_entry = NULL;
    return;
  }
  out_results->sync_entry = sync_entry;
  SIMPLE_CACHE_UMA(TIMES, "DiskCreateLatency", cache_type,
                   base::TimeTicks::Now() - start_sync_create_entry);
}

// static
int SimpleSynchronousEntry::DoomEntry(const FilePath& path,
                                      uint64_t entry_hash) {
  const bool deleted_well = DeleteFilesForEntryHash(path, entry_hash);
  return deleted_well ? net::OK : net::ERR_FAILED;
}

// static
int SimpleSynchronousEntry::TruncateEntryFiles(const base::FilePath& path,
                                               uint64_t entry_hash) {
  const bool deleted_well = TruncateFilesForEntryHash(path, entry_hash);
  return deleted_well ? net::OK : net::ERR_FAILED;
}

// static
int SimpleSynchronousEntry::DoomEntrySet(
    const std::vector<uint64_t>* key_hashes,
    const FilePath& path) {
  const size_t did_delete_count = std::count_if(
      key_hashes->begin(), key_hashes->end(),
      [&path](const uint64_t& key_hash) {
        return SimpleSynchronousEntry::DeleteFilesForEntryHash(path, key_hash);
      });
  return (did_delete_count == key_hashes->size()) ? net::OK : net::ERR_FAILED;
}

void SimpleSynchronousEntry::ReadData(const EntryOperationData& in_entry_op,
                                      CRCRequest* crc_request,
                                      SimpleEntryStat* entry_stat,
                                      net::IOBuffer* out_buf,
                                      int* out_result) {
  DCHECK(initialized_);
  DCHECK_NE(0, in_entry_op.index);
  int file_index = GetFileIndexFromStreamIndex(in_entry_op.index);
  if (header_and_key_check_needed_[file_index] &&
      !CheckHeaderAndKey(file_index)) {
    *out_result = net::ERR_FAILED;
    Doom();
    return;
  }
  const int64_t file_offset = entry_stat->GetOffsetInFile(
      key_.size(), in_entry_op.offset, in_entry_op.index);
  // Zero-length reads and reads to the empty streams of omitted files should
  // be handled in the SimpleEntryImpl.
  DCHECK_GT(in_entry_op.buf_len, 0);
  DCHECK(!empty_file_omitted_[file_index]);
  int bytes_read = files_[file_index].Read(file_offset, out_buf->data(),
                                           in_entry_op.buf_len);
  if (bytes_read > 0) {
    entry_stat->set_last_used(Time::Now());
    if (crc_request != nullptr) {
      crc_request->data_crc32 =
          crc32(crc_request->data_crc32,
                reinterpret_cast<const Bytef*>(out_buf->data()), bytes_read);
      // Verify checksum after last read, if we've been asked to.
      if (crc_request->request_verify &&
          in_entry_op.offset + bytes_read ==
              entry_stat->data_size(in_entry_op.index)) {
        crc_request->performed_verify = true;
        int checksum_result = CheckEOFRecord(in_entry_op.index, *entry_stat,
                                             crc_request->data_crc32);
        if (checksum_result < 0) {
          crc_request->verify_ok = false;
          *out_result = checksum_result;
          return;
        } else {
          crc_request->verify_ok = true;
        }
      }
    }
  }
  if (bytes_read >= 0) {
    *out_result = bytes_read;
  } else {
    *out_result = net::ERR_CACHE_READ_FAILURE;
    Doom();
  }
}

void SimpleSynchronousEntry::WriteData(const EntryOperationData& in_entry_op,
                                       net::IOBuffer* in_buf,
                                       SimpleEntryStat* out_entry_stat,
                                       int* out_result) {
  base::ElapsedTimer write_time;
  DCHECK(initialized_);
  DCHECK_NE(0, in_entry_op.index);
  int index = in_entry_op.index;
  int file_index = GetFileIndexFromStreamIndex(index);
  if (header_and_key_check_needed_[file_index] &&
      !empty_file_omitted_[file_index] && !CheckHeaderAndKey(file_index)) {
    *out_result = net::ERR_FAILED;
    Doom();
    return;
  }
  int offset = in_entry_op.offset;
  int buf_len = in_entry_op.buf_len;
  bool truncate = in_entry_op.truncate;
  bool doomed = in_entry_op.doomed;
  const int64_t file_offset = out_entry_stat->GetOffsetInFile(
      key_.size(), in_entry_op.offset, in_entry_op.index);
  bool extending_by_write = offset + buf_len > out_entry_stat->data_size(index);

  if (empty_file_omitted_[file_index]) {
    // Don't create a new file if the entry has been doomed, to avoid it being
    // mixed up with a newly-created entry with the same key.
    if (doomed) {
      DLOG(WARNING) << "Rejecting write to lazily omitted stream "
                    << in_entry_op.index << " of doomed cache entry.";
      RecordWriteResult(cache_type_, WRITE_RESULT_LAZY_STREAM_ENTRY_DOOMED);
      *out_result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
    File::Error error;
    if (!MaybeCreateFile(file_index, FILE_REQUIRED, &error)) {
      RecordWriteResult(cache_type_, WRITE_RESULT_LAZY_CREATE_FAILURE);
      Doom();
      *out_result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
    CreateEntryResult result;
    if (!InitializeCreatedFile(file_index, &result)) {
      RecordWriteResult(cache_type_, WRITE_RESULT_LAZY_INITIALIZE_FAILURE);
      Doom();
      *out_result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
  }
  DCHECK(!empty_file_omitted_[file_index]);

  if (extending_by_write) {
    // The EOF record and the eventual stream afterward need to be zeroed out.
    const int64_t file_eof_offset =
        out_entry_stat->GetEOFOffsetInFile(key_.size(), index);
    if (!files_[file_index].SetLength(file_eof_offset)) {
      RecordWriteResult(cache_type_, WRITE_RESULT_PRETRUNCATE_FAILURE);
      Doom();
      *out_result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
  }
  if (buf_len > 0) {
    if (files_[file_index].Write(file_offset, in_buf->data(), buf_len) !=
        buf_len) {
      RecordWriteResult(cache_type_, WRITE_RESULT_WRITE_FAILURE);
      Doom();
      *out_result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
  }
  if (!truncate && (buf_len > 0 || !extending_by_write)) {
    out_entry_stat->set_data_size(
        index, std::max(out_entry_stat->data_size(index), offset + buf_len));
  } else {
    out_entry_stat->set_data_size(index, offset + buf_len);
    int file_eof_offset =
        out_entry_stat->GetLastEOFOffsetInFile(key_.size(), index);
    if (!files_[file_index].SetLength(file_eof_offset)) {
      RecordWriteResult(cache_type_, WRITE_RESULT_TRUNCATE_FAILURE);
      Doom();
      *out_result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
  }

  SIMPLE_CACHE_UMA(TIMES, "DiskWriteLatency", cache_type_,
                   write_time.Elapsed());
  RecordWriteResult(cache_type_, WRITE_RESULT_SUCCESS);
  base::Time modification_time = Time::Now();
  out_entry_stat->set_last_used(modification_time);
  out_entry_stat->set_last_modified(modification_time);
  *out_result = buf_len;
}

void SimpleSynchronousEntry::ReadSparseData(
    const EntryOperationData& in_entry_op,
    net::IOBuffer* out_buf,
    base::Time* out_last_used,
    int* out_result) {
  DCHECK(initialized_);
  int64_t offset = in_entry_op.sparse_offset;
  int buf_len = in_entry_op.buf_len;

  char* buf = out_buf->data();
  int read_so_far = 0;

  // Find the first sparse range at or after the requested offset.
  SparseRangeIterator it = sparse_ranges_.lower_bound(offset);

  if (it != sparse_ranges_.begin()) {
    // Hop back one range and read the one overlapping with the start.
    --it;
    SparseRange* found_range = &it->second;
    DCHECK_EQ(it->first, found_range->offset);
    if (found_range->offset + found_range->length > offset) {
      DCHECK_GE(found_range->length, 0);
      DCHECK_LE(found_range->length, std::numeric_limits<int32_t>::max());
      DCHECK_GE(offset - found_range->offset, 0);
      DCHECK_LE(offset - found_range->offset,
                std::numeric_limits<int32_t>::max());
      int net_offset = static_cast<int>(offset - found_range->offset);
      int range_len_after_offset =
          static_cast<int>(found_range->length - net_offset);
      DCHECK_GE(range_len_after_offset, 0);

      int len_to_read = std::min(buf_len, range_len_after_offset);
      if (!ReadSparseRange(found_range, net_offset, len_to_read, buf)) {
        *out_result = net::ERR_CACHE_READ_FAILURE;
        return;
      }
      read_so_far += len_to_read;
    }
    ++it;
  }

  // Keep reading until the buffer is full or there is not another contiguous
  // range.
  while (read_so_far < buf_len &&
         it != sparse_ranges_.end() &&
         it->second.offset == offset + read_so_far) {
    SparseRange* found_range = &it->second;
    DCHECK_EQ(it->first, found_range->offset);
    int range_len = base::saturated_cast<int>(found_range->length);
    int len_to_read = std::min(buf_len - read_so_far, range_len);
    if (!ReadSparseRange(found_range, 0, len_to_read, buf + read_so_far)) {
      *out_result = net::ERR_CACHE_READ_FAILURE;
      return;
    }
    read_so_far += len_to_read;
    ++it;
  }

  *out_result = read_so_far;
}

void SimpleSynchronousEntry::WriteSparseData(
    const EntryOperationData& in_entry_op,
    net::IOBuffer* in_buf,
    uint64_t max_sparse_data_size,
    SimpleEntryStat* out_entry_stat,
    int* out_result) {
  DCHECK(initialized_);
  int64_t offset = in_entry_op.sparse_offset;
  int buf_len = in_entry_op.buf_len;

  const char* buf = in_buf->data();
  int written_so_far = 0;
  int appended_so_far = 0;

  if (!sparse_file_open() && !CreateSparseFile()) {
    *out_result = net::ERR_CACHE_WRITE_FAILURE;
    return;
  }

  uint64_t sparse_data_size = out_entry_stat->sparse_data_size();
  // This is a pessimistic estimate; it assumes the entire buffer is going to
  // be appended as a new range, not written over existing ranges.
  if (sparse_data_size + buf_len > max_sparse_data_size) {
    DVLOG(1) << "Truncating sparse data file (" << sparse_data_size << " + "
             << buf_len << " > " << max_sparse_data_size << ")";
    TruncateSparseFile();
    out_entry_stat->set_sparse_data_size(0);
  }

  SparseRangeIterator it = sparse_ranges_.lower_bound(offset);

  if (it != sparse_ranges_.begin()) {
    --it;
    SparseRange* found_range = &it->second;
    if (found_range->offset + found_range->length > offset) {
      DCHECK_GE(found_range->length, 0);
      DCHECK_LE(found_range->length, std::numeric_limits<int32_t>::max());
      DCHECK_GE(offset - found_range->offset, 0);
      DCHECK_LE(offset - found_range->offset,
                std::numeric_limits<int32_t>::max());
      int net_offset = static_cast<int>(offset - found_range->offset);
      int range_len_after_offset =
          static_cast<int>(found_range->length - net_offset);
      DCHECK_GE(range_len_after_offset, 0);

      int len_to_write = std::min(buf_len, range_len_after_offset);
      if (!WriteSparseRange(found_range, net_offset, len_to_write, buf)) {
        *out_result = net::ERR_CACHE_WRITE_FAILURE;
        return;
      }
      written_so_far += len_to_write;
    }
    ++it;
  }

  while (written_so_far < buf_len &&
         it != sparse_ranges_.end() &&
         it->second.offset < offset + buf_len) {
    SparseRange* found_range = &it->second;
    if (offset + written_so_far < found_range->offset) {
      int len_to_append =
          static_cast<int>(found_range->offset - (offset + written_so_far));
      if (!AppendSparseRange(offset + written_so_far,
                             len_to_append,
                             buf + written_so_far)) {
        *out_result = net::ERR_CACHE_WRITE_FAILURE;
        return;
      }
      written_so_far += len_to_append;
      appended_so_far += len_to_append;
    }
    int range_len = base::saturated_cast<int>(found_range->length);
    int len_to_write = std::min(buf_len - written_so_far, range_len);
    if (!WriteSparseRange(found_range,
                          0,
                          len_to_write,
                          buf + written_so_far)) {
      *out_result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
    written_so_far += len_to_write;
    ++it;
  }

  if (written_so_far < buf_len) {
    int len_to_append = buf_len - written_so_far;
    if (!AppendSparseRange(offset + written_so_far,
                           len_to_append,
                           buf + written_so_far)) {
      *out_result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
    written_so_far += len_to_append;
    appended_so_far += len_to_append;
  }

  DCHECK_EQ(buf_len, written_so_far);

  base::Time modification_time = Time::Now();
  out_entry_stat->set_last_used(modification_time);
  out_entry_stat->set_last_modified(modification_time);
  int32_t old_sparse_data_size = out_entry_stat->sparse_data_size();
  out_entry_stat->set_sparse_data_size(old_sparse_data_size + appended_so_far);
  *out_result = written_so_far;
}

void SimpleSynchronousEntry::GetAvailableRange(
    const EntryOperationData& in_entry_op,
    int64_t* out_start,
    int* out_result) {
  DCHECK(initialized_);
  int64_t offset = in_entry_op.sparse_offset;
  int len = in_entry_op.buf_len;

  SparseRangeIterator it = sparse_ranges_.lower_bound(offset);

  int64_t start = offset;
  int64_t avail_so_far = 0;

  if (it != sparse_ranges_.end() && it->second.offset < offset + len)
    start = it->second.offset;

  if ((it == sparse_ranges_.end() || it->second.offset > offset) &&
      it != sparse_ranges_.begin()) {
    --it;
    if (it->second.offset + it->second.length > offset) {
      start = offset;
      avail_so_far = (it->second.offset + it->second.length) - offset;
    }
    ++it;
  }

  while (start + avail_so_far < offset + len &&
         it != sparse_ranges_.end() &&
         it->second.offset == start + avail_so_far) {
    avail_so_far += it->second.length;
    ++it;
  }

  int64_t len_from_start = len - (start - offset);
  *out_start = start;
  *out_result = static_cast<int>(std::min(avail_so_far, len_from_start));
}

int SimpleSynchronousEntry::CheckEOFRecord(int index,
                                           const SimpleEntryStat& entry_stat,
                                           uint32_t expected_crc32) const {
  DCHECK(initialized_);
  uint32_t crc32;
  bool has_crc32;
  bool has_key_sha256;
  int32_t stream_size;
  int rv = GetEOFRecordData(index, entry_stat, &has_crc32, &has_key_sha256,
                            &crc32, &stream_size);
  if (rv != net::OK) {
    Doom();
    return rv;
  }
  if (has_crc32 && crc32 != expected_crc32) {
    DVLOG(1) << "EOF record had bad crc.";
    RecordCheckEOFResult(cache_type_, CHECK_EOF_RESULT_CRC_MISMATCH);
    Doom();
    return net::ERR_CACHE_CHECKSUM_MISMATCH;
  }
  RecordCheckEOFResult(cache_type_, CHECK_EOF_RESULT_SUCCESS);
  return net::OK;
}

void SimpleSynchronousEntry::Close(
    const SimpleEntryStat& entry_stat,
    std::unique_ptr<std::vector<CRCRecord>> crc32s_to_write,
    net::GrowableIOBuffer* stream_0_data) {
  base::ElapsedTimer close_time;
  DCHECK(stream_0_data);

  for (std::vector<CRCRecord>::const_iterator it = crc32s_to_write->begin();
       it != crc32s_to_write->end(); ++it) {
    const int stream_index = it->index;
    const int file_index = GetFileIndexFromStreamIndex(stream_index);
    if (empty_file_omitted_[file_index])
      continue;

    if (stream_index == 0) {
      // Write stream 0 data.
      int stream_0_offset = entry_stat.GetOffsetInFile(key_.size(), 0, 0);
      if (files_[0].Write(stream_0_offset, stream_0_data->data(),
                          entry_stat.data_size(0)) != entry_stat.data_size(0)) {
        RecordCloseResult(cache_type_, CLOSE_RESULT_WRITE_FAILURE);
        DVLOG(1) << "Could not write stream 0 data.";
        Doom();
      }
      net::SHA256HashValue hash_value;
      CalculateSHA256OfKey(key_, &hash_value);
      if (files_[0].Write(stream_0_offset + entry_stat.data_size(0),
                          reinterpret_cast<char*>(hash_value.data),
                          sizeof(hash_value)) != sizeof(hash_value)) {
        RecordCloseResult(cache_type_, CLOSE_RESULT_WRITE_FAILURE);
        DVLOG(1) << "Could not write stream 0 data.";
        Doom();
      }
    }

    SimpleFileEOF eof_record;
    eof_record.stream_size = entry_stat.data_size(stream_index);
    eof_record.final_magic_number = kSimpleFinalMagicNumber;
    eof_record.flags = 0;
    if (it->has_crc32)
      eof_record.flags |= SimpleFileEOF::FLAG_HAS_CRC32;
    if (stream_index == 0)
      eof_record.flags |= SimpleFileEOF::FLAG_HAS_KEY_SHA256;
    eof_record.data_crc32 = it->data_crc32;
    int eof_offset = entry_stat.GetEOFOffsetInFile(key_.size(), stream_index);
    // If stream 0 changed size, the file needs to be resized, otherwise the
    // next open will yield wrong stream sizes. On stream 1 and stream 2 proper
    // resizing of the file is handled in SimpleSynchronousEntry::WriteData().
    if (stream_index == 0 &&
        !files_[file_index].SetLength(eof_offset)) {
      RecordCloseResult(cache_type_, CLOSE_RESULT_WRITE_FAILURE);
      DVLOG(1) << "Could not truncate stream 0 file.";
      Doom();
      break;
    }
    if (files_[file_index].Write(eof_offset,
                                 reinterpret_cast<const char*>(&eof_record),
                                 sizeof(eof_record)) !=
        sizeof(eof_record)) {
      RecordCloseResult(cache_type_, CLOSE_RESULT_WRITE_FAILURE);
      DVLOG(1) << "Could not write eof record.";
      Doom();
      break;
    }
  }
  for (int i = 0; i < kSimpleEntryFileCount; ++i) {
    if (empty_file_omitted_[i])
      continue;

    if (header_and_key_check_needed_[i] && !CheckHeaderAndKey(i)) {
      Doom();
    }
    files_[i].Close();
    const int64_t file_size = entry_stat.GetFileSize(key_.size(), i);
    SIMPLE_CACHE_UMA(CUSTOM_COUNTS,
                     "LastClusterSize", cache_type_,
                     file_size % 4096, 0, 4097, 50);
    const int64_t cluster_loss = file_size % 4096 ? 4096 - file_size % 4096 : 0;
    SIMPLE_CACHE_UMA(PERCENTAGE,
                     "LastClusterLossPercent", cache_type_,
                     static_cast<base::HistogramBase::Sample>(
                         cluster_loss * 100 / (cluster_loss + file_size)));
  }

  if (sparse_file_open())
    sparse_file_.Close();

  if (files_created_) {
    const int stream2_file_index = GetFileIndexFromStreamIndex(2);
    SIMPLE_CACHE_UMA(BOOLEAN, "EntryCreatedAndStream2Omitted", cache_type_,
                     empty_file_omitted_[stream2_file_index]);
  }
  SIMPLE_CACHE_UMA(TIMES, "DiskCloseLatency", cache_type_,
                   close_time.Elapsed());
  RecordCloseResult(cache_type_, CLOSE_RESULT_SUCCESS);
  have_open_files_ = false;
  delete this;
}

SimpleSynchronousEntry::SimpleSynchronousEntry(net::CacheType cache_type,
                                               const FilePath& path,
                                               const std::string& key,
                                               const uint64_t entry_hash,
                                               const bool had_index)
    : cache_type_(cache_type),
      path_(path),
      entry_hash_(entry_hash),
      had_index_(had_index),
      key_(key),
      have_open_files_(false),
      initialized_(false) {
  for (int i = 0; i < kSimpleEntryFileCount; ++i)
    empty_file_omitted_[i] = false;
}

SimpleSynchronousEntry::~SimpleSynchronousEntry() {
  DCHECK(!(have_open_files_ && initialized_));
  if (have_open_files_)
    CloseFiles();
}

bool SimpleSynchronousEntry::MaybeOpenFile(
    int file_index,
    File::Error* out_error) {
  DCHECK(out_error);

  FilePath filename = GetFilenameFromFileIndex(file_index);
  int flags = File::FLAG_OPEN | File::FLAG_READ | File::FLAG_WRITE |
              File::FLAG_SHARE_DELETE;
  files_[file_index].Initialize(filename, flags);
  *out_error = files_[file_index].error_details();

  if (CanOmitEmptyFile(file_index) && !files_[file_index].IsValid() &&
      *out_error == File::FILE_ERROR_NOT_FOUND) {
    empty_file_omitted_[file_index] = true;
    return true;
  }

  return files_[file_index].IsValid();
}

bool SimpleSynchronousEntry::MaybeCreateFile(
    int file_index,
    FileRequired file_required,
    File::Error* out_error) {
  DCHECK(out_error);

  if (CanOmitEmptyFile(file_index) && file_required == FILE_NOT_REQUIRED) {
    empty_file_omitted_[file_index] = true;
    return true;
  }

  FilePath filename = GetFilenameFromFileIndex(file_index);
  int flags = File::FLAG_CREATE | File::FLAG_READ | File::FLAG_WRITE |
              File::FLAG_SHARE_DELETE;
  files_[file_index].Initialize(filename, flags);

  // It's possible that the creation failed because someone deleted the
  // directory (e.g. because someone pressed "clear cache" on Android).
  // If so, we would keep failing for a while until periodic index snapshot
  // re-creates the cache dir, so try to recover from it quickly here.
  if (!files_[file_index].IsValid() &&
      files_[file_index].error_details() == File::FILE_ERROR_NOT_FOUND &&
      !base::DirectoryExists(path_)) {
    if (base::CreateDirectory(path_))
      files_[file_index].Initialize(filename, flags);
  }

  *out_error = files_[file_index].error_details();
  empty_file_omitted_[file_index] = false;

  return files_[file_index].IsValid();
}

bool SimpleSynchronousEntry::OpenFiles(SimpleEntryStat* out_entry_stat) {
  for (int i = 0; i < kSimpleEntryFileCount; ++i) {
    File::Error error;
    if (!MaybeOpenFile(i, &error)) {
      // TODO(juliatuttle,gavinp): Remove one each of these triplets of
      // histograms. We can calculate the third as the sum or difference of the
      // other two.
      RecordSyncOpenResult(cache_type_, OPEN_ENTRY_PLATFORM_FILE_ERROR,
                           had_index_);
      SIMPLE_CACHE_UMA(ENUMERATION,
                       "SyncOpenPlatformFileError", cache_type_,
                       -error, -base::File::FILE_ERROR_MAX);
      if (had_index_) {
        SIMPLE_CACHE_UMA(ENUMERATION,
                         "SyncOpenPlatformFileError_WithIndex", cache_type_,
                         -error, -base::File::FILE_ERROR_MAX);
      } else {
        SIMPLE_CACHE_UMA(ENUMERATION,
                         "SyncOpenPlatformFileError_WithoutIndex",
                         cache_type_,
                         -error, -base::File::FILE_ERROR_MAX);
      }
      while (--i >= 0)
        CloseFile(i);
      return false;
    }
  }

  have_open_files_ = true;

  base::TimeDelta entry_age = base::Time::Now() - base::Time::UnixEpoch();
  for (int i = 0; i < kSimpleEntryFileCount; ++i) {
    if (empty_file_omitted_[i]) {
      out_entry_stat->set_data_size(i + 1, 0);
      continue;
    }

    File::Info file_info;
    bool success = files_[i].GetInfo(&file_info);
    base::Time file_last_modified;
    if (!success) {
      DLOG(WARNING) << "Could not get platform file info.";
      continue;
    }
    out_entry_stat->set_last_used(file_info.last_accessed);
    out_entry_stat->set_last_modified(file_info.last_modified);

    base::TimeDelta stream_age =
        base::Time::Now() - out_entry_stat->last_modified();
    if (stream_age < entry_age)
      entry_age = stream_age;

    // Two things prevent from knowing the right values for |data_size|:
    // 1) The key is not known, hence its length is unknown.
    // 2) Stream 0 and stream 1 are in the same file, and the exact size for
    // each will only be known when reading the EOF record for stream 0.
    //
    // The size for file 0 and 1 is temporarily kept in
    // |data_size(1)| and |data_size(2)| respectively. Reading the key in
    // InitializeForOpen yields the data size for each file. In the case of
    // file hash_1, this is the total size of stream 2, and is assigned to
    // data_size(2). In the case of file 0, it is the combined size of stream
    // 0, stream 1 and one EOF record. The exact distribution of sizes between
    // stream 1 and stream 0 is only determined after reading the EOF record
    // for stream 0 in ReadAndValidateStream0.
    if (!base::IsValueInRangeForNumericType<int>(file_info.size)) {
      RecordSyncOpenResult(cache_type_, OPEN_ENTRY_INVALID_FILE_LENGTH,
                           had_index_);
      return false;
    }
    out_entry_stat->set_data_size(i + 1, static_cast<int>(file_info.size));
  }
  SIMPLE_CACHE_UMA(CUSTOM_COUNTS,
                   "SyncOpenEntryAge", cache_type_,
                   entry_age.InHours(), 1, 1000, 50);

  files_created_ = false;

  return true;
}

bool SimpleSynchronousEntry::CreateFiles(SimpleEntryStat* out_entry_stat) {
  for (int i = 0; i < kSimpleEntryFileCount; ++i) {
    File::Error error;
    if (!MaybeCreateFile(i, FILE_NOT_REQUIRED, &error)) {
      // TODO(juliatuttle,gavinp): Remove one each of these triplets of
      // histograms. We can calculate the third as the sum or difference of the
      // other two.
      RecordSyncCreateResult(CREATE_ENTRY_PLATFORM_FILE_ERROR, had_index_);
      SIMPLE_CACHE_UMA(ENUMERATION,
                       "SyncCreatePlatformFileError", cache_type_,
                       -error, -base::File::FILE_ERROR_MAX);
      if (had_index_) {
        SIMPLE_CACHE_UMA(ENUMERATION,
                         "SyncCreatePlatformFileError_WithIndex", cache_type_,
                         -error, -base::File::FILE_ERROR_MAX);
      } else {
        SIMPLE_CACHE_UMA(ENUMERATION,
                         "SyncCreatePlatformFileError_WithoutIndex",
                         cache_type_,
                         -error, -base::File::FILE_ERROR_MAX);
      }
      while (--i >= 0)
        CloseFile(i);
      return false;
    }
  }

  have_open_files_ = true;

  base::Time creation_time = Time::Now();
  out_entry_stat->set_last_modified(creation_time);
  out_entry_stat->set_last_used(creation_time);
  for (int i = 0; i < kSimpleEntryStreamCount; ++i)
      out_entry_stat->set_data_size(i, 0);

  files_created_ = true;

  return true;
}

void SimpleSynchronousEntry::CloseFile(int index) {
  if (empty_file_omitted_[index]) {
    empty_file_omitted_[index] = false;
  } else {
    DCHECK(files_[index].IsValid());
    files_[index].Close();
  }

  if (sparse_file_open())
    CloseSparseFile();
}

void SimpleSynchronousEntry::CloseFiles() {
  for (int i = 0; i < kSimpleEntryFileCount; ++i)
    CloseFile(i);
}

bool SimpleSynchronousEntry::CheckHeaderAndKey(int file_index) {
  // TODO(gavinp): Frequently we are doing this at the same time as we read from
  // the beginning of an entry. It might improve performance to make a single
  // read(2) call rather than two separate reads. On the other hand, it would
  // mean an extra memory to memory copy. In the case where we are opening an
  // entry without a key, the kInitialHeaderRead setting means that we are
  // actually already reading stream 1 data here, and tossing it out.
  std::vector<char> header_data(key_.empty() ? kInitialHeaderRead
                                             : GetHeaderSize(key_.size()));
  int bytes_read =
      files_[file_index].Read(0, header_data.data(), header_data.size());
  const SimpleFileHeader* header =
      reinterpret_cast<const SimpleFileHeader*>(header_data.data());

  if (bytes_read == -1 || static_cast<size_t>(bytes_read) < sizeof(*header)) {
    RecordSyncOpenResult(cache_type_, OPEN_ENTRY_CANT_READ_HEADER, had_index_);
    return false;
  }
  // This resize will not invalidate iterators since it does not enlarge the
  // header_data.
  DCHECK_LE(static_cast<size_t>(bytes_read), header_data.size());
  header_data.resize(bytes_read);

  if (header->initial_magic_number != kSimpleInitialMagicNumber) {
    RecordSyncOpenResult(cache_type_, OPEN_ENTRY_BAD_MAGIC_NUMBER, had_index_);
    return false;
  }

  if (header->version != kSimpleEntryVersionOnDisk) {
    RecordSyncOpenResult(cache_type_, OPEN_ENTRY_BAD_VERSION, had_index_);
    return false;
  }

  size_t expected_header_size = GetHeaderSize(header->key_length);
  if (header_data.size() < expected_header_size) {
    size_t old_size = header_data.size();
    int bytes_to_read = expected_header_size - old_size;
    // This resize will invalidate iterators, since it is enlarging header_data.
    header_data.resize(expected_header_size);
    int bytes_read = files_[file_index].Read(
        old_size, header_data.data() + old_size, bytes_to_read);
    if (bytes_read != bytes_to_read) {
      RecordSyncOpenResult(cache_type_, OPEN_ENTRY_CANT_READ_KEY, had_index_);
      return false;
    }
    header = reinterpret_cast<const SimpleFileHeader*>(header_data.data());
  }

  char* key_data = header_data.data() + sizeof(*header);
  if (base::Hash(key_data, header->key_length) != header->key_hash) {
    RecordSyncOpenResult(cache_type_, OPEN_ENTRY_KEY_HASH_MISMATCH, had_index_);
    return false;
  }

  std::string key_from_header(key_data, header->key_length);
  if (key_.empty()) {
    key_.swap(key_from_header);
  } else {
    if (key_ != key_from_header) {
      RecordSyncOpenResult(cache_type_, OPEN_ENTRY_KEY_MISMATCH, had_index_);
      return false;
    }
  }

  header_and_key_check_needed_[file_index] = false;
  return true;
}

int SimpleSynchronousEntry::InitializeForOpen(
    SimpleEntryStat* out_entry_stat,
    scoped_refptr<net::GrowableIOBuffer>* stream_0_data,
    uint32_t* out_stream_0_crc32) {
  DCHECK(!initialized_);
  if (!OpenFiles(out_entry_stat)) {
    DLOG(WARNING) << "Could not open platform files for entry.";
    return net::ERR_FAILED;
  }
  for (int i = 0; i < kSimpleEntryFileCount; ++i) {
    if (empty_file_omitted_[i])
      continue;

    if (key_.empty()) {
      // If |key_| is empty, we were opened via the iterator interface, without
      // knowing what our key is. We must therefore read the header immediately
      // to discover it, so SimpleEntryImpl can make it available to
      // disk_cache::Entry::GetKey().
      if (!CheckHeaderAndKey(i))
        return net::ERR_FAILED;
    } else {
      // If we do know which key were are looking for, we still need to
      // check that the file actually has it (rather than just being a hash
      // collision or some sort of file system accident), but that can be put
      // off until opportune time: either the read of the footer, or when we
      // start reading in the data, depending on stream # and format revision.
      header_and_key_check_needed_[i] = true;
    }

    if (i == 0) {
      // File size for stream 0 has been stored temporarily in data_size[1].
      int ret_value_stream_0 =
          ReadAndValidateStream0(out_entry_stat->data_size(1), out_entry_stat,
                                 stream_0_data, out_stream_0_crc32);
      if (ret_value_stream_0 != net::OK)
        return ret_value_stream_0;
    } else {
      out_entry_stat->set_data_size(
          2,
          GetDataSizeFromFileSize(key_.size(), out_entry_stat->data_size(2)));
      if (out_entry_stat->data_size(2) < 0) {
        DLOG(WARNING) << "Stream 2 file is too small.";
        return net::ERR_FAILED;
      }
    }
  }

  int32_t sparse_data_size = 0;
  if (!OpenSparseFileIfExists(&sparse_data_size)) {
    RecordSyncOpenResult(cache_type_, OPEN_ENTRY_SPARSE_OPEN_FAILED,
                         had_index_);
    return net::ERR_FAILED;
  }
  out_entry_stat->set_sparse_data_size(sparse_data_size);

  bool removed_stream2 = false;
  const int stream2_file_index = GetFileIndexFromStreamIndex(2);
  DCHECK(CanOmitEmptyFile(stream2_file_index));
  if (!empty_file_omitted_[stream2_file_index] &&
      out_entry_stat->data_size(2) == 0) {
    DVLOG(1) << "Removing empty stream 2 file.";
    CloseFile(stream2_file_index);
    DeleteFileForEntryHash(path_, entry_hash_, stream2_file_index);
    empty_file_omitted_[stream2_file_index] = true;
    removed_stream2 = true;
  }

  SIMPLE_CACHE_UMA(BOOLEAN, "EntryOpenedAndStream2Removed", cache_type_,
                   removed_stream2);

  RecordSyncOpenResult(cache_type_, OPEN_ENTRY_SUCCESS, had_index_);
  initialized_ = true;
  return net::OK;
}

bool SimpleSynchronousEntry::InitializeCreatedFile(
    int file_index,
    CreateEntryResult* out_result) {
  SimpleFileHeader header;
  header.initial_magic_number = kSimpleInitialMagicNumber;
  header.version = kSimpleEntryVersionOnDisk;

  header.key_length = key_.size();
  header.key_hash = base::Hash(key_);

  int bytes_written = files_[file_index].Write(
      0, reinterpret_cast<char*>(&header), sizeof(header));
  if (bytes_written != sizeof(header)) {
    *out_result = CREATE_ENTRY_CANT_WRITE_HEADER;
    return false;
  }

  bytes_written = files_[file_index].Write(sizeof(header), key_.data(),
                                           key_.size());
  if (bytes_written != base::checked_cast<int>(key_.size())) {
    *out_result = CREATE_ENTRY_CANT_WRITE_KEY;
    return false;
  }

  return true;
}

int SimpleSynchronousEntry::InitializeForCreate(
    SimpleEntryStat* out_entry_stat) {
  DCHECK(!initialized_);
  if (!CreateFiles(out_entry_stat)) {
    DLOG(WARNING) << "Could not create platform files.";
    return net::ERR_FILE_EXISTS;
  }
  for (int i = 0; i < kSimpleEntryFileCount; ++i) {
    if (empty_file_omitted_[i])
      continue;

    CreateEntryResult result;
    if (!InitializeCreatedFile(i, &result)) {
      RecordSyncCreateResult(result, had_index_);
      return net::ERR_FAILED;
    }
  }
  RecordSyncCreateResult(CREATE_ENTRY_SUCCESS, had_index_);
  initialized_ = true;
  return net::OK;
}

int SimpleSynchronousEntry::ReadAndValidateStream0(
    int file_size,
    SimpleEntryStat* out_entry_stat,
    scoped_refptr<net::GrowableIOBuffer>* stream_0_data,
    uint32_t* out_stream_0_crc32) {
  // Pretend this file has a null stream zero, and contains the optional key
  // SHA256. This is good enough to read the EOF record on the file, which gives
  // the actual size of stream 0.
  int temp_data_size = GetDataSizeFromFileSize(key_.size(), file_size);
  out_entry_stat->set_data_size(0, 0);
  out_entry_stat->set_data_size(
      1, temp_data_size - sizeof(net::SHA256HashValue) - sizeof(SimpleFileEOF));

  bool has_crc32;
  bool has_key_sha256;
  uint32_t read_crc32;
  int32_t stream_0_size;
  int ret_value_crc32 =
      GetEOFRecordData(0, *out_entry_stat, &has_crc32, &has_key_sha256,
                       &read_crc32, &stream_0_size);
  if (ret_value_crc32 != net::OK)
    return ret_value_crc32;

  // Calculate and set the real values for the two streams.
  int32_t total_size = out_entry_stat->data_size(1);
  if (!has_key_sha256)
    total_size += sizeof(net::SHA256HashValue);
  if (stream_0_size > total_size)
    return net::ERR_FAILED;
  out_entry_stat->set_data_size(0, stream_0_size);
  out_entry_stat->set_data_size(1, total_size - stream_0_size);

  // Put stream 0 data in memory.
  *stream_0_data = new net::GrowableIOBuffer();
  (*stream_0_data)->SetCapacity(stream_0_size + sizeof(net::SHA256HashValue));
  int file_offset = out_entry_stat->GetOffsetInFile(key_.size(), 0, 0);
  int read_size = stream_0_size;
  if (has_key_sha256)
    read_size += sizeof(net::SHA256HashValue);
  if (files_[0].Read(file_offset, (*stream_0_data)->data(), read_size) !=
      read_size)
    return net::ERR_FAILED;

  // Check the CRC32.
  uint32_t expected_crc32 =
      stream_0_size == 0
          ? crc32(0, Z_NULL, 0)
          : crc32(crc32(0, Z_NULL, 0),
                  reinterpret_cast<const Bytef*>((*stream_0_data)->data()),
                  stream_0_size);
  if (has_crc32 && read_crc32 != expected_crc32) {
    DVLOG(1) << "EOF record had bad crc.";
    RecordCheckEOFResult(cache_type_, CHECK_EOF_RESULT_CRC_MISMATCH);
    return net::ERR_FAILED;
  }
  *out_stream_0_crc32 = expected_crc32;

  // If present, check the key SHA256.
  if (has_key_sha256) {
    net::SHA256HashValue hash_value;
    CalculateSHA256OfKey(key_, &hash_value);
    bool matched =
        std::memcmp(&hash_value, (*stream_0_data)->data() + stream_0_size,
                    sizeof(hash_value)) == 0;
    if (!matched) {
      RecordKeySHA256Result(cache_type_, KeySHA256Result::NO_MATCH);
      return net::ERR_FAILED;
    }
    // Elide header check if we verified sha256(key) via footer.
    header_and_key_check_needed_[0] = false;
    RecordKeySHA256Result(cache_type_, KeySHA256Result::MATCHED);
  } else {
    RecordKeySHA256Result(cache_type_, KeySHA256Result::NOT_PRESENT);
  }

  // Ensure the key is validated before completion.
  if (!has_key_sha256 && header_and_key_check_needed_[0])
    CheckHeaderAndKey(0);

  RecordCheckEOFResult(cache_type_, CHECK_EOF_RESULT_SUCCESS);
  return net::OK;
}

int SimpleSynchronousEntry::GetEOFRecordData(int index,
                                             const SimpleEntryStat& entry_stat,
                                             bool* out_has_crc32,
                                             bool* out_has_key_sha256,
                                             uint32_t* out_crc32,
                                             int32_t* out_data_size) const {
  SimpleFileEOF eof_record;
  int file_offset = entry_stat.GetEOFOffsetInFile(key_.size(), index);
  int file_index = GetFileIndexFromStreamIndex(index);
  File* file = const_cast<File*>(&files_[file_index]);
  if (file->Read(file_offset, reinterpret_cast<char*>(&eof_record),
                 sizeof(eof_record)) !=
      sizeof(eof_record)) {
    RecordCheckEOFResult(cache_type_, CHECK_EOF_RESULT_READ_FAILURE);
    return net::ERR_CACHE_CHECKSUM_READ_FAILURE;
  }

  if (eof_record.final_magic_number != kSimpleFinalMagicNumber) {
    RecordCheckEOFResult(cache_type_, CHECK_EOF_RESULT_MAGIC_NUMBER_MISMATCH);
    DVLOG(1) << "EOF record had bad magic number.";
    return net::ERR_CACHE_CHECKSUM_READ_FAILURE;
  }

  if (!base::IsValueInRangeForNumericType<int32_t>(eof_record.stream_size))
    return net::ERR_FAILED;

  *out_has_crc32 = (eof_record.flags & SimpleFileEOF::FLAG_HAS_CRC32) ==
                   SimpleFileEOF::FLAG_HAS_CRC32;
  *out_has_key_sha256 =
      (eof_record.flags & SimpleFileEOF::FLAG_HAS_KEY_SHA256) ==
      SimpleFileEOF::FLAG_HAS_KEY_SHA256;
  *out_crc32 = eof_record.data_crc32;
  *out_data_size = eof_record.stream_size;
  SIMPLE_CACHE_UMA(BOOLEAN, "SyncCheckEOFHasCrc", cache_type_, *out_has_crc32);
  return net::OK;
}

void SimpleSynchronousEntry::Doom() const {
  DeleteFilesForEntryHash(path_, entry_hash_);
}

// static
bool SimpleSynchronousEntry::DeleteFileForEntryHash(const FilePath& path,
                                                    const uint64_t entry_hash,
                                                    const int file_index) {
  FilePath to_delete = path.AppendASCII(
      GetFilenameFromEntryHashAndFileIndex(entry_hash, file_index));
  return simple_util::SimpleCacheDeleteFile(to_delete);
}

// static
bool SimpleSynchronousEntry::DeleteFilesForEntryHash(
    const FilePath& path,
    const uint64_t entry_hash) {
  bool result = true;
  for (int i = 0; i < kSimpleEntryFileCount; ++i) {
    if (!DeleteFileForEntryHash(path, entry_hash, i) && !CanOmitEmptyFile(i))
      result = false;
  }
  FilePath to_delete = path.AppendASCII(
      GetSparseFilenameFromEntryHash(entry_hash));
  simple_util::SimpleCacheDeleteFile(to_delete);
  return result;
}

// static
bool SimpleSynchronousEntry::TruncateFilesForEntryHash(
    const FilePath& path,
    const uint64_t entry_hash) {
  bool result = true;
  for (int i = 0; i < kSimpleEntryFileCount; ++i) {
    FilePath filename_to_truncate =
        path.AppendASCII(GetFilenameFromEntryHashAndFileIndex(entry_hash, i));
    if (!TruncatePath(filename_to_truncate))
      result = false;
  }
  FilePath to_delete =
      path.AppendASCII(GetSparseFilenameFromEntryHash(entry_hash));
  TruncatePath(to_delete);
  return result;
}

void SimpleSynchronousEntry::RecordSyncCreateResult(CreateEntryResult result,
                                                    bool had_index) {
  DCHECK_LT(result, CREATE_ENTRY_MAX);
  SIMPLE_CACHE_UMA(ENUMERATION,
                   "SyncCreateResult", cache_type_, result, CREATE_ENTRY_MAX);
  if (had_index) {
    SIMPLE_CACHE_UMA(ENUMERATION,
                     "SyncCreateResult_WithIndex", cache_type_,
                     result, CREATE_ENTRY_MAX);
  } else {
    SIMPLE_CACHE_UMA(ENUMERATION,
                     "SyncCreateResult_WithoutIndex", cache_type_,
                     result, CREATE_ENTRY_MAX);
  }
}

FilePath SimpleSynchronousEntry::GetFilenameFromFileIndex(int file_index) {
  return path_.AppendASCII(
      GetFilenameFromEntryHashAndFileIndex(entry_hash_, file_index));
}

bool SimpleSynchronousEntry::OpenSparseFileIfExists(
    int32_t* out_sparse_data_size) {
  DCHECK(!sparse_file_open());

  FilePath filename = path_.AppendASCII(
      GetSparseFilenameFromEntryHash(entry_hash_));
  int flags = File::FLAG_OPEN | File::FLAG_READ | File::FLAG_WRITE |
              File::FLAG_SHARE_DELETE;
  sparse_file_.Initialize(filename, flags);
  if (sparse_file_.IsValid())
    return ScanSparseFile(out_sparse_data_size);

  return sparse_file_.error_details() == File::FILE_ERROR_NOT_FOUND;
}

bool SimpleSynchronousEntry::CreateSparseFile() {
  DCHECK(!sparse_file_open());

  FilePath filename = path_.AppendASCII(
      GetSparseFilenameFromEntryHash(entry_hash_));
  int flags = File::FLAG_CREATE | File::FLAG_READ | File::FLAG_WRITE |
              File::FLAG_SHARE_DELETE;
  sparse_file_.Initialize(filename, flags);
  if (!sparse_file_.IsValid())
    return false;

  return InitializeSparseFile();
}

void SimpleSynchronousEntry::CloseSparseFile() {
  DCHECK(sparse_file_open());
  sparse_file_.Close();
}

bool SimpleSynchronousEntry::TruncateSparseFile() {
  DCHECK(sparse_file_open());

  int64_t header_and_key_length = sizeof(SimpleFileHeader) + key_.size();
  if (!sparse_file_.SetLength(header_and_key_length)) {
    DLOG(WARNING) << "Could not truncate sparse file";
    return false;
  }

  sparse_ranges_.clear();
  sparse_tail_offset_ = header_and_key_length;

  return true;
}

bool SimpleSynchronousEntry::InitializeSparseFile() {
  DCHECK(sparse_file_open());

  SimpleFileHeader header;
  header.initial_magic_number = kSimpleInitialMagicNumber;
  header.version = kSimpleVersion;
  header.key_length = key_.size();
  header.key_hash = base::Hash(key_);

  int header_write_result =
      sparse_file_.Write(0, reinterpret_cast<char*>(&header), sizeof(header));
  if (header_write_result != sizeof(header)) {
    DLOG(WARNING) << "Could not write sparse file header";
    return false;
  }

  int key_write_result = sparse_file_.Write(sizeof(header), key_.data(),
                                            key_.size());
  if (key_write_result != base::checked_cast<int>(key_.size())) {
    DLOG(WARNING) << "Could not write sparse file key";
    return false;
  }

  sparse_ranges_.clear();
  sparse_tail_offset_ = sizeof(header) + key_.size();

  return true;
}

bool SimpleSynchronousEntry::ScanSparseFile(int32_t* out_sparse_data_size) {
  DCHECK(sparse_file_open());

  int64_t sparse_data_size = 0;

  SimpleFileHeader header;
  int header_read_result =
      sparse_file_.Read(0, reinterpret_cast<char*>(&header), sizeof(header));
  if (header_read_result != sizeof(header)) {
    DLOG(WARNING) << "Could not read header from sparse file.";
    return false;
  }

  if (header.initial_magic_number != kSimpleInitialMagicNumber) {
    DLOG(WARNING) << "Sparse file magic number did not match.";
    return false;
  }

  if (header.version != kSimpleVersion) {
    DLOG(WARNING) << "Sparse file unreadable version.";
    return false;
  }

  sparse_ranges_.clear();

  int64_t range_header_offset = sizeof(header) + key_.size();
  while (1) {
    SimpleFileSparseRangeHeader range_header;
    int range_header_read_result =
        sparse_file_.Read(range_header_offset,
                          reinterpret_cast<char*>(&range_header),
                          sizeof(range_header));
    if (range_header_read_result == 0)
      break;
    if (range_header_read_result != sizeof(range_header)) {
      DLOG(WARNING) << "Could not read sparse range header.";
      return false;
    }

    if (range_header.sparse_range_magic_number !=
        kSimpleSparseRangeMagicNumber) {
      DLOG(WARNING) << "Invalid sparse range header magic number.";
      return false;
    }

    SparseRange range;
    range.offset = range_header.offset;
    range.length = range_header.length;
    range.data_crc32 = range_header.data_crc32;
    range.file_offset = range_header_offset + sizeof(range_header);
    sparse_ranges_.insert(std::make_pair(range.offset, range));

    range_header_offset += sizeof(range_header) + range.length;

    DCHECK_GE(sparse_data_size + range.length, sparse_data_size);
    sparse_data_size += range.length;
  }

  *out_sparse_data_size = static_cast<int32_t>(sparse_data_size);
  sparse_tail_offset_ = range_header_offset;

  return true;
}

bool SimpleSynchronousEntry::ReadSparseRange(const SparseRange* range,
                                             int offset, int len, char* buf) {
  DCHECK(range);
  DCHECK(buf);
  DCHECK_LE(offset, range->length);
  DCHECK_LE(offset + len, range->length);

  int bytes_read = sparse_file_.Read(range->file_offset + offset, buf, len);
  if (bytes_read < len) {
    DLOG(WARNING) << "Could not read sparse range.";
    return false;
  }

  // If we read the whole range and we have a crc32, check it.
  if (offset == 0 && len == range->length && range->data_crc32 != 0) {
    uint32_t actual_crc32 =
        crc32(crc32(0L, Z_NULL, 0), reinterpret_cast<const Bytef*>(buf), len);
    if (actual_crc32 != range->data_crc32) {
      DLOG(WARNING) << "Sparse range crc32 mismatch.";
      return false;
    }
  }
  // TODO(juliatuttle): Incremental crc32 calculation?

  return true;
}

bool SimpleSynchronousEntry::WriteSparseRange(SparseRange* range,
                                              int offset, int len,
                                              const char* buf) {
  DCHECK(range);
  DCHECK(buf);
  DCHECK_LE(offset, range->length);
  DCHECK_LE(offset + len, range->length);

  uint32_t new_crc32 = 0;
  if (offset == 0 && len == range->length) {
    new_crc32 = crc32(crc32(0L, Z_NULL, 0),
                      reinterpret_cast<const Bytef*>(buf),
                      len);
  }

  if (new_crc32 != range->data_crc32) {
    range->data_crc32 = new_crc32;

    SimpleFileSparseRangeHeader header;
    header.sparse_range_magic_number = kSimpleSparseRangeMagicNumber;
    header.offset = range->offset;
    header.length = range->length;
    header.data_crc32 = range->data_crc32;

    int bytes_written = sparse_file_.Write(range->file_offset - sizeof(header),
                                           reinterpret_cast<char*>(&header),
                                           sizeof(header));
    if (bytes_written != base::checked_cast<int>(sizeof(header))) {
      DLOG(WARNING) << "Could not rewrite sparse range header.";
      return false;
    }
  }

  int bytes_written = sparse_file_.Write(range->file_offset + offset, buf, len);
  if (bytes_written < len) {
    DLOG(WARNING) << "Could not write sparse range.";
    return false;
  }

  return true;
}

bool SimpleSynchronousEntry::AppendSparseRange(int64_t offset,
                                               int len,
                                               const char* buf) {
  DCHECK_GE(offset, 0);
  DCHECK_GT(len, 0);
  DCHECK(buf);

  uint32_t data_crc32 =
      crc32(crc32(0L, Z_NULL, 0), reinterpret_cast<const Bytef*>(buf), len);

  SimpleFileSparseRangeHeader header;
  header.sparse_range_magic_number = kSimpleSparseRangeMagicNumber;
  header.offset = offset;
  header.length = len;
  header.data_crc32 = data_crc32;

  int bytes_written = sparse_file_.Write(sparse_tail_offset_,
                                         reinterpret_cast<char*>(&header),
                                         sizeof(header));
  if (bytes_written != base::checked_cast<int>(sizeof(header))) {
    DLOG(WARNING) << "Could not append sparse range header.";
    return false;
  }
  sparse_tail_offset_ += bytes_written;

  bytes_written = sparse_file_.Write(sparse_tail_offset_, buf, len);
  if (bytes_written < len) {
    DLOG(WARNING) << "Could not append sparse range data.";
    return false;
  }
  int64_t data_file_offset = sparse_tail_offset_;
  sparse_tail_offset_ += bytes_written;

  SparseRange range;
  range.offset = offset;
  range.length = len;
  range.data_crc32 = data_crc32;
  range.file_offset = data_file_offset;
  sparse_ranges_.insert(std::make_pair(offset, range));

  return true;
}

}  // namespace disk_cache
