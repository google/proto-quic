// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_header_block.h"

#include <string.h>

#include <algorithm>
#include <utility>

#include "base/logging.h"
#include "base/macros.h"
#include "base/values.h"
#include "net/base/arena.h"
#include "net/http/http_log_util.h"
#include "net/log/net_log_capture_mode.h"
#include "net/spdy/platform/api/spdy_estimate_memory_usage.h"

using base::StringPiece;
using std::dec;
using std::hex;
using std::make_pair;
using std::max;
using std::min;
using std::string;

namespace net {
namespace {

// By default, linked_hash_map's internal map allocates space for 100 map
// buckets on construction, which is larger than necessary.  Standard library
// unordered map implementations use a list of prime numbers to set the bucket
// count for a particular capacity.  |kInitialMapBuckets| is chosen to reduce
// memory usage for small header blocks, at the cost of having to rehash for
// large header blocks.
const size_t kInitialMapBuckets = 11;

// SpdyHeaderBlock::Storage allocates blocks of this size by default.
const size_t kDefaultStorageBlockSize = 2048;

const char kCookieKey[] = "cookie";
const char kNullSeparator = 0;

StringPiece SeparatorForKey(StringPiece key) {
  if (key == kCookieKey) {
    static StringPiece cookie_separator = "; ";
    return cookie_separator;
  } else {
    return StringPiece(&kNullSeparator, 1);
  }
}

}  // namespace

// This class provides a backing store for StringPieces. It previously used
// custom allocation logic, but now uses an UnsafeArena instead. It has the
// property that StringPieces that refer to data in Storage are never
// invalidated until the Storage is deleted or Clear() is called.
//
// Write operations always append to the last block. If there is not enough
// space to perform the write, a new block is allocated, and any unused space
// is wasted.
class SpdyHeaderBlock::Storage {
 public:
  Storage() : arena_(kDefaultStorageBlockSize) {}
  ~Storage() { Clear(); }

  StringPiece Write(const StringPiece s) {
    return StringPiece(arena_.Memdup(s.data(), s.size()), s.size());
  }

  // If |s| points to the most recent allocation from arena_, the arena will
  // reclaim the memory. Otherwise, this method is a no-op.
  void Rewind(const StringPiece s) {
    arena_.Free(const_cast<char*>(s.data()), s.size());
  }

  void Clear() { arena_.Reset(); }

  // Given a list of fragments and a separator, writes the fragments joined by
  // the separator to a contiguous region of memory. Returns a StringPiece
  // pointing to the region of memory.
  StringPiece WriteFragments(const std::vector<StringPiece>& fragments,
                             StringPiece separator) {
    if (fragments.empty()) {
      return StringPiece();
    }
    size_t total_size = separator.size() * (fragments.size() - 1);
    for (const auto fragment : fragments) {
      total_size += fragment.size();
    }
    char* dst = arena_.Alloc(total_size);
    size_t written = Join(dst, fragments, separator);
    DCHECK_EQ(written, total_size);
    return StringPiece(dst, total_size);
  }

  size_t bytes_allocated() const { return arena_.status().bytes_allocated(); }

  // TODO(xunjieli): https://crbug.com/669108. Merge this with bytes_allocated()
  size_t EstimateMemoryUsage() const {
    return arena_.status().bytes_allocated();
  }

 private:
  UnsafeArena arena_;

  DISALLOW_COPY_AND_ASSIGN(Storage);
};

SpdyHeaderBlock::HeaderValue::HeaderValue(Storage* storage,
                                          StringPiece key,
                                          StringPiece initial_value)
    : storage_(storage), fragments_({initial_value}), pair_({key, {}}) {}

SpdyHeaderBlock::HeaderValue::HeaderValue(HeaderValue&& other)
    : storage_(other.storage_),
      fragments_(std::move(other.fragments_)),
      pair_(std::move(other.pair_)) {}

SpdyHeaderBlock::HeaderValue& SpdyHeaderBlock::HeaderValue::operator=(
    HeaderValue&& other) {
  storage_ = other.storage_;
  fragments_ = std::move(other.fragments_);
  pair_ = std::move(other.pair_);
  return *this;
}

SpdyHeaderBlock::HeaderValue::~HeaderValue() {}

StringPiece SpdyHeaderBlock::HeaderValue::ConsolidatedValue() const {
  if (fragments_.empty()) {
    return StringPiece();
  }
  if (fragments_.size() > 1) {
    fragments_ = {
        storage_->WriteFragments(fragments_, SeparatorForKey(pair_.first))};
  }
  return fragments_[0];
}

void SpdyHeaderBlock::HeaderValue::Append(StringPiece fragment) {
  fragments_.push_back(fragment);
}

const std::pair<StringPiece, StringPiece>&
SpdyHeaderBlock::HeaderValue::as_pair() const {
  pair_.second = ConsolidatedValue();
  return pair_;
}

SpdyHeaderBlock::iterator::iterator(MapType::const_iterator it) : it_(it) {}

SpdyHeaderBlock::iterator::iterator(const iterator& other) : it_(other.it_) {}

SpdyHeaderBlock::iterator::~iterator() {}

SpdyHeaderBlock::ValueProxy::ValueProxy(
    SpdyHeaderBlock::MapType* block,
    SpdyHeaderBlock::Storage* storage,
    SpdyHeaderBlock::MapType::iterator lookup_result,
    const StringPiece key)
    : block_(block),
      storage_(storage),
      lookup_result_(lookup_result),
      key_(key),
      valid_(true) {}

SpdyHeaderBlock::ValueProxy::ValueProxy(ValueProxy&& other)
    : block_(other.block_),
      storage_(other.storage_),
      lookup_result_(other.lookup_result_),
      key_(other.key_),
      valid_(true) {
  other.valid_ = false;
}

SpdyHeaderBlock::ValueProxy& SpdyHeaderBlock::ValueProxy::operator=(
    SpdyHeaderBlock::ValueProxy&& other) {
  block_ = other.block_;
  storage_ = other.storage_;
  lookup_result_ = other.lookup_result_;
  key_ = other.key_;
  valid_ = true;
  other.valid_ = false;
  return *this;
}

SpdyHeaderBlock::ValueProxy::~ValueProxy() {
  // If the ValueProxy is destroyed while lookup_result_ == block_->end(),
  // the assignment operator was never used, and the block's Storage can
  // reclaim the memory used by the key. This makes lookup-only access to
  // SpdyHeaderBlock through operator[] memory-neutral.
  if (valid_ && lookup_result_ == block_->end()) {
    storage_->Rewind(key_);
  }
}

SpdyHeaderBlock::ValueProxy& SpdyHeaderBlock::ValueProxy::operator=(
    const StringPiece value) {
  if (lookup_result_ == block_->end()) {
    DVLOG(1) << "Inserting: (" << key_ << ", " << value << ")";
    lookup_result_ =
        block_
            ->emplace(make_pair(
                key_, HeaderValue(storage_, key_, storage_->Write(value))))
            .first;
  } else {
    DVLOG(1) << "Updating key: " << key_ << " with value: " << value;
    lookup_result_->second =
        HeaderValue(storage_, key_, storage_->Write(value));
  }
  return *this;
}

string SpdyHeaderBlock::ValueProxy::as_string() const {
  if (lookup_result_ == block_->end()) {
    return "";
  } else {
    return lookup_result_->second.value().as_string();
  }
}

SpdyHeaderBlock::SpdyHeaderBlock() : block_(kInitialMapBuckets) {}

SpdyHeaderBlock::SpdyHeaderBlock(SpdyHeaderBlock&& other) = default;

SpdyHeaderBlock::~SpdyHeaderBlock() {}

SpdyHeaderBlock& SpdyHeaderBlock::operator=(SpdyHeaderBlock&& other) {
  block_.swap(other.block_);
  storage_.swap(other.storage_);
  return *this;
}

SpdyHeaderBlock SpdyHeaderBlock::Clone() const {
  SpdyHeaderBlock copy;
  for (const auto& p : *this) {
    copy.AppendHeader(p.first, p.second);
  }
  return copy;
}

bool SpdyHeaderBlock::operator==(const SpdyHeaderBlock& other) const {
  return size() == other.size() && std::equal(begin(), end(), other.begin());
}

bool SpdyHeaderBlock::operator!=(const SpdyHeaderBlock& other) const {
  return !(operator==(other));
}

string SpdyHeaderBlock::DebugString() const {
  if (empty()) {
    return "{}";
  }

  string output = "\n{\n";
  for (auto it = begin(); it != end(); ++it) {
    output +=
        "  " + it->first.as_string() + " " + it->second.as_string() + "\n";
  }
  output.append("}\n");
  return output;
}

void SpdyHeaderBlock::clear() {
  block_.clear();
  storage_.reset();
}

void SpdyHeaderBlock::insert(const SpdyHeaderBlock::value_type& value) {
  // TODO(birenroy): Write new value in place of old value, if it fits.
  auto iter = block_.find(value.first);
  if (iter == block_.end()) {
    DVLOG(1) << "Inserting: (" << value.first << ", " << value.second << ")";
    AppendHeader(value.first, value.second);
  } else {
    DVLOG(1) << "Updating key: " << iter->first
             << " with value: " << value.second;
    auto* storage = GetStorage();
    iter->second =
        HeaderValue(storage, iter->first, storage->Write(value.second));
  }
}

SpdyHeaderBlock::ValueProxy SpdyHeaderBlock::operator[](const StringPiece key) {
  DVLOG(2) << "Operator[] saw key: " << key;
  StringPiece out_key;
  auto iter = block_.find(key);
  if (iter == block_.end()) {
    // We write the key first, to assure that the ValueProxy has a
    // reference to a valid StringPiece in its operator=.
    out_key = GetStorage()->Write(key);
    DVLOG(2) << "Key written as: " << std::hex
             << static_cast<const void*>(key.data()) << ", " << std::dec
             << key.size();
  } else {
    out_key = iter->first;
  }
  return ValueProxy(&block_, GetStorage(), iter, out_key);
}

void SpdyHeaderBlock::AppendValueOrAddHeader(const StringPiece key,
                                             const StringPiece value) {
  auto iter = block_.find(key);
  if (iter == block_.end()) {
    DVLOG(1) << "Inserting: (" << key << ", " << value << ")";
    AppendHeader(key, value);
    return;
  }
  DVLOG(1) << "Updating key: " << iter->first << "; appending value: " << value;
  iter->second.Append(GetStorage()->Write(value));
}

size_t SpdyHeaderBlock::EstimateMemoryUsage() const {
  // TODO(xunjieli): https://crbug.com/669108. Also include |block_| when EMU()
  // supports linked_hash_map.
  return SpdyEstimateMemoryUsage(storage_);
}

void SpdyHeaderBlock::AppendHeader(const StringPiece key,
                                   const StringPiece value) {
  auto* storage = GetStorage();
  auto backed_key = storage->Write(key);
  block_.emplace(make_pair(
      backed_key, HeaderValue(storage, backed_key, storage->Write(value))));
}

SpdyHeaderBlock::Storage* SpdyHeaderBlock::GetStorage() {
  if (!storage_) {
    storage_.reset(new Storage);
  }
  return storage_.get();
}

std::unique_ptr<base::Value> SpdyHeaderBlockNetLogCallback(
    const SpdyHeaderBlock* headers,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  base::DictionaryValue* headers_dict = new base::DictionaryValue();
  for (SpdyHeaderBlock::const_iterator it = headers->begin();
       it != headers->end(); ++it) {
    headers_dict->SetWithoutPathExpansion(
        it->first.as_string(),
        new base::StringValue(ElideHeaderValueForNetLog(
            capture_mode, it->first.as_string(), it->second.as_string())));
  }
  dict->Set("headers", headers_dict);
  return std::move(dict);
}

bool SpdyHeaderBlockFromNetLogParam(
    const base::Value* event_param,
    SpdyHeaderBlock* headers) {
  headers->clear();

  const base::DictionaryValue* dict = NULL;
  const base::DictionaryValue* header_dict = NULL;

  if (!event_param ||
      !event_param->GetAsDictionary(&dict) ||
      !dict->GetDictionary("headers", &header_dict)) {
    return false;
  }

  for (base::DictionaryValue::Iterator it(*header_dict); !it.IsAtEnd();
       it.Advance()) {
    string value;
    if (!it.value().GetAsString(&value)) {
      headers->clear();
      return false;
    }
    (*headers)[it.key()] = value;
  }
  return true;
}

size_t SpdyHeaderBlock::bytes_allocated() const {
  if (storage_ == nullptr) {
    return 0;
  } else {
    return storage_->bytes_allocated();
  }
}

size_t Join(char* dst,
            const std::vector<StringPiece>& fragments,
            StringPiece separator) {
  if (fragments.empty()) {
    return 0;
  }
  auto* original_dst = dst;
  auto it = fragments.begin();
  memcpy(dst, it->data(), it->size());
  dst += it->size();
  for (++it; it != fragments.end(); ++it) {
    memcpy(dst, separator.data(), separator.size());
    dst += separator.size();
    memcpy(dst, it->data(), it->size());
    dst += it->size();
  }
  return dst - original_dst;
}

}  // namespace net
