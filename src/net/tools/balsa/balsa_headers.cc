// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/balsa/balsa_headers.h"

#include <stdio.h>

#include <algorithm>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "base/strings/stringprintf.h"
#include "net/tools/balsa/balsa_enums.h"
#include "net/tools/balsa/buffer_interface.h"
#include "net/tools/balsa/simple_buffer.h"
#include "third_party/tcmalloc/chromium/src/base/googleinit.h"

#if defined(COMPILER_MSVC)
#include <string.h>
#define snprintf _snprintf
#define strncasecmp _strnicmp
#else
#include <strings.h>
#endif

namespace {

const char kContentLength[] = "Content-Length";
const char kTransferEncoding[] = "Transfer-Encoding";
const char kSpaceChar = ' ';

std::unordered_set<base::StringPiece,
                   net::StringPieceCaseHash,
                   net::StringPieceCaseEqual>
    g_multivalued_headers;

void InitMultivaluedHeaders() {
  g_multivalued_headers.insert("accept");
  g_multivalued_headers.insert("accept-charset");
  g_multivalued_headers.insert("accept-encoding");
  g_multivalued_headers.insert("accept-language");
  g_multivalued_headers.insert("accept-ranges");
  g_multivalued_headers.insert("allow");
  g_multivalued_headers.insert("cache-control");
  g_multivalued_headers.insert("connection");
  g_multivalued_headers.insert("content-encoding");
  g_multivalued_headers.insert("content-language");
  g_multivalued_headers.insert("expect");
  g_multivalued_headers.insert("if-match");
  g_multivalued_headers.insert("if-none-match");
  g_multivalued_headers.insert("pragma");
  g_multivalued_headers.insert("proxy-authenticate");
  g_multivalued_headers.insert("te");
  g_multivalued_headers.insert("trailer");
  g_multivalued_headers.insert("transfer-encoding");
  g_multivalued_headers.insert("upgrade");
  g_multivalued_headers.insert("vary");
  g_multivalued_headers.insert("via");
  g_multivalued_headers.insert("warning");
  g_multivalued_headers.insert("www-authenticate");
  // Not mentioned in RFC 2616, but it can have multiple values.
  g_multivalued_headers.insert("set-cookie");
}

REGISTER_MODULE_INITIALIZER(multivalued_headers, InitMultivaluedHeaders());

const int kFastToBufferSize = 32;  // I think 22 is adequate, but anyway..

}  // namespace

namespace net {

BalsaHeaders::iterator_base::iterator_base() : headers_(NULL), idx_(0) { }

BalsaHeaders::iterator_base::iterator_base(const iterator_base& it)
    : headers_(it.headers_),
      idx_(it.idx_) {
}

std::ostream& BalsaHeaders::iterator_base::operator<<(std::ostream& os) const {
  os << "[" << this->headers_ << ", " << this->idx_ << "]";
  return os;
}

BalsaHeaders::iterator_base::iterator_base(const BalsaHeaders* headers,
                                           HeaderLines::size_type index)
    : headers_(headers),
      idx_(index) {
}

BalsaBuffer::~BalsaBuffer() {
  CleanupBlocksStartingFrom(0);
}

// Returns the total amount of memory used by the buffer blocks.
size_t BalsaBuffer::GetTotalBufferBlockSize() const {
  size_t buffer_size = 0;
  for (Blocks::const_iterator iter = blocks_.begin();
       iter != blocks_.end();
       ++iter) {
    buffer_size += iter->buffer_size;
  }
  return buffer_size;
}

void BalsaBuffer::WriteToContiguousBuffer(const base::StringPiece& sp) {
  if (sp.empty()) {
    return;
  }
  CHECK(can_write_to_contiguous_buffer_);
  DCHECK_GE(blocks_.size(), 1u);
  if (blocks_[0].buffer == NULL && sp.size() <= blocksize_) {
    blocks_[0] = AllocBlock();
    memcpy(blocks_[0].start_of_unused_bytes(), sp.data(), sp.size());
  } else if (blocks_[0].bytes_free < sp.size()) {
    // the first block isn't big enough, resize it.
    const size_t old_storage_size_used = blocks_[0].bytes_used();
    const size_t new_storage_size = old_storage_size_used + sp.size();
    char* new_storage = new char[new_storage_size];
    char* old_storage = blocks_[0].buffer;
    if (old_storage_size_used) {
      memcpy(new_storage, old_storage, old_storage_size_used);
    }
    memcpy(new_storage + old_storage_size_used, sp.data(), sp.size());
    blocks_[0].buffer = new_storage;
    blocks_[0].bytes_free = sp.size();
    blocks_[0].buffer_size = new_storage_size;
    delete[] old_storage;
  } else {
    memcpy(blocks_[0].start_of_unused_bytes(), sp.data(), sp.size());
  }
  blocks_[0].bytes_free -= sp.size();
}

base::StringPiece BalsaBuffer::Write(const base::StringPiece& sp,
                                     Blocks::size_type* block_buffer_idx) {
  if (sp.empty()) {
    return sp;
  }
  char* storage = Reserve(sp.size(), block_buffer_idx);
  memcpy(storage, sp.data(), sp.size());
  return base::StringPiece(storage, sp.size());
}

char* BalsaBuffer::Reserve(size_t size,
                           Blocks::size_type* block_buffer_idx) {
  // There should always be a 'first_block', even if it
  // contains nothing.
  DCHECK_GE(blocks_.size(), 1u);
  BufferBlock* block = NULL;
  Blocks::size_type block_idx = can_write_to_contiguous_buffer_ ? 1 : 0;
  for (; block_idx < blocks_.size(); ++block_idx) {
    if (blocks_[block_idx].bytes_free >= size) {
      block = &blocks_[block_idx];
      break;
    }
  }
  if (block == NULL) {
    if (blocksize_ < size) {
      blocks_.push_back(AllocCustomBlock(size));
    } else {
      blocks_.push_back(AllocBlock());
    }
    block = &blocks_.back();
  }

  char* storage = block->start_of_unused_bytes();
  block->bytes_free -= size;
  if (block_buffer_idx) {
    *block_buffer_idx = block_idx;
  }
  return storage;
}

void BalsaBuffer::Clear() {
  CHECK(!blocks_.empty());
  if (blocksize_ == blocks_[0].buffer_size) {
    CleanupBlocksStartingFrom(1);
    blocks_[0].bytes_free = blocks_[0].buffer_size;
  } else {
    CleanupBlocksStartingFrom(0);
    blocks_.push_back(AllocBlock());
  }
  DCHECK_GE(blocks_.size(), 1u);
  can_write_to_contiguous_buffer_ = true;
}

void BalsaBuffer::Swap(BalsaBuffer* b) {
  blocks_.swap(b->blocks_);
  std::swap(can_write_to_contiguous_buffer_,
            b->can_write_to_contiguous_buffer_);
  std::swap(blocksize_, b->blocksize_);
}

void BalsaBuffer::CopyFrom(const BalsaBuffer& b) {
  CleanupBlocksStartingFrom(0);
  blocks_.resize(b.blocks_.size());
  for (Blocks::size_type i = 0; i < blocks_.size(); ++i) {
    blocks_[i] = CopyBlock(b.blocks_[i]);
  }
  blocksize_ = b.blocksize_;
  can_write_to_contiguous_buffer_ = b.can_write_to_contiguous_buffer_;
}

BalsaBuffer::BalsaBuffer()
    : blocksize_(kDefaultBlocksize), can_write_to_contiguous_buffer_(true) {
  blocks_.push_back(AllocBlock());
}

BalsaBuffer::BalsaBuffer(size_t blocksize) :
    blocksize_(blocksize), can_write_to_contiguous_buffer_(true) {
  blocks_.push_back(AllocBlock());
}

BalsaBuffer::BufferBlock BalsaBuffer::AllocBlock() {
  return AllocCustomBlock(blocksize_);
}

BalsaBuffer::BufferBlock BalsaBuffer::AllocCustomBlock(size_t blocksize) {
  return BufferBlock(new char[blocksize], blocksize, blocksize);
}

BalsaBuffer::BufferBlock BalsaBuffer::CopyBlock(const BufferBlock& b) {
  BufferBlock block = b;
  if (b.buffer == NULL) {
    return block;
  }

  block.buffer = new char[b.buffer_size];
  memcpy(block.buffer, b.buffer, b.bytes_used());
  return block;
}

void BalsaBuffer::CleanupBlocksStartingFrom(Blocks::size_type start_idx) {
  for (Blocks::size_type i = start_idx; i < blocks_.size(); ++i) {
    delete[] blocks_[i].buffer;
  }
  blocks_.resize(start_idx);
}

BalsaHeaders::const_header_lines_key_iterator::const_header_lines_key_iterator(
    const const_header_lines_key_iterator& other)
    : iterator_base(other),
      key_(other.key_) {
}

BalsaHeaders::const_header_lines_key_iterator::const_header_lines_key_iterator(
    const BalsaHeaders* headers,
    HeaderLines::size_type index,
    const base::StringPiece& key)
    : iterator_base(headers, index),
      key_(key) {
}

BalsaHeaders::const_header_lines_key_iterator::const_header_lines_key_iterator(
    const BalsaHeaders* headers,
    HeaderLines::size_type index)
    : iterator_base(headers, index) {
}

BalsaHeaders::BalsaHeaders()
    : balsa_buffer_(4096),
      content_length_(0),
      content_length_status_(BalsaHeadersEnums::NO_CONTENT_LENGTH),
      parsed_response_code_(0),
      firstline_buffer_base_idx_(0),
      whitespace_1_idx_(0),
      non_whitespace_1_idx_(0),
      whitespace_2_idx_(0),
      non_whitespace_2_idx_(0),
      whitespace_3_idx_(0),
      non_whitespace_3_idx_(0),
      whitespace_4_idx_(0),
      end_of_firstline_idx_(0),
      transfer_encoding_is_chunked_(false) {
}

BalsaHeaders::~BalsaHeaders() {}

void BalsaHeaders::Clear() {
  balsa_buffer_.Clear();
  transfer_encoding_is_chunked_ = false;
  content_length_ = 0;
  content_length_status_ = BalsaHeadersEnums::NO_CONTENT_LENGTH;
  parsed_response_code_ = 0;
  firstline_buffer_base_idx_ = 0;
  whitespace_1_idx_ = 0;
  non_whitespace_1_idx_ = 0;
  whitespace_2_idx_ = 0;
  non_whitespace_2_idx_ = 0;
  whitespace_3_idx_ = 0;
  non_whitespace_3_idx_ = 0;
  whitespace_4_idx_ = 0;
  end_of_firstline_idx_ = 0;
  header_lines_.clear();
}

void BalsaHeaders::Swap(BalsaHeaders* other) {
  // Protect against swapping with self.
  if (this == other) return;

  balsa_buffer_.Swap(&other->balsa_buffer_);

  bool tmp_bool = transfer_encoding_is_chunked_;
  transfer_encoding_is_chunked_ = other->transfer_encoding_is_chunked_;
  other->transfer_encoding_is_chunked_ = tmp_bool;

  size_t tmp_size_t = content_length_;
  content_length_ = other->content_length_;
  other->content_length_ = tmp_size_t;

  BalsaHeadersEnums::ContentLengthStatus tmp_status =
      content_length_status_;
  content_length_status_ = other->content_length_status_;
  other->content_length_status_ = tmp_status;

  tmp_size_t = parsed_response_code_;
  parsed_response_code_ = other->parsed_response_code_;
  other->parsed_response_code_ = tmp_size_t;

  BalsaBuffer::Blocks::size_type tmp_blk_idx = firstline_buffer_base_idx_;
  firstline_buffer_base_idx_ = other->firstline_buffer_base_idx_;
  other->firstline_buffer_base_idx_ = tmp_blk_idx;

  tmp_size_t = whitespace_1_idx_;
  whitespace_1_idx_ = other->whitespace_1_idx_;
  other->whitespace_1_idx_ = tmp_size_t;

  tmp_size_t = non_whitespace_1_idx_;
  non_whitespace_1_idx_ = other->non_whitespace_1_idx_;
  other->non_whitespace_1_idx_ = tmp_size_t;

  tmp_size_t = whitespace_2_idx_;
  whitespace_2_idx_ = other->whitespace_2_idx_;
  other->whitespace_2_idx_ = tmp_size_t;

  tmp_size_t = non_whitespace_2_idx_;
  non_whitespace_2_idx_ = other->non_whitespace_2_idx_;
  other->non_whitespace_2_idx_ = tmp_size_t;

  tmp_size_t = whitespace_3_idx_;
  whitespace_3_idx_ = other->whitespace_3_idx_;
  other->whitespace_3_idx_ = tmp_size_t;

  tmp_size_t = non_whitespace_3_idx_;
  non_whitespace_3_idx_ = other->non_whitespace_3_idx_;
  other->non_whitespace_3_idx_ = tmp_size_t;

  tmp_size_t = whitespace_4_idx_;
  whitespace_4_idx_ = other->whitespace_4_idx_;
  other->whitespace_4_idx_ = tmp_size_t;

  tmp_size_t = end_of_firstline_idx_;
  end_of_firstline_idx_ = other->end_of_firstline_idx_;
  other->end_of_firstline_idx_ = tmp_size_t;

  swap(header_lines_, other->header_lines_);
}

void BalsaHeaders::CopyFrom(const BalsaHeaders& other) {
  // Protect against copying with self.
  if (this == &other) return;

  balsa_buffer_.CopyFrom(other.balsa_buffer_);
  transfer_encoding_is_chunked_ = other.transfer_encoding_is_chunked_;
  content_length_ = other.content_length_;
  content_length_status_ = other.content_length_status_;
  parsed_response_code_ = other.parsed_response_code_;
  firstline_buffer_base_idx_ = other.firstline_buffer_base_idx_;
  whitespace_1_idx_ = other.whitespace_1_idx_;
  non_whitespace_1_idx_ = other.non_whitespace_1_idx_;
  whitespace_2_idx_ = other.whitespace_2_idx_;
  non_whitespace_2_idx_ = other.non_whitespace_2_idx_;
  whitespace_3_idx_ = other.whitespace_3_idx_;
  non_whitespace_3_idx_ = other.non_whitespace_3_idx_;
  whitespace_4_idx_ = other.whitespace_4_idx_;
  end_of_firstline_idx_ = other.end_of_firstline_idx_;
  header_lines_ = other.header_lines_;
}

void BalsaHeaders::AddAndMakeDescription(const base::StringPiece& key,
                                         const base::StringPiece& value,
                                         HeaderLineDescription* d) {
  CHECK(d != NULL);
  // + 2 to size for ": "
  size_t line_size = key.size() + 2 + value.size();
  BalsaBuffer::Blocks::size_type block_buffer_idx = 0;
  char* storage = balsa_buffer_.Reserve(line_size, &block_buffer_idx);
  size_t base_idx = storage - GetPtr(block_buffer_idx);

  char* cur_loc = storage;
  memcpy(cur_loc, key.data(), key.size());
  cur_loc += key.size();
  *cur_loc = ':';
  ++cur_loc;
  *cur_loc = ' ';
  ++cur_loc;
  memcpy(cur_loc, value.data(), value.size());
  *d = HeaderLineDescription(base_idx,
                             base_idx + key.size(),
                             base_idx + key.size() + 2,
                             base_idx + key.size() + 2 + value.size(),
                             block_buffer_idx);
}

void BalsaHeaders::AppendOrPrependAndMakeDescription(
    const base::StringPiece& key,
    const base::StringPiece& value,
    bool append,
    HeaderLineDescription* d) {
  // Figure out how much space we need to reserve for the new header size.
  size_t old_value_size = d->last_char_idx - d->value_begin_idx;
  if (old_value_size == 0) {
    AddAndMakeDescription(key, value, d);
    return;
  }
  base::StringPiece old_value(GetPtr(d->buffer_base_idx) + d->value_begin_idx,
                        old_value_size);

  BalsaBuffer::Blocks::size_type block_buffer_idx = 0;
  // + 3 because we potentially need to add ": ", and "," to the line.
  size_t new_size = key.size() + 3 + old_value_size + value.size();
  char* storage = balsa_buffer_.Reserve(new_size, &block_buffer_idx);
  size_t base_idx = storage - GetPtr(block_buffer_idx);

  base::StringPiece first_value = old_value;
  base::StringPiece second_value = value;
  if (!append) {  // !append == prepend
    first_value = value;
    second_value = old_value;
  }
  char* cur_loc = storage;
  memcpy(cur_loc, key.data(), key.size());
  cur_loc += key.size();
  *cur_loc = ':';
  ++cur_loc;
  *cur_loc = ' ';
  ++cur_loc;
  memcpy(cur_loc, first_value.data(), first_value.size());
  cur_loc += first_value.size();
  *cur_loc = ',';
  ++cur_loc;
  memcpy(cur_loc, second_value.data(), second_value.size());

  *d = HeaderLineDescription(base_idx,
                             base_idx + key.size(),
                             base_idx + key.size() + 2,
                             base_idx + new_size,
                             block_buffer_idx);
}

// Removes all keys value pairs with key 'key' starting at 'start'.
void BalsaHeaders::RemoveAllOfHeaderStartingAt(const base::StringPiece& key,
                                               HeaderLines::iterator start) {
  while (start != header_lines_.end()) {
    start->skip = true;
    ++start;
    start = GetHeaderLinesIterator(key, start);
  }
}

void BalsaHeaders::HackHeader(const base::StringPiece& key,
                              const base::StringPiece& value) {
  // See TODO in balsa_headers.h
  const HeaderLines::iterator end = header_lines_.end();
  const HeaderLines::iterator begin = header_lines_.begin();
  HeaderLines::iterator i = GetHeaderLinesIteratorNoSkip(key, begin);
  if (i != end) {
    // First, remove all of the header lines including this one.  We want to
    // remove before replacing, in case our replacement ends up being appended
    // at the end (and thus would be removed by this call)
    RemoveAllOfHeaderStartingAt(key, i);
    // Now add the replacement, at this location.
    AddAndMakeDescription(key, value, &(*i));
    return;
  }
  AppendHeader(key, value);
}

void BalsaHeaders::HackAppendToHeader(const base::StringPiece& key,
                                      const base::StringPiece& append_value) {
  // See TODO in balsa_headers.h
  const HeaderLines::iterator end = header_lines_.end();
  const HeaderLines::iterator begin = header_lines_.begin();

  HeaderLines::iterator i = GetHeaderLinesIterator(key, begin);
  if (i == end) {
    HackHeader(key, append_value);
    return;
  }

  AppendOrPrependAndMakeDescription(key, append_value, true, &(*i));
}

void BalsaHeaders::ReplaceOrAppendHeader(const base::StringPiece& key,
                                         const base::StringPiece& value) {
  const HeaderLines::iterator end = header_lines_.end();
  const HeaderLines::iterator begin = header_lines_.begin();
  HeaderLines::iterator i = GetHeaderLinesIterator(key, begin);
  if (i != end) {
    // First, remove all of the header lines including this one.  We want to
    // remove before replacing, in case our replacement ends up being appended
    // at the end (and thus would be removed by this call)
    RemoveAllOfHeaderStartingAt(key, i);
    // Now, take the first instance and replace it.  This will remove the
    // 'skipped' tag if the replacement is done in-place.
    AddAndMakeDescription(key, value, &(*i));
    return;
  }
  AppendHeader(key, value);
}

void BalsaHeaders::AppendHeader(const base::StringPiece& key,
                                const base::StringPiece& value) {
  HeaderLineDescription hld;
  AddAndMakeDescription(key, value, &hld);
  header_lines_.push_back(hld);
}

void BalsaHeaders::AppendToHeader(const base::StringPiece& key,
                                  const base::StringPiece& value) {
  AppendOrPrependToHeader(key, value, true);
}

void BalsaHeaders::PrependToHeader(const base::StringPiece& key,
                                   const base::StringPiece& value) {
  AppendOrPrependToHeader(key, value, false);
}

base::StringPiece BalsaHeaders::GetValueFromHeaderLineDescription(
    const HeaderLineDescription& line) const {
  DCHECK_GE(line.last_char_idx, line.value_begin_idx);
  return base::StringPiece(GetPtr(line.buffer_base_idx) + line.value_begin_idx,
                     line.last_char_idx - line.value_begin_idx);
}

const base::StringPiece BalsaHeaders::GetHeader(
    const base::StringPiece& key) const {
  DCHECK(!IsMultivaluedHeader(key))
      << "Header '" << key << "' may consist of multiple lines. Do not "
      << "use BalsaHeaders::GetHeader() or you may be missing some of its "
      << "values.";
  const HeaderLines::const_iterator end = header_lines_.end();
  const HeaderLines::const_iterator begin = header_lines_.begin();
  HeaderLines::const_iterator i = GetConstHeaderLinesIterator(key, begin);
  if (i == end) {
    return base::StringPiece();
  }
  return GetValueFromHeaderLineDescription(*i);
}

BalsaHeaders::const_header_lines_iterator BalsaHeaders::GetHeaderPosition(
    const base::StringPiece& key) const {
  const HeaderLines::const_iterator end = header_lines_.end();
  const HeaderLines::const_iterator begin = header_lines_.begin();
  HeaderLines::const_iterator i = GetConstHeaderLinesIterator(key, begin);
  if (i == end) {
    return header_lines_end();
  }

  return const_header_lines_iterator(this, (i - begin));
}

BalsaHeaders::const_header_lines_key_iterator BalsaHeaders::GetIteratorForKey(
    const base::StringPiece& key) const {
  HeaderLines::const_iterator i =
      GetConstHeaderLinesIterator(key, header_lines_.begin());
  if (i == header_lines_.end()) {
    return header_lines_key_end();
  }

  const HeaderLines::const_iterator begin = header_lines_.begin();
  return const_header_lines_key_iterator(this, (i - begin), key);
}

void BalsaHeaders::AppendOrPrependToHeader(const base::StringPiece& key,
                                           const base::StringPiece& value,
                                           bool append) {
  HeaderLines::iterator i = GetHeaderLinesIterator(key, header_lines_.begin());
  if (i == header_lines_.end()) {
    // The header did not exist already.  Instead of appending to an existing
    // header simply append the key/value pair to the headers.
    AppendHeader(key, value);
    return;
  }
  HeaderLineDescription hld = *i;

  AppendOrPrependAndMakeDescription(key, value, append, &hld);

  // Invalidate the old header line and add the new one.
  i->skip = true;
  header_lines_.push_back(hld);
}

BalsaHeaders::HeaderLines::const_iterator
BalsaHeaders::GetConstHeaderLinesIterator(
    const base::StringPiece& key,
    BalsaHeaders::HeaderLines::const_iterator start) const {
  const HeaderLines::const_iterator end = header_lines_.end();
  for (HeaderLines::const_iterator i = start; i != end; ++i) {
    const HeaderLineDescription& line = *i;
    if (line.skip) {
      continue;
    }
    const size_t key_len = line.key_end_idx - line.first_char_idx;

    if (key_len != key.size()) {
      continue;
    }
    if (strncasecmp(GetPtr(line.buffer_base_idx) + line.first_char_idx,
                    key.data(), key_len) == 0) {
      DCHECK_GE(line.last_char_idx, line.value_begin_idx);
      return i;
    }
  }
  return end;
}

BalsaHeaders::HeaderLines::iterator BalsaHeaders::GetHeaderLinesIteratorNoSkip(
    const base::StringPiece& key,
    BalsaHeaders::HeaderLines::iterator start) {
  const HeaderLines::iterator end = header_lines_.end();
  for (HeaderLines::iterator i = start; i != end; ++i) {
    const HeaderLineDescription& line = *i;
    const size_t key_len = line.key_end_idx - line.first_char_idx;

    if (key_len != key.size()) {
      continue;
    }
    if (strncasecmp(GetPtr(line.buffer_base_idx) + line.first_char_idx,
                    key.data(), key_len) == 0) {
      DCHECK_GE(line.last_char_idx, line.value_begin_idx);
      return i;
    }
  }
  return end;
}

BalsaHeaders::HeaderLines::iterator BalsaHeaders::GetHeaderLinesIterator(
    const base::StringPiece& key,
    BalsaHeaders::HeaderLines::iterator start) {
  const HeaderLines::iterator end = header_lines_.end();
  for (HeaderLines::iterator i = start; i != end; ++i) {
    const HeaderLineDescription& line = *i;
    if (line.skip) {
      continue;
    }
    const size_t key_len = line.key_end_idx - line.first_char_idx;

    if (key_len != key.size()) {
      continue;
    }
    if (strncasecmp(GetPtr(line.buffer_base_idx) + line.first_char_idx,
                    key.data(), key_len) == 0) {
      DCHECK_GE(line.last_char_idx, line.value_begin_idx);
      return i;
    }
  }
  return end;
}

void BalsaHeaders::GetAllOfHeader(
    const base::StringPiece& key, std::vector<base::StringPiece>* out) const {
  for (const_header_lines_key_iterator it = GetIteratorForKey(key);
       it != header_lines_end(); ++it) {
    out->push_back(it->second);
  }
}

bool BalsaHeaders::HasNonEmptyHeader(const base::StringPiece& key) const {
  for (const_header_lines_key_iterator it = GetIteratorForKey(key);
       it != header_lines_key_end(); ++it) {
    if (!it->second.empty())
      return true;
  }
  return false;
}

void BalsaHeaders::GetAllOfHeaderAsString(const base::StringPiece& key,
                                          std::string* out) const {
  const_header_lines_iterator it = header_lines_begin();
  const_header_lines_iterator end = header_lines_end();

  for (; it != end; ++it) {
    if (key == it->first) {
      if (!out->empty()) {
        out->append(",");
      }
      out->append(std::string(it->second.data(), it->second.size()));
    }
  }
}

// static
bool BalsaHeaders::IsMultivaluedHeader(const base::StringPiece& header) {
  return g_multivalued_headers.find(header) != g_multivalued_headers.end();
}

void BalsaHeaders::RemoveAllOfHeader(const base::StringPiece& key) {
  HeaderLines::iterator it = GetHeaderLinesIterator(key, header_lines_.begin());
  RemoveAllOfHeaderStartingAt(key, it);
}

void BalsaHeaders::RemoveAllHeadersWithPrefix(const base::StringPiece& key) {
  for (HeaderLines::size_type i = 0; i < header_lines_.size(); ++i) {
    if (header_lines_[i].skip) {
      continue;
    }
    HeaderLineDescription& line = header_lines_[i];
    const size_t key_len = line.key_end_idx - line.first_char_idx;
    if (key_len < key.size()) {
      // If the key given to us is longer than this header, don't consider it.
      continue;
    }
    if (!strncasecmp(GetPtr(line.buffer_base_idx) + line.first_char_idx,
                     key.data(), key.size())) {
      line.skip = true;
    }
  }
}

size_t BalsaHeaders::GetMemoryUsedLowerBound() const {
  return (sizeof(*this) +
          balsa_buffer_.GetTotalBufferBlockSize() +
          header_lines_.capacity() * sizeof(HeaderLineDescription));
}

size_t BalsaHeaders::GetSizeForWriteBuffer() const {
  // First add the space required for the first line + CRLF
  size_t write_buf_size = whitespace_4_idx_ - non_whitespace_1_idx_ + 2;
  // Then add the space needed for each header line to write out + CRLF.
  const HeaderLines::size_type end = header_lines_.size();
  for (HeaderLines::size_type i = 0; i < end; ++i) {
    const HeaderLineDescription& line = header_lines_[i];
    if (!line.skip) {
      // Add the key size and ": ".
      write_buf_size += line.key_end_idx - line.first_char_idx + 2;
      // Add the value size and the CRLF
      write_buf_size += line.last_char_idx - line.value_begin_idx + 2;
    }
  }
  // Finally tag on the terminal CRLF.
  return write_buf_size + 2;
}

void BalsaHeaders::DumpToString(std::string* str) const {
  const base::StringPiece firstline = first_line();
  const int buffer_length =
      OriginalHeaderStreamEnd() - OriginalHeaderStreamBegin();
  // First check whether the header object is empty.
  if (firstline.empty() && buffer_length == 0) {
    str->append("\n<empty header>\n");
    return;
  }

  // Then check whether the header is in a partially parsed state. If so, just
  // dump the raw data.
  if (balsa_buffer_.can_write_to_contiguous_buffer()) {
    base::StringAppendF(str, "\n<incomplete header len: %d>\n%.*s\n",
                        buffer_length, buffer_length,
                        OriginalHeaderStreamBegin());
    return;
  }

  DumpHeadersToString(str);
}

void BalsaHeaders::DumpHeadersToString(std::string* str) const {
  const base::StringPiece firstline = first_line();
  // If the header is complete, then just dump them with the logical key value
  // pair.
  str->reserve(str->size() + GetSizeForWriteBuffer());
  base::StringAppendF(str, "\n %.*s\n",
                      static_cast<int>(firstline.size()),
                      firstline.data());
  BalsaHeaders::const_header_lines_iterator i = header_lines_begin();
  for (; i != header_lines_end(); ++i) {
    base::StringAppendF(str, " %.*s: %.*s\n",
                        static_cast<int>(i->first.size()), i->first.data(),
                        static_cast<int>(i->second.size()), i->second.data());
  }
}

void BalsaHeaders::SetFirstLine(const base::StringPiece& line) {
  base::StringPiece new_line = balsa_buffer_.Write(line,
                                                   &firstline_buffer_base_idx_);
  whitespace_1_idx_ = new_line.data() - GetPtr(firstline_buffer_base_idx_);
  non_whitespace_1_idx_ = whitespace_1_idx_;
  whitespace_4_idx_ = whitespace_1_idx_ + line.size();
  whitespace_2_idx_ = whitespace_4_idx_;
  non_whitespace_2_idx_ = whitespace_4_idx_;
  whitespace_3_idx_ = whitespace_4_idx_;
  non_whitespace_3_idx_ = whitespace_4_idx_;
  end_of_firstline_idx_ = whitespace_4_idx_;
}

void BalsaHeaders::SetContentLength(size_t length) {
  // If the content-length is already the one we want, don't do anything.
  if (content_length_status_ == BalsaHeadersEnums::VALID_CONTENT_LENGTH &&
      content_length_ == length) {
    return;
  }
  const base::StringPiece content_length(kContentLength,
                                         sizeof(kContentLength) - 1);
  // If header state indicates that there is either a content length or
  // transfer encoding header, remove them before adding the new content
  // length. There is always the possibility that client can manually add
  // either header directly and cause content_length_status_ or
  // transfer_encoding_is_chunked_ to be inconsistent with the actual header.
  // In the interest of efficiency, however, we will assume that clients will
  // use the header object correctly and thus we will not scan the all headers
  // each time this function is called.
  if (content_length_status_ != BalsaHeadersEnums::NO_CONTENT_LENGTH) {
    RemoveAllOfHeader(content_length);
  } else if (transfer_encoding_is_chunked_) {
    const base::StringPiece transfer_encoding(kTransferEncoding,
                                        sizeof(kTransferEncoding) - 1);
    RemoveAllOfHeader(transfer_encoding);
    transfer_encoding_is_chunked_ = false;
  }
  content_length_status_ = BalsaHeadersEnums::VALID_CONTENT_LENGTH;
  content_length_ = length;
  // FastUInt64ToBuffer is supposed to use a maximum of kFastToBufferSize bytes.
  char buffer[kFastToBufferSize];
  int len_converted = snprintf(buffer, sizeof(buffer), "%zd", length);
  CHECK_GT(len_converted, 0);
  const base::StringPiece length_str(buffer, len_converted);
  AppendHeader(content_length, length_str);
}

void BalsaHeaders::SetChunkEncoding(bool chunk_encode) {
  if (transfer_encoding_is_chunked_ == chunk_encode) {
    return;
  }
  if (content_length_status_ != BalsaHeadersEnums::NO_CONTENT_LENGTH &&
      chunk_encode) {
    // Want to change to chunk encoding, but have content length. Arguably we
    // can leave this step out, since transfer-encoding overrides
    // content-length.
    const base::StringPiece content_length(kContentLength,
                                     sizeof(kContentLength) - 1);
    RemoveAllOfHeader(content_length);
    content_length_status_ = BalsaHeadersEnums::NO_CONTENT_LENGTH;
    content_length_ = 0;
  }
  const base::StringPiece transfer_encoding(kTransferEncoding,
                                      sizeof(kTransferEncoding) - 1);
  if (chunk_encode) {
    const char kChunked[] = "chunked";
    const base::StringPiece chunked(kChunked, sizeof(kChunked) - 1);
    AppendHeader(transfer_encoding, chunked);
  } else {
    RemoveAllOfHeader(transfer_encoding);
  }
  transfer_encoding_is_chunked_ = chunk_encode;
}

// See the comment about this function in the header file for a
// warning about its usage.
void BalsaHeaders::SetFirstlineFromStringPieces(
    const base::StringPiece& firstline_a,
    const base::StringPiece& firstline_b,
    const base::StringPiece& firstline_c) {
  size_t line_size = (firstline_a.size() +
                      firstline_b.size() +
                      firstline_c.size() +
                      2);
  char* storage = balsa_buffer_.Reserve(line_size, &firstline_buffer_base_idx_);
  char* cur_loc = storage;

  memcpy(cur_loc, firstline_a.data(), firstline_a.size());
  cur_loc += firstline_a.size();

  *cur_loc = ' ';
  ++cur_loc;

  memcpy(cur_loc, firstline_b.data(), firstline_b.size());
  cur_loc += firstline_b.size();

  *cur_loc = ' ';
  ++cur_loc;

  memcpy(cur_loc, firstline_c.data(), firstline_c.size());

  whitespace_1_idx_ = storage - GetPtr(firstline_buffer_base_idx_);
  non_whitespace_1_idx_ = whitespace_1_idx_;
  whitespace_2_idx_ = non_whitespace_1_idx_ + firstline_a.size();
  non_whitespace_2_idx_ = whitespace_2_idx_ + 1;
  whitespace_3_idx_ = non_whitespace_2_idx_ + firstline_b.size();
  non_whitespace_3_idx_ = whitespace_3_idx_ + 1;
  whitespace_4_idx_ = non_whitespace_3_idx_ + firstline_c.size();
  end_of_firstline_idx_ = whitespace_4_idx_;
}

void BalsaHeaders::SetRequestMethod(const base::StringPiece& method) {
  // This is the first of the three parts of the firstline.
  if (method.size() <= (whitespace_2_idx_ - non_whitespace_1_idx_)) {
    non_whitespace_1_idx_ = whitespace_2_idx_ - method.size();
    char* stream_begin = GetPtr(firstline_buffer_base_idx_);
    memcpy(stream_begin + non_whitespace_1_idx_,
           method.data(),
           method.size());
  } else {
    // The new method is too large to fit in the space available for the old
    // one, so we have to reformat the firstline.
    SetFirstlineFromStringPieces(method, request_uri(), request_version());
  }
}

void BalsaHeaders::SetResponseVersion(const base::StringPiece& version) {
  // Note: There is no difference between request_method() and
  // response_Version(). Thus, a function to set one is equivalent to a
  // function to set the other. We maintain two functions for this as it is
  // much more descriptive, and makes code more understandable.
  SetRequestMethod(version);
}

void BalsaHeaders::SetRequestUri(const base::StringPiece& uri) {
  SetFirstlineFromStringPieces(request_method(), uri, request_version());
}

void BalsaHeaders::SetResponseCode(const base::StringPiece& code) {
  // Note: There is no difference between request_uri() and response_code().
  // Thus, a function to set one is equivalent to a function to set the other.
  // We maintain two functions for this as it is much more descriptive, and
  // makes code more understandable.
  SetRequestUri(code);
}

void BalsaHeaders::SetParsedResponseCodeAndUpdateFirstline(
    size_t parsed_response_code) {
  char buffer[kFastToBufferSize];
  int len_converted = snprintf(buffer, sizeof(buffer),
                               "%zd", parsed_response_code);
  CHECK_GT(len_converted, 0);
  SetResponseCode(base::StringPiece(buffer, len_converted));
}

void BalsaHeaders::SetRequestVersion(const base::StringPiece& version) {
  // This is the last of the three parts of the firstline.
  // Since whitespace_3_idx and non_whitespace_3_idx may point to the same
  // place, we ensure below that any available space includes space for a
  // litteral space (' ') character between the second component and the third
  // component. If the space between whitespace_3_idx_ and
  // end_of_firstline_idx_ is >= to version.size() + 1 (for the space), then we
  // can update the firstline in-place.
  char* stream_begin = GetPtr(firstline_buffer_base_idx_);
  if (version.size() + 1 <= end_of_firstline_idx_ - whitespace_3_idx_) {
    *(stream_begin + whitespace_3_idx_) = kSpaceChar;
    non_whitespace_3_idx_ = whitespace_3_idx_ + 1;
    whitespace_4_idx_ = non_whitespace_3_idx_ + version.size();
    memcpy(stream_begin + non_whitespace_3_idx_,
           version.data(),
           version.size());
  } else {
    // The new version is to large to fit in the space available for the old
    // one, so we have to reformat the firstline.
    SetFirstlineFromStringPieces(request_method(), request_uri(), version);
  }
}

void BalsaHeaders::SetResponseReasonPhrase(const base::StringPiece& reason) {
  // Note: There is no difference between request_version() and
  // response_reason_phrase(). Thus, a function to set one is equivalent to a
  // function to set the other. We maintain two functions for this as it is
  // much more descriptive, and makes code more understandable.
  SetRequestVersion(reason);
}

}  // namespace net
