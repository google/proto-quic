// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/mock_http_cache.h"

#include <limits>
#include <utility>

#include "base/bind.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/completion_callback.h"
#include "net/base/net_errors.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// During testing, we are going to limit the size of a cache entry to this many
// bytes using DCHECKs in order to prevent a test from causing unbounded memory
// growth. In practice cache entry shouldn't come anywhere near this limit for
// tests that use the mock cache. If they do, that's likely a problem with the
// test. If a test requires using massive cache entries, they should use a real
// cache backend instead.
const int kMaxMockCacheEntrySize = 100 * 1000 * 1000;

// We can override the test mode for a given operation by setting this global
// variable.
int g_test_mode = 0;

int GetTestModeForEntry(const std::string& key) {
  // 'key' is prefixed with an identifier if it corresponds to a cached POST.
  // Skip past that to locate the actual URL.
  //
  // TODO(darin): It breaks the abstraction a bit that we assume 'key' is an
  // URL corresponding to a registered MockTransaction.  It would be good to
  // have another way to access the test_mode.
  GURL url;
  if (isdigit(key[0])) {
    size_t slash = key.find('/');
    DCHECK(slash != std::string::npos);
    url = GURL(key.substr(slash + 1));
  } else {
    url = GURL(key);
  }
  const MockTransaction* t = FindMockTransaction(url);
  DCHECK(t);
  return t->test_mode;
}

void CallbackForwader(const CompletionCallback& callback, int result) {
  callback.Run(result);
}

}  // namespace

//-----------------------------------------------------------------------------

struct MockDiskEntry::CallbackInfo {
  scoped_refptr<MockDiskEntry> entry;
  CompletionCallback callback;
  int result;
};

MockDiskEntry::MockDiskEntry(const std::string& key)
    : key_(key),
      doomed_(false),
      sparse_(false),
      fail_requests_(false),
      fail_sparse_requests_(false),
      busy_(false),
      delayed_(false),
      cancel_(false) {
  test_mode_ = GetTestModeForEntry(key);
}

void MockDiskEntry::Doom() {
  doomed_ = true;
}

void MockDiskEntry::Close() {
  Release();
}

std::string MockDiskEntry::GetKey() const {
  return key_;
}

base::Time MockDiskEntry::GetLastUsed() const {
  return base::Time::Now();
}

base::Time MockDiskEntry::GetLastModified() const {
  return base::Time::Now();
}

int32_t MockDiskEntry::GetDataSize(int index) const {
  DCHECK(index >= 0 && index < kNumCacheEntryDataIndices);
  return static_cast<int32_t>(data_[index].size());
}

int MockDiskEntry::ReadData(int index,
                            int offset,
                            IOBuffer* buf,
                            int buf_len,
                            const CompletionCallback& callback) {
  DCHECK(index >= 0 && index < kNumCacheEntryDataIndices);
  DCHECK(!callback.is_null());

  if (fail_requests_)
    return ERR_CACHE_READ_FAILURE;

  if (offset < 0 || offset > static_cast<int>(data_[index].size()))
    return ERR_FAILED;
  if (static_cast<size_t>(offset) == data_[index].size())
    return 0;

  int num = std::min(buf_len, static_cast<int>(data_[index].size()) - offset);
  memcpy(buf->data(), &data_[index][offset], num);

  if (MockHttpCache::GetTestMode(test_mode_) & TEST_MODE_SYNC_CACHE_READ)
    return num;

  CallbackLater(callback, num);
  return ERR_IO_PENDING;
}

int MockDiskEntry::WriteData(int index,
                             int offset,
                             IOBuffer* buf,
                             int buf_len,
                             const CompletionCallback& callback,
                             bool truncate) {
  DCHECK(index >= 0 && index < kNumCacheEntryDataIndices);
  DCHECK(!callback.is_null());
  DCHECK(truncate);

  if (fail_requests_) {
    CallbackLater(callback, ERR_CACHE_READ_FAILURE);
    return ERR_IO_PENDING;
  }

  if (offset < 0 || offset > static_cast<int>(data_[index].size()))
    return ERR_FAILED;

  DCHECK_LT(offset + buf_len, kMaxMockCacheEntrySize);
  data_[index].resize(offset + buf_len);
  if (buf_len)
    memcpy(&data_[index][offset], buf->data(), buf_len);

  if (MockHttpCache::GetTestMode(test_mode_) & TEST_MODE_SYNC_CACHE_WRITE)
    return buf_len;

  CallbackLater(callback, buf_len);
  return ERR_IO_PENDING;
}

int MockDiskEntry::ReadSparseData(int64_t offset,
                                  IOBuffer* buf,
                                  int buf_len,
                                  const CompletionCallback& callback) {
  DCHECK(!callback.is_null());
  if (fail_sparse_requests_)
    return ERR_NOT_IMPLEMENTED;
  if (!sparse_ || busy_ || cancel_)
    return ERR_CACHE_OPERATION_NOT_SUPPORTED;
  if (offset < 0)
    return ERR_FAILED;

  if (fail_requests_)
    return ERR_CACHE_READ_FAILURE;

  DCHECK(offset < std::numeric_limits<int32_t>::max());
  int real_offset = static_cast<int>(offset);
  if (!buf_len)
    return 0;

  int num = std::min(static_cast<int>(data_[1].size()) - real_offset,
                     buf_len);
  memcpy(buf->data(), &data_[1][real_offset], num);

  if (MockHttpCache::GetTestMode(test_mode_) & TEST_MODE_SYNC_CACHE_READ)
    return num;

  CallbackLater(callback, num);
  busy_ = true;
  delayed_ = false;
  return ERR_IO_PENDING;
}

int MockDiskEntry::WriteSparseData(int64_t offset,
                                   IOBuffer* buf,
                                   int buf_len,
                                   const CompletionCallback& callback) {
  DCHECK(!callback.is_null());
  if (fail_sparse_requests_)
    return ERR_NOT_IMPLEMENTED;
  if (busy_ || cancel_)
    return ERR_CACHE_OPERATION_NOT_SUPPORTED;
  if (!sparse_) {
    if (data_[1].size())
      return ERR_CACHE_OPERATION_NOT_SUPPORTED;
    sparse_ = true;
  }
  if (offset < 0)
    return ERR_FAILED;
  if (!buf_len)
    return 0;

  if (fail_requests_)
    return ERR_CACHE_READ_FAILURE;

  DCHECK(offset < std::numeric_limits<int32_t>::max());
  int real_offset = static_cast<int>(offset);

  if (static_cast<int>(data_[1].size()) < real_offset + buf_len) {
    DCHECK_LT(real_offset + buf_len, kMaxMockCacheEntrySize);
    data_[1].resize(real_offset + buf_len);
  }

  memcpy(&data_[1][real_offset], buf->data(), buf_len);
  if (MockHttpCache::GetTestMode(test_mode_) & TEST_MODE_SYNC_CACHE_WRITE)
    return buf_len;

  CallbackLater(callback, buf_len);
  return ERR_IO_PENDING;
}

int MockDiskEntry::GetAvailableRange(int64_t offset,
                                     int len,
                                     int64_t* start,
                                     const CompletionCallback& callback) {
  DCHECK(!callback.is_null());
  if (!sparse_ || busy_ || cancel_)
    return ERR_CACHE_OPERATION_NOT_SUPPORTED;
  if (offset < 0)
    return ERR_FAILED;

  if (fail_requests_)
    return ERR_CACHE_READ_FAILURE;

  *start = offset;
  DCHECK(offset < std::numeric_limits<int32_t>::max());
  int real_offset = static_cast<int>(offset);
  if (static_cast<int>(data_[1].size()) < real_offset)
    return 0;

  int num = std::min(static_cast<int>(data_[1].size()) - real_offset, len);
  int count = 0;
  for (; num > 0; num--, real_offset++) {
    if (!count) {
      if (data_[1][real_offset]) {
        count++;
        *start = real_offset;
      }
    } else {
      if (!data_[1][real_offset])
        break;
      count++;
    }
  }
  if (MockHttpCache::GetTestMode(test_mode_) & TEST_MODE_SYNC_CACHE_WRITE)
    return count;

  CallbackLater(callback, count);
  return ERR_IO_PENDING;
}

bool MockDiskEntry::CouldBeSparse() const {
  if (fail_sparse_requests_)
    return false;
  return sparse_;
}

void MockDiskEntry::CancelSparseIO() {
  cancel_ = true;
}

int MockDiskEntry::ReadyForSparseIO(const CompletionCallback& callback) {
  if (fail_sparse_requests_)
    return ERR_NOT_IMPLEMENTED;
  if (!cancel_)
    return OK;

  cancel_ = false;
  DCHECK(!callback.is_null());
  if (MockHttpCache::GetTestMode(test_mode_) & TEST_MODE_SYNC_CACHE_READ)
    return OK;

  // The pending operation is already in the message loop (and hopefully
  // already in the second pass).  Just notify the caller that it finished.
  CallbackLater(callback, 0);
  return ERR_IO_PENDING;
}

// If |value| is true, don't deliver any completion callbacks until called
// again with |value| set to false.  Caution: remember to enable callbacks
// again or all subsequent tests will fail.
// Static.
void MockDiskEntry::IgnoreCallbacks(bool value) {
  if (ignore_callbacks_ == value)
    return;
  ignore_callbacks_ = value;
  if (!value)
    StoreAndDeliverCallbacks(false, NULL, CompletionCallback(), 0);
}

MockDiskEntry::~MockDiskEntry() {
}

// Unlike the callbacks for MockHttpTransaction, we want this one to run even
// if the consumer called Close on the MockDiskEntry.  We achieve that by
// leveraging the fact that this class is reference counted.
void MockDiskEntry::CallbackLater(const CompletionCallback& callback,
                                  int result) {
  if (ignore_callbacks_)
    return StoreAndDeliverCallbacks(true, this, callback, result);
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&MockDiskEntry::RunCallback, this, callback, result));
}

void MockDiskEntry::RunCallback(const CompletionCallback& callback,
                                int result) {
  if (busy_) {
    // This is kind of hacky, but controlling the behavior of just this entry
    // from a test is sort of complicated.  What we really want to do is
    // delay the delivery of a sparse IO operation a little more so that the
    // request start operation (async) will finish without seeing the end of
    // this operation (already posted to the message loop)... and without
    // just delaying for n mS (which may cause trouble with slow bots).  So
    // we re-post this operation (all async sparse IO operations will take two
    // trips through the message loop instead of one).
    if (!delayed_) {
      delayed_ = true;
      return CallbackLater(callback, result);
    }
  }
  busy_ = false;
  callback.Run(result);
}

// When |store| is true, stores the callback to be delivered later; otherwise
// delivers any callback previously stored.
// Static.
void MockDiskEntry::StoreAndDeliverCallbacks(bool store,
                                             MockDiskEntry* entry,
                                             const CompletionCallback& callback,
                                             int result) {
  static std::vector<CallbackInfo> callback_list;
  if (store) {
    CallbackInfo c = {entry, callback, result};
    callback_list.push_back(c);
  } else {
    for (size_t i = 0; i < callback_list.size(); i++) {
      CallbackInfo& c = callback_list[i];
      c.entry->CallbackLater(c.callback, c.result);
    }
    callback_list.clear();
  }
}

// Statics.
bool MockDiskEntry::ignore_callbacks_ = false;

//-----------------------------------------------------------------------------

MockDiskCache::MockDiskCache()
    : open_count_(0), create_count_(0), fail_requests_(false),
      soft_failures_(false), double_create_check_(true),
      fail_sparse_requests_(false) {
}

MockDiskCache::~MockDiskCache() {
  ReleaseAll();
}

CacheType MockDiskCache::GetCacheType() const {
  return DISK_CACHE;
}

int32_t MockDiskCache::GetEntryCount() const {
  return static_cast<int32_t>(entries_.size());
}

int MockDiskCache::OpenEntry(const std::string& key,
                             disk_cache::Entry** entry,
                             const CompletionCallback& callback) {
  DCHECK(!callback.is_null());
  if (fail_requests_)
    return ERR_CACHE_OPEN_FAILURE;

  EntryMap::iterator it = entries_.find(key);
  if (it == entries_.end())
    return ERR_CACHE_OPEN_FAILURE;

  if (it->second->is_doomed()) {
    it->second->Release();
    entries_.erase(it);
    return ERR_CACHE_OPEN_FAILURE;
  }

  open_count_++;

  it->second->AddRef();
  *entry = it->second;

  if (soft_failures_)
    it->second->set_fail_requests();

  if (GetTestModeForEntry(key) & TEST_MODE_SYNC_CACHE_START)
    return OK;

  CallbackLater(callback, OK);
  return ERR_IO_PENDING;
}

int MockDiskCache::CreateEntry(const std::string& key,
                               disk_cache::Entry** entry,
                               const CompletionCallback& callback) {
  DCHECK(!callback.is_null());
  if (fail_requests_)
    return ERR_CACHE_CREATE_FAILURE;

  EntryMap::iterator it = entries_.find(key);
  if (it != entries_.end()) {
    if (!it->second->is_doomed()) {
      if (double_create_check_)
        NOTREACHED();
      else
        return ERR_CACHE_CREATE_FAILURE;
    }
    it->second->Release();
    entries_.erase(it);
  }

  create_count_++;

  MockDiskEntry* new_entry = new MockDiskEntry(key);

  new_entry->AddRef();
  entries_[key] = new_entry;

  new_entry->AddRef();
  *entry = new_entry;

  if (soft_failures_)
    new_entry->set_fail_requests();

  if (fail_sparse_requests_)
    new_entry->set_fail_sparse_requests();

  if (GetTestModeForEntry(key) & TEST_MODE_SYNC_CACHE_START)
    return OK;

  CallbackLater(callback, OK);
  return ERR_IO_PENDING;
}

int MockDiskCache::DoomEntry(const std::string& key,
                             const CompletionCallback& callback) {
  DCHECK(!callback.is_null());
  EntryMap::iterator it = entries_.find(key);
  if (it != entries_.end()) {
    it->second->Release();
    entries_.erase(it);
  }

  if (GetTestModeForEntry(key) & TEST_MODE_SYNC_CACHE_START)
    return OK;

  CallbackLater(callback, OK);
  return ERR_IO_PENDING;
}

int MockDiskCache::DoomAllEntries(const CompletionCallback& callback) {
  return ERR_NOT_IMPLEMENTED;
}

int MockDiskCache::DoomEntriesBetween(const base::Time initial_time,
                                      const base::Time end_time,
                                      const CompletionCallback& callback) {
  return ERR_NOT_IMPLEMENTED;
}

int MockDiskCache::DoomEntriesSince(const base::Time initial_time,
                                    const CompletionCallback& callback) {
  return ERR_NOT_IMPLEMENTED;
}

int MockDiskCache::CalculateSizeOfAllEntries(
    const CompletionCallback& callback) {
  return ERR_NOT_IMPLEMENTED;
}

class MockDiskCache::NotImplementedIterator : public Iterator {
 public:
  int OpenNextEntry(disk_cache::Entry** next_entry,
                    const CompletionCallback& callback) override {
    return ERR_NOT_IMPLEMENTED;
  }
};

std::unique_ptr<disk_cache::Backend::Iterator> MockDiskCache::CreateIterator() {
  return std::unique_ptr<Iterator>(new NotImplementedIterator());
}

void MockDiskCache::GetStats(base::StringPairs* stats) {
}

void MockDiskCache::OnExternalCacheHit(const std::string& key) {
}

void MockDiskCache::ReleaseAll() {
  EntryMap::iterator it = entries_.begin();
  for (; it != entries_.end(); ++it)
    it->second->Release();
  entries_.clear();
}

void MockDiskCache::CallbackLater(const CompletionCallback& callback,
                                  int result) {
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&CallbackForwader, callback, result));
}

//-----------------------------------------------------------------------------

int MockBackendFactory::CreateBackend(
    NetLog* net_log,
    std::unique_ptr<disk_cache::Backend>* backend,
    const CompletionCallback& callback) {
  backend->reset(new MockDiskCache());
  return OK;
}

//-----------------------------------------------------------------------------

MockHttpCache::MockHttpCache()
    : MockHttpCache(base::MakeUnique<MockBackendFactory>()) {}

MockHttpCache::MockHttpCache(
    std::unique_ptr<HttpCache::BackendFactory> disk_cache_factory)
    : http_cache_(base::MakeUnique<MockNetworkLayer>(),
                  std::move(disk_cache_factory),
                  true) {}

disk_cache::Backend* MockHttpCache::backend() {
  TestCompletionCallback cb;
  disk_cache::Backend* backend;
  int rv = http_cache_.GetBackend(&backend, cb.callback());
  rv = cb.GetResult(rv);
  return (rv == OK) ? backend : NULL;
}

MockDiskCache* MockHttpCache::disk_cache() {
  return static_cast<MockDiskCache*>(backend());
}

int MockHttpCache::CreateTransaction(std::unique_ptr<HttpTransaction>* trans) {
  return http_cache_.CreateTransaction(DEFAULT_PRIORITY, trans);
}

void MockHttpCache::BypassCacheLock() {
  http_cache_.BypassLockForTest();
}

void MockHttpCache::FailConditionalizations() {
  http_cache_.FailConditionalizationForTest();
}

bool MockHttpCache::ReadResponseInfo(disk_cache::Entry* disk_entry,
                                     HttpResponseInfo* response_info,
                                     bool* response_truncated) {
  int size = disk_entry->GetDataSize(0);

  TestCompletionCallback cb;
  scoped_refptr<IOBuffer> buffer(new IOBuffer(size));
  int rv = disk_entry->ReadData(0, 0, buffer.get(), size, cb.callback());
  rv = cb.GetResult(rv);
  EXPECT_EQ(size, rv);

  return HttpCache::ParseResponseInfo(buffer->data(), size, response_info,
                                      response_truncated);
}

bool MockHttpCache::WriteResponseInfo(disk_cache::Entry* disk_entry,
                                      const HttpResponseInfo* response_info,
                                      bool skip_transient_headers,
                                      bool response_truncated) {
  base::Pickle pickle;
  response_info->Persist(
      &pickle, skip_transient_headers, response_truncated);

  TestCompletionCallback cb;
  scoped_refptr<WrappedIOBuffer> data(
      new WrappedIOBuffer(reinterpret_cast<const char*>(pickle.data())));
  int len = static_cast<int>(pickle.size());

  int rv = disk_entry->WriteData(0, 0, data.get(), len, cb.callback(), true);
  rv = cb.GetResult(rv);
  return (rv == len);
}

bool MockHttpCache::OpenBackendEntry(const std::string& key,
                                     disk_cache::Entry** entry) {
  TestCompletionCallback cb;
  int rv = backend()->OpenEntry(key, entry, cb.callback());
  return (cb.GetResult(rv) == OK);
}

bool MockHttpCache::CreateBackendEntry(const std::string& key,
                                       disk_cache::Entry** entry,
                                       NetLog* net_log) {
  TestCompletionCallback cb;
  int rv = backend()->CreateEntry(key, entry, cb.callback());
  return (cb.GetResult(rv) == OK);
}

// Static.
int MockHttpCache::GetTestMode(int test_mode) {
  if (!g_test_mode)
    return test_mode;

  return g_test_mode;
}

// Static.
void MockHttpCache::SetTestMode(int test_mode) {
  g_test_mode = test_mode;
}

//-----------------------------------------------------------------------------

int MockDiskCacheNoCB::CreateEntry(const std::string& key,
                                   disk_cache::Entry** entry,
                                   const CompletionCallback& callback) {
  return ERR_IO_PENDING;
}

//-----------------------------------------------------------------------------

int MockBackendNoCbFactory::CreateBackend(
    NetLog* net_log,
    std::unique_ptr<disk_cache::Backend>* backend,
    const CompletionCallback& callback) {
  backend->reset(new MockDiskCacheNoCB());
  return OK;
}

//-----------------------------------------------------------------------------

MockBlockingBackendFactory::MockBlockingBackendFactory()
    : backend_(NULL),
      block_(true),
      fail_(false) {
}

MockBlockingBackendFactory::~MockBlockingBackendFactory() {
}

int MockBlockingBackendFactory::CreateBackend(
    NetLog* net_log,
    std::unique_ptr<disk_cache::Backend>* backend,
    const CompletionCallback& callback) {
  if (!block_) {
    if (!fail_)
      backend->reset(new MockDiskCache());
    return Result();
  }

  backend_ =  backend;
  callback_ = callback;
  return ERR_IO_PENDING;
}

void MockBlockingBackendFactory::FinishCreation() {
  block_ = false;
  if (!callback_.is_null()) {
    if (!fail_)
      backend_->reset(new MockDiskCache());
    CompletionCallback cb = callback_;
    callback_.Reset();
    cb.Run(Result());  // This object can be deleted here.
  }
}

}  // namespace net
