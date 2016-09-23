// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is a mock of the http cache and related testing classes. To be fair, it
// is not really a mock http cache given that it uses the real implementation of
// the http cache, but it has fake implementations of all required components,
// so it is useful for unit tests at the http layer.

#ifndef NET_HTTP_MOCK_HTTP_CACHE_H_
#define NET_HTTP_MOCK_HTTP_CACHE_H_

#include <stdint.h>

#include <unordered_map>

#include "base/strings/string_split.h"
#include "net/disk_cache/disk_cache.h"
#include "net/http/http_cache.h"
#include "net/http/http_transaction_test_util.h"

namespace net {

//-----------------------------------------------------------------------------
// Mock disk cache (a very basic memory cache implementation).

class MockDiskEntry : public disk_cache::Entry,
                      public base::RefCounted<MockDiskEntry> {
 public:
  explicit MockDiskEntry(const std::string& key);

  bool is_doomed() const { return doomed_; }

  void Doom() override;
  void Close() override;
  std::string GetKey() const override;
  base::Time GetLastUsed() const override;
  base::Time GetLastModified() const override;
  int32_t GetDataSize(int index) const override;
  int ReadData(int index,
               int offset,
               IOBuffer* buf,
               int buf_len,
               const CompletionCallback& callback) override;
  int WriteData(int index,
                int offset,
                IOBuffer* buf,
                int buf_len,
                const CompletionCallback& callback,
                bool truncate) override;
  int ReadSparseData(int64_t offset,
                     IOBuffer* buf,
                     int buf_len,
                     const CompletionCallback& callback) override;
  int WriteSparseData(int64_t offset,
                      IOBuffer* buf,
                      int buf_len,
                      const CompletionCallback& callback) override;
  int GetAvailableRange(int64_t offset,
                        int len,
                        int64_t* start,
                        const CompletionCallback& callback) override;
  bool CouldBeSparse() const override;
  void CancelSparseIO() override;
  int ReadyForSparseIO(const CompletionCallback& completion_callback) override;

  // Fail most subsequent requests.
  void set_fail_requests() { fail_requests_ = true; }

  void set_fail_sparse_requests() { fail_sparse_requests_ = true; }

  // If |value| is true, don't deliver any completion callbacks until called
  // again with |value| set to false.  Caution: remember to enable callbacks
  // again or all subsequent tests will fail.
  static void IgnoreCallbacks(bool value);

 private:
  friend class base::RefCounted<MockDiskEntry>;
  struct CallbackInfo;

  ~MockDiskEntry() override;

  // Unlike the callbacks for MockHttpTransaction, we want this one to run even
  // if the consumer called Close on the MockDiskEntry.  We achieve that by
  // leveraging the fact that this class is reference counted.
  void CallbackLater(const CompletionCallback& callback, int result);

  void RunCallback(const CompletionCallback& callback, int result);

  // When |store| is true, stores the callback to be delivered later; otherwise
  // delivers any callback previously stored.
  static void StoreAndDeliverCallbacks(bool store,
                                       MockDiskEntry* entry,
                                       const CompletionCallback& callback,
                                       int result);

  static const int kNumCacheEntryDataIndices = 3;

  std::string key_;
  std::vector<char> data_[kNumCacheEntryDataIndices];
  int test_mode_;
  bool doomed_;
  bool sparse_;
  bool fail_requests_;
  bool fail_sparse_requests_;
  bool busy_;
  bool delayed_;
  bool cancel_;
  static bool ignore_callbacks_;
};

class MockDiskCache : public disk_cache::Backend {
 public:
  MockDiskCache();
  ~MockDiskCache() override;

  CacheType GetCacheType() const override;
  int32_t GetEntryCount() const override;
  int OpenEntry(const std::string& key,
                disk_cache::Entry** entry,
                const CompletionCallback& callback) override;
  int CreateEntry(const std::string& key,
                  disk_cache::Entry** entry,
                  const CompletionCallback& callback) override;
  int DoomEntry(const std::string& key,
                const CompletionCallback& callback) override;
  int DoomAllEntries(const CompletionCallback& callback) override;
  int DoomEntriesBetween(base::Time initial_time,
                         base::Time end_time,
                         const CompletionCallback& callback) override;
  int DoomEntriesSince(base::Time initial_time,
                       const CompletionCallback& callback) override;
  int CalculateSizeOfAllEntries(const CompletionCallback& callback) override;
  std::unique_ptr<Iterator> CreateIterator() override;
  void GetStats(base::StringPairs* stats) override;
  void OnExternalCacheHit(const std::string& key) override;

  // Returns number of times a cache entry was successfully opened.
  int open_count() const { return open_count_; }

  // Returns number of times a cache entry was successfully created.
  int create_count() const { return create_count_; }

  // Fail any subsequent CreateEntry and OpenEntry.
  void set_fail_requests() { fail_requests_ = true; }

  // Return entries that fail some of their requests.
  void set_soft_failures(bool value) { soft_failures_ = value; }

  // Makes sure that CreateEntry is not called twice for a given key.
  void set_double_create_check(bool value) { double_create_check_ = value; }

  // Makes all requests for data ranges to fail as not implemented.
  void set_fail_sparse_requests() { fail_sparse_requests_ = true; }

  void ReleaseAll();

 private:
  using EntryMap = std::unordered_map<std::string, MockDiskEntry*>;
  class NotImplementedIterator;

  void CallbackLater(const CompletionCallback& callback, int result);

  EntryMap entries_;
  int open_count_;
  int create_count_;
  bool fail_requests_;
  bool soft_failures_;
  bool double_create_check_;
  bool fail_sparse_requests_;
};

class MockBackendFactory : public HttpCache::BackendFactory {
 public:
  int CreateBackend(NetLog* net_log,
                    std::unique_ptr<disk_cache::Backend>* backend,
                    const CompletionCallback& callback) override;
};

class MockHttpCache {
 public:
  MockHttpCache();
  explicit MockHttpCache(
      std::unique_ptr<HttpCache::BackendFactory> disk_cache_factory);

  HttpCache* http_cache() { return &http_cache_; }

  MockNetworkLayer* network_layer() {
    return static_cast<MockNetworkLayer*>(http_cache_.network_layer());
  }
  disk_cache::Backend* backend();
  MockDiskCache* disk_cache();

  // Wrapper around http_cache()->CreateTransaction(DEFAULT_PRIORITY...)
  int CreateTransaction(std::unique_ptr<HttpTransaction>* trans);

  // Wrapper to bypass the cache lock for new transactions.
  void BypassCacheLock();

  // Wrapper to fail request conditionalization for new transactions.
  void FailConditionalizations();

  // Helper function for reading response info from the disk cache.
  static bool ReadResponseInfo(disk_cache::Entry* disk_entry,
                               HttpResponseInfo* response_info,
                               bool* response_truncated);

  // Helper function for writing response info into the disk cache.
  static bool WriteResponseInfo(disk_cache::Entry* disk_entry,
                                const HttpResponseInfo* response_info,
                                bool skip_transient_headers,
                                bool response_truncated);

  // Helper function to synchronously open a backend entry.
  bool OpenBackendEntry(const std::string& key, disk_cache::Entry** entry);

  // Helper function to synchronously create a backend entry.
  bool CreateBackendEntry(const std::string& key,
                          disk_cache::Entry** entry,
                          NetLog* net_log);

  // Returns the test mode after considering the global override.
  static int GetTestMode(int test_mode);

  // Overrides the test mode for a given operation. Remember to reset it after
  // the test! (by setting test_mode to zero).
  static void SetTestMode(int test_mode);

 private:
  HttpCache http_cache_;
};

// This version of the disk cache doesn't invoke CreateEntry callbacks.
class MockDiskCacheNoCB : public MockDiskCache {
  int CreateEntry(const std::string& key,
                  disk_cache::Entry** entry,
                  const CompletionCallback& callback) override;
};

class MockBackendNoCbFactory : public HttpCache::BackendFactory {
 public:
  int CreateBackend(NetLog* net_log,
                    std::unique_ptr<disk_cache::Backend>* backend,
                    const CompletionCallback& callback) override;
};

// This backend factory allows us to control the backend instantiation.
class MockBlockingBackendFactory : public HttpCache::BackendFactory {
 public:
  MockBlockingBackendFactory();
  ~MockBlockingBackendFactory() override;

  int CreateBackend(NetLog* net_log,
                    std::unique_ptr<disk_cache::Backend>* backend,
                    const CompletionCallback& callback) override;

  // Completes the backend creation. Any blocked call will be notified via the
  // provided callback.
  void FinishCreation();

  std::unique_ptr<disk_cache::Backend>* backend() { return backend_; }
  void set_fail(bool fail) { fail_ = fail; }

  const CompletionCallback& callback() { return callback_; }

 private:
  int Result() { return fail_ ? ERR_FAILED : OK; }

  std::unique_ptr<disk_cache::Backend>* backend_;
  CompletionCallback callback_;
  bool block_;
  bool fail_;
};

}  // namespace net

#endif  // NET_HTTP_MOCK_HTTP_CACHE_H_
