// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file declares a HttpTransactionFactory implementation that can be
// layered on top of another HttpTransactionFactory to add HTTP caching.  The
// caching logic follows RFC 7234 (any exceptions are called out in the code).
//
// The HttpCache takes a disk_cache::Backend as a parameter, and uses that for
// the cache storage.
//
// See HttpTransactionFactory and HttpTransaction for more details.

#ifndef NET_HTTP_HTTP_CACHE_H_
#define NET_HTTP_HTTP_CACHE_H_

#include <list>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>

#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/threading/thread_checker.h"
#include "base/time/clock.h"
#include "base/time/time.h"
#include "net/base/cache_type.h"
#include "net/base/completion_callback.h"
#include "net/base/load_states.h"
#include "net/base/net_export.h"
#include "net/base/request_priority.h"
#include "net/http/http_network_session.h"
#include "net/http/http_transaction_factory.h"

class GURL;

namespace base {
namespace trace_event {
class ProcessMemoryDump;
}
}  // namespace base

namespace disk_cache {
class Backend;
class Entry;
}  // namespace disk_cache

namespace net {

class HttpNetworkSession;
class HttpResponseInfo;
class IOBuffer;
class NetLog;
class ViewCacheHelper;
struct HttpRequestInfo;

class NET_EXPORT HttpCache : public HttpTransactionFactory {
 public:
  // The cache mode of operation.
  enum Mode {
    // Normal mode just behaves like a standard web cache.
    NORMAL = 0,
    // Disables reads and writes from the cache.
    // Equivalent to setting LOAD_DISABLE_CACHE on every request.
    DISABLE
  };

  // A BackendFactory creates a backend object to be used by the HttpCache.
  class NET_EXPORT BackendFactory {
   public:
    virtual ~BackendFactory() {}

    // The actual method to build the backend. Returns a net error code. If
    // ERR_IO_PENDING is returned, the |callback| will be notified when the
    // operation completes, and |backend| must remain valid until the
    // notification arrives.
    // The implementation must not access the factory object after invoking the
    // |callback| because the object can be deleted from within the callback.
    virtual int CreateBackend(NetLog* net_log,
                              std::unique_ptr<disk_cache::Backend>* backend,
                              const CompletionCallback& callback) = 0;
  };

  // A default backend factory for the common use cases.
  class NET_EXPORT DefaultBackend : public BackendFactory {
   public:
    // |path| is the destination for any files used by the backend. If
    // |max_bytes| is  zero, a default value will be calculated automatically.
    DefaultBackend(CacheType type,
                   BackendType backend_type,
                   const base::FilePath& path,
                   int max_bytes);
    ~DefaultBackend() override;

    // Returns a factory for an in-memory cache.
    static std::unique_ptr<BackendFactory> InMemory(int max_bytes);

    // BackendFactory implementation.
    int CreateBackend(NetLog* net_log,
                      std::unique_ptr<disk_cache::Backend>* backend,
                      const CompletionCallback& callback) override;

   private:
    CacheType type_;
    BackendType backend_type_;
    const base::FilePath path_;
    int max_bytes_;
  };

  // The number of minutes after a resource is prefetched that it can be used
  // again without validation.
  static const int kPrefetchReuseMins = 5;

  // The disk cache is initialized lazily (by CreateTransaction) in this case.
  // Provide an existing HttpNetworkSession, the cache can construct a
  // network layer with a shared HttpNetworkSession in order for multiple
  // network layers to share information (e.g. authentication data). The
  // HttpCache takes ownership of the |backend_factory|.
  //
  // The HttpCache must be destroyed before the HttpNetworkSession.
  //
  // If |is_main_cache| is true, configures the cache to track
  // information about servers supporting QUIC.
  // TODO(zhongyi): remove |is_main_cache| when we get rid of cache split.
  HttpCache(HttpNetworkSession* session,
            std::unique_ptr<BackendFactory> backend_factory,
            bool is_main_cache);

  // Initialize the cache from its component parts. |network_layer| and
  // |backend_factory| will be destroyed when the HttpCache is.
  HttpCache(std::unique_ptr<HttpTransactionFactory> network_layer,
            std::unique_ptr<BackendFactory> backend_factory,
            bool is_main_cache);

  ~HttpCache() override;

  HttpTransactionFactory* network_layer() { return network_layer_.get(); }

  // Retrieves the cache backend for this HttpCache instance. If the backend
  // is not initialized yet, this method will initialize it. The return value is
  // a network error code, and it could be ERR_IO_PENDING, in which case the
  // |callback| will be notified when the operation completes. The pointer that
  // receives the |backend| must remain valid until the operation completes.
  int GetBackend(disk_cache::Backend** backend,
                 const CompletionCallback& callback);

  // Returns the current backend (can be NULL).
  disk_cache::Backend* GetCurrentBackend() const;

  // Given a header data blob, convert it to a response info object.
  static bool ParseResponseInfo(const char* data, int len,
                                HttpResponseInfo* response_info,
                                bool* response_truncated);

  // Writes |buf_len| bytes of metadata stored in |buf| to the cache entry
  // referenced by |url|, as long as the entry's |expected_response_time| has
  // not changed. This method returns without blocking, and the operation will
  // be performed asynchronously without any completion notification.
  // Takes ownership of |buf|.
  void WriteMetadata(const GURL& url,
                     RequestPriority priority,
                     base::Time expected_response_time,
                     IOBuffer* buf,
                     int buf_len);

  // Get/Set the cache's mode.
  void set_mode(Mode value) { mode_ = value; }
  Mode mode() { return mode_; }

  // Get/Set the cache's clock. These are public only for testing.
  void SetClockForTesting(std::unique_ptr<base::Clock> clock) {
    clock_ = std::move(clock);
  }
  base::Clock* clock() const { return clock_.get(); }

  // Close currently active sockets so that fresh page loads will not use any
  // recycled connections.  For sockets currently in use, they may not close
  // immediately, but they will not be reusable. This is for debugging.
  void CloseAllConnections();

  // Close all idle connections. Will close all sockets not in active use.
  void CloseIdleConnections();

  // Called whenever an external cache in the system reuses the resource
  // referred to by |url| and |http_method|.
  void OnExternalCacheHit(const GURL& url, const std::string& http_method);

  // Causes all transactions created after this point to simulate lock timeout
  // and effectively bypass the cache lock whenever there is lock contention.
  void SimulateCacheLockTimeoutForTesting() { bypass_lock_for_test_ = true; }

  // Causes all transactions created after this point to simulate lock timeout
  // and effectively bypass the cache lock whenever there is lock contention
  // after the transaction has completed its headers phase.
  void SimulateCacheLockTimeoutAfterHeadersForTesting() {
    bypass_lock_after_headers_for_test_ = true;
  }

  // Causes all transactions created after this point to generate a failure
  // when attempting to conditionalize a network request.
  void FailConditionalizationForTest() {
    fail_conditionalization_for_test_ = true;
  }

  // HttpTransactionFactory implementation:
  int CreateTransaction(RequestPriority priority,
                        std::unique_ptr<HttpTransaction>* trans) override;
  HttpCache* GetCache() override;
  HttpNetworkSession* GetSession() override;

  base::WeakPtr<HttpCache> GetWeakPtr() { return weak_factory_.GetWeakPtr(); }

  // Resets the network layer to allow for tests that probe
  // network changes (e.g. host unreachable).  The old network layer is
  // returned to allow for filter patterns that only intercept
  // some creation requests.  Note ownership exchange.
  std::unique_ptr<HttpTransactionFactory>
  SetHttpNetworkTransactionFactoryForTesting(
      std::unique_ptr<HttpTransactionFactory> new_network_layer);

  // Dumps memory allocation stats. |parent_dump_absolute_name| is the name
  // used by the parent MemoryAllocatorDump in the memory dump hierarchy.
  void DumpMemoryStats(base::trace_event::ProcessMemoryDump* pmd,
                       const std::string& parent_absolute_name) const;

 private:
  // Types --------------------------------------------------------------------

  // Disk cache entry data indices.
  enum {
    kResponseInfoIndex = 0,
    kResponseContentIndex,
    kMetadataIndex,

    // Must remain at the end of the enum.
    kNumCacheEntryDataIndices
  };

  class MetadataWriter;
  class QuicServerInfoFactoryAdaptor;
  class Transaction;
  class WorkItem;
  class Writers;
  friend class WritersTest;  // To access ActiveEntry in the test class.
  friend class MockHttpCacheTransaction;
  friend class Transaction;
  friend class ViewCacheHelper;
  struct PendingOp;  // Info for an entry under construction.

  // To help with testing.
  friend class MockHttpCache;

  using TransactionList = std::list<Transaction*>;
  using TransactionSet = std::unordered_set<Transaction*>;
  typedef std::list<std::unique_ptr<WorkItem>> WorkItemList;

  // We implement a basic reader/writer lock for the disk cache entry. If there
  // is a writer, then all transactions must wait to read the body. But the
  // waiting transactions can start their headers phase in parallel. Headers
  // phase is allowed for one transaction at a time so that if it doesn't match
  // the existing headers, remaining transactions do not also try to match the
  // existing entry in parallel leading to wasted network requests. If the
  // headers do not match, this entry will be doomed.
  //
  // A transaction goes through these state transitions.
  //
  // Write mode transactions:
  // add_to_entry_queue-> headers_transaction -> writer
  // add_to_entry_queue-> headers_transaction -> done_headers_queue -> readers
  // (once the data is written to the cache by another writer)
  //
  // Read only transactions:
  // add_to_entry_queue-> headers_transaction -> done_headers_queue -> readers
  // (once the data is written to the cache by the writer)

  struct ActiveEntry {
    explicit ActiveEntry(disk_cache::Entry* entry);
    ~ActiveEntry();
    size_t EstimateMemoryUsage() const;

    // Returns true if no transactions are associated with this entry.
    bool HasNoTransactions();

    disk_cache::Entry* disk_entry = nullptr;

    // Transactions waiting to be added to entry.
    TransactionList add_to_entry_queue;

    // Transaction currently in the headers phase, either validating the
    // response or getting new headers. This can exist simultaneously with
    // writer or readers while validating existing headers.
    Transaction* headers_transaction = nullptr;

    // Transactions that have completed their headers phase and are waiting
    // to read the response body or write the response body.
    TransactionList done_headers_queue;

    // Transaction currently reading from the network and writing to the cache.
    Transaction* writer = nullptr;

    // Transactions that can only read from the cache. Only one of writer or
    // readers can exist at a time.
    TransactionSet readers;

    // The following variables are true if OnProcessQueuedTransactions is posted
    bool will_process_queued_transactions = false;

    // True if entry is doomed.
    bool doomed = false;
  };

  using ActiveEntriesMap =
      std::unordered_map<std::string, std::unique_ptr<ActiveEntry>>;
  using PendingOpsMap = std::unordered_map<std::string, PendingOp*>;
  using ActiveEntriesSet = std::map<ActiveEntry*, std::unique_ptr<ActiveEntry>>;
  using PlaybackCacheMap = std::unordered_map<std::string, int>;

  // Methods ------------------------------------------------------------------

  // Creates the |backend| object and notifies the |callback| when the operation
  // completes. Returns an error code.
  int CreateBackend(disk_cache::Backend** backend,
                    const CompletionCallback& callback);

  // Makes sure that the backend creation is complete before allowing the
  // provided transaction to use the object. Returns an error code.  |trans|
  // will be notified via its IO callback if this method returns ERR_IO_PENDING.
  // The transaction is free to use the backend directly at any time after
  // receiving the notification.
  int GetBackendForTransaction(Transaction* trans);

  // Generates the cache key for this request.
  std::string GenerateCacheKey(const HttpRequestInfo*);

  // Dooms the entry selected by |key|, if it is currently in the list of active
  // entries.
  void DoomActiveEntry(const std::string& key);

  // Dooms the entry selected by |key|. |trans| will be notified via its IO
  // callback if this method returns ERR_IO_PENDING. The entry can be
  // currently in use or not. If entry is in use and the invoking transaction
  // is associated with this entry and this entry is already doomed, this API
  // should not be invoked.
  int DoomEntry(const std::string& key, Transaction* trans);

  // Dooms the entry selected by |key|. |trans| will be notified via its IO
  // callback if this method returns ERR_IO_PENDING. The entry should not
  // be currently in use.
  int AsyncDoomEntry(const std::string& key, Transaction* trans);

  // Dooms the entry associated with a GET for a given |url|.
  void DoomMainEntryForUrl(const GURL& url);

  // Closes a previously doomed entry.
  void FinalizeDoomedEntry(ActiveEntry* entry);

  // Returns an entry that is currently in use and not doomed, or NULL.
  ActiveEntry* FindActiveEntry(const std::string& key);

  // Creates a new ActiveEntry and starts tracking it. |disk_entry| is the disk
  // cache entry.
  ActiveEntry* ActivateEntry(disk_cache::Entry* disk_entry);

  // Deletes an ActiveEntry.
  void DeactivateEntry(ActiveEntry* entry);

  // Deletes an ActiveEntry using an exhaustive search.
  void SlowDeactivateEntry(ActiveEntry* entry);

  // Returns the PendingOp for the desired |key|. If an entry is not under
  // construction already, a new PendingOp structure is created.
  PendingOp* GetPendingOp(const std::string& key);

  // Deletes a PendingOp.
  void DeletePendingOp(PendingOp* pending_op);

  // Opens the disk cache entry associated with |key|, returning an ActiveEntry
  // in |*entry|. |trans| will be notified via its IO callback if this method
  // returns ERR_IO_PENDING.
  int OpenEntry(const std::string& key, ActiveEntry** entry,
                Transaction* trans);

  // Creates the disk cache entry associated with |key|, returning an
  // ActiveEntry in |*entry|. |trans| will be notified via its IO callback if
  // this method returns ERR_IO_PENDING.
  int CreateEntry(const std::string& key, ActiveEntry** entry,
                  Transaction* trans);

  // Destroys an ActiveEntry (active or doomed).
  void DestroyEntry(ActiveEntry* entry);

  // Adds a transaction to an ActiveEntry. This method returns ERR_IO_PENDING
  // and the transaction will be notified about completion via its IO callback.
  // In a failure case, the callback will be invoked with ERR_CACHE_RACE.
  int AddTransactionToEntry(ActiveEntry* entry, Transaction* transaction);

  // Transaction invokes this when its response headers phase is complete
  // If the transaction is responsible for writing the response body,
  // it becomes the writer and returns OK. In other cases ERR_IO_PENDING is
  // returned and the transaction will be notified about completion via its
  // IO callback. In a failure case, the callback will be invoked with
  // ERR_CACHE_RACE.
  int DoneWithResponseHeaders(ActiveEntry* entry,
                              Transaction* transaction,
                              bool is_partial);

  // Called when the transaction has finished working with this entry.
  // |process_cancel| is true if the transaction could have been writing the
  // response body and was cancelled by the caller instead of running
  // to completion. This will be confirmed and if true, its impact on queued
  // transactions will be processed.
  void DoneWithEntry(ActiveEntry* entry,
                     Transaction* transaction,
                     bool process_cancel,
                     bool is_partial);

  // Called when the transaction has finished writing to this entry. |success|
  // is false if the cache entry should be deleted.
  void DoneWritingToEntry(ActiveEntry* entry,
                          bool success,
                          Transaction* transaction);

  // Called when the transaction has finished reading from this entry.
  void DoneReadingFromEntry(ActiveEntry* entry, Transaction* transaction);

  // Called when the transaction has received a non-matching response to
  // validation and it's not the transaction responsible for writing the
  // response body.
  void DoomEntryValidationNoMatch(ActiveEntry* entry);

  // Removes and returns all queued transactions in |entry| in FIFO order. This
  // includes transactions that have completed the headers phase and those that
  // have not been added to the entry yet in that order. |list| is the output
  // argument.
  void RemoveAllQueuedTransactions(ActiveEntry* entry, TransactionList* list);

  // Processes either writer's failure to write response body or
  // headers_transactions's failure to write headers.
  void ProcessEntryFailure(ActiveEntry* entry, Transaction* transaction);

  // Restarts headers_transaction and done_headers_queue transactions.
  void RestartHeadersPhaseTransactions(ActiveEntry* entry,
                                       Transaction* transaction);

  // Restarts the headers_transaction by setting its state. Since the
  // headers_transaction is awaiting an asynchronous operation completion,
  // it will be restarted when it's IO callback is invoked.
  void RestartHeadersTransaction(ActiveEntry* entry);

  // Resumes processing the queued transactions of |entry|.
  void ProcessQueuedTransactions(ActiveEntry* entry);

  // Checks if a transaction can be added to the entry. If yes, it will
  // invoke the IO callback of the transaction. This is a helper function for
  // OnProcessQueuedTransactions. It will take a transaction from
  // add_to_entry_queue and make it a headers_transaction, if one doesn't exist
  // already.
  void ProcessAddToEntryQueue(ActiveEntry* entry);

  // Invoked when a transaction that has already completed the response headers
  // phase can resume reading/writing the response body. It will invoke the IO
  // callback of the transaction. This is a helper function for
  // OnProcessQueuedTransactions.
  void ProcessDoneHeadersQueue(ActiveEntry* entry);

  // Returns true if this transaction can write headers to the entry.
  bool CanTransactionWriteResponseHeaders(ActiveEntry* entry,
                                          Transaction* transaction,
                                          bool is_partial,
                                          bool is_match) const;

  // Returns true if any transactions in the ActiveEntry depend on this
  // transaction to complete writing to the cache.
  bool HasDependentTransactions(ActiveEntry* entry,
                                Transaction* transaction) const;

  // Check the sanity of response code for a writer transaction.
  bool IsValidResponseForWriter(Transaction* transaction,
                                bool is_partial) const;

  // Returns true if a transaction is currently writing the response body.
  bool IsWritingInProgress(ActiveEntry* entry) const;

  // Returns the LoadState of the provided pending transaction.
  LoadState GetLoadStateForPendingTransaction(const Transaction* trans);

  // Removes the transaction |trans|, from the pending list of an entry
  // (PendingOp, active or doomed entry).
  void RemovePendingTransaction(Transaction* trans);

  // Removes the transaction |trans|, from the pending list of |entry|.
  bool RemovePendingTransactionFromEntry(ActiveEntry* entry,
                                         Transaction* trans);

  // Removes the transaction |trans|, from the pending list of |pending_op|.
  bool RemovePendingTransactionFromPendingOp(PendingOp* pending_op,
                                             Transaction* trans);

  // Events (called via PostTask) ---------------------------------------------

  void OnProcessQueuedTransactions(ActiveEntry* entry);

  // Callbacks ----------------------------------------------------------------

  // Processes BackendCallback notifications.
  void OnIOComplete(int result, PendingOp* entry);

  // Helper to conditionally delete |pending_op| if the HttpCache object it
  // is meant for has been deleted.
  //
  // TODO(ajwong): The PendingOp lifetime management is very tricky.  It might
  // be possible to simplify it using either base::Owned() or base::Passed()
  // with the callback.
  static void OnPendingOpComplete(const base::WeakPtr<HttpCache>& cache,
                                  PendingOp* pending_op,
                                  int result);

  // Processes the backend creation notification.
  void OnBackendCreated(int result, PendingOp* pending_op);

  // Variables ----------------------------------------------------------------

  NetLog* net_log_;

  // Used when lazily constructing the disk_cache_.
  std::unique_ptr<BackendFactory> backend_factory_;
  bool building_backend_;
  bool bypass_lock_for_test_;
  bool bypass_lock_after_headers_for_test_;
  bool fail_conditionalization_for_test_;

  Mode mode_;

  std::unique_ptr<HttpTransactionFactory> network_layer_;

  std::unique_ptr<disk_cache::Backend> disk_cache_;

  // The set of active entries indexed by cache key.
  ActiveEntriesMap active_entries_;

  // The set of doomed entries.
  ActiveEntriesSet doomed_entries_;

  // The set of entries "under construction".
  PendingOpsMap pending_ops_;

  std::unique_ptr<PlaybackCacheMap> playback_cache_map_;

  // A clock that can be swapped out for testing.
  std::unique_ptr<base::Clock> clock_;

  THREAD_CHECKER(thread_checker_);

  base::WeakPtrFactory<HttpCache> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(HttpCache);
};

}  // namespace net

#endif  // NET_HTTP_HTTP_CACHE_H_
