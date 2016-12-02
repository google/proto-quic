// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_CHANNEL_ID_SERVICE_H_
#define NET_SSL_CHANNEL_ID_SERVICE_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/threading/non_thread_safe.h"
#include "base/time/time.h"
#include "net/base/completion_callback.h"
#include "net/base/net_export.h"
#include "net/ssl/channel_id_store.h"

namespace base {
class TaskRunner;
}  // namespace base

namespace crypto {
class ECPrivateKey;
}  // namespace crypto

namespace net {

class ChannelIDServiceJob;

// A class for creating and fetching Channel IDs.

// Inherits from NonThreadSafe in order to use the function
// |CalledOnValidThread|.
class NET_EXPORT ChannelIDService
    : NON_EXPORTED_BASE(public base::NonThreadSafe) {
 public:
  class NET_EXPORT Request {
   public:
    Request();
    ~Request();

    // Cancel the request.  Does nothing if the request finished or was already
    // cancelled.
    void Cancel();

    bool is_active() const { return !callback_.is_null(); }

   private:
    friend class ChannelIDService;
    friend class ChannelIDServiceJob;

    void RequestStarted(ChannelIDService* service,
                        base::TimeTicks request_start,
                        const CompletionCallback& callback,
                        std::unique_ptr<crypto::ECPrivateKey>* key,
                        ChannelIDServiceJob* job);

    void Post(int error, std::unique_ptr<crypto::ECPrivateKey> key);

    ChannelIDService* service_;
    base::TimeTicks request_start_;
    CompletionCallback callback_;
    std::unique_ptr<crypto::ECPrivateKey>* key_;
    ChannelIDServiceJob* job_;
  };

  // Password used on EncryptedPrivateKeyInfo data stored in EC private_key
  // values.  (This is not used to provide any security, but to workaround NSS
  // being unable to import unencrypted PrivateKeyInfo for EC keys.)
  static const char kEPKIPassword[];

  // This object owns |channel_id_store|.  |task_runner| will
  // be used to post channel ID generation worker tasks.  The tasks are
  // safe for use with WorkerPool and SequencedWorkerPool::CONTINUE_ON_SHUTDOWN.
  ChannelIDService(
      ChannelIDStore* channel_id_store,
      const scoped_refptr<base::TaskRunner>& task_runner);

  ~ChannelIDService();

  // Returns the domain to be used for |host|.  The domain is the
  // "registry controlled domain", or the "ETLD + 1" where one exists, or
  // the origin otherwise.
  static std::string GetDomainForHost(const std::string& host);

  // Fetches the channel ID for the specified host if one exists and
  // creates one otherwise. Returns OK if successful or an error code upon
  // failure.
  //
  // On successful completion, |key| holds the ECDSA keypair used for this
  // channel ID.
  //
  // |callback| must not be null. ERR_IO_PENDING is returned if the operation
  // could not be completed immediately, in which case the result code will
  // be passed to the callback when available.
  //
  // |*out_req| will be initialized with a handle to the async request.
  int GetOrCreateChannelID(const std::string& host,
                           std::unique_ptr<crypto::ECPrivateKey>* key,
                           const CompletionCallback& callback,
                           Request* out_req);

  // Fetches the channel ID for the specified host if one exists.
  // Returns OK if successful, ERR_FILE_NOT_FOUND if none exists, or an error
  // code upon failure.
  //
  // On successful completion, |key| holds the ECDSA keypair used for this
  // channel ID.
  //
  // |callback| must not be null. ERR_IO_PENDING is returned if the operation
  // could not be completed immediately, in which case the result code will
  // be passed to the callback when available. If an in-flight
  // GetChannelID is pending, and a new GetOrCreateChannelID
  // request arrives for the same domain, the GetChannelID request will
  // not complete until a new channel ID is created.
  //
  // |*out_req| will be initialized with a handle to the async request.
  int GetChannelID(const std::string& host,
                   std::unique_ptr<crypto::ECPrivateKey>* key,
                   const CompletionCallback& callback,
                   Request* out_req);

  // Returns the backing ChannelIDStore.
  ChannelIDStore* GetChannelIDStore();

  // Returns an ID that is unique across all instances of ChannelIDService in
  // this process. TODO(nharper): remove this once crbug.com/548423 is resolved.
  int GetUniqueID() const { return id_; }

  // Public only for unit testing.
  int channel_id_count();
  uint64_t requests() const { return requests_; }
  uint64_t key_store_hits() const { return key_store_hits_; }
  uint64_t inflight_joins() const { return inflight_joins_; }
  uint64_t workers_created() const { return workers_created_; }

 private:
  void GotChannelID(int err,
                    const std::string& server_identifier,
                    std::unique_ptr<crypto::ECPrivateKey> key);
  void GeneratedChannelID(
      const std::string& server_identifier,
      int error,
      std::unique_ptr<ChannelIDStore::ChannelID> channel_id);
  void HandleResult(int error,
                    const std::string& server_identifier,
                    std::unique_ptr<crypto::ECPrivateKey> key);

  // Searches for an in-flight request for the same domain. If found,
  // attaches to the request and returns true. Returns false if no in-flight
  // request is found.
  bool JoinToInFlightRequest(const base::TimeTicks& request_start,
                             const std::string& domain,
                             std::unique_ptr<crypto::ECPrivateKey>* key,
                             bool create_if_missing,
                             const CompletionCallback& callback,
                             Request* out_req);

  // Looks for the channel ID for |domain| in this service's store.
  // Returns OK if it can be found synchronously, ERR_IO_PENDING if the
  // result cannot be obtained synchronously, or a network error code on
  // failure (including failure to find a channel ID of |domain|).
  int LookupChannelID(const base::TimeTicks& request_start,
                      const std::string& domain,
                      std::unique_ptr<crypto::ECPrivateKey>* key,
                      bool create_if_missing,
                      const CompletionCallback& callback,
                      Request* out_req);

  std::unique_ptr<ChannelIDStore> channel_id_store_;
  scoped_refptr<base::TaskRunner> task_runner_;
  const int id_;

  // inflight_ maps from a server to an active generation which is taking
  // place.
  std::map<std::string, std::unique_ptr<ChannelIDServiceJob>> inflight_;

  uint64_t requests_;
  uint64_t key_store_hits_;
  uint64_t inflight_joins_;
  uint64_t workers_created_;

  base::WeakPtrFactory<ChannelIDService> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(ChannelIDService);
};

}  // namespace net

#endif  // NET_SSL_CHANNEL_ID_SERVICE_H_
