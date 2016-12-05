// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_QUIC_SERVER_INFO_H_
#define NET_QUIC_CRYPTO_QUIC_SERVER_INFO_H_

#include <string>
#include <vector>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/time/time.h"
#include "net/base/completion_callback.h"
#include "net/base/net_export.h"
#include "net/quic/core/quic_server_id.h"

namespace net {

// QuicServerInfo is an interface for fetching information about a QUIC server.
// This information may be stored on disk so does not include keys or other
// sensitive information. Primarily it's intended for caching the QUIC server's
// crypto config.
class NET_EXPORT_PRIVATE QuicServerInfo {
 public:
  // Enum to track number of times data read/parse/write API calls of
  // QuicServerInfo to and from disk cache is called.
  enum QuicServerInfoAPICall {
    QUIC_SERVER_INFO_START = 0,
    QUIC_SERVER_INFO_WAIT_FOR_DATA_READY = 1,
    QUIC_SERVER_INFO_PARSE = 2,
    QUIC_SERVER_INFO_WAIT_FOR_DATA_READY_CANCEL = 3,
    QUIC_SERVER_INFO_READY_TO_PERSIST = 4,
    QUIC_SERVER_INFO_PERSIST = 5,
    QUIC_SERVER_INFO_EXTERNAL_CACHE_HIT = 6,
    QUIC_SERVER_INFO_RESET_WAIT_FOR_DATA_READY = 7,
    QUIC_SERVER_INFO_NUM_OF_API_CALLS = 8,
  };

  // Enum to track failure reasons to read/load/write of QuicServerInfo to
  // and from disk cache.
  enum FailureReason {
    WAIT_FOR_DATA_READY_INVALID_ARGUMENT_FAILURE = 0,
    GET_BACKEND_FAILURE = 1,
    OPEN_FAILURE = 2,
    CREATE_OR_OPEN_FAILURE = 3,
    PARSE_NO_DATA_FAILURE = 4,
    PARSE_FAILURE = 5,
    READ_FAILURE = 6,
    READY_TO_PERSIST_FAILURE = 7,
    PERSIST_NO_BACKEND_FAILURE = 8,
    WRITE_FAILURE = 9,
    NO_FAILURE = 10,
    PARSE_DATA_DECODE_FAILURE = 11,
    NUM_OF_FAILURES = 12,
  };

  explicit QuicServerInfo(const QuicServerId& server_id);
  virtual ~QuicServerInfo();

  // Start will commence the lookup. This must be called before any other
  // methods. By opportunistically calling this early, it may be possible to
  // overlap this object's lookup and reduce latency.
  virtual void Start() = 0;

  // WaitForDataReady returns OK if the fetch of the requested data has
  // completed. Otherwise it returns ERR_IO_PENDING and will call |callback| on
  // the current thread when ready.
  //
  // Only a single callback can be outstanding at a given time and, in the
  // event that WaitForDataReady returns OK, it's the caller's responsibility
  // to delete |callback|.
  //
  // |callback| may be NULL, in which case ERR_IO_PENDING may still be returned
  // but, obviously, a callback will never be made.
  virtual int WaitForDataReady(const CompletionCallback& callback) = 0;

  // Reset's WaitForDataReady callback. This method shouldn't have any side
  // effects (could be called even if HttpCache doesn't exist).
  virtual void ResetWaitForDataReadyCallback() = 0;

  // Cancel's WaitForDataReady callback. |callback| passed in WaitForDataReady
  // will not be called.
  virtual void CancelWaitForDataReadyCallback() = 0;

  // Returns true if data is loaded from disk cache and ready (WaitForDataReady
  // doesn't have a pending callback).
  virtual bool IsDataReady() = 0;

  // Returns true if the object is ready to persist data, in other words, if
  // data is loaded from disk cache and ready and there are no pending writes.
  virtual bool IsReadyToPersist() = 0;

  // Persist allows for the server information to be updated for future users.
  // This is a fire and forget operation: the caller may drop its reference
  // from this object and the store operation will still complete. This can
  // only be called once WaitForDataReady has returned OK or called its
  // callback.
  virtual void Persist() = 0;

  // Called whenever an external cache reuses quic server config.
  virtual void OnExternalCacheHit() = 0;

  struct State {
    State();
    ~State();

    void Clear();

    // This class matches QuicClientCryptoConfig::CachedState.
    std::string server_config;         // A serialized handshake message.
    std::string source_address_token;  // An opaque proof of IP ownership.
    std::string cert_sct;              // Signed timestamp of the leaf cert.
    std::string chlo_hash;             // Hash of the CHLO message.
    std::vector<std::string> certs;    // A list of certificates in leaf-first
                                       // order.
    std::string server_config_sig;     // A signature of |server_config_|.

   private:
    DISALLOW_COPY_AND_ASSIGN(State);
  };

  // Once the data is ready, it can be read using the following members. These
  // members can then be updated before calling |Persist|.
  const State& state() const;
  State* mutable_state();

  base::TimeTicks wait_for_data_start_time() const {
    return wait_for_data_start_time_;
  }

  base::TimeTicks wait_for_data_end_time() const {
    return wait_for_data_end_time_;
  }

 protected:
  // Parse parses pickled data and fills out the public member fields of this
  // object. It returns true iff the parse was successful. The public member
  // fields will be set to something sane in any case.
  bool Parse(const std::string& data);
  std::string Serialize();

  State state_;

  // Time when WaitForDataReady was called and when it has finished.
  base::TimeTicks wait_for_data_start_time_;
  base::TimeTicks wait_for_data_end_time_;

  // This is the QUIC server (hostname, port, is_https, privacy_mode) tuple for
  // which we restore the crypto_config.
  const QuicServerId server_id_;

 private:
  // ParseInner is a helper function for Parse.
  bool ParseInner(const std::string& data);

  // SerializeInner is a helper function for Serialize.
  std::string SerializeInner() const;

  DISALLOW_COPY_AND_ASSIGN(QuicServerInfo);
};

class NET_EXPORT_PRIVATE QuicServerInfoFactory {
 public:
  QuicServerInfoFactory() {}
  virtual ~QuicServerInfoFactory();

  // GetForServer returns a fresh, allocated QuicServerInfo for the given
  // |server_id| or NULL on failure.
  virtual QuicServerInfo* GetForServer(const QuicServerId& server_id) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicServerInfoFactory);
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_QUIC_SERVER_INFO_H_
