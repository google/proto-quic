// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/disk_cache_based_quic_server_info.h"

#include "base/bind.h"
#include "base/callback.h"
#include "base/callback_helpers.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/stl_util.h"
#include "net/base/completion_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/http/http_cache.h"
#include "net/http/http_network_session.h"
#include "net/quic/core/quic_server_id.h"

namespace net {

// Some APIs inside disk_cache take a handle that the caller must keep alive
// until the API has finished its asynchronous execution.
//
// Unfortunately, DiskCacheBasedQuicServerInfo may be deleted before the
// operation completes causing a use-after-free.
//
// This data shim struct is meant to provide a location for the disk_cache
// APIs to write into even if the originating DiskCacheBasedQuicServerInfo
// object has been deleted.  The lifetime for instances of this struct
// should be bound to the CompletionCallback that is passed to the disk_cache
// API.  We do this by binding an instance of this struct to an unused
// parameter for OnIOComplete() using base::Owned().
//
// This is a hack. A better fix is to make it so that the disk_cache APIs
// take a Callback to a mutator for setting the output value rather than
// writing into a raw handle. Then the caller can just pass in a Callback
// bound to WeakPtr for itself. This callback would correctly "no-op" itself
// when the DiskCacheBasedQuicServerInfo object is deleted.
//
// TODO(ajwong): Change disk_cache's API to return results via Callback.
struct DiskCacheBasedQuicServerInfo::CacheOperationDataShim {
  CacheOperationDataShim() : backend(NULL), entry(NULL) {}

  disk_cache::Backend* backend;
  disk_cache::Entry* entry;
};

DiskCacheBasedQuicServerInfo::DiskCacheBasedQuicServerInfo(
    const QuicServerId& server_id,
    HttpCache* http_cache)
    : QuicServerInfo(server_id),
      data_shim_(new CacheOperationDataShim()),
      state_(GET_BACKEND),
      ready_(false),
      found_entry_(false),
      server_id_(server_id),
      http_cache_(http_cache),
      backend_(NULL),
      entry_(NULL),
      last_failure_(NO_FAILURE),
      weak_factory_(this) {
      io_callback_ =
          base::Bind(&DiskCacheBasedQuicServerInfo::OnIOComplete,
                     weak_factory_.GetWeakPtr(),
                     base::Owned(data_shim_));  // Ownership assigned.
}

DiskCacheBasedQuicServerInfo::~DiskCacheBasedQuicServerInfo() {
  DCHECK(wait_for_ready_callback_.is_null());
  if (entry_)
    entry_->Close();
}

void DiskCacheBasedQuicServerInfo::Start() {
  DCHECK(CalledOnValidThread());
  DCHECK_EQ(GET_BACKEND, state_);
  DCHECK_EQ(last_failure_, NO_FAILURE);
  RecordQuicServerInfoStatus(QUIC_SERVER_INFO_START);
  load_start_time_ = base::TimeTicks::Now();
  DoLoop(OK);
}

int DiskCacheBasedQuicServerInfo::WaitForDataReady(
    const CompletionCallback& callback) {
  DCHECK(CalledOnValidThread());
  DCHECK_NE(GET_BACKEND, state_);
  wait_for_data_start_time_ = base::TimeTicks::Now();

  RecordQuicServerInfoStatus(QUIC_SERVER_INFO_WAIT_FOR_DATA_READY);
  if (ready_) {
    wait_for_data_end_time_ = base::TimeTicks::Now();
    RecordLastFailure();
    return OK;
  }

  if (!callback.is_null()) {
    // Prevent a new callback for WaitForDataReady overwriting an existing
    // pending callback (|wait_for_ready_callback_|).
    if (!wait_for_ready_callback_.is_null()) {
      RecordQuicServerInfoFailure(WAIT_FOR_DATA_READY_INVALID_ARGUMENT_FAILURE);
      return ERR_INVALID_ARGUMENT;
    }
    wait_for_ready_callback_ = callback;
  }

  return ERR_IO_PENDING;
}

void DiskCacheBasedQuicServerInfo::ResetWaitForDataReadyCallback() {
  DCHECK(CalledOnValidThread());
  wait_for_ready_callback_.Reset();
}

void DiskCacheBasedQuicServerInfo::CancelWaitForDataReadyCallback() {
  DCHECK(CalledOnValidThread());

  RecordQuicServerInfoStatus(QUIC_SERVER_INFO_WAIT_FOR_DATA_READY_CANCEL);
  if (!wait_for_ready_callback_.is_null()) {
    RecordLastFailure();
    wait_for_ready_callback_.Reset();
  }
}

bool DiskCacheBasedQuicServerInfo::IsDataReady() {
  return ready_;
}

bool DiskCacheBasedQuicServerInfo::IsReadyToPersist() {
  // The data can be persisted if it has been loaded from the disk cache
  // and there are no pending writes.
  RecordQuicServerInfoStatus(QUIC_SERVER_INFO_READY_TO_PERSIST);
  if (ready_ && new_data_.empty())
    return true;
  RecordQuicServerInfoFailure(READY_TO_PERSIST_FAILURE);
  return false;
}

void DiskCacheBasedQuicServerInfo::Persist() {
  DCHECK(CalledOnValidThread());
  if (!IsReadyToPersist()) {
    // Handle updates while a write is pending or if we haven't loaded from disk
    // cache. Save the data to be written into a temporary buffer and then
    // persist that data when we are ready to persist.
    pending_write_data_ = Serialize();
    return;
  }
  PersistInternal();
}

void DiskCacheBasedQuicServerInfo::PersistInternal() {
  DCHECK(CalledOnValidThread());
  DCHECK_NE(GET_BACKEND, state_);
  DCHECK(new_data_.empty());
  CHECK(ready_);
  DCHECK(wait_for_ready_callback_.is_null());

  if (pending_write_data_.empty()) {
    new_data_ = Serialize();
  } else {
    new_data_ = pending_write_data_;
    base::STLClearObject(&pending_write_data_);
  }

  RecordQuicServerInfoStatus(QUIC_SERVER_INFO_PERSIST);
  if (!backend_) {
    RecordQuicServerInfoFailure(PERSIST_NO_BACKEND_FAILURE);
    return;
  }

  state_ = CREATE_OR_OPEN;
  DoLoop(OK);
}

void DiskCacheBasedQuicServerInfo::OnExternalCacheHit() {
  DCHECK(CalledOnValidThread());
  DCHECK_NE(GET_BACKEND, state_);

  RecordQuicServerInfoStatus(QUIC_SERVER_INFO_EXTERNAL_CACHE_HIT);
  if (!backend_) {
    RecordQuicServerInfoFailure(PERSIST_NO_BACKEND_FAILURE);
    return;
  }

  backend_->OnExternalCacheHit(key());
}

std::string DiskCacheBasedQuicServerInfo::key() const {
  return "quicserverinfo:" + server_id_.ToString();
}

void DiskCacheBasedQuicServerInfo::OnIOComplete(CacheOperationDataShim* unused,
                                                int rv) {
  DCHECK_NE(NONE, state_);
  rv = DoLoop(rv);
  if (rv == ERR_IO_PENDING)
    return;

  base::WeakPtr<DiskCacheBasedQuicServerInfo> weak_this =
      weak_factory_.GetWeakPtr();

  if (!wait_for_ready_callback_.is_null()) {
    wait_for_data_end_time_ = base::TimeTicks::Now();
    RecordLastFailure();
    base::ResetAndReturn(&wait_for_ready_callback_).Run(rv);
  }
  // |wait_for_ready_callback_| could delete the object if there is an error.
  // Check if |weak_this| still exists before accessing it.
  if (weak_this.get() && ready_ && !pending_write_data_.empty()) {
    DCHECK_EQ(NONE, state_);
    PersistInternal();
  }
}

int DiskCacheBasedQuicServerInfo::DoLoop(int rv) {
  do {
    switch (state_) {
      case GET_BACKEND:
        rv = DoGetBackend();
        break;
      case GET_BACKEND_COMPLETE:
        rv = DoGetBackendComplete(rv);
        break;
      case OPEN:
        rv = DoOpen();
        break;
      case OPEN_COMPLETE:
        rv = DoOpenComplete(rv);
        break;
      case READ:
        rv = DoRead();
        break;
      case READ_COMPLETE:
        rv = DoReadComplete(rv);
        break;
      case WAIT_FOR_DATA_READY_DONE:
        rv = DoWaitForDataReadyDone();
        break;
      case CREATE_OR_OPEN:
        rv = DoCreateOrOpen();
        break;
      case CREATE_OR_OPEN_COMPLETE:
        rv = DoCreateOrOpenComplete(rv);
        break;
      case WRITE:
        rv = DoWrite();
        break;
      case WRITE_COMPLETE:
        rv = DoWriteComplete(rv);
        break;
      case SET_DONE:
        rv = DoSetDone();
        break;
      default:
        rv = OK;
        NOTREACHED();
    }
  } while (rv != ERR_IO_PENDING && state_ != NONE);

  return rv;
}

int DiskCacheBasedQuicServerInfo::DoGetBackendComplete(int rv) {
  if (rv == OK) {
    backend_ = data_shim_->backend;
    state_ = OPEN;
  } else {
    RecordQuicServerInfoFailure(GET_BACKEND_FAILURE);
    state_ = WAIT_FOR_DATA_READY_DONE;
  }
  return OK;
}

int DiskCacheBasedQuicServerInfo::DoOpenComplete(int rv) {
  if (rv == OK) {
    entry_ = data_shim_->entry;
    state_ = READ;
    found_entry_ = true;
  } else {
    RecordQuicServerInfoFailure(OPEN_FAILURE);
    state_ = WAIT_FOR_DATA_READY_DONE;
  }

  return OK;
}

int DiskCacheBasedQuicServerInfo::DoReadComplete(int rv) {
  if (rv > 0)
    data_.assign(read_buffer_->data(), rv);
  else if (rv < 0)
    RecordQuicServerInfoFailure(READ_FAILURE);

  read_buffer_ = nullptr;
  state_ = WAIT_FOR_DATA_READY_DONE;
  return OK;
}

int DiskCacheBasedQuicServerInfo::DoWriteComplete(int rv) {
  if (rv < 0)
    RecordQuicServerInfoFailure(WRITE_FAILURE);
  write_buffer_ = nullptr;
  state_ = SET_DONE;
  return OK;
}

int DiskCacheBasedQuicServerInfo::DoCreateOrOpenComplete(int rv) {
  if (rv != OK) {
    RecordQuicServerInfoFailure(CREATE_OR_OPEN_FAILURE);
    state_ = SET_DONE;
  } else {
    if (!entry_) {
      entry_ = data_shim_->entry;
      found_entry_ = true;
    }
    DCHECK(entry_);
    state_ = WRITE;
  }
  return OK;
}

int DiskCacheBasedQuicServerInfo::DoGetBackend() {
  state_ = GET_BACKEND_COMPLETE;
  return http_cache_->GetBackend(&data_shim_->backend, io_callback_);
}

int DiskCacheBasedQuicServerInfo::DoOpen() {
  state_ = OPEN_COMPLETE;
  return backend_->OpenEntry(key(), &data_shim_->entry, io_callback_);
}

int DiskCacheBasedQuicServerInfo::DoRead() {
  const int32_t size = entry_->GetDataSize(0 /* index */);
  if (!size) {
    state_ = WAIT_FOR_DATA_READY_DONE;
    return OK;
  }

  read_buffer_ = new IOBuffer(size);
  state_ = READ_COMPLETE;
  return entry_->ReadData(
      0 /* index */, 0 /* offset */, read_buffer_.get(), size, io_callback_);
}

int DiskCacheBasedQuicServerInfo::DoWrite() {
  write_buffer_ = new IOBuffer(new_data_.size());
  memcpy(write_buffer_->data(), new_data_.data(), new_data_.size());
  state_ = WRITE_COMPLETE;

  return entry_->WriteData(0 /* index */,
                           0 /* offset */,
                           write_buffer_.get(),
                           new_data_.size(),
                           io_callback_,
                           true /* truncate */);
}

int DiskCacheBasedQuicServerInfo::DoCreateOrOpen() {
  state_ = CREATE_OR_OPEN_COMPLETE;
  if (entry_)
    return OK;

  if (found_entry_) {
    return backend_->OpenEntry(key(), &data_shim_->entry, io_callback_);
  }

  return backend_->CreateEntry(key(), &data_shim_->entry, io_callback_);
}

int DiskCacheBasedQuicServerInfo::DoWaitForDataReadyDone() {
  DCHECK(!ready_);
  state_ = NONE;
  ready_ = true;
  // We close the entry because, if we shutdown before ::Persist is called,
  // then we might leak a cache reference, which causes a DCHECK on shutdown.
  if (entry_)
    entry_->Close();
  entry_ = NULL;

  RecordQuicServerInfoStatus(QUIC_SERVER_INFO_PARSE);
  if (!Parse(data_)) {
    if (data_.empty())
      RecordQuicServerInfoFailure(PARSE_NO_DATA_FAILURE);
    else
      RecordQuicServerInfoFailure(PARSE_FAILURE);
  }

  UMA_HISTOGRAM_TIMES("Net.QuicServerInfo.DiskCacheLoadTime",
                      base::TimeTicks::Now() - load_start_time_);
  return OK;
}

int DiskCacheBasedQuicServerInfo::DoSetDone() {
  if (entry_)
    entry_->Close();
  entry_ = NULL;
  base::STLClearObject(&new_data_);
  state_ = NONE;
  return OK;
}

void DiskCacheBasedQuicServerInfo::RecordQuicServerInfoStatus(
    QuicServerInfoAPICall call) {
  if (!backend_) {
    UMA_HISTOGRAM_ENUMERATION("Net.QuicDiskCache.APICall.NoBackend", call,
                              QUIC_SERVER_INFO_NUM_OF_API_CALLS);
  } else if (backend_->GetCacheType() == MEMORY_CACHE) {
    UMA_HISTOGRAM_ENUMERATION("Net.QuicDiskCache.APICall.MemoryCache", call,
                              QUIC_SERVER_INFO_NUM_OF_API_CALLS);
  } else {
    UMA_HISTOGRAM_ENUMERATION("Net.QuicDiskCache.APICall.DiskCache", call,
                              QUIC_SERVER_INFO_NUM_OF_API_CALLS);
  }
}

void DiskCacheBasedQuicServerInfo::RecordLastFailure() {
  if (last_failure_ != NO_FAILURE) {
    UMA_HISTOGRAM_ENUMERATION(
        "Net.QuicDiskCache.FailureReason.WaitForDataReady",
        last_failure_, NUM_OF_FAILURES);
  }
  last_failure_ = NO_FAILURE;
}

void DiskCacheBasedQuicServerInfo::RecordQuicServerInfoFailure(
    FailureReason failure) {
  last_failure_ = failure;

  if (!backend_) {
    UMA_HISTOGRAM_ENUMERATION("Net.QuicDiskCache.FailureReason.NoBackend",
                              failure, NUM_OF_FAILURES);
  } else if (backend_->GetCacheType() == MEMORY_CACHE) {
    UMA_HISTOGRAM_ENUMERATION("Net.QuicDiskCache.FailureReason.MemoryCache",
                              failure, NUM_OF_FAILURES);
  } else {
    UMA_HISTOGRAM_ENUMERATION("Net.QuicDiskCache.FailureReason.DiskCache",
                              failure, NUM_OF_FAILURES);
  }
}

}  // namespace net
