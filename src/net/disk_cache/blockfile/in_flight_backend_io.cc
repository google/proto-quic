// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/blockfile/in_flight_backend_io.h"

#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/compiler_specific.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/single_thread_task_runner.h"
#include "net/base/net_errors.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/blockfile/entry_impl.h"
#include "net/disk_cache/blockfile/histogram_macros.h"

// Provide a BackendImpl object to macros from histogram_macros.h.
#define CACHE_UMA_BACKEND_IMPL_OBJ backend_

namespace disk_cache {

namespace {

// Used to leak a strong reference to an EntryImpl to the user of disk_cache.
EntryImpl* LeakEntryImpl(scoped_refptr<EntryImpl> entry) {
  // Balanced on OP_CLOSE_ENTRY handling in BackendIO::ExecuteBackendOperation.
  if (entry)
    entry->AddRef();
  return entry.get();
}

}  // namespace

BackendIO::BackendIO(InFlightIO* controller, BackendImpl* backend,
                     const net::CompletionCallback& callback)
    : BackgroundIO(controller),
      backend_(backend),
      callback_(callback),
      operation_(OP_NONE),
      entry_ptr_(NULL),
      iterator_(NULL),
      entry_(NULL),
      index_(0),
      offset_(0),
      buf_len_(0),
      truncate_(false),
      offset64_(0),
      start_(NULL) {
  start_time_ = base::TimeTicks::Now();
}

// Runs on the background thread.
void BackendIO::ExecuteOperation() {
  if (IsEntryOperation())
    return ExecuteEntryOperation();

  ExecuteBackendOperation();
}

// Runs on the background thread.
void BackendIO::OnIOComplete(int result) {
  DCHECK(IsEntryOperation());
  DCHECK_NE(result, net::ERR_IO_PENDING);
  result_ = result;
  NotifyController();
}

// Runs on the primary thread.
void BackendIO::OnDone(bool cancel) {
  if (IsEntryOperation()) {
    CACHE_UMA(TIMES, "TotalIOTime", 0, ElapsedTime());
  }

  if (!ReturnsEntry())
    return;

  if (result() == net::OK) {
    static_cast<EntryImpl*>(*entry_ptr_)->OnEntryCreated(backend_);
    if (cancel)
      (*entry_ptr_)->Close();
  }
}

bool BackendIO::IsEntryOperation() {
  return operation_ > OP_MAX_BACKEND;
}

void BackendIO::Init() {
  operation_ = OP_INIT;
}

void BackendIO::OpenEntry(const std::string& key, Entry** entry) {
  operation_ = OP_OPEN;
  key_ = key;
  entry_ptr_ = entry;
}

void BackendIO::CreateEntry(const std::string& key, Entry** entry) {
  operation_ = OP_CREATE;
  key_ = key;
  entry_ptr_ = entry;
}

void BackendIO::DoomEntry(const std::string& key) {
  operation_ = OP_DOOM;
  key_ = key;
}

void BackendIO::DoomAllEntries() {
  operation_ = OP_DOOM_ALL;
}

void BackendIO::DoomEntriesBetween(const base::Time initial_time,
                                   const base::Time end_time) {
  operation_ = OP_DOOM_BETWEEN;
  initial_time_ = initial_time;
  end_time_ = end_time;
}

void BackendIO::DoomEntriesSince(const base::Time initial_time) {
  operation_ = OP_DOOM_SINCE;
  initial_time_ = initial_time;
}

void BackendIO::CalculateSizeOfAllEntries() {
  operation_ = OP_SIZE_ALL;
}

void BackendIO::OpenNextEntry(Rankings::Iterator* iterator,
                              Entry** next_entry) {
  operation_ = OP_OPEN_NEXT;
  iterator_ = iterator;
  entry_ptr_ = next_entry;
}

void BackendIO::EndEnumeration(std::unique_ptr<Rankings::Iterator> iterator) {
  operation_ = OP_END_ENUMERATION;
  scoped_iterator_ = std::move(iterator);
}

void BackendIO::OnExternalCacheHit(const std::string& key) {
  operation_ = OP_ON_EXTERNAL_CACHE_HIT;
  key_ = key;
}

void BackendIO::CloseEntryImpl(EntryImpl* entry) {
  operation_ = OP_CLOSE_ENTRY;
  entry_ = entry;
}

void BackendIO::DoomEntryImpl(EntryImpl* entry) {
  operation_ = OP_DOOM_ENTRY;
  entry_ = entry;
}

void BackendIO::FlushQueue() {
  operation_ = OP_FLUSH_QUEUE;
}

void BackendIO::RunTask(const base::Closure& task) {
  operation_ = OP_RUN_TASK;
  task_ = task;
}

void BackendIO::ReadData(EntryImpl* entry, int index, int offset,
                         net::IOBuffer* buf, int buf_len) {
  operation_ = OP_READ;
  entry_ = entry;
  index_ = index;
  offset_ = offset;
  buf_ = buf;
  buf_len_ = buf_len;
}

void BackendIO::WriteData(EntryImpl* entry, int index, int offset,
                          net::IOBuffer* buf, int buf_len, bool truncate) {
  operation_ = OP_WRITE;
  entry_ = entry;
  index_ = index;
  offset_ = offset;
  buf_ = buf;
  buf_len_ = buf_len;
  truncate_ = truncate;
}

void BackendIO::ReadSparseData(EntryImpl* entry,
                               int64_t offset,
                               net::IOBuffer* buf,
                               int buf_len) {
  operation_ = OP_READ_SPARSE;
  entry_ = entry;
  offset64_ = offset;
  buf_ = buf;
  buf_len_ = buf_len;
}

void BackendIO::WriteSparseData(EntryImpl* entry,
                                int64_t offset,
                                net::IOBuffer* buf,
                                int buf_len) {
  operation_ = OP_WRITE_SPARSE;
  entry_ = entry;
  offset64_ = offset;
  buf_ = buf;
  buf_len_ = buf_len;
}

void BackendIO::GetAvailableRange(EntryImpl* entry,
                                  int64_t offset,
                                  int len,
                                  int64_t* start) {
  operation_ = OP_GET_RANGE;
  entry_ = entry;
  offset64_ = offset;
  buf_len_ = len;
  start_ = start;
}

void BackendIO::CancelSparseIO(EntryImpl* entry) {
  operation_ = OP_CANCEL_IO;
  entry_ = entry;
}

void BackendIO::ReadyForSparseIO(EntryImpl* entry) {
  operation_ = OP_IS_READY;
  entry_ = entry;
}

BackendIO::~BackendIO() {}

bool BackendIO::ReturnsEntry() {
  return operation_ == OP_OPEN || operation_ == OP_CREATE ||
      operation_ == OP_OPEN_NEXT;
}

base::TimeDelta BackendIO::ElapsedTime() const {
  return base::TimeTicks::Now() - start_time_;
}

// Runs on the background thread.
void BackendIO::ExecuteBackendOperation() {
  switch (operation_) {
    case OP_INIT:
      result_ = backend_->SyncInit();
      break;
    case OP_OPEN: {
      scoped_refptr<EntryImpl> entry;
      result_ = backend_->SyncOpenEntry(key_, &entry);
      *entry_ptr_ = LeakEntryImpl(std::move(entry));
      break;
    }
    case OP_CREATE: {
      scoped_refptr<EntryImpl> entry;
      result_ = backend_->SyncCreateEntry(key_, &entry);
      *entry_ptr_ = LeakEntryImpl(std::move(entry));
      break;
    }
    case OP_DOOM:
      result_ = backend_->SyncDoomEntry(key_);
      break;
    case OP_DOOM_ALL:
      result_ = backend_->SyncDoomAllEntries();
      break;
    case OP_DOOM_BETWEEN:
      result_ = backend_->SyncDoomEntriesBetween(initial_time_, end_time_);
      break;
    case OP_DOOM_SINCE:
      result_ = backend_->SyncDoomEntriesSince(initial_time_);
      break;
    case OP_SIZE_ALL:
      result_ = backend_->SyncCalculateSizeOfAllEntries();
      break;
    case OP_OPEN_NEXT: {
      scoped_refptr<EntryImpl> entry;
      result_ = backend_->SyncOpenNextEntry(iterator_, &entry);
      *entry_ptr_ = LeakEntryImpl(std::move(entry));
      break;
    }
    case OP_END_ENUMERATION:
      backend_->SyncEndEnumeration(std::move(scoped_iterator_));
      result_ = net::OK;
      break;
    case OP_ON_EXTERNAL_CACHE_HIT:
      backend_->SyncOnExternalCacheHit(key_);
      result_ = net::OK;
      break;
    case OP_CLOSE_ENTRY:
      // Collect the reference to |entry_| to balance with the AddRef() in
      // LeakEntryImpl.
      entry_->Release();
      result_ = net::OK;
      break;
    case OP_DOOM_ENTRY:
      entry_->DoomImpl();
      result_ = net::OK;
      break;
    case OP_FLUSH_QUEUE:
      result_ = net::OK;
      break;
    case OP_RUN_TASK:
      task_.Run();
      result_ = net::OK;
      break;
    default:
      NOTREACHED() << "Invalid Operation";
      result_ = net::ERR_UNEXPECTED;
  }
  DCHECK_NE(net::ERR_IO_PENDING, result_);
  NotifyController();
}

// Runs on the background thread.
void BackendIO::ExecuteEntryOperation() {
  switch (operation_) {
    case OP_READ:
      result_ =
          entry_->ReadDataImpl(index_, offset_, buf_.get(), buf_len_,
                               base::Bind(&BackendIO::OnIOComplete, this));
      break;
    case OP_WRITE:
      result_ =
          entry_->WriteDataImpl(index_, offset_, buf_.get(), buf_len_,
                                base::Bind(&BackendIO::OnIOComplete, this),
                                truncate_);
      break;
    case OP_READ_SPARSE:
      result_ = entry_->ReadSparseDataImpl(
                    offset64_, buf_.get(), buf_len_,
                    base::Bind(&BackendIO::OnIOComplete, this));
      break;
    case OP_WRITE_SPARSE:
      result_ = entry_->WriteSparseDataImpl(
                    offset64_, buf_.get(), buf_len_,
                    base::Bind(&BackendIO::OnIOComplete, this));
      break;
    case OP_GET_RANGE:
      result_ = entry_->GetAvailableRangeImpl(offset64_, buf_len_, start_);
      break;
    case OP_CANCEL_IO:
      entry_->CancelSparseIOImpl();
      result_ = net::OK;
      break;
    case OP_IS_READY:
      result_ = entry_->ReadyForSparseIOImpl(
                    base::Bind(&BackendIO::OnIOComplete, this));
      break;
    default:
      NOTREACHED() << "Invalid Operation";
      result_ = net::ERR_UNEXPECTED;
  }
  buf_ = NULL;
  if (result_ != net::ERR_IO_PENDING)
    NotifyController();
}

InFlightBackendIO::InFlightBackendIO(
    BackendImpl* backend,
    const scoped_refptr<base::SingleThreadTaskRunner>& background_thread)
    : backend_(backend),
      background_thread_(background_thread),
      ptr_factory_(this) {
}

InFlightBackendIO::~InFlightBackendIO() {
}

void InFlightBackendIO::Init(const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->Init();
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::OpenEntry(const std::string& key, Entry** entry,
                                  const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->OpenEntry(key, entry);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::CreateEntry(const std::string& key, Entry** entry,
                                    const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->CreateEntry(key, entry);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::DoomEntry(const std::string& key,
                                  const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->DoomEntry(key);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::DoomAllEntries(
    const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->DoomAllEntries();
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::DoomEntriesBetween(const base::Time initial_time,
                        const base::Time end_time,
                        const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->DoomEntriesBetween(initial_time, end_time);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::CalculateSizeOfAllEntries(
    const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->CalculateSizeOfAllEntries();
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::DoomEntriesSince(
    const base::Time initial_time, const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->DoomEntriesSince(initial_time);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::OpenNextEntry(Rankings::Iterator* iterator,
                                      Entry** next_entry,
                                      const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->OpenNextEntry(iterator, next_entry);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::EndEnumeration(
    std::unique_ptr<Rankings::Iterator> iterator) {
  scoped_refptr<BackendIO> operation(
      new BackendIO(this, backend_, net::CompletionCallback()));
  operation->EndEnumeration(std::move(iterator));
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::OnExternalCacheHit(const std::string& key) {
  scoped_refptr<BackendIO> operation(
      new BackendIO(this, backend_, net::CompletionCallback()));
  operation->OnExternalCacheHit(key);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::CloseEntryImpl(EntryImpl* entry) {
  scoped_refptr<BackendIO> operation(
      new BackendIO(this, backend_, net::CompletionCallback()));
  operation->CloseEntryImpl(entry);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::DoomEntryImpl(EntryImpl* entry) {
  scoped_refptr<BackendIO> operation(
      new BackendIO(this, backend_, net::CompletionCallback()));
  operation->DoomEntryImpl(entry);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::FlushQueue(const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->FlushQueue();
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::RunTask(
    const base::Closure& task, const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->RunTask(task);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::ReadData(EntryImpl* entry, int index, int offset,
                                 net::IOBuffer* buf, int buf_len,
                                 const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->ReadData(entry, index, offset, buf, buf_len);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::WriteData(EntryImpl* entry, int index, int offset,
                                  net::IOBuffer* buf, int buf_len,
                                  bool truncate,
                                  const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->WriteData(entry, index, offset, buf, buf_len, truncate);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::ReadSparseData(
    EntryImpl* entry,
    int64_t offset,
    net::IOBuffer* buf,
    int buf_len,
    const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->ReadSparseData(entry, offset, buf, buf_len);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::WriteSparseData(
    EntryImpl* entry,
    int64_t offset,
    net::IOBuffer* buf,
    int buf_len,
    const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->WriteSparseData(entry, offset, buf, buf_len);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::GetAvailableRange(
    EntryImpl* entry,
    int64_t offset,
    int len,
    int64_t* start,
    const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->GetAvailableRange(entry, offset, len, start);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::CancelSparseIO(EntryImpl* entry) {
  scoped_refptr<BackendIO> operation(
      new BackendIO(this, backend_, net::CompletionCallback()));
  operation->CancelSparseIO(entry);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::ReadyForSparseIO(
    EntryImpl* entry, const net::CompletionCallback& callback) {
  scoped_refptr<BackendIO> operation(new BackendIO(this, backend_, callback));
  operation->ReadyForSparseIO(entry);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::WaitForPendingIO() {
  InFlightIO::WaitForPendingIO();
}

void InFlightBackendIO::OnOperationComplete(BackgroundIO* operation,
                                            bool cancel) {
  BackendIO* op = static_cast<BackendIO*>(operation);
  op->OnDone(cancel);

  if (!op->callback().is_null() && (!cancel || op->IsEntryOperation()))
    op->callback().Run(op->result());
}

void InFlightBackendIO::PostOperation(
    const tracked_objects::Location& from_here,
    BackendIO* operation) {
  background_thread_->PostTask(
      from_here, base::Bind(&BackendIO::ExecuteOperation, operation));
  OnOperationPosted(operation);
}

base::WeakPtr<InFlightBackendIO> InFlightBackendIO::GetWeakPtr() {
  return ptr_factory_.GetWeakPtr();
}

}  // namespace
