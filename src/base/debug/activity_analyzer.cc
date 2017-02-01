// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/debug/activity_analyzer.h"

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/memory_mapped_file.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/stl_util.h"
#include "base/strings/string_util.h"

namespace base {
namespace debug {

ThreadActivityAnalyzer::Snapshot::Snapshot() {}
ThreadActivityAnalyzer::Snapshot::~Snapshot() {}

ThreadActivityAnalyzer::ThreadActivityAnalyzer(
    const ThreadActivityTracker& tracker)
    : activity_snapshot_valid_(tracker.CreateSnapshot(&activity_snapshot_)) {}

ThreadActivityAnalyzer::ThreadActivityAnalyzer(void* base, size_t size)
    : ThreadActivityAnalyzer(ThreadActivityTracker(base, size)) {}

ThreadActivityAnalyzer::ThreadActivityAnalyzer(
    PersistentMemoryAllocator* allocator,
    PersistentMemoryAllocator::Reference reference)
    : ThreadActivityAnalyzer(allocator->GetAsArray<char>(
                                 reference,
                                 GlobalActivityTracker::kTypeIdActivityTracker,
                                 PersistentMemoryAllocator::kSizeAny),
                             allocator->GetAllocSize(reference)) {}

ThreadActivityAnalyzer::~ThreadActivityAnalyzer() {}

void ThreadActivityAnalyzer::AddGlobalInformation(
    GlobalActivityAnalyzer* global) {
  if (!IsValid())
    return;

  // User-data is held at the global scope even though it's referenced at the
  // thread scope.
  activity_snapshot_.user_data_stack.clear();
  for (auto& activity : activity_snapshot_.activity_stack) {
    // The global GetUserDataSnapshot will return an empty snapshot if the ref
    // or id is not valid.
    activity_snapshot_.user_data_stack.push_back(global->GetUserDataSnapshot(
        activity.user_data_ref, activity.user_data_id));
  }
}

GlobalActivityAnalyzer::GlobalActivityAnalyzer(
    std::unique_ptr<PersistentMemoryAllocator> allocator)
    : allocator_(std::move(allocator)), allocator_iterator_(allocator_.get()) {}

GlobalActivityAnalyzer::~GlobalActivityAnalyzer() {}

#if !defined(OS_NACL)
// static
std::unique_ptr<GlobalActivityAnalyzer> GlobalActivityAnalyzer::CreateWithFile(
    const FilePath& file_path) {
  // Map the file read-write so it can guarantee consistency between
  // the analyzer and any trackers that my still be active.
  std::unique_ptr<MemoryMappedFile> mmfile(new MemoryMappedFile());
  mmfile->Initialize(file_path, MemoryMappedFile::READ_WRITE);
  if (!mmfile->IsValid())
    return nullptr;

  if (!FilePersistentMemoryAllocator::IsFileAcceptable(*mmfile, true))
    return nullptr;

  return WrapUnique(
      new GlobalActivityAnalyzer(MakeUnique<FilePersistentMemoryAllocator>(
          std::move(mmfile), 0, 0, base::StringPiece(), true)));
}
#endif  // !defined(OS_NACL)

ThreadActivityAnalyzer* GlobalActivityAnalyzer::GetFirstAnalyzer() {
  PrepareAllAnalyzers();
  analyzers_iterator_ = analyzers_.begin();
  if (analyzers_iterator_ == analyzers_.end())
    return nullptr;
  return analyzers_iterator_->second.get();
}

ThreadActivityAnalyzer* GlobalActivityAnalyzer::GetNextAnalyzer() {
  DCHECK(analyzers_iterator_ != analyzers_.end());
  ++analyzers_iterator_;
  if (analyzers_iterator_ == analyzers_.end())
    return nullptr;
  return analyzers_iterator_->second.get();
}

ThreadActivityAnalyzer* GlobalActivityAnalyzer::GetAnalyzerForThread(
    const ThreadKey& key) {
  auto found = analyzers_.find(key);
  if (found == analyzers_.end())
    return nullptr;
  return found->second.get();
}

ActivityUserData::Snapshot GlobalActivityAnalyzer::GetUserDataSnapshot(
    uint32_t ref,
    uint32_t id) {
  ActivityUserData::Snapshot snapshot;

  void* memory = allocator_->GetAsArray<char>(
      ref, GlobalActivityTracker::kTypeIdUserDataRecord,
      PersistentMemoryAllocator::kSizeAny);
  if (memory) {
    size_t size = allocator_->GetAllocSize(ref);
    const ActivityUserData user_data(memory, size);
    user_data.CreateSnapshot(&snapshot);
    if (user_data.id() != id) {
      // This allocation has been overwritten since it was created. Return an
      // empty snapshot because whatever was captured is incorrect.
      snapshot.clear();
    }
  }

  return snapshot;
}

ActivityUserData::Snapshot GlobalActivityAnalyzer::GetGlobalUserDataSnapshot() {
  ActivityUserData::Snapshot snapshot;

  PersistentMemoryAllocator::Reference ref =
      PersistentMemoryAllocator::Iterator(allocator_.get())
          .GetNextOfType(GlobalActivityTracker::kTypeIdGlobalDataRecord);
  void* memory = allocator_->GetAsArray<char>(
      ref, GlobalActivityTracker::kTypeIdGlobalDataRecord,
      PersistentMemoryAllocator::kSizeAny);
  if (memory) {
    size_t size = allocator_->GetAllocSize(ref);
    const ActivityUserData global_data(memory, size);
    global_data.CreateSnapshot(&snapshot);
  }

  return snapshot;
}

std::vector<std::string> GlobalActivityAnalyzer::GetLogMessages() {
  std::vector<std::string> messages;
  PersistentMemoryAllocator::Reference ref;

  PersistentMemoryAllocator::Iterator iter(allocator_.get());
  while ((ref = iter.GetNextOfType(
              GlobalActivityTracker::kTypeIdGlobalLogMessage)) != 0) {
    const char* message = allocator_->GetAsArray<char>(
        ref, GlobalActivityTracker::kTypeIdGlobalLogMessage,
        PersistentMemoryAllocator::kSizeAny);
    if (message)
      messages.push_back(message);
  }

  return messages;
}

std::vector<GlobalActivityTracker::ModuleInfo>
GlobalActivityAnalyzer::GetModules() {
  std::vector<GlobalActivityTracker::ModuleInfo> modules;

  PersistentMemoryAllocator::Iterator iter(allocator_.get());
  const GlobalActivityTracker::ModuleInfoRecord* record;
  while (
      (record =
           iter.GetNextOfObject<GlobalActivityTracker::ModuleInfoRecord>()) !=
      nullptr) {
    GlobalActivityTracker::ModuleInfo info;
    if (record->DecodeTo(&info, allocator_->GetAllocSize(
                                    allocator_->GetAsReference(record)))) {
      modules.push_back(std::move(info));
    }
  }

  return modules;
}

GlobalActivityAnalyzer::ProgramLocation
GlobalActivityAnalyzer::GetProgramLocationFromAddress(uint64_t address) {
  // TODO(bcwhite): Implement this.
  return { 0, 0 };
}

void GlobalActivityAnalyzer::PrepareAllAnalyzers() {
  // Fetch all the records. This will retrieve only ones created since the
  // last run since the PMA iterator will continue from where it left off.
  uint32_t type;
  PersistentMemoryAllocator::Reference ref;
  while ((ref = allocator_iterator_.GetNext(&type)) != 0) {
    switch (type) {
      case GlobalActivityTracker::kTypeIdActivityTracker:
      case GlobalActivityTracker::kTypeIdActivityTrackerFree:
        // Free or not, add it to the list of references for later analysis.
        tracker_references_.insert(ref);
        break;
    }
  }

  // Go through all the known references and create analyzers for them with
  // snapshots of the current state.
  analyzers_.clear();
  for (PersistentMemoryAllocator::Reference tracker_ref : tracker_references_) {
    // Get the actual data segment for the tracker. This can fail if the
    // record has been marked "free" since the type will not match.
    void* base = allocator_->GetAsArray<char>(
        tracker_ref, GlobalActivityTracker::kTypeIdActivityTracker,
        PersistentMemoryAllocator::kSizeAny);
    if (!base)
      continue;

    // Create the analyzer on the data. This will capture a snapshot of the
    // tracker state. This can fail if the tracker is somehow corrupted or is
    // in the process of shutting down.
    std::unique_ptr<ThreadActivityAnalyzer> analyzer(new ThreadActivityAnalyzer(
        base, allocator_->GetAllocSize(tracker_ref)));
    if (!analyzer->IsValid())
      continue;
    analyzer->AddGlobalInformation(this);

    // Add this analyzer to the map of known ones, indexed by a unique thread
    // identifier.
    DCHECK(!base::ContainsKey(analyzers_, analyzer->GetThreadKey()));
    analyzer->allocator_reference_ = ref;
    analyzers_[analyzer->GetThreadKey()] = std::move(analyzer);
  }
}

}  // namespace debug
}  // namespace base
