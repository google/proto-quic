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

ThreadActivityAnalyzer::ThreadActivityAnalyzer(
    const ThreadActivityTracker& tracker)
    : activity_snapshot_valid_(tracker.Snapshot(&activity_snapshot_)) {}

ThreadActivityAnalyzer::ThreadActivityAnalyzer(void* base, size_t size)
    : ThreadActivityAnalyzer(ThreadActivityTracker(base, size)) {}

ThreadActivityAnalyzer::ThreadActivityAnalyzer(
    PersistentMemoryAllocator* allocator,
    PersistentMemoryAllocator::Reference reference)
    : ThreadActivityAnalyzer(allocator->GetAsObject<char>(
                                 reference,
                                 GlobalActivityTracker::kTypeIdActivityTracker),
                             allocator->GetAllocSize(reference)) {}

ThreadActivityAnalyzer::~ThreadActivityAnalyzer() {}

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
    void* base = allocator_->GetAsObject<char>(
        tracker_ref, GlobalActivityTracker::kTypeIdActivityTracker);
    if (!base)
      continue;

    // Create the analyzer on the data. This will capture a snapshot of the
    // tracker state. This can fail if the tracker is somehow corrupted or is
    // in the process of shutting down.
    std::unique_ptr<ThreadActivityAnalyzer> analyzer(new ThreadActivityAnalyzer(
        base, allocator_->GetAllocSize(tracker_ref)));
    if (!analyzer->IsValid())
      continue;

    // Add this analyzer to the map of known ones, indexed by a unique thread
    // identifier.
    DCHECK(!base::ContainsKey(analyzers_, analyzer->GetThreadKey()));
    analyzer->allocator_reference_ = ref;
    analyzers_[analyzer->GetThreadKey()] = std::move(analyzer);
  }
}

}  // namespace debug
}  // namespace base
