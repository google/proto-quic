// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_DEBUG_ACTIVITY_ANALYZER_H_
#define BASE_DEBUG_ACTIVITY_ANALYZER_H_

#include <map>
#include <memory>
#include <set>
#include <string>

#include "base/base_export.h"
#include "base/debug/activity_tracker.h"

namespace base {
namespace debug {

class GlobalActivityAnalyzer;

// This class provides analysis of data captured from a ThreadActivityTracker.
// When created, it takes a snapshot of the data held by the tracker and
// makes that information available to other code.
class BASE_EXPORT ThreadActivityAnalyzer {
 public:
  struct BASE_EXPORT Snapshot : ThreadActivityTracker::Snapshot {
    Snapshot();
    ~Snapshot();

    // The user-data snapshot for an activity, matching the |activity_stack|
    // of ThreadActivityTracker::Snapshot, if any.
    std::vector<ActivityUserData::Snapshot> user_data_stack;
  };

  // This class provides keys that uniquely identify a thread, even across
  // multiple processes.
  class ThreadKey {
   public:
    ThreadKey(int64_t pid, int64_t tid) : pid_(pid), tid_(tid) {}

    bool operator<(const ThreadKey& rhs) const {
      if (pid_ != rhs.pid_)
        return pid_ < rhs.pid_;
      return tid_ < rhs.tid_;
    }

    bool operator==(const ThreadKey& rhs) const {
      return (pid_ == rhs.pid_ && tid_ == rhs.tid_);
    }

   private:
    int64_t pid_;
    int64_t tid_;
  };

  // Creates an analyzer for an existing activity |tracker|. A snapshot is taken
  // immediately and the tracker is not referenced again.
  explicit ThreadActivityAnalyzer(const ThreadActivityTracker& tracker);

  // Creates an analyzer for a block of memory currently or previously in-use
  // by an activity-tracker. A snapshot is taken immediately and the memory
  // is not referenced again.
  ThreadActivityAnalyzer(void* base, size_t size);

  // Creates an analyzer for a block of memory held within a persistent-memory
  // |allocator| at the given |reference|. A snapshot is taken immediately and
  // the memory is not referenced again.
  ThreadActivityAnalyzer(PersistentMemoryAllocator* allocator,
                         PersistentMemoryAllocator::Reference reference);

  ~ThreadActivityAnalyzer();

  // Adds information from the global analyzer.
  void AddGlobalInformation(GlobalActivityAnalyzer* global);

  // Returns true iff the contained data is valid. Results from all other
  // methods are undefined if this returns false.
  bool IsValid() { return activity_snapshot_valid_; }

  // Gets the name of the thread.
  const std::string& GetThreadName() {
    return activity_snapshot_.thread_name;
  }

  // Gets the TheadKey for this thread.
  ThreadKey GetThreadKey() {
    return ThreadKey(activity_snapshot_.process_id,
                     activity_snapshot_.thread_id);
  }

  const Snapshot& activity_snapshot() { return activity_snapshot_; }

 private:
  friend class GlobalActivityAnalyzer;

  // The snapshot of the activity tracker taken at the moment of construction.
  Snapshot activity_snapshot_;

  // Flag indicating if the snapshot data is valid.
  bool activity_snapshot_valid_;

  // A reference into a persistent memory allocator, used by the global
  // analyzer to know where this tracker came from.
  PersistentMemoryAllocator::Reference allocator_reference_ = 0;

  DISALLOW_COPY_AND_ASSIGN(ThreadActivityAnalyzer);
};


// This class manages analyzers for all known processes and threads as stored
// in a persistent memory allocator. It supports retrieval of them through
// iteration and directly using a ThreadKey, which allows for cross-references
// to be resolved.
// Note that though atomic snapshots are used and everything has its snapshot
// taken at the same time, the multi-snapshot itself is not atomic and thus may
// show small inconsistencies between threads if attempted on a live system.
class BASE_EXPORT GlobalActivityAnalyzer {
 public:
  struct ProgramLocation {
    int module;
    uintptr_t offset;
  };

  using ThreadKey = ThreadActivityAnalyzer::ThreadKey;

  // Creates a global analyzer from a persistent memory allocator.
  explicit GlobalActivityAnalyzer(
      std::unique_ptr<PersistentMemoryAllocator> allocator);

  ~GlobalActivityAnalyzer();

#if !defined(OS_NACL)
  // Creates a global analyzer using the contents of a file given in
  // |file_path|.
  static std::unique_ptr<GlobalActivityAnalyzer> CreateWithFile(
      const FilePath& file_path);
#endif  // !defined(OS_NACL)

  // Iterates over all known valid analyzers or returns null if there are no
  // more. Ownership stays with the global analyzer object and all existing
  // analyzer pointers are invalidated when GetFirstAnalyzer() is called.
  ThreadActivityAnalyzer* GetFirstAnalyzer();
  ThreadActivityAnalyzer* GetNextAnalyzer();

  // Gets the analyzer for a specific thread or null if there is none.
  // Ownership stays with the global analyzer object.
  ThreadActivityAnalyzer* GetAnalyzerForThread(const ThreadKey& key);

  // Extract user data based on a reference and its identifier.
  ActivityUserData::Snapshot GetUserDataSnapshot(uint32_t ref, uint32_t id);

  // Extract the global user data.
  ActivityUserData::Snapshot GetGlobalUserDataSnapshot();

  // Gets all log messages stored within.
  std::vector<std::string> GetLogMessages();

  // Gets all the known modules.
  std::vector<GlobalActivityTracker::ModuleInfo> GetModules();

  // Gets the corresponding "program location" for a given "program counter".
  // This will return {0,0} if no mapping could be found.
  ProgramLocation GetProgramLocationFromAddress(uint64_t address);

 private:
  using AnalyzerMap =
      std::map<ThreadKey, std::unique_ptr<ThreadActivityAnalyzer>>;

  // Finds, creates, and indexes analyzers for all known processes and threads.
  void PrepareAllAnalyzers();

  // The persistent memory allocator holding all tracking data.
  std::unique_ptr<PersistentMemoryAllocator> allocator_;

  // The iterator for finding tracking information in the allocator.
  PersistentMemoryAllocator::Iterator allocator_iterator_;

  // A set of all tracker memory references found within the allocator.
  std::set<PersistentMemoryAllocator::Reference> tracker_references_;

  // A map, keyed by ThreadKey, of all valid activity analyzers.
  AnalyzerMap analyzers_;

  // The iterator within the analyzers_ map for returning analyzers through
  // first/next iteration.
  AnalyzerMap::iterator analyzers_iterator_;

  DISALLOW_COPY_AND_ASSIGN(GlobalActivityAnalyzer);
};

}  // namespace debug
}  // namespace base

#endif  // BASE_DEBUG_ACTIVITY_ANALYZER_H_
