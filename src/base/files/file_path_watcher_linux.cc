// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/file_path_watcher.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/containers/hash_tables.h"
#include "base/files/file_enumerator.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/lazy_instance.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/weak_ptr.h"
#include "base/posix/eintr_wrapper.h"
#include "base/single_thread_task_runner.h"
#include "base/stl_util.h"
#include "base/synchronization/lock.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "base/threading/thread.h"
#include "base/trace_event/trace_event.h"

namespace base {

namespace {

class FilePathWatcherImpl;

// Singleton to manage all inotify watches.
// TODO(tony): It would be nice if this wasn't a singleton.
// http://crbug.com/38174
class InotifyReader {
 public:
  typedef int Watch;  // Watch descriptor used by AddWatch and RemoveWatch.
  static const Watch kInvalidWatch = -1;

  // Watch directory |path| for changes. |watcher| will be notified on each
  // change. Returns kInvalidWatch on failure.
  Watch AddWatch(const FilePath& path, FilePathWatcherImpl* watcher);

  // Remove |watch| if it's valid.
  void RemoveWatch(Watch watch, FilePathWatcherImpl* watcher);

  // Callback for InotifyReaderTask.
  void OnInotifyEvent(const inotify_event* event);

 private:
  friend struct LazyInstanceTraitsBase<InotifyReader>;

  typedef std::set<FilePathWatcherImpl*> WatcherSet;

  InotifyReader();
  // There is no destructor because |g_inotify_reader| is a
  // base::LazyInstace::Leaky object. Having a destructor causes build
  // issues with GCC 6 (http://crbug.com/636346).

  // We keep track of which delegates want to be notified on which watches.
  hash_map<Watch, WatcherSet> watchers_;

  // Lock to protect watchers_.
  Lock lock_;

  // Separate thread on which we run blocking read for inotify events.
  Thread thread_;

  // File descriptor returned by inotify_init.
  const int inotify_fd_;

  // Flag set to true when startup was successful.
  bool valid_;

  DISALLOW_COPY_AND_ASSIGN(InotifyReader);
};

class FilePathWatcherImpl : public FilePathWatcher::PlatformDelegate {
 public:
  FilePathWatcherImpl();
  ~FilePathWatcherImpl() override;

  // Called for each event coming from the watch. |fired_watch| identifies the
  // watch that fired, |child| indicates what has changed, and is relative to
  // the currently watched path for |fired_watch|.
  //
  // |created| is true if the object appears.
  // |deleted| is true if the object disappears.
  // |is_dir| is true if the object is a directory.
  void OnFilePathChanged(InotifyReader::Watch fired_watch,
                         const FilePath::StringType& child,
                         bool created,
                         bool deleted,
                         bool is_dir);

 private:
  void OnFilePathChangedOnOriginSequence(InotifyReader::Watch fired_watch,
                                         const FilePath::StringType& child,
                                         bool created,
                                         bool deleted,
                                         bool is_dir);

  // Start watching |path| for changes and notify |delegate| on each change.
  // Returns true if watch for |path| has been added successfully.
  bool Watch(const FilePath& path,
             bool recursive,
             const FilePathWatcher::Callback& callback) override;

  // Cancel the watch. This unregisters the instance with InotifyReader.
  void Cancel() override;

  // Inotify watches are installed for all directory components of |target_|.
  // A WatchEntry instance holds:
  // - |watch|: the watch descriptor for a component.
  // - |subdir|: the subdirectory that identifies the next component.
  //   - For the last component, there is no next component, so it is empty.
  // - |linkname|: the target of the symlink.
  //   - Only if the target being watched is a symbolic link.
  struct WatchEntry {
    explicit WatchEntry(const FilePath::StringType& dirname)
        : watch(InotifyReader::kInvalidWatch),
          subdir(dirname) {}

    InotifyReader::Watch watch;
    FilePath::StringType subdir;
    FilePath::StringType linkname;
  };
  typedef std::vector<WatchEntry> WatchVector;

  // Reconfigure to watch for the most specific parent directory of |target_|
  // that exists. Also calls UpdateRecursiveWatches() below.
  void UpdateWatches();

  // Reconfigure to recursively watch |target_| and all its sub-directories.
  // - This is a no-op if the watch is not recursive.
  // - If |target_| does not exist, then clear all the recursive watches.
  // - Assuming |target_| exists, passing kInvalidWatch as |fired_watch| forces
  //   addition of recursive watches for |target_|.
  // - Otherwise, only the directory associated with |fired_watch| and its
  //   sub-directories will be reconfigured.
  void UpdateRecursiveWatches(InotifyReader::Watch fired_watch, bool is_dir);

  // Enumerate recursively through |path| and add / update watches.
  void UpdateRecursiveWatchesForPath(const FilePath& path);

  // Do internal bookkeeping to update mappings between |watch| and its
  // associated full path |path|.
  void TrackWatchForRecursion(InotifyReader::Watch watch, const FilePath& path);

  // Remove all the recursive watches.
  void RemoveRecursiveWatches();

  // |path| is a symlink to a non-existent target. Attempt to add a watch to
  // the link target's parent directory. Update |watch_entry| on success.
  void AddWatchForBrokenSymlink(const FilePath& path, WatchEntry* watch_entry);

  bool HasValidWatchVector() const;

  // Callback to notify upon changes.
  FilePathWatcher::Callback callback_;

  // The file or directory we're supposed to watch.
  FilePath target_;

  bool recursive_;

  // The vector of watches and next component names for all path components,
  // starting at the root directory. The last entry corresponds to the watch for
  // |target_| and always stores an empty next component name in |subdir|.
  WatchVector watches_;

  hash_map<InotifyReader::Watch, FilePath> recursive_paths_by_watch_;
  std::map<FilePath, InotifyReader::Watch> recursive_watches_by_path_;

  WeakPtrFactory<FilePathWatcherImpl> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(FilePathWatcherImpl);
};

void InotifyReaderCallback(InotifyReader* reader, int inotify_fd) {
  // Make sure the file descriptors are good for use with select().
  CHECK_LE(0, inotify_fd);
  CHECK_GT(FD_SETSIZE, inotify_fd);

  trace_event::TraceLog::GetInstance()->SetCurrentThreadBlocksMessageLoop();

  while (true) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(inotify_fd, &rfds);

    // Wait until some inotify events are available.
    int select_result =
      HANDLE_EINTR(select(inotify_fd + 1, &rfds, NULL, NULL, NULL));
    if (select_result < 0) {
      DPLOG(WARNING) << "select failed";
      return;
    }

    // Adjust buffer size to current event queue size.
    int buffer_size;
    int ioctl_result = HANDLE_EINTR(ioctl(inotify_fd, FIONREAD,
                                          &buffer_size));

    if (ioctl_result != 0) {
      DPLOG(WARNING) << "ioctl failed";
      return;
    }

    std::vector<char> buffer(buffer_size);

    ssize_t bytes_read = HANDLE_EINTR(read(inotify_fd, &buffer[0],
                                           buffer_size));

    if (bytes_read < 0) {
      DPLOG(WARNING) << "read from inotify fd failed";
      return;
    }

    ssize_t i = 0;
    while (i < bytes_read) {
      inotify_event* event = reinterpret_cast<inotify_event*>(&buffer[i]);
      size_t event_size = sizeof(inotify_event) + event->len;
      DCHECK(i + event_size <= static_cast<size_t>(bytes_read));
      reader->OnInotifyEvent(event);
      i += event_size;
    }
  }
}

static LazyInstance<InotifyReader>::Leaky g_inotify_reader =
    LAZY_INSTANCE_INITIALIZER;

InotifyReader::InotifyReader()
    : thread_("inotify_reader"),
      inotify_fd_(inotify_init()),
      valid_(false) {
  if (inotify_fd_ < 0)
    PLOG(ERROR) << "inotify_init() failed";

  if (inotify_fd_ >= 0 && thread_.Start()) {
    thread_.task_runner()->PostTask(
        FROM_HERE,
        Bind(&InotifyReaderCallback, this, inotify_fd_));
    valid_ = true;
  }
}

InotifyReader::Watch InotifyReader::AddWatch(
    const FilePath& path, FilePathWatcherImpl* watcher) {
  if (!valid_)
    return kInvalidWatch;

  AutoLock auto_lock(lock_);

  Watch watch = inotify_add_watch(inotify_fd_, path.value().c_str(),
                                  IN_ATTRIB | IN_CREATE | IN_DELETE |
                                  IN_CLOSE_WRITE | IN_MOVE |
                                  IN_ONLYDIR);

  if (watch == kInvalidWatch)
    return kInvalidWatch;

  watchers_[watch].insert(watcher);

  return watch;
}

void InotifyReader::RemoveWatch(Watch watch, FilePathWatcherImpl* watcher) {
  if (!valid_ || (watch == kInvalidWatch))
    return;

  AutoLock auto_lock(lock_);

  watchers_[watch].erase(watcher);

  if (watchers_[watch].empty()) {
    watchers_.erase(watch);
    inotify_rm_watch(inotify_fd_, watch);
  }
}

void InotifyReader::OnInotifyEvent(const inotify_event* event) {
  if (event->mask & IN_IGNORED)
    return;

  FilePath::StringType child(event->len ? event->name : FILE_PATH_LITERAL(""));
  AutoLock auto_lock(lock_);

  for (WatcherSet::iterator watcher = watchers_[event->wd].begin();
       watcher != watchers_[event->wd].end();
       ++watcher) {
    (*watcher)->OnFilePathChanged(event->wd,
                                  child,
                                  event->mask & (IN_CREATE | IN_MOVED_TO),
                                  event->mask & (IN_DELETE | IN_MOVED_FROM),
                                  event->mask & IN_ISDIR);
  }
}

FilePathWatcherImpl::FilePathWatcherImpl()
    : recursive_(false), weak_factory_(this) {}

FilePathWatcherImpl::~FilePathWatcherImpl() {
  DCHECK(!task_runner() || task_runner()->RunsTasksOnCurrentThread());
}

void FilePathWatcherImpl::OnFilePathChanged(InotifyReader::Watch fired_watch,
                                            const FilePath::StringType& child,
                                            bool created,
                                            bool deleted,
                                            bool is_dir) {
  DCHECK(!task_runner()->RunsTasksOnCurrentThread());

  // This method is invoked on the Inotify thread. Switch to task_runner() to
  // access |watches_| safely. Use a WeakPtr to prevent the callback from
  // running after |this| is destroyed (i.e. after the watch is cancelled).
  task_runner()->PostTask(
      FROM_HERE, Bind(&FilePathWatcherImpl::OnFilePathChangedOnOriginSequence,
                      weak_factory_.GetWeakPtr(), fired_watch, child, created,
                      deleted, is_dir));
}

void FilePathWatcherImpl::OnFilePathChangedOnOriginSequence(
    InotifyReader::Watch fired_watch,
    const FilePath::StringType& child,
    bool created,
    bool deleted,
    bool is_dir) {
  DCHECK(task_runner()->RunsTasksOnCurrentThread());
  DCHECK(!watches_.empty());
  DCHECK(HasValidWatchVector());

  // Used below to avoid multiple recursive updates.
  bool did_update = false;

  // Find the entry in |watches_| that corresponds to |fired_watch|.
  for (size_t i = 0; i < watches_.size(); ++i) {
    const WatchEntry& watch_entry = watches_[i];
    if (fired_watch != watch_entry.watch)
      continue;

    // Check whether a path component of |target_| changed.
    bool change_on_target_path =
        child.empty() ||
        (child == watch_entry.linkname) ||
        (child == watch_entry.subdir);

    // Check if the change references |target_| or a direct child of |target_|.
    bool target_changed;
    if (watch_entry.subdir.empty()) {
      // The fired watch is for a WatchEntry without a subdir. Thus for a given
      // |target_| = "/path/to/foo", this is for "foo". Here, check either:
      // - the target has no symlink: it is the target and it changed.
      // - the target has a symlink, and it matches |child|.
      target_changed = (watch_entry.linkname.empty() ||
                        child == watch_entry.linkname);
    } else {
      // The fired watch is for a WatchEntry with a subdir. Thus for a given
      // |target_| = "/path/to/foo", this is for {"/", "/path", "/path/to"}.
      // So we can safely access the next WatchEntry since we have not reached
      // the end yet. Check |watch_entry| is for "/path/to", i.e. the next
      // element is "foo".
      bool next_watch_may_be_for_target = watches_[i + 1].subdir.empty();
      if (next_watch_may_be_for_target) {
        // The current |watch_entry| is for "/path/to", so check if the |child|
        // that changed is "foo".
        target_changed = watch_entry.subdir == child;
      } else {
        // The current |watch_entry| is not for "/path/to", so the next entry
        // cannot be "foo". Thus |target_| has not changed.
        target_changed = false;
      }
    }

    // Update watches if a directory component of the |target_| path
    // (dis)appears. Note that we don't add the additional restriction of
    // checking the event mask to see if it is for a directory here as changes
    // to symlinks on the target path will not have IN_ISDIR set in the event
    // masks. As a result we may sometimes call UpdateWatches() unnecessarily.
    if (change_on_target_path && (created || deleted) && !did_update) {
      UpdateWatches();
      did_update = true;
    }

    // Report the following events:
    //  - The target or a direct child of the target got changed (in case the
    //    watched path refers to a directory).
    //  - One of the parent directories got moved or deleted, since the target
    //    disappears in this case.
    //  - One of the parent directories appears. The event corresponding to
    //    the target appearing might have been missed in this case, so recheck.
    if (target_changed ||
        (change_on_target_path && deleted) ||
        (change_on_target_path && created && PathExists(target_))) {
      if (!did_update) {
        UpdateRecursiveWatches(fired_watch, is_dir);
        did_update = true;
      }
      callback_.Run(target_, false /* error */);
      return;
    }
  }

  if (ContainsKey(recursive_paths_by_watch_, fired_watch)) {
    if (!did_update)
      UpdateRecursiveWatches(fired_watch, is_dir);
    callback_.Run(target_, false /* error */);
  }
}

bool FilePathWatcherImpl::Watch(const FilePath& path,
                                bool recursive,
                                const FilePathWatcher::Callback& callback) {
  DCHECK(target_.empty());

  set_task_runner(SequencedTaskRunnerHandle::Get());
  callback_ = callback;
  target_ = path;
  recursive_ = recursive;

  std::vector<FilePath::StringType> comps;
  target_.GetComponents(&comps);
  DCHECK(!comps.empty());
  for (size_t i = 1; i < comps.size(); ++i)
    watches_.push_back(WatchEntry(comps[i]));
  watches_.push_back(WatchEntry(FilePath::StringType()));
  UpdateWatches();
  return true;
}

void FilePathWatcherImpl::Cancel() {
  if (!callback_) {
    // Watch() was never called.
    set_cancelled();
    return;
  }

  DCHECK(task_runner()->RunsTasksOnCurrentThread());
  DCHECK(!is_cancelled());

  set_cancelled();
  callback_.Reset();

  for (size_t i = 0; i < watches_.size(); ++i)
    g_inotify_reader.Get().RemoveWatch(watches_[i].watch, this);
  watches_.clear();
  target_.clear();
  RemoveRecursiveWatches();
}

void FilePathWatcherImpl::UpdateWatches() {
  // Ensure this runs on the task_runner() exclusively in order to avoid
  // concurrency issues.
  DCHECK(task_runner()->RunsTasksOnCurrentThread());
  DCHECK(HasValidWatchVector());

  // Walk the list of watches and update them as we go.
  FilePath path(FILE_PATH_LITERAL("/"));
  for (size_t i = 0; i < watches_.size(); ++i) {
    WatchEntry& watch_entry = watches_[i];
    InotifyReader::Watch old_watch = watch_entry.watch;
    watch_entry.watch = InotifyReader::kInvalidWatch;
    watch_entry.linkname.clear();
    watch_entry.watch = g_inotify_reader.Get().AddWatch(path, this);
    if (watch_entry.watch == InotifyReader::kInvalidWatch) {
      // Ignore the error code (beyond symlink handling) to attempt to add
      // watches on accessible children of unreadable directories. Note that
      // this is a best-effort attempt; we may not catch events in this
      // scenario.
      if (IsLink(path))
        AddWatchForBrokenSymlink(path, &watch_entry);
    }
    if (old_watch != watch_entry.watch)
      g_inotify_reader.Get().RemoveWatch(old_watch, this);
    path = path.Append(watch_entry.subdir);
  }

  UpdateRecursiveWatches(InotifyReader::kInvalidWatch,
                         false /* is directory? */);
}

void FilePathWatcherImpl::UpdateRecursiveWatches(
    InotifyReader::Watch fired_watch,
    bool is_dir) {
  DCHECK(HasValidWatchVector());

  if (!recursive_)
    return;

  if (!DirectoryExists(target_)) {
    RemoveRecursiveWatches();
    return;
  }

  // Check to see if this is a forced update or if some component of |target_|
  // has changed. For these cases, redo the watches for |target_| and below.
  if (!ContainsKey(recursive_paths_by_watch_, fired_watch) &&
      fired_watch != watches_.back().watch) {
    UpdateRecursiveWatchesForPath(target_);
    return;
  }

  // Underneath |target_|, only directory changes trigger watch updates.
  if (!is_dir)
    return;

  const FilePath& changed_dir =
      ContainsKey(recursive_paths_by_watch_, fired_watch) ?
      recursive_paths_by_watch_[fired_watch] :
      target_;

  std::map<FilePath, InotifyReader::Watch>::iterator start_it =
      recursive_watches_by_path_.lower_bound(changed_dir);
  std::map<FilePath, InotifyReader::Watch>::iterator end_it = start_it;
  for (; end_it != recursive_watches_by_path_.end(); ++end_it) {
    const FilePath& cur_path = end_it->first;
    if (!changed_dir.IsParent(cur_path))
      break;
    if (!DirectoryExists(cur_path))
      g_inotify_reader.Get().RemoveWatch(end_it->second, this);
  }
  recursive_watches_by_path_.erase(start_it, end_it);
  UpdateRecursiveWatchesForPath(changed_dir);
}

void FilePathWatcherImpl::UpdateRecursiveWatchesForPath(const FilePath& path) {
  DCHECK(recursive_);
  DCHECK(!path.empty());
  DCHECK(DirectoryExists(path));

  // Note: SHOW_SYM_LINKS exposes symlinks as symlinks, so they are ignored
  // rather than followed. Following symlinks can easily lead to the undesirable
  // situation where the entire file system is being watched.
  FileEnumerator enumerator(
      path,
      true /* recursive enumeration */,
      FileEnumerator::DIRECTORIES | FileEnumerator::SHOW_SYM_LINKS);
  for (FilePath current = enumerator.Next();
       !current.empty();
       current = enumerator.Next()) {
    DCHECK(enumerator.GetInfo().IsDirectory());

    if (!ContainsKey(recursive_watches_by_path_, current)) {
      // Add new watches.
      InotifyReader::Watch watch =
          g_inotify_reader.Get().AddWatch(current, this);
      TrackWatchForRecursion(watch, current);
    } else {
      // Update existing watches.
      InotifyReader::Watch old_watch = recursive_watches_by_path_[current];
      DCHECK_NE(InotifyReader::kInvalidWatch, old_watch);
      InotifyReader::Watch watch =
          g_inotify_reader.Get().AddWatch(current, this);
      if (watch != old_watch) {
        g_inotify_reader.Get().RemoveWatch(old_watch, this);
        recursive_paths_by_watch_.erase(old_watch);
        recursive_watches_by_path_.erase(current);
        TrackWatchForRecursion(watch, current);
      }
    }
  }
}

void FilePathWatcherImpl::TrackWatchForRecursion(InotifyReader::Watch watch,
                                                 const FilePath& path) {
  DCHECK(recursive_);
  DCHECK(!path.empty());
  DCHECK(target_.IsParent(path));

  if (watch == InotifyReader::kInvalidWatch)
    return;

  DCHECK(!ContainsKey(recursive_paths_by_watch_, watch));
  DCHECK(!ContainsKey(recursive_watches_by_path_, path));
  recursive_paths_by_watch_[watch] = path;
  recursive_watches_by_path_[path] = watch;
}

void FilePathWatcherImpl::RemoveRecursiveWatches() {
  if (!recursive_)
    return;

  for (hash_map<InotifyReader::Watch, FilePath>::const_iterator it =
           recursive_paths_by_watch_.begin();
       it != recursive_paths_by_watch_.end();
       ++it) {
    g_inotify_reader.Get().RemoveWatch(it->first, this);
  }
  recursive_paths_by_watch_.clear();
  recursive_watches_by_path_.clear();
}

void FilePathWatcherImpl::AddWatchForBrokenSymlink(const FilePath& path,
                                                   WatchEntry* watch_entry) {
  DCHECK_EQ(InotifyReader::kInvalidWatch, watch_entry->watch);
  FilePath link;
  if (!ReadSymbolicLink(path, &link))
    return;

  if (!link.IsAbsolute())
    link = path.DirName().Append(link);

  // Try watching symlink target directory. If the link target is "/", then we
  // shouldn't get here in normal situations and if we do, we'd watch "/" for
  // changes to a component "/" which is harmless so no special treatment of
  // this case is required.
  InotifyReader::Watch watch =
      g_inotify_reader.Get().AddWatch(link.DirName(), this);
  if (watch == InotifyReader::kInvalidWatch) {
    // TODO(craig) Symlinks only work if the parent directory for the target
    // exist. Ideally we should make sure we've watched all the components of
    // the symlink path for changes. See crbug.com/91561 for details.
    DPLOG(WARNING) << "Watch failed for "  << link.DirName().value();
    return;
  }
  watch_entry->watch = watch;
  watch_entry->linkname = link.BaseName().value();
}

bool FilePathWatcherImpl::HasValidWatchVector() const {
  if (watches_.empty())
    return false;
  for (size_t i = 0; i < watches_.size() - 1; ++i) {
    if (watches_[i].subdir.empty())
      return false;
  }
  return watches_.back().subdir.empty();
}

}  // namespace

FilePathWatcher::FilePathWatcher() {
  sequence_checker_.DetachFromSequence();
  impl_ = MakeUnique<FilePathWatcherImpl>();
}

}  // namespace base
