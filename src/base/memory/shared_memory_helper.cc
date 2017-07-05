// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/shared_memory_helper.h"

#if defined(OS_CHROMEOS)
#include <sys/resource.h>
#include <sys/time.h>

#include "base/debug/alias.h"
#endif  // defined(OS_CHROMEOS)

#include "base/threading/thread_restrictions.h"

namespace base {

struct ScopedPathUnlinkerTraits {
  static const FilePath* InvalidValue() { return nullptr; }

  static void Free(const FilePath* path) {
    if (unlink(path->value().c_str()))
      PLOG(WARNING) << "unlink";
  }
};

// Unlinks the FilePath when the object is destroyed.
using ScopedPathUnlinker =
    ScopedGeneric<const FilePath*, ScopedPathUnlinkerTraits>;

#if !defined(OS_ANDROID)
bool CreateAnonymousSharedMemory(const SharedMemoryCreateOptions& options,
                                 ScopedFILE* fp,
                                 ScopedFD* readonly_fd,
                                 FilePath* path) {
#if !(defined(OS_MACOSX) && !defined(OS_IOS)) && !defined(OS_FUCHSIA)
  // It doesn't make sense to have a open-existing private piece of shmem
  DCHECK(!options.open_existing_deprecated);
#endif  // !(defined(OS_MACOSX) && !defined(OS_IOS)
  // Q: Why not use the shm_open() etc. APIs?
  // A: Because they're limited to 4mb on OS X.  FFFFFFFUUUUUUUUUUU
  FilePath directory;
  ScopedPathUnlinker path_unlinker;
  if (!GetShmemTempDir(options.executable, &directory))
    return false;

  fp->reset(base::CreateAndOpenTemporaryFileInDir(directory, path));

  if (!*fp)
    return false;

  // Deleting the file prevents anyone else from mapping it in (making it
  // private), and prevents the need for cleanup (once the last fd is
  // closed, it is truly freed).
  path_unlinker.reset(path);

  if (options.share_read_only) {
    // Also open as readonly so that we can GetReadOnlyHandle.
    readonly_fd->reset(HANDLE_EINTR(open(path->value().c_str(), O_RDONLY)));
    if (!readonly_fd->is_valid()) {
      DPLOG(ERROR) << "open(\"" << path->value() << "\", O_RDONLY) failed";
      fp->reset();
      return false;
    }
  }
  return true;
}

bool PrepareMapFile(ScopedFILE fp,
                    ScopedFD readonly_fd,
                    int* mapped_file,
                    int* readonly_mapped_file) {
  DCHECK_EQ(-1, *mapped_file);
  DCHECK_EQ(-1, *readonly_mapped_file);
  if (fp == NULL)
    return false;

  // This function theoretically can block on the disk, but realistically
  // the temporary files we create will just go into the buffer cache
  // and be deleted before they ever make it out to disk.
  base::ThreadRestrictions::ScopedAllowIO allow_io;

  if (readonly_fd.is_valid()) {
    struct stat st = {};
    if (fstat(fileno(fp.get()), &st))
      NOTREACHED();

    struct stat readonly_st = {};
    if (fstat(readonly_fd.get(), &readonly_st))
      NOTREACHED();
    if (st.st_dev != readonly_st.st_dev || st.st_ino != readonly_st.st_ino) {
      LOG(ERROR) << "writable and read-only inodes don't match; bailing";
      return false;
    }
  }

  *mapped_file = HANDLE_EINTR(dup(fileno(fp.get())));
  if (*mapped_file == -1) {
    NOTREACHED() << "Call to dup failed, errno=" << errno;

#if defined(OS_CHROMEOS)
    if (errno == EMFILE) {
      // We're out of file descriptors and are probably about to crash somewhere
      // else in Chrome anyway. Let's collect what FD information we can and
      // crash.
      // Added for debugging crbug.com/733718
      int original_fd_limit = 16384;
      struct rlimit rlim;
      if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        original_fd_limit = rlim.rlim_cur;
        if (rlim.rlim_max > rlim.rlim_cur) {
          // Increase fd limit so breakpad has a chance to write a minidump.
          rlim.rlim_cur = rlim.rlim_max;
          if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
            PLOG(ERROR) << "setrlimit() failed";
          }
        }
      } else {
        PLOG(ERROR) << "getrlimit() failed";
      }

      const char kFileDataMarker[] = "FDATA";
      char buf[PATH_MAX];
      char fd_path[PATH_MAX];
      char crash_buffer[32 * 1024] = {0};
      char* crash_ptr = crash_buffer;
      base::debug::Alias(crash_buffer);

      // Put a marker at the start of our data so we can confirm where it
      // begins.
      crash_ptr = strncpy(crash_ptr, kFileDataMarker, strlen(kFileDataMarker));
      for (int i = original_fd_limit; i >= 0; --i) {
        memset(buf, 0, arraysize(buf));
        memset(fd_path, 0, arraysize(fd_path));
        snprintf(fd_path, arraysize(fd_path) - 1, "/proc/self/fd/%d", i);
        ssize_t count = readlink(fd_path, buf, arraysize(buf) - 1);
        if (count < 0) {
          PLOG(ERROR) << "readlink failed for: " << fd_path;
          continue;
        }

        if (crash_ptr + count + 1 < crash_buffer + arraysize(crash_buffer)) {
          crash_ptr = strncpy(crash_ptr, buf, count + 1);
        }
        LOG(ERROR) << i << ": " << buf;
      }
      LOG(FATAL) << "Logged for file descriptor exhaustion, crashing now";
    }
#endif  // defined(OS_CHROMEOS)
  }
  *readonly_mapped_file = readonly_fd.release();

  return true;
}
#endif  // !defined(OS_ANDROID)

}  // namespace base
