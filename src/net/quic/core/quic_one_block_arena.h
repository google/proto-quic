// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// An arena that consists of a single inlined block of |ArenaSize|. Useful to
// avoid repeated calls to malloc/new and to improve memory locality. DCHECK's
// if an allocation out of the arena ever fails in debug builds; falls back to
// heap allocation in release builds.

#ifndef NET_QUIC_CORE_QUIC_ONE_BLOCK_ARENA_H_
#define NET_QUIC_CORE_QUIC_ONE_BLOCK_ARENA_H_

#include <cstdint>

#include "net/quic/core/quic_arena_scoped_ptr.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/platform/api/quic_bug_tracker.h"

#define PREDICT_FALSE(x) x

namespace net {

template <uint32_t ArenaSize>
class QuicOneBlockArena {
  static const uint32_t kMaxAlign = 8;

 public:
  QuicOneBlockArena();

  // Instantiates an object of type |T| with |args|. |args| are perfectly
  // forwarded to |T|'s constructor. The returned pointer's lifetime is
  // controlled by QuicArenaScopedPtr.
  template <typename T, typename... Args>
  QuicArenaScopedPtr<T> New(Args&&... args);

 private:
  // Returns the size of |T| aligned up to |kMaxAlign|.
  template <typename T>
  static inline uint32_t AlignedSize() {
    return ((sizeof(T) + (kMaxAlign - 1)) / kMaxAlign) * kMaxAlign;
  }

  // Actual storage.
  // Subtle/annoying: the value '8' must be coded explicitly into the alignment
  // declaration for MSVC.
  QUIC_ALIGNED(8) char storage_[ArenaSize];
  // Current offset into the storage.
  uint32_t offset_;

  DISALLOW_COPY_AND_ASSIGN(QuicOneBlockArena);
};

template <uint32_t ArenaSize>
QuicOneBlockArena<ArenaSize>::QuicOneBlockArena() : offset_(0) {}

template <uint32_t ArenaSize>
template <typename T, typename... Args>
QuicArenaScopedPtr<T> QuicOneBlockArena<ArenaSize>::New(Args&&... args) {
  DCHECK_LT(AlignedSize<T>(), ArenaSize)
      << "Object is too large for the arena.";
  static_assert(QUIC_ALIGN_OF(T) > 1,
                "Objects added to the arena must be at least 2B aligned.");
  if (PREDICT_FALSE(offset_ > ArenaSize - AlignedSize<T>())) {
    QUIC_BUG << "Ran out of space in QuicOneBlockArena at " << this
             << ", max size was " << ArenaSize << ", failing request was "
             << AlignedSize<T>() << ", end of arena was " << offset_;
    return QuicArenaScopedPtr<T>(new T(std::forward<Args>(args)...));
  }

  void* buf = &storage_[offset_];
  new (buf) T(std::forward<Args>(args)...);
  offset_ += AlignedSize<T>();
  return QuicArenaScopedPtr<T>(buf,
                               QuicArenaScopedPtr<T>::ConstructFrom::kArena);
}

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_ONE_BLOCK_ARENA_H_
