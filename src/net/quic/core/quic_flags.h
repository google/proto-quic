// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_QUIC_FLAGS_H_
#define NET_QUIC_CORE_QUIC_FLAGS_H_

#include <cstdint>
#include <string>

#include "net/quic/platform/api/quic_export.h"

#define QUIC_FLAG(type, flag, value) QUIC_EXPORT_PRIVATE extern type flag;
#include "net/quic/core/quic_flags_list.h"
#undef QUIC_FLAG

// API compatibility with new-style flags.
namespace base {

inline bool GetFlag(bool flag) {
  return flag;
}
inline int32_t GetFlag(int32_t flag) {
  return flag;
}
inline int64_t GetFlag(int64_t flag) {
  return flag;
}
inline uint64_t GetFlag(uint64_t flag) {
  return flag;
}
inline double GetFlag(double flag) {
  return flag;
}
inline std::string GetFlag(const std::string& flag) {
  return flag;
}

inline void SetFlag(bool* f, bool v) {
  *f = v;
}
inline void SetFlag(int32_t* f, int32_t v) {
  *f = v;
}
inline void SetFlag(int64_t* f, int64_t v) {
  *f = v;
}
inline void SetFlag(uint64_t* f, uint64_t v) {
  *f = v;
}
inline void SetFlag(double* f, double v) {
  *f = v;
}
inline void SetFlag(std::string* f, const std::string& v) {
  *f = v;
}

}  // namespace base

#endif  // NET_QUIC_CORE_QUIC_FLAGS_H_
