// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_ALLOCATOR_ALLOCATOR_SHIM_WIN_H_
#define BASE_ALLOCATOR_ALLOCATOR_SHIM_WIN_H_

#include <stddef.h>

namespace base {
namespace allocator {
// Used to indicate that the shim is actually in place.
extern bool g_is_win_shim_layer_initialized;
}  // namespace allocator
}  // namespace base

#endif  // BASE_ALLOCATOR_ALLOCATOR_SHIM_WIN_H_
