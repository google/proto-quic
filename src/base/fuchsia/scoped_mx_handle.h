// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_FUCHSIA_SCOPED_MX_HANDLE_H_
#define BASE_FUCHSIA_SCOPED_MX_HANDLE_H_

#include <magenta/status.h>
#include <magenta/syscalls.h>

#include "base/logging.h"
#include "base/scoped_generic.h"

namespace base {

namespace internal {

struct ScopedMxHandleTraits {
  static mx_handle_t InvalidValue() { return MX_HANDLE_INVALID; }
  static void Free(mx_handle_t object) {
    mx_status_t status = mx_handle_close(object);
    CHECK_EQ(MX_OK, status) << mx_status_get_string(status);
  }
};

}  // namespace internal

using ScopedMxHandle =
    ScopedGeneric<mx_handle_t, internal::ScopedMxHandleTraits>;

}  // namespace base

#endif  // BASE_FUCHSIA_SCOPED_MX_HANDLE_H_
