// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// scoped_ptr is just a type alias for std::unique_ptr. Mass conversion coming
// soon (stay tuned for the PSA!), but until then, please continue using
// scoped_ptr.

#ifndef BASE_MEMORY_SCOPED_PTR_H_
#define BASE_MEMORY_SCOPED_PTR_H_

#include <memory>

// TODO(dcheng): Temporary, to facilitate transition off scoped_ptr.
#include "base/memory/ptr_util.h"

template <typename T, typename D = std::default_delete<T>>
using scoped_ptr = std::unique_ptr<T, D>;

#endif  // BASE_MEMORY_SCOPED_PTR_H_
