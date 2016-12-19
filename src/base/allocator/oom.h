// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_ALLOCATOR_OOM_H
#define BASE_ALLOCATOR_OOM_H

#include "base/logging.h"

#if defined(OS_WIN)
#include <windows.h>
#endif

// OOM_CRASH() - Specialization of IMMEDIATE_CRASH which will raise a custom
// exception on Windows to signal this is OOM and not a normal assert.
#if defined(OS_WIN)
#define OOM_CRASH()                                                     \
  do {                                                                  \
    ::RaiseException(0xE0000008, EXCEPTION_NONCONTINUABLE, 0, nullptr); \
    IMMEDIATE_CRASH();                                                  \
  } while (0)
#else
#define OOM_CRASH() IMMEDIATE_CRASH()
#endif

#endif  // BASE_ALLOCATOR_OOM_H
