// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DISK_CACHE_BLOCKFILE_STRESS_SUPPORT_H_
#define NET_DISK_CACHE_BLOCKFILE_STRESS_SUPPORT_H_

#include "base/logging.h"

namespace disk_cache {

// Uncomment this line to generate a debug build of stress_cache with checks
// to ensure that we are not producing corrupt entries.
// #define NET_BUILD_STRESS_CACHE 1

// Uncomment this line to direct the in-memory disk cache tracing to the base
// logging system. On Windows this option will enable ETW (Event Tracing for
// Windows) so logs across multiple runs can be collected.
// #define DISK_CACHE_TRACE_TO_LOG 1

// Uncomment this line to perform extended integrity checks during init. It is
// not recommended to enable this option unless some corruption is being tracked
// down.
// #define STRESS_CACHE_EXTENDED_VALIDATION 1

#if defined(NET_BUILD_STRESS_CACHE)
#define STRESS_NOTREACHED() NOTREACHED()
#define STRESS_DCHECK(a) DCHECK(a)
#else
// We don't support streams with these macros, but that's a small price to pay
// to have a straightforward logic here. Please don't add something like
// LogMessageVoidify.
#define STRESS_NOTREACHED() {}
#define STRESS_DCHECK(a) {}
#endif

}  // namespace disk_cache

#endif  // NET_DISK_CACHE_BLOCKFILE_STRESS_SUPPORT_H_
