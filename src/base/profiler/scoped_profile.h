// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.


#ifndef BASE_PROFILER_SCOPED_PROFILE_H_
#define BASE_PROFILER_SCOPED_PROFILE_H_

//------------------------------------------------------------------------------
// ScopedProfile provides basic helper functions for profiling a short
// region of code within a scope.  It is separate from the related ThreadData
// class so that it can be included without much other cruft, and provide the
// macros listed below.

#include "base/base_export.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/profiler/tracked_time.h"
#include "base/trace_event/heap_profiler.h"
#include "base/tracked_objects.h"

// Two level indirection is required for correct macro substitution.
#define PASTE_COUNTER_ON_NAME2(name, counter) name##counter
#define PASTE_COUNTER_ON_NAME(name, counter) \
  PASTE_COUNTER_ON_NAME2(name, counter)

#define COUNTER_BASED_VARIABLE_NAME_FOR_PROFILING \
  PASTE_COUNTER_ON_NAME(some_profiler_variable_, __COUNTER__)

// Defines the containing scope as a profiled region. This allows developers to
// profile their code and see results on their about:profiler page, as well as
// on the UMA dashboard and heap profiler.
#define TRACK_RUN_IN_THIS_SCOPED_REGION(dispatch_function_name)               \
  const ::tracked_objects::Location& location =                               \
      FROM_HERE_WITH_EXPLICIT_FUNCTION(#dispatch_function_name);              \
  TRACE_HEAP_PROFILER_API_SCOPED_TASK_EXECUTION                               \
  COUNTER_BASED_VARIABLE_NAME_FOR_PROFILING(location.file_name());            \
  ::tracked_objects::ScopedProfile COUNTER_BASED_VARIABLE_NAME_FOR_PROFILING( \
      location, ::tracked_objects::ScopedProfile::ENABLED)

// Same as TRACK_RUN_IN_THIS_SCOPED_REGION except that there's an extra param
// which is concatenated with the function name for better filtering.
#define TRACK_SCOPED_REGION(category_name, dispatch_function_name)            \
  const ::tracked_objects::Location& location =                               \
      FROM_HERE_WITH_EXPLICIT_FUNCTION("[" category_name                      \
                                       "]" dispatch_function_name);           \
  TRACE_HEAP_PROFILER_API_SCOPED_TASK_EXECUTION                               \
  COUNTER_BASED_VARIABLE_NAME_FOR_PROFILING(location.file_name());            \
  ::tracked_objects::ScopedProfile COUNTER_BASED_VARIABLE_NAME_FOR_PROFILING( \
      location, ::tracked_objects::ScopedProfile::ENABLED)

namespace tracked_objects {
class Births;

class BASE_EXPORT ScopedProfile {
 public:
  // Mode of operation. Specifies whether ScopedProfile should be a no-op or
  // needs to create and tally a task.
  enum Mode {
    DISABLED,  // Do nothing.
    ENABLED    // Create and tally a task.
  };

  ScopedProfile(const Location& location, Mode mode);
  ~ScopedProfile();

 private:
  Births* birth_;  // Place in code where tracking started.
  TaskStopwatch stopwatch_;

  DISALLOW_COPY_AND_ASSIGN(ScopedProfile);
};

}  // namespace tracked_objects

#endif  // BASE_PROFILER_SCOPED_PROFILE_H_
