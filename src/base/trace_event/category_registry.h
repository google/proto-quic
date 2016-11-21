// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_CATEGORY_H_
#define BASE_TRACE_EVENT_CATEGORY_H_

#include <stddef.h>
#include <stdint.h>

#include "base/base_export.h"
#include "base/logging.h"

namespace base {
namespace trace_event {

struct TraceCategory;
class TraceCategoryTest;
class TraceLog;

// Keeps track of the state of all tracing categories. The reason why this
// is a fully static class with global state is to allow to statically define
// known categories as global linker-initialized structs, without requiring
// static initializers.
class BASE_EXPORT CategoryRegistry {
 public:
  // Allows for-each iterations over a slice of the categories array.
  class Range {
   public:
    Range(TraceCategory* begin, TraceCategory* end) : begin_(begin), end_(end) {
      DCHECK_LE(begin, end);
    }
    TraceCategory* begin() const { return begin_; }
    TraceCategory* end() const { return end_; }

   private:
    TraceCategory* const begin_;
    TraceCategory* const end_;
  };

  // Known categories.
  static TraceCategory* const kCategoryExhausted;
  static TraceCategory* const kCategoryMetadata;
  static TraceCategory* const kCategoryAlreadyShutdown;

  // Returns a category entry from the Category.state_ptr() pointer.
  // TODO(primiano): trace macros should just keep a pointer to the entire
  // TraceCategory, not just the enabled state pointer. That would remove the
  // need for this function and make everything cleaner at no extra cost (as
  // long as the |state_| is the first field of the struct, which can be
  // guaranteed via static_assert, see TraceCategory ctor).
  static const TraceCategory* GetCategoryByStatePtr(
      const uint8_t* category_state);

  static bool IsBuiltinCategory(const TraceCategory*);

 private:
  friend class TraceCategoryTest;
  friend class TraceLog;

  // Only for debugging/testing purposes, is a no-op on release builds.
  static void Initialize();

  // Resets the state of all categories, to clear up the state between tests.
  static void ResetForTesting();

  // The output |category| argument is an undefinitely lived pointer to the
  // TraceCategory owned by the registry. TRACE_EVENTx macros will cache this
  // pointer and use it for checks in their fast-paths.
  // Returns false if the category was already present, true if the category
  // has just been added and hence requires initialization.
  static bool GetOrCreateCategoryByName(const char* category_name,
                                        TraceCategory** category);

  // Allows to iterate over the valid categories in a for-each loop.
  // This includes builtin categories such as __metadata.
  static Range GetAllCategories();
};

}  // namespace trace_event
}  // namespace base

#endif  // BASE_TRACE_EVENT_CATEGORY_H_
