// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This defines helpful methods for dealing with Callbacks.  Because Callbacks
// are implemented using templates, with a class per callback signature, adding
// methods to Callback<> itself is unattractive (lots of extra code gets
// generated).  Instead, consider adding methods here.
//
// ResetAndReturn(&cb) is like cb.Reset() but allows executing a callback (via a
// move or copy) after the original callback is Reset().  This can be handy if
// Run() reads/writes the variable holding the Callback.

#ifndef BASE_CALLBACK_HELPERS_H_
#define BASE_CALLBACK_HELPERS_H_

#include "base/callback.h"
#include "base/compiler_specific.h"
#include "base/macros.h"

namespace base {

template <typename Signature,
          internal::CopyMode copy_mode,
          internal::RepeatMode repeat_mode>
base::Callback<Signature, copy_mode, repeat_mode> ResetAndReturn(
    base::Callback<Signature, copy_mode, repeat_mode>* cb) {
  base::Callback<Signature, copy_mode, repeat_mode> ret(std::move(*cb));
  DCHECK(!*cb);
  return ret;
}

// ScopedClosureRunner is akin to std::unique_ptr<> for Closures. It ensures
// that the Closure is executed no matter how the current scope exits.
class BASE_EXPORT ScopedClosureRunner {
 public:
  ScopedClosureRunner();
  explicit ScopedClosureRunner(const Closure& closure);
  ~ScopedClosureRunner();

  ScopedClosureRunner(ScopedClosureRunner&& other);

  // Releases the current closure if it's set and replaces it with the closure
  // from |other|.
  ScopedClosureRunner& operator=(ScopedClosureRunner&& other);

  // Calls the current closure and resets it, so it wont be called again.
  void RunAndReset();

  // Replaces closure with the new one releasing the old one without calling it.
  void ReplaceClosure(const Closure& closure);

  // Releases the Closure without calling.
  Closure Release() WARN_UNUSED_RESULT;

 private:
  Closure closure_;

  DISALLOW_COPY_AND_ASSIGN(ScopedClosureRunner);
};

}  // namespace base

#endif  // BASE_CALLBACK_HELPERS_H_
