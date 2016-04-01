// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_MEMORY_PTR_UTIL_H_
#define BASE_MEMORY_PTR_UTIL_H_

#include <memory>

// A function to convert T* into scoped_ptr<T>
// Doing e.g. make_scoped_ptr(new FooBarBaz<type>(arg)) is a shorter notation
// for scoped_ptr<FooBarBaz<type>>(new FooBarBaz<type>(arg))
//
// Why doesn't this just return a scoped_ptr?
//
// make_scoped_ptr is currently being migrated out of scoped_ptr.h, so we can
// globally rename make_scoped_ptr to WrapUnique without breaking the build.
// Doing so without breaking intermediate builds involves several steps:
//
// 1. Move make_scoped_ptr into ptr_util.h and include ptr_util.h from
//    scoped_ptr.h.
// 2. Add an #include for ptr_util.h to every file that references
//    make_scoped_ptr.
// 3. Remove ptr_util.h include from scoped_ptr.h.
// 4. Global rewrite everything.
//
// Unfortunately, step 1 introduces an awkward cycle of dependencies between
// ptr_util.h and scoped_ptr.h To break that cycle, we exploit the fact that
// scoped_ptr is really just a type alias for std::unique_ptr.
template <typename T>
std::unique_ptr<T> make_scoped_ptr(T* ptr) {
  return std::unique_ptr<T>(ptr);
}

namespace base {

// Helper to transfer ownership of a raw pointer to a std::unique_ptr<T>.
// Note that std::unique_ptr<T> has very different semantics from
// std::unique_ptr<T[]>: do not use this helper for array allocations.
template <typename T>
std::unique_ptr<T> WrapUnique(T* ptr) {
  return std::unique_ptr<T>(ptr);
}

}  // namespace base

#endif  // BASE_MEMORY_PTR_UTIL_H_
