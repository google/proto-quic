// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/threading/non_thread_safe.h"

#include <memory>

#include "base/logging.h"
#include "base/macros.h"
#include "base/test/gtest_util.h"
#include "base/threading/simple_thread.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

namespace {

// Simple class to exersice the basics of NonThreadSafe.
// Both the destructor and DoStuff should verify that they were
// called on the same thread as the constructor.
class NonThreadSafeClass : public NonThreadSafe {
 public:
  NonThreadSafeClass() {}

  // Verifies that it was called on the same thread as the constructor.
  void DoStuff() {
    DCHECK(CalledOnValidThread());
  }

  void DetachFromThread() {
    NonThreadSafe::DetachFromThread();
  }

  static void MethodOnDifferentThreadImpl();
  static void DestructorOnDifferentThreadImpl();

 private:
  DISALLOW_COPY_AND_ASSIGN(NonThreadSafeClass);
};

// Calls NonThreadSafeClass::DoStuff on another thread.
class CallDoStuffOnThread : public SimpleThread {
 public:
  explicit CallDoStuffOnThread(NonThreadSafeClass* non_thread_safe_class)
      : SimpleThread("call_do_stuff_on_thread"),
        non_thread_safe_class_(non_thread_safe_class) {
  }

  void Run() override { non_thread_safe_class_->DoStuff(); }

 private:
  NonThreadSafeClass* non_thread_safe_class_;

  DISALLOW_COPY_AND_ASSIGN(CallDoStuffOnThread);
};

// Deletes NonThreadSafeClass on a different thread.
class DeleteNonThreadSafeClassOnThread : public SimpleThread {
 public:
  explicit DeleteNonThreadSafeClassOnThread(
      NonThreadSafeClass* non_thread_safe_class)
      : SimpleThread("delete_non_thread_safe_class_on_thread"),
        non_thread_safe_class_(non_thread_safe_class) {
  }

  void Run() override { non_thread_safe_class_.reset(); }

 private:
  std::unique_ptr<NonThreadSafeClass> non_thread_safe_class_;

  DISALLOW_COPY_AND_ASSIGN(DeleteNonThreadSafeClassOnThread);
};

}  // namespace

TEST(NonThreadSafeTest, CallsAllowedOnSameThread) {
  std::unique_ptr<NonThreadSafeClass> non_thread_safe_class(
      new NonThreadSafeClass);

  // Verify that DoStuff doesn't assert.
  non_thread_safe_class->DoStuff();

  // Verify that the destructor doesn't assert.
  non_thread_safe_class.reset();
}

TEST(NonThreadSafeTest, DetachThenDestructOnDifferentThread) {
  std::unique_ptr<NonThreadSafeClass> non_thread_safe_class(
      new NonThreadSafeClass);

  // Verify that the destructor doesn't assert when called on a different thread
  // after a detach.
  non_thread_safe_class->DetachFromThread();
  DeleteNonThreadSafeClassOnThread delete_on_thread(
      non_thread_safe_class.release());

  delete_on_thread.Start();
  delete_on_thread.Join();
}

void NonThreadSafeClass::MethodOnDifferentThreadImpl() {
  std::unique_ptr<NonThreadSafeClass> non_thread_safe_class(
      new NonThreadSafeClass);

  // Verify that DoStuff asserts in debug builds only when called
  // on a different thread.
  CallDoStuffOnThread call_on_thread(non_thread_safe_class.get());

  call_on_thread.Start();
  call_on_thread.Join();
}

#if DCHECK_IS_ON()
TEST(NonThreadSafeDeathTest, MethodNotAllowedOnDifferentThreadInDebug) {
  ::testing::FLAGS_gtest_death_test_style = "threadsafe";
  ASSERT_DCHECK_DEATH({ NonThreadSafeClass::MethodOnDifferentThreadImpl(); });
}
#else
TEST(NonThreadSafeTest, MethodAllowedOnDifferentThreadInRelease) {
  NonThreadSafeClass::MethodOnDifferentThreadImpl();
}
#endif  // DCHECK_IS_ON()

void NonThreadSafeClass::DestructorOnDifferentThreadImpl() {
  std::unique_ptr<NonThreadSafeClass> non_thread_safe_class(
      new NonThreadSafeClass);

  // Verify that the destructor asserts in debug builds only
  // when called on a different thread.
  DeleteNonThreadSafeClassOnThread delete_on_thread(
      non_thread_safe_class.release());

  delete_on_thread.Start();
  delete_on_thread.Join();
}

#if DCHECK_IS_ON()
TEST(NonThreadSafeDeathTest, DestructorNotAllowedOnDifferentThreadInDebug) {
  ::testing::FLAGS_gtest_death_test_style = "threadsafe";
  ASSERT_DCHECK_DEATH(
      { NonThreadSafeClass::DestructorOnDifferentThreadImpl(); });
}
#else
TEST(NonThreadSafeTest, DestructorAllowedOnDifferentThreadInRelease) {
  NonThreadSafeClass::DestructorOnDifferentThreadImpl();
}
#endif  // DCHECK_IS_ON()

}  // namespace base
