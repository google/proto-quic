// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "sql/test/scoped_error_expecter.h"

#include "base/bind.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace sql {
namespace test {

// static
int ScopedErrorExpecter::SQLiteLibVersionNumber() {
  return sqlite3_libversion_number();
}

ScopedErrorExpecter::ScopedErrorExpecter()
    : checked_(false) {
  callback_ =
      base::Bind(&ScopedErrorExpecter::ErrorSeen, base::Unretained(this));
  Connection::SetErrorExpecter(&callback_);
}

ScopedErrorExpecter::~ScopedErrorExpecter() {
  EXPECT_TRUE(checked_) << " Test must call SawExpectedErrors()";
  Connection::ResetErrorExpecter();
}

void ScopedErrorExpecter::ExpectError(int err) {
  EXPECT_EQ(0u, errors_expected_.count(err))
      << " Error " << err << " is already expected";
  errors_expected_.insert(err);
}

bool ScopedErrorExpecter::SawExpectedErrors() {
  checked_ = true;
  return errors_expected_ == errors_seen_;
}

bool ScopedErrorExpecter::ErrorSeen(int err) {
  // Look for extended code.
  if (errors_expected_.count(err) > 0) {
    // Record that the error was seen.
    errors_seen_.insert(err);
    return true;
  }

  // Trim extended codes and check again.
  int base_err = err & 0xff;
  if (errors_expected_.count(base_err) > 0) {
    // Record that the error was seen.
    errors_seen_.insert(base_err);
    return true;
  }

  // Unexpected error.
  ADD_FAILURE() << " Unexpected SQLite error " << err;
  return false;
}

}  // namespace test
}  // namespace sql
