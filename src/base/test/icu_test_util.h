// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_ICU_TEST_UTIL_H_
#define BASE_ICU_TEST_UTIL_H_

#include <string>

#include "base/macros.h"

namespace base {
namespace test {

class ScopedRestoreICUDefaultLocale {
 public:
  ScopedRestoreICUDefaultLocale();
  ~ScopedRestoreICUDefaultLocale();

 private:
  std::string default_locale_;

  DISALLOW_COPY_AND_ASSIGN(ScopedRestoreICUDefaultLocale);
};

void InitializeICUForTesting();

}  // namespace test
}  // namespace base

#endif  // BASE_ICU_TEST_UTIL_H_
