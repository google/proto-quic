// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SQL_CORRECT_SQL_TEST_BASE_H_
#define SQL_CORRECT_SQL_TEST_BASE_H_

// This header exists to get around gn check. We want to use the same testing
// code in both the sql_unittests target (which uses gtest and targets the
// filesystem directly) and sql_apptests.mojo (which uses mojo:apptest and
// proxies the additional filesystem access to mojo:filesystem). Both of these
// files define a class named sql::SQLTestBase and have the same interface.
//
// Unfortunately, gn check does not understand preprocessor directives. If it
// did, the following code would be gn check clean, but since it isn't, we
// stuff this redirection header in its own file, give it its own source_set
// target, and then set check_includes to false.
//
// This work around was suggested by brettw@.
#if defined(MOJO_APPTEST_IMPL)
#include "sql/mojo/sql_test_base.h"
#else
#include "sql/test/sql_test_base.h"
#endif

#endif  // SQL_CORRECT_SQL_TEST_BASE_H_

