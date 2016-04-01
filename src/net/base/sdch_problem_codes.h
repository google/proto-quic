// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_SDCH_PROBLEM_CODES_H_
#define NET_BASE_SDCH_PROBLEM_CODES_H_

namespace net {

// A list of errors that appeared and were either resolved, or used to turn
// off sdch encoding.
enum SdchProblemCode {
#define SDCH_PROBLEM_CODE(label, value) SDCH_##label = value,
#include "net/base/sdch_problem_code_list.h"
#undef SDCH_PROBLEM_CODE
};

}  // namespace net

#endif  // NET_BASE_SDCH_PROBLEM_CODES_H_
