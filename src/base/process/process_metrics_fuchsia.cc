// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/process/process_metrics.h"

namespace base {

size_t GetSystemCommitCharge() {
  // Not available, doesn't seem likely that it will be (for the whole system).
  NOTIMPLEMENTED();
  return 0;
}

}  // namespace bse
