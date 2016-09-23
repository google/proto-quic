// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/process/process_metrics.h"

#include <memory>

#include "testing/gtest/include/gtest/gtest.h"

TEST(ProcessMetricsTestIos, Memory) {
  std::unique_ptr<base::ProcessMetrics> process_metrics(
      base::ProcessMetrics::CreateProcessMetrics(
          base::GetCurrentProcessHandle()));

  ASSERT_NE(0u, process_metrics->GetWorkingSetSize());
}
