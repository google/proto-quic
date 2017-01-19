// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/metrics/histogram_snapshot_manager.h"

#include <memory>

#include "base/debug/alias.h"
#include "base/metrics/histogram_flattener.h"
#include "base/metrics/histogram_samples.h"
#include "base/metrics/statistics_recorder.h"
#include "base/stl_util.h"

namespace base {

HistogramSnapshotManager::HistogramSnapshotManager(
    HistogramFlattener* histogram_flattener)
    : histogram_flattener_(histogram_flattener) {
  DCHECK(histogram_flattener_);
}

HistogramSnapshotManager::~HistogramSnapshotManager() {
}

void HistogramSnapshotManager::PrepareDelta(HistogramBase* histogram) {
  PrepareSamples(histogram, histogram->SnapshotDelta());
}

void HistogramSnapshotManager::PrepareFinalDelta(
    const HistogramBase* histogram) {
  PrepareSamples(histogram, histogram->SnapshotFinalDelta());
}

void HistogramSnapshotManager::PrepareSamples(
    const HistogramBase* histogram,
    std::unique_ptr<HistogramSamples> samples) {
  DCHECK(histogram_flattener_);

  // Get information known about this histogram. If it did not previously
  // exist, one will be created and initialized.
  SampleInfo* sample_info = &known_histograms_[histogram->name_hash()];

  // Crash if we detect that our histograms have been overwritten.  This may be
  // a fair distance from the memory smasher, but we hope to correlate these
  // crashes with other events, such as plugins, or usage patterns, etc.
  uint32_t corruption = histogram->FindCorruption(*samples);
  if (HistogramBase::BUCKET_ORDER_ERROR & corruption) {
    // Extract fields useful during debug.
    const BucketRanges* ranges =
        static_cast<const Histogram*>(histogram)->bucket_ranges();
    std::vector<HistogramBase::Sample> ranges_copy;
    for (size_t i = 0; i < ranges->size(); ++i)
      ranges_copy.push_back(ranges->range(i));
    HistogramBase::Sample* ranges_ptr = &ranges_copy[0];
    uint32_t ranges_checksum = ranges->checksum();
    uint32_t ranges_calc_checksum = ranges->CalculateChecksum();
    const char* histogram_name = histogram->histogram_name().c_str();
    int32_t flags = histogram->flags();
    // The checksum should have caught this, so crash separately if it didn't.
    CHECK_NE(0U, HistogramBase::RANGE_CHECKSUM_ERROR & corruption);
    CHECK(false);  // Crash for the bucket order corruption.
    // Ensure that compiler keeps around pointers to |histogram| and its
    // internal |bucket_ranges_| for any minidumps.
    base::debug::Alias(&ranges_ptr);
    base::debug::Alias(&ranges_checksum);
    base::debug::Alias(&ranges_calc_checksum);
    base::debug::Alias(&histogram_name);
    base::debug::Alias(&flags);
  }
  // Checksum corruption might not have caused order corruption.
  CHECK_EQ(0U, HistogramBase::RANGE_CHECKSUM_ERROR & corruption);

  // Note, at this point corruption can only be COUNT_HIGH_ERROR or
  // COUNT_LOW_ERROR and they never arise together, so we don't need to extract
  // bits from corruption.
  if (corruption) {
    DLOG(ERROR) << "Histogram: \"" << histogram->histogram_name()
                << "\" has data corruption: " << corruption;
    histogram_flattener_->InconsistencyDetected(
        static_cast<HistogramBase::Inconsistency>(corruption));
    // Don't record corrupt data to metrics services.
    const uint32_t old_corruption = sample_info->inconsistencies;
    if (old_corruption == (corruption | old_corruption))
      return;  // We've already seen this corruption for this histogram.
    sample_info->inconsistencies |= corruption;
    histogram_flattener_->UniqueInconsistencyDetected(
        static_cast<HistogramBase::Inconsistency>(corruption));
    return;
  }

  if (samples->TotalCount() > 0)
    histogram_flattener_->RecordDelta(*histogram, *samples);
}

void HistogramSnapshotManager::InspectLoggedSamplesInconsistency(
      const HistogramSamples& new_snapshot,
      HistogramSamples* logged_samples) {
  HistogramBase::Count discrepancy =
      logged_samples->TotalCount() - logged_samples->redundant_count();
  if (!discrepancy)
    return;

  histogram_flattener_->InconsistencyDetectedInLoggedCount(discrepancy);
  if (discrepancy > Histogram::kCommonRaceBasedCountMismatch) {
    // Fix logged_samples.
    logged_samples->Subtract(*logged_samples);
    logged_samples->Add(new_snapshot);
  }
}

}  // namespace base
