// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/histogram_tester.h"

#include <stddef.h>

#include "base/metrics/histogram.h"
#include "base/metrics/histogram_samples.h"
#include "base/metrics/metrics_hashes.h"
#include "base/metrics/sample_map.h"
#include "base/metrics/statistics_recorder.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

HistogramTester::HistogramTester() {
  StatisticsRecorder::Initialize();  // Safe to call multiple times.

  // Record any histogram data that exists when the object is created so it can
  // be subtracted later.
  StatisticsRecorder::Histograms histograms;
  StatisticsRecorder::GetSnapshot(std::string(), &histograms);
  for (const auto& histogram : histograms) {
    histograms_snapshot_[histogram->histogram_name()] =
        histogram->SnapshotSamples();
  }
}

HistogramTester::~HistogramTester() {
}

void HistogramTester::ExpectUniqueSample(
    const std::string& name,
    base::HistogramBase::Sample sample,
    base::HistogramBase::Count expected_count) const {
  base::HistogramBase* histogram =
      base::StatisticsRecorder::FindHistogram(name);
  EXPECT_NE(nullptr, histogram) << "Histogram \"" << name
                                << "\" does not exist.";

  if (histogram) {
    std::unique_ptr<base::HistogramSamples> samples =
        histogram->SnapshotSamples();
    CheckBucketCount(name, sample, expected_count, *samples);
    CheckTotalCount(name, expected_count, *samples);
  }
}

void HistogramTester::ExpectBucketCount(
    const std::string& name,
    base::HistogramBase::Sample sample,
    base::HistogramBase::Count expected_count) const {
  base::HistogramBase* histogram =
      base::StatisticsRecorder::FindHistogram(name);
  EXPECT_NE(nullptr, histogram) << "Histogram \"" << name
                                << "\" does not exist.";

  if (histogram) {
    std::unique_ptr<base::HistogramSamples> samples =
        histogram->SnapshotSamples();
    CheckBucketCount(name, sample, expected_count, *samples);
  }
}

void HistogramTester::ExpectTotalCount(const std::string& name,
                                       base::HistogramBase::Count count) const {
  base::HistogramBase* histogram =
      base::StatisticsRecorder::FindHistogram(name);
  if (histogram) {
    std::unique_ptr<base::HistogramSamples> samples =
        histogram->SnapshotSamples();
    CheckTotalCount(name, count, *samples);
  } else {
    // No histogram means there were zero samples.
    EXPECT_EQ(count, 0) << "Histogram \"" << name << "\" does not exist.";
  }
}

std::vector<Bucket> HistogramTester::GetAllSamples(
    const std::string& name) const {
  std::vector<Bucket> samples;
  std::unique_ptr<HistogramSamples> snapshot =
      GetHistogramSamplesSinceCreation(name);
  if (snapshot) {
    for (auto it = snapshot->Iterator(); !it->Done(); it->Next()) {
      HistogramBase::Sample sample;
      HistogramBase::Count count;
      it->Get(&sample, nullptr, &count);
      samples.push_back(Bucket(sample, count));
    }
  }
  return samples;
}

HistogramTester::CountsMap HistogramTester::GetTotalCountsForPrefix(
    const std::string& query) const {
  EXPECT_TRUE(query.find('.') != std::string::npos)
      << "|query| ought to contain at least one period, to avoid matching too"
      << " many histograms.";

  // Find matches by using the prefix-matching logic built into GetSnapshot().
  StatisticsRecorder::Histograms query_matches;
  StatisticsRecorder::GetSnapshot(query, &query_matches);

  CountsMap result;
  for (base::HistogramBase* histogram : query_matches) {
    std::unique_ptr<HistogramSamples> new_samples =
        GetHistogramSamplesSinceCreation(histogram->histogram_name());
    // Omit unchanged histograms from the result.
    if (new_samples->TotalCount()) {
      result[histogram->histogram_name()] = new_samples->TotalCount();
    }
  }
  return result;
}

std::unique_ptr<HistogramSamples>
HistogramTester::GetHistogramSamplesSinceCreation(
    const std::string& histogram_name) const {
  HistogramBase* histogram = StatisticsRecorder::FindHistogram(histogram_name);
  // Whether the histogram exists or not may not depend on the current test
  // calling this method, but rather on which tests ran before and possibly
  // generated a histogram or not (see http://crbug.com/473689). To provide a
  // response which is independent of the previously run tests, this method
  // creates empty samples in the absence of the histogram, rather than
  // returning null.
  if (!histogram) {
    return std::unique_ptr<HistogramSamples>(
        new SampleMap(HashMetricName(histogram_name)));
  }
  std::unique_ptr<HistogramSamples> named_samples =
      histogram->SnapshotSamples();
  auto original_samples_it = histograms_snapshot_.find(histogram_name);
  if (original_samples_it != histograms_snapshot_.end())
    named_samples->Subtract(*original_samples_it->second.get());
  return named_samples;
}

void HistogramTester::CheckBucketCount(
    const std::string& name,
    base::HistogramBase::Sample sample,
    base::HistogramBase::Count expected_count,
    const base::HistogramSamples& samples) const {
  int actual_count = samples.GetCount(sample);
  auto histogram_data = histograms_snapshot_.find(name);
  if (histogram_data != histograms_snapshot_.end())
    actual_count -= histogram_data->second->GetCount(sample);

  EXPECT_EQ(expected_count, actual_count)
      << "Histogram \"" << name
      << "\" does not have the right number of samples (" << expected_count
      << ") in the expected bucket (" << sample << "). It has (" << actual_count
      << ").";
}

void HistogramTester::CheckTotalCount(
    const std::string& name,
    base::HistogramBase::Count expected_count,
    const base::HistogramSamples& samples) const {
  int actual_count = samples.TotalCount();
  auto histogram_data = histograms_snapshot_.find(name);
  if (histogram_data != histograms_snapshot_.end())
    actual_count -= histogram_data->second->TotalCount();

  EXPECT_EQ(expected_count, actual_count)
      << "Histogram \"" << name
      << "\" does not have the right total number of samples ("
      << expected_count << "). It has (" << actual_count << ").";
}

bool Bucket::operator==(const Bucket& other) const {
  return min == other.min && count == other.count;
}

void PrintTo(const Bucket& bucket, std::ostream* os) {
  *os << "Bucket " << bucket.min << ": " << bucket.count;
}

}  // namespace base
