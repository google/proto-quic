// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include "base/metrics/histogram.h"
#include "base/metrics/histogram_base.h"
#include "base/metrics/sparse_histogram.h"
#include "base/metrics/statistics_recorder.h"
#include "base/pickle.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

class HistogramBaseTest : public testing::Test {
 protected:
  HistogramBaseTest() {
    // Each test will have a clean state (no Histogram / BucketRanges
    // registered).
    ResetStatisticsRecorder();
  }

  ~HistogramBaseTest() override {
    HistogramBase::report_histogram_ = nullptr;
  }

  void ResetStatisticsRecorder() {
    // It is necessary to fully destruct any existing StatisticsRecorder
    // before creating a new one.
    statistics_recorder_.reset();
    statistics_recorder_ = StatisticsRecorder::CreateTemporaryForTesting();
  }

  HistogramBase* GetCreationReportHistogram(const std::string& name) {
    HistogramBase::EnableActivityReportHistogram(name);
    return HistogramBase::report_histogram_;
  }

 private:
  std::unique_ptr<StatisticsRecorder> statistics_recorder_;

  DISALLOW_COPY_AND_ASSIGN(HistogramBaseTest);
};

TEST_F(HistogramBaseTest, DeserializeHistogram) {
  HistogramBase* histogram = Histogram::FactoryGet(
      "TestHistogram", 1, 1000, 10,
      (HistogramBase::kUmaTargetedHistogramFlag |
      HistogramBase::kIPCSerializationSourceFlag));

  Pickle pickle;
  ASSERT_TRUE(histogram->SerializeInfo(&pickle));

  PickleIterator iter(pickle);
  HistogramBase* deserialized = DeserializeHistogramInfo(&iter);
  EXPECT_EQ(histogram, deserialized);

  ResetStatisticsRecorder();

  PickleIterator iter2(pickle);
  deserialized = DeserializeHistogramInfo(&iter2);
  EXPECT_TRUE(deserialized);
  EXPECT_NE(histogram, deserialized);
  EXPECT_EQ("TestHistogram", deserialized->histogram_name());
  EXPECT_TRUE(deserialized->HasConstructionArguments(1, 1000, 10));

  // kIPCSerializationSourceFlag will be cleared.
  EXPECT_EQ(HistogramBase::kUmaTargetedHistogramFlag, deserialized->flags());
}

TEST_F(HistogramBaseTest, DeserializeLinearHistogram) {
  HistogramBase* histogram = LinearHistogram::FactoryGet(
      "TestHistogram", 1, 1000, 10,
      HistogramBase::kIPCSerializationSourceFlag);

  Pickle pickle;
  ASSERT_TRUE(histogram->SerializeInfo(&pickle));

  PickleIterator iter(pickle);
  HistogramBase* deserialized = DeserializeHistogramInfo(&iter);
  EXPECT_EQ(histogram, deserialized);

  ResetStatisticsRecorder();

  PickleIterator iter2(pickle);
  deserialized = DeserializeHistogramInfo(&iter2);
  EXPECT_TRUE(deserialized);
  EXPECT_NE(histogram, deserialized);
  EXPECT_EQ("TestHistogram", deserialized->histogram_name());
  EXPECT_TRUE(deserialized->HasConstructionArguments(1, 1000, 10));
  EXPECT_EQ(0, deserialized->flags());
}

TEST_F(HistogramBaseTest, DeserializeBooleanHistogram) {
  HistogramBase* histogram = BooleanHistogram::FactoryGet(
      "TestHistogram", HistogramBase::kIPCSerializationSourceFlag);

  Pickle pickle;
  ASSERT_TRUE(histogram->SerializeInfo(&pickle));

  PickleIterator iter(pickle);
  HistogramBase* deserialized = DeserializeHistogramInfo(&iter);
  EXPECT_EQ(histogram, deserialized);

  ResetStatisticsRecorder();

  PickleIterator iter2(pickle);
  deserialized = DeserializeHistogramInfo(&iter2);
  EXPECT_TRUE(deserialized);
  EXPECT_NE(histogram, deserialized);
  EXPECT_EQ("TestHistogram", deserialized->histogram_name());
  EXPECT_TRUE(deserialized->HasConstructionArguments(1, 2, 3));
  EXPECT_EQ(0, deserialized->flags());
}

TEST_F(HistogramBaseTest, DeserializeCustomHistogram) {
  std::vector<HistogramBase::Sample> ranges;
  ranges.push_back(13);
  ranges.push_back(5);
  ranges.push_back(9);

  HistogramBase* histogram = CustomHistogram::FactoryGet(
      "TestHistogram", ranges, HistogramBase::kIPCSerializationSourceFlag);

  Pickle pickle;
  ASSERT_TRUE(histogram->SerializeInfo(&pickle));

  PickleIterator iter(pickle);
  HistogramBase* deserialized = DeserializeHistogramInfo(&iter);
  EXPECT_EQ(histogram, deserialized);

  ResetStatisticsRecorder();

  PickleIterator iter2(pickle);
  deserialized = DeserializeHistogramInfo(&iter2);
  EXPECT_TRUE(deserialized);
  EXPECT_NE(histogram, deserialized);
  EXPECT_EQ("TestHistogram", deserialized->histogram_name());
  EXPECT_TRUE(deserialized->HasConstructionArguments(5, 13, 4));
  EXPECT_EQ(0, deserialized->flags());
}

TEST_F(HistogramBaseTest, DeserializeSparseHistogram) {
  HistogramBase* histogram = SparseHistogram::FactoryGet(
      "TestHistogram", HistogramBase::kIPCSerializationSourceFlag);

  Pickle pickle;
  ASSERT_TRUE(histogram->SerializeInfo(&pickle));

  PickleIterator iter(pickle);
  HistogramBase* deserialized = DeserializeHistogramInfo(&iter);
  EXPECT_EQ(histogram, deserialized);

  ResetStatisticsRecorder();

  PickleIterator iter2(pickle);
  deserialized = DeserializeHistogramInfo(&iter2);
  EXPECT_TRUE(deserialized);
  EXPECT_NE(histogram, deserialized);
  EXPECT_EQ("TestHistogram", deserialized->histogram_name());
  EXPECT_EQ(0, deserialized->flags());
}

TEST_F(HistogramBaseTest, CreationReportHistogram) {
  // Enabled creation report. Itself is not included in the report.
  HistogramBase* report = GetCreationReportHistogram("CreationReportTest");
  ASSERT_TRUE(report);

  std::vector<HistogramBase::Sample> ranges;
  ranges.push_back(1);
  ranges.push_back(2);
  ranges.push_back(4);
  ranges.push_back(8);
  ranges.push_back(10);

  // Create all histogram types and verify counts.
  Histogram::FactoryGet("CRH-Histogram", 1, 10, 5, 0);
  LinearHistogram::FactoryGet("CRH-Linear", 1, 10, 5, 0);
  BooleanHistogram::FactoryGet("CRH-Boolean", 0);
  CustomHistogram::FactoryGet("CRH-Custom", ranges, 0);
  SparseHistogram::FactoryGet("CRH-Sparse", 0);

  std::unique_ptr<HistogramSamples> samples = report->SnapshotSamples();
  EXPECT_EQ(1, samples->GetCount(HISTOGRAM_REPORT_CREATED));
  EXPECT_EQ(5, samples->GetCount(HISTOGRAM_REPORT_HISTOGRAM_CREATED));
  EXPECT_EQ(0, samples->GetCount(HISTOGRAM_REPORT_HISTOGRAM_LOOKUP));
  EXPECT_EQ(1, samples->GetCount(HISTOGRAM_REPORT_TYPE_LOGARITHMIC));
  EXPECT_EQ(1, samples->GetCount(HISTOGRAM_REPORT_TYPE_LINEAR));
  EXPECT_EQ(1, samples->GetCount(HISTOGRAM_REPORT_TYPE_BOOLEAN));
  EXPECT_EQ(1, samples->GetCount(HISTOGRAM_REPORT_TYPE_CUSTOM));
  EXPECT_EQ(1, samples->GetCount(HISTOGRAM_REPORT_TYPE_SPARSE));

  // Create all flag types and verify counts.
  Histogram::FactoryGet("CRH-Histogram-UMA-Targeted", 1, 10, 5,
                        HistogramBase::kUmaTargetedHistogramFlag);
  Histogram::FactoryGet("CRH-Histogram-UMA-Stability", 1, 10, 5,
                        HistogramBase::kUmaStabilityHistogramFlag);
  SparseHistogram::FactoryGet("CRH-Sparse-UMA-Targeted",
                              HistogramBase::kUmaTargetedHistogramFlag);
  SparseHistogram::FactoryGet("CRH-Sparse-UMA-Stability",
                              HistogramBase::kUmaStabilityHistogramFlag);
  samples = report->SnapshotSamples();
  EXPECT_EQ(1, samples->GetCount(HISTOGRAM_REPORT_CREATED));
  EXPECT_EQ(9, samples->GetCount(HISTOGRAM_REPORT_HISTOGRAM_CREATED));
  EXPECT_EQ(0, samples->GetCount(HISTOGRAM_REPORT_HISTOGRAM_LOOKUP));
  EXPECT_EQ(2, samples->GetCount(HISTOGRAM_REPORT_FLAG_UMA_TARGETED));
  EXPECT_EQ(2, samples->GetCount(HISTOGRAM_REPORT_FLAG_UMA_STABILITY));

  // Do lookup of existing histograms and verify counts.
  Histogram::FactoryGet("CRH-Histogram", 1, 10, 5, 0);
  LinearHistogram::FactoryGet("CRH-Linear", 1, 10, 5, 0);
  BooleanHistogram::FactoryGet("CRH-Boolean", 0);
  CustomHistogram::FactoryGet("CRH-Custom", ranges, 0);
  SparseHistogram::FactoryGet("CRH-Sparse", 0);
  samples = report->SnapshotSamples();
  EXPECT_EQ(1, samples->GetCount(HISTOGRAM_REPORT_CREATED));
  EXPECT_EQ(9, samples->GetCount(HISTOGRAM_REPORT_HISTOGRAM_CREATED));
  EXPECT_EQ(5, samples->GetCount(HISTOGRAM_REPORT_HISTOGRAM_LOOKUP));
}

}  // namespace base
