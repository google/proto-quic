// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_OBSERVATION_BUFFER_H_
#define NET_NQE_OBSERVATION_BUFFER_H_

#include <float.h>

#include <algorithm>
#include <deque>
#include <vector>

#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/time/time.h"
#include "net/base/net_export.h"
#include "net/nqe/network_quality_observation_source.h"
#include "net/nqe/weighted_observation.h"

namespace net {

namespace nqe {

namespace internal {

// Stores observations sorted by time.
template <typename ValueType>
class NET_EXPORT_PRIVATE ObservationBuffer {
 public:
  explicit ObservationBuffer(double weight_multiplier_per_second)
      : weight_multiplier_per_second_(weight_multiplier_per_second) {
    static_assert(kMaximumObservationsBufferSize > 0U,
                  "Minimum size of observation buffer must be > 0");
    DCHECK_GE(weight_multiplier_per_second_, 0.0);
    DCHECK_LE(weight_multiplier_per_second_, 1.0);
  }

  ~ObservationBuffer() {}

  // Adds |observation| to the buffer. The oldest observation in the buffer
  // will be evicted to make room if the buffer is already full.
  void AddObservation(const Observation<ValueType>& observation) {
    DCHECK_LE(observations_.size(),
              static_cast<size_t>(kMaximumObservationsBufferSize));
    // Evict the oldest element if the buffer is already full.
    if (observations_.size() == kMaximumObservationsBufferSize)
      observations_.pop_front();

    observations_.push_back(observation);
    DCHECK_LE(observations_.size(),
              static_cast<size_t>(kMaximumObservationsBufferSize));
  }

  // Returns the number of observations in this buffer.
  size_t Size() const { return static_cast<size_t>(observations_.size()); }

  // Returns the capacity of this buffer.
  size_t Capacity() const {
    return static_cast<size_t>(kMaximumObservationsBufferSize);
  }

  // Clears the observations stored in this buffer.
  void Clear() { observations_.clear(); }

  // Returns true iff the |percentile| value of the observations in this
  // buffer is available. Sets |result| to the computed |percentile|
  // value among all observations since |begin_timestamp|. If the value is
  // unavailable, false is returned and |result| is not modified. Percentile
  // value is unavailable if all the values in observation buffer are older
  // than |begin_timestamp|.
  // |result| must not be null.
  bool GetPercentile(const base::TimeTicks& begin_timestamp,
                     ValueType* result,
                     int percentile,
                     const std::vector<NetworkQualityObservationSource>&
                         disallowed_observation_sources) const {
    DCHECK(result);
    DCHECK_GE(Capacity(), Size());
    // Stores WeightedObservation in increasing order of value.
    std::vector<WeightedObservation<ValueType>> weighted_observations;

    // Total weight of all observations in |weighted_observations|.
    double total_weight = 0.0;

    ComputeWeightedObservations(begin_timestamp, weighted_observations,
                                &total_weight, disallowed_observation_sources);
    if (weighted_observations.empty())
      return false;

    DCHECK(!weighted_observations.empty());
    DCHECK_GT(total_weight, 0.0);

    // |weighted_observations| may have a smaller size than observations_ since
    // the former contains only the observations later than begin_timestamp.
    DCHECK_GE(observations_.size(), weighted_observations.size());

    double desired_weight = percentile / 100.0 * total_weight;

    double cumulative_weight_seen_so_far = 0.0;
    for (const auto& weighted_observation : weighted_observations) {
      cumulative_weight_seen_so_far += weighted_observation.weight;

      if (cumulative_weight_seen_so_far >= desired_weight) {
        *result = weighted_observation.value;
        return true;
      }
    }

    // Computation may reach here due to floating point errors. This may happen
    // if |percentile| was 100 (or close to 100), and |desired_weight| was
    // slightly larger than |total_weight| (due to floating point errors).
    // In this case, we return the highest |value| among all observations.
    // This is same as value of the last observation in the sorted vector.
    *result = weighted_observations.at(weighted_observations.size() - 1).value;
    return true;
  }

 private:
  // Maximum number of observations that can be held in the ObservationBuffer.
  static const size_t kMaximumObservationsBufferSize = 300;

  // Computes the weighted observations and stores them in
  // |weighted_observations| sorted by ascending |WeightedObservation.value|.
  // Only the observations with timestamp later than |begin_timestamp| are
  // considered. Also, sets |total_weight| to the total weight of all
  // observations. Should be called only when there is at least one
  // observation in the buffer.
  void ComputeWeightedObservations(
      const base::TimeTicks& begin_timestamp,
      std::vector<WeightedObservation<ValueType>>& weighted_observations,
      double* total_weight,
      const std::vector<NetworkQualityObservationSource>&
          disallowed_observation_sources) const {
    DCHECK_GE(Capacity(), Size());

    weighted_observations.clear();
    double total_weight_observations = 0.0;
    base::TimeTicks now = base::TimeTicks::Now();

    for (const auto& observation : observations_) {
      if (observation.timestamp < begin_timestamp)
        continue;
      bool disallowed = false;
      for (const auto& disallowed_source : disallowed_observation_sources) {
        if (disallowed_source == observation.source)
          disallowed = true;
      }
      if (disallowed)
        continue;
      base::TimeDelta time_since_sample_taken = now - observation.timestamp;
      double weight = pow(weight_multiplier_per_second_,
                          time_since_sample_taken.InSeconds());
      weight = std::max(DBL_MIN, std::min(1.0, weight));

      weighted_observations.push_back(
          WeightedObservation<ValueType>(observation.value, weight));
      total_weight_observations += weight;
    }

    // Sort the samples by value in ascending order.
    std::sort(weighted_observations.begin(), weighted_observations.end());
    *total_weight = total_weight_observations;
  }

  // Holds observations sorted by time, with the oldest observation at the
  // front of the queue.
  std::deque<Observation<ValueType>> observations_;

  // The factor by which the weight of an observation reduces every second.
  // For example, if an observation is 6 seconds old, its weight would be:
  //     weight_multiplier_per_second_ ^ 6
  // Calculated from |kHalfLifeSeconds| by solving the following equation:
  //     weight_multiplier_per_second_ ^ kHalfLifeSeconds = 0.5
  const double weight_multiplier_per_second_;

  DISALLOW_COPY_AND_ASSIGN(ObservationBuffer);
};

}  // namespace internal

}  // namespace nqe

}  // namespace net

#endif  // NET_NQE_OBSERVATION_BUFFER_H_