// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_OBSERVATION_BUFFER_H_
#define NET_NQE_OBSERVATION_BUFFER_H_

#include <float.h>

#include <algorithm>
#include <deque>
#include <memory>
#include <utility>
#include <vector>

#include "base/macros.h"
#include "base/time/default_tick_clock.h"
#include "base/time/tick_clock.h"
#include "base/time/time.h"
#include "net/base/net_export.h"
#include "net/nqe/network_quality_observation.h"
#include "net/nqe/network_quality_observation_source.h"
#include "net/nqe/weighted_observation.h"

namespace net {

namespace nqe {

namespace internal {

// Stores observations sorted by time.
template <typename ValueType>
class NET_EXPORT_PRIVATE ObservationBuffer {
 public:
  ObservationBuffer(double weight_multiplier_per_second,
                    double weight_multiplier_per_dbm)
      : weight_multiplier_per_second_(weight_multiplier_per_second),
        weight_multiplier_per_dbm_(weight_multiplier_per_dbm),
        tick_clock_(new base::DefaultTickClock()) {
    static_assert(kMaximumObservationsBufferSize > 0U,
                  "Minimum size of observation buffer must be > 0");
    DCHECK_LE(0.0, weight_multiplier_per_second_);
    DCHECK_GE(1.0, weight_multiplier_per_second_);
    DCHECK_LE(0.0, weight_multiplier_per_dbm_);
    DCHECK_GE(1.0, weight_multiplier_per_dbm_);
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
  // value of all observations made on or after |begin_timestamp|. If the
  // value is unavailable, false is returned and |result| is not modified.
  // Percentile value is unavailable if all the values in observation buffer are
  // older than |begin_timestamp|. |current_signal_strength_dbm| is the current
  // signal strength in dBm.
  // |result| must not be null.
  // TODO(tbansal): Move out param |result| as the last param of the function.
  bool GetPercentile(base::TimeTicks begin_timestamp,
                     int32_t current_signal_strength_dbm,
                     ValueType* result,
                     int percentile,
                     const std::vector<NetworkQualityObservationSource>&
                         disallowed_observation_sources) const {
    // Stores weighted observations in increasing order by value.
    std::vector<WeightedObservation<ValueType>> weighted_observations;

    // Total weight of all observations in |weighted_observations|.
    double total_weight = 0.0;

    ComputeWeightedObservations(begin_timestamp, current_signal_strength_dbm,
                                weighted_observations, &total_weight,
                                disallowed_observation_sources);
    if (weighted_observations.empty())
      return false;

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

  // Returns true iff the weighted average of the observations in this
  // buffer is available. Sets |result| to the computed weighted average value
  // of all observations made on or after |begin_timestamp|. If the value is
  // unavailable, false is returned and |result| is not modified. The unweighted
  // average value is unavailable if all the values in the observation buffer
  // are older than |begin_timestamp|. |current_signal_strength_dbm| is the
  // current signal strength in dBm. |result| must not be null.
  bool GetWeightedAverage(base::TimeTicks begin_timestamp,
                          int32_t current_signal_strength_dbm,
                          const std::vector<NetworkQualityObservationSource>&
                              disallowed_observation_sources,
                          ValueType* result) const {
    // Stores weighted observations in increasing order by value.
    std::vector<WeightedObservation<ValueType>> weighted_observations;

    // Total weight of all observations in |weighted_observations|.
    double total_weight = 0.0;

    ComputeWeightedObservations(begin_timestamp, current_signal_strength_dbm,
                                weighted_observations, &total_weight,
                                disallowed_observation_sources);
    if (weighted_observations.empty())
      return false;

    // Weighted average is the sum of observations times their respective
    // weights, divided by the sum of the weights of all observations.
    double total_weight_times_value = 0.0;
    for (const auto& weighted_observation : weighted_observations) {
      total_weight_times_value +=
          (weighted_observation.weight *
           ConvertValueTypeToDouble(weighted_observation.value));
    }

    ConvertDoubleToValueType(total_weight_times_value / total_weight, result);
    return true;
  }

  // Returns true iff the unweighted average of the observations in this buffer
  // is available. Sets |result| to the computed unweighted average value of
  // all observations made on or after |begin_timestamp|. If the value is
  // unavailable, false is returned and |result| is not modified. The weighted
  // average value is unavailable if all the values in the observation buffer
  // are older than |begin_timestamp|. |current_signal_strength_dbm| is the
  // current signal strength in dBm. |result| must not be null.
  bool GetUnweightedAverage(base::TimeTicks begin_timestamp,
                            int32_t current_signal_strength_dbm,
                            const std::vector<NetworkQualityObservationSource>&
                                disallowed_observation_sources,
                            ValueType* result) const {
    // Stores weighted observations in increasing order by value.
    std::vector<WeightedObservation<ValueType>> weighted_observations;

    // Total weight of all observations in |weighted_observations|.
    double total_weight = 0.0;

    ComputeWeightedObservations(begin_timestamp, current_signal_strength_dbm,
                                weighted_observations, &total_weight,
                                disallowed_observation_sources);
    if (weighted_observations.empty())
      return false;

    // The unweighted average is the sum of all observations divided by the
    // number of observations.
    double total_value = 0.0;
    for (const auto& weighted_observation : weighted_observations)
      total_value += ConvertValueTypeToDouble(weighted_observation.value);

    ConvertDoubleToValueType(total_value / weighted_observations.size(),
                             result);
    return true;
  }

  void SetTickClockForTesting(std::unique_ptr<base::TickClock> tick_clock) {
    tick_clock_ = std::move(tick_clock);
  }

 private:
  // Maximum number of observations that can be held in the ObservationBuffer.
  static const size_t kMaximumObservationsBufferSize = 300;

  // Convert different ValueTypes to double to make it possible to perform
  // arithmetic operations on them.
  double ConvertValueTypeToDouble(base::TimeDelta input) const {
    return input.InMilliseconds();
  }
  double ConvertValueTypeToDouble(int32_t input) const { return input; }

  // Convert double to different ValueTypes.
  void ConvertDoubleToValueType(double input, base::TimeDelta* output) const {
    *output = base::TimeDelta::FromMilliseconds(input);
  }
  void ConvertDoubleToValueType(double input, int32_t* output) const {
    *output = input;
  }

  // Computes the weighted observations and stores them in
  // |weighted_observations| sorted by ascending |WeightedObservation.value|.
  // Only the observations with timestamp later than |begin_timestamp| are
  // considered. |current_signal_strength_dbm| is the current signal strength
  // (in dBm) when the observation was taken, and is set to INT32_MIN if the
  // signal strength is currently unavailable. This method also sets
  // |total_weight| to the total weight of all observations. Should be called
  // only when there is at least one observation in the buffer.
  void ComputeWeightedObservations(
      const base::TimeTicks& begin_timestamp,
      int32_t current_signal_strength_dbm,
      std::vector<WeightedObservation<ValueType>>& weighted_observations,
      double* total_weight,
      const std::vector<NetworkQualityObservationSource>&
          disallowed_observation_sources) const {
    DCHECK_GE(Capacity(), Size());

    weighted_observations.clear();
    double total_weight_observations = 0.0;
    base::TimeTicks now = tick_clock_->NowTicks();

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
      double time_weight = pow(weight_multiplier_per_second_,
                               time_since_sample_taken.InSeconds());

      double signal_strength_weight = 1.0;
      if (current_signal_strength_dbm != INT32_MIN &&
          observation.signal_strength_dbm != INT32_MIN &&
          current_signal_strength_dbm != INT32_MAX &&
          observation.signal_strength_dbm != INT32_MAX) {
        int32_t signal_strength_weight_diff = std::abs(
            current_signal_strength_dbm - observation.signal_strength_dbm);
        signal_strength_weight =
            pow(weight_multiplier_per_dbm_, signal_strength_weight_diff);
      }

      double weight = time_weight * signal_strength_weight;

      weight = std::max(DBL_MIN, std::min(1.0, weight));

      weighted_observations.push_back(
          WeightedObservation<ValueType>(observation.value, weight));
      total_weight_observations += weight;
    }

    // Sort the samples by value in ascending order.
    std::sort(weighted_observations.begin(), weighted_observations.end());
    *total_weight = total_weight_observations;

    DCHECK_LE(0.0, *total_weight);
    DCHECK(weighted_observations.empty() || 0.0 < *total_weight);

    // |weighted_observations| may have a smaller size than |observations_|
    // since the former contains only the observations later than
    // |begin_timestamp|.
    DCHECK_GE(observations_.size(), weighted_observations.size());
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

  // The factor by which the weight of an observation reduces for every dbM
  // difference in the current signal strength, and the signal strength at
  // which the observation was taken.
  // For example, if the observation was taken at 90 dBm, and current signal
  // strength is 95 dBm, the weight of the observation would be:
  // |weight_multiplier_per_dbm_| ^ 5.
  const double weight_multiplier_per_dbm_;

  std::unique_ptr<base::TickClock> tick_clock_;

  DISALLOW_COPY_AND_ASSIGN(ObservationBuffer);
};

}  // namespace internal

}  // namespace nqe

}  // namespace net

#endif  // NET_NQE_OBSERVATION_BUFFER_H_
