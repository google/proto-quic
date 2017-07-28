// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_METRICS_HISTOGRAM_BASE_H_
#define BASE_METRICS_HISTOGRAM_BASE_H_

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "base/atomicops.h"
#include "base/base_export.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "base/time/time.h"

namespace base {

class DictionaryValue;
class HistogramBase;
class HistogramSamples;
class ListValue;
class Pickle;
class PickleIterator;

////////////////////////////////////////////////////////////////////////////////
// This enum is used to facilitate deserialization of histograms from other
// processes into the browser. If you create another class that inherits from
// HistogramBase, add new histogram types and names below.

enum HistogramType {
  HISTOGRAM,
  LINEAR_HISTOGRAM,
  BOOLEAN_HISTOGRAM,
  CUSTOM_HISTOGRAM,
  SPARSE_HISTOGRAM,
};

std::string HistogramTypeToString(HistogramType type);

// This enum is used for reporting how many histograms and of what types and
// variations are being created. It has to be in the main .h file so it is
// visible to files that define the various histogram types.
enum HistogramReport {
  // Count the number of reports created. The other counts divided by this
  // number will give the average per run of the program.
  HISTOGRAM_REPORT_CREATED = 0,

  // Count the total number of histograms created. It is the limit against
  // which all others are compared.
  HISTOGRAM_REPORT_HISTOGRAM_CREATED = 1,

  // Count the total number of histograms looked-up. It's better to cache
  // the result of a single lookup rather than do it repeatedly.
  HISTOGRAM_REPORT_HISTOGRAM_LOOKUP = 2,

  // These count the individual histogram types. This must follow the order
  // of HistogramType above.
  HISTOGRAM_REPORT_TYPE_LOGARITHMIC = 3,
  HISTOGRAM_REPORT_TYPE_LINEAR = 4,
  HISTOGRAM_REPORT_TYPE_BOOLEAN = 5,
  HISTOGRAM_REPORT_TYPE_CUSTOM = 6,
  HISTOGRAM_REPORT_TYPE_SPARSE = 7,

  // These indicate the individual flags that were set.
  HISTOGRAM_REPORT_FLAG_UMA_TARGETED = 8,
  HISTOGRAM_REPORT_FLAG_UMA_STABILITY = 9,
  HISTOGRAM_REPORT_FLAG_PERSISTENT = 10,

  // This must be last.
  HISTOGRAM_REPORT_MAX = 11
};

// Create or find existing histogram that matches the pickled info.
// Returns NULL if the pickled data has problems.
BASE_EXPORT HistogramBase* DeserializeHistogramInfo(base::PickleIterator* iter);

////////////////////////////////////////////////////////////////////////////////

class BASE_EXPORT HistogramBase {
 public:
  typedef int32_t Sample;                // Used for samples.
  typedef subtle::Atomic32 AtomicCount;  // Used to count samples.
  typedef int32_t Count;  // Used to manipulate counts in temporaries.

  static const Sample kSampleType_MAX;  // INT_MAX

  enum Flags {
    kNoFlags = 0x0,

    // Histogram should be UMA uploaded.
    kUmaTargetedHistogramFlag = 0x1,

    // Indicates that this is a stability histogram. This flag exists to specify
    // which histograms should be included in the initial stability log. Please
    // refer to |MetricsService::PrepareInitialStabilityLog|.
    kUmaStabilityHistogramFlag = kUmaTargetedHistogramFlag | 0x2,

    // Indicates that the histogram was pickled to be sent across an IPC
    // Channel. If we observe this flag on a histogram being aggregated into
    // after IPC, then we are running in a single process mode, and the
    // aggregation should not take place (as we would be aggregating back into
    // the source histogram!).
    kIPCSerializationSourceFlag = 0x10,

    // Indicates that a callback exists for when a new sample is recorded on
    // this histogram. We store this as a flag with the histogram since
    // histograms can be in performance critical code, and this allows us
    // to shortcut looking up the callback if it doesn't exist.
    kCallbackExists = 0x20,

    // Indicates that the histogram is held in "persistent" memory and may
    // be accessible between processes. This is only possible if such a
    // memory segment has been created/attached, used to create a Persistent-
    // MemoryAllocator, and that loaded into the Histogram module before this
    // histogram is created.
    kIsPersistent = 0x40,
  };

  // Histogram data inconsistency types.
  enum Inconsistency : uint32_t {
    NO_INCONSISTENCIES = 0x0,
    RANGE_CHECKSUM_ERROR = 0x1,
    BUCKET_ORDER_ERROR = 0x2,
    COUNT_HIGH_ERROR = 0x4,
    COUNT_LOW_ERROR = 0x8,

    NEVER_EXCEEDED_VALUE = 0x10,
  };

  explicit HistogramBase(const std::string& name);
  virtual ~HistogramBase();

  const std::string& histogram_name() const { return histogram_name_; }

  // Comapres |name| to the histogram name and triggers a DCHECK if they do not
  // match. This is a helper function used by histogram macros, which results in
  // in more compact machine code being generated by the macros.
  void CheckName(const StringPiece& name) const;

  // Get a unique ID for this histogram's samples.
  virtual uint64_t name_hash() const = 0;

  // Operations with Flags enum.
  int32_t flags() const { return subtle::NoBarrier_Load(&flags_); }
  void SetFlags(int32_t flags);
  void ClearFlags(int32_t flags);

  virtual HistogramType GetHistogramType() const = 0;

  // Whether the histogram has construction arguments as parameters specified.
  // For histograms that don't have the concept of minimum, maximum or
  // bucket_count, this function always returns false.
  virtual bool HasConstructionArguments(
      Sample expected_minimum,
      Sample expected_maximum,
      uint32_t expected_bucket_count) const = 0;

  virtual void Add(Sample value) = 0;

  // In Add function the |value| bucket is increased by one, but in some use
  // cases we need to increase this value by an arbitrary integer. AddCount
  // function increases the |value| bucket by |count|. |count| should be greater
  // than or equal to 1.
  virtual void AddCount(Sample value, int count) = 0;

  // 2 convenient functions that call Add(Sample).
  void AddTime(const TimeDelta& time);
  void AddBoolean(bool value);

  virtual void AddSamples(const HistogramSamples& samples) = 0;
  virtual bool AddSamplesFromPickle(base::PickleIterator* iter) = 0;

  // Serialize the histogram info into |pickle|.
  // Note: This only serializes the construction arguments of the histogram, but
  // does not serialize the samples.
  bool SerializeInfo(base::Pickle* pickle) const;

  // Try to find out data corruption from histogram and the samples.
  // The returned value is a combination of Inconsistency enum.
  virtual uint32_t FindCorruption(const HistogramSamples& samples) const;

  // Snapshot the current complete set of sample data.
  // Override with atomic/locked snapshot if needed.
  // NOTE: this data can overflow for long-running sessions. It should be
  // handled with care and this method is recommended to be used only
  // in about:histograms and test code.
  virtual std::unique_ptr<HistogramSamples> SnapshotSamples() const = 0;

  // Calculate the change (delta) in histogram counts since the previous call
  // to this method. Each successive call will return only those counts
  // changed since the last call.
  virtual std::unique_ptr<HistogramSamples> SnapshotDelta() = 0;

  // Calculate the change (delta) in histogram counts since the previous call
  // to SnapshotDelta() but do so without modifying any internal data as to
  // what was previous logged. After such a call, no further calls to this
  // method or to SnapshotDelta() should be done as the result would include
  // data previously returned. Because no internal data is changed, this call
  // can be made on "const" histograms such as those with data held in
  // read-only memory.
  virtual std::unique_ptr<HistogramSamples> SnapshotFinalDelta() const = 0;

  // The following methods provide graphical histogram displays.
  virtual void WriteHTMLGraph(std::string* output) const = 0;
  virtual void WriteAscii(std::string* output) const = 0;

  // TODO(bcwhite): Remove this after crbug/736675.
  virtual bool ValidateHistogramContents(bool crash_if_invalid,
                                         int corrupted_count) const;

  // Produce a JSON representation of the histogram. This is implemented with
  // the help of GetParameters and GetCountAndBucketData; overwrite them to
  // customize the output.
  void WriteJSON(std::string* output) const;

  // This enables a histogram that reports the what types of histograms are
  // created and their flags. It must be called while still single-threaded.
  //
  // IMPORTANT: Callers must update tools/metrics/histograms/histograms.xml
  // with the following histogram:
  //    UMA.Histograms.process_type.Creations
  static void EnableActivityReportHistogram(const std::string& process_type);

 protected:
  enum ReportActivity { HISTOGRAM_CREATED, HISTOGRAM_LOOKUP };

  // Subclasses should implement this function to make SerializeInfo work.
  virtual bool SerializeInfoImpl(base::Pickle* pickle) const = 0;

  // Writes information about the construction parameters in |params|.
  virtual void GetParameters(DictionaryValue* params) const = 0;

  // Writes information about the current (non-empty) buckets and their sample
  // counts to |buckets|, the total sample count to |count| and the total sum
  // to |sum|.
  virtual void GetCountAndBucketData(Count* count,
                                     int64_t* sum,
                                     ListValue* buckets) const = 0;

  //// Produce actual graph (set of blank vs non blank char's) for a bucket.
  void WriteAsciiBucketGraph(double current_size,
                             double max_size,
                             std::string* output) const;

  // Return a string description of what goes in a given bucket.
  const std::string GetSimpleAsciiBucketRange(Sample sample) const;

  // Write textual description of the bucket contents (relative to histogram).
  // Output is the count in the buckets, as well as the percentage.
  void WriteAsciiBucketValue(Count current,
                             double scaled_sum,
                             std::string* output) const;

  // Retrieves the callback for this histogram, if one exists, and runs it
  // passing |sample| as the parameter.
  void FindAndRunCallback(Sample sample) const;

  // Update report with an |activity| that occurred for |histogram|.
  static void ReportHistogramActivity(const HistogramBase& histogram,
                                      ReportActivity activicty);

  // Retrieves the global histogram reporting what histograms are created.
  static HistogramBase* report_histogram_;

 private:
  friend class HistogramBaseTest;

  const std::string histogram_name_;
  AtomicCount flags_;

  DISALLOW_COPY_AND_ASSIGN(HistogramBase);
};

}  // namespace base

#endif  // BASE_METRICS_HISTOGRAM_BASE_H_
