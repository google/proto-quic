// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/filter/brotli_filter.h"

#include "base/bit_cast.h"
#include "base/macros.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_conversions.h"
#include "base/numerics/safe_math.h"
#include "third_party/brotli/dec/decode.h"

namespace net {

namespace {
const uint8_t kGzipHeader[] = {0x1f, 0x8b, 0x08};
}

// BrotliFilter applies Brotli content decoding to a data stream.
// Brotli format specification: http://www.ietf.org/id/draft-alakuijala-brotli
//
// BrotliFilter is a subclass of Filter. See the latter's header file filter.h
// for sample usage.
class BrotliFilter : public Filter {
 public:
  BrotliFilter(FilterType type)
      : Filter(type),
        decoding_status_(DecodingStatus::DECODING_IN_PROGRESS),
        used_memory_(0),
        used_memory_maximum_(0),
        consumed_bytes_(0),
        produced_bytes_(0),
        gzip_header_detected_(true) {
    brotli_state_ = BrotliCreateState(BrotliFilter::AllocateMemory,
                                      BrotliFilter::FreeMemory, this);
    CHECK(brotli_state_);
  }

  ~BrotliFilter() override {
    BrotliErrorCode error_code = BrotliGetErrorCode(brotli_state_);
    BrotliDestroyState(brotli_state_);
    brotli_state_ = nullptr;
    DCHECK(used_memory_ == 0);

    // Don't report that gzip header was detected in case of lack of input.
    gzip_header_detected_ &= (consumed_bytes_ >= sizeof(kGzipHeader));

    UMA_HISTOGRAM_ENUMERATION(
        "BrotliFilter.Status", static_cast<int>(decoding_status_),
        static_cast<int>(DecodingStatus::DECODING_STATUS_COUNT));
    UMA_HISTOGRAM_BOOLEAN("BrotliFilter.GzipHeaderDetected",
                          gzip_header_detected_);
    if (decoding_status_ == DecodingStatus::DECODING_DONE) {
      // CompressionPercent is undefined when there is no output produced.
      if (produced_bytes_ != 0) {
        UMA_HISTOGRAM_PERCENTAGE(
            "BrotliFilter.CompressionPercent",
            static_cast<int>((consumed_bytes_ * 100) / produced_bytes_));
      }
    }
    if (error_code < 0) {
      UMA_HISTOGRAM_ENUMERATION("BrotliFilter.ErrorCode",
                                -static_cast<int>(error_code),
                                1 - BROTLI_LAST_ERROR_CODE);
    }

    // All code here is for gathering stats, and can be removed when
    // BrotliFilter is considered stable.
    static const int kBuckets = 48;
    static const int64_t kMaxKb = 1 << (kBuckets / 3);  // 64MiB in KiB
    UMA_HISTOGRAM_CUSTOM_COUNTS("BrotliFilter.UsedMemoryKB",
                                used_memory_maximum_ / 1024, 1, kMaxKb,
                                kBuckets);
  }

  // Decodes the pre-filter data and writes the output into the |dest_buffer|
  // passed in.
  // The function returns FilterStatus. See filter.h for its description.
  //
  // Upon entry, |*dest_len| is the total size (in number of chars) of the
  // destination buffer. Upon exit, |*dest_len| is the actual number of chars
  // written into the destination buffer.
  //
  // This function will fail if there is no pre-filter data in the
  // |stream_buffer_|. On the other hand, |*dest_len| can be 0 upon successful
  // return. For example, decompressor may process some pre-filter data
  // but not produce output yet.
  FilterStatus ReadFilteredData(char* dest_buffer, int* dest_len) override {
    if (!dest_buffer || !dest_len)
      return Filter::FILTER_ERROR;

    if (decoding_status_ == DecodingStatus::DECODING_DONE) {
      *dest_len = 0;
      return Filter::FILTER_DONE;
    }

    if (decoding_status_ != DecodingStatus::DECODING_IN_PROGRESS)
      return Filter::FILTER_ERROR;

    size_t output_buffer_size = base::checked_cast<size_t>(*dest_len);
    size_t input_buffer_size = base::checked_cast<size_t>(stream_data_len_);

    size_t available_in = input_buffer_size;
    const uint8_t* next_in = bit_cast<uint8_t*>(next_stream_data_);
    size_t available_out = output_buffer_size;
    uint8_t* next_out = bit_cast<uint8_t*>(dest_buffer);
    size_t total_out = 0;

    // Check if start of the input stream looks like gzip stream.
    for (size_t i = consumed_bytes_; i < sizeof(kGzipHeader); ++i) {
      if (!gzip_header_detected_)
        break;
      size_t j = i - consumed_bytes_;
      if (j < available_in && kGzipHeader[i] != next_in[j])
        gzip_header_detected_ = false;
    }

    BrotliResult result =
        BrotliDecompressStream(&available_in, &next_in, &available_out,
                               &next_out, &total_out, brotli_state_);

    CHECK(available_in <= input_buffer_size);
    CHECK(available_out <= output_buffer_size);
    consumed_bytes_ += input_buffer_size - available_in;
    produced_bytes_ += output_buffer_size - available_out;

    base::CheckedNumeric<size_t> safe_bytes_written(output_buffer_size);
    safe_bytes_written -= available_out;
    int bytes_written =
        base::checked_cast<int>(safe_bytes_written.ValueOrDie());

    switch (result) {
      case BROTLI_RESULT_NEEDS_MORE_OUTPUT:
      // Fall through.
      case BROTLI_RESULT_SUCCESS:
        *dest_len = bytes_written;
        stream_data_len_ = base::checked_cast<int>(available_in);
        next_stream_data_ = bit_cast<char*>(next_in);
        if (result == BROTLI_RESULT_SUCCESS) {
          decoding_status_ = DecodingStatus::DECODING_DONE;
          return Filter::FILTER_DONE;
        }
        return Filter::FILTER_OK;

      case BROTLI_RESULT_NEEDS_MORE_INPUT:
        *dest_len = bytes_written;
        stream_data_len_ = 0;
        next_stream_data_ = nullptr;
        return Filter::FILTER_NEED_MORE_DATA;

      default:
        decoding_status_ = DecodingStatus::DECODING_ERROR;
        return Filter::FILTER_ERROR;
    }
  }

 private:
  static void* AllocateMemory(void* opaque, size_t size) {
    BrotliFilter* filter = reinterpret_cast<BrotliFilter*>(opaque);
    return filter->AllocateMemoryInternal(size);
  }

  static void FreeMemory(void* opaque, void* address) {
    BrotliFilter* filter = reinterpret_cast<BrotliFilter*>(opaque);
    filter->FreeMemoryInternal(address);
  }

  void* AllocateMemoryInternal(size_t size) {
    size_t* array = reinterpret_cast<size_t*>(malloc(size + sizeof(size_t)));
    if (!array)
      return nullptr;
    used_memory_ += size;
    if (used_memory_maximum_ < used_memory_)
      used_memory_maximum_ = used_memory_;
    array[0] = size;
    return &array[1];
  }

  void FreeMemoryInternal(void* address) {
    if (!address)
      return;
    size_t* array = reinterpret_cast<size_t*>(address);
    used_memory_ -= array[-1];
    free(&array[-1]);
  }

  // Reported in UMA and must be kept in sync with the histograms.xml file.
  enum class DecodingStatus : int {
    DECODING_IN_PROGRESS = 0,
    DECODING_DONE,
    DECODING_ERROR,

    DECODING_STATUS_COUNT
    // DECODING_STATUS_COUNT must always be the last element in this enum.
  };

  // Tracks the status of decoding.
  // This variable is updated only by ReadFilteredData.
  DecodingStatus decoding_status_;

  BrotliState* brotli_state_;

  size_t used_memory_;
  size_t used_memory_maximum_;
  size_t consumed_bytes_;
  size_t produced_bytes_;

  bool gzip_header_detected_;

  DISALLOW_COPY_AND_ASSIGN(BrotliFilter);
};

Filter* CreateBrotliFilter(Filter::FilterType type_id) {
  return new BrotliFilter(type_id);
}

}  // namespace net
