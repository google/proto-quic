// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/filter/filter.h"

#include <utility>

#include "base/macros.h"
#include "net/base/io_buffer.h"
#include "net/filter/mock_filter_context.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

class PassThroughFilter : public Filter {
 public:
  PassThroughFilter() : Filter(FILTER_TYPE_UNSUPPORTED) {}

  FilterStatus ReadFilteredData(char* dest_buffer, int* dest_len) override {
    return CopyOut(dest_buffer, dest_len);
  }

  DISALLOW_COPY_AND_ASSIGN(PassThroughFilter);
};

}  // namespace

TEST(FilterTest, ContentTypeId) {
  // Check for basic translation of Content-Encoding, including case variations.
  EXPECT_EQ(Filter::FILTER_TYPE_DEFLATE,
            Filter::ConvertEncodingToType("deflate"));
  EXPECT_EQ(Filter::FILTER_TYPE_DEFLATE,
            Filter::ConvertEncodingToType("deflAte"));
  EXPECT_EQ(Filter::FILTER_TYPE_GZIP,
            Filter::ConvertEncodingToType("gzip"));
  EXPECT_EQ(Filter::FILTER_TYPE_GZIP,
            Filter::ConvertEncodingToType("GzIp"));
  EXPECT_EQ(Filter::FILTER_TYPE_GZIP,
            Filter::ConvertEncodingToType("x-gzip"));
  EXPECT_EQ(Filter::FILTER_TYPE_GZIP,
            Filter::ConvertEncodingToType("X-GzIp"));
  EXPECT_EQ(Filter::FILTER_TYPE_SDCH,
            Filter::ConvertEncodingToType("sdch"));
  EXPECT_EQ(Filter::FILTER_TYPE_SDCH,
            Filter::ConvertEncodingToType("sDcH"));
  EXPECT_EQ(Filter::FILTER_TYPE_UNSUPPORTED,
            Filter::ConvertEncodingToType("weird"));
  EXPECT_EQ(Filter::FILTER_TYPE_UNSUPPORTED,
            Filter::ConvertEncodingToType("strange"));
}

TEST(FilterTest, SdchEncoding) {
  // Handle content encodings including SDCH.
  const std::string kTextHtmlMime("text/html");
  MockFilterContext filter_context;
  // Empty handle indicates to filter that SDCH is active.
  filter_context.SetSdchResponse(
      SdchManager::CreateEmptyDictionarySetForTesting());

  std::vector<Filter::FilterType> encoding_types;

  // Check for most common encoding, and verify it survives unchanged.
  encoding_types.clear();
  encoding_types.push_back(Filter::FILTER_TYPE_SDCH);
  encoding_types.push_back(Filter::FILTER_TYPE_GZIP);
  filter_context.SetMimeType(kTextHtmlMime);
  Filter::FixupEncodingTypes(filter_context, &encoding_types);
  ASSERT_EQ(2U, encoding_types.size());
  EXPECT_EQ(Filter::FILTER_TYPE_SDCH, encoding_types[0]);
  EXPECT_EQ(Filter::FILTER_TYPE_GZIP, encoding_types[1]);

  // Unchanged even with other mime types.
  encoding_types.clear();
  encoding_types.push_back(Filter::FILTER_TYPE_SDCH);
  encoding_types.push_back(Filter::FILTER_TYPE_GZIP);
  filter_context.SetMimeType("other/type");
  Filter::FixupEncodingTypes(filter_context, &encoding_types);
  ASSERT_EQ(2U, encoding_types.size());
  EXPECT_EQ(Filter::FILTER_TYPE_SDCH, encoding_types[0]);
  EXPECT_EQ(Filter::FILTER_TYPE_GZIP, encoding_types[1]);

  // Solo SDCH is extended to include optional gunzip.
  encoding_types.clear();
  encoding_types.push_back(Filter::FILTER_TYPE_SDCH);
  Filter::FixupEncodingTypes(filter_context, &encoding_types);
  ASSERT_EQ(2U, encoding_types.size());
  EXPECT_EQ(Filter::FILTER_TYPE_SDCH, encoding_types[0]);
  EXPECT_EQ(Filter::FILTER_TYPE_GZIP_HELPING_SDCH, encoding_types[1]);
}

TEST(FilterTest, MissingSdchEncoding) {
  // Handle interesting case where entire SDCH encoding assertion "got lost."
  const std::string kTextHtmlMime("text/html");
  MockFilterContext filter_context;
  filter_context.SetSdchResponse(
      SdchManager::CreateEmptyDictionarySetForTesting());

  std::vector<Filter::FilterType> encoding_types;

  // Loss of encoding, but it was an SDCH response with html type.
  encoding_types.clear();
  filter_context.SetMimeType(kTextHtmlMime);
  Filter::FixupEncodingTypes(filter_context, &encoding_types);
  ASSERT_EQ(2U, encoding_types.size());
  EXPECT_EQ(Filter::FILTER_TYPE_SDCH_POSSIBLE, encoding_types[0]);
  EXPECT_EQ(Filter::FILTER_TYPE_GZIP_HELPING_SDCH, encoding_types[1]);

  // Loss of encoding, but it was an SDCH response with a prefix that says it
  // was an html type. Note that it *should* be the case that a precise match
  // with "text/html" we be collected by GetMimeType() and passed in, but we
  // coded the fixup defensively (scanning for a prefix of "text/html", so this
  // is an example which could survive such confusion in the caller).
  encoding_types.clear();
  filter_context.SetMimeType("text/html; charset=UTF-8");
  Filter::FixupEncodingTypes(filter_context, &encoding_types);
  ASSERT_EQ(2U, encoding_types.size());
  EXPECT_EQ(Filter::FILTER_TYPE_SDCH_POSSIBLE, encoding_types[0]);
  EXPECT_EQ(Filter::FILTER_TYPE_GZIP_HELPING_SDCH, encoding_types[1]);

  // No encoding, but it was an SDCH response with non-html type.
  encoding_types.clear();
  filter_context.SetMimeType("other/mime");
  Filter::FixupEncodingTypes(filter_context, &encoding_types);
  ASSERT_EQ(2U, encoding_types.size());
  EXPECT_EQ(Filter::FILTER_TYPE_SDCH_POSSIBLE, encoding_types[0]);
  EXPECT_EQ(Filter::FILTER_TYPE_GZIP_HELPING_SDCH, encoding_types[1]);
}

// FixupEncodingTypes() should leave gzip encoding intact.
TEST(FilterTest, Gzip) {
  const std::string kUrl("http://example.com/foo");
  MockFilterContext filter_context;
  std::vector<Filter::FilterType> encoding_types;
  filter_context.SetURL(GURL(kUrl));

  Filter::FixupEncodingTypes(filter_context, &encoding_types);
  EXPECT_EQ(0U, encoding_types.size());

  encoding_types.clear();
  encoding_types.push_back(Filter::FILTER_TYPE_GZIP);
  Filter::FixupEncodingTypes(filter_context, &encoding_types);
  ASSERT_EQ(1U, encoding_types.size());
  EXPECT_EQ(Filter::FILTER_TYPE_GZIP, encoding_types.front());
}

// Make sure a series of three pass-through filters copies the data cleanly.
// Regression test for http://crbug.com/418975.
TEST(FilterTest, ThreeFilterChain) {
  std::unique_ptr<PassThroughFilter> filter1(new PassThroughFilter);
  std::unique_ptr<PassThroughFilter> filter2(new PassThroughFilter);
  std::unique_ptr<PassThroughFilter> filter3(new PassThroughFilter);

  filter1->InitBuffer(32 * 1024);
  filter2->InitBuffer(32 * 1024);
  filter3->InitBuffer(32 * 1024);

  filter2->next_filter_ = std::move(filter3);
  filter1->next_filter_ = std::move(filter2);

  // Initialize the input array with a varying byte sequence.
  const size_t input_array_size = 64 * 1024;
  char input_array[input_array_size];
  size_t read_array_index = 0;
  for (size_t i = 0; i < input_array_size; i++) {
    input_array[i] = i % 113;
  }

  const size_t output_array_size = 4 * 1024;
  char output_array[output_array_size];

  size_t compare_array_index = 0;

  do {
    // Read data from the filter chain.
    int amount_read = output_array_size;
    Filter::FilterStatus status = filter1->ReadData(output_array, &amount_read);
    EXPECT_NE(Filter::FILTER_ERROR, status);
    EXPECT_EQ(0, memcmp(output_array, input_array + compare_array_index,
                        amount_read));
    compare_array_index += amount_read;

    // Detect the various indications that data transfer along the chain is
    // complete.
    if (Filter::FILTER_DONE == status || Filter::FILTER_ERROR == status ||
        (Filter::FILTER_OK == status && amount_read == 0) ||
        (Filter::FILTER_NEED_MORE_DATA == status &&
         read_array_index == input_array_size))
      break;

    if (Filter::FILTER_OK == status)
      continue;

    // Write needed data into the filter chain.
    ASSERT_EQ(Filter::FILTER_NEED_MORE_DATA, status);
    ASSERT_NE(0, filter1->stream_buffer_size());
    size_t amount_to_copy = std::min(
        static_cast<size_t>(filter1->stream_buffer_size()),
        input_array_size - read_array_index);
    memcpy(filter1->stream_buffer()->data(),
           input_array + read_array_index,
           amount_to_copy);
    filter1->FlushStreamBuffer(amount_to_copy);
    read_array_index += amount_to_copy;
  } while (true);

  EXPECT_EQ(read_array_index, input_array_size);
  EXPECT_EQ(compare_array_index, input_array_size);
}

}  // Namespace net
