// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/iovector.h"

#include <string.h>

#include <memory>
#include <string>

#include "net/test/gtest_util.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::string;

namespace net {
namespace test {
namespace {

const char* const test_data[] = {
    "test string 1, a medium size one.", "test string2",
    "test string      3, a looooooooooooong loooooooooooooooong string"};

TEST(IOVectorTest, CopyConstructor) {
  IOVector iov1;
  for (size_t i = 0; i < arraysize(test_data); ++i) {
    iov1.Append(const_cast<char*>(test_data[i]), strlen(test_data[i]));
  }
  IOVector iov2 = iov1;
  EXPECT_EQ(iov2.Size(), iov1.Size());
  for (size_t i = 0; i < iov2.Size(); ++i) {
    EXPECT_TRUE(iov2.iovec()[i].iov_base == iov1.iovec()[i].iov_base);
    EXPECT_EQ(iov2.iovec()[i].iov_len, iov1.iovec()[i].iov_len);
  }
  EXPECT_EQ(iov2.TotalBufferSize(), iov1.TotalBufferSize());
}

TEST(IOVectorTest, AssignmentOperator) {
  IOVector iov1;
  for (size_t i = 0; i < arraysize(test_data); ++i) {
    iov1.Append(const_cast<char*>(test_data[i]), strlen(test_data[i]));
  }
  IOVector iov2;
  iov2.Append(const_cast<char*>("ephemeral string"), 16);
  // The following assignment results in a shallow copy;
  // both IOVectors point to the same underlying data.
  iov2 = iov1;
  EXPECT_EQ(iov2.Size(), iov1.Size());
  for (size_t i = 0; i < iov2.Size(); ++i) {
    EXPECT_TRUE(iov2.iovec()[i].iov_base == iov1.iovec()[i].iov_base);
    EXPECT_EQ(iov2.iovec()[i].iov_len, iov1.iovec()[i].iov_len);
  }
  EXPECT_EQ(iov2.TotalBufferSize(), iov1.TotalBufferSize());
}

TEST(IOVectorTest, Append) {
  IOVector iov;
  int length = 0;
  const struct iovec* iov2 = iov.iovec();

  ASSERT_EQ(0u, iov.Size());
  ASSERT_TRUE(iov2 == nullptr);
  for (size_t i = 0; i < arraysize(test_data); ++i) {
    const int str_len = strlen(test_data[i]);
    const int append_len = str_len / 2;
    // This should append a new block.
    iov.Append(const_cast<char*>(test_data[i]), append_len);
    length += append_len;
    ASSERT_EQ(i + 1, static_cast<size_t>(iov.Size()));
    ASSERT_TRUE(iov.LastBlockEnd() == test_data[i] + append_len);
    // This should just lengthen the existing block.
    iov.Append(const_cast<char*>(test_data[i] + append_len),
               str_len - append_len);
    length += (str_len - append_len);
    ASSERT_EQ(i + 1, static_cast<size_t>(iov.Size()));
    ASSERT_TRUE(iov.LastBlockEnd() == test_data[i] + str_len);
  }

  iov2 = iov.iovec();
  ASSERT_TRUE(iov2 != nullptr);
  for (size_t i = 0; i < iov.Size(); ++i) {
    ASSERT_TRUE(test_data[i] == iov2[i].iov_base);
    ASSERT_EQ(strlen(test_data[i]), iov2[i].iov_len);
  }
}

TEST(IOVectorTest, AppendIovec) {
  IOVector iov;
  const struct iovec test_iov[] = {{const_cast<char*>("foo"), 3},
                                   {const_cast<char*>("bar"), 3},
                                   {const_cast<char*>("buzzzz"), 6}};
  iov.AppendIovec(test_iov, arraysize(test_iov));
  for (size_t i = 0; i < arraysize(test_iov); ++i) {
    EXPECT_EQ(test_iov[i].iov_base, iov.iovec()[i].iov_base);
    EXPECT_EQ(test_iov[i].iov_len, iov.iovec()[i].iov_len);
  }

  // Test AppendIovecAtMostBytes.
  iov.Clear();
  // Stop in the middle of a block.
  EXPECT_EQ(5u, iov.AppendIovecAtMostBytes(test_iov, arraysize(test_iov), 5));
  EXPECT_EQ(5u, iov.TotalBufferSize());
  iov.Append(static_cast<char*>(test_iov[1].iov_base) + 2, 1);
  // Make sure the boundary case, where max_bytes == size of block also works.
  EXPECT_EQ(6u, iov.AppendIovecAtMostBytes(&test_iov[2], 1, 6));
  ASSERT_LE(arraysize(test_iov), static_cast<size_t>(iov.Size()));
  for (size_t i = 0; i < arraysize(test_iov); ++i) {
    EXPECT_EQ(test_iov[i].iov_base, iov.iovec()[i].iov_base);
    EXPECT_EQ(test_iov[i].iov_len, iov.iovec()[i].iov_len);
  }
}

TEST(IOVectorTest, ConsumeHalfBlocks) {
  IOVector iov;
  int length = 0;

  for (size_t i = 0; i < arraysize(test_data); ++i) {
    const int str_len = strlen(test_data[i]);
    iov.Append(const_cast<char*>(test_data[i]), str_len);
    length += str_len;
  }
  const char* endp = iov.LastBlockEnd();
  for (size_t i = 0; i < arraysize(test_data); ++i) {
    const struct iovec* iov2 = iov.iovec();
    const size_t str_len = strlen(test_data[i]);
    size_t tmp = str_len / 2;

    ASSERT_TRUE(iov2 != nullptr);
    ASSERT_TRUE(iov2[0].iov_base == test_data[i]);
    ASSERT_EQ(str_len, iov2[0].iov_len);

    // Consume half of the first block.
    size_t consumed = iov.Consume(tmp);
    ASSERT_EQ(tmp, consumed);
    ASSERT_EQ(arraysize(test_data) - i, static_cast<size_t>(iov.Size()));
    iov2 = iov.iovec();
    ASSERT_TRUE(iov2 != nullptr);
    ASSERT_TRUE(iov2[0].iov_base == test_data[i] + tmp);
    ASSERT_EQ(iov2[0].iov_len, str_len - tmp);

    // Consume the rest of the first block.
    consumed = iov.Consume(str_len - tmp);
    ASSERT_EQ(str_len - tmp, consumed);
    ASSERT_EQ(arraysize(test_data) - i - 1, static_cast<size_t>(iov.Size()));
    iov2 = iov.iovec();
    if (iov.Size() > 0) {
      ASSERT_TRUE(iov2 != nullptr);
      ASSERT_TRUE(iov.LastBlockEnd() == endp);
    } else {
      ASSERT_TRUE(iov2 == nullptr);
      ASSERT_TRUE(iov.LastBlockEnd() == nullptr);
    }
  }
}

TEST(IOVectorTest, ConsumeTwoAndHalfBlocks) {
  IOVector iov;
  int length = 0;

  for (size_t i = 0; i < arraysize(test_data); ++i) {
    const int str_len = strlen(test_data[i]);
    iov.Append(const_cast<char*>(test_data[i]), str_len);
    length += str_len;
  }
  const size_t last_len = strlen(test_data[arraysize(test_data) - 1]);
  const size_t half_len = last_len / 2;

  const char* endp = iov.LastBlockEnd();
  size_t consumed = iov.Consume(length - half_len);
  ASSERT_EQ(length - half_len, consumed);
  const struct iovec* iov2 = iov.iovec();
  ASSERT_TRUE(iov2 != nullptr);
  ASSERT_EQ(1u, iov.Size());
  ASSERT_TRUE(iov2[0].iov_base ==
              test_data[arraysize(test_data) - 1] + last_len - half_len);
  ASSERT_EQ(half_len, iov2[0].iov_len);
  ASSERT_TRUE(iov.LastBlockEnd() == endp);

  consumed = iov.Consume(half_len);
  ASSERT_EQ(half_len, consumed);
  iov2 = iov.iovec();
  ASSERT_EQ(0u, iov.Size());
  ASSERT_TRUE(iov2 == nullptr);
  ASSERT_TRUE(iov.LastBlockEnd() == nullptr);
}

TEST(IOVectorTest, ConsumeTooMuch) {
  IOVector iov;
  int length = 0;

  for (size_t i = 0; i < arraysize(test_data); ++i) {
    const int str_len = strlen(test_data[i]);
    iov.Append(const_cast<char*>(test_data[i]), str_len);
    length += str_len;
  }

  int consumed = 0;
  EXPECT_DFATAL({ consumed = iov.Consume(length + 1); },
                "Attempting to consume 1 non-existent bytes.");
  ASSERT_EQ(length, consumed);
  const struct iovec* iov2 = iov.iovec();
  ASSERT_EQ(0u, iov.Size());
  ASSERT_TRUE(iov2 == nullptr);
  ASSERT_TRUE(iov.LastBlockEnd() == nullptr);
}

TEST(IOVectorTest, ConsumeAndCopyHalfBlocks) {
  IOVector iov;
  int length = 0;

  for (size_t i = 0; i < arraysize(test_data); ++i) {
    const int str_len = strlen(test_data[i]);
    iov.Append(const_cast<char*>(test_data[i]), str_len);
    length += str_len;
  }
  const char* endp = iov.LastBlockEnd();
  for (size_t i = 0; i < arraysize(test_data); ++i) {
    const struct iovec* iov2 = iov.iovec();
    const size_t str_len = strlen(test_data[i]);
    size_t tmp = str_len / 2;

    ASSERT_TRUE(iov2 != nullptr);
    ASSERT_TRUE(iov2[0].iov_base == test_data[i]);
    ASSERT_EQ(str_len, iov2[0].iov_len);

    // Consume half of the first block.
    std::unique_ptr<char[]> buffer(new char[str_len]);
    size_t consumed = iov.ConsumeAndCopy(tmp, buffer.get());
    EXPECT_EQ(0, memcmp(test_data[i], buffer.get(), tmp));
    ASSERT_EQ(tmp, consumed);
    ASSERT_EQ(arraysize(test_data) - i, static_cast<size_t>(iov.Size()));
    iov2 = iov.iovec();
    ASSERT_TRUE(iov2 != nullptr);
    ASSERT_TRUE(iov2[0].iov_base == test_data[i] + tmp);
    ASSERT_EQ(iov2[0].iov_len, str_len - tmp);

    // Consume the rest of the first block.
    consumed = iov.ConsumeAndCopy(str_len - tmp, buffer.get());
    ASSERT_EQ(str_len - tmp, consumed);
    ASSERT_EQ(arraysize(test_data) - i - 1, static_cast<size_t>(iov.Size()));
    iov2 = iov.iovec();
    if (iov.Size() > 0) {
      ASSERT_TRUE(iov2 != nullptr);
      ASSERT_TRUE(iov.LastBlockEnd() == endp);
    } else {
      ASSERT_TRUE(iov2 == nullptr);
      ASSERT_TRUE(iov.LastBlockEnd() == nullptr);
    }
  }
}

TEST(IOVectorTest, ConsumeAndCopyTwoAndHalfBlocks) {
  IOVector iov;
  size_t length = 0;

  for (size_t i = 0; i < arraysize(test_data); ++i) {
    const int str_len = strlen(test_data[i]);
    iov.Append(const_cast<char*>(test_data[i]), str_len);
    length += str_len;
  }
  const size_t last_len = strlen(test_data[arraysize(test_data) - 1]);
  const size_t half_len = last_len / 2;

  const char* endp = iov.LastBlockEnd();
  std::unique_ptr<char[]> buffer(new char[length]);
  size_t consumed = iov.ConsumeAndCopy(length - half_len, buffer.get());
  ASSERT_EQ(length - half_len, consumed);
  const struct iovec* iov2 = iov.iovec();
  ASSERT_TRUE(iov2 != nullptr);
  ASSERT_EQ(1u, iov.Size());
  ASSERT_TRUE(iov2[0].iov_base ==
              test_data[arraysize(test_data) - 1] + last_len - half_len);
  ASSERT_EQ(half_len, iov2[0].iov_len);
  ASSERT_TRUE(iov.LastBlockEnd() == endp);

  consumed = iov.Consume(half_len);
  ASSERT_EQ(half_len, consumed);
  iov2 = iov.iovec();
  ASSERT_EQ(0u, iov.Size());
  ASSERT_TRUE(iov2 == nullptr);
  ASSERT_TRUE(iov.LastBlockEnd() == nullptr);
}

TEST(IOVectorTest, ConsumeAndCopyTooMuch) {
  IOVector iov;
  int length = 0;

  for (size_t i = 0; i < arraysize(test_data); ++i) {
    const int str_len = strlen(test_data[i]);
    iov.Append(const_cast<char*>(test_data[i]), str_len);
    length += str_len;
  }

  int consumed = 0;
  std::unique_ptr<char[]> buffer(new char[length + 1]);
  EXPECT_DFATAL({ consumed = iov.ConsumeAndCopy(length + 1, buffer.get()); },
                "Attempting to consume 1 non-existent bytes.");
  ASSERT_EQ(length, consumed);
  const struct iovec* iov2 = iov.iovec();
  ASSERT_EQ(0u, iov.Size());
  ASSERT_TRUE(iov2 == nullptr);
  ASSERT_TRUE(iov.LastBlockEnd() == nullptr);
}

TEST(IOVectorTest, Clear) {
  IOVector iov;
  int length = 0;

  for (size_t i = 0; i < arraysize(test_data); ++i) {
    const int str_len = strlen(test_data[i]);
    iov.Append(const_cast<char*>(test_data[i]), str_len);
    length += str_len;
  }
  const struct iovec* iov2 = iov.iovec();
  ASSERT_TRUE(iov2 != nullptr);
  ASSERT_EQ(arraysize(test_data), static_cast<size_t>(iov.Size()));

  iov.Clear();
  iov2 = iov.iovec();
  ASSERT_EQ(0u, iov.Size());
  ASSERT_TRUE(iov2 == nullptr);
}

TEST(IOVectorTest, Capacity) {
  IOVector iov;
  // Note: IOVector merges adjacent Appends() into a single iov.
  // Therefore, if we expect final size of iov to be 3, we must insure
  // that the items we are appending are not adjacent. To achieve that
  // we use use an array (a[1] provides a buffer between a[0] and b[0],
  // and makes them non-adjacent).
  char a[2], b[2], c[2];
  iov.Append(&a[0], 1);
  iov.Append(&b[0], 1);
  iov.Append(&c[0], 1);
  ASSERT_EQ(3u, iov.Size());
  size_t capacity = iov.Capacity();
  EXPECT_LE(iov.Size(), capacity);
  iov.Consume(2);
  // The capacity should not have changed.
  EXPECT_EQ(capacity, iov.Capacity());
}

TEST(IOVectorTest, Swap) {
  IOVector iov1, iov2;
  // See IOVector merge comment above.
  char a[2], b[2], c[2], d[2], e[2];
  iov1.Append(&a[0], 1);
  iov1.Append(&b[0], 1);

  iov2.Append(&c[0], 1);
  iov2.Append(&d[0], 1);
  iov2.Append(&e[0], 1);
  iov1.Swap(&iov2);

  ASSERT_EQ(3u, iov1.Size());
  EXPECT_EQ(&c[0], iov1.iovec()[0].iov_base);
  EXPECT_EQ(1u, iov1.iovec()[0].iov_len);
  EXPECT_EQ(&d[0], iov1.iovec()[1].iov_base);
  EXPECT_EQ(1u, iov1.iovec()[1].iov_len);
  EXPECT_EQ(&e[0], iov1.iovec()[2].iov_base);
  EXPECT_EQ(1u, iov1.iovec()[2].iov_len);

  ASSERT_EQ(2u, iov2.Size());
  EXPECT_EQ(&a[0], iov2.iovec()[0].iov_base);
  EXPECT_EQ(1u, iov2.iovec()[0].iov_len);
  EXPECT_EQ(&b[0], iov2.iovec()[1].iov_base);
  EXPECT_EQ(1u, iov2.iovec()[1].iov_len);
}

}  // namespace
}  // namespace test
}  // namespace net
