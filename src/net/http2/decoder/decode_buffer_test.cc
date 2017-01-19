// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/decoder/decode_buffer.h"

#include <string>

#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "net/http2/tools/http2_random.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::string;

namespace net {
namespace test {

enum class TestEnumClass32 {
  kValue1 = 1,
  kValue99 = 99,
  kValue1M = 1000000,
};

enum class TestEnumClass8 {
  kValue1 = 1,
  kValue2 = 1,
  kValue99 = 99,
  kValue255 = 255,
};

enum TestEnum8 {
  kMaskLo = 0x01,
  kMaskHi = 0x80,
};

struct TestStruct {
  uint8_t f1;
  uint16_t f2;
  uint32_t f3;  // Decoded as a uint24
  uint32_t f4;
  uint32_t f5;  // Decoded as if uint31
  TestEnumClass32 f6;
  TestEnumClass8 f7;
  TestEnum8 f8;
};

const size_t kF1Offset = 0;
const size_t kF2Offset = 1;
const size_t kF3Offset = 3;
const size_t kF4Offset = 6;
const size_t kF5Offset = 10;
const size_t kF6Offset = 14;
const size_t kF7Offset = 18;
const size_t kF8Offset = 19;

class DecodeBufferTest : public ::testing::Test {
 public:
  DecodeBufferTest() {}

 protected:
  // Double checks the call fn(f).
  template <typename T>
  bool SlowDecodeField(DecodeBuffer* b,
                       size_t field_size,
                       size_t field_offset,
                       std::function<bool(DecodeBuffer*)> fn,
                       T* f) {
    VLOG(2) << "Remaining: " << b->Remaining();
    VLOG(2) << "field_size: " << field_size;
    VLOG(2) << "field_offset: " << field_offset;
    VLOG(2) << "decode_offset_: " << decode_offset_;
    EXPECT_GE(decode_offset_, field_offset);
    bool had_data = b->HasData();
    VLOG(2) << "had_data: " << had_data;
    uint32_t old = static_cast<uint32_t>(*f);
    VLOG(2) << "old: " << old;
    size_t old_decode_offset = decode_offset_;
    bool done = fn(b);
    VLOG(2) << "done: " << done;
    if (old_decode_offset == decode_offset_) {
      // Didn't do any decoding (may have no input, or may have already
      // decoded this field).
      if (done) {
        EXPECT_LE(field_offset + field_size, decode_offset_);
        // Shouldn't have modified already decoded field.
        EXPECT_EQ(old, static_cast<uint32_t>(*f));
      } else {
        EXPECT_TRUE(!had_data);
      }
    } else {
      // Did some decoding.
      EXPECT_TRUE(had_data);
      EXPECT_LT(old_decode_offset, decode_offset_);
      if (done) {
        EXPECT_EQ(field_offset + field_size, decode_offset_);
      } else {
        EXPECT_GT(field_offset + field_size, decode_offset_);
      }
    }
    VLOG(2) << "---------------------------------------";
    return done;
  }


  void SlowDecodeTestStruct(StringPiece input, TestStruct* p) {
    VLOG(2) << "############################################################";
    EXPECT_LE(10u, input.size());
    decode_offset_ = 0;
    auto decode_f1 = [this, p](DecodeBuffer* db) {
      return db->SlowDecodeUInt8(kF1Offset, &decode_offset_, &p->f1);
    };
    auto decode_f2 = [this, p](DecodeBuffer* db) {
      return db->SlowDecodeUInt16(kF2Offset, &decode_offset_, &p->f2);
    };
    auto decode_f3 = [this, p](DecodeBuffer* db) {
      return db->SlowDecodeUInt24(kF3Offset, &decode_offset_, &p->f3);
    };
    auto decode_f4 = [this, p](DecodeBuffer* db) {
      return db->SlowDecodeUInt32(kF4Offset, &decode_offset_, &p->f4);
    };
    auto decode_f5 = [this, p](DecodeBuffer* db) {
      return db->SlowDecodeUInt31(kF5Offset, &decode_offset_, &p->f5);
    };
    auto decode_f6 = [this, p](DecodeBuffer* db) {
      return db->SlowDecodeEnum(4, kF6Offset, &decode_offset_, &p->f6);
    };
    auto decode_f7 = [this, p](DecodeBuffer* db) {
      return db->SlowDecodeEnum(1, kF7Offset, &decode_offset_, &p->f7);
    };
    auto decode_f8 = [this, p](DecodeBuffer* db) {
      return db->SlowDecodeEnum(1, kF8Offset, &decode_offset_, &p->f8);
    };
    while (input.size() > 0) {
      size_t size = input.size();
      // Sometimes check that zero length input is OK.
      auto r = random_.Next();
      if (r % 100 == 0) {
        size = 0;
      } else if (size > 1) {
        auto r = random_.Next();
        size = (r % size) + 1;
      }
      VLOG(2) << "================= input size " << size;
      DecodeBuffer b(input.data(), size);
      size_t old_decode_offset = decode_offset_;
      if (SlowDecodeField(&b, 1, kF1Offset, decode_f1, &p->f1) &&
          SlowDecodeField(&b, 2, kF2Offset, decode_f2, &p->f2) &&
          SlowDecodeField(&b, 3, kF3Offset, decode_f3, &p->f3) &&
          SlowDecodeField(&b, 4, kF4Offset, decode_f4, &p->f4) &&
          SlowDecodeField(&b, 4, kF5Offset, decode_f5, &p->f5) &&
          SlowDecodeField(&b, 4, kF6Offset, decode_f6, &p->f6) &&
          SlowDecodeField(&b, 1, kF7Offset, decode_f7, &p->f7) &&
          SlowDecodeField(&b, 1, kF8Offset, decode_f8, &p->f8)) {
        EXPECT_TRUE(b.Empty());
        EXPECT_EQ(size, input.size());
        EXPECT_EQ(input.size(), b.Offset());  // All input consumed.
        return;
      }
      EXPECT_EQ(old_decode_offset + size, decode_offset_);
      EXPECT_TRUE(b.Empty());
      EXPECT_EQ(size, b.Offset());    // All input consumed.
      EXPECT_LT(size, input.size());  // More remains.
      input = StringPiece(input.data() + size, input.size() - size);
    }
    ADD_FAILURE() << "Ran out of input! decode_offset_ = " << decode_offset_;
  }

  Http2Random random_;
  uint32_t decode_offset_;
};

TEST_F(DecodeBufferTest, DecodesFixedInts) {
  const char data[] = "\x01\x12\x23\x34\x45\x56\x67\x78\x89\x9a";
  DecodeBuffer b1(data, strlen(data));
  EXPECT_EQ(1, b1.DecodeUInt8());
  EXPECT_EQ(0x1223u, b1.DecodeUInt16());
  EXPECT_EQ(0x344556u, b1.DecodeUInt24());
  EXPECT_EQ(0x6778899Au, b1.DecodeUInt32());

  DecodeBuffer b2(data, strlen(data));
  uint8_t b;
  decode_offset_ = 0;
  EXPECT_TRUE(b2.SlowDecodeUInt8(0, &decode_offset_, &b));
  EXPECT_EQ(1, b);
  uint16_t s;
  decode_offset_ = 0;
  EXPECT_TRUE(b2.SlowDecodeUInt16(0, &decode_offset_, &s));
  EXPECT_EQ(0x1223, s);
  uint32_t i;
  decode_offset_ = 0;
  EXPECT_TRUE(b2.SlowDecodeUInt24(0, &decode_offset_, &i));
  //  EXPECT_EQ(0x344556, b1.DecodeUInt24());
  //  EXPECT_EQ(0x6778899a, b1.DecodeUInt32());
}

// Decode the structure many times, where we'll pass different partitions
// into DecodeSlowly.
TEST_F(DecodeBufferTest, SlowDecodeTestStruct) {
  // clang-format off
  const char data[] = {
    0x12u,                       // f1
    0x23u, 0x34u,                // f2
    0x45u, 0x56u, 0x67u,         // f3
    0x78u, 0x89u, 0x9au, 0xabu,  // f4
    0xfeu, 0xedu, 0xdcu, 0xcbu,  // f5 (high-bit will be cleared.)
    0x00u, 0x0fu, 0x42u, 0x40u,  // f6 (kValue1M)
    0x63u,                       // f7 (kValue99)
    0x81u,                       // f8 (kMaskLo | kMaskHi)
  };
  // clang-format on
  StringPiece input(data, sizeof data);
  for (int i = 0; i < 200; ++i) {
    TestStruct ts;
    // Init the struct to random garbage.
    ts.f1 = random_.Rand8();
    ts.f2 = random_.Rand16();
    ts.f3 = random_.Rand32();
    ts.f4 = random_.Rand32();
    ts.f5 = 0x80000000 | random_.Rand32();  // Ensure high-bit is set.
    ts.f6 = static_cast<TestEnumClass32>(random_.Rand32());
    ts.f7 = static_cast<TestEnumClass8>(random_.Rand8());
    ts.f8 = static_cast<TestEnum8>(random_.Rand8());
    SlowDecodeTestStruct(input, &ts);
    ASSERT_EQ(0x12u, ts.f1);
    ASSERT_EQ(0x2334u, ts.f2);
    ASSERT_EQ(0x455667u, ts.f3);
    ASSERT_EQ(0x78899AABu, ts.f4);
    ASSERT_EQ(0x7EEDDCCBu, ts.f5);
    ASSERT_EQ(TestEnumClass32::kValue1M, ts.f6);
    ASSERT_EQ(TestEnumClass8::kValue99, ts.f7);
    ASSERT_EQ(kMaskLo | kMaskHi, ts.f8);
  }
}

// Make sure that DecodeBuffer is not copying input, just pointing into
// provided input buffer.
TEST_F(DecodeBufferTest, HasNotCopiedInput) {
  const char data[] = "ab";
  DecodeBuffer b1(data, 2);

  EXPECT_EQ(2u, b1.Remaining());
  EXPECT_EQ(0u, b1.Offset());
  EXPECT_FALSE(b1.Empty());
  EXPECT_EQ(data, b1.cursor());  // cursor points to input buffer
  EXPECT_TRUE(b1.HasData());

  b1.AdvanceCursor(1);

  EXPECT_EQ(1u, b1.Remaining());
  EXPECT_EQ(1u, b1.Offset());
  EXPECT_FALSE(b1.Empty());
  EXPECT_EQ(&data[1], b1.cursor());
  EXPECT_TRUE(b1.HasData());

  b1.AdvanceCursor(1);

  EXPECT_EQ(0u, b1.Remaining());
  EXPECT_EQ(2u, b1.Offset());
  EXPECT_TRUE(b1.Empty());
  EXPECT_EQ(&data[2], b1.cursor());
  EXPECT_FALSE(b1.HasData());

  DecodeBuffer b2(data, 0);

  EXPECT_EQ(0u, b2.Remaining());
  EXPECT_EQ(0u, b2.Offset());
  EXPECT_TRUE(b2.Empty());
  EXPECT_EQ(data, b2.cursor());
  EXPECT_FALSE(b2.HasData());
}

// DecodeBufferSubset can't go beyond the end of the base buffer.
TEST_F(DecodeBufferTest, DecodeBufferSubsetLimited) {
  const char data[] = "abc";
  DecodeBuffer base(data, 3);
  base.AdvanceCursor(1);
  DecodeBufferSubset subset(&base, 100);
  EXPECT_EQ(2u, subset.FullSize());
}

// DecodeBufferSubset advances the cursor of its base upon destruction.
TEST_F(DecodeBufferTest, DecodeBufferSubsetAdvancesCursor) {
  const char data[] = "abc";
  const size_t size = sizeof(data) - 1;
  EXPECT_EQ(3u, size);
  DecodeBuffer base(data, size);
  {
    // First no change to the cursor.
    DecodeBufferSubset subset(&base, size + 100);
    EXPECT_EQ(size, subset.FullSize());
    EXPECT_EQ(base.FullSize(), subset.FullSize());
    EXPECT_EQ(0u, subset.Offset());
  }
  EXPECT_EQ(0u, base.Offset());
  EXPECT_EQ(size, base.Remaining());
}

// Make sure that DecodeBuffer ctor complains about bad args.
#if GTEST_HAS_DEATH_TEST && !defined(NDEBUG)
TEST(DecodeBufferDeathTest, NonNullBufferRequired) {
  EXPECT_DEBUG_DEATH({ DecodeBuffer b(nullptr, 3); }, "nullptr");
}

// Make sure that DecodeBuffer ctor complains about bad args.
TEST(DecodeBufferDeathTest, ModestBufferSizeRequired) {
  EXPECT_DEBUG_DEATH(
      {
        const char data[] = "abc";
        size_t len = 0;
        DecodeBuffer b(data, ~len);
      },
      "Max.*Length");
}

// Make sure that DecodeBuffer detects advance beyond end, in debug mode.
TEST(DecodeBufferDeathTest, LimitedAdvance) {
  {
    // Advance right up to end is OK.
    const char data[] = "abc";
    DecodeBuffer b(data, 3);
    b.AdvanceCursor(3);  // OK
    EXPECT_TRUE(b.Empty());
  }
  EXPECT_DEBUG_DEATH(
      {
        // Going beyond is not OK.
        const char data[] = "abc";
        DecodeBuffer b(data, 3);
        b.AdvanceCursor(4);
      },
      "4 vs. 3");
}

// Make sure that DecodeBuffer detects decode beyond end, in debug mode.
TEST(DecodeBufferDeathTest, DecodeUInt8PastEnd) {
  const char data[] = {0x12, 0x23};
  DecodeBuffer b(data, sizeof data);
  EXPECT_EQ(2u, b.FullSize());
  EXPECT_EQ(0x1223, b.DecodeUInt16());
  EXPECT_DEBUG_DEATH({ b.DecodeUInt8(); }, "1 vs. 0");
}

// Make sure that DecodeBuffer detects decode beyond end, in debug mode.
TEST(DecodeBufferDeathTest, DecodeUInt16OverEnd) {
  const char data[] = {0x12, 0x23, 0x34};
  DecodeBuffer b(data, sizeof data);
  EXPECT_EQ(3u, b.FullSize());
  EXPECT_EQ(0x1223, b.DecodeUInt16());
  EXPECT_DEBUG_DEATH({ b.DecodeUInt16(); }, "2 vs. 1");
}

// Make sure that DecodeBuffer doesn't agree with having two subsets.
TEST(DecodeBufferSubsetDeathTest, TwoSubsets) {
  const char data[] = "abc";
  DecodeBuffer base(data, 3);
  DecodeBufferSubset subset1(&base, 1);
  EXPECT_DEBUG_DEATH({ DecodeBufferSubset subset2(&base, 1); },
                     "There is already a subset");
}

// Make sure that DecodeBufferSubset notices when the base's cursor has moved.
TEST(DecodeBufferSubsetDeathTest, BaseCursorAdvanced) {
  const char data[] = "abc";
  DecodeBuffer base(data, 3);
  base.AdvanceCursor(1);
  EXPECT_DEBUG_DEATH(
      {
        DecodeBufferSubset subset1(&base, 2);
        base.AdvanceCursor(1);
      },
      "Access via subset only when present");
}
#endif  // GTEST_HAS_DEATH_TEST && !defined(NDEBUG)

}  // namespace test
}  // namespace net
