// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP2_TOOLS_HTTP2_RANDOM_H_
#define NET_HTTP2_TOOLS_HTTP2_RANDOM_H_

#include <stdint.h>

#include <string>

namespace net {
namespace test {

class RandomBase {
 public:
  virtual ~RandomBase() {}
  virtual bool OneIn(int n) = 0;
  virtual int32_t Uniform(int32_t n) = 0;
  virtual uint8_t Rand8() = 0;
  virtual uint16_t Rand16() = 0;
  virtual uint32_t Rand32() = 0;
  virtual uint64_t Rand64() = 0;
  virtual int32_t Next() = 0;
  virtual int32_t Skewed(int max_log) = 0;
  virtual std::string RandString(int length) = 0;
};

class Http2Random : public RandomBase {
 public:
  ~Http2Random() override {}
  bool OneIn(int n) override;
  int32_t Uniform(int32_t n) override;
  uint8_t Rand8() override;
  uint16_t Rand16() override;
  uint32_t Rand32() override;
  uint64_t Rand64() override;
  int32_t Next() override;
  int32_t Skewed(int max_log) override;
  std::string RandString(int length) override;
};

}  // namespace test
}  // namespace net

#endif  // NET_HTTP2_TOOLS_HTTP2_RANDOM_H_
