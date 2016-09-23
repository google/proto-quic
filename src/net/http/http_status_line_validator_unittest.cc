// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_status_line_validator.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

using Status = HttpStatusLineValidator::StatusLineStatus;

struct ValidatorTestData {
  const char* name;
  const char* status_line;
  const Status expected_status;
};

class ValidatorTest : public ::testing::Test,
                      public ::testing::WithParamInterface<ValidatorTestData> {
 public:
  ValidatorTest() {}
  ~ValidatorTest() override {}
};

std::string TestName(testing::TestParamInfo<ValidatorTestData> info) {
  return info.param.name;
}

TEST_P(ValidatorTest, Validate) {
  const ValidatorTestData test = GetParam();

  EXPECT_EQ(HttpStatusLineValidator::ValidateStatusLine(test.status_line),
            test.expected_status);
}

const ValidatorTestData validator_tests[] = {
    {"Http10_Ok", "HTTP/1.0 200 OK", Status::STATUS_LINE_OK},
    {"Http11_Ok", "HTTP/1.1 200 OK", Status::STATUS_LINE_OK},
    {"Empty", "", Status::STATUS_LINE_EMPTY},
    {"NotHttp", "xyzzy", Status::STATUS_LINE_NOT_HTTP},
    {"CaseMismatch", "HtTp/1.1 200 OK", Status::STATUS_LINE_HTTP_CASE_MISMATCH},
    {"NoVersion", "HTTP 200 OK", Status::STATUS_LINE_HTTP_NO_VERSION},
    {"InvalidVersion_0", "HTTP/a.b 200 OK",
     Status::STATUS_LINE_INVALID_VERSION},
    {"InvalidVersion_1", "HTTP/1.a 200 OK",
     Status::STATUS_LINE_INVALID_VERSION},
    {"InvalidVersion_2", "HTTP/a.1 200 OK",
     Status::STATUS_LINE_INVALID_VERSION},
    {"InvalidVersion_3", "HTTP/1 200 OK", Status::STATUS_LINE_INVALID_VERSION},
    {"InvalidVersion_4", "HTTP/1. 200 OK", Status::STATUS_LINE_INVALID_VERSION},
    {"MultiDigit_0", "HTTP/10.0 200 OK",
     Status::STATUS_LINE_MULTI_DIGIT_VERSION},
    {"MultiDigit_1", "HTTP/1.00 200 OK",
     Status::STATUS_LINE_MULTI_DIGIT_VERSION},
    {"UnknownVersion_0", "HTTP/1.2 200 OK",
     Status::STATUS_LINE_UNKNOWN_VERSION},
    {"UnknownVersion_1", "HTTP/2.0 200 OK",
     Status::STATUS_LINE_UNKNOWN_VERSION},
    {"Explicit09", "HTTP/0.9 200 OK", Status::STATUS_LINE_EXPLICIT_0_9},
    {"MissingStatusCode", "HTTP/1.0", Status::STATUS_LINE_MISSING_STATUS_CODE},
    {"InvalidStatusCode_0", "HTTP/1.0 abc OK",
     Status::STATUS_LINE_INVALID_STATUS_CODE},
    {"InvalidStatusCode_1", "HTTP/1.0 17 OK",
     Status::STATUS_LINE_INVALID_STATUS_CODE},
    {"StatusCodeTrailing", "HTTP/1.0 200a OK",
     Status::STATUS_LINE_STATUS_CODE_TRAILING},
    {"MissingReasonPhrase", "HTTP/1.0 200",
     Status::STATUS_LINE_MISSING_REASON_PHRASE},
    {"EmptyReasonPhrase_Ok", "HTTP/1.0 200 ", Status::STATUS_LINE_OK},
    {"ReasonDisallowedCharacter", "HTTP/1.0 200 OK\x01",
     Status::STATUS_LINE_REASON_DISALLOWED_CHARACTER},
    {"ExcessWhitespace", "HTTP/1.0  200 OK",
     Status::STATUS_LINE_EXCESS_WHITESPACE},
    {"ReasonWhitespace_Ok", "HTTP/1.0 200  OK", Status::STATUS_LINE_OK},
    {"ReservedStatusCode_0", "HTTP/1.0 099 OK",
     Status::STATUS_LINE_RESERVED_STATUS_CODE},
    {"ReservedStatusCode_1", "HTTP/1.0 600 OK",
     Status::STATUS_LINE_RESERVED_STATUS_CODE}};

INSTANTIATE_TEST_CASE_P(HttpStatusLineValidator,
                        ValidatorTest,
                        testing::ValuesIn(validator_tests),
                        TestName);

}  // namespace
}  // namespace net
