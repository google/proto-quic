// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/gtest_xml_unittest_result_printer.h"

#include "base/base64.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/time/time.h"

namespace base {

XmlUnitTestResultPrinter::XmlUnitTestResultPrinter() : output_file_(NULL) {
}

XmlUnitTestResultPrinter::~XmlUnitTestResultPrinter() {
  if (output_file_) {
    fprintf(output_file_, "</testsuites>\n");
    fflush(output_file_);
    CloseFile(output_file_);
  }
}

bool XmlUnitTestResultPrinter::Initialize(const FilePath& output_file_path) {
  DCHECK(!output_file_);
  output_file_ = OpenFile(output_file_path, "w");
  if (!output_file_)
    return false;

  fprintf(output_file_,
          "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n");
  fflush(output_file_);

  return true;
}

void XmlUnitTestResultPrinter::OnTestCaseStart(
    const testing::TestCase& test_case) {
  fprintf(output_file_, "  <testsuite>\n");
  fflush(output_file_);
}

void XmlUnitTestResultPrinter::OnTestStart(
    const testing::TestInfo& test_info) {
  // This is our custom extension - it helps to recognize which test was
  // running when the test binary crashed. Note that we cannot even open the
  // <testcase> tag here - it requires e.g. run time of the test to be known.
  fprintf(output_file_,
          "    <x-teststart name=\"%s\" classname=\"%s\" />\n",
          test_info.name(),
          test_info.test_case_name());
  fflush(output_file_);
}

void XmlUnitTestResultPrinter::OnTestEnd(const testing::TestInfo& test_info) {
  fprintf(output_file_,
          "    <testcase name=\"%s\" status=\"run\" time=\"%.3f\""
          " classname=\"%s\">\n",
          test_info.name(),
          static_cast<double>(test_info.result()->elapsed_time()) /
              Time::kMillisecondsPerSecond,
          test_info.test_case_name());
  if (test_info.result()->Failed()) {
    fprintf(output_file_,
            "      <failure message=\"\" type=\"\"></failure>\n");
  }
  for (int i = 0; i < test_info.result()->total_part_count(); ++i) {
    WriteTestPartResult(test_info.result()->GetTestPartResult(i));
  }
  fprintf(output_file_, "    </testcase>\n");
  fflush(output_file_);
}

void XmlUnitTestResultPrinter::OnTestCaseEnd(
    const testing::TestCase& test_case) {
  fprintf(output_file_, "  </testsuite>\n");
  fflush(output_file_);
}

void XmlUnitTestResultPrinter::WriteTestPartResult(
    const testing::TestPartResult& test_part_result) {
  const char* type = "unknown";
  switch (test_part_result.type()) {
    case testing::TestPartResult::kSuccess:
      type = "success";
      break;
    case testing::TestPartResult::kNonFatalFailure:
      type = "failure";
      break;
    case testing::TestPartResult::kFatalFailure:
      type = "fatal_failure";
      break;
  }
  std::string summary = test_part_result.summary();
  std::string summary_encoded;
  Base64Encode(summary, &summary_encoded);
  std::string message = test_part_result.message();
  std::string message_encoded;
  Base64Encode(message, &message_encoded);
  fprintf(output_file_,
          "      <x-test-result-part type=\"%s\" file=\"%s\" line=\"%d\">\n"
          "        <summary>%s</summary>\n"
          "        <message>%s</message>\n"
          "      </x-test-result-part>\n",
          type, test_part_result.file_name(), test_part_result.line_number(),
          summary_encoded.c_str(), message_encoded.c_str());
  fflush(output_file_);
}

}  // namespace base
