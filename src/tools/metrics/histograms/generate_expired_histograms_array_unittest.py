# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import datetime
import unittest

import generate_expired_histograms_array

_EXPECTED_HEADER_FILE_CONTENT = (
"""// Generated from generate_expired_histograms_array.py. Do not edit!

#ifndef TEST_TEST_H_
#define TEST_TEST_H_

#include <stdint.h>

namespace some_namespace {

// Contains hashes of expired histograms.
const uint64_t kExpiredHistogramsHashes[] = {
  0x965ce8e9e12a9c89,  // Test.FirstHistogram
  0xdb5b2f55ffd139e8,  // Test.SecondHistogram
};

const size_t kNumExpiredHistograms = 2;

}  // namespace some_namespace

#endif  // TEST_TEST_H_
""")

class ExpiredHistogramsTest(unittest.TestCase):

  def testGetExpiredHistograms(self):
    histograms = {
        "FirstHistogram": {
            "expiry_date": "2000/10/01"
        },
        "SecondHistogram": {
            "expiry_date": "2002/10/01"
        },
        "ThirdHistogram": {
            "expiry_date": "2001/10/01"
        },
        "FourthHistogram": {},
        "FifthHistogram": {
            "obsolete": "Has expired.",
            "expiry_date": "2000/10/01"
        }
    }

    base_date = datetime.date(2001, 10, 1)

    expired_histograms_names = (
        generate_expired_histograms_array._GetExpiredHistograms(
            histograms, base_date))

    self.assertEqual(expired_histograms_names, ["FirstHistogram"])

  def testBadExpiryDate(self):
    histograms = {
        "FirstHistogram": {
            "expiry_date": "2000/10/01"
        },
        "SecondHistogram": {
            "expiry_date": "2000-10-01"
        },
    }
    base_date = datetime.date(2000, 10, 01)

    with self.assertRaises(generate_expired_histograms_array.Error) as error:
        _ = generate_expired_histograms_array._GetExpiredHistograms(histograms,
            base_date)

    self.assertEqual(
        "Unable to parse expiry date 2000-10-01 in histogram SecondHistogram.",
        str(error.exception))


  def testGenerateHeaderFileContent(self):
    header_filename = "test/test.h"
    namespace = "some_namespace"
    hash_datatype = "uint64_t"

    histogram_map = generate_expired_histograms_array._GetHashToNameMap(
        ["Test.FirstHistogram", "Test.SecondHistogram"])
    expected_histogram_map = {
        "0x965ce8e9e12a9c89": "Test.FirstHistogram",
        "0xdb5b2f55ffd139e8": "Test.SecondHistogram",
    }
    self.assertEqual(expected_histogram_map, histogram_map)

    content = generate_expired_histograms_array._GenerateHeaderFileContent(
        header_filename, namespace, hash_datatype, histogram_map)

    self.assertEqual(_EXPECTED_HEADER_FILE_CONTENT, content)

if __name__ == "__main__":
  unittest.main()
