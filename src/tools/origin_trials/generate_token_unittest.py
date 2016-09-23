#!/usr/bin/env python
# Copyright (c) 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Tests for generate_token.py"""

import argparse
import generate_token
import unittest


class GenerateTokenTest(unittest.TestCase):

  def test_hostname_validation(self):
    for hostname, expected_result in [
        ("", None),
        (None, None),
        ("example.com", "example.com"),
        ("127.0.0.1", "127.0.0.1"),
        ("localhost", "localhost"),
        ("example.com.", "example.com"),
        ("ExAmPlE.coM", "example.com"),
        (".example.com", None),
        ("example..com", None),
        ("example123.com", "example123.com"),
        ("123example.com", "123example.com"),
        ("a.com", "a.com"),
        ("1.com", "1.com"),
        ("-.com", None),
        ("aa.com", "aa.com"),
        ("a1.com", "a1.com"),
        ("a-.com", None),
        ("-a.com", None),
        ("123-example.com", "123-example.com"),
        ("-123example.com", None),
        ("123example-.com", None),
        (("a"*63)+".com", ("a"*63)+".com"),
        (("a"*64)+".com", None),
        (".".join([("a"*15)]*16), ".".join([("a"*15)]*16)),
        (".".join([("a"*15)]*17), None)]:
      self.assertEqual(generate_token.HostnameFromArg(hostname),
                       expected_result)

  def test_origin_constructed_correctly(self):
    for origin_arg, expected_result in [
        ("example.com", "https://example.com:443"),
        ("https://example.com", "https://example.com:443"),
        ("https://example.com/", "https://example.com:443"),
        ("http://example.com", "http://example.com:80"),
        ("http://127.0.0.1:8000", "http://127.0.0.1:8000"),
        ("http://user:pass@example.com/path", "http://example.com:80")]:
      self.assertEqual(generate_token.OriginFromArg(origin_arg),
                       expected_result)

  def test_origin_fails_correctly(self):
    for invalid_hostname in [
        "example..com",
        "gopher://gopher.tc.umn.edu",
        "https://",
        "https://example.com:NaN/",
        "Not even close"]:
      self.assertRaises(argparse.ArgumentTypeError,
                        generate_token.OriginFromArg,
                        invalid_hostname)

if __name__ == '__main__':
  unittest.main()
