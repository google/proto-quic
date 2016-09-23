#!/usr/bin/env python
# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Verifies that the histograms XML file is well-formatted."""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'common'))
import path_util

import extract_histograms

def main():
  # This will raise an exception if the file is not well-formatted.
  xml_file = path_util.GetHistogramsFile()
  histograms = extract_histograms.ExtractHistograms(xml_file)


if __name__ == '__main__':
  main()

