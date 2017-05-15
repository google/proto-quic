#!/usr/bin/python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os.path
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import processor


def GetIncludes(inputs):
  includes = set()
  for f in inputs:
    includes.update(processor.Processor(f).included_files)
  return includes


if __name__ == "__main__":
  # TODO(dpapad): Dedup inputs in ninja files, using relative paths with respect
  # to the out directory.
  print "\n".join(GetIncludes(sys.argv[1:]))
