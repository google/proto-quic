#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Prints "1" if Chrome targets should be built with hermetic xcode. Otherwise
prints "0"."""

import os
import sys


def _IsCorpMachine():
  return os.path.isdir('/Library/GoogleCorpSupport/')


def main():
  if os.environ.get('FORCE_MAC_TOOLCHAIN') or _IsCorpMachine():
    return "1"
  else:
    return "0"


if __name__ == '__main__':
  print main()
  sys.exit(0)
