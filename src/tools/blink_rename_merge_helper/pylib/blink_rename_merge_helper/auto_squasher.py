#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Simple utility to help squash multiple commits into one."""

import sys


def main():
  with open(sys.argv[1], 'r+') as f:
    lines = f.readlines()
    for i, line in enumerate(lines):
      if i:
        if line.startswith('pick '):
          lines[i] = line.replace('pick ', 'squash ', 1)
    f.seek(0)
    f.truncate()
    f.write('\n'.join(lines))


if __name__ == '__main__':
  sys.exit(main())
