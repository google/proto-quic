#!/usr/bin/env python
# Copyright (c) 2011 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import sys

from syscalls import syscalls


def parseEvents(z):
  calls = { }
  for e in z:
    if e['eventtype'] == 'EVENT_TYPE_SYSCALL' and e['syscall'] == 17:
      delta = e['done'] - e['ms']
      tid = e['thread']
      ms = e['ms']
      print '%f - %f - %x' % (
          delta, ms, tid)


def main():
  execfile(sys.argv[1])


if __name__ == '__main__':
  sys.exit(main())
