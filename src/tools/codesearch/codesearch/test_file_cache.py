# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from __future__ import absolute_import

import unittest
import tempfile
import shutil
from .file_cache import FileCache


class TestFileCache(unittest.TestCase):

  def test_with_no_cache_dir(self):
    try:
      f = FileCache()
      f.put('foo', 'hello')
      self.assertEqual('hello', f.get('foo'))
    finally:
      f.close()

  def test_with_cache_dir(self):
    f = None
    g = None
    test_dir = None
    try:
      test_dir = tempfile.mkdtemp()
      f = FileCache(cache_dir=test_dir)
      f.put('foo', 'hello')
      f.close()
      f = None

      g = FileCache(cache_dir=test_dir)
      self.assertEqual('hello', g.get('foo'))
      g.close()
      g = None
    finally:
      if f:
        f.close()
      if g:
        g.close()
      if test_dir:
        shutil.rmtree(test_dir)


if __name__ == '__main__':
  unittest.main()
