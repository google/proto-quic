#!/usr/bin/env python
# Copyright 2016 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

import logging
import os
import sys
import tempfile
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(
    __file__.decode(sys.getfilesystemencoding()))))
sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, os.path.join(ROOT_DIR, 'third_party'))

from depot_tools import fix_encoding
from utils import file_path
from utils import fs
import named_cache


class CacheManagerTest(unittest.TestCase):
  def setUp(self):
    self.tempdir = tempfile.mkdtemp(prefix=u'named_cache_test')
    self.manager = named_cache.CacheManager(self.tempdir)

  def tearDown(self):
    try:
      file_path.rmtree(self.tempdir)
    finally:
      super(CacheManagerTest, self).tearDown()

  def test_request(self):
    with self.assertRaises(AssertionError):
      self.manager.request('foo')  # manager is not open
    with self.manager.open():
      foo_path = self.manager.request('foo')
      self.assertEqual(foo_path, self.manager.request('foo'))
      bar_path = self.manager.request('bar')
    self.assertEqual(
        foo_path,
        os.path.abspath(os.readlink(
            os.path.join(self.tempdir, 'named', 'foo'))))
    self.assertEqual(
        bar_path,
        os.path.abspath(os.readlink(
            os.path.join(self.tempdir, 'named', 'bar'))))
    self.assertEqual(os.path.dirname(bar_path), self.tempdir)
    self.assertEqual([], os.listdir(foo_path))
    self.assertEqual([], os.listdir(bar_path))

  def test_get_oldest(self):
    with self.manager.open():
      self.assertIsNone(self.manager.get_oldest())
      for i in xrange(10):
        self.manager.request(str(i))
      self.assertEqual(self.manager.get_oldest(), '0')

  def test_get_timestamp(self):
    now = 0
    time_fn = lambda: now
    with self.manager.open(time_fn=time_fn):
      for i in xrange(10):
        self.manager.request(str(i))
        now += 1
      for i in xrange(10):
        self.assertEqual(i, self.manager.get_timestamp(str(i)))

  def test_create_symlinks(self):
    dest_dir = tempfile.mkdtemp(prefix=u'named_cache_test')
    with self.manager.open():
      for i in xrange(10):
        self.manager.request(str(i))
      self.manager.create_symlinks(dest_dir, [('1', 'a'), ('3', 'c')])
      self.assertEqual({'a', 'c'}, set(os.listdir(dest_dir)))
      self.assertEqual(
          os.readlink(os.path.join(dest_dir, 'a')), self.manager.request('1'))
      self.assertEqual(
          os.readlink(os.path.join(dest_dir, 'c')), self.manager.request('3'))
      self.assertEqual([], os.listdir(os.path.join(dest_dir, 'c')))

  def test_trim(self):
    with self.manager.open():
      item_count = named_cache.MAX_CACHE_SIZE + 10
      for i in xrange(item_count):
        self.manager.request(str(i))
      self.assertEqual(len(self.manager), item_count)
      self.manager.trim(None)
      self.assertEqual(len(self.manager), named_cache.MAX_CACHE_SIZE)
      self.assertEqual(
          set(map(str, xrange(10, 10 + named_cache.MAX_CACHE_SIZE))),
          set(os.listdir(os.path.join(self.tempdir, 'named'))),
      )

  def test_corrupted(self):
    with open(os.path.join(self.tempdir, u'state.json'), 'w') as f:
      f.write('}}}}')
    fs.makedirs(os.path.join(self.tempdir, 'a'), 0777)
    with self.manager.open():
      self.assertFalse(os.path.isdir(self.tempdir))
      self.manager.request('a')
    self.assertTrue(fs.islink(os.path.join(self.tempdir, 'named', 'a')))


if __name__ == '__main__':
  fix_encoding.fix_encoding()
  VERBOSE = '-v' in sys.argv
  logging.basicConfig(level=logging.DEBUG if VERBOSE else logging.ERROR)
  unittest.main()
