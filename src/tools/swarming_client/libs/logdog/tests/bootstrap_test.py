#!/usr/bin/env python
# Copyright 2016 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

import os
import sys
import unittest

ROOT_DIR = os.path.dirname(os.path.abspath(os.path.join(
    __file__.decode(sys.getfilesystemencoding()),
    os.pardir, os.pardir, os.pardir)))
sys.path.insert(0, ROOT_DIR)

from libs.logdog import bootstrap


class BootstrapTestCase(unittest.TestCase):

  def setUp(self):
    self.env = {
        bootstrap.ButlerBootstrap._ENV_PROJECT: 'test-project',
        bootstrap.ButlerBootstrap._ENV_PREFIX: 'foo/bar',
        bootstrap.ButlerBootstrap._ENV_STREAM_SERVER_PATH: 'fake:path',
    }

  def testProbeSucceeds(self):
    bs = bootstrap.ButlerBootstrap.probe(self.env)
    self.assertEqual(bs, bootstrap.ButlerBootstrap(
      project='test-project',
      prefix='foo/bar',
      streamserver_uri='fake:path'))

  def testProbeNoBootstrapRaisesError(self):
    self.assertRaises(bootstrap.NotBootstrappedError,
        bootstrap.ButlerBootstrap.probe, env={})

  def testProbeMissingProjectRaisesError(self):
    self.env.pop(bootstrap.ButlerBootstrap._ENV_PROJECT)
    self.assertRaises(bootstrap.NotBootstrappedError,
        bootstrap.ButlerBootstrap.probe, env=self.env)

  def testProbeMissingPrefixRaisesError(self):
    self.env.pop(bootstrap.ButlerBootstrap._ENV_PREFIX)
    self.assertRaises(bootstrap.NotBootstrappedError,
        bootstrap.ButlerBootstrap.probe, env=self.env)

  def testProbeInvalidPrefixRaisesError(self):
    self.env[bootstrap.ButlerBootstrap._ENV_PREFIX] = '!!! not valid !!!'
    self.assertRaises(bootstrap.NotBootstrappedError,
        bootstrap.ButlerBootstrap.probe, env=self.env)


if __name__ == '__main__':
  unittest.main()
