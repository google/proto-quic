# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

import fieldtrial_util
import os
import tempfile


class FieldTrialUtilUnittest(unittest.TestCase):

  def runGenerateArgs(self, config):
    result = None
    with tempfile.NamedTemporaryFile('w', delete=False) as base_file:
      try:
        base_file.write(config)
        base_file.close()
        result = fieldtrial_util.GenerateArgs(base_file.name)
      finally:
        os.unlink(base_file.name)
    return result

  def test_GenArgsEmptyPaths(self):
    args = fieldtrial_util.GenerateArgs('')
    self.assertEqual([], args)

  def test_GenArgsOneConfig(self):
    config = '''{
      "BrowserBlackList": [
        { "group_name": "Enabled" }
      ],
      "c": [
        {
          "group_name": "d.",
          "params": {"url": "http://www.google.com"},
          "enable_features": ["x"],
          "disable_features": ["y"]
        }
      ],
      "SimpleParams": [
        {
          "group_name": "Default",
          "params": {"id": "abc"},
          "enable_features": ["a", "b"]
        }
      ]
    }'''
    result = self.runGenerateArgs(config)
    self.assertEqual(['--force-fieldtrials='
        'BrowserBlackList/Enabled/c/d./SimpleParams/Default',
        '--force-fieldtrial-params='
        'c.d%2E:url/http%3A%2F%2Fwww%2Egoogle%2Ecom,'
        'SimpleParams.Default:id/abc',
        '--enable-features=x,a,b',
        '--disable-features=y'], result)

  def test_DuplicateEnableFeatures(self):
    config = '''{
      "X": [
        {
          "group_name": "x",
          "enable_features": ["x"]
        }
      ],
      "Y": [
        {
          "group_name": "Default",
          "enable_features": ["x", "y"]
        }
      ]
    }'''
    with self.assertRaises(Exception) as raised:
      self.runGenerateArgs(config)
    self.assertEqual('Duplicate feature(s) in enable_features: x',
                     str(raised.exception))

  def test_DuplicateDisableFeatures(self):
    config = '''{
      "X": [
        {
          "group_name": "x",
          "enable_features": ["y", "z"]
        }
      ],
      "Y": [
        {
          "group_name": "Default",
          "enable_features": ["z", "x", "y"]
        }
      ]
    }'''
    with self.assertRaises(Exception) as raised:
      self.runGenerateArgs(config)
    self.assertEqual('Duplicate feature(s) in enable_features: y, z',
                     str(raised.exception))


  def test_DuplicateEnableDisable(self):
    config = '''{
      "X": [
        {
          "group_name": "x",
          "enable_features": ["x"]
        }
      ],
      "Y": [
        {
          "group_name": "Default",
          "disable_features": ["x", "y"]
        }
      ]
    }'''
    with self.assertRaises(Exception) as raised:
      self.runGenerateArgs(config)
    self.assertEqual('Conflicting features set as both enabled and disabled: x',
                     str(raised.exception))

if __name__ == '__main__':
  unittest.main()