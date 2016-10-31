#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

import deps2submodules


class Deps2SubmodulesCollateDepsTest(unittest.TestCase):
  def testBasic(self):
    arg = ({
      'src/monkeypatch': 'http://git.chromium.org/monkepatch.git@abc123',
      'src/third_party/monkeyfood':
          'http://git.chromium.org/monkeyfood@def456',
    }, {})  # No OS-specific DEPS.
    expected = {
      'monkeypatch':
          [['all'], 'http://git.chromium.org/monkepatch.git', 'abc123'],
      'third_party/monkeyfood':
          [['all'], 'http://git.chromium.org/monkeyfood', 'def456'],
    }
    self.assertEqual(expected, deps2submodules.CollateDeps(arg))

  def testSrcPrefixStrip(self):
    arg = ({
      'src/in_src': 'http://git.chromium.org/src.git@f00bad',
      'not_in_src/foo': 'http://other.git.something/main.git@123456',
    }, {})  # No OS-specific DEPS.
    expected = {
      'in_src': [['all'], 'http://git.chromium.org/src.git', 'f00bad'],
      'not_in_src/foo':
          [['all'], 'http://other.git.something/main.git', '123456'],
    }
    self.assertEqual(expected, deps2submodules.CollateDeps(arg))

  def testOSDeps(self):
    arg = ({
      'src/hotp': 'http://hmac.org/hotp.git@7fffffff',
    }, {
      'linux': {
        'src/third_party/selinux': 'http://kernel.org/selinux.git@abc123',
        'src/multios': 'http://git.chromium.org/multi.git@000005',
      },
      'mac': {
        'src/third_party/security':
            'http://opensource.apple.com/security.git@def456',
      },
      'win': {
        'src/multios': 'http://git.chromium.org/multi.git@000005',
      },
    })
    expected = {
      'hotp': [['all'], 'http://hmac.org/hotp.git', '7fffffff'],
      'third_party/selinux':
          [['linux'], 'http://kernel.org/selinux.git', 'abc123'],
      'third_party/security':
          [['mac'], 'http://opensource.apple.com/security.git', 'def456'],
      'multios':
          [['win', 'linux'], 'http://git.chromium.org/multi.git', '000005'],
    }
    self.assertEqual(expected, deps2submodules.CollateDeps(arg))

  def testOSDepsWithNone(self):
    arg = ({
      'src/skia': 'http://git.chromium.org/skia.git@abc123',
      'src/aura': 'http://git.chromium.org/aura.git',
    }, {
      'ios': {
        'src/skia': None,
        'src/apple': 'http://git.chromium.org/apple.git@def456',
      }
    })
    expected = {
      'skia': [['all'], 'http://git.chromium.org/skia.git', 'abc123'],
      'aura': [['all'], 'http://git.chromium.org/aura.git', ''],
      'apple': [['ios'], 'http://git.chromium.org/apple.git', 'def456'],
    }
    self.assertEqual(expected, deps2submodules.CollateDeps(arg))


if __name__ == '__main__':
  unittest.main()
