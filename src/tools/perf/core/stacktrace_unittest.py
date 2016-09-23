# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import tempfile
import os

from telemetry.core import exceptions
from telemetry import decorators
from telemetry.testing import tab_test_case


class TabStackTraceTest(tab_test_case.TabTestCase):

  # Stack traces do not currently work on 10.6, but they are also being
  # disabled shortly so just disable it for now.
  # All platforms except chromeos should at least have a valid minidump.
  @decorators.Disabled('snowleopard', 'chromeos')
  def testValidDump(self):
    with self.assertRaises(exceptions.DevtoolsTargetCrashException) as c:
      self._tab.Navigate('chrome://crash', timeout=5)
    self.assertTrue(c.exception.is_valid_dump)

  # Stack traces aren't working on Android yet.
  @decorators.Enabled('mac', 'linux')
  @decorators.Disabled('snowleopard')
  def testCrashSymbols(self):
    with self.assertRaises(exceptions.DevtoolsTargetCrashException) as c:
      self._tab.Navigate('chrome://crash', timeout=5)
    self.assertIn('CrashIntentionally', '\n'.join(c.exception.stack_trace))

  # Some platforms do not support full stack traces, this test requires only
  # minimal symbols to be available.
  @decorators.Enabled('mac', 'linux', 'win')
  @decorators.Disabled('snowleopard')
  def testCrashMinimalSymbols(self):
    with self.assertRaises(exceptions.DevtoolsTargetCrashException) as c:
      self._tab.Navigate('chrome://crash', timeout=5)
    self.assertIn('OnNavigate', '\n'.join(c.exception.stack_trace))

  # The breakpad file specific test only apply to platforms which use the
  # breakpad symbol format. This also must be tested in isolation because it can
  # potentially interfere with other tests symbol parsing.
  @decorators.Enabled('mac', 'linux')
  @decorators.Isolated
  def testBadBreakpadFileIgnored(self):
    # pylint: disable=protected-access
    executable_path = self._browser._browser_backend._executable
    executable = os.path.basename(executable_path)
    with tempfile.NamedTemporaryFile(mode='wt',
                                     dir=os.path.dirname(executable_path),
                                     prefix=executable + '.breakpad',
                                     delete=True) as f:
      garbage_hash = 'ABCDEF1234567'
      f.write('MODULE PLATFORM ARCH %s %s' % (garbage_hash, executable))
      f.flush()
      with self.assertRaises(exceptions.DevtoolsTargetCrashException) as c:
        self._tab.Navigate('chrome://crash', timeout=5)
      # The symbol directory should now symbols for out executable.
      tmp_dir = os.path.join(self._browser._browser_backend._tmp_minidump_dir)
      symbol_dir = os.path.join(tmp_dir, 'symbols')
      self.assertTrue(os.path.isdir(symbol_dir))

      # Bad breakpad file should not be in the symbol directory
      garbage_symbol_dir = os.path.join(symbol_dir, executable, garbage_hash)
      self.assertFalse(os.path.isdir(garbage_symbol_dir))

      # Stack trace should still work.
      self.assertIn('CrashIntentionally', '\n'.join(c.exception.stack_trace))
