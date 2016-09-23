# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
import tempfile
import unittest

try:
  import sqlite3  # Not present on ChromeOS.
except ImportError:
  pass


from telemetry import decorators
from profile_creators.cookie_profile_extender import CookieProfileExtender


# Testing private method.
# pylint: disable=protected-access
class CookieProfileExtenderTest(unittest.TestCase):

  def _CreateCookieTable(self, path):
    connection = sqlite3.connect(path)
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE cookies (url text)")
    connection.commit()
    connection.close()

  def _AddCookiesToTable(self, path, count):
    connection = sqlite3.connect(path)
    cursor = connection.cursor()
    for i in range(count):
      cursor.execute("INSERT INTO cookies VALUES ('%s')" % i)
    connection.commit()
    connection.close()

  @decorators.Disabled("chromeos")  # crbug.com/483212
  def testCookieCount(self):
    # Neither tempfile.TemporaryFile() nor tempfile.NamedTemporaryFile() work
    # well here. The former doesn't work at all, since it doesn't guarantee a
    # file-system visible path. The latter doesn't work well, since the
    # returned file cannot be opened a second time on Windows. The returned
    # file would have to be closed, and the method would need to be called with
    # Delete=False, which makes its functionality no simpler than
    # tempfile.mkstemp().
    handle, path = tempfile.mkstemp()
    try:
      os.close(handle)

      self._CreateCookieTable(path)
      self.assertEquals(CookieProfileExtender._CookieCountInDB(path), 0)

      self._AddCookiesToTable(path, 100)
      self.assertEquals(CookieProfileExtender._CookieCountInDB(path), 100)
    finally:
      os.remove(path)
