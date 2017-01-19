# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import common
from common import TestDriver
from common import IntegrationTest


class Incognito(IntegrationTest):

  # Ensure Chrome does not use DataSaver in Incognito mode.
  def testCheckPageWithIncognito(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.AddChromeArg('--incognito')
      t.LoadURL('http://check.googlezip.net/test.html')
      for response in t.GetHTTPResponses():
        self.assertNotHasChromeProxyViaHeader(response)

if __name__ == '__main__':
  IntegrationTest.RunAllTests()
