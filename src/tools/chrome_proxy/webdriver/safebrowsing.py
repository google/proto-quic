# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import common
from common import TestDriver
from common import IntegrationTest
from common import AndroidOnly
from common import NotAndroid


class SafeBrowsing(IntegrationTest):

  @AndroidOnly
  def testSafeBrowsingOn(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.LoadURL('http://testsafebrowsing.appspot.com/s/malware.html')
      responses = t.GetHTTPResponses()
      self.assertEqual(0, len(responses))

  @NotAndroid
  def testSafeBrowsingOff(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.LoadURL('http://testsafebrowsing.appspot.com/s/malware.html')
      responses = t.GetHTTPResponses()
      self.assertEqual(1, len(responses))
      for response in responses:
        self.assertHasChromeProxyViaHeader(response)

if __name__ == '__main__':
  IntegrationTest.RunAllTests()
