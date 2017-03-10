# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import common
from common import TestDriver
from common import IntegrationTest
from common import NotAndroid


class Smoke(IntegrationTest):

  # Ensure Chrome does not use DataSaver in Incognito mode.
  # Clank does not honor the --incognito flag.
  @NotAndroid
  def testCheckPageWithIncognito(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.AddChromeArg('--incognito')
      t.LoadURL('http://check.googlezip.net/test.html')
      for response in t.GetHTTPResponses():
        self.assertNotHasChromeProxyViaHeader(response)

  # Ensure Chrome uses DataSaver with QUIC enabled.
  def testCheckPageWithQuicProxy(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.AddChromeArg('--enable-quic')
      t.AddChromeArg('--data-reduction-proxy-http-proxies=https://proxy.googlezip.net:443')
      t.AddChromeArg('--force-fieldtrials=DataReductionProxyUseQuic/Enabled')
      t.LoadURL('http://check.googlezip.net/test.html')
      responses = t.GetHTTPResponses()
      self.assertEqual(2, len(responses))
      for response in responses:
        self.assertHasChromeProxyViaHeader(response)

  # Ensure pageload metric pingback with DataSaver.
  def testPingback(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.AddChromeArg('--enable-data-reduction-proxy-force-pingback')
      t.LoadURL('http://check.googlezip.net/test.html')
      t.LoadURL('http://check.googlezip.net/test.html')
      t.SleepUntilHistogramHasEntry("DataReductionProxy.Pingback.Succeeded")
      # Verify one pingback attempt that was successful.
      attempted = t.GetHistogram('DataReductionProxy.Pingback.Attempted')
      self.assertEqual(1, attempted['count'])
      succeeded = t.GetHistogram('DataReductionProxy.Pingback.Succeeded')
      self.assertEqual(1, succeeded['count'])

if __name__ == '__main__':
  IntegrationTest.RunAllTests()
