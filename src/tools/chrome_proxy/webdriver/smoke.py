# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import common
from common import TestDriver
from common import IntegrationTest


class Smoke(IntegrationTest):

  # Ensure Chrome does not use DataSaver in Incognito mode.
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

if __name__ == '__main__':
  IntegrationTest.RunAllTests()
