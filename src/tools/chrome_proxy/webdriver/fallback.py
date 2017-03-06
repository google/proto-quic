# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import common
from common import TestDriver
from common import IntegrationTest

class Fallback(IntegrationTest):

  # Ensure that when a carrier blocks using the secure proxy, requests fallback
  # to the HTTP proxy server.
  def testSecureProxyProbeFallback(self):
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')

      # Set the secure proxy check URL to the google.com favicon, which will be
      # interpreted as a secure proxy check failure since the response body is
      # not "OK". The google.com favicon is used because it will load reliably
      # fast, and there have been problems with chromeproxy-test.appspot.com
      # being slow and causing tests to flake.
      test_driver.AddChromeArg(
          '--data-reduction-proxy-secure-proxy-check-url='
          'http://www.google.com/favicon.ico')

      # Start chrome to begin the secure proxy check
      test_driver.LoadURL('http://www.google.com/favicon.ico')

      self.assertTrue(
        test_driver.SleepUntilHistogramHasEntry("DataReductionProxy.ProbeURL"))

      test_driver.LoadURL('http://check.googlezip.net/test.html')
      responses = test_driver.GetHTTPResponses()
      self.assertNotEqual(0, len(responses))
      for response in responses:
          self.assertHasChromeProxyViaHeader(response)
          self.assertEqual(u'http/1.1', response.protocol)

if __name__ == '__main__':
  IntegrationTest.RunAllTests()
