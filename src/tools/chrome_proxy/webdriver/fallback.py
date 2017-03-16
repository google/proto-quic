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

  # Verify that when Chrome receives a non-4xx response through a Data Reduction
  # Proxy that doesn't set a proper via header, Chrome falls back to the next
  # available proxy.
  def testMissingViaHeaderNon4xxFallback(self):
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')

      # Set the primary Data Reduction Proxy to be the test server, which does
      # not add any Via headers. The fallback Data Reduction Proxy is set to the
      # canonical Data Reduction Proxy target.
      test_driver.AddChromeArg('--data-reduction-proxy-http-proxies='
                               'https://chromeproxy-test.appspot.com;'
                               'http://compress.googlezip.net')

      # Load a page that should fall back off of the test server proxy, and onto
      # the canonical proxy that will set the correct Via header.
      test_driver.LoadURL('http://chromeproxy-test.appspot.com/default')
      responses = test_driver.GetHTTPResponses()
      self.assertNotEqual(0, len(responses))
      for response in responses:
        self.assertHasChromeProxyViaHeader(response)
        self.assertEqual(u'http/1.1', response.protocol)

      # Check that the BypassTypePrimary histogram has a single entry in the
      # MissingViaHeaderOther category (which is enum value 5), to make sure
      # that the bypass was caused by the missing via header logic and not
      # something else.
      histogram = test_driver.GetHistogram(
          "DataReductionProxy.BypassTypePrimary")
      self.assertEqual(1, histogram['count'])
      self.assertIn({'count': 1, 'high': 6, 'low': 5}, histogram['buckets'])


if __name__ == '__main__':
  IntegrationTest.RunAllTests()
