# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import common
from common import TestDriver
from common import IntegrationTest


class Bypass(IntegrationTest):

  # Ensure Chrome does not use Data Saver for block-once, but does use Data
  # Saver for a subsequent request.
  def testBlockOnce(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.LoadURL('http://check.googlezip.net/blocksingle/')
      responses = t.GetHTTPResponses()
      self.assertEqual(2, len(responses))
      for response in responses:
        if response.url == "http://check.googlezip.net/image.png":
          self.assertHasChromeProxyViaHeader(response)
        else:
          self.assertNotHasChromeProxyViaHeader(response)

  # Ensure Chrome does not use Data Saver for block=0, which uses the default
  # proxy retry delay.
  def testBypass(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.LoadURL('http://check.googlezip.net/block/')
      for response in t.GetHTTPResponses():
        self.assertNotHasChromeProxyViaHeader(response)

      # Load another page and check that Data Saver is not used.
      t.LoadURL('http://check.googlezip.net/test.html')
      for response in t.GetHTTPResponses():
        self.assertNotHasChromeProxyViaHeader(response)

  # Ensure Chrome does not use Data Saver for HTTPS requests.
  def testHttpsBypass(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')

      # Load HTTP page and check that Data Saver is used.
      t.LoadURL('http://check.googlezip.net/test.html')
      responses = t.GetHTTPResponses()
      self.assertEqual(2, len(responses))
      for response in responses:
        self.assertHasChromeProxyViaHeader(response)

      # Load HTTPS page and check that Data Saver is not used.
      t.LoadURL('https://check.googlezip.net/test.html')
      responses = t.GetHTTPResponses()
      self.assertEqual(2, len(responses))
      for response in responses:
        self.assertNotHasChromeProxyViaHeader(response)

  # Verify that CORS requests receive a block-once from the data reduction
  # proxy by checking that those requests are retried without data reduction
  # proxy.
  def testCorsBypass(self):
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')
      test_driver.LoadURL('http://www.gstatic.com/chrome/googlezip/cors/')

      # Navigate to a different page to verify that later requests are not
      # blocked.
      test_driver.LoadURL('http://check.googlezip.net/test.html')

      cors_requests = 0
      same_origin_requests = 0
      for response in test_driver.GetHTTPResponses():
        # The origin header implies that |response| is a CORS request.
        if ('origin' not in response.request_headers):
          self.assertHasChromeProxyViaHeader(response)
          same_origin_requests = same_origin_requests + 1
        else:
          self.assertNotHasChromeProxyViaHeader(response)
          cors_requests = cors_requests + 1
      # Verify that both CORS and same origin requests were seen.
      self.assertNotEqual(0, same_origin_requests)
      self.assertNotEqual(0, cors_requests)

  # Verify that when an origin times out using Data Saver, the request is
  # fetched directly and data saver is bypassed only for one request.
  def testOriginTimeoutBlockOnce(self):
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')

      # Load URL that times out when the proxy server tries to access it.
      test_driver.LoadURL('http://chromeproxy-test.appspot.com/blackhole')
      responses = test_driver.GetHTTPResponses()
      self.assertNotEqual(0, len(responses))
      for response in responses:
          self.assertNotHasChromeProxyViaHeader(response)

      # Load HTTP page and check that Data Saver is used.
      test_driver.LoadURL('http://check.googlezip.net/test.html')
      responses = test_driver.GetHTTPResponses()
      self.assertNotEqual(0, len(responses))
      for response in responses:
        self.assertHasChromeProxyViaHeader(response)

  # Verify that when Chrome receives a 4xx response through a Data Reduction
  # Proxy that doesn't set a proper via header, Chrome bypasses all proxies and
  # retries the request over direct.
  def testMissingViaHeader4xxBypass(self):
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')

      # Set the primary Data Reduction Proxy to be the test server, which does
      # not add any Via headers.
      test_driver.AddChromeArg('--data-reduction-proxy-http-proxies='
                               'https://chromeproxy-test.appspot.com;'
                               'http://compress.googlezip.net')

      # Load a page that will come back with a 4xx response code and without the
      # proper via header. Chrome should bypass all proxies and retry the
      # request.
      test_driver.LoadURL(
          'http://chromeproxy-test.appspot.com/default?respStatus=414')
      responses = test_driver.GetHTTPResponses()
      self.assertNotEqual(0, len(responses))
      for response in responses:
        self.assertNotHasChromeProxyViaHeader(response)
        self.assertEqual(u'http/1.1', response.protocol)

      # Check that the BlockTypePrimary histogram has a single entry in the
      # MissingViaHeader4xx category (which is enum value 4), to make sure that
      # the bypass was caused by the missing via header logic and not something
      # else.
      histogram = test_driver.GetHistogram(
          "DataReductionProxy.BlockTypePrimary")
      self.assertEqual(1, histogram['count'])
      self.assertIn({'count': 1, 'high': 5, 'low': 4}, histogram['buckets'])

  # Verify that the Data Reduction Proxy understands the "exp" directive.
  def testExpDirectiveBypass(self):
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')
      test_driver.AddChromeArg('--data-reduction-proxy-experiment=test')

      # Verify that loading a page other than the specific exp directive test
      # page loads through the proxy without being bypassed.
      test_driver.LoadURL('http://check.googlezip.net/test.html')
      responses = test_driver.GetHTTPResponses()
      self.assertNotEqual(0, len(responses))
      for response in responses:
        self.assertHasChromeProxyViaHeader(response)

      # Verify that loading the exp directive test page with "exp=test" triggers
      # a bypass.
      test_driver.LoadURL('http://check.googlezip.net/exp/')
      responses = test_driver.GetHTTPResponses()
      self.assertNotEqual(0, len(responses))
      for response in responses:
        self.assertNotHasChromeProxyViaHeader(response)

    # Verify that loading the same test page without setting "exp=test" loads
    # through the proxy without being bypassed.
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')

      test_driver.LoadURL('http://check.googlezip.net/exp/')
      responses = test_driver.GetHTTPResponses()
      self.assertNotEqual(0, len(responses))
      for response in responses:
        self.assertHasChromeProxyViaHeader(response)


if __name__ == '__main__':
  IntegrationTest.RunAllTests()
