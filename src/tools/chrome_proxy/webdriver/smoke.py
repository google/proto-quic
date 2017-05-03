# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import common
import time
from common import TestDriver
from common import IntegrationTest
from decorators import NotAndroid


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

  # Ensure Chrome uses DataSaver in normal mode.
  def testCheckPageWithNormalMode(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.LoadURL('http://check.googlezip.net/test.html')
      responses = t.GetHTTPResponses()
      self.assertNotEqual(0, len(responses))
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

  # Ensure client config is fetched at the start of the Chrome session, and the
  # session ID is correctly set in the chrome-proxy request header.
  def testClientConfig(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.SleepUntilHistogramHasEntry(
        'DataReductionProxy.ConfigService.FetchResponseCode')
      t.LoadURL('http://check.googlezip.net/test.html')
      responses = t.GetHTTPResponses()
      self.assertEqual(2, len(responses))
      for response in responses:
        chrome_proxy_header = response.request_headers['chrome-proxy']
        self.assertIn('s=', chrome_proxy_header)
        self.assertNotIn('ps=', chrome_proxy_header)
        self.assertNotIn('sid=', chrome_proxy_header)
        # Verify that the proxy server honored the session ID.
        self.assertHasChromeProxyViaHeader(response)
        self.assertEqual(200, response.status)

  # Verify unique page IDs are sent in the Chrome-Proxy header.
  def testPageID(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      page_identifiers = []
      page_loads = 5

      for i in range (0, page_loads):
        t.LoadURL('http://check.googlezip.net/test.html')
        responses = t.GetHTTPResponses()
        self.assertEqual(2, len(responses))
        pid_in_page_count = 0
        page_id = ''
        for response in responses:
          self.assertHasChromeProxyViaHeader(response)
          self.assertEqual(200, response.status)
          chrome_proxy_header = response.request_headers['chrome-proxy']
          chrome_proxy_directives = chrome_proxy_header.split(',')
          for directive in chrome_proxy_directives:
            if 'pid=' in directive:
              pid_in_page_count = pid_in_page_count+1
              page_id = directive.split('=')[1]
              self.assertNotEqual('', page_id)
              self.assertNotIn(page_id, page_identifiers)
        page_identifiers.append(page_id)
        self.assertEqual(1, pid_in_page_count)

  # Ensure that block causes resources to load from the origin directly.
  def testCheckBlockIsWorking(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.LoadURL('http://check.googlezip.net/block')
      responses = t.GetHTTPResponses()
      self.assertNotEqual(0, len(responses))
      for response in responses:
        self.assertNotHasChromeProxyViaHeader(response)

  # Ensure image, css, and javascript resources are compressed.
  def testCheckImageCssJavascriptIsCompressed(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.LoadURL('http://check.googlezip.net/static')
      # http://check.googlezip.net/static is a test page that has
      # image/css/javascript resources.
      responses = t.GetHTTPResponses()
      self.assertNotEqual(0, len(responses))
      for response in responses:
        self.assertHasChromeProxyViaHeader(response)

if __name__ == '__main__':
  IntegrationTest.RunAllTests()
