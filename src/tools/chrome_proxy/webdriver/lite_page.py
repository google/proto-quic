# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import common
from common import TestDriver
from common import IntegrationTest


class LitePage(IntegrationTest):

  # Checks that a Lite Page is served and that the ignore_preview_blacklist
  # experiment is being used.
  def testLitePage(self):
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')
      test_driver.AddChromeArg('--data-reduction-proxy-lo-fi=always-on')
      test_driver.AddChromeArg('--enable-data-reduction-proxy-lite-page')

      test_driver.LoadURL('http://check.googlezip.net/test.html')

      lite_page_responses = 0
      for response in test_driver.GetHTTPResponses():
        # Skip CSI requests when validating Lite Page headers. CSI requests
        # aren't expected to have LoFi headers.
        if '/csi?' in response.url:
          continue
        if response.url.startswith('data:'):
          continue
        self.assertIn('exp=ignore_preview_blacklist',
          response.request_headers['chrome-proxy'])
        if (self.checkLitePageResponse(response)):
          lite_page_responses = lite_page_responses + 1

      # Verify that a Lite Page response for the main frame was seen.
      self.assertEqual(1, lite_page_responses)

  # Checks that Lo-Fi images are used when the user is in the
  # DataCompressionProxyLitePageFallback field trial and a Lite Page is not
  # served.
  def testLitePageFallback(self):
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')
      test_driver.AddChromeArg('--force-fieldtrials='
                               'DataCompressionProxyLoFi/Enabled_Preview/'
                               'DataCompressionProxyLitePageFallback/Enabled')
      test_driver.AddChromeArg('--force-fieldtrial-params='
                               'DataCompressionProxyLoFi.Enabled_Preview:'
                               'effective_connection_type/4G')
      test_driver.AddChromeArg('--force-net-effective-connection-type=2g')

      test_driver.LoadURL('http://check.googlezip.net/lite-page-fallback')

      lite_page_requests = 0
      lo_fi_responses = 0
      for response in test_driver.GetHTTPResponses():
        if not response.request_headers:
          continue

        cpat_request = response.request_headers['chrome-proxy-accept-transform']
        if ('lite-page' in cpat_request):
          lite_page_requests = lite_page_requests + 1
          self.assertFalse(self.checkLitePageResponse(response))

        if not response.url.endswith('png'):
          continue

        if (self.checkLoFiResponse(response, True)):
          lo_fi_responses = lo_fi_responses + 1

      # Verify that a Lite Page was requested and that the page fell back to
      # Lo-Fi images.
      self.assertEqual(1, lite_page_requests)
      self.assertEqual(1, lo_fi_responses)

  # Checks that Lo-Fi images are not used when the user is not in the
  # DataCompressionProxyLitePageFallback field trial and a Lite Page is not
  # served.
  def testLitePageNoFallback(self):
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')
      # Lite Pages must be enabled via the field trial because the Lite Page
      # flag always falls back to Lo-Fi.
      test_driver.AddChromeArg('--force-fieldtrials='
                               'DataCompressionProxyLoFi/Enabled_Preview')
      test_driver.AddChromeArg('--force-fieldtrial-params='
                               'DataCompressionProxyLoFi.Enabled_Preview:'
                               'effective_connection_type/4G')
      test_driver.AddChromeArg('--force-net-effective-connection-type=2g')

      test_driver.LoadURL('http://check.googlezip.net/lite-page-fallback')

      lite_page_requests = 0
      for response in test_driver.GetHTTPResponses():
        if not response.request_headers:
          continue

        if ('chrome-proxy-accept-transform' in response.request_headers):
          cpat_request = response.request_headers[
                           'chrome-proxy-accept-transform']
          if ('lite-page' in cpat_request):
            lite_page_requests = lite_page_requests + 1
            self.assertFalse(self.checkLitePageResponse(response))

        if not response.url.endswith('png'):
          continue

        self.checkLoFiResponse(response, False)

      # Verify that a Lite Page was requested and that the page fell back to
      # Lo-Fi images.
      self.assertEqual(1, lite_page_requests)

if __name__ == '__main__':
  IntegrationTest.RunAllTests()
