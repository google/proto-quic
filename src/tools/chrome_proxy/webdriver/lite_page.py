# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import common
from common import TestDriver
from common import IntegrationTest

import time

class LitePage(IntegrationTest):

  # Checks that a Lite Page is served and that the ignore_preview_blacklist
  # experiment is being used.
  def testLitePage(self):
    # If it was attempted to run with another experiment, skip this test.
    if common.ParseFlags().browser_args and ('--data-reduction-proxy-experiment'
        in common.ParseFlags().browser_args):
      self.skipTest('This test cannot be run with other experiments.')
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

  # Checks that a Lite Page does not have an error when scrolling to the bottom
  # of the page and is able to load all resources.
  def testLitePageBTF(self):
    # If it was attempted to run with another experiment, skip this test.
    if common.ParseFlags().browser_args and ('--data-reduction-proxy-experiment'
        in common.ParseFlags().browser_args):
      self.skipTest('This test cannot be run with other experiments.')
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')
      test_driver.AddChromeArg('--data-reduction-proxy-lo-fi=always-on')
      test_driver.AddChromeArg('--enable-data-reduction-proxy-lite-page')

      # This page is long and has many media resources.
      test_driver.LoadURL('http://check.googlezip.net/metrics/index.html')

      # Verify that a Lite Page response for the main frame was seen.
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
      self.assertEqual(1, lite_page_responses)

      # Scroll to the bottom of the window and ensure scrollHeight increases.
      original_scroll_height = test_driver.ExecuteJavascriptStatement(
        'document.body.scrollHeight')
      test_driver.ExecuteJavascriptStatement(
        'window.scrollTo(0,Math.max(document.body.scrollHeight));')
      # Give some time for loading after scrolling.
      time.sleep(2)
      new_scroll_height = test_driver.ExecuteJavascriptStatement(
        'document.body.scrollHeight')
      self.assertGreater(new_scroll_height, original_scroll_height)

      # Make sure there were more requests that were proxied.
      responses = test_driver.GetHTTPResponses(override_has_logs=True)
      self.assertNotEqual(0, len(responses))
      for response in responses:
        self.assertHasChromeProxyViaHeader(response)
        self.assertIn(response.status, [200, 204])

  # Lo-Fi fallback is not currently supported via the client. Check that
  # no Lo-Fi response is received if the user is in the
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

        if ('chrome-proxy-accept-transform' in response.request_headers):
          cpat_request = response.request_headers[
                           'chrome-proxy-accept-transform']
          if ('lite-page' in cpat_request):
            lite_page_requests = lite_page_requests + 1
            self.assertFalse(self.checkLitePageResponse(response))

        if not response.url.endswith('png'):
          continue

        # Lo-Fi fallback is not currently supported via the client. Check that
        # no Lo-Fi response is received.
        self.checkLoFiResponse(response, False)

      # Verify that a Lite Page was requested.
      self.assertEqual(1, lite_page_requests)

if __name__ == '__main__':
  IntegrationTest.RunAllTests()
