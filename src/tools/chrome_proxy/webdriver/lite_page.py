# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import common
from common import TestDriver
from common import IntegrationTest
from decorators import ChromeVersionEqualOrAfterM

import time

class LitePage(IntegrationTest):

  # Verifies that a Lite Page is served for slow connection if any copyright
  # restricted country blacklist is ignored.
  # Note: this test is for the CPAT protocol change in M-61.
  @ChromeVersionEqualOrAfterM(61)
  def testLitePageWithoutCopyrightRestriction(self):
    # If it was attempted to run with another experiment, skip this test.
    if common.ParseFlags().browser_args and ('--data-reduction-proxy-experiment'
        in common.ParseFlags().browser_args):
      self.skipTest('This test cannot be run with other experiments.')
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')
      test_driver.AddChromeArg('--enable-features='
                               'DataReductionProxyDecidesTransform')
      test_driver.AddChromeArg(
          '--force-fieldtrial-params=NetworkQualityEstimator.Enabled:'
          'force_effective_connection_type/2G,'
          'DataReductionProxyServerExperiments.IgnoreCountryBlacklist:'
          'exp/ignore_preview_blacklist')
      test_driver.AddChromeArg(
          '--force-fieldtrials=NetworkQualityEstimator/Enabled/'
          'DataReductionProxyServerExperiments/IgnoreCountryBlacklist')

      test_driver.LoadURL('http://check.googlezip.net/test.html')

      lite_page_responses = 0
      for response in test_driver.GetHTTPResponses():
        # Verify client sends ignore directive on every request for session.
        self.assertIn('exp=ignore_preview_blacklist',
          response.request_headers['chrome-proxy'])
        self.assertEqual('2G', response.request_headers['chrome-proxy-ect'])
        if response.url.endswith('html'):
          self.assertTrue(self.checkLitePageResponse(response))
          lite_page_responses = lite_page_responses + 1
          # Expect no fallback page policy
          if 'chrome-proxy' in response.response_headers:
            self.assertNotIn('page-policies',
                             response.response_headers['chrome-proxy'])
        else:
          # No subresources should accept transforms.
          self.assertNotIn('chrome-proxy-accept-transform',
            response.request_headers)

      # Verify that a Lite Page response for the main frame was seen.
      self.assertEqual(1, lite_page_responses)

  # Checks that a Lite Page is served and the force_lite_page experiment
  # directive is provided when always-on.
  def testLitePageForcedExperiment(self):
    # If it was attempted to run with another experiment, skip this test.
    if common.ParseFlags().browser_args and ('--data-reduction-proxy-experiment'
        in common.ParseFlags().browser_args):
      self.skipTest('This test cannot be run with other experiments.')
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')
      test_driver.AddChromeArg('--data-reduction-proxy-lo-fi=always-on')
      test_driver.AddChromeArg('--enable-data-reduction-proxy-lite-page')

      # Force ECT to be 4G to confirm that we get Lite Page even for fast
      # conneciton.
      test_driver.AddChromeArg('--force-fieldtrial-params='
                               'NetworkQualityEstimator.Enabled:'
                               'force_effective_connection_type/4G')
      test_driver.AddChromeArg('--force-fieldtrials='
                               'NetworkQualityEstimator/Enabled/')

      test_driver.LoadURL('http://check.googlezip.net/test.html')

      lite_page_responses = 0
      for response in test_driver.GetHTTPResponses():
        # Verify client sends force directive on every request for session.
        self.assertIn('exp=force_lite_page',
          response.request_headers['chrome-proxy'])
        self.assertEqual('4G', response.request_headers['chrome-proxy-ect'])
        # Skip CSI requests when validating Lite Page headers. CSI requests
        # aren't expected to have LoFi headers.
        if '/csi?' in response.url:
          continue
        if response.url.startswith('data:'):
          continue
        if (self.checkLitePageResponse(response)):
          lite_page_responses = lite_page_responses + 1

      # Verify that a Lite Page response for the main frame was seen.
      self.assertEqual(1, lite_page_responses)

  # Checks that a Lite Page is not served for the Cellular-Only option but
  # not on cellular connection.
  def testLitePageNotAcceptedForCellularOnlyFlag(self):
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')
      test_driver.AddChromeArg('--data-reduction-proxy-lo-fi=cellular-only')
      test_driver.AddChromeArg('--enable-data-reduction-proxy-lite-page')

      test_driver.LoadURL('http://check.googlezip.net/test.html')

      non_lite_page_responses = 0
      for response in test_driver.GetHTTPResponses():
        if response.url.endswith('html'):
          self.assertNotIn('chrome-proxy-accept-transform',
                           response.request_headers)
          self.assertNotIn('chrome-proxy-content-transform',
                           response.response_headers)
          non_lite_page_responses = non_lite_page_responses + 1
          # Note that the client will still send exp=force_lite_page (if not
          # using the exp paramter to specify other experiments).
          if common.ParseFlags().browser_args:
            if ('--data-reduction-proxy-experiment'
                not in common.ParseFlags().browser_args):
              # Verify force directive present.
              self.assertIn('exp=force_lite_page',
                response.request_headers['chrome-proxy'])

      # Verify that a main frame without Lite Page was seen.
      self.assertEqual(1, non_lite_page_responses)

  # Checks that a Lite Page does not have an error when scrolling to the bottom
  # of the page and is able to load all resources.
  def testLitePageBTF(self):
    # If it was attempted to run with another experiment, skip this test.
    if common.ParseFlags().browser_args and ('--data-reduction-proxy-experiment'
        in common.ParseFlags().browser_args):
      self.skipTest('This test cannot be run with other experiments.')
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')
      # Need to force lite page so target page doesn't fallback to Lo-Fi
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

  # Lo-Fi fallback is not supported without the
  # DataReductionProxyDecidesTransform feature. Check that no Lo-Fi response
  # is received if a Lite Page is not served.
  def testLitePageNoFallback(self):
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')
      test_driver.AddChromeArg('--force-fieldtrials='
                               'DataCompressionProxyLoFi/Enabled_Preview/')
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

  # Verifies Lo-Fi fallback via the page-policies server directive.
  # Note: this test is for the CPAT protocol change in M-61.
  @ChromeVersionEqualOrAfterM(61)
  def testLitePageFallbackViaPagePolicies(self):
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')
      test_driver.AddChromeArg('--enable-features='
                               'DataReductionProxyDecidesTransform')
      test_driver.AddChromeArg('--force-fieldtrial-params='
                               'NetworkQualityEstimator.Enabled:'
                               'force_effective_connection_type/Slow2G')
      test_driver.AddChromeArg('--force-fieldtrials='
                               'NetworkQualityEstimator/Enabled/')

      test_driver.LoadURL('http://check.googlezip.net/lite-page-fallback')

      lite_page_responses = 0
      lofi_resource = 0
      for response in test_driver.GetHTTPResponses():
        self.assertEqual('Slow-2G',
                         response.request_headers['chrome-proxy-ect'])

        if response.url.endswith('html'):
          # Verify that the server provides the fallback directive
          self.assertIn('page-policies=empty-image',
                        response.response_headers['chrome-proxy'])
          # Main resource should not accept and transform to lite page.
          if self.checkLitePageResponse(response):
            lite_page_responses = lite_page_responses + 1
        if response.url.endswith('png'):
          if self.checkLoFiResponse(response, True):
            lofi_resource = lofi_resource + 1

      self.assertEqual(0, lite_page_responses)
      self.assertNotEqual(0, lofi_resource)
      self.assertNotEqual(0, lofi_resource)

  # Checks that the server provides a preview (either Lite Page or fallback
  # to LoFi) for a 2G connection.
  # Note: this test is for the CPAT protocol change in M-61.
  @ChromeVersionEqualOrAfterM(61)
  def testPreviewProvidedForSlowConnection(self):
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')
      test_driver.AddChromeArg('--enable-features='
                               'DataReductionProxyDecidesTransform')
      test_driver.AddChromeArg('--force-fieldtrial-params='
                               'NetworkQualityEstimator.Enabled:'
                               'force_effective_connection_type/2G')
      test_driver.AddChromeArg('--force-fieldtrials='
                               'NetworkQualityEstimator/Enabled/')

      test_driver.LoadURL('http://check.googlezip.net/test.html')

      lite_page_responses = 0
      page_policies_responses = 0
      for response in test_driver.GetHTTPResponses():
        self.assertEqual('2G', response.request_headers['chrome-proxy-ect'])
        if response.url.endswith('html'):
          if self.checkLitePageResponse(response):
            lite_page_responses = lite_page_responses + 1
          elif 'chrome-proxy' in response.response_headers:
            self.assertIn('page-policies',
                             response.response_headers['chrome-proxy'])
            page_policies_responses = page_policies_responses + 1

      self.assertTrue(lite_page_responses == 1 or page_policies_responses == 1)

  # Checks that the server does not provide a preview (neither Lite Page nor
  # fallback to LoFi) for a fast connection.
  # Note: this test is for the CPAT protocol change in M-61.
  @ChromeVersionEqualOrAfterM(61)
  def testPreviewNotProvidedForFastConnection(self):
    with TestDriver() as test_driver:
      test_driver.AddChromeArg('--enable-spdy-proxy-auth')
      test_driver.AddChromeArg('--enable-features='
                               'DataReductionProxyDecidesTransform')
      test_driver.AddChromeArg('--force-fieldtrial-params='
                               'NetworkQualityEstimator.Enabled:'
                               'force_effective_connection_type/4G')
      test_driver.AddChromeArg('--force-fieldtrials='
                               'NetworkQualityEstimator/Enabled/')

      test_driver.LoadURL('http://check.googlezip.net/test.html')

      for response in test_driver.GetHTTPResponses():
        self.assertEqual('4G', response.request_headers['chrome-proxy-ect'])
        if response.url.endswith('html'):
          # Main resource should accept lite page but not be transformed.
          self.assertEqual('lite-page',
            response.request_headers['chrome-proxy-accept-transform'])
          self.assertNotIn('chrome-proxy-content-transform',
            response.response_headers)
          # Expect no fallback page policy
          if 'chrome-proxy' in response.response_headers:
            self.assertNotIn('page-policies',
                             response.response_headers['chrome-proxy'])
        else:
          # No subresources should accept transforms.
          self.assertNotIn('chrome-proxy-accept-transform',
            response.request_headers)

if __name__ == '__main__':
  IntegrationTest.RunAllTests()
