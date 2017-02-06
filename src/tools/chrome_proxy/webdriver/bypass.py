# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import common
from common import TestDriver
from common import IntegrationTest


class Bypass(IntegrationTest):

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

if __name__ == '__main__':
  IntegrationTest.RunAllTests()
