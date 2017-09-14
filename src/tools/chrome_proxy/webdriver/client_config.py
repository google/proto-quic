# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import common
from common import TestDriver
from common import IntegrationTest
from decorators import ChromeVersionEqualOrAfterM
import json


class ClientConfig(IntegrationTest):
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
        header_values = [v.strip(' ') for v in chrome_proxy_header.split(',')]
        self.assertTrue(any(v[:2] == 's=' for v in header_values))
        self.assertFalse(any(v[:3] == 'ps=' for v in header_values))
        self.assertFalse(any(v[:4] == 'sid=' for v in header_values))
        # Verify that the proxy server honored the session ID.
        self.assertHasChromeProxyViaHeader(response)
        self.assertEqual(200, response.status)


  # Ensure client config is fetched at the start of the Chrome session, and the
  # variations ID is set in the request.
  # Disabled on android because the net log is not copied yet. crbug.com/761507
  @ChromeVersionEqualOrAfterM(62)
  def testClientConfigVariationsHeader(self):
    with TestDriver() as t:
      t.UseNetLog()
      t.AddChromeArg('--enable-spdy-proxy-auth')
      # Force set the variations ID, so they are send along with the client
      # config fetch request.
      t.AddChromeArg('--force-variation-ids=42')

      t.LoadURL('http://check.googlezip.net/test.html')

      variation_header_count = 0

      # Look for the request made to data saver client config server.
      data = t.StopAndGetNetLog()
      for i in data["events"]:
        dumped_event = json.dumps(i)
        if dumped_event.find("datasaver.googleapis.com") !=-1 and\
          dumped_event.find("clientConfigs") != -1 and\
          dumped_event.find("headers") != -1 and\
          dumped_event.find("accept-encoding") != -1 and\
          dumped_event.find("x-client-data") !=-1:
            variation_header_count = variation_header_count + 1

      # Variation IDs are set. x-client-data should be present in the request
      # headers.
      self.assertLessEqual(1, variation_header_count)

  # Ensure client config is fetched at the start of the Chrome session, and the
  # variations ID is not set in the request.
  # Disabled on android because the net log is not copied yet. crbug.com/761507
  @ChromeVersionEqualOrAfterM(62)
  def testClientConfigNoVariationsHeader(self):
    with TestDriver() as t:
      t.UseNetLog()
      t.AddChromeArg('--enable-spdy-proxy-auth')

      t.LoadURL('http://check.googlezip.net/test.html')

      variation_header_count = 0

      # Look for the request made to data saver client config server.
      data = t.StopAndGetNetLog()
      for i in data["events"]:
        dumped_event = json.dumps(i)
        if dumped_event.find("datasaver.googleapis.com") !=-1 and\
          dumped_event.find("clientConfigs") != -1 and\
          dumped_event.find("headers") != -1 and\
          dumped_event.find("accept-encoding") != -1 and\
          dumped_event.find("x-client-data") !=-1:
            variation_header_count = variation_header_count + 1

      # Variation IDs are not set. x-client-data should not be present in the
      # request headers.
      self.assertEqual(0, variation_header_count)

if __name__ == '__main__':
  IntegrationTest.RunAllTests()