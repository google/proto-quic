# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import common
from common import TestDriver
from common import IntegrationTest
from decorators import ChromeVersionEqualOrAfterM
import json


class CrossOriginPush(IntegrationTest):
  # Ensure cross origin push from trusted proxy server is adopted by Chromium.
  # Disabled on android because the net log is not copied yet. crbug.com/761507
  @ChromeVersionEqualOrAfterM(62)
  def testClientConfigVariationsHeader(self):
    with TestDriver() as t:
      t.UseNetLog()
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.AddChromeArg(
          '--force-fieldtrial-params=DataReductionProxyServerExperiments'
          '.TestNanoRedirectPush:exp/test_nano_redirect_push')
      t.AddChromeArg(
          '--force-fieldtrials=DataReductionProxyServerExperiments'
          '/TestNanoRedirectPush')

      t.LoadURL('http://googleweblight.com/i?u='
        'http://check.googlezip.net/test.html')

      promised_stream_count = 0
      adopted_stream_count = 0

      # Look for the request made to data saver client config server.
      data = t.StopAndGetNetLog()

      mapped_const = data["constants"]["logEventTypes"]\
        ["HTTP2_STREAM_ADOPTED_PUSH_STREAM"]
      self.assertLess(0, mapped_const)

      for i in data["events"]:
        dumped_event = json.dumps(i)
        if dumped_event.find("chrome-proxy") != -1 and\
          dumped_event.find("check.googlezip.net/test.html") != -1 and\
          dumped_event.find("promised_stream_id") !=-1:
            promised_stream_count = promised_stream_count + 1

        if dumped_event.find(str(mapped_const)) != -1 and\
          dumped_event.find("check.googlezip.net/test.html") != -1 and\
          dumped_event.find("stream_id") !=-1:
            adopted_stream_count = adopted_stream_count + 1

      # Verify that the stream was pushed and adopted.
      self.assertEqual(1, promised_stream_count)
      self.assertEqual(1, adopted_stream_count)


if __name__ == '__main__':
  IntegrationTest.RunAllTests()