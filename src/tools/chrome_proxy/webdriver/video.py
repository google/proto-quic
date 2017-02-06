# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import common
from common import TestDriver
from common import IntegrationTest


class Video(IntegrationTest):

  # Check videos are proxied.
  def testCheckVideoHasViaHeader(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.LoadURL(
        'http://check.googlezip.net/cacheable/video/buck_bunny_tiny.html')
      for response in t.GetHTTPResponses():
        self.assertHasChromeProxyViaHeader(response)

  # Videos fetched via an XHR request should not be proxied.
  def testNoCompressionOnXHR(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      # The test will actually use Javascript, so use a site that won't have any
      # resources on it that could interfere.
      t.LoadURL('http://check.googlezip.net/connect')
      t.ExecuteJavascript(
        'var xhr = new XMLHttpRequest();'
        'xhr.open("GET", "/cacheable/video/data/buck_bunny_tiny.mp4", false);'
        'xhr.send();'
        'return;'
      )
      saw_video_response = False
      for response in t.GetHTTPResponses():
        if 'video' in response.response_headers['content-type']:
          self.assertNotHasChromeProxyViaHeader(response)
          saw_video_response = True
        else:
          self.assertHasChromeProxyViaHeader(response)
      self.assertTrue(saw_video_response, 'No video request seen in test!')

if __name__ == '__main__':
  IntegrationTest.RunAllTests()
