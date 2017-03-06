# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import time

import common
from common import TestDriver
from common import IntegrationTest
from common import NotAndroid


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

  # Check the compressed video has the same frame count, width, height, and
  # duration as uncompressed.
  def testVideoMetrics(self):
    expected = {
      'duration': 3.124,
      'webkitDecodedFrameCount': 54.0,
      'videoWidth': 1280.0,
      'videoHeight': 720.0
    }
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.LoadURL('http://check.googlezip.net/cacheable/video/buck_bunny_tiny.html')
      # Check request was proxied and we got a compressed video back.
      for response in t.GetHTTPResponses():
        self.assertHasChromeProxyViaHeader(response)
        if ('content-type' in response.response_headers
            and 'video' in response.response_headers['content-type']):
          self.assertEqual('video/webm',
            response.response_headers['content-type'])
      t.ExecuteJavascriptStatement(
        'document.querySelectorAll("video")[0].play()')
      # Wait for the video to finish playing, plus some headroom.
      time.sleep(5)
      # Check each metric against its expected value.
      for metric in expected:
        actual = float(t.ExecuteJavascriptStatement(
          'document.querySelectorAll("video")[0].%s' % metric))
        self.assertAlmostEqual(expected[metric], actual, msg="Compressed video "
          "metric doesn't match expected! Metric=%s Expected=%f Actual=%f"
          % (metric, expected[metric], actual), places=None, delta=0.001)

  # Check the frames of a compressed video.
  def testVideoFrames(self):
    self.instrumentedVideoTest('http://check.googlezip.net/cacheable/video/buck_bunny_640x360_24fps_video.html')

  # Check the audio volume of a compressed video.
  def testVideoAudio(self):
    self.instrumentedVideoTest('http://check.googlezip.net/cacheable/video/buck_bunny_640x360_24fps_audio.html')

  def instrumentedVideoTest(self, url):
    """Run an instrumented video test. The given page is reloaded up to some
    maximum number of times until a compressed video is seen by ChromeDriver by
    inspecting the network logs. Once that happens, test.ready is set and that
    will signal the Javascript test on the page to begin. Once it is complete,
    check the results.
    """
    # The maximum number of times to attempt to reload the page for a compressed
    # video.
    max_attempts = 10
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      loaded_compressed_video = False
      attempts = 0
      while not loaded_compressed_video and attempts < max_attempts:
        t.LoadURL(url)
        attempts += 1
        for resp in t.GetHTTPResponses():
          if ('content-type' in resp.response_headers
              and resp.response_headers['content-type'] == 'video/webm'):
            loaded_compressed_video = True
            self.assertHasChromeProxyViaHeader(resp)
          else:
            # Take a breath before requesting again.
            time.sleep(1)
      if attempts >= max_attempts:
        self.fail('Could not get a compressed video after %d tries' % attempts)
      t.ExecuteJavascriptStatement('test.ready = true')
      wait_time = int(t.ExecuteJavascriptStatement('test.waitTime'))
      t.WaitForJavascriptExpression('test.metrics.complete', wait_time)
      metrics = t.ExecuteJavascriptStatement('test.metrics')
      if not metrics['complete']:
        raise Exception('Test not complete after %d seconds.' % wait_time)
      if metrics['failed']:
        raise Exception('Test failed!')

  # Make sure YouTube autoplays.
  @NotAndroid
  def testYoutube(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.LoadURL('http://data-saver-test.appspot.com/youtube')
      t.WaitForJavascriptExpression(
        'window.playerState == YT.PlayerState.PLAYING', 30)
      for response in t.GetHTTPResponses():
        if not response.url.startswith('https'):
          self.assertHasChromeProxyViaHeader(response)

if __name__ == '__main__':
  IntegrationTest.RunAllTests()
