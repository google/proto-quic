# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import sys
import time

import common
from common import TestDriver
from common import IntegrationTest


class Examples(IntegrationTest):

  # Simple example integration test.
  def testCheckPageWithProxy(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.LoadURL('http://check.googlezip.net/test.html')
      print 'Document Title: ', t.ExecuteJavascriptStatement('document.title',
        timeout=1)
      responses = t.GetHTTPResponses()
      for response in responses:
        print "URL: %s, ViaHeader: %s, XHR: %s" % (response.url,
          response.ResponseHasViaHeader(), response.WasXHR())
        self.assertHasChromeProxyViaHeader(response)

  # Simple example integration test.
  def testCheckPageWithoutProxy(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.LoadURL('https://check.googlezip.net/test.html')
      print 'Document Title: ', t.ExecuteJavascriptStatement('document.title',
        timeout=1)
      responses = t.GetHTTPResponses()
      for response in responses:
        print "URL: %s, ViaHeader: %s, XHR: %s" % (response.url,
          response.ResponseHasViaHeader(), response.WasXHR())
        self.assertNotHasChromeProxyViaHeader(response)

  # Show how to get a histogram.
  def testPingbackHistogram(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.LoadURL('http://check.googlezip.net/test.html')
      t.LoadURL('http://check.googlezip.net/test.html')
      print t.GetHistogram('DataReductionProxy.Pingback.Attempted')

  # Show how to use WaitForJavascriptExpression
  def testHTML5(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.LoadURL('http://html5test.com/')
      t.WaitForJavascriptExpression(
        'document.getElementsByClassName("pointsPanel")', 15)

  # Show how to use SetNetworkConnection
  def testSetNetworkConnection(self):
    with TestDriver(control_network_connection=True) as t:
      t.SetNetworkConnection("2G")
      t.LoadURL('https://www.google.com')

if __name__ == '__main__':
  IntegrationTest.RunAllTests()
