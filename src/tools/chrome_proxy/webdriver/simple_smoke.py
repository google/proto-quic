# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import time

from common import IntegrationTest
from common import TestDriver


class SimpleSmoke(IntegrationTest):

  # Simple example integration test.
  def TestCheckPageWithProxy(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.SetURL('http://check.googlezip.net/test.html')
      t.LoadPage()
      print 'Document Title: ', t.ExecuteJavascriptStatement('document.title',
        timeout=1)
      time.sleep(5)
      responses = t.GetHTTPResponses()
      for response in responses:
        print "URL: %s, ViaHeader: %s, XHR: %s" % (response.url,
          response.ResponseHasViaHeader(), response.WasXHR())

  # Show how to get a histogram.
  def TestPingbackHistogram(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.SetURL('http://check.googlezip.net/test.html')
      t.LoadPage()
      t.LoadPage()
      print t.GetHistogram('DataReductionProxy.Pingback.Attempted')

if __name__ == '__main__':
  test = SimpleSmoke()
  test.RunAllTests()
