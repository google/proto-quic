# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import sys
import time
import unittest

import common
from common import TestDriver


class SimpleSmoke(unittest.TestCase):

  # Simple example integration test.
  def testCheckPageWithProxy(self):
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
  def testPingbackHistogram(self):
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.SetURL('http://check.googlezip.net/test.html')
      t.LoadPage()
      t.LoadPage()
      print t.GetHistogram('DataReductionProxy.Pingback.Attempted')

if __name__ == '__main__':
  # The unittest library uses sys.argv itself and is easily confused by our
  # command line options. Pass it a simpler argv instead.
  unittest.main(argv=[sys.argv[0]], verbosity=2)
