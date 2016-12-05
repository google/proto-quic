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
      t.AddChromeArgs(['--enable-spdy-proxy-auth'])
      t.SetURL('http://check.googlezip.net/test.html')
      t.LoadPage()
      print 'Document Title: ', t.ExecuteJavascript('document.title')
      time.sleep(5)

if __name__ == '__main__':
  test = SimpleSmoke()
  test.RunAllTests()
