# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import common
from common import TestDriver
from common import IntegrationTest

# Technically not an Integration test, but we'll use the same infrastructure.
#
# This tests hits a test page and computes the compression rate for each of the
# resource types on it. These metrics are then output to the console. After
# metrics from several releases have been manually captured from the console,
# this test be changed to check compression rates against the known good rates
# and alert if they fall outside a tolerance.
class CompressionRegression(IntegrationTest):

  # TODO(robertogden): Once month-long metric gathering is up, remove print
  # statements and make into a true test.
  def testCompression(self):
    def AddToCompression(compression, key, value):
      if key in compression:
        compression[key].append(value)
      else:
        compression[key] = [value]
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.LoadURL('http://check.googlezip.net/metrics/')
      print ''
      compression = {}
      for response in t.GetHTTPResponses():
        if not response.url.endswith('webp'):
          cl = response.response_headers['content-length']
          ocl = response.response_headers['x-original-content-length']
          compression_rate = 1.0 - (float(cl) / float(ocl))
          if 'html' in response.response_headers['content-type']:
            AddToCompression(compression, 'html', compression_rate)
          else:
            resource = response.url[response.url.rfind('/'):]
            AddToCompression(compression, resource[resource.rfind('.') + 1:],
              compression_rate)
      for url in sorted(compression):
        average = sum(compression[url]) / float(len(compression[url]))
        print url, average
if __name__ == '__main__':
  IntegrationTest.RunAllTests()
