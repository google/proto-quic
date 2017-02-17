# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import datetime
import json
import math
import subprocess
import time

import common
from common import TestDriver
from common import IntegrationTest

# The maximum number of data points that will be saved.
MAX_DATA_POINTS = 365

# The persistant storage for compression data is kept in Google Storage with
# this bucket name.
BUCKET = 'chrome_proxy_compression'

# The data file name in the Google Storage bucket, above. The data file is also
# saved locally under the same name.
DATA_FILE = 'compression_data.json'

class CompressionRegression(IntegrationTest):
  """This class is responsible for alerting the Chrome Proxy team to regression
  in the compression metrics of the proxy. At present, this class will simply
  gather data and save it to a Google Storage bucket. Once enough data has been
  gathered to form a reasonable model, alerting will be added to check for
  regression.

  Before running the test, this class will fetch the JSON data file from Google
  Storage in a subprocess and store it on the local disk with the same file
  name. The data is then read from that file. After running the test, if the
  data has changed the file will be uploaded back to Google Storage.

  The JSON data object and data dict object used widely in this class has the
  following structure:
  {
    "2017-02-29": {
      "html": 0.314,
      "jpg": 0.1337,
      "png": 0.1234,
      "mp4": 0.9876
    }
  }
  where keys are date stamps in the form "YYYY-MM-DD", and each key in the child
  object is the resource type with its compression value.

  Also frequently referenced is the compression_average dict object, which
  contains the compression data just now gathered from Chrome in
  getCurrentCompressionMetrics(). That object has the following structure:
  {
    "test/html": 0.314,
    "image/jpg": 0.1337,
    "image/png": 0.1234,
    "video/mp4": 0.9876
  }
  where keys are the content type with its compression value.

  Due to the complexity of several methods in this class, a number of local
  unit tests can be found at the bottom of this file.

  Please note that while this test uses the IntegrationTest framework, it is
  classified as a regression test.
  """

  def testCompression(self):
      """This function is the main test function for regression compression
      checking and facilitates the test with all of the helper functions'
      behavior.
      """
      compression_average = self.getCurrentCompressionMetrics()
      self.fetchFromGoogleStorage()
      data = {}
      with open(DATA_FILE, 'r') as data_fp:
        data = json.load(data_fp)
      if self.updateDataObject(compression_average, data):
        with open(DATA_FILE, 'w') as data_fp:
          json.dump(data, data_fp)
        self.uploadToGoogleStorage()

  def getCurrentCompressionMetrics(self):
    """This function uses the ChromeDriver framework to open Chrome and navigate
    to a number of static resources of different types, like jpg, png, mp4, gif,
    html. Multiple resources of a single type are supported. This function will
    check that each resource was fetched via the Chrome Proxy, and then compute
    the compression as a percentage from the Content-Length and
    X-Original-Content-Length headers where compression = 1 - (cl / xocl). The
    function will then return the average compression for each of the resource
    types.

    Returns:
      a dict object mapping resource type to compression
    """
    def AddToCompression(compression, key, value):
      if key in compression:
        compression[key].append(value)
      else:
        compression[key] = [value]
    with TestDriver() as t:
      t.AddChromeArg('--enable-spdy-proxy-auth')
      t.AddChromeArg('--data-reduction-proxy-server-experiments-disabled')
      t.LoadURL('http://check.googlezip.net/metrics/local.gif')
      t.LoadURL('http://check.googlezip.net/metrics/local.png')
      t.LoadURL('http://check.googlezip.net/metrics/local.jpg')
      t.LoadURL(
        'http://check.googlezip.net/cacheable/video/buck_bunny_tiny.html')
      compression = {}
      for response in t.GetHTTPResponses():
        # Check that the response was proxied.
        self.assertHasChromeProxyViaHeader(response)
        # Compute compression metrics.
        cl = response.response_headers['content-length']
        ocl = response.response_headers['x-original-content-length']
        content_type = response.response_headers['content-type']
        compression_rate = 1.0 - (float(cl) / float(ocl))
        if 'html' in response.response_headers['content-type']:
          AddToCompression(compression, 'html', compression_rate)
        else:
          resource = response.url[response.url.rfind('/'):]
          AddToCompression(compression, resource[resource.rfind('.') + 1:],
            compression_rate)
      # Compute the average compression for each resource type.
      compression_average = {}
      for resource_type in compression:
        compression_average[resource_type] = (sum(compression[resource_type]) /
          float(len(compression[resource_type])))
      return compression_average

  def updateDataObject(self, compression_average, data,
      today=datetime.date.today()):
    """This function handles the updating of the data object when new data is
    available. Given the existing data object, the results of the
    getCurrentCompressionMetrics() func, and a date object, it will check if
    data exists for today. If it does, the method will do nothing and return
    False. Otherwise, it will update the data object with the compression data.
    If needed, it will also find the least recent entry in the data object and
    remove it.

    Args:
      compression_average: the compression data from
        getCurrentCompressionMetrics()
      data: the current data object, a dict
      today: a date object, specifiable here for testing purposes.
    Returns:
      True iff the data object was changed
    """
    datestamp = today.strftime('%Y-%m-%d')
    # Check if this data has already been recorded.
    if datestamp in data:
      return False
    # Append new data, removing the least recent if needed.
    data[datestamp] = compression_average
    if len(data) > MAX_DATA_POINTS:
      min_date = None
      for date_str in data:
        date = datetime.date(*[int(d) for d in date_str.split('-')])
        if min_date == None or date < min_date:
          min_date = date
      del data[min_date.strftime('%Y-%m-%d')]
    return True

  def uploadToGoogleStorage(self):
    """This function uses the gsutil command to upload the local data file to
    Google Storage.
    """
    gs_location = 'gs://%s/%s' % (BUCKET, DATA_FILE)
    cmd = ['gsutil', 'cp', DATA_FILE, gs_location]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if proc.returncode:
      raise Exception('Uploading to Google Storage failed! output: %s %s' %
        (stdout, stderr))

  def fetchFromGoogleStorage(self):
    """This function uses the gsutil command to fetch the local data file from
    Google Storage.
    """
    gs_location = 'gs://%s/%s' % (BUCKET, DATA_FILE)
    cmd = ['gsutil', 'cp', gs_location, DATA_FILE]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if proc.returncode:
      raise Exception('Fetching to Google Storage failed! output: %s %s' %
        (stdout, stderr))

  def test0UpdateDataObject_NoUpdate(self):
    """This unit test asserts that the updateDataObject() function doesn't
    update the data object when today is already contained in the data object.
    """
    data = { '2017-02-06': {'hello': 'world'}}
    new_data = {'Benoit': 'Mandelbrot'}
    test_day = datetime.date(2017, 02, 06)
    changed = self.updateDataObject(new_data, data, today=test_day)
    self.assertFalse(changed, "No data should have been recorded!")

  def test0UpdateDataObject_Update(self):
    """This unit test asserts that the updateDataObject() function updates the
    data object when there is new data available, also removing the least recent
    data point.
    """
    start_date = datetime.date(2017, 2, 6)
    data = {}
    for i in range(MAX_DATA_POINTS):
      date_obj = start_date + datetime.timedelta(days=i)
      datestamp = date_obj.strftime('%Y-%m-%d')
      data[datestamp] = {'hello': 'world'}
    new_data = {'Benoit': 'Mandelbrot'}
    test_day = datetime.date(2017, 02, 06) + datetime.timedelta(
      days=(MAX_DATA_POINTS))
    changed = self.updateDataObject(new_data, data, today=test_day)
    self.assertTrue(changed, "Data should have been recorded!")
    self.assertNotIn('2017-02-06', data)
    self.assertIn(test_day.strftime('%Y-%m-%d'), data)

if __name__ == '__main__':
  IntegrationTest.RunAllTests()
