# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from measurements import blink_style

from telemetry import decorators
from telemetry.testing import options_for_unittests
from telemetry.testing import page_test_test_case


class BlinkStyleTest(page_test_test_case.PageTestTestCase):
  """Smoke test for Bink Style measurements.

     Runs BlinkStyle measurement on some simple pages and verifies
     that expected metrics were added to the results.  The test is purely
     functional, i.e. it only checks if the metrics are present and non-zero.
  """

  def setUp(self):
    self._options = options_for_unittests.GetCopy()

  @decorators.Disabled('chromeos')  # crbug.com/483212
  def testForParsing(self):
    ps = self.CreateStorySetFromFileInUnittestDataDir('blink_style.html')
    measurement = blink_style.BlinkStyle()
    results = self.RunMeasurement(measurement, ps, options=self._options)
    self.assertEquals(0, len(results.failures))

    def getMetric(results, name, count=1):
      metrics = results.FindAllPageSpecificValuesNamed(name)
      self.assertEquals(count, len(metrics))
      return metrics[0].value

    self.assertGreater(getMetric(results, 'parse_css_regular'), 0)
    self.assertGreater(getMetric(results, 'tokenize_css_regular'), 0)
    self.assertGreater(getMetric(results, 'update_style', 5), 0)
    self.assertGreater(getMetric(results, 'update_style_cold', 5), 0)
