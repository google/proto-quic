# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from decorators import AndroidOnly
from decorators import ChromeVersionEqualOrAfterM
from decorators import ChromeVersionBeforeM
from common import ParseFlags
from common import IntegrationTest


class DecoratorSmokeTest(IntegrationTest):

  def AndroidOnlyFunction(self):
    # This function should never be called.
    self.fail()

  @AndroidOnly
  def testDecorator(self):
    # This test should always result as 'skipped' or pass if --android given.
    if not ParseFlags().android:
      self.AndroidOnlyFunction()

  @ChromeVersionBeforeM(0)
  def testVersionBeforeDecorator(self):
    self.fail('This function should not be called when the Chrome Milestone is '
      'greater than 0')

  @ChromeVersionEqualOrAfterM(999999999)
  def testVersionAfterDecorator(self):
    self.fail('This function should not be called when the Chrome Milestone is '
      'less than 999999999')

if __name__ == '__main__':
  IntegrationTest.RunAllTests()
