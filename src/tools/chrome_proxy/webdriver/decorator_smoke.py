# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from common import AndroidOnly
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


if __name__ == '__main__':
  IntegrationTest.RunAllTests()
