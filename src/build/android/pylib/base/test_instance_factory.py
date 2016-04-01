# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from pylib.gtest import gtest_test_instance
from pylib.instrumentation import instrumentation_test_instance
from pylib.uirobot import uirobot_test_instance
from pylib.utils import isolator


def CreateTestInstance(args, error_func):

  if args.command == 'gtest':
    return gtest_test_instance.GtestTestInstance(
        args, isolator.Isolator(), error_func)
  elif args.command == 'instrumentation':
    return instrumentation_test_instance.InstrumentationTestInstance(
        args, isolator.Isolator(), error_func)
  elif args.command == 'uirobot':
    return uirobot_test_instance.UirobotTestInstance(args, error_func)

  error_func('Unable to create %s test instance.' % args.command)
