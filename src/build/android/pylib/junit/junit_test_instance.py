# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from pylib.base import test_instance


class JunitTestInstance(test_instance.TestInstance):

  def __init__(self, args, _):
    super(JunitTestInstance, self).__init__()

    self._coverage_dir = args.coverage_dir
    self._package_filter = args.package_filter
    self._runner_filter = args.runner_filter
    self._test_filter = args.test_filter
    self._test_suite = args.test_suite

  #override
  def TestType(self):
    return 'junit'

  #override
  def SetUp(self):
    pass

  #override
  def TearDown(self):
    pass

  @property
  def coverage_dir(self):
    return self._coverage_dir

  @property
  def package_filter(self):
    return self._package_filter

  @property
  def runner_filter(self):
    return self._runner_filter

  @property
  def test_filter(self):
    return self._test_filter

  @property
  def suite(self):
    return self._test_suite
