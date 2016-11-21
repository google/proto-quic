# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from pylib.base import environment


class LocalMachineEnvironment(environment.Environment):

  def __init__(self, _args, _error_func):
    super(LocalMachineEnvironment, self).__init__()

  #override
  def SetUp(self):
    pass

  #override
  def TearDown(self):
    pass
