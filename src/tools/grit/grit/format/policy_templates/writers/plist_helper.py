#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


'''Common functions for plist_writer and plist_strings_writer.
'''


def GetPlistFriendlyName(name):
  '''Transforms a string so that it will be suitable for use as
  a pfm_name in the plist manifest file.
  '''
  return name.replace(' ', '_')
