#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import os
import subprocess


def GenerateWithNinja(path):
  """Generates a compile database using ninja.

  Args:
    path: The build directory to generate a compile database for.
  """
  # TODO(dcheng): Incorporate Windows-specific compile DB munging from
  # https://codereview.chromium.org/718873004
  print 'Generating compile database in %s...' % path
  args = ['ninja', '-C', path, '-t', 'compdb', 'cc', 'cxx', 'objc', 'objcxx']
  output = subprocess.check_output(args)
  with file(os.path.join(path, 'compile_commands.json'), 'w') as f:
    f.write(output)


def Read(path):
  """Reads a compile database into memory.

  Args:
    path: Directory that contains the compile database.
  """
  with open(os.path.join(path, 'compile_commands.json'), 'rb') as db:
    return json.load(db)
