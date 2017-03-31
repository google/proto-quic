#!/usr/bin/env python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Downloads pre-built sanitizer-instrumented third-party libraries from GCS.
This script should only be run from gn.
"""

import subprocess
import sys


def main(args):
  if not sys.platform.startswith('linux'):
    raise Exception("Prebuilt instrumented libraries require Linux.")

  sha1file = args[0]
  tarfile = args[1]

  subprocess.check_call([
      'download_from_google_storage',
      '--no_resume',
      '--no_auth',
      '--bucket', 'chromium-instrumented-libraries',
      '-s', sha1file, '-o', tarfile])

  return 0


if __name__ == '__main__':
  # TODO(thomasanderson): Remove this once all third_party DEPS
  # entires for this script are removed.
  if (len(sys.argv) == 1):
    sys.exit(0)
  sys.exit(main(sys.argv[1:]))
