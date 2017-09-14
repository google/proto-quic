#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Updates URLRequestAnnotationType enums in histograms.xml with values read
from tools/traffic_annotation/summary/annotations.xml.

If the file was pretty-printed, the updated version is pretty-printed too.
"""

import os
import sys

from update_histogram_enum import UpdateHistogramEnumFromXML

if __name__ == '__main__':
  if len(sys.argv) > 1:
    print >>sys.stderr, 'No arguments expected!'
    sys.stderr.write(__doc__)
    sys.exit(1)

  UpdateHistogramEnumFromXML(
      histogram_enum_name='URLRequestAnnotationType',
      source_enum_path='tools/traffic_annotation/summary/annotations.xml',
      caller_script_name='update_traffic_annotation_histograms.py',
      element_name='item',
      value_attribute='hash_code',
      label_attribute='id')
