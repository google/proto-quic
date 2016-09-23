#!/bin/bash

# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -e
set -x

for script in generate-*.py ; do
  python "$script"
done

# Cleanup temporary files.
rm -rf *.pyc
rm -rf out/
