#!/bin/bash
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# # Use of this source code is governed by a BSD-style license that can be
# # found in the LICENSE file.
#
# This script is tested ONLY on Linux. It may not work correctly on
# Mac OS X.
#
TOPSRC="$(dirname "$0")/.."
source "${TOPSRC}/scripts/data_common.sh"

echo "Copying icudtl.dat and the corresponding assembly source for Linux"
cp "data/out/tmp/icudt${VERSION}l.dat" "${TOPSRC}/common/icudtl.dat"
cp "data/out/tmp/icudt${VERSION}l_dat.S" "${TOPSRC}/linux/icudtl_dat.S"

"${TOPSRC}/scripts/make_mac_assembly.sh"

echo "Done with copying pre-built ICU data files."
