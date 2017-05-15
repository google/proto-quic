#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with a root, intermediate and target. The intermediate has
a smaller validity range than the other certificates, making it easy to violate
just its validity.

  Root:          2015/01/01 -> 2016/01/01
  Intermediate:  2015/03/01 -> 2015/09/01
  Target:        2015/01/01 -> 2016/01/01
"""

import sys
sys.path += ['..']

import common

# Self-signed root certificate.
root = common.create_self_signed_root_certificate('Root')
root.set_validity_range(common.JANUARY_1_2015_UTC, common.JANUARY_1_2016_UTC)

# Intermediate certificate.
intermediate = common.create_intermediate_certificate('Intermediate', root)
intermediate.set_validity_range(common.MARCH_1_2015_UTC,
                                common.SEPTEMBER_1_2015_UTC)

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)
target.set_validity_range(common.JANUARY_1_2015_UTC, common.JANUARY_1_2016_UTC)

chain = [target, intermediate, root]
common.write_chain(__doc__, chain, 'chain.pem')
