#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with 1 intermediate, where the target is expired (violates
validity.notAfter). Verification is expected to fail."""

import common

# Self-signed root certificate (used as trust anchor).
root = common.create_self_signed_root_certificate('Root')
root.set_validity_range(common.JANUARY_1_2015_UTC, common.JANUARY_1_2016_UTC)

# Intermediate certificate.
intermediate = common.create_intermediate_certificate('Intermediate', root)
intermediate.set_validity_range(common.JANUARY_1_2015_UTC,
                                common.JANUARY_1_2016_UTC)

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)
target.set_validity_range(common.JANUARY_1_2015_UTC, common.MARCH_1_2015_UTC)

chain = [target, intermediate]
trusted = common.TrustAnchor(root, constrained=False)

# Both the root and intermediate are valid at this time, however the
# target is not.
time = common.MARCH_2_2015_UTC
verify_result = False
errors = """[Context] Processing Certificate
  index: 1
      [Error] Time is after notAfter
"""

common.write_test_file(__doc__, chain, trusted, time, verify_result, errors)
