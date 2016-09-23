#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with 1 intermediate and a trusted root. The intermediate
lacks the basic constraints extension, and hence is expected to fail validation
(RFC 5280 requires v3 signing certificates have a BasicConstaints)."""

import common

# Self-signed root certificate (used as trust anchor).
root = common.create_self_signed_root_certificate('Root')

# Intermediate that lacks basic constraints.
intermediate = common.create_intermediate_certificate('Intermediate', root)
intermediate.get_extensions().remove_property('basicConstraints')

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)

chain = [target, intermediate]
trusted = common.TrustAnchor(root, constrained=False)
time = common.DEFAULT_TIME
verify_result = False
errors = """[Context] Processing Certificate
  index: 0
      [Error] Does not have Basic Constraints
"""

common.write_test_file(__doc__, chain, trusted, time, verify_result, errors)
