#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with 1 intermediate and a trust anchor. The trust anchor
has a basic constraints extension that indicates it is NOT a CA. Verification
is expected to succeed even though the trust anchor enforces constraints, since
the CA part of basic constraints is not enforced."""

import common

# Self-signed root certificate (used as trust anchor) with non-CA basic
# constraints.
root = common.create_self_signed_root_certificate('Root')
root.get_extensions().set_property('basicConstraints', 'critical,CA:false')

# Intermediate certificate.
intermediate = common.create_intermediate_certificate('Intermediate', root)

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)

chain = [target, intermediate]
trusted = common.TrustAnchor(root, constrained=True)
time = common.DEFAULT_TIME
verify_result = True
errors = None

common.write_test_file(__doc__, chain, trusted, time, verify_result, errors)
