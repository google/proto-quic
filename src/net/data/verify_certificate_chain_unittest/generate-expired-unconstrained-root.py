#!/usr/bin/python
# Copyright (c) 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with 1 intermediate, where the root certificate is expired
(violates validity.notAfter). Verification is expected to succeed as
the trust anchor has no constraints (so expiration of the certificate is not
enforced)."""

import common

# Self-signed root certificate (used as trust anchor).
root = common.create_self_signed_root_certificate('Root')
root.set_validity_range(common.JANUARY_1_2015_UTC, common.MARCH_1_2015_UTC)

# Intermediate certificate.
intermediate = common.create_intermediate_certificate('Intermediate', root)
intermediate.set_validity_range(common.JANUARY_1_2015_UTC,
                                common.JANUARY_1_2016_UTC)

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)
target.set_validity_range(common.JANUARY_1_2015_UTC, common.JANUARY_1_2016_UTC)

chain = [target, intermediate]
trusted = common.TrustAnchor(root, constrained=False)

# Both the target and intermediate are valid at this time, however the
# root is not. This doesn't matter since the root certificate is
# just a delivery mechanism for the name + SPKI.
time = common.MARCH_2_2015_UTC
verify_result = True
errors = None

common.write_test_file(__doc__, chain, trusted, time, verify_result, errors)
