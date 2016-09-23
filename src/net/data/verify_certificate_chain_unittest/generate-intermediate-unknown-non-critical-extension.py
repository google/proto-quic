#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with 1 intermediate and a trusted root. The intermediate
has an unknown X.509v3 extension that is marked as non-critical. Verification
is expected to succeed because although unrecognized, the extension is not
critical."""

import common

# Self-signed root certificate (used as trust anchor).
root = common.create_self_signed_root_certificate('Root')
intermediate = common.create_intermediate_certificate('Intermediate', root)

# Intermediate that has an unknown non-critical extension.
intermediate.get_extensions().add_property('1.2.3.4', 'DER:01:02:03:04')

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)

chain = [target, intermediate]
trusted = common.TrustAnchor(root, constrained=False)
time = common.DEFAULT_TIME
verify_result = True
errors = None

common.write_test_file(__doc__, chain, trusted, time, verify_result, errors)
