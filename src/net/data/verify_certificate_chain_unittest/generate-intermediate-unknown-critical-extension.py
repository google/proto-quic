#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with 1 intermediate and a trusted root. The intermediate
has an unknown X.509v3 extension (OID=1.2.3.4) that is marked as critical.
Verifying this certificate chain is expected to fail because there is an
unrecognized critical extension."""

import common

# Self-signed root certificate (used as trust anchor).
root = common.create_self_signed_root_certificate('Root')

# Intermediate that has an unknown critical extension.
intermediate = common.create_intermediate_certificate('Intermediate', root)
intermediate.get_extensions().add_property('1.2.3.4',
                                           'critical,DER:01:02:03:04')

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)

chain = [target, intermediate]
trusted = common.TrustAnchor(root, constrained=False)
time = common.DEFAULT_TIME
verify_result = False
errors = """[Context] Processing Certificate
  index: 0
      [Error] Unconsumed critical extension
        oid: 2A0304
        value: 01020304
"""

common.write_test_file(__doc__, chain, trusted, time, verify_result, errors)
