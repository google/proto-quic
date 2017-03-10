#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with an intermediate that uses MD5 to sign the target
certificate. This is expected to fail because MD5 is too weak."""

import common

# Self-signed root certificate (used as trust anchor).
root = common.create_self_signed_root_certificate('Root')

# Intermediate.
intermediate = common.create_intermediate_certificate('Intermediate', root)

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate)
target.set_signature_hash('md5')

chain = [target, intermediate]
trusted = common.TrustAnchor(root, constrained=False)
time = common.DEFAULT_TIME
verify_result = False
errors = """[Context] Processing Certificate
  index: 1
      [Error] Unacceptable signature algorithm
      [Error] VerifySignedData failed
"""

common.write_test_file(__doc__, chain, trusted, time, verify_result, errors)
