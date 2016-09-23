#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain where the target has an incorrect signature. Everything
else should check out, however the digital signature contained in the target
certificate is wrong."""

import common

# Self-signed root certificate (used as trust anchor).
root = common.create_self_signed_root_certificate('Root')

# Intermediate certificate to include in the certificate chain.
intermediate = common.create_intermediate_certificate('Intermediate', root)

# Actual intermediate that was used to sign the target certificate. It has the
# same subject as expected, but a different RSA key from the certificate
# included in the actual chain.
wrong_intermediate = common.create_intermediate_certificate('Intermediate',
                                                            root)

# Target certificate, signed using |wrong_intermediate| NOT |intermediate|.
target = common.create_end_entity_certificate('Target', wrong_intermediate)

chain = [target, intermediate]
trusted = common.TrustAnchor(root, constrained=False)
time = common.DEFAULT_TIME
verify_result = False
errors = """[Context] Processing Certificate
  index: 1
      [Error] Signature verification failed
      [Error] VerifySignedData failed
"""

common.write_test_file(__doc__, chain, trusted, time, verify_result, errors)
