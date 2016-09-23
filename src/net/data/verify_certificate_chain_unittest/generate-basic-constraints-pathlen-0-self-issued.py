#!/usr/bin/python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Certificate chain with 2 intermediates. The first intermediate has a basic
constraints path length of 0. The second one is self-issued so does not count
against the path length."""

import common

# Self-signed root certificate (used as trust anchor).
root = common.create_self_signed_root_certificate('Root')

# Intermediate with pathlen 0
intermediate1 = common.create_intermediate_certificate('Intermediate', root)
intermediate1.get_extensions().set_property('basicConstraints',
                                            'critical,CA:true,pathlen:0')

# Another intermediate (with the same pathlen restriction).
# Note that this is self-issued but NOT self-signed.
intermediate2 = common.create_intermediate_certificate('Intermediate',
                                                       intermediate1)
intermediate2.get_extensions().set_property('basicConstraints',
                                            'critical,CA:true,pathlen:0')

# Target certificate.
target = common.create_end_entity_certificate('Target', intermediate2)

chain = [target, intermediate2, intermediate1]
trusted = common.TrustAnchor(root, constrained=False)
time = common.DEFAULT_TIME
verify_result = True
errors = None

common.write_test_file(__doc__, chain, trusted, time, verify_result, errors)
