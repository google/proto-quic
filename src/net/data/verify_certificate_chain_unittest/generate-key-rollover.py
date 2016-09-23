#!/usr/bin/python
# Copyright (c) 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A certificate tree with two self-signed root certificates(oldroot, newroot),
and a third root certificate (newrootrollover) which has the same key as newroot
but is signed by oldroot, all with the same subject and issuer.
There are two intermediates with the same key, subject and issuer
(oldintermediate signed by oldroot, and newintermediate signed by newroot).
The target certificate is signed by the intermediate key.


In graphical form:

   oldroot-------->newrootrollover  newroot
      |                      |        |
      v                      v        v
oldintermediate           newintermediate
      |                          |
      +------------+-------------+
                   |
                   v
                 target


Several chains are output:
  key-rollover-oldchain.pem:
    target<-oldintermediate<-oldroot
  key-rollover-rolloverchain.pem:
    target<-newintermediate<-newrootrollover<-oldroot
  key-rollover-longrolloverchain.pem:
    target<-newintermediate<-newroot<-newrootrollover<-oldroot
  key-rollover-newchain.pem:
    target<-newintermediate<-newroot

All of these chains should verify successfully.
"""

import common

# The new certs should have a newer notbefore date than "old" certs. This should
# affect path builder sorting, but otherwise won't matter.
JANUARY_2_2015_UTC = '150102120000Z'

# Self-signed root certificates. Same name, different keys.
oldroot = common.create_self_signed_root_certificate('Root')
oldroot.set_validity_range(common.JANUARY_1_2015_UTC, common.JANUARY_1_2016_UTC)
newroot = common.create_self_signed_root_certificate('Root')
newroot.set_validity_range(JANUARY_2_2015_UTC, common.JANUARY_1_2016_UTC)
# Root with the new key signed by the old key.
newrootrollover = common.create_intermediate_certificate('Root', oldroot)
newrootrollover.set_key(newroot.get_key())
newrootrollover.set_validity_range(JANUARY_2_2015_UTC,
                                   common.JANUARY_1_2016_UTC)

# Intermediate signed by oldroot.
oldintermediate = common.create_intermediate_certificate('Intermediate',
                                                         oldroot)
oldintermediate.set_validity_range(common.JANUARY_1_2015_UTC,
                                   common.JANUARY_1_2016_UTC)
# Intermediate signed by newroot. Same key as oldintermediate.
newintermediate = common.create_intermediate_certificate('Intermediate',
                                                         newroot)
newintermediate.set_key(oldintermediate.get_key())
newintermediate.set_validity_range(JANUARY_2_2015_UTC,
                                   common.JANUARY_1_2016_UTC)

# Target certificate.
target = common.create_end_entity_certificate('Target', oldintermediate)

oldchain = [target, oldintermediate]
rolloverchain = [target, newintermediate, newrootrollover]
longrolloverchain = [target, newintermediate, newroot, newrootrollover]
oldtrusted = common.TrustAnchor(oldroot, constrained=False)

newchain = [target, newintermediate]
newtrusted = common.TrustAnchor(newroot, constrained=False)

time = common.DEFAULT_TIME
verify_result = True
errors = None

common.write_test_file(__doc__, oldchain, oldtrusted, time, verify_result,
                       errors, out_pem="key-rollover-oldchain.pem")
common.write_test_file(__doc__, rolloverchain, oldtrusted, time, verify_result,
                       errors, out_pem="key-rollover-rolloverchain.pem")
common.write_test_file(__doc__, longrolloverchain, oldtrusted, time,
                       verify_result, errors,
                       out_pem="key-rollover-longrolloverchain.pem")
common.write_test_file(__doc__, newchain, newtrusted, time, verify_result,
                       errors, out_pem="key-rollover-newchain.pem")
