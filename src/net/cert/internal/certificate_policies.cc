// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>

#include "net/cert/internal/certificate_policies.h"

#include "net/der/input.h"
#include "net/der/parser.h"
#include "net/der/tag.h"

namespace net {

namespace {

// -- policyQualifierIds for Internet policy qualifiers
//
// id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
// id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
//
// In dotted decimal form: 1.3.6.1.5.5.7.2.1
const der::Input CpsPointerId() {
  static const uint8_t cps_pointer_id[] = {0x2b, 0x06, 0x01, 0x05,
                                           0x05, 0x07, 0x02, 0x01};
  return der::Input(cps_pointer_id);
}

// id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
//
// In dotted decimal form: 1.3.6.1.5.5.7.2.2
const der::Input UserNoticeId() {
  static const uint8_t user_notice_id[] = {0x2b, 0x06, 0x01, 0x05,
                                           0x05, 0x07, 0x02, 0x02};
  return der::Input(user_notice_id);
}

// Ignores the policyQualifiers, but does some minimal correctness checking.
// TODO(mattm): parse and return the policyQualifiers, since the cert viewer
// still needs to display them.
bool ParsePolicyQualifiers(const der::Input& policy_oid,
                           der::Parser* policy_qualifiers_sequence_parser) {
  // If it is present, the policyQualifiers sequence should have at least 1
  // element.
  if (!policy_qualifiers_sequence_parser->HasMore())
    return false;
  while (policy_qualifiers_sequence_parser->HasMore()) {
    der::Parser policy_information_parser;
    if (!policy_qualifiers_sequence_parser->ReadSequence(
            &policy_information_parser)) {
      return false;
    }
    der::Input qualifier_oid;
    if (!policy_information_parser.ReadTag(der::kOid, &qualifier_oid))
      return false;
    // RFC 5280 section 4.2.1.4: When qualifiers are used with the special
    // policy anyPolicy, they MUST be limited to the qualifiers identified in
    // this section.
    if (policy_oid == AnyPolicy() && qualifier_oid != CpsPointerId() &&
        qualifier_oid != UserNoticeId()) {
      return false;
    }
    der::Tag tag;
    der::Input value;
    if (!policy_information_parser.ReadTagAndValue(&tag, &value))
      return false;
    // Should not have trailing data after qualifier.
    if (policy_information_parser.HasMore())
      return false;
  }
  return true;
}

}  // namespace

const der::Input AnyPolicy() {
  // id-ce OBJECT IDENTIFIER  ::=  {joint-iso-ccitt(2) ds(5) 29}
  //
  // id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }
  //
  // anyPolicy OBJECT IDENTIFIER ::= { id-ce-certificatePolicies 0 }
  //
  // In dotted decimal form: 2.5.29.32.0
  static const uint8_t any_policy[] = {0x55, 0x1D, 0x20, 0x00};
  return der::Input(any_policy);
}

// RFC 5280 section 4.2.1.4.  Certificate Policies:
//
// certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
//
// PolicyInformation ::= SEQUENCE {
//      policyIdentifier   CertPolicyId,
//      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
//                              PolicyQualifierInfo OPTIONAL }
//
// CertPolicyId ::= OBJECT IDENTIFIER
//
// PolicyQualifierInfo ::= SEQUENCE {
//      policyQualifierId  PolicyQualifierId,
//      qualifier          ANY DEFINED BY policyQualifierId }
//
// PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
//
// Qualifier ::= CHOICE {
//      cPSuri           CPSuri,
//      userNotice       UserNotice }
//
// CPSuri ::= IA5String
//
// UserNotice ::= SEQUENCE {
//      noticeRef        NoticeReference OPTIONAL,
//      explicitText     DisplayText OPTIONAL }
//
// NoticeReference ::= SEQUENCE {
//      organization     DisplayText,
//      noticeNumbers    SEQUENCE OF INTEGER }
//
// DisplayText ::= CHOICE {
//      ia5String        IA5String      (SIZE (1..200)),
//      visibleString    VisibleString  (SIZE (1..200)),
//      bmpString        BMPString      (SIZE (1..200)),
//      utf8String       UTF8String     (SIZE (1..200)) }
bool ParseCertificatePoliciesExtension(const der::Input& extension_value,
                                       std::vector<der::Input>* policies) {
  der::Parser extension_parser(extension_value);
  der::Parser policies_sequence_parser;
  if (!extension_parser.ReadSequence(&policies_sequence_parser))
    return false;
  // Should not have trailing data after certificatePolicies sequence.
  if (extension_parser.HasMore())
    return false;
  // The certificatePolicies sequence should have at least 1 element.
  if (!policies_sequence_parser.HasMore())
    return false;

  policies->clear();

  while (policies_sequence_parser.HasMore()) {
    der::Parser policy_information_parser;
    if (!policies_sequence_parser.ReadSequence(&policy_information_parser))
      return false;
    der::Input policy_oid;
    if (!policy_information_parser.ReadTag(der::kOid, &policy_oid))
      return false;

    // Build the |policies| vector in sorted order (sorted on DER encoded policy
    // OID). Use a binary search to check whether a duplicate policy is present,
    // and if not, where to insert the policy to maintain the sorted order.
    std::vector<der::Input>::iterator i =
        std::lower_bound(policies->begin(), policies->end(), policy_oid);
    // RFC 5280 section 4.2.1.4: A certificate policy OID MUST NOT appear more
    // than once in a certificate policies extension.
    if (i != policies->end() && *i == policy_oid)
      return false;

    policies->insert(i, policy_oid);

    if (!policy_information_parser.HasMore())
      continue;

    der::Parser policy_qualifiers_sequence_parser;
    if (!policy_information_parser.ReadSequence(
            &policy_qualifiers_sequence_parser)) {
      return false;
    }
    // Should not have trailing data after policyQualifiers sequence.
    if (policy_information_parser.HasMore())
      return false;
    if (!ParsePolicyQualifiers(policy_oid, &policy_qualifiers_sequence_parser))
      return false;
  }

  return true;
}

}  // namespace net
