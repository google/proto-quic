// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/name_constraints.h"

#include <limits.h>

#include <memory>

#include "base/strings/string_util.h"
#include "net/cert/internal/verify_name_match.h"
#include "net/der/input.h"
#include "net/der/parser.h"
#include "net/der/tag.h"

namespace net {

namespace {

// The name types of GeneralName that are fully supported in name constraints.
//
// (The other types will have the minimal checking described by RFC 5280
// section 4.2.1.10: If a name constraints extension that is marked as critical
// imposes constraints on a particular name form, and an instance of
// that name form appears in the subject field or subjectAltName
// extension of a subsequent certificate, then the application MUST
// either process the constraint or reject the certificate.)
const int kSupportedNameTypes = GENERAL_NAME_DNS_NAME |
                                GENERAL_NAME_DIRECTORY_NAME |
                                GENERAL_NAME_IP_ADDRESS;

// Controls wildcard handling of DNSNameMatches.
// If WildcardMatchType is WILDCARD_PARTIAL_MATCH "*.bar.com" is considered to
// match the constraint "foo.bar.com". If it is WILDCARD_FULL_MATCH, "*.bar.com"
// will match "bar.com" but not "foo.bar.com".
enum WildcardMatchType { WILDCARD_PARTIAL_MATCH, WILDCARD_FULL_MATCH };

// Returns true if |name| falls in the subtree defined by |dns_constraint|.
// RFC 5280 section 4.2.1.10:
// DNS name restrictions are expressed as host.example.com. Any DNS
// name that can be constructed by simply adding zero or more labels
// to the left-hand side of the name satisfies the name constraint. For
// example, www.host.example.com would satisfy the constraint but
// host1.example.com would not.
//
// |wildcard_matching| controls handling of wildcard names (|name| starts with
// "*."). Wildcard handling is not specified by RFC 5280, but certificate
// verification allows it, name constraints must check it similarly.
bool DNSNameMatches(base::StringPiece name,
                    base::StringPiece dns_constraint,
                    WildcardMatchType wildcard_matching) {
  // Everything matches the empty DNS name constraint.
  if (dns_constraint.empty())
    return true;

  // Normalize absolute DNS names by removing the trailing dot, if any.
  if (!name.empty() && *name.rbegin() == '.')
    name.remove_suffix(1);
  if (!dns_constraint.empty() && *dns_constraint.rbegin() == '.')
    dns_constraint.remove_suffix(1);

  // Wildcard partial-match handling ("*.bar.com" matching name constraint
  // "foo.bar.com"). This only handles the case where the the dnsname and the
  // constraint match after removing the leftmost label, otherwise it is handled
  // by falling through to the check of whether the dnsname is fully within or
  // fully outside of the constraint.
  if (wildcard_matching == WILDCARD_PARTIAL_MATCH && name.size() > 2 &&
      name[0] == '*' && name[1] == '.') {
    size_t dns_constraint_dot_pos = dns_constraint.find('.');
    if (dns_constraint_dot_pos != std::string::npos) {
      base::StringPiece dns_constraint_domain(
          dns_constraint.begin() + dns_constraint_dot_pos + 1,
          dns_constraint.size() - dns_constraint_dot_pos - 1);
      base::StringPiece wildcard_domain(name.begin() + 2, name.size() - 2);
      if (base::EqualsCaseInsensitiveASCII(wildcard_domain,
                                           dns_constraint_domain)) {
        return true;
      }
    }
  }

  if (!base::EndsWith(name, dns_constraint,
                      base::CompareCase::INSENSITIVE_ASCII)) {
    return false;
  }
  // Exact match.
  if (name.size() == dns_constraint.size())
    return true;
  // If dNSName constraint starts with a dot, only subdomains should match.
  // (e.g., "foo.bar.com" matches constraint ".bar.com", but "bar.com" doesn't.)
  // RFC 5280 is ambiguous, but this matches the behavior of other platforms.
  if (!dns_constraint.empty() && dns_constraint[0] == '.')
    dns_constraint.remove_prefix(1);
  // Subtree match.
  if (name.size() > dns_constraint.size() &&
      name[name.size() - dns_constraint.size() - 1] == '.') {
    return true;
  }
  // Trailing text matches, but not in a subtree (e.g., "foobar.com" is not a
  // match for "bar.com").
  return false;
}

// Return true if the bitmask |mask| contains only zeros after the first
// |prefix_length| bits.
bool IsSuffixZero(const std::vector<uint8_t>& mask, unsigned prefix_length) {
  size_t zero_bits = mask.size() * CHAR_BIT - prefix_length;
  size_t zero_bytes = zero_bits / CHAR_BIT;
  std::vector<uint8_t> zeros(zero_bytes, 0);
  if (memcmp(zeros.data(), mask.data() + mask.size() - zero_bytes, zero_bytes))
    return false;
  size_t leftover_bits = zero_bits % CHAR_BIT;
  if (leftover_bits) {
    uint8_t b = mask[mask.size() - zero_bytes - 1];
    for (size_t i = 0; i < leftover_bits; ++i) {
      if (b & (1 << i))
        return false;
    }
  }
  return true;
}

// Controls handling of unsupported name types in ParseGeneralName. (Unsupported
// types are those not in kSupportedNameTypes.)
// RECORD_UNSUPPORTED causes unsupported types to be recorded in
// |present_name_types|.
// IGNORE_UNSUPPORTED causes unsupported types to not be recorded.
enum ParseGeneralNameUnsupportedTypeBehavior {
  RECORD_UNSUPPORTED,
  IGNORE_UNSUPPORTED,
};

// Controls parsing of iPAddress names in ParseGeneralName.
// IP_ADDRESS_ONLY parses the iPAddress names as a 4 or 16 byte IP address.
// IP_ADDRESS_AND_NETMASK parses the iPAddress names as 8 or 32 bytes containing
// an IP address followed by a netmask.
enum ParseGeneralNameIPAddressType {
  IP_ADDRESS_ONLY,
  IP_ADDRESS_AND_NETMASK,
};

// Parses a GeneralName value and adds it to |subtrees|.
WARN_UNUSED_RESULT bool ParseGeneralName(
    const der::Input& input,
    ParseGeneralNameUnsupportedTypeBehavior unsupported_type_behavior,
    ParseGeneralNameIPAddressType ip_address_type,
    GeneralNames* subtrees) {
  der::Parser parser(input);
  der::Tag tag;
  der::Input value;
  if (!parser.ReadTagAndValue(&tag, &value))
    return false;
  GeneralNameTypes name_type = GENERAL_NAME_NONE;
  if (tag == der::ContextSpecificConstructed(0)) {
    // otherName                       [0]     OtherName,
    name_type = GENERAL_NAME_OTHER_NAME;
  } else if (tag == der::ContextSpecificPrimitive(1)) {
    // rfc822Name                      [1]     IA5String,
    name_type = GENERAL_NAME_RFC822_NAME;
  } else if (tag == der::ContextSpecificPrimitive(2)) {
    // dNSName                         [2]     IA5String,
    name_type = GENERAL_NAME_DNS_NAME;
    const std::string s = value.AsString();
    if (!base::IsStringASCII(s))
      return false;
    subtrees->dns_names.push_back(s);
  } else if (tag == der::ContextSpecificConstructed(3)) {
    // x400Address                     [3]     ORAddress,
    name_type = GENERAL_NAME_X400_ADDRESS;
  } else if (tag == der::ContextSpecificConstructed(4)) {
    // directoryName                   [4]     Name,
    name_type = GENERAL_NAME_DIRECTORY_NAME;
    // Name is a CHOICE { rdnSequence  RDNSequence }, therefore the SEQUENCE
    // tag is explicit. Remove it, since the name matching functions expect
    // only the value portion.
    der::Parser name_parser(value);
    der::Input name_value;
    if (!name_parser.ReadTag(der::kSequence, &name_value) || parser.HasMore())
      return false;
    subtrees->directory_names.push_back(
        std::vector<uint8_t>(name_value.UnsafeData(),
                             name_value.UnsafeData() + name_value.Length()));
  } else if (tag == der::ContextSpecificConstructed(5)) {
    // ediPartyName                    [5]     EDIPartyName,
    name_type = GENERAL_NAME_EDI_PARTY_NAME;
  } else if (tag == der::ContextSpecificPrimitive(6)) {
    // uniformResourceIdentifier       [6]     IA5String,
    name_type = GENERAL_NAME_UNIFORM_RESOURCE_IDENTIFIER;
  } else if (tag == der::ContextSpecificPrimitive(7)) {
    // iPAddress                       [7]     OCTET STRING,
    name_type = GENERAL_NAME_IP_ADDRESS;
    if (ip_address_type == IP_ADDRESS_ONLY) {
      // RFC 5280 section 4.2.1.6:
      // When the subjectAltName extension contains an iPAddress, the address
      // MUST be stored in the octet string in "network byte order", as
      // specified in [RFC791].  The least significant bit (LSB) of each octet
      // is the LSB of the corresponding byte in the network address.  For IP
      // version 4, as specified in [RFC791], the octet string MUST contain
      // exactly four octets.  For IP version 6, as specified in [RFC2460],
      // the octet string MUST contain exactly sixteen octets.
      if ((value.Length() != IPAddress::kIPv4AddressSize &&
           value.Length() != IPAddress::kIPv6AddressSize)) {
        return false;
      }
      subtrees->ip_addresses.push_back(
          IPAddress(value.UnsafeData(), value.Length()));
    } else {
      DCHECK_EQ(ip_address_type, IP_ADDRESS_AND_NETMASK);
      // RFC 5280 section 4.2.1.10:
      // The syntax of iPAddress MUST be as described in Section 4.2.1.6 with
      // the following additions specifically for name constraints. For IPv4
      // addresses, the iPAddress field of GeneralName MUST contain eight (8)
      // octets, encoded in the style of RFC 4632 (CIDR) to represent an
      // address range [RFC4632]. For IPv6 addresses, the iPAddress field
      // MUST contain 32 octets similarly encoded. For example, a name
      // constraint for "class C" subnet 192.0.2.0 is represented as the
      // octets C0 00 02 00 FF FF FF 00, representing the CIDR notation
      // 192.0.2.0/24 (mask 255.255.255.0).
      if (value.Length() != IPAddress::kIPv4AddressSize * 2 &&
          value.Length() != IPAddress::kIPv6AddressSize * 2) {
        return false;
      }
      const IPAddress mask(value.UnsafeData() + value.Length() / 2,
                           value.Length() / 2);
      const unsigned mask_prefix_length = MaskPrefixLength(mask);
      if (!IsSuffixZero(mask.bytes(), mask_prefix_length))
        return false;
      subtrees->ip_address_ranges.push_back(
          std::make_pair(IPAddress(value.UnsafeData(), value.Length() / 2),
                         mask_prefix_length));
    }
  } else if (tag == der::ContextSpecificPrimitive(8)) {
    // registeredID                    [8]     OBJECT IDENTIFIER }
    name_type = GENERAL_NAME_REGISTERED_ID;
  } else {
    return false;
  }
  DCHECK_NE(GENERAL_NAME_NONE, name_type);
  if ((name_type & kSupportedNameTypes) ||
      unsupported_type_behavior == RECORD_UNSUPPORTED) {
    subtrees->present_name_types |= name_type;
  }
  return true;
}

// Parses a GeneralSubtrees |value| and store the contents in |subtrees|.
// The individual values stored into |subtrees| are not validated by this
// function.
// NOTE: |subtrees| is not pre-initialized by the function(it is expected to be
// a default initialized object), and it will be modified regardless of the
// return value.
WARN_UNUSED_RESULT bool ParseGeneralSubtrees(const der::Input& value,
                                             bool is_critical,
                                             GeneralNames* subtrees) {
  // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
  //
  // GeneralSubtree ::= SEQUENCE {
  //      base                    GeneralName,
  //      minimum         [0]     BaseDistance DEFAULT 0,
  //      maximum         [1]     BaseDistance OPTIONAL }
  //
  // BaseDistance ::= INTEGER (0..MAX)
  der::Parser sequence_parser(value);
  // The GeneralSubtrees sequence should have at least 1 element.
  if (!sequence_parser.HasMore())
    return false;
  while (sequence_parser.HasMore()) {
    der::Parser subtree_sequence;
    if (!sequence_parser.ReadSequence(&subtree_sequence))
      return false;

    der::Input raw_general_name;
    if (!subtree_sequence.ReadRawTLV(&raw_general_name))
      return false;

    if (!ParseGeneralName(raw_general_name,
                          is_critical ? RECORD_UNSUPPORTED : IGNORE_UNSUPPORTED,
                          IP_ADDRESS_AND_NETMASK, subtrees)) {
      return false;
    }

    // RFC 5280 section 4.2.1.10:
    // Within this profile, the minimum and maximum fields are not used with any
    // name forms, thus, the minimum MUST be zero, and maximum MUST be absent.
    // However, if an application encounters a critical name constraints
    // extension that specifies other values for minimum or maximum for a name
    // form that appears in a subsequent certificate, the application MUST
    // either process these fields or reject the certificate.

    // Note that technically failing here isn't required: rather only need to
    // fail if a name of this type actually appears in a subsequent cert and
    // this extension was marked critical. However the minimum and maximum
    // fields appear uncommon enough that implementing that isn't useful.
    if (subtree_sequence.HasMore())
      return false;
  }
  return true;
}

}  // namespace

GeneralNames::GeneralNames() {}

GeneralNames::~GeneralNames() {}

// static
std::unique_ptr<GeneralNames> GeneralNames::Create(
    const der::Input& general_names_tlv) {
  // RFC 5280 section 4.2.1.6:
  // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
  std::unique_ptr<GeneralNames> general_names(new GeneralNames());
  der::Parser parser(general_names_tlv);
  der::Parser sequence_parser;
  if (!parser.ReadSequence(&sequence_parser))
    return nullptr;
  // Should not have trailing data after GeneralNames sequence.
  if (parser.HasMore())
    return nullptr;
  // The GeneralNames sequence should have at least 1 element.
  if (!sequence_parser.HasMore())
    return nullptr;

  while (sequence_parser.HasMore()) {
    der::Input raw_general_name;
    if (!sequence_parser.ReadRawTLV(&raw_general_name))
      return nullptr;

    if (!ParseGeneralName(raw_general_name, RECORD_UNSUPPORTED, IP_ADDRESS_ONLY,
                          general_names.get()))
      return nullptr;
  }

  return general_names;
}

NameConstraints::~NameConstraints() {}

// static
std::unique_ptr<NameConstraints> NameConstraints::Create(
    const der::Input& extension_value,
    bool is_critical) {
  std::unique_ptr<NameConstraints> name_constraints(new NameConstraints());
  if (!name_constraints->Parse(extension_value, is_critical))
    return nullptr;
  return name_constraints;
}

bool NameConstraints::Parse(const der::Input& extension_value,
                            bool is_critical) {
  der::Parser extension_parser(extension_value);
  der::Parser sequence_parser;

  // NameConstraints ::= SEQUENCE {
  //      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
  //      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
  if (!extension_parser.ReadSequence(&sequence_parser))
    return false;
  if (extension_parser.HasMore())
    return false;

  bool had_permitted_subtrees = false;
  der::Input permitted_subtrees_value;
  if (!sequence_parser.ReadOptionalTag(der::ContextSpecificConstructed(0),
                                       &permitted_subtrees_value,
                                       &had_permitted_subtrees)) {
    return false;
  }
  if (had_permitted_subtrees &&
      !ParseGeneralSubtrees(permitted_subtrees_value, is_critical,
                            &permitted_subtrees_)) {
    return false;
  }

  bool had_excluded_subtrees = false;
  der::Input excluded_subtrees_value;
  if (!sequence_parser.ReadOptionalTag(der::ContextSpecificConstructed(1),
                                       &excluded_subtrees_value,
                                       &had_excluded_subtrees)) {
    return false;
  }
  if (had_excluded_subtrees &&
      !ParseGeneralSubtrees(excluded_subtrees_value, is_critical,
                            &excluded_subtrees_)) {
    return false;
  }

  // RFC 5280 section 4.2.1.10:
  // Conforming CAs MUST NOT issue certificates where name constraints is an
  // empty sequence. That is, either the permittedSubtrees field or the
  // excludedSubtrees MUST be present.
  if (!had_permitted_subtrees && !had_excluded_subtrees)
    return false;

  if (sequence_parser.HasMore())
    return false;

  return true;
}

bool NameConstraints::IsPermittedCert(
    const der::Input& subject_rdn_sequence,
    const GeneralNames* subject_alt_names) const {
  // Subject Alternative Name handling:
  //
  // RFC 5280 section 4.2.1.6:
  // id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }
  //
  // SubjectAltName ::= GeneralNames
  //
  // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

  if (subject_alt_names) {
    // Check unsupported name types:
    // ConstrainedNameTypes for the unsupported types will only be true if that
    // type of name was present in a name constraint that was marked critical.
    //
    // RFC 5280 section 4.2.1.10:
    // If a name constraints extension that is marked as critical
    // imposes constraints on a particular name form, and an instance of
    // that name form appears in the subject field or subjectAltName
    // extension of a subsequent certificate, then the application MUST
    // either process the constraint or reject the certificate.
    if (ConstrainedNameTypes() & subject_alt_names->present_name_types &
        ~kSupportedNameTypes) {
      return false;
    }

    // Check supported name types:
    for (const auto& dns_name : subject_alt_names->dns_names) {
      if (!IsPermittedDNSName(dns_name))
        return false;
    }

    for (const auto& directory_name : subject_alt_names->directory_names) {
      if (!IsPermittedDirectoryName(
              der::Input(directory_name.data(), directory_name.size()))) {
        return false;
      }
    }

    for (const auto& ip_address : subject_alt_names->ip_addresses) {
      if (!IsPermittedIP(ip_address))
        return false;
    }
  }

  // Subject handling:

  // RFC 5280 section 4.2.1.10:
  // Legacy implementations exist where an electronic mail address is embedded
  // in the subject distinguished name in an attribute of type emailAddress
  // (Section 4.1.2.6). When constraints are imposed on the rfc822Name name
  // form, but the certificate does not include a subject alternative name, the
  // rfc822Name constraint MUST be applied to the attribute of type emailAddress
  // in the subject distinguished name.
  if (!subject_alt_names &&
      (ConstrainedNameTypes() & GENERAL_NAME_RFC822_NAME)) {
    bool contained_email_address = false;
    if (!NameContainsEmailAddress(subject_rdn_sequence,
                                  &contained_email_address)) {
      return false;
    }
    if (contained_email_address)
      return false;
  }

  // RFC 5280 4.1.2.6:
  // If subject naming information is present only in the subjectAltName
  // extension (e.g., a key bound only to an email address or URI), then the
  // subject name MUST be an empty sequence and the subjectAltName extension
  // MUST be critical.
  // This code assumes that criticality condition is checked by the caller, and
  // therefore only needs to avoid the IsPermittedDirectoryName check against an
  // empty subject in such a case.
  if (subject_alt_names && subject_rdn_sequence.Length() == 0)
    return true;

  return IsPermittedDirectoryName(subject_rdn_sequence);
}

bool NameConstraints::IsPermittedDNSName(const std::string& name) const {
  for (const std::string& excluded_name : excluded_subtrees_.dns_names) {
    // When matching wildcard hosts against excluded subtrees, consider it a
    // match if the constraint would match any expansion of the wildcard. Eg,
    // *.bar.com should match a constraint of foo.bar.com.
    if (DNSNameMatches(name, excluded_name, WILDCARD_PARTIAL_MATCH))
      return false;
  }

  // If permitted subtrees are not constrained, any name that is not excluded is
  // allowed.
  if (!(permitted_subtrees_.present_name_types & GENERAL_NAME_DNS_NAME))
    return true;

  for (const std::string& permitted_name : permitted_subtrees_.dns_names) {
    // When matching wildcard hosts against permitted subtrees, consider it a
    // match only if the constraint would match all expansions of the wildcard.
    // Eg, *.bar.com should match a constraint of bar.com, but not foo.bar.com.
    if (DNSNameMatches(name, permitted_name, WILDCARD_FULL_MATCH))
      return true;
  }

  return false;
}

bool NameConstraints::IsPermittedDirectoryName(
    const der::Input& name_rdn_sequence) const {
  for (const auto& excluded_name : excluded_subtrees_.directory_names) {
    if (VerifyNameInSubtree(
            name_rdn_sequence,
            der::Input(excluded_name.data(), excluded_name.size()))) {
      return false;
    }
  }

  // If permitted subtrees are not constrained, any name that is not excluded is
  // allowed.
  if (!(permitted_subtrees_.present_name_types & GENERAL_NAME_DIRECTORY_NAME))
    return true;

  for (const auto& permitted_name : permitted_subtrees_.directory_names) {
    if (VerifyNameInSubtree(
            name_rdn_sequence,
            der::Input(permitted_name.data(), permitted_name.size()))) {
      return true;
    }
  }

  return false;
}

bool NameConstraints::IsPermittedIP(const IPAddress& ip) const {
  for (const auto& excluded_ip : excluded_subtrees_.ip_address_ranges) {
    if (IPAddressMatchesPrefix(ip, excluded_ip.first, excluded_ip.second))
      return false;
  }

  // If permitted subtrees are not constrained, any name that is not excluded is
  // allowed.
  if (!(permitted_subtrees_.present_name_types & GENERAL_NAME_IP_ADDRESS))
    return true;

  for (const auto& permitted_ip : permitted_subtrees_.ip_address_ranges) {
    if (IPAddressMatchesPrefix(ip, permitted_ip.first, permitted_ip.second))
      return true;
  }

  return false;
}

int NameConstraints::ConstrainedNameTypes() const {
  return (permitted_subtrees_.present_name_types |
          excluded_subtrees_.present_name_types);
}

}  // namespace net
