// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_NAME_CONSTRAINTS_H_
#define NET_CERT_INTERNAL_NAME_CONSTRAINTS_H_

#include <stdint.h>

#include <memory>
#include <vector>

#include "base/compiler_specific.h"
#include "net/base/ip_address.h"

namespace net {

namespace der {
class Input;
}  // namespace der

// Bitfield values for the GeneralName types defined in RFC 5280. The ordering
// and exact values are not important, but match the order from the RFC for
// convenience.
enum GeneralNameTypes {
  GENERAL_NAME_NONE = 0,
  GENERAL_NAME_OTHER_NAME = 1 << 0,
  GENERAL_NAME_RFC822_NAME = 1 << 1,
  GENERAL_NAME_DNS_NAME = 1 << 2,
  GENERAL_NAME_X400_ADDRESS = 1 << 3,
  GENERAL_NAME_DIRECTORY_NAME = 1 << 4,
  GENERAL_NAME_EDI_PARTY_NAME = 1 << 5,
  GENERAL_NAME_UNIFORM_RESOURCE_IDENTIFIER = 1 << 6,
  GENERAL_NAME_IP_ADDRESS = 1 << 7,
  GENERAL_NAME_REGISTERED_ID = 1 << 8,
};

// Represents a GeneralNames structure. When processing GeneralNames, it is
// often necessary to know which types of names were present, and to check
// all the names of a certain type. Therefore, a bitfield of all the name
// types is kept, and the names are split into members for each type. Only
// name types that are handled by this code are stored (though all types are
// recorded in the bitfield.)
// TODO(mattm): move this to some other file?
struct NET_EXPORT GeneralNames {
  GeneralNames();
  ~GeneralNames();

  // Create a GeneralNames object representing the DER-encoded
  // |general_names_tlv|.
  static std::unique_ptr<GeneralNames> CreateFromDer(
      const der::Input& general_names_tlv);

  // ASCII hostnames.
  std::vector<std::string> dns_names;

  // DER-encoded Name values (not including the Sequence tag).
  std::vector<std::vector<uint8_t>> directory_names;

  // iPAddresses as sequences of octets in network byte order. This will be
  // populated if the GeneralNames represents a Subject Alternative Name.
  std::vector<IPAddress> ip_addresses;

  // iPAddress ranges, as <IP, prefix length> pairs. This will be populated
  // if the GeneralNames represents a Name Constraints.
  std::vector<std::pair<IPAddress, unsigned>> ip_address_ranges;

  // Which name types were present, as a bitfield of GeneralNameTypes.
  // Includes both the supported and unsupported types (although unsupported
  // ones may not be recorded depending on the context, like non-critical name
  // constraints.)
  int present_name_types = GENERAL_NAME_NONE;
};

// Parses a NameConstraints extension value and allows testing whether names are
// allowed under those constraints as defined by RFC 5280 section 4.2.1.10.
class NET_EXPORT NameConstraints {
 public:

  ~NameConstraints();

  // Parses a DER-encoded NameConstraints extension and initializes this object.
  // |extension_value| should be the extnValue from the extension (not including
  // the OCTET STRING tag). |is_critical| should be true if the extension was
  // marked critical. Returns nullptr if parsing the the extension failed.
  // The object lifetime is not bound to the lifetime of |extension_value| data.
  static std::unique_ptr<NameConstraints> CreateFromDer(
      const der::Input& extension_value,
      bool is_critical);

  // Tests if a certificate is allowed by the name constraints.
  // |subject_rdn_sequence| should be the DER-encoded value of the subject's
  // RDNSequence (not including Sequence tag), and may be an empty ASN.1
  // sequence. |subject_alt_names| should be the parsed representation of the
  // subjectAltName extension or nullptr if the extension was not present.
  // Note that this method does not check hostname or IP address in commonName,
  // which is deprecated (crbug.com/308330).
  bool IsPermittedCert(const der::Input& subject_rdn_sequence,
                       const GeneralNames* subject_alt_names) const;

  // Returns true if the ASCII hostname |name| is permitted.
  // |name| may be a wildcard hostname (starts with "*."). Eg, "*.bar.com"
  // would not be permitted if "bar.com" is permitted and "foo.bar.com" is
  // excluded, while "*.baz.com" would only be permitted if "baz.com" is
  // permitted.
  bool IsPermittedDNSName(const std::string& name) const;

  // Returns true if the directoryName |name_rdn_sequence| is permitted.
  // |name_rdn_sequence| should be the DER-encoded RDNSequence value (not
  // including the Sequence tag.)
  bool IsPermittedDirectoryName(const der::Input& name_rdn_sequence) const;

  // Returns true if the iPAddress |ip| is permitted.
  bool IsPermittedIP(const IPAddress& ip) const;

  // Returns a bitfield of GeneralNameTypes of all the types constrained by this
  // NameConstraints. Name types that aren't supported will only be present if
  // the name constraint they appeared in was marked critical.
  //
  // RFC 5280 section 4.2.1.10 says:
  // Applications conforming to this profile MUST be able to process name
  // constraints that are imposed on the directoryName name form and SHOULD be
  // able to process name constraints that are imposed on the rfc822Name,
  // uniformResourceIdentifier, dNSName, and iPAddress name forms.
  // If a name constraints extension that is marked as critical
  // imposes constraints on a particular name form, and an instance of
  // that name form appears in the subject field or subjectAltName
  // extension of a subsequent certificate, then the application MUST
  // either process the constraint or reject the certificate.
  int ConstrainedNameTypes() const;

 private:
  bool Parse(const der::Input& extension_value,
             bool is_critical) WARN_UNUSED_RESULT;

  GeneralNames permitted_subtrees_;
  GeneralNames excluded_subtrees_;
};

}  // namespace net

#endif  // NET_CERT_INTERNAL_NAME_CONSTRAINTS_H_
