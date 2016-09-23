// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_PARSED_CERTIFICATE_H_
#define NET_CERT_INTERNAL_PARSED_CERTIFICATE_H_

#include <map>
#include <memory>
#include <vector>

#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"
#include "net/cert/internal/parse_certificate.h"
#include "net/der/input.h"

namespace net {

struct GeneralNames;
class NameConstraints;
class ParsedCertificate;
class SignatureAlgorithm;
class CertErrors;

using ParsedCertificateList = std::vector<scoped_refptr<ParsedCertificate>>;

// Represents an X.509 certificate, including Certificate, TBSCertificate, and
// standard extensions.
// Creating a ParsedCertificate does not completely parse and validate the
// certificate data. Presence of a member in this class implies the DER was
// parsed successfully to that level, but does not imply the contents of that
// member are valid, unless otherwise specified. See the documentation for each
// member or the documentation of the type it returns.
class NET_EXPORT ParsedCertificate
    : public base::RefCountedThreadSafe<ParsedCertificate> {
 public:
  // Map from OID to ParsedExtension.
  using ExtensionsMap = std::map<der::Input, ParsedExtension>;

  // Creates a ParsedCertificate given a DER-encoded Certificate. Returns
  // nullptr on failure. Failure will occur if the standard certificate fields
  // and supported extensions cannot be parsed.
  //
  // The provided certificate data is copied, so |data| needn't remain valid
  // after this call.
  //
  // On either success or failure, if |errors| is non-null it may have error
  // information added to it.
  static scoped_refptr<ParsedCertificate> Create(
      const uint8_t* data,
      size_t length,
      const ParseCertificateOptions& options,
      CertErrors* errors);

  // Overload that takes a StringPiece.
  static scoped_refptr<ParsedCertificate> Create(
      const base::StringPiece& data,
      const ParseCertificateOptions& options,
      CertErrors* errors);

  // Creates a ParsedCertificate by copying the provided |data|, and appends it
  // to |chain|. Returns true if the certificate was successfully parsed and
  // added. If false is return, |chain| is unmodified.
  //
  // On either success or failure, if |errors| is non-null it may have error
  // information added to it.
  static bool CreateAndAddToVector(
      const uint8_t* data,
      size_t length,
      const ParseCertificateOptions& options,
      std::vector<scoped_refptr<net::ParsedCertificate>>* chain,
      CertErrors* errors);

  // Overload that takes a StringPiece.
  static bool CreateAndAddToVector(
      const base::StringPiece& data,
      const ParseCertificateOptions& options,
      std::vector<scoped_refptr<net::ParsedCertificate>>* chain,
      CertErrors* errors);

  // Like Create() this builds a ParsedCertificate given a DER-encoded
  // Certificate and returns nullptr on failure.
  //
  // However a copy of |data| is NOT made.
  //
  // This is a dangerous way to create as ParsedCertificate and should only be
  // used with care when saving a copy is really worth it, or the data is known
  // to come from static storage (and hence remain valid for entire life of
  // process).
  //
  // ParsedCertificate is reference counted, so it is easy to extend the life
  // and and end up with a ParsedCertificate referencing feed memory.
  //
  // On either success or failure, if |errors| is non-null it may have error
  // information added to it.
  static scoped_refptr<ParsedCertificate> CreateWithoutCopyingUnsafe(
      const uint8_t* data,
      size_t length,
      const ParseCertificateOptions& options,
      CertErrors* errors);

  // Returns the DER-encoded certificate data for this cert.
  const der::Input& der_cert() const { return cert_; }

  // Accessors for raw fields of the Certificate.
  const der::Input& tbs_certificate_tlv() const { return tbs_certificate_tlv_; }

  const der::Input& signature_algorithm_tlv() const {
    return signature_algorithm_tlv_;
  }

  const der::BitString& signature_value() const { return signature_value_; }

  // Accessor for struct containing raw fields of the TbsCertificate.
  const ParsedTbsCertificate& tbs() const { return tbs_; }

  // Returns true if the signatureAlgorithm of the Certificate is supported and
  // valid.
  bool has_valid_supported_signature_algorithm() const {
    return signature_algorithm_ != nullptr;
  }

  // Returns the signatureAlgorithm of the Certificate (not the tbsCertificate).
  // Must not be called if has_valid_supported_signature_algorithm() is false.
  const SignatureAlgorithm& signature_algorithm() const {
    DCHECK(signature_algorithm_);
    return *signature_algorithm_;
  }

  // Returns the DER-encoded normalized subject value (not including outer
  // Sequence tag). This is gauranteed to be valid DER, though the contents of
  // unhandled string types are treated as raw bytes.
  der::Input normalized_subject() const {
    return der::Input(&normalized_subject_);
  }
  // Returns the DER-encoded normalized issuer value (not including outer
  // Sequence tag). This is gauranteed to be valid DER, though the contents of
  // unhandled string types are treated as raw bytes.
  der::Input normalized_issuer() const {
    return der::Input(&normalized_issuer_);
  }

  // Returns true if the certificate has a BasicConstraints extension.
  bool has_basic_constraints() const { return has_basic_constraints_; }

  // Returns the ParsedBasicConstraints struct. Caller must check
  // has_basic_constraints() before accessing this.
  const ParsedBasicConstraints& basic_constraints() const {
    DCHECK(has_basic_constraints_);
    return basic_constraints_;
  }

  // Returns true if the certificate has a KeyUsage extension.
  bool has_key_usage() const { return has_key_usage_; }

  // Returns the KeyUsage BitString. Caller must check
  // has_key_usage() before accessing this.
  const der::BitString& key_usage() const {
    DCHECK(has_key_usage_);
    return key_usage_;
  }

  // Returns true if the certificate has a SubjectAltName extension.
  bool has_subject_alt_names() const { return subject_alt_names_ != nullptr; }

  // Returns the ParsedExtension struct for the SubjectAltName extension.
  // If the cert did not have a SubjectAltName extension, this will be a
  // default-initialized ParsedExtension struct.
  const ParsedExtension& subject_alt_names_extension() const {
    return subject_alt_names_extension_;
  }

  // Returns the GeneralNames class parsed from SubjectAltName extension, or
  // nullptr if no SubjectAltName extension was present.
  const GeneralNames* subject_alt_names() const {
    return subject_alt_names_.get();
  }

  // Returns true if the certificate has a NameConstraints extension.
  bool has_name_constraints() const { return name_constraints_ != nullptr; }

  // Returns the parsed NameConstraints extension. Must not be called if
  // has_name_constraints() is false.
  const NameConstraints& name_constraints() const {
    DCHECK(name_constraints_);
    return *name_constraints_;
  }

  // Returns true if the certificate has an AuthorityInfoAccess extension.
  bool has_authority_info_access() const { return has_authority_info_access_; }

  // Returns the ParsedExtension struct for the AuthorityInfoAccess extension.
  const ParsedExtension& authority_info_access_extension() const {
    return authority_info_access_extension_;
  }

  // Returns any caIssuers URIs from the AuthorityInfoAccess extension.
  const std::vector<base::StringPiece>& ca_issuers_uris() const {
    return ca_issuers_uris_;
  }

  // Returns any OCSP URIs from the AuthorityInfoAccess extension.
  const std::vector<base::StringPiece>& ocsp_uris() const { return ocsp_uris_; }

  // Returns a map of unhandled extensions (excludes the ones above).
  const ExtensionsMap& unparsed_extensions() const {
    return unparsed_extensions_;
  }

 private:
  // The certificate data for may either be owned internally (INTERNAL_COPY) or
  // owned externally (EXTERNAL_REFERENCE). When it is owned internally the data
  // is held by |cert_data_|
  enum class DataSource {
    INTERNAL_COPY,
    EXTERNAL_REFERENCE,
  };

  friend class base::RefCountedThreadSafe<ParsedCertificate>;
  ParsedCertificate();
  ~ParsedCertificate();

  static scoped_refptr<ParsedCertificate> CreateInternal(
      const uint8_t* data,
      size_t length,
      DataSource source,
      const ParseCertificateOptions& options,
      CertErrors* errors);

  // These private overloads should not be used, and have no definition.
  //
  // They are here to prevent incorrectly passing a const char*
  // in place of a base::StringPiece (thanks to StringPiece implicit
  // ctor on const char*).
  //
  // Accidentally inflating a const char* (without length) to a
  // StringPiece would be a bug.
  static scoped_refptr<ParsedCertificate> Create(
      const char* invalid_data,
      const ParseCertificateOptions& options,
      CertErrors* errors);
  static bool CreateAndAddToVector(
      const char* data,
      const ParseCertificateOptions& options,
      std::vector<scoped_refptr<net::ParsedCertificate>>* chain,
      CertErrors* errors);

  // The backing store for the certificate data. This is only applicable when
  // the ParsedCertificate was initialized using DataSource::INTERNAL_COPY.
  std::vector<uint8_t> cert_data_;

  // Note that the backing data for |cert_| (and its  may come either from
  // |cert_data_| or some external buffer (depending on how the
  // ParsedCertificate was created).

  // Points to the raw certificate DER.
  der::Input cert_;

  der::Input tbs_certificate_tlv_;
  der::Input signature_algorithm_tlv_;
  der::BitString signature_value_;
  ParsedTbsCertificate tbs_;

  // The signatureAlgorithm from the Certificate.
  std::unique_ptr<SignatureAlgorithm> signature_algorithm_;

  // Normalized DER-encoded Subject (not including outer Sequence tag).
  std::string normalized_subject_;
  // Normalized DER-encoded Issuer (not including outer Sequence tag).
  std::string normalized_issuer_;

  // BasicConstraints extension.
  bool has_basic_constraints_ = false;
  ParsedBasicConstraints basic_constraints_;

  // KeyUsage extension.
  bool has_key_usage_ = false;
  der::BitString key_usage_;

  // Raw SubjectAltName extension.
  ParsedExtension subject_alt_names_extension_;
  // Parsed SubjectAltName extension.
  std::unique_ptr<GeneralNames> subject_alt_names_;

  // NameConstraints extension.
  std::unique_ptr<NameConstraints> name_constraints_;

  // AuthorityInfoAccess extension.
  bool has_authority_info_access_ = false;
  ParsedExtension authority_info_access_extension_;
  // CaIssuers and Ocsp URIs parsed from the AuthorityInfoAccess extension. Note
  // that the AuthorityInfoAccess may have contained other AccessDescriptions
  // which are not represented here.
  std::vector<base::StringPiece> ca_issuers_uris_;
  std::vector<base::StringPiece> ocsp_uris_;

  // The remaining extensions (excludes the standard ones above).
  ExtensionsMap unparsed_extensions_;

  DISALLOW_COPY_AND_ASSIGN(ParsedCertificate);
};

}  // namespace net

#endif  // NET_CERT_INTERNAL_PARSED_CERTIFICATE_H_
