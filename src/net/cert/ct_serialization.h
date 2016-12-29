// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_CT_SERIALIZATION_H_
#define NET_CERT_CT_SERIALIZATION_H_

#include <string>
#include <vector>

#include "base/memory/ref_counted.h"
#include "base/strings/string_piece.h"
#include "base/time/time.h"
#include "net/base/net_export.h"

namespace net {

// Utility functions for encoding/decoding structures used by Certificate
// Transparency to/from the TLS wire format encoding.
namespace ct {

struct DigitallySigned;
struct LogEntry;
struct MerkleTreeLeaf;
struct SignedCertificateTimestamp;
struct SignedTreeHead;

// If |input.signature_data| is less than kMaxSignatureLength, encodes the
// |input| to |output| and returns true. Otherwise, returns false.
NET_EXPORT_PRIVATE bool EncodeDigitallySigned(const DigitallySigned& input,
                                              std::string* output);

// Reads and decodes a DigitallySigned object from |input|.
// The bytes read from |input| are discarded (i.e. |input|'s prefix removed)
// Returns true and fills |output| if all fields can be read, false otherwise.
NET_EXPORT_PRIVATE bool DecodeDigitallySigned(base::StringPiece* input,
                                              DigitallySigned* output);

// Encodes the |input| LogEntry to |output|. Returns true if the entry size
// does not exceed allowed size in RFC6962, false otherwise.
NET_EXPORT_PRIVATE bool EncodeLogEntry(const LogEntry& input,
                                       std::string* output);

// Serialises the Merkle tree |leaf|, appending it to |output|.
// These bytes can be hashed for use with audit proof fetching.
// Note that |leaf.log_id| is not part of the TLS encoding, and so will not be
// serialized.
NET_EXPORT bool EncodeTreeLeaf(const MerkleTreeLeaf& leaf, std::string* output);

// Encodes the data signed by a Signed Certificate Timestamp (SCT) into
// |output|. The signature included in the SCT is then verified over these
// bytes.
// |timestamp| timestamp from the SCT.
// |serialized_log_entry| the log entry signed by the SCT.
// |extensions| CT extensions.
// Returns true if the extensions' length does not exceed
// kMaxExtensionsLength, false otherwise.
NET_EXPORT_PRIVATE bool EncodeV1SCTSignedData(
    const base::Time& timestamp,
    const std::string& serialized_log_entry,
    const std::string& extensions,
    std::string* output);

// Encodes the data signed by a Signed Tree Head (STH) |signed_tree_head| into
// |output|. The signature included in the |signed_tree_head| can then be
// verified over these bytes.
NET_EXPORT_PRIVATE void EncodeTreeHeadSignature(
    const SignedTreeHead& signed_tree_head,
    std::string* output);

// Decode a list of Signed Certificate Timestamps
// (SignedCertificateTimestampList as defined in RFC6962): from a single
// string in |input| to a vector of individually-encoded SCTs |output|.
// This list is typically obtained from the CT extension in a certificate.
// Returns true if the list could be read and decoded successfully, false
// otherwise (note that the validity of each individual SCT should be checked
// separately).
NET_EXPORT_PRIVATE bool DecodeSCTList(base::StringPiece input,
                                      std::vector<base::StringPiece>* output);

// Decodes a single SCT from |input| to |output|.
// Returns true if all fields in the SCT could be read and decoded, false
// otherwise.
NET_EXPORT_PRIVATE bool DecodeSignedCertificateTimestamp(
    base::StringPiece* input,
    scoped_refptr<ct::SignedCertificateTimestamp>* output);

// Writes an SCTList into |output|, containing a single |sct|.
NET_EXPORT_PRIVATE bool EncodeSCTListForTesting(const base::StringPiece& sct,
                                                std::string* output);
}  // namespace ct

}  // namespace net

#endif  // NET_CERT_CT_SERIALIZATION_H_
