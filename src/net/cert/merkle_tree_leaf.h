// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_MERKLE_TREE_LEAF_H_
#define NET_CERT_MERKLE_TREE_LEAF_H_

#include <memory>
#include <string>

#include "base/time/time.h"
#include "net/base/net_export.h"
#include "net/cert/signed_certificate_timestamp.h"

namespace net {

class X509Certificate;

namespace ct {

// Represents a MerkleTreeLeaf as defined in RFC6962, section 3.4.
// Has all the data as the MerkleTreeLeaf defined in the RFC, arranged
// slightly differently.
struct NET_EXPORT MerkleTreeLeaf {
  MerkleTreeLeaf();
  ~MerkleTreeLeaf();

  // The log id this leaf belongs to.
  std::string log_id;

  // Certificate / Precertificate and indication of entry type.
  LogEntry log_entry;

  // Timestamp from the SCT.
  base::Time timestamp;

  // Extensions from the SCT.
  std::string extensions;
};

NET_EXPORT bool GetMerkleTreeLeaf(const X509Certificate* cert,
                                  const SignedCertificateTimestamp* sct,
                                  MerkleTreeLeaf* merkle_tree_leaf);

// Sets |*out| to the hash of the Merkle |tree_leaf|, as defined in RFC6962.
// Returns true if the hash was generated, false if an error occurred.
NET_EXPORT bool Hash(const MerkleTreeLeaf& tree_leaf, std::string* out);

}  // namespace ct

}  // namespace net

#endif  // NET_CERT_MERKLE_TREE_LEAF_H_
