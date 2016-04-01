// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_CT_EV_WHITELIST_H_
#define NET_CERT_CT_EV_WHITELIST_H_

#include <string>

#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"

namespace base {

class Version;

}  // namespace base

namespace net {

namespace ct {

class NET_EXPORT EVCertsWhitelist
    : public base::RefCountedThreadSafe<EVCertsWhitelist> {
 public:
  // Returns true if the |certificate_hash| appears in the EV certificate hashes
  // whitelist.
  virtual bool ContainsCertificateHash(
      const std::string& certificate_hash) const = 0;

  // Returns true if the global EV certificate hashes whitelist is non-empty,
  // false otherwise.
  virtual bool IsValid() const = 0;

  // Returns the version of the whitelist in use
  virtual base::Version Version() const = 0;

 protected:
  virtual ~EVCertsWhitelist() {}

 private:
  friend class base::RefCountedThreadSafe<EVCertsWhitelist>;
};

}  // namespace ct

}  // namespace net

#endif  // NET_CERT_CT_EV_WHITELIST_H_
