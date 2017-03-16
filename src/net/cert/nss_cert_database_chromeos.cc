// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/nss_cert_database_chromeos.h"

#include <cert.h>
#include <pk11pub.h>

#include <algorithm>
#include <memory>
#include <utility>

#include "base/bind.h"
#include "base/callback.h"
#include "base/location.h"
#include "base/stl_util.h"
#include "base/task_runner.h"
#include "net/cert/x509_certificate.h"

namespace net {

NSSCertDatabaseChromeOS::NSSCertDatabaseChromeOS(
    crypto::ScopedPK11Slot public_slot,
    crypto::ScopedPK11Slot private_slot)
    : NSSCertDatabase(std::move(public_slot), std::move(private_slot)) {
  // By default, don't use a system slot. Only if explicitly set by
  // SetSystemSlot, the system slot will be used.
  profile_filter_.Init(GetPublicSlot(),
                       GetPrivateSlot(),
                       crypto::ScopedPK11Slot() /* no system slot */);
}

NSSCertDatabaseChromeOS::~NSSCertDatabaseChromeOS() {}

void NSSCertDatabaseChromeOS::SetSystemSlot(
    crypto::ScopedPK11Slot system_slot) {
  system_slot_ = std::move(system_slot);
  profile_filter_.Init(GetPublicSlot(), GetPrivateSlot(), GetSystemSlot());
}

void NSSCertDatabaseChromeOS::ListCertsSync(CertificateList* certs) {
  ListCertsImpl(profile_filter_, certs);
}

void NSSCertDatabaseChromeOS::ListCerts(
    const NSSCertDatabase::ListCertsCallback& callback) {
  std::unique_ptr<CertificateList> certs(new CertificateList());

  // base::Pased will NULL out |certs|, so cache the underlying pointer here.
  CertificateList* raw_certs = certs.get();
  GetSlowTaskRunner()->PostTaskAndReply(
      FROM_HERE, base::Bind(&NSSCertDatabaseChromeOS::ListCertsImpl,
                            profile_filter_, base::Unretained(raw_certs)),
      base::Bind(callback, base::Passed(&certs)));
}

crypto::ScopedPK11Slot NSSCertDatabaseChromeOS::GetSystemSlot() const {
  if (system_slot_)
    return crypto::ScopedPK11Slot(PK11_ReferenceSlot(system_slot_.get()));
  return crypto::ScopedPK11Slot();
}

void NSSCertDatabaseChromeOS::ListModules(
    std::vector<crypto::ScopedPK11Slot>* modules,
    bool need_rw) const {
  NSSCertDatabase::ListModules(modules, need_rw);

  size_t pre_size = modules->size();
  base::EraseIf(*modules,
                NSSProfileFilterChromeOS::ModuleNotAllowedForProfilePredicate(
                    profile_filter_));
  DVLOG(1) << "filtered " << pre_size - modules->size() << " of " << pre_size
           << " modules";
}

void NSSCertDatabaseChromeOS::ListCertsImpl(
    const NSSProfileFilterChromeOS& profile_filter,
    CertificateList* certs) {
  NSSCertDatabase::ListCertsImpl(crypto::ScopedPK11Slot(), certs);

  size_t pre_size = certs->size();
  base::EraseIf(*certs,
                NSSProfileFilterChromeOS::CertNotAllowedForProfilePredicate(
                    profile_filter));
  DVLOG(1) << "filtered " << pre_size - certs->size() << " of " << pre_size
           << " certs";
}

}  // namespace net
