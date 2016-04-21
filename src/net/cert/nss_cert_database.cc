// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/nss_cert_database.h"

#include <cert.h>
#include <certdb.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <secmod.h>

#include <memory>
#include <utility>

#include "base/bind.h"
#include "base/callback.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/observer_list_threadsafe.h"
#include "base/task_runner.h"
#include "base/task_runner_util.h"
#include "base/threading/worker_pool.h"
#include "crypto/scoped_nss_types.h"
#include "net/base/crypto_module.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_database.h"
#include "net/cert/x509_certificate.h"
#include "net/third_party/mozilla_security_manager/nsNSSCertificateDB.h"
#include "net/third_party/mozilla_security_manager/nsPKCS12Blob.h"

// In NSS 3.13, CERTDB_VALID_PEER was renamed CERTDB_TERMINAL_RECORD. So we use
// the new name of the macro.
#if !defined(CERTDB_TERMINAL_RECORD)
#define CERTDB_TERMINAL_RECORD CERTDB_VALID_PEER
#endif

// PSM = Mozilla's Personal Security Manager.
namespace psm = mozilla_security_manager;

namespace net {

namespace {

// TODO(pneubeck): Move this class out of NSSCertDatabase and to the caller of
// the c'tor of NSSCertDatabase, see https://crbug.com/395983 .
// Helper that observes events from the NSSCertDatabase and forwards them to
// the given CertDatabase.
class CertNotificationForwarder : public NSSCertDatabase::Observer {
 public:
  explicit CertNotificationForwarder(CertDatabase* cert_db)
      : cert_db_(cert_db) {}

  ~CertNotificationForwarder() override {}

  // NSSCertDatabase::Observer implementation:
  void OnCertAdded(const X509Certificate* cert) override {
    cert_db_->NotifyObserversOfCertAdded(cert);
  }

  void OnCertRemoved(const X509Certificate* cert) override {
    cert_db_->NotifyObserversOfCertRemoved(cert);
  }

  void OnCACertChanged(const X509Certificate* cert) override {
    cert_db_->NotifyObserversOfCACertChanged(cert);
  }

 private:
  CertDatabase* cert_db_;

  DISALLOW_COPY_AND_ASSIGN(CertNotificationForwarder);
};

}  // namespace

NSSCertDatabase::ImportCertFailure::ImportCertFailure(
    const scoped_refptr<X509Certificate>& cert,
    int err)
    : certificate(cert), net_error(err) {}

NSSCertDatabase::ImportCertFailure::ImportCertFailure(
    const ImportCertFailure& other) = default;

NSSCertDatabase::ImportCertFailure::~ImportCertFailure() {}

NSSCertDatabase::NSSCertDatabase(crypto::ScopedPK11Slot public_slot,
                                 crypto::ScopedPK11Slot private_slot)
    : public_slot_(std::move(public_slot)),
      private_slot_(std::move(private_slot)),
      observer_list_(new base::ObserverListThreadSafe<Observer>),
      weak_factory_(this) {
  CHECK(public_slot_);

  // This also makes sure that NSS has been initialized.
  CertDatabase* cert_db = CertDatabase::GetInstance();
  cert_notification_forwarder_.reset(new CertNotificationForwarder(cert_db));
  AddObserver(cert_notification_forwarder_.get());

  psm::EnsurePKCS12Init();
}

NSSCertDatabase::~NSSCertDatabase() {}

void NSSCertDatabase::ListCertsSync(CertificateList* certs) {
  ListCertsImpl(crypto::ScopedPK11Slot(), certs);
}

void NSSCertDatabase::ListCerts(
    const base::Callback<void(std::unique_ptr<CertificateList> certs)>&
        callback) {
  std::unique_ptr<CertificateList> certs(new CertificateList());

  // base::Passed will NULL out |certs|, so cache the underlying pointer here.
  CertificateList* raw_certs = certs.get();
  GetSlowTaskRunner()->PostTaskAndReply(
      FROM_HERE,
      base::Bind(&NSSCertDatabase::ListCertsImpl,
                 base::Passed(crypto::ScopedPK11Slot()),
                 base::Unretained(raw_certs)),
      base::Bind(callback, base::Passed(&certs)));
}

void NSSCertDatabase::ListCertsInSlot(const ListCertsCallback& callback,
                                      PK11SlotInfo* slot) {
  DCHECK(slot);
  std::unique_ptr<CertificateList> certs(new CertificateList());

  // base::Passed will NULL out |certs|, so cache the underlying pointer here.
  CertificateList* raw_certs = certs.get();
  GetSlowTaskRunner()->PostTaskAndReply(
      FROM_HERE,
      base::Bind(&NSSCertDatabase::ListCertsImpl,
                 base::Passed(crypto::ScopedPK11Slot(PK11_ReferenceSlot(slot))),
                 base::Unretained(raw_certs)),
      base::Bind(callback, base::Passed(&certs)));
}

#if defined(OS_CHROMEOS)
crypto::ScopedPK11Slot NSSCertDatabase::GetSystemSlot() const {
  return crypto::ScopedPK11Slot();
}
#endif

crypto::ScopedPK11Slot NSSCertDatabase::GetPublicSlot() const {
  return crypto::ScopedPK11Slot(PK11_ReferenceSlot(public_slot_.get()));
}

crypto::ScopedPK11Slot NSSCertDatabase::GetPrivateSlot() const {
  if (!private_slot_)
    return crypto::ScopedPK11Slot();
  return crypto::ScopedPK11Slot(PK11_ReferenceSlot(private_slot_.get()));
}

CryptoModule* NSSCertDatabase::GetPublicModule() const {
  crypto::ScopedPK11Slot slot(GetPublicSlot());
  return CryptoModule::CreateFromHandle(slot.get());
}

CryptoModule* NSSCertDatabase::GetPrivateModule() const {
  crypto::ScopedPK11Slot slot(GetPrivateSlot());
  return CryptoModule::CreateFromHandle(slot.get());
}

void NSSCertDatabase::ListModules(CryptoModuleList* modules,
                                  bool need_rw) const {
  modules->clear();

  // The wincx arg is unused since we don't call PK11_SetIsLoggedInFunc.
  crypto::ScopedPK11SlotList slot_list(
      PK11_GetAllTokens(CKM_INVALID_MECHANISM,
                        need_rw ? PR_TRUE : PR_FALSE,  // needRW
                        PR_TRUE,                       // loadCerts (unused)
                        NULL));                        // wincx
  if (!slot_list) {
    LOG(ERROR) << "PK11_GetAllTokens failed: " << PORT_GetError();
    return;
  }

  PK11SlotListElement* slot_element = PK11_GetFirstSafe(slot_list.get());
  while (slot_element) {
    modules->push_back(CryptoModule::CreateFromHandle(slot_element->slot));
    slot_element = PK11_GetNextSafe(slot_list.get(), slot_element,
                                    PR_FALSE);  // restart
  }
}

int NSSCertDatabase::ImportFromPKCS12(CryptoModule* module,
                                      const std::string& data,
                                      const base::string16& password,
                                      bool is_extractable,
                                      CertificateList* imported_certs) {
  DVLOG(1) << __func__ << " "
           << PK11_GetModuleID(module->os_module_handle()) << ":"
           << PK11_GetSlotID(module->os_module_handle());
  int result = psm::nsPKCS12Blob_Import(module->os_module_handle(),
                                        data.data(), data.size(),
                                        password,
                                        is_extractable,
                                        imported_certs);
  if (result == OK)
    NotifyObserversOfCertAdded(NULL);

  return result;
}

int NSSCertDatabase::ExportToPKCS12(
    const CertificateList& certs,
    const base::string16& password,
    std::string* output) const {
  return psm::nsPKCS12Blob_Export(output, certs, password);
}

X509Certificate* NSSCertDatabase::FindRootInList(
    const CertificateList& certificates) const {
  DCHECK_GT(certificates.size(), 0U);

  if (certificates.size() == 1)
    return certificates[0].get();

  X509Certificate* cert0 = certificates[0].get();
  X509Certificate* cert1 = certificates[1].get();
  X509Certificate* certn_2 = certificates[certificates.size() - 2].get();
  X509Certificate* certn_1 = certificates[certificates.size() - 1].get();

  if (CERT_CompareName(&cert1->os_cert_handle()->issuer,
                       &cert0->os_cert_handle()->subject) == SECEqual)
    return cert0;
  if (CERT_CompareName(&certn_2->os_cert_handle()->issuer,
                       &certn_1->os_cert_handle()->subject) == SECEqual)
    return certn_1;

  LOG(WARNING) << "certificate list is not a hierarchy";
  return cert0;
}

int NSSCertDatabase::ImportUserCert(const std::string& data) {
  CertificateList certificates =
      X509Certificate::CreateCertificateListFromBytes(
          data.c_str(), data.size(), net::X509Certificate::FORMAT_AUTO);
  int result = psm::ImportUserCert(certificates);

  if (result == OK)
    NotifyObserversOfCertAdded(NULL);

  return result;
}

bool NSSCertDatabase::ImportCACerts(const CertificateList& certificates,
                                    TrustBits trust_bits,
                                    ImportCertFailureList* not_imported) {
  crypto::ScopedPK11Slot slot(GetPublicSlot());
  X509Certificate* root = FindRootInList(certificates);
  bool success = psm::ImportCACerts(
      slot.get(), certificates, root, trust_bits, not_imported);
  if (success)
    NotifyObserversOfCACertChanged(NULL);

  return success;
}

bool NSSCertDatabase::ImportServerCert(const CertificateList& certificates,
                                       TrustBits trust_bits,
                                       ImportCertFailureList* not_imported) {
  crypto::ScopedPK11Slot slot(GetPublicSlot());
  return psm::ImportServerCert(
      slot.get(), certificates, trust_bits, not_imported);
}

NSSCertDatabase::TrustBits NSSCertDatabase::GetCertTrust(
    const X509Certificate* cert,
    CertType type) const {
  CERTCertTrust trust;
  SECStatus srv = CERT_GetCertTrust(cert->os_cert_handle(), &trust);
  if (srv != SECSuccess) {
    LOG(ERROR) << "CERT_GetCertTrust failed with error " << PORT_GetError();
    return TRUST_DEFAULT;
  }
  // We define our own more "friendly" TrustBits, which means we aren't able to
  // round-trip all possible NSS trust flag combinations.  We try to map them in
  // a sensible way.
  switch (type) {
    case CA_CERT: {
      const unsigned kTrustedCA = CERTDB_TRUSTED_CA | CERTDB_TRUSTED_CLIENT_CA;
      const unsigned kCAFlags = kTrustedCA | CERTDB_TERMINAL_RECORD;

      TrustBits trust_bits = TRUST_DEFAULT;
      if ((trust.sslFlags & kCAFlags) == CERTDB_TERMINAL_RECORD)
        trust_bits |= DISTRUSTED_SSL;
      else if (trust.sslFlags & kTrustedCA)
        trust_bits |= TRUSTED_SSL;

      if ((trust.emailFlags & kCAFlags) == CERTDB_TERMINAL_RECORD)
        trust_bits |= DISTRUSTED_EMAIL;
      else if (trust.emailFlags & kTrustedCA)
        trust_bits |= TRUSTED_EMAIL;

      if ((trust.objectSigningFlags & kCAFlags) == CERTDB_TERMINAL_RECORD)
        trust_bits |= DISTRUSTED_OBJ_SIGN;
      else if (trust.objectSigningFlags & kTrustedCA)
        trust_bits |= TRUSTED_OBJ_SIGN;

      return trust_bits;
    }
    case SERVER_CERT:
      if (trust.sslFlags & CERTDB_TERMINAL_RECORD) {
        if (trust.sslFlags & CERTDB_TRUSTED)
          return TRUSTED_SSL;
        return DISTRUSTED_SSL;
      }
      return TRUST_DEFAULT;
    default:
      return TRUST_DEFAULT;
  }
}

bool NSSCertDatabase::IsUntrusted(const X509Certificate* cert) const {
  CERTCertTrust nsstrust;
  SECStatus rv = CERT_GetCertTrust(cert->os_cert_handle(), &nsstrust);
  if (rv != SECSuccess) {
    LOG(ERROR) << "CERT_GetCertTrust failed with error " << PORT_GetError();
    return false;
  }

  // The CERTCertTrust structure contains three trust records:
  // sslFlags, emailFlags, and objectSigningFlags.  The three
  // trust records are independent of each other.
  //
  // If the CERTDB_TERMINAL_RECORD bit in a trust record is set,
  // then that trust record is a terminal record.  A terminal
  // record is used for explicit trust and distrust of an
  // end-entity or intermediate CA cert.
  //
  // In a terminal record, if neither CERTDB_TRUSTED_CA nor
  // CERTDB_TRUSTED is set, then the terminal record means
  // explicit distrust.  On the other hand, if the terminal
  // record has either CERTDB_TRUSTED_CA or CERTDB_TRUSTED bit
  // set, then the terminal record means explicit trust.
  //
  // For a root CA, the trust record does not have
  // the CERTDB_TERMINAL_RECORD bit set.

  static const unsigned int kTrusted = CERTDB_TRUSTED_CA | CERTDB_TRUSTED;
  if ((nsstrust.sslFlags & CERTDB_TERMINAL_RECORD) != 0 &&
      (nsstrust.sslFlags & kTrusted) == 0) {
    return true;
  }
  if ((nsstrust.emailFlags & CERTDB_TERMINAL_RECORD) != 0 &&
      (nsstrust.emailFlags & kTrusted) == 0) {
    return true;
  }
  if ((nsstrust.objectSigningFlags & CERTDB_TERMINAL_RECORD) != 0 &&
      (nsstrust.objectSigningFlags & kTrusted) == 0) {
    return true;
  }

  // Self-signed certificates that don't have any trust bits set are untrusted.
  // Other certificates that don't have any trust bits set may still be trusted
  // if they chain up to a trust anchor.
  if (CERT_CompareName(&cert->os_cert_handle()->issuer,
                       &cert->os_cert_handle()->subject) == SECEqual) {
    return (nsstrust.sslFlags & kTrusted) == 0 &&
           (nsstrust.emailFlags & kTrusted) == 0 &&
           (nsstrust.objectSigningFlags & kTrusted) == 0;
  }

  return false;
}

bool NSSCertDatabase::SetCertTrust(const X509Certificate* cert,
                                CertType type,
                                TrustBits trust_bits) {
  bool success = psm::SetCertTrust(cert, type, trust_bits);
  if (success)
    NotifyObserversOfCACertChanged(cert);

  return success;
}

bool NSSCertDatabase::DeleteCertAndKey(X509Certificate* cert) {
  if (!DeleteCertAndKeyImpl(cert))
    return false;
  NotifyObserversOfCertRemoved(cert);
  return true;
}

void NSSCertDatabase::DeleteCertAndKeyAsync(
    const scoped_refptr<X509Certificate>& cert,
    const DeleteCertCallback& callback) {
  base::PostTaskAndReplyWithResult(
      GetSlowTaskRunner().get(),
      FROM_HERE,
      base::Bind(&NSSCertDatabase::DeleteCertAndKeyImpl, cert),
      base::Bind(&NSSCertDatabase::NotifyCertRemovalAndCallBack,
                 weak_factory_.GetWeakPtr(),
                 cert,
                 callback));
}

bool NSSCertDatabase::IsReadOnly(const X509Certificate* cert) const {
  PK11SlotInfo* slot = cert->os_cert_handle()->slot;
  return slot && PK11_IsReadOnly(slot);
}

bool NSSCertDatabase::IsHardwareBacked(const X509Certificate* cert) const {
  PK11SlotInfo* slot = cert->os_cert_handle()->slot;
  return slot && PK11_IsHW(slot);
}

void NSSCertDatabase::AddObserver(Observer* observer) {
  observer_list_->AddObserver(observer);
}

void NSSCertDatabase::RemoveObserver(Observer* observer) {
  observer_list_->RemoveObserver(observer);
}

void NSSCertDatabase::SetSlowTaskRunnerForTest(
    const scoped_refptr<base::TaskRunner>& task_runner) {
  slow_task_runner_for_test_ = task_runner;
}

// static
void NSSCertDatabase::ListCertsImpl(crypto::ScopedPK11Slot slot,
                                    CertificateList* certs) {
  certs->clear();

  CERTCertList* cert_list = NULL;
  if (slot)
    cert_list = PK11_ListCertsInSlot(slot.get());
  else
    cert_list = PK11_ListCerts(PK11CertListUnique, NULL);

  CERTCertListNode* node;
  for (node = CERT_LIST_HEAD(cert_list); !CERT_LIST_END(node, cert_list);
       node = CERT_LIST_NEXT(node)) {
    certs->push_back(X509Certificate::CreateFromHandle(
        node->cert, X509Certificate::OSCertHandles()));
  }
  CERT_DestroyCertList(cert_list);
}

scoped_refptr<base::TaskRunner> NSSCertDatabase::GetSlowTaskRunner() const {
  if (slow_task_runner_for_test_.get())
    return slow_task_runner_for_test_;
  return base::WorkerPool::GetTaskRunner(true /*task is slow*/);
}

void NSSCertDatabase::NotifyCertRemovalAndCallBack(
    scoped_refptr<X509Certificate> cert,
    const DeleteCertCallback& callback,
    bool success) {
  if (success)
    NotifyObserversOfCertRemoved(cert.get());
  callback.Run(success);
}

void NSSCertDatabase::NotifyObserversOfCertAdded(const X509Certificate* cert) {
  observer_list_->Notify(FROM_HERE, &Observer::OnCertAdded,
                         base::RetainedRef(cert));
}

void NSSCertDatabase::NotifyObserversOfCertRemoved(
    const X509Certificate* cert) {
  observer_list_->Notify(FROM_HERE, &Observer::OnCertRemoved,
                         base::RetainedRef(cert));
}

void NSSCertDatabase::NotifyObserversOfCACertChanged(
    const X509Certificate* cert) {
  observer_list_->Notify(FROM_HERE, &Observer::OnCACertChanged,
                         base::RetainedRef(cert));
}

// static
bool NSSCertDatabase::DeleteCertAndKeyImpl(
    scoped_refptr<X509Certificate> cert) {
  // For some reason, PK11_DeleteTokenCertAndKey only calls
  // SEC_DeletePermCertificate if the private key is found.  So, we check
  // whether a private key exists before deciding which function to call to
  // delete the cert.
  SECKEYPrivateKey* privKey =
      PK11_FindKeyByAnyCert(cert->os_cert_handle(), NULL);
  if (privKey) {
    SECKEY_DestroyPrivateKey(privKey);
    if (PK11_DeleteTokenCertAndKey(cert->os_cert_handle(), NULL)) {
      LOG(ERROR) << "PK11_DeleteTokenCertAndKey failed: " << PORT_GetError();
      return false;
    }
  } else {
    if (SEC_DeletePermCertificate(cert->os_cert_handle())) {
      LOG(ERROR) << "SEC_DeletePermCertificate failed: " << PORT_GetError();
      return false;
    }
  }
  return true;
}

}  // namespace net
