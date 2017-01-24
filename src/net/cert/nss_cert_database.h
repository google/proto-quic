// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_NSS_CERT_DATABASE_H_
#define NET_CERT_NSS_CERT_DATABASE_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "base/callback_forward.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/strings/string16.h"
#include "crypto/scoped_nss_types.h"
#include "net/base/net_errors.h"
#include "net/base/net_export.h"
#include "net/cert/cert_type.h"
#include "net/cert/x509_certificate.h"

namespace base {
template <class ObserverType>
class ObserverListThreadSafe;
class TaskRunner;
}

namespace net {

class CryptoModule;
typedef std::vector<scoped_refptr<CryptoModule> > CryptoModuleList;

// Provides functions to manipulate the NSS certificate stores.
// Forwards notifications about certificate changes to the global CertDatabase
// singleton.
class NET_EXPORT NSSCertDatabase {
 public:
  class NET_EXPORT Observer {
   public:
    virtual ~Observer() {}

    // Will be called when a CA certificate is changed.
    // Called with |cert| == NULL after importing a list of certificates
    // in ImportCACerts().
    virtual void OnCertDBChanged(const X509Certificate* cert) {}

   protected:
    Observer() {}

   private:
    DISALLOW_COPY_AND_ASSIGN(Observer);
  };

  // Stores per-certificate error codes for import failures.
  struct NET_EXPORT ImportCertFailure {
   public:
    ImportCertFailure(const scoped_refptr<X509Certificate>& cert, int err);
    ImportCertFailure(const ImportCertFailure& other);
    ~ImportCertFailure();

    scoped_refptr<X509Certificate> certificate;
    int net_error;
  };
  typedef std::vector<ImportCertFailure> ImportCertFailureList;

  // Constants that define which usages a certificate is trusted for.
  // They are used in combination with CertType to specify trust for each type
  // of certificate.
  // For a CA_CERT, they specify that the CA is trusted for issuing server and
  // client certs of each type.
  // For SERVER_CERT, only TRUSTED_SSL makes sense, and specifies the cert is
  // trusted as a server.
  // For EMAIL_CERT, only TRUSTED_EMAIL makes sense, and specifies the cert is
  // trusted for email.
  // DISTRUSTED_* specifies that the cert should not be trusted for the given
  // usage, regardless of whether it would otherwise inherit trust from the
  // issuer chain.
  // Use TRUST_DEFAULT to inherit trust as normal.
  // NOTE: The actual constants are defined using an enum instead of static
  // consts due to compilation/linkage constraints with template functions.
  typedef uint32_t TrustBits;
  enum {
    TRUST_DEFAULT         =      0,
    TRUSTED_SSL           = 1 << 0,
    TRUSTED_EMAIL         = 1 << 1,
    TRUSTED_OBJ_SIGN      = 1 << 2,
    DISTRUSTED_SSL        = 1 << 3,
    DISTRUSTED_EMAIL      = 1 << 4,
    DISTRUSTED_OBJ_SIGN   = 1 << 5,
  };

  typedef base::Callback<void(std::unique_ptr<CertificateList> certs)>
      ListCertsCallback;

  typedef base::Callback<void(bool)> DeleteCertCallback;

  // Creates a NSSCertDatabase that will store public information (such as
  // certificates and trust records) in |public_slot|, and private information
  // (such as keys) in |private_slot|.
  // In general, code should avoid creating an NSSCertDatabase directly,
  // as doing so requires making opinionated decisions about where to store
  // data, and instead prefer to be passed an existing NSSCertDatabase
  // instance.
  // |public_slot| must not be NULL, |private_slot| can be NULL. Both slots can
  // be identical.
  NSSCertDatabase(crypto::ScopedPK11Slot public_slot,
                  crypto::ScopedPK11Slot private_slot);
  virtual ~NSSCertDatabase();

  // Get a list of unique certificates in the certificate database (one
  // instance of all certificates).
  // DEPRECATED by |ListCerts|. See http://crbug.com/340460.
  virtual void ListCertsSync(CertificateList* certs);

  // Asynchronously get a list of unique certificates in the certificate
  // database (one instance of all certificates). Note that the callback may be
  // run even after the database is deleted.
  virtual void ListCerts(const ListCertsCallback& callback);

  // Get a list of certificates in the certificate database of the given slot.
  // Note that the callback may be run even after the database is deleted.
  // Must be called on the IO thread and it calls |callback| on the IO thread.
  // This does not block by retrieving the certs asynchronously on a worker
  // thread. Never calls |callback| synchronously.
  virtual void ListCertsInSlot(const ListCertsCallback& callback,
                               PK11SlotInfo* slot);

#if defined(OS_CHROMEOS)
  // Get the slot for system-wide key data. May be NULL if the system token was
  // not explicitly set.
  // Note: The System slot is set after the NSSCertDatabase is constructed and
  // this call returns synchronously. Thus, it is possible to call this function
  // before SetSystemSlot is called and get a NULL result.
  // See https://crbug.com/399554 .
  virtual crypto::ScopedPK11Slot GetSystemSlot() const;
#endif

  // Get the default slot for public key data.
  crypto::ScopedPK11Slot GetPublicSlot() const;

  // Get the default slot for private key or mixed private/public key data.
  // Can return NULL.
  crypto::ScopedPK11Slot GetPrivateSlot() const;

  // Get all modules.
  // If |need_rw| is true, only writable modules will be returned.
  // TODO(mattm): come up with better alternative to CryptoModuleList.
  virtual void ListModules(CryptoModuleList* modules, bool need_rw) const;

  // Import certificates and private keys from PKCS #12 blob into the module.
  // If |is_extractable| is false, mark the private key as being unextractable
  // from the module.
  // Returns OK or a network error code such as ERR_PKCS12_IMPORT_BAD_PASSWORD
  // or ERR_PKCS12_IMPORT_ERROR. |imported_certs|, if non-NULL, returns a list
  // of certs that were imported.
  int ImportFromPKCS12(PK11SlotInfo* slot_info,
                       const std::string& data,
                       const base::string16& password,
                       bool is_extractable,
                       CertificateList* imported_certs);

  // Export the given certificates and private keys into a PKCS #12 blob,
  // storing into |output|.
  // Returns the number of certificates successfully exported.
  int ExportToPKCS12(const CertificateList& certs,
                     const base::string16& password,
                     std::string* output) const;

  // Uses similar logic to nsNSSCertificateDB::handleCACertDownload to find the
  // root.  Assumes the list is an ordered hierarchy with the root being either
  // the first or last element.
  // TODO(mattm): improve this to handle any order.
  X509Certificate* FindRootInList(const CertificateList& certificates) const;

  // Import a user certificate. The private key for the user certificate must
  // already be installed, otherwise we return ERR_NO_PRIVATE_KEY_FOR_CERT.
  // Returns OK or a network error code.
  int ImportUserCert(const std::string& data);
  int ImportUserCert(X509Certificate* cert);

  // Import CA certificates.
  // Tries to import all the certificates given.  The root will be trusted
  // according to |trust_bits|.  Any certificates that could not be imported
  // will be listed in |not_imported|.
  // Returns false if there is an internal error, otherwise true is returned and
  // |not_imported| should be checked for any certificates that were not
  // imported.
  bool ImportCACerts(const CertificateList& certificates,
                     TrustBits trust_bits,
                     ImportCertFailureList* not_imported);

  // Import server certificate.  The first cert should be the server cert.  Any
  // additional certs should be intermediate/CA certs and will be imported but
  // not given any trust.
  // Any certificates that could not be imported will be listed in
  // |not_imported|.
  // |trust_bits| can be set to explicitly trust or distrust the certificate, or
  // use TRUST_DEFAULT to inherit trust as normal.
  // Returns false if there is an internal error, otherwise true is returned and
  // |not_imported| should be checked for any certificates that were not
  // imported.
  bool ImportServerCert(const CertificateList& certificates,
                        TrustBits trust_bits,
                        ImportCertFailureList* not_imported);

  // Get trust bits for certificate.
  TrustBits GetCertTrust(const X509Certificate* cert, CertType type) const;

  // IsUntrusted returns true if |cert| is specifically untrusted. These
  // certificates are stored in the database for the specific purpose of
  // rejecting them.
  bool IsUntrusted(const X509Certificate* cert) const;

  // Set trust values for certificate.
  // Returns true on success or false on failure.
  bool SetCertTrust(const X509Certificate* cert,
                    CertType type,
                    TrustBits trust_bits);

  // Delete certificate and associated private key (if one exists).
  // |cert| is still valid when this function returns. Returns true on
  // success.
  bool DeleteCertAndKey(X509Certificate* cert);

  // Like DeleteCertAndKey but does not block by running the removal on a worker
  // thread. This must be called on IO thread and it will run |callback| on IO
  // thread. Never calls |callback| synchronously.
  void DeleteCertAndKeyAsync(const scoped_refptr<X509Certificate>& cert,
                             const DeleteCertCallback& callback);

  // Check whether cert is stored in a readonly slot.
  bool IsReadOnly(const X509Certificate* cert) const;

  // Check whether cert is stored in a hardware slot.
  bool IsHardwareBacked(const X509Certificate* cert) const;

  // Overrides task runner that's used for running slow tasks.
  void SetSlowTaskRunnerForTest(
      const scoped_refptr<base::TaskRunner>& task_runner);

 protected:
  // Certificate listing implementation used by |ListCerts*| and
  // |ListCertsSync|. Static so it may safely be used on the worker thread.
  // If |slot| is NULL, obtains the certs of all slots, otherwise only of
  // |slot|.
  static void ListCertsImpl(crypto::ScopedPK11Slot slot,
                            CertificateList* certs);

  // Gets task runner that should be used for slow tasks like certificate
  // listing. Defaults to a base::WorkerPool runner, but may be overriden
  // in tests (see SetSlowTaskRunnerForTest).
  scoped_refptr<base::TaskRunner> GetSlowTaskRunner() const;

 protected:
  // Broadcasts notifications to all registered observers.
  void NotifyObserversCertDBChanged(const X509Certificate* cert);

 private:
  // Registers |observer| to receive notifications of certificate changes.  The
  // thread on which this is called is the thread on which |observer| will be
  // called back with notifications.
  // NOTE: Observers registered here will only receive notifications generated
  // directly through the NSSCertDatabase, but not those from the CertDatabase.
  // CertDatabase observers will receive all certificate notifications.
  void AddObserver(Observer* observer);

  // Unregisters |observer| from receiving notifications.  This must be called
  // on the same thread on which AddObserver() was called.
  void RemoveObserver(Observer* observer);

  // Notifies observers of the removal of |cert| and calls |callback| with
  // |success| as argument.
  void NotifyCertRemovalAndCallBack(scoped_refptr<X509Certificate> cert,
                                    const DeleteCertCallback& callback,
                                    bool success);

  // Certificate removal implementation used by |DeleteCertAndKey*|. Static so
  // it may safely be used on the worker thread.
  static bool DeleteCertAndKeyImpl(scoped_refptr<X509Certificate> cert);

  crypto::ScopedPK11Slot public_slot_;
  crypto::ScopedPK11Slot private_slot_;

  // A helper observer that forwards events from this database to CertDatabase.
  std::unique_ptr<Observer> cert_notification_forwarder_;

  // Task runner that should be used in tests if set.
  scoped_refptr<base::TaskRunner> slow_task_runner_for_test_;

  const scoped_refptr<base::ObserverListThreadSafe<Observer>> observer_list_;

  base::WeakPtrFactory<NSSCertDatabase> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(NSSCertDatabase);
};

}  // namespace net

#endif  // NET_CERT_NSS_CERT_DATABASE_H_
