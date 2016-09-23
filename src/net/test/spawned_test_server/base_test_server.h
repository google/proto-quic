// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TEST_SPAWNED_TEST_SERVER_BASE_TEST_SERVER_H_
#define NET_TEST_SPAWNED_TEST_SERVER_BASE_TEST_SERVER_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "net/base/host_port_pair.h"
#include "net/ssl/ssl_client_cert_type.h"

class GURL;

namespace base {
class DictionaryValue;
}

namespace net {

class AddressList;
class ScopedPortException;
class X509Certificate;

// The base class of Test server implementation.
class BaseTestServer {
 public:
  typedef std::pair<std::string, std::string> StringPair;

  // Following types represent protocol schemes. See also
  // http://www.iana.org/assignments/uri-schemes.html
  enum Type {
    TYPE_BASIC_AUTH_PROXY,
    TYPE_FTP,
    TYPE_HTTP,
    TYPE_HTTPS,
    TYPE_WS,
    TYPE_WSS,
    TYPE_TCP_ECHO,
    TYPE_UDP_ECHO,
  };

  // Container for various options to control how the HTTPS or WSS server is
  // initialized.
  struct SSLOptions {
    enum ServerCertificate {
      CERT_OK,

      // CERT_AUTO causes the testserver to generate a test certificate issued
      // by "Testing CA" (see net/data/ssl/certificates/ocsp-test-root.pem).
      CERT_AUTO,

      CERT_MISMATCHED_NAME,
      CERT_EXPIRED,
      // Cross-signed certificate to test PKIX path building. Contains an
      // intermediate cross-signed by an unknown root, while the client (via
      // TestRootStore) is expected to have a self-signed version of the
      // intermediate.
      CERT_CHAIN_WRONG_ROOT,

      // Causes the testserver to use a hostname that is a domain
      // instead of an IP.
      CERT_COMMON_NAME_IS_DOMAIN,

      // A certificate with invalid notBefore and notAfter times. Windows'
      // certificate library will not parse this certificate.
      CERT_BAD_VALIDITY,
    };

    // OCSPStatus enumerates the types of OCSP response that the testserver
    // can produce.
    enum OCSPStatus {
      OCSP_OK,
      OCSP_REVOKED,
      OCSP_INVALID_RESPONSE,
      OCSP_UNAUTHORIZED,
      OCSP_UNKNOWN,
      OCSP_INVALID_RESPONSE_DATA,
      OCSP_TRY_LATER,
      OCSP_MISMATCHED_SERIAL,
    };

    // OCSPDate enumerates the date ranges for OCSP responses that the
    // testserver can produce.
    enum OCSPDate {
      OCSP_DATE_VALID,
      OCSP_DATE_OLD,
      OCSP_DATE_EARLY,
      OCSP_DATE_LONG,
    };

    // OCSPSingleResponse is used when specifying multiple stapled responses,
    // each
    // with their own CertStatus and date validity.
    struct OCSPSingleResponse {
      OCSPStatus status;
      OCSPDate date;
    };

    // OCSPProduced enumerates the validity of the producedAt field in OCSP
    // responses produced by the testserver.
    enum OCSPProduced {
      OCSP_PRODUCED_VALID,
      OCSP_PRODUCED_BEFORE_CERT,
      OCSP_PRODUCED_AFTER_CERT,
    };

    // Bitmask of key exchange algorithms that the test server supports and that
    // can be selectively enabled or disabled.
    enum KeyExchange {
      // Special value used to indicate that any algorithm the server supports
      // is acceptable. Preferred over explicitly OR-ing all key exchange
      // algorithms.
      KEY_EXCHANGE_ANY = 0,

      KEY_EXCHANGE_RSA = (1 << 0),
      KEY_EXCHANGE_DHE_RSA = (1 << 1),
      KEY_EXCHANGE_ECDHE_RSA = (1 << 2),
    };

    // Bitmask of bulk encryption algorithms that the test server supports
    // and that can be selectively enabled or disabled.
    enum BulkCipher {
      // Special value used to indicate that any algorithm the server supports
      // is acceptable. Preferred over explicitly OR-ing all ciphers.
      BULK_CIPHER_ANY = 0,

      BULK_CIPHER_RC4 = (1 << 0),
      BULK_CIPHER_AES128 = (1 << 1),
      BULK_CIPHER_AES256 = (1 << 2),

      // NOTE: 3DES support in the Python test server has external
      // dependencies and not be available on all machines. Clients may not
      // be able to connect if only 3DES is specified.
      BULK_CIPHER_3DES = (1 << 3),

      BULK_CIPHER_AES128GCM = (1 << 4),
    };

    // NOTE: the values of these enumerators are passed to the the Python test
    // server. Do not change them.
    enum TLSIntolerantLevel {
      TLS_INTOLERANT_NONE = 0,
      TLS_INTOLERANT_ALL = 1,  // Intolerant of all TLS versions.
      TLS_INTOLERANT_TLS1_1 = 2,  // Intolerant of TLS 1.1 or higher.
      TLS_INTOLERANT_TLS1_2 = 3,  // Intolerant of TLS 1.2 or higher.
    };

    // Values which control how the server reacts in response to a ClientHello
    // it is intolerant of.
    enum TLSIntoleranceType {
      TLS_INTOLERANCE_ALERT = 0,  // Send a handshake_failure alert.
      TLS_INTOLERANCE_CLOSE = 1,  // Close the connection.
      TLS_INTOLERANCE_RESET = 2,  // Send a TCP reset.
    };

    // Initialize a new SSLOptions using CERT_OK as the certificate.
    SSLOptions();

    // Initialize a new SSLOptions that will use the specified certificate.
    explicit SSLOptions(ServerCertificate cert);
    SSLOptions(const SSLOptions& other);
    ~SSLOptions();

    // Returns the relative filename of the file that contains the
    // |server_certificate|.
    base::FilePath GetCertificateFile() const;

    // GetOCSPArgument returns the value of any OCSP argument to testserver or
    // the empty string if there is none.
    std::string GetOCSPArgument() const;

    // GetOCSPDateArgument returns the value of the OCSP date argument to
    // testserver or the empty string if there is none.
    std::string GetOCSPDateArgument() const;

    // GetOCSPProducedArgument returns the value of the OCSP produced argument
    // to testserver or the empty string if there is none.
    std::string GetOCSPProducedArgument() const;

    // The certificate to use when serving requests.
    ServerCertificate server_certificate;

    // If |server_certificate==CERT_AUTO| then this determines the type of OCSP
    // response returned. Ignored if |ocsp_responses| is non-empty.
    OCSPStatus ocsp_status;

    // If |server_certificate==CERT_AUTO| then this determines the date range
    // set on the OCSP response returned. Ignore if |ocsp_responses| is
    // non-empty.
    OCSPDate ocsp_date;

    // If |server_certificate==CERT_AUTO|, contains the status and validity for
    // multiple stapled responeses. Overrides |ocsp_status| and |ocsp_date| when
    // non-empty.
    std::vector<OCSPSingleResponse> ocsp_responses;

    // If |server_certificate==CERT_AUTO| then this determines the validity of
    // the producedAt field on the returned OCSP response.
    OCSPProduced ocsp_produced;

    // If not zero, |cert_serial| will be the serial number of the
    // auto-generated leaf certificate when |server_certificate==CERT_AUTO|.
    uint64_t cert_serial;

    // True if a CertificateRequest should be sent to the client during
    // handshaking.
    bool request_client_certificate;

    // If |request_client_certificate| is true, an optional list of files,
    // each containing a single, PEM-encoded X.509 certificates. The subject
    // from each certificate will be added to the certificate_authorities
    // field of the CertificateRequest.
    std::vector<base::FilePath> client_authorities;

    // If |request_client_certificate| is true, an optional list of
    // SSLClientCertType values to populate the certificate_types field of the
    // CertificateRequest.
    std::vector<SSLClientCertType> client_cert_types;

    // A bitwise-OR of KeyExchnage that should be used by the
    // HTTPS server, or KEY_EXCHANGE_ANY to indicate that all implemented
    // key exchange algorithms are acceptable.
    int key_exchanges;

    // A bitwise-OR of BulkCipher that should be used by the
    // HTTPS server, or BULK_CIPHER_ANY to indicate that all implemented
    // ciphers are acceptable.
    int bulk_ciphers;

    // If true, pass the --https-record-resume argument to testserver.py which
    // causes it to log session cache actions and echo the log on
    // /ssl-session-cache.
    bool record_resume;

    // If not TLS_INTOLERANT_NONE, the server will abort any handshake that
    // negotiates an intolerant TLS version in order to test version fallback.
    TLSIntolerantLevel tls_intolerant;

    // If |tls_intolerant| is not TLS_INTOLERANT_NONE, how the server reacts to
    // an intolerant TLS version.
    TLSIntoleranceType tls_intolerance_type;

    // fallback_scsv_enabled, if true, causes the server to process the
    // TLS_FALLBACK_SCSV cipher suite. This cipher suite is sent by Chrome
    // when performing TLS version fallback in response to an SSL handshake
    // failure. If this option is enabled then the server will reject fallback
    // connections.
    bool fallback_scsv_enabled;

    // Temporary glue for testing: validation of SCTs is application-controlled
    // and can be appropriately mocked out, so sending fake data here does not
    // affect handshaking behaviour.
    // TODO(ekasper): replace with valid SCT files for test certs.
    // (Fake) SignedCertificateTimestampList (as a raw binary string) to send in
    // a TLS extension.
    std::string signed_cert_timestamps_tls_ext;

    // Whether to staple the OCSP response.
    bool staple_ocsp_response;

    // Whether to make the OCSP server unavailable. This does not affect the
    // stapled OCSP response.
    bool ocsp_server_unavailable;

    // List of protocols to advertise in NPN extension.  NPN is not supported if
    // list is empty.  Note that regardless of what protocol is negotiated, the
    // test server will continue to speak HTTP/1.1.
    std::vector<std::string> npn_protocols;

    // List of supported ALPN protocols.
    std::vector<std::string> alpn_protocols;

    // Whether to send a fatal alert immediately after completing the handshake.
    bool alert_after_handshake;

    // If true, disables channel ID on the server.
    bool disable_channel_id;

    // If true, disables extended master secret tls extension.
    bool disable_extended_master_secret;

    // List of token binding params that the server supports and will negotiate.
    std::vector<int> supported_token_binding_params;
  };

  // Pass as the 'host' parameter during construction to server on 127.0.0.1
  static const char kLocalhost[];

  // Initialize a TestServer listening on a specific host (IP or hostname).
  BaseTestServer(Type type,  const std::string& host);

  // Initialize a TestServer with a specific set of SSLOptions for HTTPS or WSS.
  BaseTestServer(Type type, const SSLOptions& ssl_options);

  // Returns the host port pair used by current Python based test server only
  // if the server is started.
  const HostPortPair& host_port_pair() const;

  const base::FilePath& document_root() const { return document_root_; }
  const base::DictionaryValue& server_data() const;
  std::string GetScheme() const;
  bool GetAddressList(AddressList* address_list) const WARN_UNUSED_RESULT;

  GURL GetURL(const std::string& path) const;

  GURL GetURLWithUser(const std::string& path,
                      const std::string& user) const;

  GURL GetURLWithUserAndPassword(const std::string& path,
                                 const std::string& user,
                                 const std::string& password) const;

  static bool GetFilePathWithReplacements(
      const std::string& original_path,
      const std::vector<StringPair>& text_to_replace,
      std::string* replacement_path);

  static bool UsingSSL(Type type) {
    return type == BaseTestServer::TYPE_HTTPS ||
           type == BaseTestServer::TYPE_WSS;
  }

  // Enable HTTP basic authentication. Currently this only works for TYPE_WS and
  // TYPE_WSS.
  void set_websocket_basic_auth(bool ws_basic_auth) {
    ws_basic_auth_ = ws_basic_auth;
  }

  // Disable creation of anonymous FTP user.
  void set_no_anonymous_ftp_user(bool no_anonymous_ftp_user) {
    no_anonymous_ftp_user_ = no_anonymous_ftp_user;
  }

  // Marks the root certificate of an HTTPS test server as trusted for
  // the duration of tests.
  bool LoadTestRootCert() const WARN_UNUSED_RESULT;

  // Returns the certificate that the server is using.
  scoped_refptr<X509Certificate> GetCertificate() const;

 protected:
  virtual ~BaseTestServer();
  Type type() const { return type_; }

  // Gets port currently assigned to host_port_pair_ without checking
  // whether it's available (server started) or not.
  uint16_t GetPort();

  // Sets |port| as the actual port used by Python based test server.
  void SetPort(uint16_t port);

  // Set up internal status when the server is started.
  bool SetupWhenServerStarted() WARN_UNUSED_RESULT;

  // Clean up internal status when starting to stop server.
  void CleanUpWhenStoppingServer();

  // Set path of test resources.
  void SetResourcePath(const base::FilePath& document_root,
                       const base::FilePath& certificates_dir);

  // Parses the server data read from the test server.  Returns true
  // on success.
  bool ParseServerData(const std::string& server_data) WARN_UNUSED_RESULT;

  // Generates a DictionaryValue with the arguments for launching the external
  // Python test server.
  bool GenerateArguments(base::DictionaryValue* arguments) const
    WARN_UNUSED_RESULT;

  // Subclasses can override this to add arguments that are specific to their
  // own test servers.
  virtual bool GenerateAdditionalArguments(
      base::DictionaryValue* arguments) const WARN_UNUSED_RESULT;

 private:
  void Init(const std::string& host);

  // Document root of the test server.
  base::FilePath document_root_;

  // Directory that contains the SSL certificates.
  base::FilePath certificates_dir_;

  // Address the test server listens on.
  HostPortPair host_port_pair_;

  // Holds the data sent from the server (e.g., port number).
  std::unique_ptr<base::DictionaryValue> server_data_;

  // If |type_| is TYPE_HTTPS or TYPE_WSS, the TLS settings to use for the test
  // server.
  SSLOptions ssl_options_;

  Type type_;

  // Has the server been started?
  bool started_;

  // Enables logging of the server to the console.
  bool log_to_console_;

  // Is WebSocket basic HTTP authentication enabled?
  bool ws_basic_auth_;

  // Disable creation of anonymous FTP user?
  bool no_anonymous_ftp_user_;

  std::unique_ptr<ScopedPortException> allowed_port_;

  DISALLOW_COPY_AND_ASSIGN(BaseTestServer);
};

}  // namespace net

#endif  // NET_TEST_SPAWNED_TEST_SERVER_BASE_TEST_SERVER_H_
