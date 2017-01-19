// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_ANDROID_NETWORK_LIBRARY_H_
#define NET_ANDROID_NETWORK_LIBRARY_H_

#include <jni.h>
#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "net/android/cert_verify_result_android.h"
#include "net/base/ip_endpoint.h"
#include "net/base/mime_util.h"
#include "net/base/net_export.h"

namespace net {
namespace android {

// |cert_chain| is DER encoded chain of certificates, with the server's own
// certificate listed first.
// |auth_type| is as per the Java X509Certificate.checkServerTrusted method.
void VerifyX509CertChain(const std::vector<std::string>& cert_chain,
                         const std::string& auth_type,
                         const std::string& host,
                         CertVerifyStatusAndroid* status,
                         bool* is_issued_by_known_root,
                         std::vector<std::string>* verified_chain);

// Adds a certificate as a root trust certificate to the trust manager.
// |cert| is DER encoded certificate, |len| is its length in bytes.
void AddTestRootCertificate(const uint8_t* cert, size_t len);

// Removes all root certificates added by |AddTestRootCertificate| calls.
void ClearTestRootCertificates();

// Returns true if cleartext traffic to |host| is allowed by the app. Always
// true on L and older.
bool IsCleartextPermitted(const std::string& host);

// Returns true if it can determine that only loopback addresses are configured.
// i.e. if only 127.0.0.1 and ::1 are routable.
// Also returns false if it cannot determine this.
bool HaveOnlyLoopbackAddresses();

// Get the mime type (if any) that is associated with the file extension.
// Returns true if a corresponding mime type exists.
bool GetMimeTypeFromExtension(const std::string& extension,
                              std::string* result);

// Returns the ISO country code equivalent of the current MCC (mobile country
// code).
NET_EXPORT std::string GetTelephonyNetworkCountryIso();

// Returns MCC+MNC (mobile country code + mobile network code) as
// the numeric name of the current registered operator.
NET_EXPORT std::string GetTelephonyNetworkOperator();

// Returns MCC+MNC (mobile country code + mobile network code) as
// the numeric name of the current SIM operator.
NET_EXPORT std::string GetTelephonySimOperator();

// Returns true if the device is roaming on the currently active network. When
// true, it suggests that use of data may incur extra costs.
NET_EXPORT bool GetIsRoaming();

// Returns true if the system's captive portal probe was blocked for the current
// default data network. The method will return false if the captive portal
// probe was not blocked, the login process to the captive portal has been
// successfully completed, or if the captive portal status can't be determined.
// Requires ACCESS_NETWORK_STATE permission. Only available on Android
// Marshmallow and later versions. Returns false on earlier versions.
NET_EXPORT bool GetIsCaptivePortal();

// Gets the SSID of the currently associated WiFi access point if there is one.
// Otherwise, returns empty string.
NET_EXPORT_PRIVATE std::string GetWifiSSID();

// Gets the DNS servers and puts them in |dns_servers|.
// Only callable on Marshmallow and newer releases.
NET_EXPORT_PRIVATE void GetDnsServers(std::vector<IPEndPoint>* dns_servers);

}  // namespace android
}  // namespace net

#endif  // NET_ANDROID_NETWORK_LIBRARY_H_
