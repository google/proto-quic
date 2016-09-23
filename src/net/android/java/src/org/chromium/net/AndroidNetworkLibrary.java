// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.net;

import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.security.KeyChain;
import android.telephony.TelephonyManager;
import android.util.Log;

import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.CalledByNativeUnchecked;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URLConnection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

/**
 * This class implements net utilities required by the net component.
 */
class AndroidNetworkLibrary {

    private static final String TAG = "AndroidNetworkLibrary";

    /**
     * Stores the key pair through the CertInstaller activity.
     * @param context current application context.
     * @param publicKey The public key bytes as DER-encoded SubjectPublicKeyInfo (X.509)
     * @param privateKey The private key as DER-encoded PrivateKeyInfo (PKCS#8).
     * @return: true on success, false on failure.
     *
     * Note that failure means that the function could not launch the CertInstaller
     * activity. Whether the keys are valid or properly installed will be indicated
     * by the CertInstaller UI itself.
     */
    @CalledByNative
    public static boolean storeKeyPair(Context context, byte[] publicKey, byte[] privateKey) {
        // TODO(digit): Use KeyChain official extra values to pass the public and private
        // keys when they're available. The "KEY" and "PKEY" hard-coded constants were taken
        // from the platform sources, since there are no official KeyChain.EXTRA_XXX definitions
        // for them. b/5859651
        try {
            Intent intent = KeyChain.createInstallIntent();
            intent.putExtra("PKEY", privateKey);
            intent.putExtra("KEY", publicKey);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(intent);
            return true;
        } catch (ActivityNotFoundException e) {
            Log.w(TAG, "could not store key pair: " + e);
        }
        return false;
    }

    /**
      * Adds a cryptographic file (User certificate, a CA certificate or
      * PKCS#12 keychain) through the system's CertInstaller activity.
      *
      * @param context current application context.
      * @param certType cryptographic file type. E.g. CertificateMimeType.X509_USER_CERT
      * @param data certificate/keychain data bytes.
      * @return true on success, false on failure.
      *
      * Note that failure only indicates that the function couldn't launch the
      * CertInstaller activity, not that the certificate/keychain was properly
      * installed to the keystore.
      */
    @CalledByNative
    public static boolean storeCertificate(Context context, int certType, byte[] data) {
        try {
            Intent intent = KeyChain.createInstallIntent();
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

            switch (certType) {
                case CertificateMimeType.X509_USER_CERT:
                case CertificateMimeType.X509_CA_CERT:
                    intent.putExtra(KeyChain.EXTRA_CERTIFICATE, data);
                    break;

                case CertificateMimeType.PKCS12_ARCHIVE:
                    intent.putExtra(KeyChain.EXTRA_PKCS12, data);
                    break;

                default:
                    Log.w(TAG, "invalid certificate type: " + certType);
                    return false;
            }
            context.startActivity(intent);
            return true;
        } catch (ActivityNotFoundException e) {
            Log.w(TAG, "could not store crypto file: " + e);
        }
        return false;
    }

    /**
     * @return the mime type (if any) that is associated with the file
     *         extension. Returns null if no corresponding mime type exists.
     */
    @CalledByNative
    public static String getMimeTypeFromExtension(String extension) {
        return URLConnection.guessContentTypeFromName("foo." + extension);
    }

    /**
     * @return true if it can determine that only loopback addresses are
     *         configured. i.e. if only 127.0.0.1 and ::1 are routable. Also
     *         returns false if it cannot determine this.
     */
    @CalledByNative
    public static boolean haveOnlyLoopbackAddresses() {
        Enumeration<NetworkInterface> list = null;
        try {
            list = NetworkInterface.getNetworkInterfaces();
            if (list == null) return false;
        } catch (Exception e) {
            Log.w(TAG, "could not get network interfaces: " + e);
            return false;
        }

        while (list.hasMoreElements()) {
            NetworkInterface netIf = list.nextElement();
            try {
                if (netIf.isUp() && !netIf.isLoopback()) return false;
            } catch (SocketException e) {
                continue;
            }
        }
        return true;
    }

    /**
     * Validate the server's certificate chain is trusted. Note that the caller
     * must still verify the name matches that of the leaf certificate.
     *
     * @param certChain The ASN.1 DER encoded bytes for certificates.
     * @param authType The key exchange algorithm name (e.g. RSA).
     * @param host The hostname of the server.
     * @return Android certificate verification result code.
     */
    @CalledByNative
    public static AndroidCertVerifyResult verifyServerCertificates(byte[][] certChain,
                                                                   String authType,
                                                                   String host) {
        try {
            return X509Util.verifyServerCertificates(certChain, authType, host);
        } catch (KeyStoreException e) {
            return new AndroidCertVerifyResult(CertVerifyStatusAndroid.FAILED);
        } catch (NoSuchAlgorithmException e) {
            return new AndroidCertVerifyResult(CertVerifyStatusAndroid.FAILED);
        } catch (IllegalArgumentException e) {
            return new AndroidCertVerifyResult(CertVerifyStatusAndroid.FAILED);
        }
    }

    /**
     * Adds a test root certificate to the local trust store.
     * @param rootCert DER encoded bytes of the certificate.
     */
    @CalledByNativeUnchecked
    public static void addTestRootCertificate(byte[] rootCert) throws CertificateException,
            KeyStoreException, NoSuchAlgorithmException {
        X509Util.addTestRootCertificate(rootCert);
    }

    /**
     * Removes all test root certificates added by |addTestRootCertificate| calls from the local
     * trust store.
     */
    @CalledByNativeUnchecked
    public static void clearTestRootCertificates() throws NoSuchAlgorithmException,
            CertificateException, KeyStoreException {
        X509Util.clearTestRootCertificates();
    }

    /**
     * Returns the ISO country code equivalent of the current MCC.
     */
    @CalledByNative
    private static String getNetworkCountryIso(Context context) {
        TelephonyManager telephonyManager =
                (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        if (telephonyManager == null) return "";
        return telephonyManager.getNetworkCountryIso();
    }

    /**
     * Returns the MCC+MNC (mobile country code + mobile network code) as
     * the numeric name of the current registered operator.
     */
    @CalledByNative
    private static String getNetworkOperator(Context context) {
        TelephonyManager telephonyManager =
                (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        if (telephonyManager == null) return "";
        return telephonyManager.getNetworkOperator();
    }

    /**
     * Returns the MCC+MNC (mobile country code + mobile network code) as
     * the numeric name of the current SIM operator.
     */
    @CalledByNative
    private static String getSimOperator(Context context) {
        TelephonyManager telephonyManager =
                (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        if (telephonyManager == null) return "";
        return telephonyManager.getSimOperator();
    }

    /**
     * Indicates whether the device is roaming on the currently active network. When true, it
     * suggests that use of data may incur extra costs.
     */
    @CalledByNative
    private static boolean getIsRoaming(Context context) {
        ConnectivityManager connectivityManager =
                (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = connectivityManager.getActiveNetworkInfo();
        if (networkInfo == null) return false; // No active network.
        return networkInfo.isRoaming();
    }

    /**
     * Gets the SSID of the currently associated WiFi access point if there is one. Otherwise,
     * returns empty string.
     */
    @CalledByNative
    public static String getWifiSSID(Context context) {
        if (context == null) {
            return "";
        }
        final Intent intent = context.registerReceiver(
                null, new IntentFilter(WifiManager.NETWORK_STATE_CHANGED_ACTION));
        if (intent != null) {
            final WifiInfo wifiInfo = intent.getParcelableExtra(WifiManager.EXTRA_WIFI_INFO);
            if (wifiInfo != null) {
                final String ssid = wifiInfo.getSSID();
                if (ssid != null) {
                    return ssid;
                }
            }
        }
        return "";
    }
}
