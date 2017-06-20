// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.net;

import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.http.X509TrustManagerExtensions;
import android.os.Build;
import android.security.KeyChain;
import android.util.Pair;

import org.chromium.base.BuildInfo;
import org.chromium.base.ContextUtils;
import org.chromium.base.Log;
import org.chromium.base.annotations.JNINamespace;
import org.chromium.base.annotations.SuppressFBWarnings;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

/**
 * Utility functions for verifying X.509 certificates.
 */
@JNINamespace("net")
public class X509Util {

    private static final String TAG = "X509Util";

    // For Android O+, ACTION_STORAGE_CHANGED is split into several different
    // intents.
    //
    // TODO(davidben): Replace these with the constants from android.security.Keychain once O is
    // released.
    private static final String ACTION_KEYCHAIN_CHANGED =
            "android.security.action.KEYCHAIN_CHANGED";
    private static final String ACTION_KEY_ACCESS_CHANGED =
            "android.security.action.KEY_ACCESS_CHANGED";
    private static final String ACTION_TRUST_STORE_CHANGED =
            "android.security.action.TRUST_STORE_CHANGED";
    private static final String EXTRA_KEY_ACCESSIBLE = "android.security.extra.KEY_ACCESSIBLE";

    private static final class TrustStorageListener extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            boolean shouldReloadTrustManager = false;
            if (BuildInfo.isAtLeastO()) {
                if (ACTION_KEYCHAIN_CHANGED.equals(intent.getAction())
                        || ACTION_TRUST_STORE_CHANGED.equals(intent.getAction())) {
                    // TODO(davidben): ACTION_KEYCHAIN_CHANGED indicates client certificates
                    // changed, not the trust store. The two signals within CertDatabase are
                    // identical, so we are reloading more than needed. But note b/36492171.
                    shouldReloadTrustManager = true;
                } else if (ACTION_KEY_ACCESS_CHANGED.equals(intent.getAction())
                        && !intent.getBooleanExtra(EXTRA_KEY_ACCESSIBLE, false)) {
                    // We lost access to a client certificate key. Reload all client certificate
                    // state as we are not currently able to forget an individual identity.
                    shouldReloadTrustManager = true;
                }
            } else {
                // Before Android O, KeyChain only emitted a coarse-grained intent. This fires much
                // more often than it should (https://crbug.com/381912), but there are no APIs to
                // distinguish the various cases.
                shouldReloadTrustManager =
                        KeyChain.ACTION_STORAGE_CHANGED.equals(intent.getAction());
            }

            if (shouldReloadTrustManager) {
                try {
                    reloadDefaultTrustManager();
                } catch (CertificateException e) {
                    Log.e(TAG, "Unable to reload the default TrustManager", e);
                } catch (KeyStoreException e) {
                    Log.e(TAG, "Unable to reload the default TrustManager", e);
                } catch (NoSuchAlgorithmException e) {
                    Log.e(TAG, "Unable to reload the default TrustManager", e);
                }
            }
        }
    }

    /**
     * Interface that wraps one of X509TrustManager or
     * X509TrustManagerExtensions to support platforms before the latter was
     * added.
     */
    private static interface X509TrustManagerImplementation {
        public List<X509Certificate> checkServerTrusted(X509Certificate[] chain,
                                                        String authType,
                                                        String host) throws CertificateException;
    }

    private static final class X509TrustManagerIceCreamSandwich implements
            X509TrustManagerImplementation {
        private final X509TrustManager mTrustManager;

        public X509TrustManagerIceCreamSandwich(X509TrustManager trustManager) {
            mTrustManager = trustManager;
        }

        @Override
        public List<X509Certificate> checkServerTrusted(X509Certificate[] chain,
                                                        String authType,
                                                        String host) throws CertificateException {
            mTrustManager.checkServerTrusted(chain, authType);
            return Collections.<X509Certificate>emptyList();
        }
    }

    private static final class X509TrustManagerJellyBean implements X509TrustManagerImplementation {
        private final X509TrustManagerExtensions mTrustManagerExtensions;

        @SuppressLint("NewApi")
        public X509TrustManagerJellyBean(X509TrustManager trustManager) {
            mTrustManagerExtensions = new X509TrustManagerExtensions(trustManager);
        }

        @Override
        public List<X509Certificate> checkServerTrusted(X509Certificate[] chain,
                                                        String authType,
                                                        String host) throws CertificateException {
            return mTrustManagerExtensions.checkServerTrusted(chain, authType, host);
        }
    }

    private static CertificateFactory sCertificateFactory;

    private static final String OID_TLS_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    private static final String OID_ANY_EKU = "2.5.29.37.0";
    // Server-Gated Cryptography (necessary to support a few legacy issuers):
    //    Netscape:
    private static final String OID_SERVER_GATED_NETSCAPE = "2.16.840.1.113730.4.1";
    //    Microsoft:
    private static final String OID_SERVER_GATED_MICROSOFT = "1.3.6.1.4.1.311.10.3.3";

    /**
     * BroadcastReceiver that listens to change in the system keystore to invalidate certificate
     * caches.
     */
    private static TrustStorageListener sTrustStorageListener;

    /**
     * The system key store. This is used to determine whether a trust anchor is a system trust
     * anchor or user-installed.
     */
    private static KeyStore sSystemKeyStore;

    /**
     * The directory where system certificates are stored. This is used to determine whether a
     * trust anchor is a system trust anchor or user-installed. The KeyStore API alone is not
     * sufficient to efficiently query whether a given X500Principal, PublicKey pair is a trust
     * anchor.
     */
    private static File sSystemCertificateDirectory;

    /**
     * True if ensureInitialized has run successfully.
     */
    private static boolean sInitialized;

    /**
     * The list of test root certificates to inject via testing. This list is protected by sLock.
     */
    private static List<X509Certificate> sTestRoots = new ArrayList<X509Certificate>();

    /**
     * Wraps all reloadable state in the verifier. When the backing KeyStores change, this field
     * should be reset to null. Any verifications currently using the old instance will run to
     * completion, but new ones use fresh state.
     */
    private static CertificateVerifier sVerifier;

    /**
     * Lock object used to synchronize all calls that modify or depend on the above globals. All
     * fields except sVerifier are final once ensureInitialized completes successfully.
     */
    private static final Object sLock = new Object();

    /**
     * Allow disabling registering the observer and recording histograms for the certificate
     * changes. Net unit tests do not load native libraries which prevent this to succeed. Moreover,
     * the system does not allow to interact with the certificate store without user interaction.
     */
    private static boolean sDisableNativeCodeForTest;

    private static final class CertificateVerifier {
        /**
         * X509TrustManager wrapping the default KeyStore.
         */
        private X509TrustManagerImplementation mDefaultTrustManager;

        /**
         * X509TrustManager wrapping any test roots which were configured when the
         * CertificateVerifier was created.
         */
        private X509TrustManagerImplementation mTestTrustManager;

        /**
         * An in-memory cache of which trust anchors are system trust roots. This avoids reading and
         * decoding the root from disk on every verification and mirrors a similar in-memory cache
         * in Conscrypt's X509TrustManager implementation.
         */
        private Set<Pair<X500Principal, PublicKey>> mSystemTrustAnchorCache;

        /**
         * Lock object used to synchronize mSystemTrustAnchorCache.
         */
        private Object mSystemTrustAnchorCacheLock;

        public CertificateVerifier()
                throws CertificateException, KeyStoreException, NoSuchAlgorithmException {
            assert Thread.holdsLock(sLock);
            ensureInitializedLocked();

            mDefaultTrustManager = createTrustManager(null);
            if (!sTestRoots.isEmpty()) {
                KeyStore testKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                try {
                    testKeyStore.load(null);
                } catch (IOException e) {
                    // No IO operation is attempted
                }
                for (int i = 0; i < sTestRoots.size(); i++) {
                    testKeyStore.setCertificateEntry(
                            "root_cert_" + Integer.toString(i), sTestRoots.get(i));
                }
                mTestTrustManager = createTrustManager(testKeyStore);
            }
            mSystemTrustAnchorCache = new HashSet<Pair<X500Principal, PublicKey>>();
            mSystemTrustAnchorCacheLock = new Object();
        }

        /**
         * Creates a X509TrustManagerImplementation backed up by the given key store. When null is
         * passed as a key store, system default trust store is used. Returns null if no created
         * TrustManager was suitable.
         * @throws KeyStoreException, NoSuchAlgorithmException on error initializing the
         * TrustManager.
         */
        private static X509TrustManagerImplementation createTrustManager(KeyStore keyStore)
                throws KeyStoreException, NoSuchAlgorithmException {
            String algorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
            tmf.init(keyStore);

            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager) {
                    try {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                            return new X509TrustManagerJellyBean((X509TrustManager) tm);
                        } else {
                            return new X509TrustManagerIceCreamSandwich((X509TrustManager) tm);
                        }
                    } catch (IllegalArgumentException e) {
                        String className = tm.getClass().getName();
                        Log.e(TAG, "Error creating trust manager (" + className + "): " + e);
                    }
                }
            }
            Log.e(TAG, "Could not find suitable trust manager");
            return null;
        }

        private static final char[] HEX_DIGITS = {
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        };

        private static String hashPrincipal(X500Principal principal)
                throws NoSuchAlgorithmException {
            // Android hashes a principal as the first four bytes of its MD5 digest, encoded in
            // lowercase hex and reversed. Verified in 4.2, 4.3, and 4.4.
            byte[] digest = MessageDigest.getInstance("MD5").digest(principal.getEncoded());
            char[] hexChars = new char[8];
            for (int i = 0; i < 4; i++) {
                hexChars[2 * i] = HEX_DIGITS[(digest[3 - i] >> 4) & 0xf];
                hexChars[2 * i + 1] = HEX_DIGITS[digest[3 - i] & 0xf];
            }
            return new String(hexChars);
        }

        private boolean isKnownRoot(X509Certificate root)
                throws NoSuchAlgorithmException, KeyStoreException {
            // Could not find the system key store. Conservatively report false.
            if (sSystemKeyStore == null) return false;

            // Check the in-memory cache first; avoid decoding the anchor from disk
            // if it has been seen before.
            Pair<X500Principal, PublicKey> key = new Pair<X500Principal, PublicKey>(
                    root.getSubjectX500Principal(), root.getPublicKey());

            synchronized (mSystemTrustAnchorCacheLock) {
                if (mSystemTrustAnchorCache.contains(key)) return true;
            }

            // Note: It is not sufficient to call sSystemKeyStore.getCertificiateAlias. If the
            // server supplies a copy of a trust anchor, X509TrustManagerExtensions returns the
            // server's version rather than the system one. getCertificiateAlias will then fail to
            // find an anchor name. This is fixed upstream in
            // https://android-review.googlesource.com/#/c/91605/
            //
            // TODO(davidben): When the change trickles into an Android release, query
            // sSystemKeyStore directly.

            // System trust anchors are stored under a hash of the principal. In case of collisions,
            // a number is appended.
            String hash = hashPrincipal(root.getSubjectX500Principal());
            for (int i = 0; true; i++) {
                String alias = hash + '.' + i;
                if (!new File(sSystemCertificateDirectory, alias).exists()) break;

                Certificate anchor = sSystemKeyStore.getCertificate("system:" + alias);
                // It is possible for this to return null if the user deleted a trust anchor. In
                // that case, the certificate remains in the system directory but is also added to
                // another file. Continue iterating as there may be further collisions after the
                // deleted anchor.
                if (anchor == null) continue;

                if (!(anchor instanceof X509Certificate)) {
                    // This should never happen.
                    String className = anchor.getClass().getName();
                    Log.e(TAG, "Anchor " + alias + " not an X509Certificate: " + className);
                    continue;
                }

                // If the subject and public key match, this is a system root.
                X509Certificate anchorX509 = (X509Certificate) anchor;
                if (root.getSubjectX500Principal().equals(anchorX509.getSubjectX500Principal())
                        && root.getPublicKey().equals(anchorX509.getPublicKey())) {
                    synchronized (mSystemTrustAnchorCacheLock) {
                        mSystemTrustAnchorCache.add(key);
                    }
                    return true;
                }
            }

            return false;
        }

        public AndroidCertVerifyResult verifyServerCertificates(byte[][] certChain, String authType,
                String host) throws KeyStoreException, NoSuchAlgorithmException {
            if (certChain == null || certChain.length == 0 || certChain[0] == null) {
                throw new IllegalArgumentException("Expected non-null and non-empty certificate "
                        + "chain passed as |certChain|. |certChain|="
                        + Arrays.deepToString(certChain));
            }

            X509Certificate[] serverCertificates = new X509Certificate[certChain.length];
            try {
                for (int i = 0; i < certChain.length; ++i) {
                    serverCertificates[i] = createCertificateFromBytes(certChain[i]);
                }
            } catch (CertificateException e) {
                return new AndroidCertVerifyResult(CertVerifyStatusAndroid.UNABLE_TO_PARSE);
            }

            // Expired and not yet valid certificates would be rejected by the trust managers, but
            // the trust managers report all certificate errors using the general
            // CertificateException. In order to get more granular error information, cert validity
            // time range is being checked separately.
            try {
                serverCertificates[0].checkValidity();
                if (!verifyKeyUsage(serverCertificates[0])) {
                    return new AndroidCertVerifyResult(CertVerifyStatusAndroid.INCORRECT_KEY_USAGE);
                }
            } catch (CertificateExpiredException e) {
                return new AndroidCertVerifyResult(CertVerifyStatusAndroid.EXPIRED);
            } catch (CertificateNotYetValidException e) {
                return new AndroidCertVerifyResult(CertVerifyStatusAndroid.NOT_YET_VALID);
            } catch (CertificateException e) {
                return new AndroidCertVerifyResult(CertVerifyStatusAndroid.FAILED);
            }

            List<X509Certificate> verifiedChain;
            try {
                verifiedChain =
                        mDefaultTrustManager.checkServerTrusted(serverCertificates, authType, host);
            } catch (CertificateException eDefaultManager) {
                try {
                    if (mTestTrustManager == null) {
                        throw new CertificateException();
                    }
                    verifiedChain = mTestTrustManager.checkServerTrusted(
                            serverCertificates, authType, host);
                } catch (CertificateException eTestManager) {
                    // Neither of the trust managers confirms the validity of the certificate chain,
                    // log the error message returned by the system trust manager.
                    Log.i(TAG,
                            "Failed to validate the certificate chain, error: "
                                    + eDefaultManager.getMessage());
                    return new AndroidCertVerifyResult(CertVerifyStatusAndroid.NO_TRUSTED_ROOT);
                }
            }

            boolean isIssuedByKnownRoot = false;
            if (verifiedChain.size() > 0) {
                X509Certificate root = verifiedChain.get(verifiedChain.size() - 1);
                isIssuedByKnownRoot = isKnownRoot(root);
            }

            return new AndroidCertVerifyResult(
                    CertVerifyStatusAndroid.OK, isIssuedByKnownRoot, verifiedChain);
        }
    }

    /**
     * Ensures that the trust managers and certificate factory are initialized.
     */
    private static void ensureInitialized() throws CertificateException,
            KeyStoreException, NoSuchAlgorithmException {
        synchronized (sLock) {
            ensureInitializedLocked();
        }
    }

    /**
     * Ensures that the trust managers and certificate factory are initialized. Must be called with
     * |sLock| held.
     */
    // FindBugs' static field initialization warnings do not handle methods that are expected to be
    // called locked.
    @SuppressFBWarnings({"LI_LAZY_INIT_STATIC", "LI_LAZY_INIT_UPDATE_STATIC"})
    private static void ensureInitializedLocked()
            throws CertificateException, KeyStoreException, NoSuchAlgorithmException {
        assert Thread.holdsLock(sLock);

        if (sInitialized) return;

        sCertificateFactory = CertificateFactory.getInstance("X.509");

        try {
            sSystemKeyStore = KeyStore.getInstance("AndroidCAStore");
            try {
                sSystemKeyStore.load(null);
            } catch (IOException e) {
                // No IO operation is attempted.
            }
            sSystemCertificateDirectory =
                    new File(System.getenv("ANDROID_ROOT") + "/etc/security/cacerts");
        } catch (KeyStoreException e) {
            // Could not load AndroidCAStore. Continue anyway; isKnownRoot will always
            // return false.
        }
        if (!sDisableNativeCodeForTest) {
            nativeRecordCertVerifyCapabilitiesHistogram(sSystemKeyStore != null);
        }

        if (!sDisableNativeCodeForTest && sTrustStorageListener == null) {
            sTrustStorageListener = new TrustStorageListener();
            IntentFilter filter = new IntentFilter();
            if (BuildInfo.isAtLeastO()) {
                filter.addAction(ACTION_KEYCHAIN_CHANGED);
                filter.addAction(ACTION_KEY_ACCESS_CHANGED);
                filter.addAction(ACTION_TRUST_STORE_CHANGED);
            } else {
                filter.addAction(KeyChain.ACTION_STORAGE_CHANGED);
            }
            ContextUtils.getApplicationContext().registerReceiver(sTrustStorageListener, filter);
        }

        sInitialized = true;
    }

    /**
     * Returns the current CertificateVerifier instance.
     */
    private static CertificateVerifier getVerifier()
            throws CertificateException, KeyStoreException, NoSuchAlgorithmException {
        synchronized (sLock) {
            if (sVerifier == null) {
                sVerifier = new CertificateVerifier();
            }
            return sVerifier;
        }
    }

    /**
     * After each modification by the system of the key store, trust manager has to be regenerated.
     */
    private static void reloadDefaultTrustManager()
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException {
        synchronized (sLock) {
            // Invalidate the current verifier. Future certificate requests will
            // use fresh state.
            sVerifier = null;
        }
        nativeNotifyKeyChainChanged();
    }

    /**
     * Convert a DER encoded certificate to an X509Certificate.
     */
    public static X509Certificate createCertificateFromBytes(byte[] derBytes) throws
            CertificateException, KeyStoreException, NoSuchAlgorithmException {
        ensureInitialized();
        return (X509Certificate) sCertificateFactory.generateCertificate(
                new ByteArrayInputStream(derBytes));
    }

    public static void addTestRootCertificate(byte[] rootCertBytes) throws CertificateException,
            KeyStoreException, NoSuchAlgorithmException {
        X509Certificate rootCert = createCertificateFromBytes(rootCertBytes);
        synchronized (sLock) {
            sTestRoots.add(rootCert);
            sVerifier = null;
        }
    }

    public static void clearTestRootCertificates()
            throws NoSuchAlgorithmException, CertificateException, KeyStoreException {
        synchronized (sLock) {
            sTestRoots.clear();
            sVerifier = null;
        }
    }

    /**
     * If an EKU extension is present in the end-entity certificate, it MUST contain either the
     * anyEKU or serverAuth or netscapeSGC or Microsoft SGC EKUs.
     *
     * @return true if there is no EKU extension or if any of the EKU extensions is one of the valid
     * OIDs for web server certificates.
     *
     * TODO(palmer): This can be removed after the equivalent change is made to the Android default
     * TrustManager and that change is shipped to a large majority of Android users.
     */
    static boolean verifyKeyUsage(X509Certificate certificate) throws CertificateException {
        List<String> ekuOids;
        try {
            ekuOids = certificate.getExtendedKeyUsage();
        } catch (NullPointerException e) {
            // getExtendedKeyUsage() can crash due to an Android platform bug. This probably
            // happens when the EKU extension data is malformed so return false here.
            // See http://crbug.com/233610
            return false;
        }
        if (ekuOids == null) return true;

        for (String ekuOid : ekuOids) {
            if (ekuOid.equals(OID_TLS_SERVER_AUTH)
                    || ekuOid.equals(OID_ANY_EKU)
                    || ekuOid.equals(OID_SERVER_GATED_NETSCAPE)
                    || ekuOid.equals(OID_SERVER_GATED_MICROSOFT)) {
                return true;
            }
        }

        return false;
    }

    public static AndroidCertVerifyResult verifyServerCertificates(byte[][] certChain,
                                                                   String authType,
                                                                   String host)
            throws KeyStoreException, NoSuchAlgorithmException {
        CertificateVerifier verifier;
        try {
            verifier = getVerifier();
        } catch (CertificateException e) {
            return new AndroidCertVerifyResult(CertVerifyStatusAndroid.FAILED);
        }

        return verifier.verifyServerCertificates(certChain, authType, host);
    }

    public static void setDisableNativeCodeForTest(boolean disabled) {
        sDisableNativeCodeForTest = disabled;
    }
    /**
     * Notify the native net::CertDatabase instance that the system database has been updated.
     */
    private static native void nativeNotifyKeyChainChanged();

    /**
     * Record histograms on the platform's certificate verification capabilities.
     */
    private static native void nativeRecordCertVerifyCapabilitiesHistogram(
            boolean foundSystemTrustRoots);

}
