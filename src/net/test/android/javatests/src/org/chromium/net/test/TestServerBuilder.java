// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.net.test;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/** Creates instances of BaseTestServer.
 *
 * This will eventually create instances of:
 *  - FtpTestServer
 *  - HttpTestServer
 *  - TcpEchoTestServer
 *  - UdpEchoTestServer
 *  - WebsocketTestServer
 * depending on the parameters passed to the constructor.
 */
class TestServerBuilder {
    private static final String TAG = "TestServerBuilder";

    private static final Pattern SWITCH_PREFIX_RE = Pattern.compile("--");
    private static final Pattern SWITCH_VALUE_SEPARATOR_RE = Pattern.compile("=");

    private static final Set<String> OCSP_RESPONSES;
    private static final Set<String> SSL_BULK_CIPHERS;
    private static final Set<String> SSL_CLIENT_CERT_TYPES;
    private static final Set<String> SSL_KEY_EXCHANGE_ALGORITHMS;
    private static final Set<String> TLS_INTOLERANCE_TYPES;
    static {
        HashSet<String> ocspResponses = new HashSet<String>();
        ocspResponses.add("ok");
        ocspResponses.add("revoked");
        ocspResponses.add("invalid");
        OCSP_RESPONSES = Collections.unmodifiableSet(ocspResponses);

        HashSet<String> sslBulkCiphers = new HashSet<String>();
        sslBulkCiphers.add("aes256");
        sslBulkCiphers.add("aes128");
        sslBulkCiphers.add("3des");
        sslBulkCiphers.add("rc4");
        SSL_BULK_CIPHERS = Collections.unmodifiableSet(sslBulkCiphers);

        HashSet<String> sslClientCertTypes = new HashSet<String>();
        sslClientCertTypes.add("rsa_sign");
        sslClientCertTypes.add("ecdsa_sign");
        SSL_CLIENT_CERT_TYPES = Collections.unmodifiableSet(sslClientCertTypes);

        HashSet<String> sslKeyExchangeAlgorithms = new HashSet<String>();
        sslKeyExchangeAlgorithms.add("rsa");
        sslKeyExchangeAlgorithms.add("dhe_rsa");
        SSL_KEY_EXCHANGE_ALGORITHMS = Collections.unmodifiableSet(sslKeyExchangeAlgorithms);

        HashSet<String> tlsIntoleranceTypes = new HashSet<String>();
        tlsIntoleranceTypes.add("alert");
        tlsIntoleranceTypes.add("close");
        tlsIntoleranceTypes.add("reset");
        TLS_INTOLERANCE_TYPES = Collections.unmodifiableSet(tlsIntoleranceTypes);
    }

    private enum TlsIntolerant {
        MIN(0),

        TOLERATE_ALL(0),
        ABORT_ALL(1),
        ABORT_1_1_AND_ABOVE(2),
        ABORT_1_2_AND_ABOVE(3),

        MAX(3);

        private TlsIntolerant(int value) {
            mValue = value;
        }

        public int value() {
            return mValue;
        }

        private final int mValue;
    }

    private enum ServerType {
        HTTP,
        FTP,
        TCP_ECHO,
        UDP_ECHO,
        BASIC_AUTH_PROXY,
        WEBSOCKET,
    }

    // The path to the file containing the certificate and private key that the server should use,
    // in PEM format.
    private String mCertAndKeyFile;

    // Directory from which the server should read data files.
    private String mDataDir;

    // If true, the server should disable the TLS session cache. Defaults to false.
    private boolean mDisableSessionCache;

    // Root URL for files served. Defaults to "/files/"
    private String mFileRootUrl = "/files/";

    // Hostname or IP the server should listen on and accept connections from.
    // Defaults to "127.0.0.1"
    private String mHost = "127.0.0.1";

    // If true, the server should use HTTPS.
    private boolean mHttps;

    // If true, log to the logcat.
    private boolean mLogToConsole;

    // Type of OCSP response generated. Defaults to "ok".
    private String mOcsp = "ok";

    // Port to be used by the server.
    private int mPort;

    // Type of server to build.
    private ServerType mServerType = ServerType.HTTP;

    // The bulk encryption algorithms that should be accepted by the server.
    // Defaults to "aes256", "aes128", "3des", "rc4"
    private List<String> mSslBulkCiphers;

    // If true, the server should require SSL client authentication on every connection.
    // Defaults to false.
    private boolean mSslClientAuth;

    // The CA names that should be included in the client certificate requests.
    private List<String> mSslClientCas;

    // The certificate_types that should be included in the client certificate request.
    // Defaults to "rsa_sign"
    private List<String> mSslClientCertTypes;

    // The key exchange algorithms that should be accepted by the server.
    // Defaults to "rsa", "dhe_rsa"
    private List<String> mSslKeyExchanges;

    /** Create a TestServerBuilder.
     *
     * @param json The server configuration. Determines the type of server spawned and the specific
     *      configuration thereof.
     */
    public TestServerBuilder(JSONObject json) throws JSONException {
        mSslBulkCiphers = new ArrayList<String>(SSL_BULK_CIPHERS);
        mSslClientCas = new ArrayList<String>();
        mSslClientCertTypes = new ArrayList<String>();
        mSslClientCertTypes.add("rsa_sign");
        mSslKeyExchanges = new ArrayList<String>(SSL_KEY_EXCHANGE_ALGORITHMS);

        parse(json);
    }

    /** Create a BaseTestServer.
     *
     * @return An instance of BaseTestServer.
     */
    public BaseTestServer build() {
        Log.i(TAG, "building with: " + toString());

        // TODO(jbudorick): Implement this in a subsequent CL.
        throw new UnsupportedOperationException(
                "TestServerBuilder.build() hasn't been implemented yet.");
    }

    private void parse(JSONObject json) throws JSONException {
        Iterator<String> keyIter = json.keys();
        while (keyIter.hasNext()) {
            String key = keyIter.next();
            Log.i(TAG, "Received key: " + key);
            switch (key) {
                case "cert-and-key-file":
                    mCertAndKeyFile = json.getString(key);
                    break;
                case "data-dir":
                    mDataDir = json.getString(key);
                    break;
                case "disable-session-cache":
                    mDisableSessionCache = true;
                    break;
                case "host":
                    mHost = json.getString(key);
                    break;
                case "https":
                    mHttps = true;
                    break;
                case "log-to-console":
                    mLogToConsole = true;
                    break;
                case "port":
                    mPort = json.getInt(key);
                    break;
                case "server-type":
                    parseServerType(json.getString(key));
                    break;
                case "ssl-client-auth":
                    mSslClientAuth = true;
                    break;
                case "ssl-client-ca":
                    mSslClientCas = jsonArrayAsStringList(json.getJSONArray(key));
                    break;
                case "ssl-key-exchange":
                    mSslKeyExchanges = jsonArrayAsStringList(json.getJSONArray(key));
                    if (SSL_KEY_EXCHANGE_ALGORITHMS.containsAll(mSslKeyExchanges)) {
                        mSslKeyExchanges.removeAll(SSL_KEY_EXCHANGE_ALGORITHMS);
                        throw new JSONException("invalid values provided for ssl-key-exchange: "
                                + mSslKeyExchanges.toString());
                    }
                    break;
                default:
                    Log.e(TAG, "Unrecognized command-line flag: " + key);
                    break;
            }
        }
    }

    private void parseServerType(String serverType) throws JSONException {
        switch (serverType) {
            case "http":
                mServerType = ServerType.HTTP;
                break;
            case "ftp":
                mServerType = ServerType.FTP;
                break;
            case "tcp-echo":
                mServerType = ServerType.TCP_ECHO;
                break;
            case "udp-echo":
                mServerType = ServerType.UDP_ECHO;
                break;
            case "basic-auth-proxy":
                mServerType = ServerType.BASIC_AUTH_PROXY;
                break;
            case "websocket":
                mServerType = ServerType.WEBSOCKET;
                break;
            default:
                throw new JSONException("Unrecognized server-type value: \"" + serverType + "\"");
        }
    }

    private static List<String> jsonArrayAsStringList(JSONArray jsonArray) throws JSONException {
        List<String> result = new ArrayList<String>(jsonArray.length());
        for (int i = 0; i < jsonArray.length(); ++i) {
            result.set(i, jsonArray.getString(i));
        }
        return result;
    }

    public String toString() {
        StringBuilder resultBuilder = new StringBuilder("{");
        resultBuilder.append(formatString("mCertAndKeyFile", mCertAndKeyFile));
        resultBuilder.append(formatString("mDataDir", mDataDir));
        resultBuilder.append(formatBoolean("mDisableSessionCache", mDisableSessionCache));
        resultBuilder.append(formatString("mFileRootUrl", mFileRootUrl));
        resultBuilder.append(formatString("mHost", mHost));
        resultBuilder.append(formatBoolean("mHttps", mHttps));
        resultBuilder.append(formatBoolean("mLogToConsole", mLogToConsole));
        resultBuilder.append(formatString("mOcsp", mOcsp));
        resultBuilder.append(formatInt("mPort", mPort));
        resultBuilder.append(formatServerType("mServerType", mServerType));
        resultBuilder.append(formatList("mSslBulkCiphers", mSslBulkCiphers));
        resultBuilder.append(formatBoolean("mSslClientAuth", mSslClientAuth));
        resultBuilder.append(formatList("mSslClientCas", mSslClientCas));
        resultBuilder.append(formatList("mSslClientCertTypes", mSslClientCertTypes));
        resultBuilder.append(formatList("mSslKeyExchanges", mSslKeyExchanges));
        resultBuilder.append("}");
        return resultBuilder.toString();
    }

    private String formatString(String label, String value) {
        return "\"" + label + "\": \"" + formatString(value) + "\",";
    }

    private String formatString(String value) {
        return value != null ? value : "null";
    }

    private String formatInt(String label, int value) {
        return "\"" + label + "\": \"" + Integer.toString(value) + "\",";
    }

    private String formatBoolean(String label, boolean value) {
        return "\"" + label + "\": \"" + Boolean.toString(value) + "\",";
    }

    private String formatList(String label, List<String> value) {
        StringBuilder resultBuilder = new StringBuilder("\"");
        resultBuilder.append(label).append("\": [");
        for (String s : value) {
            resultBuilder.append("\"").append(formatString(s)).append("\",");
        }
        resultBuilder.append("],");
        return resultBuilder.toString();
    }

    private String formatServerType(String label, ServerType serverType) {
        String result = "\"mServerType\": \"";
        switch (serverType) {
            case HTTP:
                result += "HTTP";
                break;
            case FTP:
                result += "FTP";
                break;
            case TCP_ECHO:
                result += "TCP_ECHO";
                break;
            case UDP_ECHO:
                result += "UDP_ECHO";
                break;
            case BASIC_AUTH_PROXY:
                result += "BASIC_AUTH_PROXY";
                break;
            case WEBSOCKET:
                result += "WEBSOCKET";
                break;
            default:
                result += "???";
                break;
        }
        result += "\",";
        return result;
    }
}
