// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.net.test.util;

import android.util.Base64;
import android.util.Log;
import android.util.Pair;

import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.HttpVersion;
import org.apache.http.RequestLine;
import org.apache.http.StatusLine;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.DefaultHttpServerConnection;
import org.apache.http.impl.cookie.DateUtils;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.CoreProtocolPNames;
import org.apache.http.params.HttpParams;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

/**
 * Simple http test server for testing.
 *
 * This server runs in a thread in the current process, so it is convenient
 * for loopback testing without the need to setup tcp forwarding to the
 * host computer.
 *
 * Based heavily on the CTSWebServer in Android.
 */
public class TestWebServer {
    private static final String TAG = "TestWebServer";

    private static TestWebServer sInstance;
    private static TestWebServer sSecureInstance;
    private static Hashtable<Integer, String> sReasons;

    private final ServerThread mServerThread;
    private String mServerUri;
    private final boolean mSsl;
    private final int mPort;

    private static class Response {
        final byte[] mResponseData;
        final List<Pair<String, String>> mResponseHeaders;
        final boolean mIsRedirect;
        final Runnable mResponseAction;
        final boolean mIsNotFound;
        final boolean mIsNoContent;

        Response(byte[] responseData, List<Pair<String, String>> responseHeaders,
                boolean isRedirect, boolean isNotFound, boolean isNoContent,
                Runnable responseAction) {
            mIsRedirect = isRedirect;
            mIsNotFound = isNotFound;
            mIsNoContent = isNoContent;
            mResponseData = responseData;
            mResponseHeaders = responseHeaders == null
                    ? new ArrayList<Pair<String, String>>() : responseHeaders;
            mResponseAction = responseAction;
        }
    }

    // The Maps below are modified on both the client thread and the internal server thread, so
    // need to use a lock when accessing them.
    private final Object mLock = new Object();
    private final Map<String, Response> mResponseMap = new HashMap<String, Response>();
    private final Map<String, Integer> mResponseCountMap = new HashMap<String, Integer>();
    private final Map<String, HttpRequest> mLastRequestMap = new HashMap<String, HttpRequest>();

    /**
     * Create and start a local HTTP server instance.
     * @param port Port number the server must use, or 0 to automatically choose a free port.
     * @param ssl True if the server should be using secure sockets.
     * @throws Exception
     */
    private TestWebServer(int port, boolean ssl) throws Exception {
        mPort = port;

        mSsl = ssl;
        if (mSsl) {
            mServerUri = "https:";
            if (sSecureInstance != null) {
                sSecureInstance.shutdown();
            }
        } else {
            mServerUri = "http:";
            if (sInstance != null) {
                sInstance.shutdown();
            }
        }

        mServerThread = new ServerThread(this, mPort, mSsl);
        mServerUri += "//localhost:" + mServerThread.mSocket.getLocalPort();
    }

    public static TestWebServer start(int port) throws Exception {
        if (sInstance != null) {
            throw new IllegalStateException("Tried to start multiple TestWebServers");
        }

        TestWebServer server = new TestWebServer(port, false);
        server.mServerThread.start();
        setInstance(server);
        return server;
    }

    public static TestWebServer start() throws Exception {
        return start(0);
    }

    public static TestWebServer startSsl(int port) throws Exception {
        if (sSecureInstance != null) {
            throw new IllegalStateException("Tried to start multiple SSL TestWebServers");
        }

        TestWebServer server = new TestWebServer(port, true);
        server.mServerThread.start();
        setSecureInstance(server);
        return server;
    }

    public static TestWebServer startSsl() throws Exception {
        return startSsl(0);
    }

    /**
     * Terminate the http server.
     */
    public void shutdown() {
        if (mSsl) {
            setSecureInstance(null);
        } else {
            setInstance(null);
        }

        try {
            mServerThread.cancelAllRequests();
            // Block until the server thread is done shutting down.
            mServerThread.join();
        } catch (MalformedURLException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // Setting static variables from instance methods causes findbugs warnings. Calling static
    // methods which set static variables from instance methods isn't any better, but it silences
    // the warnings.
    private static void setInstance(TestWebServer instance) {
        sInstance = instance;
    }

    private static void setSecureInstance(TestWebServer instance) {
        sSecureInstance = instance;
    }

    private static final int RESPONSE_STATUS_NORMAL = 0;
    private static final int RESPONSE_STATUS_MOVED_TEMPORARILY = 1;
    private static final int RESPONSE_STATUS_NOT_FOUND = 2;
    private static final int RESPONSE_STATUS_NO_CONTENT = 3;

    private String setResponseInternal(
            String requestPath, byte[] responseData,
            List<Pair<String, String>> responseHeaders, Runnable responseAction,
            int status) {
        final boolean isRedirect = (status == RESPONSE_STATUS_MOVED_TEMPORARILY);
        final boolean isNotFound = (status == RESPONSE_STATUS_NOT_FOUND);
        final boolean isNoContent = (status == RESPONSE_STATUS_NO_CONTENT);

        synchronized (mLock) {
            mResponseMap.put(requestPath, new Response(
                    responseData, responseHeaders, isRedirect, isNotFound, isNoContent,
                    responseAction));
            mResponseCountMap.put(requestPath, Integer.valueOf(0));
            mLastRequestMap.put(requestPath, null);
        }
        return getResponseUrl(requestPath);
    }

    /**
     * Gets the URL on the server under which a particular request path will be accessible.
     *
     * This only gets the URL, you still need to set the response if you intend to access it.
     *
     * @param requestPath The path to respond to.
     * @return The full URL including the requestPath.
     */
    public String getResponseUrl(String requestPath) {
        return mServerUri + requestPath;
    }

    /**
     * Sets a 404 (not found) response to be returned when a particular request path is passed in.
     *
     * @param requestPath The path to respond to.
     * @return The full URL including the path that should be requested to get the expected
     *         response.
     */
    public String setResponseWithNotFoundStatus(
            String requestPath) {
        return setResponseWithNotFoundStatus(requestPath, null);
    }

    /**
     * Sets a 404 (not found) response to be returned when a particular request path is passed in.
     *
     * @param requestPath The path to respond to.
     * @param responseHeaders Any additional headers that should be returned along with the
     *                        response (null is acceptable).
     * @return The full URL including the path that should be requested to get the expected
     *         response.
     */
    public String setResponseWithNotFoundStatus(
            String requestPath, List<Pair<String, String>> responseHeaders) {
        return setResponseInternal(
                requestPath, "".getBytes(), responseHeaders, null, RESPONSE_STATUS_NOT_FOUND);
    }

    /**
     * Sets a 204 (no content) response to be returned when a particular request path is passed in.
     *
     * @param requestPath The path to respond to.
     * @return The full URL including the path that should be requested to get the expected
     *         response.
     */
    public String setResponseWithNoContentStatus(String requestPath) {
        return setResponseInternal(
                requestPath, "".getBytes(), null, null, RESPONSE_STATUS_NO_CONTENT);
    }

    /**
     * Sets a response to be returned when a particular request path is passed
     * in (with the option to specify additional headers).
     *
     * @param requestPath The path to respond to.
     * @param responseString The response body that will be returned.
     * @param responseHeaders Any additional headers that should be returned along with the
     *                        response (null is acceptable).
     * @return The full URL including the path that should be requested to get the expected
     *         response.
     */
    public String setResponse(
            String requestPath, String responseString,
            List<Pair<String, String>> responseHeaders) {
        return setResponseInternal(requestPath, responseString.getBytes(), responseHeaders, null,
                RESPONSE_STATUS_NORMAL);
    }

    /**
     * Sets a response to be returned when a particular request path is passed
     * in with the option to specify additional headers as well as an arbitrary action to be
     * executed on each request.
     *
     * @param requestPath The path to respond to.
     * @param responseString The response body that will be returned.
     * @param responseHeaders Any additional headers that should be returned along with the
     *                        response (null is acceptable).
     * @param responseAction The action to be performed when fetching the response.  This action
     *                       will be executed for each request and will be handled on a background
     *                       thread.
     * @return The full URL including the path that should be requested to get the expected
     *         response.
     */
    public String setResponseWithRunnableAction(
            String requestPath, String responseString, List<Pair<String, String>> responseHeaders,
            Runnable responseAction) {
        return setResponseInternal(
                requestPath, responseString.getBytes(), responseHeaders, responseAction,
                RESPONSE_STATUS_NORMAL);
    }

    /**
     * Sets a redirect.
     *
     * @param requestPath The path to respond to.
     * @param targetPath The path to redirect to.
     * @return The full URL including the path that should be requested to get the expected
     *         response.
     */
    public String setRedirect(
            String requestPath, String targetPath) {
        List<Pair<String, String>> responseHeaders = new ArrayList<Pair<String, String>>();
        responseHeaders.add(Pair.create("Location", targetPath));

        return setResponseInternal(requestPath, targetPath.getBytes(), responseHeaders, null,
                RESPONSE_STATUS_MOVED_TEMPORARILY);
    }

    /**
     * Sets a base64 encoded response to be returned when a particular request path is passed
     * in (with the option to specify additional headers).
     *
     * @param requestPath The path to respond to.
     * @param base64EncodedResponse The response body that is base64 encoded. The actual server
     *                              response will the decoded binary form.
     * @param responseHeaders Any additional headers that should be returned along with the
     *                        response (null is acceptable).
     * @return The full URL including the path that should be requested to get the expected
     *         response.
     */
    public String setResponseBase64(
            String requestPath, String base64EncodedResponse,
            List<Pair<String, String>> responseHeaders) {
        return setResponseInternal(
                requestPath, Base64.decode(base64EncodedResponse, Base64.DEFAULT),
                responseHeaders, null, RESPONSE_STATUS_NORMAL);
    }

    /**
     * Get the number of requests was made at this path since it was last set.
     */
    public int getRequestCount(String requestPath) {
        Integer count = null;
        synchronized (mLock) {
            count = mResponseCountMap.get(requestPath);
        }
        if (count == null) throw new IllegalArgumentException("Path not set: " + requestPath);
        return count.intValue();
    }

    /**
     * Returns the last HttpRequest at this path. Can return null if it is never requested.
     */
    public HttpRequest getLastRequest(String requestPath) {
        synchronized (mLock) {
            if (!mLastRequestMap.containsKey(requestPath))
                throw new IllegalArgumentException("Path not set: " + requestPath);
            return mLastRequestMap.get(requestPath);
        }
    }

    public String getBaseUrl() {
        return mServerUri + "/";
    }

    private URLConnection openConnection(URL url)
            throws IOException, NoSuchAlgorithmException, KeyManagementException {
        if (mSsl) {
            // Install hostname verifiers and trust managers that don't do
            // anything in order to get around the client not trusting
            // the test server due to a lack of certificates.

            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setHostnameVerifier(new TestHostnameVerifier());

            SSLContext context = SSLContext.getInstance("TLS");
            TestTrustManager trustManager = new TestTrustManager();
            context.init(null, new TestTrustManager[] {trustManager}, null);
            connection.setSSLSocketFactory(context.getSocketFactory());

            return connection;
        } else {
            return url.openConnection();
        }
    }

    /**
     * {@link X509TrustManager} that trusts everybody. This is used so that
     * the client calling {@link TestWebServer#shutdown()} can issue a request
     * for shutdown by blindly trusting the {@link TestWebServer}'s
     * credentials.
     */
    private static class TestTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // Trust the TestWebServer...
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // Trust the TestWebServer...
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }

    /**
     * {@link HostnameVerifier} that verifies everybody. This permits
     * the client to trust the web server and call
     * {@link TestWebServer#shutdown()}.
     */
    private static class TestHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

    private void servedResponseFor(String path, HttpRequest request) {
        synchronized (mLock) {
            mResponseCountMap.put(path, Integer.valueOf(
                    mResponseCountMap.get(path).intValue() + 1));
            mLastRequestMap.put(path, request);
        }
    }

    /**
     * Generate a response to the given request.
     *
     * <p>Always executed on the background server thread.
     *
     * <p>If there is an action associated with the response, it will be executed inside of
     * this function.
     *
     * @throws InterruptedException
     */
    private HttpResponse getResponse(HttpRequest request) throws InterruptedException {
        assert Thread.currentThread() == mServerThread
                : "getResponse called from non-server thread";

        RequestLine requestLine = request.getRequestLine();
        HttpResponse httpResponse = null;
        Log.i(TAG, requestLine.getMethod() + ": " + requestLine.getUri());
        String uriString = requestLine.getUri();
        URI uri = URI.create(uriString);
        String path = uri.getPath();

        Response response = null;
        synchronized (mLock) {
            response = mResponseMap.get(path);
        }
        if (response == null) {
            httpResponse = createResponse(HttpStatus.SC_NOT_FOUND);
        } else if (response.mIsNotFound) {
            httpResponse = createResponse(HttpStatus.SC_NOT_FOUND);
            for (Pair<String, String> header : response.mResponseHeaders) {
                httpResponse.addHeader(header.first, header.second);
            }
            servedResponseFor(path, request);
        } else if (response.mIsNoContent) {
            httpResponse = createResponse(HttpStatus.SC_NO_CONTENT);
            httpResponse.setHeader("Content-Length", "0");
            servedResponseFor(path, request);
        } else if (response.mIsRedirect) {
            httpResponse = createResponse(HttpStatus.SC_MOVED_TEMPORARILY);
            for (Pair<String, String> header : response.mResponseHeaders) {
                httpResponse.addHeader(header.first, header.second);
            }
            servedResponseFor(path, request);
        } else {
            if (response.mResponseAction != null) response.mResponseAction.run();

            httpResponse = createResponse(HttpStatus.SC_OK);
            ByteArrayEntity entity = createEntity(response.mResponseData);
            httpResponse.setEntity(entity);
            httpResponse.setHeader("Content-Length", "" + entity.getContentLength());
            for (Pair<String, String> header : response.mResponseHeaders) {
                httpResponse.addHeader(header.first, header.second);
            }
            servedResponseFor(path, request);
        }
        StatusLine sl = httpResponse.getStatusLine();
        Log.i(TAG, sl.getStatusCode() + "(" + sl.getReasonPhrase() + ")");

        if (path.endsWith(".js")) {
            httpResponse.addHeader("Content-Type", "application/javascript");
        }

        setDateHeaders(httpResponse);
        return httpResponse;
    }

    private void setDateHeaders(HttpResponse response) {
        response.addHeader("Date", DateUtils.formatDate(new Date(), DateUtils.PATTERN_RFC1123));
    }

    /**
     * Create an empty response with the given status.
     */
    private HttpResponse createResponse(int status) {
        HttpResponse response = new BasicHttpResponse(HttpVersion.HTTP_1_0, status, null);
        String reason = null;

        // This synchronized silences findbugs.
        synchronized (TestWebServer.class) {
            if (sReasons == null) {
                sReasons = new Hashtable<Integer, String>();
                sReasons.put(HttpStatus.SC_UNAUTHORIZED, "Unauthorized");
                sReasons.put(HttpStatus.SC_NOT_FOUND, "Not Found");
                sReasons.put(HttpStatus.SC_FORBIDDEN, "Forbidden");
                sReasons.put(HttpStatus.SC_MOVED_TEMPORARILY, "Moved Temporarily");
            }
            // Fill in error reason. Avoid use of the ReasonPhraseCatalog, which is
            // Locale-dependent.
            reason = sReasons.get(status);
        }

        if (reason != null) {
            StringBuilder buf = new StringBuilder("<html><head><title>");
            buf.append(reason);
            buf.append("</title></head><body>");
            buf.append(reason);
            buf.append("</body></html>");
            ByteArrayEntity entity = createEntity(buf.toString().getBytes());
            response.setEntity(entity);
            response.setHeader("Content-Length", "" + entity.getContentLength());
            response.setReasonPhrase(reason);
        }
        return response;
    }

    /**
     * Create a string entity for the given content.
     */
    private ByteArrayEntity createEntity(byte[] data) {
        ByteArrayEntity entity = new ByteArrayEntity(data);
        entity.setContentType("text/html");
        return entity;
    }

    private static class ServerThread extends Thread {
        private TestWebServer mServer;
        private ServerSocket mSocket;
        private boolean mIsSsl;
        private SSLContext mSslContext;

        private final Object mLock = new Object();
        private boolean mIsCancelled;
        private Socket mCurrentRequestSocket;

        /**
         * Defines the keystore contents for the server, BKS version. Holds just a
         * single self-generated key. The subject name is "Test Server".
         */
        private static final String SERVER_KEYS_BKS =
                "AAAAAQAAABQDkebzoP1XwqyWKRCJEpn/t8dqIQAABDkEAAVteWtleQAAARpYl20nAAAAAQAFWC41"
                + "MDkAAAJNMIICSTCCAbKgAwIBAgIESEfU1jANBgkqhkiG9w0BAQUFADBpMQswCQYDVQQGEwJVUzET"
                + "MBEGA1UECBMKQ2FsaWZvcm5pYTEMMAoGA1UEBxMDTVRWMQ8wDQYDVQQKEwZHb29nbGUxEDAOBgNV"
                + "BAsTB0FuZHJvaWQxFDASBgNVBAMTC1Rlc3QgU2VydmVyMB4XDTA4MDYwNTExNTgxNFoXDTA4MDkw"
                + "MzExNTgxNFowaTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExDDAKBgNVBAcTA01U"
                + "VjEPMA0GA1UEChMGR29vZ2xlMRAwDgYDVQQLEwdBbmRyb2lkMRQwEgYDVQQDEwtUZXN0IFNlcnZl"
                + "cjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA0LIdKaIr9/vsTq8BZlA3R+NFWRaH4lGsTAQy"
                + "DPMF9ZqEDOaL6DJuu0colSBBBQ85hQTPa9m9nyJoN3pEi1hgamqOvQIWcXBk+SOpUGRZZFXwniJV"
                + "zDKU5nE9MYgn2B9AoiH3CSuMz6HRqgVaqtppIe1jhukMc/kHVJvlKRNy9XMCAwEAATANBgkqhkiG"
                + "9w0BAQUFAAOBgQC7yBmJ9O/eWDGtSH9BH0R3dh2NdST3W9hNZ8hIa8U8klhNHbUCSSktZmZkvbPU"
                + "hse5LI3dh6RyNDuqDrbYwcqzKbFJaq/jX9kCoeb3vgbQElMRX8D2ID1vRjxwlALFISrtaN4VpWzV"
                + "yeoHPW4xldeZmoVtjn8zXNzQhLuBqX2MmAAAAqwAAAAUvkUScfw9yCSmALruURNmtBai7kQAAAZx"
                + "4Jmijxs/l8EBaleaUru6EOPioWkUAEVWCxjM/TxbGHOi2VMsQWqRr/DZ3wsDmtQgw3QTrUK666sR"
                + "MBnbqdnyCyvM1J2V1xxLXPUeRBmR2CXorYGF9Dye7NkgVdfA+9g9L/0Au6Ugn+2Cj5leoIgkgApN"
                + "vuEcZegFlNOUPVEs3SlBgUF1BY6OBM0UBHTPwGGxFBBcetcuMRbUnu65vyDG0pslT59qpaR0TMVs"
                + "P+tcheEzhyjbfM32/vwhnL9dBEgM8qMt0sqF6itNOQU/F4WGkK2Cm2v4CYEyKYw325fEhzTXosck"
                + "MhbqmcyLab8EPceWF3dweoUT76+jEZx8lV2dapR+CmczQI43tV9btsd1xiBbBHAKvymm9Ep9bPzM"
                + "J0MQi+OtURL9Lxke/70/MRueqbPeUlOaGvANTmXQD2OnW7PISwJ9lpeLfTG0LcqkoqkbtLKQLYHI"
                + "rQfV5j0j+wmvmpMxzjN3uvNajLa4zQ8l0Eok9SFaRr2RL0gN8Q2JegfOL4pUiHPsh64WWya2NB7f"
                + "V+1s65eA5ospXYsShRjo046QhGTmymwXXzdzuxu8IlnTEont6P4+J+GsWk6cldGbl20hctuUKzyx"
                + "OptjEPOKejV60iDCYGmHbCWAzQ8h5MILV82IclzNViZmzAapeeCnexhpXhWTs+xDEYSKEiG/camt"
                + "bhmZc3BcyVJrW23PktSfpBQ6D8ZxoMfF0L7V2GQMaUg+3r7ucrx82kpqotjv0xHghNIm95aBr1Qw"
                + "1gaEjsC/0wGmmBDg1dTDH+F1p9TInzr3EFuYD0YiQ7YlAHq3cPuyGoLXJ5dXYuSBfhDXJSeddUkl"
                + "k1ufZyOOcskeInQge7jzaRfmKg3U94r+spMEvb0AzDQVOKvjjo1ivxMSgFRZaDb/4qw=";

        private static final String PASSWORD = "android";

        /**
         * Loads a keystore from a base64-encoded String. Returns the KeyManager[]
         * for the result.
         */
        private KeyManager[] getKeyManagers() throws Exception {
            byte[] bytes = Base64.decode(SERVER_KEYS_BKS, Base64.DEFAULT);
            InputStream inputStream = new ByteArrayInputStream(bytes);

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(inputStream, PASSWORD.toCharArray());
            inputStream.close();

            String algorithm = KeyManagerFactory.getDefaultAlgorithm();
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
            keyManagerFactory.init(keyStore, PASSWORD.toCharArray());

            return keyManagerFactory.getKeyManagers();
        }

        private void setCurrentRequestSocket(Socket socket) {
            synchronized (mLock) {
                mCurrentRequestSocket = socket;
            }
        }

        private boolean getIsCancelled() {
            synchronized (mLock) {
                return mIsCancelled;
            }
        }

        // Called from non-server thread.
        public void cancelAllRequests() throws IOException {
            synchronized (mLock) {
                mIsCancelled = true;
                if (mCurrentRequestSocket != null) {
                    try {
                        mCurrentRequestSocket.close();
                    } catch (IOException ignored) {
                        // Catching this to ensure the server socket is closed as well.
                    }
                }
            }
            // Any current and subsequent accept call will throw instead of block.
            mSocket.close();
        }

        public ServerThread(TestWebServer server, int port, boolean ssl) throws Exception {
            super("ServerThread");
            mServer = server;
            mIsSsl = ssl;
            int retry = 3;
            while (true) {
                try {
                    if (mIsSsl) {
                        mSslContext = SSLContext.getInstance("TLS");
                        mSslContext.init(getKeyManagers(), null, null);
                        mSocket = mSslContext.getServerSocketFactory().createServerSocket(port);
                    } else {
                        mSocket = new ServerSocket(port);
                    }
                    return;
                } catch (IOException e) {
                    Log.w(TAG, e);
                    if (--retry == 0) {
                        throw e;
                    }
                    // sleep in case server socket is still being closed
                    Thread.sleep(1000);
                }
            }
        }

        @Override
        public void run() {
            HttpParams params = new BasicHttpParams();
            params.setParameter(CoreProtocolPNames.PROTOCOL_VERSION, HttpVersion.HTTP_1_0);
            while (!getIsCancelled()) {
                Socket socket = null;
                try {
                    socket = mSocket.accept();
                    setCurrentRequestSocket(socket);

                    DefaultHttpServerConnection conn = new DefaultHttpServerConnection();
                    conn.bind(socket, params);

                    if (getIsCancelled()) continue;
                    HttpRequest request = conn.receiveRequestHeader();
                    HttpResponse response = mServer.getResponse(request);
                    conn.sendResponseHeader(response);
                    conn.sendResponseEntity(response);

                    conn.close();
                    socket = null;
                } catch (IOException e) {
                    // normal during shutdown, ignore
                    Log.w(TAG, e);
                } catch (HttpException e) {
                    Log.w(TAG, e);
                } catch (InterruptedException e) {
                    Log.w(TAG, e);
                } catch (UnsupportedOperationException e) {
                    // DefaultHttpServerConnection's close() throws an
                    // UnsupportedOperationException.
                    Log.w(TAG, e);
                } finally {
                    // Since DefaultHttpServerConnection can raise an exception
                    // during conn.close() (in the case of SSL), we always force
                    // the socket to close, since it may be left open. This will
                    // be a no-op if the connection managed to close the socket.
                    if (socket != null) {
                        try {
                            socket.close();
                        } catch (IOException ignored) {
                            // safe to ignore
                        }
                    }
                }
            }
        }
    }
}
