// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.net.test;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Environment;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;

import org.junit.Assert;

import org.chromium.base.Log;

import java.io.File;

/** A simple file server for java tests.
 *
 * An example use:
 *   EmbeddedTestServer s = EmbeddedTestServer.createAndStartServer(context);
 *
 *   // serve requests...
 *   s.getURL("/foo/bar.txt");
 *
 *   s.stopAndDestroyServer();
 *
 * Note that this runs net::test_server::EmbeddedTestServer in a service in a separate APK.
 */
public class EmbeddedTestServer {
    private static final String TAG = "cr_TestServer";

    private static final String EMBEDDED_TEST_SERVER_SERVICE =
            "org.chromium.net.test.EMBEDDED_TEST_SERVER_SERVICE";
    private static final long SERVICE_CONNECTION_WAIT_INTERVAL_MS = 5000;

    private IEmbeddedTestServerImpl mImpl;
    private ServiceConnection mConn = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            synchronized (mImplMonitor) {
                mImpl = IEmbeddedTestServerImpl.Stub.asInterface(service);
                mImplMonitor.notify();
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            synchronized (mImplMonitor) {
                mImpl = null;
                mImplMonitor.notify();
            }
        }
    };

    private Context mContext;
    private final Object mImplMonitor = new Object();

    /**
     * Exception class raised on failure in the EmbeddedTestServer.
     */
    public static final class EmbeddedTestServerFailure extends Error {
        public EmbeddedTestServerFailure(String errorDesc) {
            super(errorDesc);
        }

        public EmbeddedTestServerFailure(String errorDesc, Throwable cause) {
            super(errorDesc, cause);
        }
    }

    /** Bind the service that will run the native server object.
     *
     *  @param context The context to use to bind the service. This will also be used to unbind
     *          the service at server destruction time.
     */
    public void initializeNative(Context context) throws InterruptedException {
        mContext = context;

        Intent intent = new Intent(EMBEDDED_TEST_SERVER_SERVICE);
        setIntentClassName(intent);
        if (!mContext.bindService(intent, mConn, Context.BIND_AUTO_CREATE)) {
            throw new EmbeddedTestServerFailure(
                    "Unable to bind to the EmbeddedTestServer service.");
        }
        synchronized (mImplMonitor) {
            Log.i(TAG, "Waiting for EmbeddedTestServer service connection.");
            while (mImpl == null) {
                mImplMonitor.wait(SERVICE_CONNECTION_WAIT_INTERVAL_MS);
                Log.i(TAG, "Still waiting for EmbeddedTestServer service connection.");
            }
            Log.i(TAG, "EmbeddedTestServer service connected.");
            boolean initialized = false;
            try {
                initialized = mImpl.initializeNative();
            } catch (RemoteException e) {
                Log.e(TAG, "Failed to initialize native server.", e);
                initialized = false;
            }

            if (!initialized) {
                throw new EmbeddedTestServerFailure("Failed to initialize native server.");
            }
        }
    }

    /** Set intent package and class name that will pass to the service.
     *
     *  @param intent The intent to use to pass into the service.
     */
    protected void setIntentClassName(Intent intent) {
        intent.setClassName(
                "org.chromium.net.test.support", "org.chromium.net.test.EmbeddedTestServerService");
    }

    /** Add the default handlers and serve files from the provided directory relative to the
     *  external storage directory.
     *
     *  @param directory The directory from which files should be served relative to the external
     *      storage directory.
     */
    public void addDefaultHandlers(File directory) {
        addDefaultHandlers(directory.getPath());
    }

    /** Add the default handlers and serve files from the provided directory relative to the
     *  external storage directory.
     *
     *  @param directoryPath The path of the directory from which files should be served relative
     *      to the external storage directory.
     */
    public void addDefaultHandlers(String directoryPath) {
        try {
            synchronized (mImplMonitor) {
                checkServiceLocked();
                mImpl.addDefaultHandlers(directoryPath);
            }
        } catch (RemoteException e) {
            throw new EmbeddedTestServerFailure(
                    "Failed to add default handlers and start serving files from " + directoryPath
                    + ": " + e.toString());
        }
    }

    /** Serve files from the provided directory.
     *
     *  @param directory The directory from which files should be served.
     */
    public void serveFilesFromDirectory(File directory) {
        serveFilesFromDirectory(directory.getPath());
    }

    /** Serve files from the provided directory.
     *
     *  @param directoryPath The path of the directory from which files should be served.
     */
    public void serveFilesFromDirectory(String directoryPath) {
        try {
            synchronized (mImplMonitor) {
                checkServiceLocked();
                mImpl.serveFilesFromDirectory(directoryPath);
            }
        } catch (RemoteException e) {
            throw new EmbeddedTestServerFailure(
                    "Failed to start serving files from " + directoryPath + ": " + e.toString());
        }
    }

    private void checkServiceLocked() {
        if (mImpl == null) {
            throw new EmbeddedTestServerFailure("Service disconnected.");
        }
    }

    /** Starts the server.
     *
     *  Note that this should be called after handlers are set up, including any relevant calls
     *  serveFilesFromDirectory.
     *
     *  @return Whether the server was successfully initialized.
     */
    public boolean start() {
        try {
            synchronized (mImplMonitor) {
                checkServiceLocked();
                return mImpl.start();
            }
        } catch (RemoteException e) {
            throw new EmbeddedTestServerFailure("Failed to start server.", e);
        }
    }

    /** Create and initialize a server that serves files from the provided directory.
     *
     *  This handles native object initialization, server configuration, and server initialization.
     *  On returning, the server is ready for use.
     *
     *  @param context The context in which the server will run.
     *  @param directory The directory from which files should be served. This must be
     *      Environment.getExternalStorageDirectory().
     *  @return The created server.
     */
    public static EmbeddedTestServer createAndStartFileServer(Context context, File directory)
            throws InterruptedException {
        // TODO(jbudorick): Update all callers to use createAndStartServer() directly.
        if (!directory.equals(Environment.getExternalStorageDirectory())) {
            throw new IllegalArgumentException("Expected directory to be ExternalStorageDirectory");
        }
        return createAndStartServer(context);
    }

    /** Create and initialize a server with the default handlers.
     *
     *  This handles native object initialization, server configuration, and server initialization.
     *  On returning, the server is ready for use.
     *
     *  @param context The context in which the server will run.
     *  @return The created server.
     */
    public static EmbeddedTestServer createAndStartDefaultServer(Context context)
            throws InterruptedException {
        // TODO(pkotwicz): Update all callers to use createAndStartServer() directly.
        return createAndStartServer(context);
    }

    /** Create and initialize a server with the default handlers.
     *
     *  This handles native object initialization, server configuration, and server initialization.
     *  On returning, the server is ready for use.
     *
     *  @param context The context in which the server will run.
     *  @return The created server.
     */
    public static EmbeddedTestServer createAndStartServer(Context context)
            throws InterruptedException {
        Assert.assertNotEquals("EmbeddedTestServer should not be created on UiThread, "
                + "the instantiation will hang forever waiting for tasks to post to UI thread",
                Looper.getMainLooper(), Looper.myLooper());
        EmbeddedTestServer server = new EmbeddedTestServer();
        return initializeAndStartServer(server, context);
    }

    /** Initialize a server with the default handlers.
     *
     *  This handles native object initialization, server configuration, and server initialization.
     *  On returning, the server is ready for use.
     *
     *  @param server The server instance that will be initialized.
     *  @param context The context in which the server will run.
     *  @return The created server.
     */
    public static <T extends EmbeddedTestServer> T initializeAndStartServer(
            T server, Context context) throws InterruptedException {
        server.initializeNative(context);
        server.addDefaultHandlers("");
        if (!server.start()) {
            throw new EmbeddedTestServerFailure("Failed to start serving using default handlers.");
        }
        return server;
    }

    /** Get the full URL for the given relative URL.
     *
     *  @param relativeUrl The relative URL for which a full URL will be obtained.
     *  @return The URL as a String.
     */
    public String getURL(String relativeUrl) {
        try {
            synchronized (mImplMonitor) {
                checkServiceLocked();
                return mImpl.getURL(relativeUrl);
            }
        } catch (RemoteException e) {
            throw new EmbeddedTestServerFailure("Failed to get URL for " + relativeUrl, e);
        }
    }

    /** Get the full URLs for the given relative URLs.
     *
     *  @see #getURL(String)
     *
     *  @param relativeUrls The relative URLs for which full URLs will be obtained.
     *  @return The URLs as a String array.
     */
    public String[] getURLs(String... relativeUrls) {
        String[] absoluteUrls = new String[relativeUrls.length];

        for (int i = 0; i < relativeUrls.length; ++i) absoluteUrls[i] = getURL(relativeUrls[i]);

        return absoluteUrls;
    }

    /** Shutdown the server.
     *
     *  @return Whether the server was successfully shut down.
     */
    public boolean shutdownAndWaitUntilComplete() {
        try {
            synchronized (mImplMonitor) {
                checkServiceLocked();
                return mImpl.shutdownAndWaitUntilComplete();
            }
        } catch (RemoteException e) {
            throw new EmbeddedTestServerFailure("Failed to shut down.", e);
        }
    }

    /** Destroy the native EmbeddedTestServer object. */
    public void destroy() {
        try {
            synchronized (mImplMonitor) {
                checkServiceLocked();
                mImpl.destroy();
            }
        } catch (RemoteException e) {
            throw new EmbeddedTestServerFailure("Failed to destroy native server.", e);
        } finally {
            mContext.unbindService(mConn);
        }
    }

    /** Stop and destroy the server.
     *
     *  This handles stopping the server and destroying the native object.
     */
    public void stopAndDestroyServer() {
        if (!shutdownAndWaitUntilComplete()) {
            throw new EmbeddedTestServerFailure("Failed to stop server.");
        }
        destroy();
    }
}
