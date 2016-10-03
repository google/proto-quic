// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.net.test;

import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;

import org.chromium.base.ContextUtils;
import org.chromium.base.Log;
import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.JNINamespace;
import org.chromium.base.library_loader.LibraryLoader;
import org.chromium.base.library_loader.LibraryProcessType;
import org.chromium.base.library_loader.ProcessInitException;
import org.chromium.base.test.util.UrlUtils;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Java bindings for running a net::test_server::EmbeddedTestServer.
 *
 * This should not be used directly. Use {@link EmbeddedTestServer} instead.
 */
@JNINamespace("net::test_server")
public class EmbeddedTestServerImpl extends IEmbeddedTestServerImpl.Stub {
    private static final String TAG = "cr_TestServer";

    private static AtomicInteger sCount = new AtomicInteger();

    private final Context mContext;
    private Handler mHandler;
    private HandlerThread mHandlerThread;
    private long mNativeEmbeddedTestServer;

    /** Create an uninitialized EmbeddedTestServer. */
    public EmbeddedTestServerImpl(Context context) {
        mContext = context;
    }

    private <V> V runOnHandlerThread(Callable<V> c) {
        FutureTask<V> t = new FutureTask<>(c);
        mHandler.post(t);
        try {
            return t.get();
        } catch (ExecutionException e) {
            Log.e(TAG, "Exception raised from native EmbeddedTestServer", e);
        } catch (InterruptedException e) {
            Log.e(TAG, "Interrupted while waiting for native EmbeddedTestServer", e);
        }
        return null;
    }

    /** Initialize the native EmbeddedTestServer object.
     *
     *  @return Whether the native object was successfully initialized.
     */
    @Override
    public boolean initializeNative() {
        // This is necessary as EmbeddedTestServerImpl is in a different process than the tests
        // using it, so it needs to initialize its own application context.
        ContextUtils.initApplicationContext(mContext.getApplicationContext());
        try {
            LibraryLoader.get(LibraryProcessType.PROCESS_BROWSER).ensureInitialized();
        } catch (ProcessInitException e) {
            Log.e(TAG, "Failed to load native libraries.", e);
            return false;
        }

        mHandlerThread = new HandlerThread("EmbeddedTestServer" + sCount.getAndIncrement());
        mHandlerThread.start();
        mHandler = new Handler(mHandlerThread.getLooper());

        runOnHandlerThread(new Callable<Void>() {
            @Override
            public Void call() {
                if (mNativeEmbeddedTestServer == 0) nativeInit(UrlUtils.getIsolatedTestRoot());
                assert mNativeEmbeddedTestServer != 0;
                return null;
            }
        });
        return true;
    }

    /** Starts the server.
     *
     *  Note that this should be called after handlers are set up, including any relevant calls
     *  serveFilesFromDirectory.
     *
     *  @return Whether the server was successfully started.
     */
    @Override
    public boolean start() {
        return runOnHandlerThread(new Callable<Boolean>() {
            @Override
            public Boolean call() {
                return nativeStart(mNativeEmbeddedTestServer);
            }
        });
    }

    /** Add the default handlers and serve files from the provided directory relative to the
     *  external storage directory.
     *
     *  @param directoryPath The path of the directory from which files should be served, relative
     *      to the external storage directory.
     */
    @Override
    public void addDefaultHandlers(final String directoryPath) {
        runOnHandlerThread(new Callable<Void>() {
            @Override
            public Void call() {
                nativeAddDefaultHandlers(mNativeEmbeddedTestServer, directoryPath);
                return null;
            }
        });
    }

    /** Serve files from the provided directory.
     *
     *  @param directoryPath The path of the directory from which files should be served.
     */
    @Override
    public void serveFilesFromDirectory(final String directoryPath) {
        runOnHandlerThread(new Callable<Void>() {
            @Override
            public Void call() {
                nativeServeFilesFromDirectory(mNativeEmbeddedTestServer, directoryPath);
                return null;
            }
        });
    }

    /** Get the full URL for the given relative URL.
     *
     *  @param relativeUrl The relative URL for which a full URL should be returned.
     *  @return The URL as a String.
     */
    @Override
    public String getURL(final String relativeUrl) {
        return runOnHandlerThread(new Callable<String>() {
            @Override
            public String call() {
                return nativeGetURL(mNativeEmbeddedTestServer, relativeUrl);
            }
        });
    }

    /** Shut down the server.
     *
     *  @return Whether the server was successfully shut down.
     */
    @Override
    public boolean shutdownAndWaitUntilComplete() {
        return runOnHandlerThread(new Callable<Boolean>() {
            @Override
            public Boolean call() {
                return nativeShutdownAndWaitUntilComplete(mNativeEmbeddedTestServer);
            }
        });
    }

    /** Destroy the native EmbeddedTestServer object. */
    @Override
    public void destroy() {
        runOnHandlerThread(new Callable<Void>() {
            @Override
            public Void call() {
                assert mNativeEmbeddedTestServer != 0;
                nativeDestroy(mNativeEmbeddedTestServer);
                assert mNativeEmbeddedTestServer == 0;
                return null;
            }
        });

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            mHandlerThread.quitSafely();
        } else {
            runOnHandlerThread(new Callable<Void>() {
                @Override
                public Void call() {
                    mHandlerThread.quit();
                    return null;
                }
            });
        }

        try {
            mHandlerThread.join();
        } catch (InterruptedException e) {
        }
    }

    @CalledByNative
    private void setNativePtr(long nativePtr) {
        assert mNativeEmbeddedTestServer == 0;
        mNativeEmbeddedTestServer = nativePtr;
    }

    @CalledByNative
    private void clearNativePtr() {
        assert mNativeEmbeddedTestServer != 0;
        mNativeEmbeddedTestServer = 0;
    }

    private native void nativeInit(String testDataDir);
    private native void nativeDestroy(long nativeEmbeddedTestServerAndroid);
    private native boolean nativeStart(long nativeEmbeddedTestServerAndroid);
    private native boolean nativeShutdownAndWaitUntilComplete(long nativeEmbeddedTestServerAndroid);
    private native String nativeGetURL(long nativeEmbeddedTestServerAndroid, String relativeUrl);
    private native void nativeAddDefaultHandlers(
            long nativeEmbeddedTestServerAndroid, String directoryPath);
    private native void nativeServeFilesFromDirectory(
            long nativeEmbeddedTestServerAndroid, String directoryPath);
}
