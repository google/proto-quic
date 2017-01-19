// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.os.Process;

import org.chromium.base.annotations.SuppressFBWarnings;
import org.chromium.base.library_loader.LibraryLoader;
import org.chromium.base.library_loader.LibraryProcessType;
import org.chromium.base.library_loader.ProcessInitException;
import org.chromium.native_test.MainRunner;

import javax.annotation.concurrent.GuardedBy;

/**
 * The service implementation used to host all multiprocess test client code.
 */
public class MultiprocessTestClientService extends Service {
    private static final String TAG = "cr_TestClient";

    private static boolean sAlreadyInitialized = false;

    private final Handler mHandler = new Handler();

    private final Object mResultLock = new Object();

    @GuardedBy("mResultLock")
    private MainReturnCodeResult mResult;

    private final ITestClient.Stub mBinder = new ITestClient.Stub() {
        @Override
        public int launch(final String[] commandLine, FileDescriptorInfo[] fdsToMap) {
            final int[] fdKeys = new int[fdsToMap.length];
            final int[] fdFds = new int[fdsToMap.length];
            for (int i = 0; i < fdsToMap.length; i++) {
                fdKeys[i] = fdsToMap[i].key;
                // Take ownership of the file descriptor so they outlive the FileDescriptorInfo
                // instances. Native code will own them.
                fdFds[i] = fdsToMap[i].fd.detachFd();
            }
            // Don't run main directly, it would block and the response would not be returned.
            // We post to the main thread as this thread does not have a Looper.
            mHandler.post(new Runnable() {
                @Override
                public void run() {
                    int result = MainRunner.runMain(commandLine, fdKeys, fdFds);
                    setMainReturnValue(result);
                }
            });
            return Process.myPid();
        }

        @SuppressFBWarnings("RCN_REDUNDANT_NULLCHECK_OF_NULL_VALUE")
        @Override
        public MainReturnCodeResult waitForMainToReturn(int timeoutMs) {
            synchronized (mResultLock) {
                while (mResult == null) {
                    try {
                        mResultLock.wait(timeoutMs);
                    } catch (InterruptedException ie) {
                        continue;
                    }
                    // Check if we timed-out.
                    if (mResult == null) {
                        Log.e(TAG, "Failed to wait for main return value.");
                        return new MainReturnCodeResult(0, true /* timed-out */);
                    }
                }
                return mResult;
            }
        }

        @SuppressFBWarnings("DM_EXIT")
        @Override
        public boolean forceStopSynchronous(int exitCode) {
            System.exit(exitCode);
            return true;
        }

        @SuppressFBWarnings("DM_EXIT")
        @Override
        public void forceStop(int exitCode) {
            System.exit(exitCode);
        }
    };

    @SuppressFBWarnings("DM_EXIT")
    @Override
    public void onCreate() {
        super.onCreate();

        if (sAlreadyInitialized) {
            // The framework controls how services are reused and even though nothing is bound to a
            // service it might be kept around. Since we really want to fork a new process when we
            // bind, we'll kill the process early when a service is reused, forcing the framework to
            // recreate the service in a new process.
            // This is not ideal, but there are no clear alternatives at this point.
            Log.e(TAG, "Service being reused, forcing stoppage.");
            System.exit(0);
            return;
        }
        markInitialized();

        ContextUtils.initApplicationContext(getApplicationContext());

        PathUtils.setPrivateDataDirectorySuffix("chrome_multiprocess_test_client_service");

        loadLibraries();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    private void loadLibraries() {
        try {
            LibraryLoader.get(LibraryProcessType.PROCESS_CHILD).loadNow();
        } catch (ProcessInitException pie) {
            Log.e(TAG, "Unable to load native libraries.", pie);
        }
        ContextUtils.initApplicationContextForNative();
    }

    private void setMainReturnValue(int result) {
        synchronized (mResultLock) {
            mResult = new MainReturnCodeResult(result, false /* timed-out */);
            mResultLock.notifyAll();
        }
    }

    private static void markInitialized() {
        // We don't set sAlreadyInitialized directly in onCreate to avoid FindBugs complaining about
        // a static member been set from a non-static function.
        sAlreadyInitialized = true;
    }
}
